"""Run a RuleSet over canonical Parquet with DuckDB.

Every rule type is compiled to one evidence relation (fkey, event_uid, step,
metric); a shared aggregation turns it into findings. Thresholds use true
sliding RANGE windows over the whole dataset (not per file or chunk), so a
window crossing a file/segment boundary is evaluated once and correctly.
Exact duplicate deliveries (same record_hash) are counted once per rule.
"""
import datetime as dt
import json

import duckdb

from .rules import Rule, RuleSet, field_sql, interval_sql, required_categories, where_sql

STALL_MIN_EVENTS = 1000  # one exact timestamp shared by this many events = stalled/clamped clock


def parquet_src(globs) -> str:
    """SQL literal for one glob or a list of globs (several sources analyzed together)."""
    if isinstance(globs, (list, tuple)):
        return "[" + ", ".join("'" + g.replace("'", "''") + "'" for g in globs) + "]"
    return "'" + globs.replace("'", "''") + "'"


def connect(region="ap-south-1", memory="3GB", temp_dir=None):
    con = duckdb.connect()
    con.execute(f"SET memory_limit='{memory}'; SET preserve_insertion_order=false; SET TimeZone='UTC'")
    if temp_dir:
        con.execute(f"SET temp_directory='{temp_dir}'")
    return con


def _enable_s3(con, region):
    con.execute("INSTALL httpfs; LOAD httpfs; INSTALL aws; LOAD aws")
    con.execute(f"CREATE SECRET IF NOT EXISTS tg_s3 (TYPE s3, PROVIDER credential_chain, REGION '{region}')")


def _base(sel: str, where: dict, extra_not_null: list[str], params: list) -> str:
    cond = where_sql(where, params)
    nn = "".join(f" AND {e} IS NOT NULL" for e in extra_not_null)
    return (f"SELECT event_uid, event_time, line_no, src_ip, dst_ip, user{sel} FROM ev WHERE {cond}{nn} "
            f"QUALIFY row_number() OVER (PARTITION BY record_hash ORDER BY line_no) = 1")


def _keys(rule: Rule):
    exprs = [field_sql(g) for g in rule.group_by]
    sel = "".join(f", {e} AS k{i}" for i, e in enumerate(exprs))
    kcols = [f"k{i}" for i in range(len(exprs))]
    def kjson(prefix=""):
        if not kcols:
            return "NULL"
        return "to_json(struct_pack(" + ", ".join(f'"{g}" := {prefix}k{i}' for i, g in enumerate(rule.group_by)) + "))"
    return exprs, sel, kcols, kjson


def evidence_sql(rule: Rule, params: list) -> str:
    """SQL yielding (fkey, keys, event_uid, event_time, step, metric, src_ip, dst_ip, user)."""
    if rule.type == "event":
        exprs, sel, kcols, kjson = _keys(rule)
        base = _base(sel, rule.where, exprs, params)
        if kcols or rule.bucket:
            b = f"time_bucket({interval_sql(rule.bucket)}, event_time)::VARCHAR" if rule.bucket else "''"
            fkey = f"coalesce({kjson()}, '') || '|' || {b}"
        else:
            fkey = "event_uid"
        return (f"WITH base AS ({base}) SELECT {fkey} AS fkey, {kjson()} AS keys, event_uid, event_time, "
                f"'match' AS step, 1.0 AS metric, src_ip, dst_ip, user FROM base")

    if rule.type == "threshold":
        exprs, sel, kcols, kjson = _keys(rule)
        th = rule.threshold
        if th.count is not None:
            agg, val, vsel = "count(*)", float(th.count), ""
        elif th.distinct:
            agg, val, vsel = "count(DISTINCT v)", th.value, f", {field_sql(th.distinct)} AS v"
        else:
            agg, val, vsel = "sum(v)", th.value, f", {field_sql(th.sum)} AS v"
        base = _base(sel + vsel, rule.where, exprs, params)
        w = interval_sql(rule.window)
        part = ", ".join(kcols)
        on = " AND ".join(f"b.{k} = s.{k}" for k in kcols)
        return f"""
        WITH base AS ({base}),
        win AS (SELECT *, {agg} OVER (PARTITION BY {part} ORDER BY event_time
                RANGE BETWEEN {w} PRECEDING AND CURRENT ROW) AS agg FROM base),
        hits AS (SELECT *, CASE WHEN event_time - lag(event_time) OVER (PARTITION BY {part} ORDER BY event_time, line_no)
                 <= {w} THEN 0 ELSE 1 END AS brk FROM win WHERE agg >= {val}),
        isl AS (SELECT *, sum(brk) OVER (PARTITION BY {part} ORDER BY event_time, line_no ROWS UNBOUNDED PRECEDING) AS grp FROM hits),
        spans AS (SELECT {part}, grp, min(event_time) - {w} AS s0, max(event_time) AS s1, max(agg) AS peak
                  FROM isl GROUP BY ALL)
        SELECT {kjson('s.')} || '|' || s.s0::VARCHAR AS fkey,
               {kjson('s.')} AS keys, b.event_uid, b.event_time, 'window' AS step,
               s.peak::DOUBLE AS metric, b.src_ip, b.dst_ip, b.user
        FROM spans s JOIN base b ON {on} AND b.event_time BETWEEN s.s0 AND s.s1"""

    if rule.type == "periodic":
        # beaconing: per key and time bucket, many events at near-constant intervals (low coefficient of variation)
        exprs, sel, kcols, kjson = _keys(rule)
        base = _base(sel, rule.where, exprs, params)
        part = ", ".join(kcols)
        b = interval_sql(rule.bucket)
        p = rule.periodic
        return f"""
        WITH base AS ({base}),
        g AS (SELECT *, time_bucket({b}, event_time) AS bk,
                     epoch(event_time - lag(event_time) OVER (PARTITION BY {part}, time_bucket({b}, event_time)
                                                              ORDER BY event_time, line_no)) AS gap FROM base),
        stats AS (SELECT {part}, bk, count(*) AS n, avg(gap) AS mean_gap, stddev_pop(gap) AS sd_gap FROM g GROUP BY ALL
                  HAVING count(*) >= {int(p.min_count)} AND avg(gap) >= epoch({interval_sql(p.min_interval)})
                     AND stddev_pop(gap) / avg(gap) <= {float(p.max_cv)})
        SELECT {kjson('s.')} || '|' || s.bk::VARCHAR AS fkey, {kjson('s.')} AS keys, g.event_uid, g.event_time,
               'beacon' AS step, s.n::DOUBLE AS metric, g.src_ip, g.dst_ip, g.user
        FROM stats s JOIN g ON {' AND '.join(f'g.{k} = s.{k}' for k in kcols)} AND g.bk = s.bk"""

    # sequence: steps joined on equal key values, ordered in time, all within `within`
    w = interval_sql(rule.within)
    ctes, n = [], len(rule.steps)
    for i, st in enumerate(rule.steps):
        ks = field_sql(st.key)
        ctes.append(f"b{i} AS ({_base(f', {ks} AS k', st.where, [ks], params)})")
    chain = "SELECT b0.k, b0.event_uid AS u0, b0.event_time AS t0"
    joins = " FROM b0"
    for i in range(1, n):
        chain += f", b{i}.event_uid AS u{i}, b{i}.event_time AS t{i}"
        joins += (f" JOIN b{i} ON b{i}.k = b0.k AND b{i}.event_time >= b{i - 1}.event_time "
                  f"AND b{i}.event_time <= b0.event_time + {w}")
    last = n - 1
    having = " AND ".join(f"count(DISTINCT u{i}) >= {st.min_count}" for i, st in enumerate(rule.steps))
    groups = (f"SELECT k, u{last} AS anchor FROM chain GROUP BY k, u{last} HAVING {having}")
    unions = " UNION ALL ".join(
        f"SELECT c.k, c.u{last} AS anchor, c.u{i} AS uid, '{st.name}' AS step FROM chain c" for i, st in enumerate(rule.steps))
    allb = " UNION ALL ".join(f"SELECT event_uid, event_time, src_ip, dst_ip, user FROM b{i}" for i in range(n))
    return f"""
    WITH {', '.join(ctes)},
    chain AS ({chain}{joins}),
    ok AS ({groups}),
    ev_steps AS (SELECT DISTINCT e.* FROM ({unions}) e JOIN ok USING (k, anchor)),
    allb AS (SELECT DISTINCT * FROM ({allb}))
    SELECT to_json(struct_pack(key := e.k)) || '|' || e.anchor AS fkey, to_json(struct_pack(key := e.k)) AS keys,
           e.uid AS event_uid, a.event_time, e.step, {n}.0 AS metric, a.src_ip, a.dst_ip, a.user
    FROM ev_steps e JOIN allb a ON a.event_uid = e.uid"""


def run(ruleset: RuleSet, events_glob, out: str, con=None, log=print, region="ap-south-1", time_from: str | None = None) -> dict:
    """time_from: only events at or after this time (incremental runs: new batch plus rule lookback)."""
    con = con or connect()
    if "s3://" in str(events_glob) or out.startswith("s3://"):
        _enable_s3(con, region)
    con.execute(f"CREATE OR REPLACE VIEW ev AS SELECT * REPLACE (event_time::TIMESTAMPTZ AS event_time) FROM read_parquet({parquet_src(events_glob)}, union_by_name=true)"
                + (f" WHERE event_time::TIMESTAMPTZ >= TIMESTAMPTZ '{time_from}'" if time_from else ""))
    con.execute(f"""CREATE OR REPLACE TEMP TABLE stalls AS SELECT event_time FROM ev GROUP BY 1
                    HAVING count(*) >= {STALL_MIN_EVENTS}""")
    con.execute("CREATE OR REPLACE TEMP TABLE evidence (rule_id VARCHAR, fkey VARCHAR, keys VARCHAR, event_uid VARCHAR, "
                "event_time TIMESTAMPTZ, step VARCHAR, metric DOUBLE, src_ip VARCHAR, dst_ip VARCHAR, user VARCHAR)")
    summary, status = {}, {}
    present = {r[0] for r in con.execute("SELECT DISTINCT category FROM ev").fetchall()}
    try:  # raw field names in the data: one row per distinct field layout is enough
        fields = {r[0] for r in con.execute(
            "SELECT DISTINCT unnest(map_keys(a)) FROM (SELECT any_value(attrs) AS a FROM ev GROUP BY schema_fp)").fetchall()}
    except duckdb.Error:  # data parsed before layouts were fingerprinted
        fields = {r[0] for r in con.execute("SELECT DISTINCT unnest(map_keys(attrs)) FROM (SELECT attrs FROM ev LIMIT 200000)").fetchall()}
    for rule in ruleset.rules:
        if not rule.enabled:
            continue
        need = required_categories(rule)
        if need is not None and not (need & present):  # the data has no events this rule could ever match
            status[rule.id] = {"status": "not_applicable", "findings": 0, "needs": sorted(need)}
            continue
        if rule.requires_fields and not (set(rule.requires_fields) & fields):  # reads fields this data does not have
            status[rule.id] = {"status": "not_applicable", "findings": 0, "needs": rule.requires_fields[:5]}
            continue
        params: list = []
        t0 = dt.datetime.now()
        try:
            sql = evidence_sql(rule, params)
            con.execute(f"INSERT INTO evidence SELECT '{rule.id}', * FROM ({sql})", params)
        except duckdb.Error as e:  # one broken rule (e.g. an imported regex) must not stop the others
            status[rule.id] = {"status": "error", "findings": 0, "error": str(e).splitlines()[0][:200]}
            log(f"  {rule.id:<12}   error  {str(e).splitlines()[0][:120]}")
            continue
        n = con.execute(f"SELECT count(DISTINCT fkey) FROM evidence WHERE rule_id = '{rule.id}'").fetchall()[0][0]
        summary[rule.id] = n
        status[rule.id] = {"status": "fired" if n else "no_match", "findings": n}
        if n or len(ruleset.rules) <= 60:
            log(f"  {rule.id:<12} {n:>7} findings  {(dt.datetime.now() - t0).total_seconds():.1f}s  {rule.title}")

    meta = [(r.id, r.version, r.fingerprint, r.title, r.severity, r.stage, r.type,
             json.dumps([t.model_dump() for t in r.attack])) for r in ruleset.rules if r.enabled]
    con.execute("CREATE OR REPLACE TEMP TABLE rule_meta (rule_id VARCHAR, rule_version INT, rule_fingerprint VARCHAR, "
                "title VARCHAR, severity VARCHAR, stage VARCHAR, rule_type VARCHAR, attack VARCHAR)")
    con.executemany("INSERT INTO rule_meta VALUES (?, ?, ?, ?, ?, ?, ?, ?)", meta)
    con.execute(f"""
    CREATE OR REPLACE TEMP TABLE findings AS
    SELECT substr(sha256(e.rule_id || ':' || m.rule_version || ':' || e.fkey), 1, 24) AS finding_id,
           e.rule_id, m.rule_version, m.rule_fingerprint, m.title, m.severity, m.stage, m.rule_type,
           m.attack, any_value(e.keys) AS keys,
           min(e.event_time) AS first_time, max(e.event_time) AS last_time,
           count(DISTINCT e.event_uid) AS event_count, max(e.metric) AS metric,
           list_sort(list_distinct(list(e.src_ip) FILTER (e.src_ip IS NOT NULL)))[1:25] AS src_ips,
           list_sort(list_distinct(list(e.dst_ip) FILTER (e.dst_ip IS NOT NULL)))[1:25] AS dst_ips,
           list_sort(list_distinct(list(e.user) FILTER (e.user IS NOT NULL)))[1:25] AS users,
           count(DISTINCT e.src_ip) AS src_ip_count, count(DISTINCT e.dst_ip) AS dst_ip_count,
           count(DISTINCT e.user) AS user_count,
           avg(CASE WHEN s.event_time IS NULL THEN 0 ELSE 1 END) AS stall_fraction,
           CASE WHEN avg(CASE WHEN s.event_time IS NULL THEN 0 ELSE 1 END) > 0.5 THEN 'degraded_clock_stall'
                ELSE 'ok' END AS time_reliability,
           'engine_detection' AS provenance, '{ruleset.fingerprint}' AS ruleset_fingerprint
    FROM evidence e JOIN rule_meta m USING (rule_id) LEFT JOIN stalls s ON s.event_time = e.event_time
    GROUP BY e.rule_id, e.fkey, m.rule_version, m.rule_fingerprint, m.title, m.severity, m.stage, m.rule_type, m.attack""")
    con.execute("""CREATE OR REPLACE TEMP TABLE finding_evidence AS
        SELECT substr(sha256(e.rule_id || ':' || m.rule_version || ':' || e.fkey), 1, 24) AS finding_id,
               e.event_uid, e.step, e.event_time
        FROM evidence e JOIN rule_meta m USING (rule_id)
        QUALIFY row_number() OVER (PARTITION BY finding_id ORDER BY e.event_time, e.event_uid) <= 500""")
    out = out.rstrip("/")
    if not out.startswith("s3://"):
        import os
        os.makedirs(out, exist_ok=True)
    con.execute(f"COPY findings TO '{out}/findings.parquet' (FORMAT parquet, COMPRESSION zstd)")
    con.execute(f"COPY finding_evidence TO '{out}/finding_evidence.parquet' (FORMAT parquet, COMPRESSION zstd)")
    import json as _json
    with (open if not out.startswith("s3://") else _s3_open)(f"{out}/rule_status.json", "w") as fh:
        fh.write(_json.dumps(status))
    return {"ruleset_fingerprint": ruleset.fingerprint, "attack_version": ruleset.attack_version, "findings": summary,
            "rule_status": status}


class _s3_open:
    """Minimal text writer to S3 for small JSON artifacts."""

    def __init__(self, uri, mode="w"):
        self.uri, self.buf = uri, []

    def __enter__(self):
        return self

    def write(self, s):
        self.buf.append(s)

    def __exit__(self, *a):
        import boto3
        b, k = self.uri[5:].split("/", 1)
        import os
        boto3.client("s3", region_name=os.environ.get("AWS_REGION", "ap-south-1")).put_object(Bucket=b, Key=k, Body="".join(self.buf).encode())
