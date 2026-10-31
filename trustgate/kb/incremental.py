"""Incremental analysis over a growing case: each new batch (e.g. another 5 GB file) is parsed on
its own, then joined to everything already known through the knowledge base.

Per revision N the lake holds, under <base>/rev-N/:
  findings.parquet, finding_evidence.parquet   all detections so far (stable ids across revisions)
  kb/entities.parquet   every tracked IP / account: first/last seen, counts, first_rev (when it appeared)
  kb/edges.parquet      observed relationships (login, flow, config change) with counts, interval, evidence, first_rev
  kb/sources.parquet    per-file time range and devices, used to say which files relate

Correctness across batches:
- Detection re-reads only the new batch plus a lookback = the longest rule window, extended back to the
  start of any detection that is still open. A brute force that starts in batch 4 and ends in batch 5
  is recomputed with the same span start, so it keeps its id and fires once. Late events move the
  lookback back to cover them.
- The knowledge base counts each source exactly once: new sources are scanned for every tracked
  entity; older sources are scanned only for entities that became tracked in this revision, and only
  for relationships that involve one of them (so nothing already counted is counted again).
- A changed rule set forces a full recompute; first-seen revisions are still carried over.
"""
import datetime as dt

from ..detection import engine
from ..detection.rules import RuleSet, lookback_parts
from ..graph import build as g
from ..ingest import semantics
from .index import segments_for

KEYS = "etype, a, b, detail"


def _rows(con, sql, params=None):
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def _ts(x) -> str:
    return x if isinstance(x, str) else x.isoformat()


def _scan(con, name, globs, cond):
    src = engine.parquet_src(globs)
    con.execute(f"""CREATE OR REPLACE TEMP TABLE {name} AS
        SELECT event_uid, event_time::TIMESTAMPTZ AS event_time, source_id, category, activity, outcome, user, src_ip, dst_ip,
               dst_port, protocol, bytes_out, bytes_in, device, action, message, src_country
        FROM read_parquet({src}, union_by_name=true) WHERE {cond}
        QUALIFY row_number() OVER (PARTITION BY record_hash ORDER BY line_no) = 1""")


def _edges_sql(x: str, extra_auth="TRUE", extra_flow="TRUE", extra_conf="TRUE"):
    return f"""
      SELECT 'AUTH' AS etype, src_ip AS a, user AS b, coalesce(outcome, 'unknown') AS detail, NULL AS action, NULL AS protocol,
             any_value(src_ip) AS via_ip, count(*) AS count, min(event_time) AS first, max(event_time) AS last,
             0::BIGINT AS bytes_out, 0::BIGINT AS bytes_in, list(event_uid ORDER BY event_time)[1:10] AS evidence
      FROM {x} WHERE category IN ('authentication', 'vpn') AND activity = 'login'
        AND user IN (SELECT u FROM t_user) AND src_ip IN (SELECT ip FROM t_ip) AND ({extra_auth}) GROUP BY ALL
      UNION ALL
      SELECT 'FLOW', src_ip, dst_ip, coalesce(dst_port::VARCHAR, '-'), NULL, any_value(protocol), any_value(src_ip), count(*),
             min(event_time), max(event_time), coalesce(sum(bytes_out), 0), coalesce(sum(bytes_in), 0),
             list(event_uid ORDER BY event_time)[1:10]
      FROM {x} WHERE category = 'network' AND src_ip IN (SELECT ip FROM t_ip) AND dst_ip IN (SELECT ip FROM t_ip)
        AND ({extra_flow}) GROUP BY src_ip, dst_ip, dst_port
      UNION ALL
      SELECT 'CONF', user, coalesce(device, 'unknown'), coalesce(message, ''), any_value(action), NULL, any_value(src_ip), count(*),
             min(event_time), max(event_time), 0, 0, list(event_uid ORDER BY event_time)[1:10]
      FROM {x} WHERE category IN ('configuration', 'account_management') AND user IN (SELECT u FROM t_user)
        AND ({extra_conf}) GROUP BY user, device, message"""


def _entity_sql(x: str, ip_table="t_ip", user_table="t_user"):
    return f"""
      SELECT kind, value, count(*) AS events, min(event_time) AS first, max(event_time) AS last,
             any_value(country) AS country, count(*) FILTER (category = 'intrusion') AS alerts_intrusion,
             count(*) FILTER (category = 'malware') AS alerts_malware
      FROM (SELECT 'ip' AS kind, src_ip AS value, event_time, src_country AS country, category FROM {x} WHERE src_ip IN (SELECT ip FROM {ip_table})
            UNION ALL SELECT 'ip', dst_ip, event_time, NULL, category FROM {x} WHERE dst_ip IN (SELECT ip FROM {ip_table})
            UNION ALL SELECT 'user', user, event_time, NULL, category FROM {x} WHERE user IN (SELECT u FROM {user_table}))
      GROUP BY kind, value"""


def update_kb(con, new_globs, old_globs, findings_dir, prev_kb, rev, out_kb, rebuild=False) -> dict:
    """Upsert entities/relationships for the entities that detections reference."""
    con.execute(f"""CREATE OR REPLACE TEMP TABLE tracked AS
        SELECT DISTINCT 'ip' AS kind, unnest(list_concat(coalesce(src_ips, []), coalesce(dst_ips, []))) AS value FROM read_parquet('{findings_dir}/findings.parquet')
        UNION SELECT DISTINCT 'user', unnest(users) FROM read_parquet('{findings_dir}/findings.parquet')""")
    if prev_kb:  # the knowledge base never forgets: once tracked, an entity stays tracked
        con.execute(f"""INSERT INTO tracked SELECT kind, value FROM read_parquet('{prev_kb}/entities.parquet') WHERE tracked
                        EXCEPT SELECT kind, value FROM tracked""")
    con.execute("CREATE OR REPLACE TEMP TABLE t_ip AS SELECT value AS ip FROM tracked WHERE kind = 'ip'")
    con.execute("CREATE OR REPLACE TEMP TABLE t_user AS SELECT value AS u FROM tracked WHERE kind = 'user'")
    if prev_kb:
        con.execute(f"CREATE OR REPLACE TEMP TABLE pe AS SELECT * FROM read_parquet('{prev_kb}/entities.parquet')")
        con.execute(f"CREATE OR REPLACE TEMP TABLE pg AS SELECT * FROM read_parquet('{prev_kb}/edges.parquet')")
        con.execute(f"CREATE OR REPLACE TEMP TABLE ps AS SELECT * FROM read_parquet('{prev_kb}/sources.parquet')")
    else:
        con.execute("""CREATE OR REPLACE TEMP TABLE pe (kind VARCHAR, value VARCHAR, events BIGINT, first TIMESTAMPTZ,
            last TIMESTAMPTZ, country VARCHAR, alerts_intrusion BIGINT, alerts_malware BIGINT, first_rev INT, last_rev INT,
            tracked BOOLEAN)""")
        con.execute("""CREATE OR REPLACE TEMP TABLE pg (etype VARCHAR, a VARCHAR, b VARCHAR, detail VARCHAR, action VARCHAR,
            protocol VARCHAR, via_ip VARCHAR, count BIGINT, first TIMESTAMPTZ, last TIMESTAMPTZ, bytes_out BIGINT,
            bytes_in BIGINT, evidence VARCHAR[], first_rev INT, last_rev INT)""")
        con.execute("""CREATE OR REPLACE TEMP TABLE ps (source_id VARCHAR, first TIMESTAMPTZ, last TIMESTAMPTZ,
            devices VARCHAR[], events BIGINT, first_rev INT)""")
    # entities that became tracked in this revision (rebuild: treat every source as new)
    con.execute("""CREATE OR REPLACE TEMP TABLE n_ip AS SELECT ip FROM t_ip WHERE ip NOT IN (SELECT value FROM pe WHERE kind='ip' AND tracked)""")
    con.execute("""CREATE OR REPLACE TEMP TABLE n_user AS SELECT u FROM t_user WHERE u NOT IN (SELECT value FROM pe WHERE kind='user' AND tracked)""")

    _scan(con, "xa", new_globs, "src_ip IN (SELECT ip FROM t_ip) OR dst_ip IN (SELECT ip FROM t_ip) OR user IN (SELECT u FROM t_user)")
    parts_e = [_edges_sql("xa")]
    parts_n = [_entity_sql("xa")]
    backfill = {"sources": 0, "indexed": 0, "segments": 0}
    files = []
    if old_globs and not rebuild:
        # history for newly relevant entities: use each older file's entity index to read only the
        # segments that mention them; files without an index fall back to a full scan of that file
        for gl in old_globs:
            segs = segments_for(con, gl, "n_ip", "n_user")
            backfill["sources"] += 1
            if segs is None:
                files.append(gl)
            else:
                backfill["indexed"] += 1
                files += segs
        backfill["segments"] = len(files)
    if files:
        _scan(con, "xb", files, "src_ip IN (SELECT ip FROM n_ip) OR dst_ip IN (SELECT ip FROM n_ip) OR user IN (SELECT u FROM n_user)")
        parts_e.append(_edges_sql("xb", "src_ip IN (SELECT ip FROM n_ip) OR user IN (SELECT u FROM n_user)",
                                  "src_ip IN (SELECT ip FROM n_ip) OR dst_ip IN (SELECT ip FROM n_ip)", "user IN (SELECT u FROM n_user)"))
        parts_n.append(_entity_sql("xb", "n_ip", "n_user"))
    carry = "" if rebuild else "UNION ALL BY NAME SELECT * EXCLUDE (first_rev, last_rev) FROM pg"
    con.execute(f"""CREATE OR REPLACE TEMP TABLE kg AS
        SELECT {KEYS}, any_value(action) AS action, any_value(protocol) AS protocol, any_value(via_ip) AS via_ip,
               sum(count) AS count, min(first) AS first, max(last) AS last, sum(bytes_out) AS bytes_out, sum(bytes_in) AS bytes_in,
               flatten(list(evidence))[1:10] AS evidence
        FROM ({' UNION ALL '.join(parts_e)} {carry}) GROUP BY {KEYS}""")
    con.execute(f"""CREATE OR REPLACE TEMP TABLE kg2 AS SELECT k.*, coalesce(p.first_rev, {rev}) AS first_rev,
               CASE WHEN p.first_rev IS NULL OR k.count <> p.count THEN {rev} ELSE p.last_rev END AS last_rev
        FROM kg k LEFT JOIN pg p USING (etype, a, b, detail)""")
    carry_e = "" if rebuild else "UNION ALL BY NAME SELECT kind, value, events, first, last, country, alerts_intrusion, alerts_malware FROM pe"
    con.execute(f"""CREATE OR REPLACE TEMP TABLE ke AS
        SELECT kind, value, sum(events) AS events, min(first) AS first, max(last) AS last, any_value(country) AS country,
               sum(alerts_intrusion) AS alerts_intrusion, sum(alerts_malware) AS alerts_malware
        FROM ({' UNION ALL '.join(parts_n)} {carry_e}) GROUP BY kind, value""")
    con.execute(f"""CREATE OR REPLACE TEMP TABLE ke2 AS SELECT k.*, coalesce(p.first_rev, {rev}) AS first_rev,
               CASE WHEN p.first_rev IS NULL OR k.events <> p.events THEN {rev} ELSE p.last_rev END AS last_rev,
               EXISTS (SELECT 1 FROM tracked t WHERE t.kind = k.kind AND t.value = k.value) AS tracked
        FROM ke k LEFT JOIN pe p USING (kind, value)""")
    # per-file stats (new files only; older ones carried over)
    con.execute(f"""CREATE OR REPLACE TEMP TABLE ks AS
        SELECT source_id, min(event_time)::TIMESTAMPTZ AS first, max(event_time)::TIMESTAMPTZ AS last,
               list_distinct(list(device) FILTER (device IS NOT NULL))[1:10] AS devices, count(*) AS events, {rev} AS first_rev
        FROM read_parquet({engine.parquet_src(new_globs)}, union_by_name=true) GROUP BY source_id
        UNION ALL BY NAME SELECT * FROM ps""")
    con.execute("CREATE OR REPLACE TEMP TABLE ks2 AS SELECT * FROM ks QUALIFY row_number() OVER (PARTITION BY source_id ORDER BY first_rev) = 1")
    for t, f in (("ke2", "entities"), ("kg2", "edges"), ("ks2", "sources")):
        con.execute(f"COPY {t} TO '{out_kb}/{f}.parquet' (FORMAT parquet, COMPRESSION zstd)")

    stats = _rows(con, f"""SELECT (SELECT count(*) FROM ke2 WHERE tracked) AS entities, (SELECT count(*) FROM ke2 WHERE tracked AND first_rev = {rev}) AS entities_new,
                                  (SELECT count(*) FROM kg2) AS edges, (SELECT count(*) FROM kg2 WHERE first_rev = {rev}) AS edges_new""")[0]
    ips = _rows(con, """SELECT value AS addr, country, alerts_intrusion AS source_alerts_ips, alerts_malware AS source_alerts_virus,
                               events AS events_as_source, first::VARCHAR AS first_seen, last::VARCHAR AS last_seen, first_rev
                        FROM ke2 WHERE tracked AND kind = 'ip'""")
    for n in ips:
        n["scope"] = semantics.zone_of_ip(n["addr"]) or "external"
        n["net24"] = ".".join(n["addr"].split(".")[:3]) + ".0/24" if n["addr"].count(".") == 3 else None
    auth = _rows(con, """SELECT a AS src_ip, b AS user, detail AS outcome, count, first::VARCHAR AS first, last::VARCHAR AS last,
                                evidence, first_rev FROM kg2 WHERE etype = 'AUTH'""")
    flows = _rows(con, """SELECT * EXCLUDE (rk) FROM (SELECT a AS src_ip, b AS dst_ip, TRY_CAST(detail AS INT) AS dst_port, protocol, count,
                                 bytes_out, bytes_in, first::VARCHAR AS first, last::VARCHAR AS last, evidence, first_rev,
                                 row_number() OVER (PARTITION BY a ORDER BY count DESC) AS rk FROM kg2 WHERE etype = 'FLOW') WHERE rk <= 50""")
    configured = _rows(con, """SELECT a AS user, b AS device, action, detail AS message, first::VARCHAR AS time,
                                      evidence[1] AS event_uid, via_ip AS src_ip, count, first_rev FROM kg2 WHERE etype = 'CONF'""")
    sources = _rows(con, "SELECT source_id, first::VARCHAR AS first, last::VARCHAR AS last, devices, events, first_rev FROM ks2")
    stats["backfill"] = backfill
    return {"ips": ips, "auth": auth, "flows": flows, "configured": configured, "sources": sources, "stats": stats}


def merge_rule_status(rules, findings, now: dict, before: dict) -> dict:
    """Per rule across all revisions: fired (has detections) > no_match (ran on applicable data) > error > not_applicable."""
    count = {}
    for f in findings:
        count[f["rule_id"]] = count.get(f["rule_id"], 0) + 1
    out = {}
    for r in rules.rules:
        a, b = now.get(r.id, {}), before.get(r.id, {})
        sts = {a.get("status"), b.get("status")}
        if count.get(r.id):
            st = "fired"
        elif "no_match" in sts or "fired" in sts:
            st = "no_match"
        elif "error" in sts:
            st = "error"
        else:
            st = "not_applicable"
        out[r.id] = {"status": st, "findings": count.get(r.id, 0)}
        if st == "error":
            out[r.id]["error"] = a.get("error") or b.get("error")
        if st == "not_applicable":
            out[r.id]["needs"] = a.get("needs") or b.get("needs")
    return out


def relate_sources(sources: list[dict], names: dict) -> list[dict]:
    out = []
    for s in sources:
        rel = []
        for o in sources:
            if o["source_id"] == s["source_id"]:
                continue
            overlap = s["first"] <= o["last"] and o["first"] <= s["last"]
            shared = sorted(set(s["devices"] or []) & set(o["devices"] or []))
            if overlap or shared:
                why = " and ".join(x for x in (f"same device {', '.join(shared[:3])}" if shared else "",
                                                "overlapping time range" if overlap else "") if x)
                rel.append({"source_id": o["source_id"], "filename": names.get(o["source_id"], o["source_id"]), "reason": why})
        out.append({**s, "filename": names.get(s["source_id"], s["source_id"]), "related": rel})
    return out


def analyze(con, rules: RuleSet, globs_by_source: dict, new_ids: list, names: dict, rev: int, out_base: str,
            prev: dict | None = None, log=print) -> dict:
    """prev: {"base": prior rev dir, "snapshot": prior graph dict, "ruleset": fingerprint} or None."""
    all_globs = list(globs_by_source.values())
    new_globs = [globs_by_source[i] for i in new_ids]
    old_globs = [g_ for i, g_ in globs_by_source.items() if i not in new_ids]
    rebuild = prev is None or prev.get("ruleset") != rules.fingerprint
    fdir, kbdir = out_base, f"{out_base}/kb"
    if not out_base.startswith("s3://"):
        import os
        os.makedirs(kbdir, exist_ok=True)
    time_from = None
    if rebuild:
        log(f"rev {rev}: full analysis over {len(all_globs)} source(s)")
        status = engine.run(rules, all_globs, fdir, con=con, log=log)["rule_status"]
    else:
        lb, bucket = lookback_parts(rules)
        batch_min = _rows(con, f"SELECT min(event_time)::TIMESTAMPTZ AS t FROM read_parquet({engine.parquet_src(new_globs)}, union_by_name=true)")[0]["t"]
        # only window/sequence detections can still be "open" across the batch boundary
        span_ids = [r.id for r in rules.rules if r.type in ("threshold", "sequence")] or [""]
        open_min = _rows(con, f"""SELECT min(first_time) AS t FROM read_parquet('{prev['base']}/findings.parquet')
                                  WHERE rule_id IN (SELECT unnest(?::VARCHAR[]))
                                    AND last_time >= TIMESTAMPTZ '{_ts(batch_min)}' - INTERVAL {lb} SECOND""", [span_ids])[0]["t"]
        cands = [x - dt.timedelta(seconds=lb) for x in (batch_min, open_min) if x is not None]
        if bucket:  # bucketed rules recompute the bucket the batch starts in, from that bucket's start
            cands.append(_rows(con, f"SELECT time_bucket(INTERVAL {bucket} SECOND, TIMESTAMPTZ '{_ts(batch_min)}') AS t")[0]["t"])
        start = min(cands)
        time_from = _ts(start)
        log(f"rev {rev}: incremental analysis; new {len(new_globs)} source(s), lookback from {time_from}")
        status = engine.run(rules, all_globs, f"{fdir}/_partial", con=con, log=log, time_from=time_from)["rule_status"]
        for f, key in (("findings", "finding_id"), ("finding_evidence", "finding_id")):
            con.execute(f"""COPY (SELECT * FROM read_parquet('{prev['base']}/{f}.parquet')
                                  WHERE {key} NOT IN (SELECT finding_id FROM read_parquet('{fdir}/_partial/findings.parquet'))
                                  UNION ALL BY NAME SELECT * FROM read_parquet('{fdir}/_partial/{f}.parquet'))
                            TO '{fdir}/{f}.parquet' (FORMAT parquet, COMPRESSION zstd)""")
    has_kb = prev is not None and prev.get("ruleset") is not None  # older revisions predate the knowledge base
    kb = update_kb(con, all_globs if rebuild else new_globs, [] if rebuild else old_globs, fdir,
                   f"{prev['base']}/kb" if has_kb else None, rev, kbdir, rebuild=rebuild)
    graph = g.build(all_globs, fdir, con=con, kb=kb, prev=(prev or {}).get("snapshot"), rev=rev, bundle_from=time_from)
    graph["sources"] = relate_sources(kb["sources"], names)
    graph["rule_status"] = merge_rule_status(rules, graph["findings"], status,
                                             ((prev or {}).get("snapshot") or {}).get("rule_status", {}) if not rebuild else {})
    graph["ruleset"] = rules.fingerprint
    prev_growth = ((prev or {}).get("snapshot") or {}).get("growth", [])
    graph["growth"] = prev_growth + [{
        "revision": rev, "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "mode": "full" if rebuild else "incremental", "lookback_from": time_from,
        "files_added": [names.get(i, i) for i in new_ids],
        "events_added": sum(s["events"] for s in kb["sources"] if s["source_id"] in new_ids),
        "entities": kb["stats"]["entities"], "entities_new": kb["stats"]["entities_new"],
        "relationships": kb["stats"]["edges"], "relationships_new": kb["stats"]["edges_new"],
        "detections": len(graph["findings"]), "detections_new": sum(f["first_rev"] == rev for f in graph["findings"]),
        "incidents": len(graph["incidents"]), "incidents_new": sum(i["change"] == "new" and i["change_rev"] == rev for i in graph["incidents"]),
        "backfill": kb["stats"]["backfill"],
        "incidents_grew": sum(i["change"] in ("grew", "merged") and i["change_rev"] == rev for i in graph["incidents"]),
    }]
    return graph
