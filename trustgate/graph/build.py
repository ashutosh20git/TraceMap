"""Build the alert/entity relationship graph from findings and load it into Neo4j.

Only entities that appear in findings are expanded, so the graph stays bounded
no matter how large the event corpus is. Every relationship carries its claim,
evidence sample, counts and a decision label:

  observed                aggregated directly from source records (AUTH, FLOW, CONFIGURED)
  contextual_association  two findings share an entity within a time gap (RELATED)
  pivot                   a finding's target host is the source of a later finding (RELATED)

Shared account/IP/time is never treated as proof of one incident; incident
nodes are explicitly `candidate` groupings with their basis listed.
"""
import json
import math
import os

from neo4j import GraphDatabase

from ..detection.engine import _enable_s3, connect, parquet_src

GRAPH_VERSION = "g1"
LINK_GAP_HOURS = 72
# an entity shared by more findings than this (e.g. the firewall's own management IP) is a hub:
# it is kept as a node but never used to link findings into one incident
HUB_MAX_FINDINGS = 25
SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# for these rules the user list is "attempted usernames", not accounts that acted
TARGET_ONLY_USER_RULES = ("TG-AUTH-001", "TG-AUTH-002")


def _rows(con, sql, params=None):
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def build(events_glob, findings_dir: str, con=None, region="ap-south-1", max_flows_per_ip=50) -> dict:
    con = con or connect()
    if "s3://" in str(events_glob) + findings_dir:
        _enable_s3(con, region)
    fd = findings_dir.rstrip("/")
    con.execute(f"CREATE OR REPLACE VIEW ev AS SELECT * REPLACE (event_time::TIMESTAMPTZ AS event_time) FROM read_parquet({parquet_src(events_glob)}, union_by_name=true)")
    con.execute(f"CREATE OR REPLACE TEMP TABLE f AS SELECT * FROM read_parquet('{fd}/findings.parquet')")
    con.execute(f"CREATE OR REPLACE TEMP TABLE fe AS SELECT * FROM read_parquet('{fd}/finding_evidence.parquet')")

    # finding -> entity with role
    con.execute(f"""CREATE OR REPLACE TEMP TABLE fent AS
        SELECT finding_id, rule_id, first_time, last_time, 'ip' AS kind, unnest(src_ips) AS value, 'source' AS role FROM f
        UNION ALL SELECT finding_id, rule_id, first_time, last_time, 'ip', unnest(dst_ips), 'target' FROM f
        UNION ALL SELECT finding_id, rule_id, first_time, last_time, 'user', unnest(users),
               CASE WHEN rule_id IN {TARGET_ONLY_USER_RULES} THEN 'targeted_account' ELSE 'account' END FROM f""")
    ips = [r["value"] for r in _rows(con, "SELECT DISTINCT value FROM fent WHERE kind='ip'")]
    con.execute("CREATE OR REPLACE TEMP TABLE ent_ip AS SELECT DISTINCT value AS ip FROM fent WHERE kind='ip'")
    con.execute("""CREATE OR REPLACE TEMP TABLE ent_user AS SELECT DISTINCT value AS u FROM fent
                   WHERE kind='user' AND role='account'""")

    # one bounded scan of the corpus for everything the graph needs about these entities
    con.execute("""CREATE OR REPLACE TEMP TABLE sub AS
        SELECT event_uid, event_time, event_type, event_subtype, event_code, action, outcome, user, src_ip, dst_ip,
               dst_port, protocol, rule_name, message, bytes_out, bytes_in, device,
               src_zone AS src_role, dst_zone AS dst_role, src_country, category, activity, target_account
        FROM ev WHERE (src_ip IN (SELECT ip FROM ent_ip) OR dst_ip IN (SELECT ip FROM ent_ip)
                       OR user IN (SELECT u FROM ent_user))
        QUALIFY row_number() OVER (PARTITION BY record_hash ORDER BY line_no) = 1""")

    ip_nodes = _rows(con, """
        SELECT ip AS addr,
               CASE WHEN ip LIKE '10.%' OR ip LIKE '192.168.%' OR regexp_matches(ip, '^172\\.(1[6-9]|2\\d|3[01])\\.')
                    THEN 'internal' ELSE 'external' END AS scope,
               regexp_extract(ip, '^(\\d+\\.\\d+\\.\\d+)\\.', 1) || '.0/24' AS net24,
               (SELECT any_value(src_country) FROM sub WHERE src_ip = ip) AS country,
               (SELECT count(*) FROM sub WHERE (src_ip = ip OR dst_ip = ip) AND event_subtype = 'ips') AS source_alerts_ips,
               (SELECT count(*) FROM sub WHERE (src_ip = ip OR dst_ip = ip) AND event_subtype = 'virus') AS source_alerts_virus,
               (SELECT count(*) FROM sub WHERE src_ip = ip) AS events_as_source
        FROM ent_ip""")
    user_nodes = _rows(con, "SELECT DISTINCT value AS name FROM fent WHERE kind='user'")

    auth = _rows(con, """
        SELECT src_ip, user, outcome, count(*) AS count, min(event_time)::VARCHAR AS first, max(event_time)::VARCHAR AS last,
               list(event_uid ORDER BY event_time)[1:10] AS evidence
        FROM sub WHERE category IN ('authentication', 'vpn') AND activity = 'login' AND user IS NOT NULL AND src_ip IS NOT NULL
          AND (outcome = 'success' OR user IN (SELECT u FROM ent_user))
        GROUP BY ALL""")
    flows = _rows(con, f"""
        SELECT * FROM (
          SELECT src_ip, dst_ip, dst_port, any_value(protocol) AS protocol, count(*) AS count,
                 sum(bytes_out) AS bytes_out, sum(bytes_in) AS bytes_in,
                 min(event_time)::VARCHAR AS first, max(event_time)::VARCHAR AS last,
                 list(event_uid ORDER BY event_time)[1:10] AS evidence,
                 row_number() OVER (PARTITION BY src_ip ORDER BY count(*) DESC) AS rk
          FROM sub WHERE event_type = 'traffic' AND src_ip IN (SELECT ip FROM ent_ip)
            AND (dst_ip IN (SELECT ip FROM ent_ip) OR dst_role IN ('dmz', 'internal'))
          GROUP BY src_ip, dst_ip, dst_port) WHERE rk <= {max_flows_per_ip}""")
    configured = _rows(con, """
        SELECT user, coalesce(device, 'unknown') AS device, action, message, event_time::VARCHAR AS time, event_uid, src_ip
        FROM sub WHERE category IN ('configuration', 'account_management') AND user IS NOT NULL""")
    findings = _rows(con, """SELECT finding_id AS id, rule_id, rule_version, title, severity, stage, attack, keys,
                             first_time::VARCHAR AS first, last_time::VARCHAR AS last, event_count, metric,
                             time_reliability, stall_fraction, provenance FROM f""")
    involves = _rows(con, "SELECT DISTINCT finding_id, kind, value, role FROM fent")

    con.execute(f"""CREATE OR REPLACE TEMP TABLE hubs AS SELECT value, count(DISTINCT finding_id) AS degree FROM fent
                    GROUP BY value HAVING count(DISTINCT finding_id) > {HUB_MAX_FINDINGS}""")
    hubs = {r["value"]: r["degree"] for r in _rows(con, "SELECT * FROM hubs")}
    for n in ip_nodes:
        n["hub_degree"] = hubs.get(n["addr"], 0)
    # finding-to-finding links with explicit basis, never within the same rule or through a hub entity
    links = _rows(con, f"""
        SELECT a.finding_id AS a, b.finding_id AS b, a.value AS entity, a.kind,
               CASE WHEN a.kind = 'ip' AND a.role = 'target' AND b.role = 'source' THEN 'pivot'
                    ELSE 'contextual_association' END AS decision,
               CASE WHEN a.kind = 'ip' AND a.role = 'target' AND b.role = 'source' THEN 'target_became_source'
                    WHEN a.kind = 'ip' THEN 'shared_ip_' || a.role || '_' || b.role
                    WHEN a.role = 'targeted_account' OR b.role = 'targeted_account' THEN 'targeted_account_reused'
                    ELSE 'shared_account' END AS basis,
               date_diff('second', a.last_time, b.first_time) AS gap_s
        FROM fent a JOIN fent b ON a.kind = b.kind AND a.value = b.value AND a.rule_id <> b.rule_id
        WHERE a.value NOT IN (SELECT value FROM hubs) AND b.first_time >= a.first_time AND a.finding_id <> b.finding_id
          AND b.first_time <= a.last_time + INTERVAL {LINK_GAP_HOURS} HOUR""")
    stalled = {f["id"] for f in findings if f["time_reliability"] != "ok"}
    for l in links:
        # equal or unreliable timestamps cannot establish "A happened before B"
        if l["decision"] == "pivot" and (l["gap_s"] is None or l["gap_s"] <= 0 or l["a"] in stalled or l["b"] in stalled):
            l["decision"], l["basis"] = "order_unresolved", "co_occurrence_order_unresolved"
        l["claim"] =f"{l['a']} and {l['b']} involve the same {l['kind']} {l['entity']} ({l['basis']})"
        l["checks"] = json.dumps({"same_value": True, "ordered_in_time": True,
                                  "gap_within_hours": LINK_GAP_HOURS, "different_rules": True})
        l["missing"] = json.dumps(["session identifiers", "process context"] if l["kind"] == "user" else ["NAT/DHCP lease history"])
        l["version"] = GRAPH_VERSION

    incidents = _candidate_incidents(findings, links)

    # evidence bundle: the exact source records behind each incident, so the UI never rescans the corpus
    inc_fids = sorted({fid for i in incidents for fid in i["finding_ids"]})
    bundle = []
    if inc_fids:
        con.execute("CREATE OR REPLACE TEMP TABLE inc_fe AS SELECT * FROM fe WHERE finding_id IN (SELECT unnest(?::VARCHAR[]))",
                    [inc_fids])
        bundle = _rows(con, """
            SELECT e.event_uid AS uid, e.event_time::VARCHAR AS time, e.time_quality, e.event_type, e.event_subtype,
                   e.event_code, e.severity, e.action, e.outcome, e.user, e.src_ip, e.dst_ip, e.dst_port, e.protocol,
                   e.rule_name, e.message, e.bytes_out, e.bytes_in, e.src_zone AS src_role,
                   e.dst_zone AS dst_role, e.src_country, e.category, e.activity,
                   e.line_no, e.byte_offset, e.byte_length, e.source_id, e.raw,
                   list(DISTINCT x.finding_id) AS finding_ids, list(DISTINCT x.step) AS steps
            FROM ev e JOIN inc_fe x ON x.event_uid = e.event_uid
            GROUP BY ALL ORDER BY time""")
    return {"ips": ip_nodes, "users": user_nodes, "auth": auth, "flows": flows, "configured": configured,
            "findings": findings, "involves": involves, "links": links, "incidents": incidents,
            "hubs": [{"value": k, "degree": v} for k, v in hubs.items()], "bundle": bundle}


def _candidate_incidents(findings, links):
    """Connected components over links that carry more than a shared attempted username."""
    parent = {f["id"]: f["id"] for f in findings}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for l in links:
        if l["basis"] not in ("targeted_account_reused", "co_occurrence_order_unresolved"):
            parent[find(l["a"])] = find(l["b"])
    groups = {}
    for f in findings:
        groups.setdefault(find(f["id"]), []).append(f)
    out = []
    for members in groups.values():
        if len(members) < 2 and SEV[members[0]["severity"]] < 3:
            continue
        stages = sorted({m["stage"] for m in members})
        rules = sorted({m["rule_id"] for m in members})
        max_sev = max(SEV[m["severity"]] for m in members)
        events = sum(m["event_count"] for m in members)
        degraded = sum(m["time_reliability"] != "ok" for m in members)
        factors = {"max_severity": max_sev * 15, "distinct_stages": 8 * len(stages),
                   "distinct_rules": 3 * len(rules), "evidence_volume": round(2 * math.log10(1 + events), 1),
                   "clock_degraded_penalty": round(-10 * degraded / len(members), 1)}
        out.append({"id": "INC-" + min(m["id"] for m in members)[:10], "status": "candidate",
                    "first": min(m["first"] for m in members), "last": max(m["last"] for m in members),
                    "finding_ids": [m["id"] for m in members], "stages": stages, "rules": rules,
                    "max_severity": max_sev, "risk": round(sum(factors.values()), 1),
                    "risk_factors": json.dumps(factors), "version": GRAPH_VERSION})
    return sorted(out, key=lambda i: -i["risk"])


CONSTRAINTS = [
    "CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (n:IP) REQUIRE n.addr IS UNIQUE",
    "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (n:User) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (n:Finding) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT rule_id IF NOT EXISTS FOR (n:Rule) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT tech_id IF NOT EXISTS FOR (n:Technique) REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT device_name IF NOT EXISTS FOR (n:Device) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (n:Incident) REQUIRE n.id IS UNIQUE",
]
LOADS = {
    "ips": "UNWIND $rows AS r MERGE (n:IP {addr: r.addr}) SET n += r",
    "users": "UNWIND $rows AS r MERGE (:User {name: r.name})",
    "findings": """UNWIND $rows AS r MERGE (f:Finding {id: r.id})
        SET f += r {.rule_id, .title, .severity, .stage, .keys, .first, .last, .event_count, .metric,
                    .time_reliability, .stall_fraction, .provenance, .attack}
        MERGE (ru:Rule {id: r.rule_id}) SET ru.version = r.rule_version, ru.title = r.title
        MERGE (f)-[:DETECTED_BY]->(ru)
        WITH f, r UNWIND r.techniques AS t
        MERGE (te:Technique {id: t.id}) SET te.name = t.name MERGE (f)-[:MAPS_TO]->(te)""",
    "involves": """UNWIND $rows AS r MATCH (f:Finding {id: r.finding_id})
        CALL (f, r) { WITH f, r WHERE r.kind = 'ip' MATCH (e:IP {addr: r.value}) MERGE (f)-[x:INVOLVES {role: r.role}]->(e)
                      UNION WITH f, r WHERE r.kind = 'user' MATCH (e:User {name: r.value}) MERGE (f)-[x:INVOLVES {role: r.role}]->(e) }""",
    "auth": """UNWIND $rows AS r MERGE (i:IP {addr: r.src_ip}) MERGE (u:User {name: r.user})
        MERGE (i)-[a:AUTH {outcome: r.outcome}]->(u)
        SET a.count = r.count, a.first = r.first, a.last = r.last, a.evidence = r.evidence, a.decision = 'observed'""",
    "flows": """UNWIND $rows AS r MERGE (s:IP {addr: r.src_ip}) MERGE (d:IP {addr: r.dst_ip})
        MERGE (s)-[x:FLOW {dst_port: coalesce(r.dst_port, -1)}]->(d)
        SET x += r {.protocol, .count, .bytes_out, .bytes_in, .first, .last, .evidence}, x.decision = 'observed'""",
    "configured": """UNWIND $rows AS r MERGE (u:User {name: r.user}) MERGE (d:Device {name: r.device})
        MERGE (u)-[c:CONFIGURED {evidence: r.event_uid}]->(d)
        SET c.action = r.action, c.message = r.message, c.time = r.time, c.from_ip = r.src_ip, c.decision = 'observed'""",
    "links": """UNWIND $rows AS r MATCH (a:Finding {id: r.a}), (b:Finding {id: r.b})
        MERGE (a)-[l:RELATED {basis: r.basis, entity: r.entity}]->(b)
        SET l += r {.decision, .gap_s, .claim, .checks, .missing, .version}""",
    "incidents": """UNWIND $rows AS r MERGE (i:Incident {id: r.id})
        SET i += r {.status, .first, .last, .stages, .rules, .max_severity, .risk, .risk_factors, .version}
        WITH i, r UNWIND r.finding_ids AS fid MATCH (f:Finding {id: fid}) MERGE (i)-[:CONTAINS]->(f)""",
}


def load(graph: dict, uri: str, user: str, password: str, reset=True, batch=2000) -> dict:
    for f in graph["findings"]:
        f["techniques"] = json.loads(f["attack"])
    counts = {}
    with GraphDatabase.driver(uri, auth=(user, password)) as drv, drv.session() as s:
        if reset:
            s.run("MATCH (n) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS")
        for c in CONSTRAINTS:
            s.run(c)
        for name in ("ips", "users", "findings", "involves", "auth", "flows", "configured", "links", "incidents"):
            rows = graph[name]
            for i in range(0, len(rows), batch):
                s.run(LOADS[name], rows=rows[i:i + batch]).consume()
            counts[name] = len(rows)
    return counts


def write_snapshot(graph: dict, path: str):
    """Static JSON snapshot for the API/UI, independent of Neo4j availability."""
    data = json.dumps(graph, default=str).encode()
    if path.startswith("s3://"):
        import boto3
        b, k = path[5:].split("/", 1)
        boto3.client("s3").put_object(Bucket=b, Key=k, Body=data, ContentType="application/json")
    else:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
