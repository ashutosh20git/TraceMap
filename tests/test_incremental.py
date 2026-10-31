"""Four batches processed one after another must give exactly the detections of one full run,
including attacks that straddle a batch boundary, and the knowledge base must only grow."""
import subprocess
import sys

import duckdb
import pytest

from trustgate.detection.engine import connect
from trustgate.detection.rules import load_rules
from trustgate.ingest.pipeline import IngestConfig, ingest
from trustgate.kb.incremental import analyze
from trustgate.kb.index import build_entity_index


@pytest.fixture(scope="module")
def batches(tmp_path_factory):
    d = tmp_path_factory.mktemp("inc")
    subprocess.run([sys.executable, "scripts/make_synthetic.py", str(d / "all.jsonl"), str(d / "key.md"), str(d / "b")], check=True,
                   capture_output=True)
    globs = {}
    for i in range(1, 5):
        sid = f"b{i}"
        # small chunks -> several segment files per batch, so the entity index has something to prune
        ingest(str(d / "b" / f"trustgate-batch-{i}.jsonl"), str(d / "canon" / sid), sid, IngestConfig(workers=2, chunk_bytes=256 << 10),
               log=lambda *_: None)
        globs[sid] = (d / "canon" / sid / "events" / "*.parquet").as_posix()
        build_entity_index(connect(), globs[sid])
    return d, globs


def finding_set(path):
    return set(duckdb.sql(f"SELECT rule_id, keys, event_count FROM '{path}/findings.parquet'").fetchall())


def test_incremental_equals_full_and_grows(batches):
    d, globs = batches
    rules = load_rules("config/rules/core.yaml")
    names = {k: k for k in globs}
    full = analyze(connect(), rules, globs, list(globs), names, 1, (d / "full").as_posix(), log=lambda *_: None)
    prev = None
    for i in range(1, 5):
        sub = {k: v for k, v in globs.items() if int(k[1:]) <= i}
        base = (d / f"rev{i}").as_posix()
        graph = analyze(connect(), rules, sub, [f"b{i}"], names, i, base, prev=prev, log=lambda *_: None)
        prev = {"base": base, "snapshot": graph, "ruleset": rules.fingerprint}
    assert finding_set((d / "rev4").as_posix()) == finding_set((d / "full").as_posix())
    g = graph["growth"]
    assert [r["revision"] for r in g] == [1, 2, 3, 4] and g[0]["mode"] == "full" and g[-1]["mode"] == "incremental"
    assert all(b["entities"] >= a["entities"] and b["relationships"] >= a["relationships"] for a, b in zip(g, g[1:]))
    # the brute force (S2) straddles batches 1 and 2: exactly one detection, and its incident grew after rev 1
    bf = [f for f in graph["findings"] if f["rule_id"] == "TG-AUTH-001"]
    assert len(bf) == 1 and bf[0]["event_count"] == 40
    # the batch-2 incident (success, account created/used/deleted) connects to the batch-1 brute force
    bf_inc = next(i for i in graph["incidents"] if bf[0]["id"] in i["finding_ids"])
    assert bf_inc["first_rev"] == 1 and bf_inc["change"] in ("grew", "merged") and len(bf_inc["finding_ids"]) > 1
    assert sum(r["incidents_grew"] for r in g) >= 1
    # the VPN pair (S8) straddles batches 3 and 4 and is found once
    assert sum(f["rule_id"] == "TG-VPN-001" for f in graph["findings"]) == 1
    # knowledge-base counts equal a full build's (each event counted once)
    full_kb = {(r["src_ip"], r["user"], r["outcome"]): r["count"] for r in full["auth"]}
    inc_kb = {(r["src_ip"], r["user"], r["outcome"]): r["count"] for r in graph["auth"]}
    assert inc_kb == full_kb and len(inc_kb) > 0
    assert inc_kb[("198.51.100.23", "j.mehta", "failure")] == 40  # straddles batches 1-2, counted exactly once
    assert graph["growth"][0]["relationships"] > 0
    # history lookups went through the entity indexes and read only some of the older segments
    segs = [len(list((d / "canon" / f"b{i}" / "events").glob("*.parquet"))) for i in range(1, 5)]
    available = sum(sum(segs[:r - 1]) for r in (2, 3, 4))  # older segments that revisions 2-4 could have rescanned
    read = sum(row["backfill"]["segments"] for row in g[1:])
    assert all(row["backfill"]["indexed"] == row["backfill"]["sources"] for row in g[1:]) and read <= available


def test_entity_index_reads_only_segments_that_mention_an_entity(tmp_path):
    import pyarrow as pa
    import pyarrow.parquet as pq
    from trustgate.kb.index import segments_for
    ev = tmp_path / "s" / "events"
    ev.mkdir(parents=True)
    for i, ips in enumerate([["10.0.0.1", "10.0.0.2"], ["10.0.0.2"], ["10.9.9.9", "10.0.0.2"]]):
        pq.write_table(pa.table({"src_ip": ips, "dst_ip": [None] * len(ips), "user": [None] * len(ips)}), ev / f"seg-{i}.parquet")
    glob = (ev / "*.parquet").as_posix()
    con = connect()
    build_entity_index(con, glob)
    con.execute("CREATE TABLE n_ip AS SELECT '10.9.9.9' AS ip; CREATE TABLE n_user AS SELECT NULL::VARCHAR AS u WHERE false")
    segs = segments_for(con, glob, "n_ip", "n_user")
    assert len(segs) == 1 and segs[0].endswith("seg-2.parquet")
