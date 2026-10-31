import datetime as dt
import json

import duckdb
import pytest

from trustgate.detection import engine
from trustgate.detection.rules import Rule, load_rules
from trustgate.ingest.pipeline import IngestConfig, ingest

T0 = dt.datetime(2026, 10, 27, 8, 0, 0)


def fgt(sec, **f):
    t = T0 + dt.timedelta(seconds=sec)
    ns = int(t.replace(tzinfo=dt.timezone.utc).timestamp()) * 10**9
    base = {"date": t.strftime("%Y-%m-%d"), "time": t.strftime("%H:%M:%S"), "eventtime": ns, "tz": "+0530",
            "devname": "FGT"}
    base.update(f)
    return " ".join(f'{k}="{v}"' if isinstance(v, str) else f"{k}={v}" for k, v in base.items()).encode()


def fail(sec, ip, user="admin"):
    return fgt(sec, logid="0100032002", type="event", subtype="system", user=user, srcip=ip, srcintfrole="wan",
               status="failed", msg=f"Administrator {user} login failed")


def ok(sec, ip, user):
    return fgt(sec, logid="0100032001", type="event", subtype="system", user=user, srcip=ip, srcintfrole="wan",
               status="success", msg=f"Administrator {user} logged in successfully")


def conf(sec, user, msg, logid="0100044546"):
    return fgt(sec, logid=logid, type="event", subtype="system", user=user, srcip="51.1.1.1", srcintfrole="wan",
               msg=msg)


@pytest.fixture(scope="module")
def findings(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("det")
    lines = []
    lines += [fail(i * 20, "45.0.0.1") for i in range(25)]             # 25 in ~8 min -> brute force
    lines += [fail(3600 + i * 20, "45.0.0.2") for i in range(19)]      # 19 -> below threshold
    lines += [fail(7200 + i * 60, f"50.41.253.{i}") for i in range(6)]  # 6 IPs, one /24 -> spray
    lines += [fail(9000 + i, "9.9.9.9", "keerthan") for i in range(10)] + [ok(9100, "35.1.1.1", "keerthan")]
    lines += [fail(9200 + i, "9.9.9.7", "typo") for i in range(3)] + [ok(9300, "10.1.1.1", "typo")]  # normal typos: no finding
    lines += [ok(9200, "9.9.9.8", "lonely")]                            # success without failures: no TG-AUTH-003
    lines += [conf(10000, "laxman", "Add system.admin svc_b", "0100044547"), ok(10300, "105.1.1.1", "svc_b"),
              conf(10600, "laxman", "Delete system.admin svc_b", "0100044547")]
    lines += [conf(20000, "shikha", "Attribute 'status' of setting 'log disk setting' changed from 'enable' to 'disable'"),
              conf(21000, "shikha", "Objects of 'firewall policy' were purged"),
              conf(22000, "shikha", "Attribute 'status' of setting 'log disk setting' changed from 'disable' to 'enable'")]
    lines += [fgt(30000 + i * 300, logid="0101039947", type="event", subtype="vpn", action="tunnel-up", user="renu",
                  srcip=ip, srccountry=c, srcintfrole="wan", status="success")
              for i, (ip, c) in enumerate([("185.1.1.1", "Brazil"), ("180.1.1.1", "France"), ("185.1.1.1", "Brazil")])]
    lines += [fgt(40000 + i * 600, logid="0000000013", type="traffic", subtype="forward", srcip="10.10.10.44",
                  dstip=f"10.10.20.{10 + i}", dstport=445, srcintfrole="lan", dstintfrole="dmz", action="accept")
              for i in range(6)]
    lines += [fail(25 * 20 + 1, "45.0.0.1")] * 1                        # exact duplicate of nothing; real dup below
    lines.append(lines[0])                                               # exact duplicate delivery
    src = tmp / "fgt.log"
    src.write_bytes(b"\n".join(lines) + b"\n")
    ingest(str(src), str(tmp / "canon"), "t", IngestConfig(workers=1, chunk_bytes=2048), log=lambda *_: None)
    rs = load_rules("config/rules/core.yaml")
    res = engine.run(rs, str(tmp / "canon" / "events" / "*.parquet").replace("\\", "/"), str(tmp / "f").replace("\\", "/"),
                     log=lambda *_: None)
    rows = duckdb.sql(f"SELECT * FROM '{(tmp / 'f' / 'findings.parquet').as_posix()}'").fetchall()
    cols = [d[0] for d in duckdb.sql(f"SELECT * FROM '{(tmp / 'f' / 'findings.parquet').as_posix()}' LIMIT 0").description]
    return res, [dict(zip(cols, r)) for r in rows], tmp


def by_rule(f, rid):
    return [x for x in f[1] if x["rule_id"] == rid]


def test_threshold_fires_once_across_segments_and_dedups(findings):
    bf = by_rule(findings, "TG-AUTH-001")
    assert len(bf) == 1, "25 failures from 45.0.0.1 split over many 2 KiB segments -> one finding"
    assert json.loads(bf[0]["keys"]) == {"src_ip": "45.0.0.1"}
    assert bf[0]["event_count"] == 26  # 25 + 1 later failure; the exact duplicate line is counted once


def test_spray_success_after_failures_and_sequences(findings):
    assert [json.loads(x["keys"]) for x in by_rule(findings, "TG-AUTH-002")] == [{"src_net24": "50.41.253.0/24"}]
    seq = by_rule(findings, "TG-AUTH-003")
    assert len(seq) == 1 and seq[0]["users"] == ["keerthan"]
    cud = by_rule(findings, "TG-PERS-002")
    assert len(cud) == 1 and cud[0]["event_count"] == 3
    assert len(by_rule(findings, "TG-EVAS-003")) == 1
    assert len(by_rule(findings, "TG-EVAS-001")) == 1 and len(by_rule(findings, "TG-EVAS-002")) == 1


def test_vpn_geo_and_smb_fanout(findings):
    assert by_rule(findings, "TG-VPN-001")[0]["users"] == ["renu"]
    smb = by_rule(findings, "TG-LAT-001")
    assert len(smb) == 1 and smb[0]["dst_ip_count"] == 6


def test_evidence_links_back_to_events(findings):
    _, rows, tmp = findings
    ev = (tmp / "f" / "finding_evidence.parquet").as_posix()
    canon = (tmp / "canon" / "events" / "*.parquet").as_posix()
    missing = duckdb.sql(f"SELECT count(*) FROM '{ev}' e ANTI JOIN '{canon}' c USING (event_uid)").fetchall()[0][0]
    assert missing == 0


def test_rule_validation_rejects_bad_config():
    with pytest.raises(ValueError):
        Rule(id="TG-X", version=1, title="x", type="threshold", severity="low", stage="impact", where={"nope": 1})
    with pytest.raises(ValueError):
        Rule(id="TG-X", version=1, title="x", type="event", severity="low", stage="impact",
             where={"user": "a; DROP TABLE ev"}, group_by=["user; --"])


def test_graph_links_and_candidate_incidents(findings):
    from trustgate.graph.build import build
    _, _, tmp = findings
    g = build((tmp / "canon" / "events" / "*.parquet").as_posix(), (tmp / "f").as_posix())
    rules_in = [set(i["rules"]) for i in g["incidents"]]
    assert any({"TG-PERS-001", "TG-PERS-002"} <= r for r in rules_in)       # create + create/use/delete
    assert any({"TG-EVAS-001", "TG-EVAS-002", "TG-EVAS-003"} <= r for r in rules_in)
    for l in g["links"]:
        assert l["claim"] and l["checks"] and l["decision"] in ("contextual_association", "pivot")
    # the spray /24 and the separate brute-force source share no entity: they must not merge
    assert not any({"TG-AUTH-001", "TG-AUTH-002"} <= r for r in rules_in)
    assert {f["provenance"] for f in g["findings"]} == {"engine_detection"}
