"""The same attack (25 failed logins from one source, then a success for an
attacked account) written in five different log schemas must produce the same
vendor-neutral detections. Also: an unknown schema is mapped by inference, and a
schema change halfway through a file is detected and still analyzed."""
import datetime as dt
import json

import duckdb
import pytest

from trustgate.detection import engine
from trustgate.detection.rules import load_rules
from trustgate.ingest.pipeline import IngestConfig, ingest

T0 = dt.datetime(2026, 10, 27, 8, 0, 0, tzinfo=dt.timezone.utc)
ATTACKER, VICTIM = "203.0.113.50", "alice"


def ts(i):
    return T0 + dt.timedelta(seconds=10 * i)


def fortigate(i, ok):
    t = ts(i)
    return (f'date={t:%Y-%m-%d} time={t:%H:%M:%S} eventtime={int(t.timestamp())}000000000 devname="FGT" '
            f'logid="{"0100032001" if ok else "0100032002"}" type="event" subtype="system" user="{VICTIM}" '
            f'srcip={ATTACKER} srcintfrole="wan" status="{"success" if ok else "failed"}" '
            f'msg="Administrator {VICTIM} {"logged in successfully" if ok else "login failed"}"')


def windows(i, ok):
    return json.dumps({"TimeCreated": ts(i).isoformat(), "EventID": 4624 if ok else 4625, "Computer": "DC01",
                       "TargetUserName": VICTIM, "IpAddress": ATTACKER, "IpPort": "50123", "LogonType": 3})


def sshd(i, ok):
    t = ts(i)
    word = "Accepted password" if ok else "Failed password"
    return f"<38>1 {t.isoformat()} web01 sshd 812 - - {word} for {VICTIM} from {ATTACKER} port 50123 ssh2 user={VICTIM} src={ATTACKER}"


def cef(i, ok):
    ms = int(ts(i).timestamp() * 1000)
    name = "Logon success" if ok else "Logon failure"
    return (f"CEF:0|Acme|IdP|2.1|{'100' if ok else '101'}|{name}|5|rt={ms} src={ATTACKER} suser={VICTIM} "
            f"outcome={'success' if ok else 'failure'} msg=user {VICTIM} login {'succeeded' if ok else 'failed'}")


def unknown_vendor(i, ok):
    # field names no alias table knows: must be inferred from names and values
    return json.dumps({"when": ts(i).isoformat(), "origin_addr": ATTACKER, "principal": VICTIM,
                       "outcome_text": "granted" if ok else "denied",
                       "description": f"login {'accepted' if ok else 'failed'} for principal {VICTIM}"})


SCHEMAS = {"fortigate": fortigate, "windows": windows, "sshd": sshd, "cef": cef, "unknown_vendor": unknown_vendor}


def run(tmp_path, lines, name):
    src = tmp_path / f"{name}.log"
    src.write_text("\n".join(lines) + "\n")
    m = ingest(str(src), str(tmp_path / name), name, IngestConfig(workers=1, chunk_bytes=4096), log=lambda *_: None)
    out = (tmp_path / f"{name}-f").as_posix()
    engine.run(load_rules("config/rules/core.yaml"), (tmp_path / name / "events" / "*.parquet").as_posix(), out, log=lambda *_: None)
    rows = duckdb.sql(f"SELECT rule_id, users, src_ips FROM '{out}/findings.parquet'").fetchall()
    return m, rows


@pytest.mark.parametrize("schema", list(SCHEMAS))
def test_same_attack_same_detections_in_every_schema(tmp_path, schema):
    make = SCHEMAS[schema]
    lines = [make(i, False) for i in range(25)] + [make(30, True)]  # 25 failures in ~4 min, then success
    m, rows = run(tmp_path, lines, schema)
    assert m["accounting"]["balanced"]
    rules = {r[0] for r in rows}
    assert "TG-AUTH-001" in rules, f"{schema}: brute force not detected; categories={m['schema']['categories']}"
    assert "TG-AUTH-003" in rules, f"{schema}: success-after-failures not detected"
    bf = next(r for r in rows if r[0] == "TG-AUTH-001")
    assert bf[2] == [ATTACKER]
    if schema == "unknown_vendor":
        inf = m["schema"]["inferred_mappings"]
        assert inf["src_ip"]["key"] == "origin_addr" and inf["user"]["key"] == "principal"
        assert inf["event_time"]["key"] == "when"


def test_schema_change_mid_file_is_reported_and_still_detected(tmp_path):
    # first half FortiGate-style, second half an unknown layout with renamed fields
    lines = [fortigate(i, False) for i in range(300)]
    lines += [unknown_vendor(400 + i, False) for i in range(300)]
    m, rows = run(tmp_path, lines, "drift")
    sch = m["schema"]
    assert sch["distinct_layouts"] >= 2 and sch["drift"], "layout change not reported"
    assert sch["drift_inferred_by_segment"], "no mapping inferred for the changed layout"
    # brute force must be found in BOTH halves: 2 separate windows (gap > 10 min between halves)
    bf = [r for r in rows if r[0] == "TG-AUTH-001"]
    assert len(bf) == 2
