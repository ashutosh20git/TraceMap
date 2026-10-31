import subprocess
import sys

import pytest
import yaml

from trustgate.detection import engine
from trustgate.detection.rules import Rule, RuleSet, where_sql
from trustgate.detection.sigma import Skip, convert
from trustgate.ingest.pipeline import IngestConfig, ingest


def sig(detection, **kw):
    doc = {"title": "t", "id": "12345678-aaaa-bbbb-cccc-1234567890ab", "status": "test", "level": "high",
           "logsource": {"product": "windows", "category": "process_creation"},
           "tags": ["attack.execution", "attack.t1059.001"], "detection": detection}
    doc.update(kw)
    return doc


def test_condition_grammar_and_modifiers():
    r = convert(sig({"selection_img": {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]},
                     "selection_cli": {"CommandLine|contains|windash": ["-enc ", "-EncodedCommand"]},
                     "filter_main": {"ParentImage|startswith": "C:\\Program Files\\"},
                     "condition": "all of selection_* and not 1 of filter_*"}), "x.yml", "r1")
    assert r["stage"] == "execution" and r["attack"][0]["id"] == "T1059.001" and r["severity"] == "high"
    assert r["requires_fields"] == ["CommandLine", "Image", "ParentImage"] and r["group_by"] == ["actor"]
    params = []
    sql = where_sql(r["where"], params)
    assert "NOT coalesce" in sql and "/enc " in params and "-enc " in params  # windash variants added


@pytest.mark.parametrize("det,reason", [
    ({"sel": {"CommandLine|base64offset|contains": "IEX"}, "condition": "sel"}, "base64offset"),
    ({"sel": {"EventID": 4625}, "condition": "sel | count() by IpAddress > 10"}, "aggregation"),
    ({"sel": {"EventID": 4625}, "condition": "sel and other"}, "unknown selection"),
])
def test_unsupported_constructs_are_skipped_not_approximated(det, reason):
    with pytest.raises(Skip, match=reason):
        convert(sig(det), "x.yml", "r1")


def test_fields_map_to_trustgate_columns_and_cidr():
    r = convert(sig({"sel": {"EventID": 4624, "LogonType": 10}, "filter": {"IpAddress|cidr": ["10.0.0.0/8", "192.168.0.0/16"]},
                     "condition": "sel and not filter"}), "x.yml", "r1")
    flat = yaml.safe_dump(r["where"])
    assert "event_code" in flat and "attr.LogonType" in flat and "src_ip" in flat and "cidr" in flat
    assert r["requires_fields"] == ["LogonType"]


def test_keyword_only_rules_are_imported_disabled():
    r = convert(sig({"keywords": ["delete", "erase"], "condition": "keywords"}, logsource={"product": "cisco"}), "x.yml", "r1")
    assert r["enabled"] is False and "cisco" in r["source"]["disabled_reason"]


def test_converted_rule_fires_on_planted_powershell(tmp_path):
    subprocess.run([sys.executable, "scripts/make_synthetic.py", str(tmp_path / "all.jsonl")], check=True, capture_output=True)
    ingest(str(tmp_path / "all.jsonl"), str(tmp_path / "canon"), "syn", IngestConfig(workers=2), log=lambda *_: None)
    r = convert(sig({"selection": {"CommandLine|contains|windash": ["-enc ", "-encodedcommand"]},
                     "condition": "selection"}), "x.yml", "r1")
    rs = RuleSet(attack_version="test", rules=[Rule(**r)])
    out = engine.run(rs, (tmp_path / "canon" / "events" / "*.parquet").as_posix(), (tmp_path / "f").as_posix(), log=lambda *_: None)
    assert out["rule_status"][r["id"]] == {"status": "fired", "findings": 1}
