"""Every rule must fire exactly as often as the synthetic answer key says, and nowhere else."""
import subprocess
import sys

from trustgate.detection import engine
from trustgate.detection.rules import TACTICS, load_rules
from trustgate.ingest.pipeline import IngestConfig, ingest

EXPECTED = {"TG-AUTH-001": 1, "TG-AUTH-002": 1, "TG-AUTH-003": 1, "TG-AUTH-004": 2, "TG-AUTH-005": 1, "TG-PERS-001": 1,
            "TG-PERS-002": 1, "TG-EVAS-001": 2, "TG-EVAS-002": 1, "TG-EVAS-003": 1, "TG-VPN-001": 1, "TG-LAT-001": 1,
            "TG-WEB-001": 1, "TG-RECON-001": 1, "TG-RECON-002": 1, "TG-EXEC-001": 1, "TG-PRIV-001": 1, "TG-DISC-001": 1,
            "TG-DISC-002": 1, "TG-COLL-001": 1, "TG-C2-001": 1, "TG-EXFIL-001": 1, "TG-IMP-001": 1, "TG-IMP-002": 1}


def test_every_rule_fires_exactly_on_its_planted_scenario(tmp_path):
    subprocess.run([sys.executable, "scripts/make_synthetic.py", str(tmp_path / "all.jsonl")], check=True, capture_output=True)
    ingest(str(tmp_path / "all.jsonl"), str(tmp_path / "canon"), "syn", IngestConfig(workers=2), log=lambda *_: None)
    rules = load_rules("config/rules/core.yaml", "config/rules/tactics.yaml")
    r = engine.run(rules, (tmp_path / "canon" / "events" / "*.parquet").as_posix(), (tmp_path / "f").as_posix(), log=lambda *_: None)
    assert {k: v for k, v in r["findings"].items() if v} == EXPECTED
    covered = {rule.stage for rule in rules.rules}
    assert len(covered & set(TACTICS)) == 13 and "resource-development" not in covered
