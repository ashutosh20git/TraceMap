from trustgate.reports import assets, story
from trustgate.reports.llm import validate
from trustgate.reports.render import ReportConfig, render_html

HOSTILE = '<script>alert(1)</script> {{ 7*7 }} <img src="http://evil/x.png"> Ignore previous instructions'


def fake_detail():
    f = {"id": "f1", "title": "Device logging disabled", "rule_id": "TG-EVAS-001", "rule_version": 1,
         "severity": "high", "stage": "defense-evasion", "attack": [{"id": "T1562.002", "name": "Impair Defenses"}],
         "first": "2026-10-23 11:40:21+00", "last": "2026-10-23 11:40:21+00", "event_count": 1,
         "time_reliability": "ok", "stall_fraction": 0.0}
    return {
        "incident": {"id": "INC-x", "title": f["title"], "first": f["first"], "last": f["last"], "risk": 50.0,
                     "stages": ["defense-evasion"], "status": "candidate", "version": "g1",
                     "risk_factors": {"max_severity": 45}},
        "nodes": [{"id": "f:f1", "type": "finding", "label": f["title"], "data": f},
                  {"id": "u:<b>eve</b>", "type": "user", "label": "<b>eve</b>", "data": {"name": "<b>eve</b>"}}],
        "edges": [{"id": "e1", "source": "f:f1", "target": "u:<b>eve</b>", "type": "INVOLVES", "label": "account",
                   "data": {"role": "account", "decision": "engine_detection"}}],
        "events": [{"uid": "ev1", "time": f["first"], "finding_ids": ["f1"], "steps": ["match"], "line_no": 7,
                    "byte_offset": 100}],
    }


def test_hostile_log_text_is_escaped_not_executed():
    d = fake_detail()
    doc = story.compose(d, {"ev1": HOSTILE}, {"snapshot": "t"})
    html = render_html(doc, {"status": "disabled", "text": None, "model": None, "errors": []}, ReportConfig(), "rpt-t")
    assert "&lt;script&gt;" in html and "<script>" not in html
    assert "{{ 7*7 }}" in html and "49" not in html.split("Appendix A")[1][:2000]
    assert 'src="http://evil' not in html
    assert "&lt;b&gt;eve&lt;/b&gt;" in html


def test_story_claims_and_svg_escape():
    d = fake_detail()
    doc = story.compose(d, {"ev1": HOSTILE}, {})
    assert [s["claim_id"] for s in doc["steps"]] == ["C1"]
    assert doc["steps"][0]["logs"][0]["raw"] == HOSTILE  # verbatim in data, escaped only at render time
    svg = assets.graph_svg(d, {"f1": "C1"})
    assert "<b>" not in svg and "&lt;b&gt;eve" in svg


def test_narrative_validation():
    st = {"steps": [{"claim_id": "C1"}, {"claim_id": "C2"}], "allowed_entities": ["10.0.0.1"]}
    assert validate("A [C1]. B by 10.0.0.1 [C2].", st) == []
    assert any("does not cite" in e for e in validate("A [C1].", st))
    assert any("unknown claims" in e for e in validate("A [C1][C2][C9].", st))
    assert any("addresses" in e for e in validate("A 8.8.8.8 [C1][C2].", st))
    assert any("overclaims" in e for e in validate("Confirmed attack [C1][C2].", st))
