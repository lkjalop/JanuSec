import json
from fastapi.testclient import TestClient
from src.api.app import app


client = TestClient(app)


def make_sample_report(n=6):
    return {
        "report_id": "r-integ-1",
        "evidence_items": [
            {"extracted_iocs": {"ip": [f"10.0.0.{i}"]}} for i in range(n)
        ],
        "verdict": {"final_verdict": "SUSPICIOUS", "final_confidence": 0.8, "all_factors": []},
    }


def test_post_persona_view_integration_top_n():
    rpt = make_sample_report(10)
    resp = client.post('/api/v1/reports/persona_view?persona=soc_analyst&disclosure_level=2&top_n=4', json=rpt)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert isinstance(data, dict)
    ss = data.get('summary_signals') or {}
    iocs = ss.get('iocs')
    assert isinstance(iocs, dict)
    # each IOC type list length <= 4
    for k, v in iocs.items():
        assert len(v) <= 4
