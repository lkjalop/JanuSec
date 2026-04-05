import copy
from src.reporting.persona_views import generate_persona_view


def make_report_with_many_iocs(n=10):
    rpt = {
        "report_id": "r-test-iocs",
        "evidence_items": [],
    }
    # create a bunch of evidence entries each with multiple IOC types
    for i in range(n):
        rpt["evidence_items"].append({
            "extracted_iocs": {
                "ip": [f"10.0.0.{i}"] ,
                "domain": [f"host{i}.example.local"],
                "hash": [f"hash{i:04d}"],
                "email": [f"user{i}@example.local"],
            }
        })
    return rpt


def test_persona_view_iocs_truncated_per_type():
    rpt = make_report_with_many_iocs(20)
    # request top_n = 3
    view = generate_persona_view(rpt, persona="soc_analyst", disclosure_level=2, top_n=3)
    assert isinstance(view, dict)
    s = view.get("summary_signals") or {}
    iocs = s.get("iocs")
    assert isinstance(iocs, dict)
    # each IOC type should be present and have at most 3 entries
    for k in ("ip", "domain", "hash", "email"):
        assert k in iocs
        v = iocs.get(k) or []
        assert isinstance(v, list)
        assert len(v) <= 3
