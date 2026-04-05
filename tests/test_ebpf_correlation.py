import json
from src.core import ebpf_correlation as ec
from src.core import sbom_enrich as se


def test_parse_falco_event_and_map():
    sample = {'rule': 'kprobe_attach', 'output': 'attach failed', 'priority': 'Warning', 'output_fields': {'proc.pid': 999, 'proc.name': 'evil'}}
    ev = ec.parse_falco_event(sample)
    assert ev['type'] == 'kprobe_attach_sensitive'
    enriched = ec.map_event_to_tags(ev['type'], ev['payload'])
    assert 'mitre' in enriched and isinstance(enriched['mitre'], list)


def test_sbom_enrich_lookup_and_mark(tmp_path, monkeypatch):
    # create a fake sbom store file
    store = {
        'my/image:latest': [
            {'cve': 'CVE-2024-0001', 'score': 9.0},
            {'cve': 'CVE-2024-0002', 'score': 5.0}
        ]
    }
    p = tmp_path / 'sbom_store.json'
    p.write_text(json.dumps(store))
    monkeypatch.setenv('PYTHONUNBUFFERED', '1')
    # ensure lookup reads from data path by copying file
    import shutil, os
    os.makedirs('data', exist_ok=True)
    shutil.copy(str(p), 'data/sbom_store.json')
    vulns = se.lookup_image_vulns('my/image:latest')
    assert any(v['cve'] == 'CVE-2024-0001' for v in vulns)
    marked = se.mark_kev_candidates(vulns)
    assert any(v.get('kev_candidate') for v in marked)
