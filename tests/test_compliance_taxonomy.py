import os

from src.modules.compliance.taxonomy_loader import ControlTaxonomyLoader


def test_taxonomy_loader_default_subset():
    loader = ControlTaxonomyLoader(search_paths=["nonexistent/path"])
    controls = loader.load()
    assert isinstance(controls, list)
    assert len(controls) > 0
    assert all('control_id' in c for c in controls)
    assert all('domain_code' in c for c in controls)


def test_taxonomy_loader_from_dir(tmp_path):
    d = tmp_path / 'taxonomy' / 'data'
    d.mkdir(parents=True)
    data = [
        {"control_id": "A.5.1.9", "title": "Test Control", "keywords": ["test","policy"]}
    ]
    p = d / 'iso_subset.json'
    p.write_text(__import__('json').dumps(data), encoding='utf-8')
    loader = ControlTaxonomyLoader(search_paths=[str(d)])
    controls = loader.load()
    assert any(c.get('control_id') == 'A.5.1.9' for c in controls)
    assert any(c.get('domain_code') == 'A.5' for c in controls)

