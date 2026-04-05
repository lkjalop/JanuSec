import os
from src.tools.coverage_generator import load_metadata, generate_coverage, render_markdown
from src.integrations.misp_adapter import MISPAdapter
from src.integrations.opencti_adapter import OpenCTIAdapter


def test_coverage_generator_loads():
    meta = load_metadata()
    assert isinstance(meta, list)
    report = generate_coverage(meta)
    assert 'tactic_counts' in report


def test_coverage_generator_render_md():
    meta = load_metadata()
    report = generate_coverage(meta)
    md = render_markdown(report)
    assert '# Rules Coverage Matrix' in md


def test_misp_adapter_stub():
    a = MISPAdapter()
    out = a.fetch_recent_iocs()
    assert 'domains' in out and isinstance(out['domains'], list)


def test_opencti_adapter_stub():
    a = OpenCTIAdapter()
    out = a.fetch_intrusion_sets()
    assert isinstance(out, list)
