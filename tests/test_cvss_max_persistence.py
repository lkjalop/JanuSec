import os
import importlib


def test_cvss_max_persists_across_reload(tmp_path, monkeypatch):
    # Use a temp file for persistence
    agg_path = tmp_path / 'sbom_vuln_aggregates.jsonl'
    monkeypatch.setenv('SBOM_VULN_AGG_PATH', str(agg_path))

    from repositories import sbom_vuln_agg_repo as repo
    importlib.reload(repo)

    tenant = 't'
    comp = 'libssl:1.1.0'

    # Record vulnerabilities with CVSS scores
    repo.record_vulnerability(tenant, comp, 'critical', cvss_score=9.8)
    repo.record_vulnerability(tenant, comp, 'high', cvss_score=7.5)

    agg = repo.get_aggregate(tenant, comp)
    assert agg is not None
    assert getattr(agg, 'cvss_max', 0.0) >= 9.8 - 1e-6

    # Simulate process restart by reloading module
    importlib.reload(repo)
    agg2 = repo.get_aggregate(tenant, comp)
    assert agg2 is not None
    assert getattr(agg2, 'cvss_max', 0.0) >= 9.8 - 1e-6

