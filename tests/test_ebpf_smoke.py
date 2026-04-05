from __future__ import annotations

import asyncio

from src.core.event_pipeline.stages.ebpf_analysis import ebpf_analysis_stage
from src.core.event_pipeline.stages.base import StageContext


class DummyCtx(StageContext):
    def __init__(self):
        super().__init__(registry=None, config=None, logger=None, state={})


def test_ebpf_smoke_full_enrichment(monkeypatch, tmp_path):
    # create simple SBOM cache with CVE
    sb = tmp_path / 'sbom.json'
    sb.write_text(__import__('json').dumps({'deadbeef': {'components': [], 'cves': [{'cve':'CVE-2020-1111','cvss':9.1,'kev':True,'epss':0.9}]}}))
    monkeypatch.setenv('SBOM_CACHE_FILE', str(sb))

    ev = {
        'source': 'falco_ebpf',
        'command': '/usr/bin/evil --doit',
        'host': 'host-smoke',
        'pid': 4321,
        'ppid': 1,
        'process_name': 'evil',
        'local_ip': '10.1.1.5',
        'remote_ip': '198.51.100.7',
        'container_id': 'c-1234',
        'container_image': 'registry.example/evil:1.0',
        'k8s_pod': 'evil-pod',
        'k8s_ns': 'default',
        'tls': {'server_name': 'api.example.com', 'fingerprint': 'aa:bb:cc'},
        'dns': {'query': 'example.com', 'answers': ['93.184.216.34']},
        # emulate exe path by creating a small file
    }
    # create fake exe and ensure hash resolves
    fakeexe = tmp_path / 'evilbin'
    fakeexe.write_bytes(b'abcdef')
    ev['exe'] = str(fakeexe)

    ctx = DummyCtx()
    res = asyncio.get_event_loop().run_until_complete(ebpf_analysis_stage(ev, ctx))
    md = res.metadata
    assert md is not None
    assert md.get('container_id') == 'c-1234'
    assert md.get('kubernetes_pod') == 'evil-pod'
    assert 'tls_server_name' in md
    assert 'dns_qname' in md
    # SBOM lookup should populate cve_summary
    # our SBOM has key 'deadbeef' so hash won't match; ensure code handles missing gracefully
    assert 'cve_summary' in md
import asyncio
from src.core.event_pipeline.stages.ebpf_analysis import ebpf_analysis_stage
from src.core.event_pipeline.stages.base import StageContext


def test_ebpf_smoke_sync():
    # create a fake falco_ebpf event
    ev = {
        'source': 'falco_ebpf',
        'command': '/bin/sh -c nsenter --mount /proc/1/ns/mnt',
        'container_id': 'cid-1234',
        'syscall': 'execve',
        'rule_name': 'Container Escape Detected'
    }

    # StageContext requires registry, config, logger, state (we can pass minimal None values)
    ctx = StageContext(registry=None, config=None, logger=None, state={})

    # call the stage (it's async)
    loop = asyncio.new_event_loop()
    try:
        res = loop.run_until_complete(ebpf_analysis_stage(ev, ctx))
    finally:
        loop.close()

    assert res.name == 'ebpf_analysis'
    # expect several factors including container_escape and falco_rule
    assert any(f.startswith('falco_rule:') for f in res.factors)
    assert 'ebpf:container_escape' in res.factors
