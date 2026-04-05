from __future__ import annotations

import asyncio

from src.core.event_pipeline.stages.ebpf_analysis import ebpf_analysis_stage
from src.core.event_pipeline.stages.base import StageContext


class DummyCtx(StageContext):
    def __init__(self):
        super().__init__(registry=None, config=None, logger=None, state={})


def test_ebpf_enrichment_metadata():
    ev = {
        'source': 'falco_ebpf',
        'command': '/bin/sh -c whoami',
        'host': 'vm1',
        'pid': 1234,
        'ppid': 1,
        'process_name': 'sh',
        'local_ip': '10.0.0.5',
        'remote_ip': '203.0.113.9'
    }
    ctx = DummyCtx()
    res = asyncio.get_event_loop().run_until_complete(ebpf_analysis_stage(ev, ctx))
    assert res.metadata is not None
    # ensure enrichment keys present
    for k in ('collector_timestamp','host_id','pid','process_name','local_ip','remote_ip'):
        assert k in res.metadata
