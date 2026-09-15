"""
Backend tests for Cluster LLM Summary, Model Catalog, and CRAG Enrich overrides.
==============================================================================
Tests:
  1. GET /tier2/llm-summary — finds cluster from persisted assessment (disk cache)
  2. GET /tier2/llm-summary — 404 for missing assessment, useful error detail
  3. GET /tier2/llm-summary — 404 for missing cluster, useful error detail
  4. GET /api/v1/llm/models/catalog — returns enabled/disabled model entries
  5. POST /enrich — still rejects LLM call when CRAG verdict is REJECT even with model override
  6. POST /enrich — accepts model and provider overrides and passes them through call_overrides
"""
from __future__ import annotations

import json
import time
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault('DISABLE_DB', '1')
os.environ.setdefault('TEST_HELPERS_ENABLED', '1')

from src.api.app import create_app

app = create_app({'mode': 'test'})


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

ASSESSMENT_ID = 'test-llm-canvas-' + str(int(time.time()))
CLUSTER_ID    = 'cluster-1'

_FAKE_CLUSTER = {
    'cluster_id':            CLUSTER_ID,
    'severity':              'high',
    'confidence':            0.82,
    'top_mitre':             ['T1078', 'T1021'],
    'shared_accounts':       ['azureuser'],
    'shared_hosts':          ['az-linux-01'],
    'shared_external_ips':   ['185.234.218.102'],
    'row_refs':              [0, 1, 2],
    'blast_radius_summary':  '3 accounts, 1 host',
    'phase_sequence':        ['execution', 'lateral_movement'],
    'attack_chain':          {'chain_text': 'cred_access → lateral_movement'},
    'reason_summary':        'azureuser shared across multiple sources',
    'fp_flag':               False,
}

_FAKE_ASSESSMENT = {
    'assessment_id':      ASSESSMENT_ID,
    'correlation_clusters': [_FAKE_CLUSTER],
    'normalized_rows':    [
        {'row_number': 0, 'row_index': 0, 'severity': 'high',
         'description': 'Suspicious logon from external IP', 'user': 'azureuser',
         'src_ip': '185.234.218.102', 'hostname': 'az-linux-01',
         'timestamp': '2025-01-15T10:00:00', 'mitre_technique': 'T1078'},
        {'row_number': 1, 'row_index': 1, 'severity': 'high',
         'description': 'Lateral movement via RDP', 'user': 'azureuser',
         'hostname': 'az-linux-02', 'timestamp': '2025-01-15T10:05:00',
         'mitre_technique': 'T1021'},
        {'row_number': 2, 'row_index': 2, 'severity': 'medium',
         'description': 'Credential access detected', 'user': 'azureuser',
         'timestamp': '2025-01-15T10:10:00', 'mitre_technique': 'T1003'},
    ],
}


def _inject_assessment(monkeypatch):
    """Inject a fake assessment into deep_analyze_endpoints.REPORT_STORE."""
    try:
        from src.api import deep_analyze_endpoints as _da
        _da.REPORT_STORE[ASSESSMENT_ID] = _FAKE_ASSESSMENT
    except Exception:
        pass


def _inject_assessment_cached(monkeypatch):
    """Monkeypatch _get_assessment_cached so disk lookup isn't needed."""
    def _fake_cached(aid):
        if aid == ASSESSMENT_ID:
            return _FAKE_ASSESSMENT
        return None

    monkeypatch.setattr(
        'src.api.tier2_canvas_endpoints._get_assessment',
        _fake_cached,
        raising=False,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — LLM summary endpoint resolves cluster from in-memory ASSESSMENT_STORE
# ─────────────────────────────────────────────────────────────────────────────

def test_llm_summary_uses_assessment_store(monkeypatch):
    """_get_assessment fallback to _ASSESSMENT_STORE should return cluster data."""
    _inject_assessment(monkeypatch)

    # Patch LLM client to avoid real inference
    class _FakeLLM:
        def generate(self, prompt, max_tokens=512, tenant_id=None, overrides=None):
            return {
                'text': (
                    'WHAT IS HAPPENING\nSuspicious login from external IP 185.234.218.102.\n\n'
                    'WHY IT MATTERS\nLateral movement could lead to data breach.\n\n'
                    'WHAT TO DO RIGHT NOW (top 3 actions, numbered, each ≤ 25 words)\n'
                    '1. Isolate azureuser immediately.\n2. Block 185.234.218.102 at firewall.\n3. Collect memory dump.\n\n'
                    'IS THIS REAL?\nLIKELY REAL — multiple correlated events across two sources.'
                ),
                'meta': {'model': 'qwen2.5:14b'},
            }

    monkeypatch.setattr('src.api.tier2_canvas_endpoints._LLM', _FakeLLM(), raising=False)

    client = TestClient(app)
    resp = client.get(
        f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/{CLUSTER_ID}/tier2/llm-summary',
        params={'model': 'qwen2.5:14b', 'force_refresh': 'true'},
        headers={'X-API-Key': 'devkey123'},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data.get('llm_available') is True, data
    sections = data.get('sections', {})
    assert 'what_is_happening' in sections
    assert 'LIKELY REAL' in sections.get('reality_verdict', '')


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — 404 with useful detail when assessment is missing
# ─────────────────────────────────────────────────────────────────────────────

def test_llm_summary_unparseable_output_gets_distinct_persona_fallback(monkeypatch):
    """Debug-style deterministic LLM output should still render useful persona steps."""
    _inject_assessment_cached(monkeypatch)

    class _FakeLLM:
        def generate(self, prompt, max_tokens=512, tenant_id=None, overrides=None):
            return {
                'text': json.dumps({
                    'provider': 'local-deterministic',
                    'summary': 'debug-json-not-numbered-sections',
                    'prompt_snippet': prompt[:160],
                }),
                'meta': {'model': 'qwen2.5:14b'},
            }

    monkeypatch.setattr('src.api.tier2_canvas_endpoints._LLM', _FakeLLM(), raising=False)

    client = TestClient(app)
    bodies = {}
    for persona in ('soc_analyst', 'threat_hunter', 'ciso'):
        resp = client.get(
            f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/{CLUSTER_ID}/tier2/llm-summary',
            params={'model': 'qwen2.5:14b', 'force_refresh': 'true'},
            headers={'X-API-Key': 'devkey123', 'x-persona': persona},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        bodies[persona] = body
        assert body['llm_available'] is True
        assert body['persona'] == persona
        assert body['fallback_generated'] is True
        assert body['fallback_reason'] == 'llm_output_unparseable'
        assert body['persona_steps']
        assert body['sections']['what_to_do']

    soc_text = json.dumps(bodies['soc_analyst']['persona_steps']).lower()
    hunter_text = json.dumps(bodies['threat_hunter']['persona_steps']).lower()
    ciso_text = json.dumps(bodies['ciso']['persona_steps']).lower()
    assert soc_text != hunter_text
    assert soc_text != ciso_text
    assert hunter_text != ciso_text
    assert 'contain' in soc_text or 'disable' in soc_text
    assert 'hunt' in hunter_text or 'pivot' in hunter_text
    assert 'business' in ciso_text or 'executive' in ciso_text


def test_llm_summary_404_missing_assessment():
    client = TestClient(app)
    resp = client.get(
        '/api/v1/assessments/nonexistent-assessment-id/clusters/cluster-1/tier2/llm-summary',
        params={'model': 'qwen2.5:14b'},
        headers={'X-API-Key': 'devkey123'},
    )
    assert resp.status_code == 404
    detail = resp.json().get('detail', '')
    assert 'nonexistent-assessment-id' in detail or 'not found' in detail.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — 404 with useful detail when cluster ID is wrong
# ─────────────────────────────────────────────────────────────────────────────

def test_llm_summary_404_missing_cluster(monkeypatch):
    """Assessment exists but cluster ID is wrong → 404 with cluster detail."""
    _inject_assessment_cached(monkeypatch)

    class _FakeLLM:
        def generate(self, *a, **kw):
            return {'text': '', 'meta': {}}

    monkeypatch.setattr('src.api.tier2_canvas_endpoints._LLM', _FakeLLM(), raising=False)

    client = TestClient(app)
    resp = client.get(
        f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/cluster-WRONG/tier2/llm-summary',
        params={'model': 'qwen2.5:14b', 'force_refresh': 'true'},
        headers={'X-API-Key': 'devkey123'},
    )
    assert resp.status_code == 404
    detail = resp.json().get('detail', '')
    assert 'cluster-WRONG' in detail or 'not found' in detail.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — Model catalog: enabled Ollama + disabled public models when no keys
# ─────────────────────────────────────────────────────────────────────────────

def test_model_catalog_structure(monkeypatch):
    """Catalog returns enabled Ollama models and disabled API models without keys."""
    # Simulate Ollama offline (no session / not enabled)
    monkeypatch.setattr('src.api.llm_catalog_endpoints.os.getenv',
                        lambda k, default='': default, raising=False)

    # Ensure no API keys bleed in from environment
    monkeypatch.delenv('ANTHROPIC_API_KEY', raising=False)
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)

    client = TestClient(app)
    resp = client.get('/api/v1/llm/models/catalog', headers={'X-API-Key': 'devkey123'})
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert 'models' in data
    models = data['models']
    assert isinstance(models, list)
    assert len(models) > 0, 'Should return at least fallback models'

    # When Ollama is offline: fallback local models should be present as disabled
    local_models = [m for m in models if m['provider'] == 'ollama']
    assert local_models, 'At least one Ollama entry expected'

    # Public cloud models should be present and disabled (no keys configured)
    cloud_models = [m for m in models if m['provider'] in ('anthropic', 'openai')]
    assert cloud_models, 'Claude/GPT entries should always appear in catalog'
    for m in cloud_models:
        assert m['available'] is False, f'{m["id"]} should be disabled without key'
        assert m['disabled_reason'], f'{m["id"]} should have disabled_reason'


def test_model_catalog_with_api_key(monkeypatch):
    """When ANTHROPIC_API_KEY is set, Claude models should appear as available."""
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'test-sk-ant-key')
    monkeypatch.setenv('OPENAI_API_KEY', '')

    client = TestClient(app)
    resp = client.get('/api/v1/llm/models/catalog', headers={'X-API-Key': 'devkey123'})
    assert resp.status_code == 200
    models = resp.json()['models']

    anthropic_models = [m for m in models if m['provider'] == 'anthropic']
    assert anthropic_models, 'Anthropic models should appear'
    for m in anthropic_models:
        assert m['available'] is True, f'{m["id"]} should be enabled with key'
        assert m['disabled_reason'] is None


# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — CRAG REJECT still blocks LLM even when model/provider override given
# ─────────────────────────────────────────────────────────────────────────────

def test_crag_reject_blocks_llm_with_model_override(monkeypatch):
    """CRAG grade=REJECT → LLM is skipped regardless of model/provider override."""
    # Inject cluster into assessment store
    _inject_assessment(monkeypatch)

    # Stub the cluster grader to always return REJECT
    monkeypatch.setattr(
        'src.api.cluster_enrich_endpoints.grade_cluster',
        lambda cluster: {
            'verdict':   'REJECT',
            'composite': 0.15,
            'reasons':   [],
            'caveats':   ['Insufficient evidence coverage'],
        },
        raising=False,
    )

    # Stub LLM client to confirm it is NOT called
    called = []

    class _SpyLLM:
        def generate(self, *a, **kw):
            called.append(True)
            return {'text': '', 'meta': {}}

    monkeypatch.setattr('src.api.cluster_enrich_endpoints.DEFAULT_CLIENT', _SpyLLM(), raising=False)

    # Also make cluster accessible via _fetch_cluster
    def _fake_fetch(aid, cid):
        if aid == ASSESSMENT_ID and cid == CLUSTER_ID:
            return _FAKE_CLUSTER
        return None
    monkeypatch.setattr('src.api.cluster_enrich_endpoints._fetch_cluster', _fake_fetch, raising=False)

    client = TestClient(app)
    resp = client.post(
        f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/{CLUSTER_ID}/enrich',
        json={
            'tenant_id':      'default',
            'force_refresh':  True,
            'thinking_budget': 1024,
            'model':          'gpt-4o',
            'provider':       'openai',
        },
        headers={'X-API-Key': 'devkey123'},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data.get('llm_used') is False
    assert 'llm_skipped_reason' in data
    assert not called, 'LLM.generate must NOT be called for REJECT grade'


# ─────────────────────────────────────────────────────────────────────────────
# Test 6 — CRAG ACCEPT wires model/provider override to call_overrides
# ─────────────────────────────────────────────────────────────────────────────

def test_crag_enrich_passes_model_override_to_call(monkeypatch):
    """POST /enrich with model=qwen2.5:7b should pass that model to the LLM call."""
    _inject_assessment(monkeypatch)

    monkeypatch.setattr(
        'src.api.cluster_enrich_endpoints.grade_cluster',
        lambda cluster: {
            'verdict':   'ACCEPT',
            'composite': 0.80,
            'reasons':   ['high confidence', 'multi-source'],
            'caveats':   [],
        },
        raising=False,
    )

    received_overrides = {}

    class _SpyLLM:
        def generate(self, prompt, max_tokens=512, tenant_id=None, overrides=None):
            received_overrides.update(overrides or {})
            return {
                'text': '1. Challenge: none\n2. Evidence: strong\n3. Narrative: lateral movement\n4. Actions: isolate\n5. Escalation: ESCALATE',
                'meta': {'model': 'qwen2.5:7b', 'provider': 'ollama'},
            }

    monkeypatch.setattr('src.api.cluster_enrich_endpoints.DEFAULT_CLIENT', _SpyLLM(), raising=False)

    def _fake_fetch(aid, cid):
        if aid == ASSESSMENT_ID and cid == CLUSTER_ID:
            return _FAKE_CLUSTER
        return None
    monkeypatch.setattr('src.api.cluster_enrich_endpoints._fetch_cluster', _fake_fetch, raising=False)

    # Disable warmup so test doesn't hang
    monkeypatch.setattr('src.api.cluster_enrich_endpoints._try_warmup_ollama',
                        lambda *a, **kw: None, raising=False)

    client = TestClient(app)
    resp = client.post(
        f'/api/v1/assessments/{ASSESSMENT_ID}/clusters/{CLUSTER_ID}/enrich',
        json={
            'tenant_id':      'default',
            'force_refresh':  True,
            'thinking_budget': 1024,
            'model':          'qwen2.5:7b',
        },
        headers={'X-API-Key': 'devkey123'},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data.get('llm_used') is True
    # Model override should have been forwarded to call_overrides
    assert received_overrides.get('ollama_model') == 'qwen2.5:7b' or \
           received_overrides.get('model') == 'qwen2.5:7b', \
           f'Expected qwen2.5:7b in overrides, got: {received_overrides}'
