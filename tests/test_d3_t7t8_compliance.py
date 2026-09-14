"""Tests for D3 graph wiring, T7/T8 pattern learning, and compliance PDF endpoint."""
from __future__ import annotations

import io
import os
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# D3.js: breach.html loads D3 for hopgraph visualization
# (investigate.html archived; breach.html is now the primary platform)
# ---------------------------------------------------------------------------

class TestD3ScriptTag:
    def test_d3_loaded_in_breach_html(self):
        html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'static', 'breach.html')
        content = open(html_path, encoding='utf-8').read()
        assert 'd3.min.js' in content or 'cdn.jsdelivr.net/npm/d3' in content, \
            'D3 script tag missing from breach.html'

    def test_d3_loaded_before_breach_hopgraph_js(self):
        html_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'static', 'breach.html')
        content = open(html_path, encoding='utf-8').read()
        d3_pos = content.find('d3.min.js')
        hg_pos = content.find('breach_hopgraph.js')
        assert d3_pos != -1 and hg_pos != -1, 'Both D3 and breach_hopgraph.js must be present in breach.html'
        assert d3_pos < hg_pos, 'D3 must be loaded before breach_hopgraph.js'


class TestD3GraphJS:
    def test_hopgraph_uses_d3_forceSimulation(self):
        js_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'static', 'js', 'breach_hopgraph.js')
        content = open(js_path, encoding='utf-8').read()
        assert 'd3.forceSimulation' in content or 'forceSimulation' in content

    def test_hopgraph_renders_svg(self):
        js_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'static', 'js', 'breach_hopgraph.js')
        content = open(js_path, encoding='utf-8').read()
        assert 'd3.select' in content or 'svg' in content

    def test_hopgraph_requires_d3(self):
        js_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'static', 'js', 'breach_hopgraph.js')
        content = open(js_path, encoding='utf-8').read()
        assert 'typeof d3' in content or 'd3' in content, 'breach_hopgraph.js must reference d3'

    def test_hopgraph_has_force_layout(self):
        js_path = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'static', 'js', 'breach_hopgraph.js')
        content = open(js_path, encoding='utf-8').read()
        assert 'alphaTarget' in content or 'force' in content.lower()


# ---------------------------------------------------------------------------
# T7/T8: Pattern learning + weight update
# ---------------------------------------------------------------------------

class TestT7PatternLearning:
    @pytest.mark.asyncio
    async def test_t7_returns_empty_gracefully_on_db_unavailable(self):
        """T7 must not raise even when DB is unavailable."""
        os.environ.setdefault('DISABLE_DB', '1')
        from src.api.analyst_review_endpoints import _run_t7_pattern_learning
        result = await _run_t7_pattern_learning(tenant='test')
        assert 'candidate_count' in result
        assert 'candidates' in result
        assert isinstance(result['candidates'], dict)

    @pytest.mark.asyncio
    async def test_t7_returns_candidates_when_trainer_works(self):
        from src.api.analyst_review_endpoints import _run_t7_pattern_learning
        fake_weights = {'unsigned_binary': 0.75, 'lolbin_misuse': 0.85}
        with patch('src.ml.online_trainer.generate_candidate_weights', AsyncMock(return_value=fake_weights)):
            result = await _run_t7_pattern_learning(tenant='acme')
        assert result['candidate_count'] == 2
        assert result['candidates'] == fake_weights
        assert result['error'] is None


class TestT8WeightUpdate:
    @pytest.mark.asyncio
    async def test_t8_skips_on_empty_candidates(self):
        from src.api.analyst_review_endpoints import _run_t8_weight_update
        result = await _run_t8_weight_update({}, tenant='test')
        assert result['updated'] == 0
        assert result['error'] is None

    @pytest.mark.asyncio
    async def test_t8_upserts_weights(self):
        from src.api.analyst_review_endpoints import _run_t8_weight_update
        candidates = {'unsigned_binary': 0.8, 'lolbin_misuse': 0.9, 'macro_autoexec': 0.7}
        upsert_calls = []

        async def fake_upsert(factor, weight, tenant_id):
            upsert_calls.append((factor, weight))

        with patch('src.repositories.factor_weights_repo.upsert_factor_weight', fake_upsert):
            result = await _run_t8_weight_update(candidates, tenant='acme')

        assert result['updated'] == 3
        assert len(upsert_calls) == 3
        factors_updated = {fc[0] for fc in upsert_calls}
        assert factors_updated == {'unsigned_binary', 'lolbin_misuse', 'macro_autoexec'}

    @pytest.mark.asyncio
    async def test_t8_orchestrator_apply_called_when_available(self):
        from src.api.analyst_review_endpoints import _run_t8_weight_update
        candidates = {'unsigned_binary': 0.8}
        mock_orch = MagicMock()

        async def fake_upsert(factor, weight, tenant_id):
            pass

        with patch('src.repositories.factor_weights_repo.upsert_factor_weight', fake_upsert):
            with patch('src.orchestrator.core.get_orchestrator', return_value=mock_orch):
                await _run_t8_weight_update(candidates, tenant='test')

        mock_orch.apply_factor_weights.assert_called_once_with(candidates, source='t8_bitemporal')


class TestT7T8RunTogether:
    @pytest.mark.asyncio
    async def test_run_t7_t8_succeeds(self):
        from src.api.analyst_review_endpoints import _run_t7_t8
        fake_weights = {'unsigned_binary': 0.78}

        async def fake_gen(**kw):
            return fake_weights

        async def fake_upsert(factor, weight, tenant_id):
            pass

        with patch('src.ml.online_trainer.generate_candidate_weights', fake_gen):
            with patch('src.repositories.factor_weights_repo.upsert_factor_weight', fake_upsert):
                # Should complete without raising
                await _run_t7_t8(tenant='test')

    @pytest.mark.asyncio
    async def test_run_t7_t8_swallows_errors(self):
        from src.api.analyst_review_endpoints import _run_t7_t8

        async def failing_gen(**kw):
            raise RuntimeError('DB down')

        with patch('src.ml.online_trainer.generate_candidate_weights', failing_gen):
            # Must not raise
            await _run_t7_t8(tenant='test')


class TestAnalystReviewQueuedField:
    def test_t7_t8_queued_in_response(self):
        """analyst_review route must include t7_t8_queued field."""
        os.environ.setdefault('PLATFORM_LITE_INIT', '1')
        os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
        os.environ.setdefault('DISABLE_DB', '1')
        import importlib
        import src.api.analyst_review_endpoints as m
        import inspect
        src_code = inspect.getsource(m.analyst_review)
        assert 't7_t8_queued' in src_code


# ---------------------------------------------------------------------------
# Compliance PDF endpoint
# ---------------------------------------------------------------------------

class TestComplianceCollectFactors:
    def test_collect_factors_from_rows(self):
        from src.api.analyst_review_endpoints import _collect_factors
        assessment = {
            'rows': [
                {'factors': ['unsigned_binary', 'lolbin_misuse']},
                {'factors': ['macro_autoexec', 'unsigned_binary']},  # dedup
            ]
        }
        factors = _collect_factors(assessment)
        assert 'unsigned_binary' in factors
        assert 'lolbin_misuse' in factors
        assert 'macro_autoexec' in factors
        assert factors.count('unsigned_binary') == 1  # deduplicated

    def test_collect_factors_top_level(self):
        from src.api.analyst_review_endpoints import _collect_factors
        assessment = {'factors': ['high_entropy_section', 'fresh_download'], 'rows': []}
        factors = _collect_factors(assessment)
        assert 'high_entropy_section' in factors

    def test_collect_factors_empty(self):
        from src.api.analyst_review_endpoints import _collect_factors
        assert _collect_factors({}) == []


class TestBuildComplianceHtml:
    def test_html_contains_framework_controls(self):
        from src.api.analyst_review_endpoints import _build_compliance_html
        compliance_hits = {
            'cis': ['CIS-9.4', 'CIS-10.1'],
            'nist_csf': ['DE.CM-1'],
        }
        html = _build_compliance_html(
            assessment={'id': 'test', 'verdict': 'escalate', 'triage_score': 0.9},
            factors=['unsigned_binary'],
            compliance_hits=compliance_hits,
            mitre_techniques={'T1036', 'T1059'},
        )
        assert 'CIS Controls v8' in html
        assert 'CIS-9.4' in html
        assert 'NIST CSF' in html
        assert 'T1036' in html
        assert 'T1059' in html

    def test_html_graceful_empty(self):
        from src.api.analyst_review_endpoints import _build_compliance_html
        html = _build_compliance_html(
            assessment={},
            factors=[],
            compliance_hits={},
            mitre_techniques=set(),
        )
        assert '<html' in html
        assert 'No control mappings' in html

    def test_html_factor_table(self):
        from src.api.analyst_review_endpoints import _build_compliance_html
        html = _build_compliance_html(
            assessment={},
            factors=['lolbin_misuse', 'persistence_registry'],
            compliance_hits={},
            mitre_techniques=set(),
        )
        assert 'lolbin_misuse' in html
        assert 'persistence_registry' in html


class TestComplianceReportEndpointRoute:
    def test_compliance_report_route_registered(self):
        os.environ.setdefault('PLATFORM_LITE_INIT', '1')
        os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
        os.environ.setdefault('DISABLE_DB', '1')
        from src.api.app import app
        routes = {getattr(r, 'path', '') for r in app.router.routes}
        assert any('compliance_report' in r for r in routes), \
            f'compliance_report route not found. Routes: {sorted(r for r in routes if "assessment" in r)}'

    @pytest.mark.asyncio
    async def test_compliance_report_html_format(self):
        """compliance_report?format=html returns HTML for a valid in-memory assessment."""
        os.environ.setdefault('PLATFORM_LITE_INIT', '1')
        os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
        os.environ.setdefault('DISABLE_DB', '1')
        os.environ.setdefault('LLM_MOCK', '1')

        from fastapi.testclient import TestClient
        from src.api.app import app
        from src.api.deep_analyze_endpoints import REPORT_STORE

        aid = 'compliance-test-001'
        REPORT_STORE[aid] = {
            'assessment_id': aid,
            'verdict': 'escalate',
            'triage_score': 0.88,
            'rows': [{'factors': ['unsigned_binary', 'lolbin_misuse'], 'entity': 'test.exe'}],
        }

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get(
                f'/api/v1/assessments/{aid}/compliance_report',
                params={'format': 'html'},
                headers={'x-api-key': 'devkey123'},
            )
        assert resp.status_code == 200
        body = resp.text
        assert '<html' in body.lower()
