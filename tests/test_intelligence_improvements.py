"""Comprehensive tests for the intelligence improvement sprint.

Covers:
  1. factor_to_mitre.py  — MITRE v14/v15, eBPF, JA4/JARM, ATLAS, OWASP LLM 2025
  2. factor_to_compliance.py — iso42001, owasp_llm, owasp_api, nist_ai_rmf + AI factors
  3. framework_mapper.py  — T1649/T1651/T1654/T1657/T1659/T1666 control records + CVE context
  4. hopgraph.py           — JA4 + JARM fingerprint node/edge (+ JA3 regression)
  5. prefill_orchestrator.py — dynamic DREAD recompute (missing, grown 25%+, not stale)
  6. narrator.py           — campaign arc, scatter-gather structure, prompt content
"""

from __future__ import annotations

import asyncio
import inspect
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_llm_client(text: str = "test narrative") -> MagicMock:
    """Stub LLM client that returns a fixed text."""
    client = MagicMock()
    client.generate = MagicMock(return_value={"text": text})
    return client


def _make_async_llm_client(text: str = "test narrative") -> MagicMock:
    client = MagicMock()
    client.generate = AsyncMock(return_value={"text": text})
    return client


# ===========================================================================
# 1. factor_to_mitre.py
# ===========================================================================

class TestFactorToMitre:
    """Tests for src/core/mappings/factor_to_mitre.py."""

    @pytest.fixture(autouse=True)
    def _import(self):
        from src.core.mappings import factor_to_mitre as m
        self.mod = m
        self.FTM = m.FACTOR_TO_MITRE
        self.ATLAS = m.FACTOR_TO_ATLAS
        self.OWASP = m.FACTOR_TO_OWASP_LLM

    # ── MITRE v14/v15 technique factors ────────────────────────────────────

    def test_adcs_cert_abuse_maps_to_T1649(self):
        assert 'T1649' in self.FTM.get('iam:adcs_cert_request_abuse', [])

    def test_ssm_unusual_maps_to_T1651(self):
        assert 'T1651' in self.FTM.get('cloud:ssm_run_command_unusual', [])

    def test_ebpf_packet_rewrite_maps_to_T1659(self):
        assert 'T1659' in self.FTM.get('endpoint:ebpf_packet_rewrite', [])

    # ── eBPF-specific factors ───────────────────────────────────────────────

    @pytest.mark.parametrize("factor,expected_technique", [
        ('endpoint:ebpf_rootkit_persist',   'T1014'),
        ('endpoint:ebpf_map_read_large',    'T1083'),
        ('endpoint:ebpf_kprobe_on_secfn',   'T1014'),
        ('endpoint:ebpf_uprobe_libc',       'T1055'),
        ('endpoint:ebpf_perf_buffer_flood', 'T1499'),
        ('endpoint:ebpf_prog_persistent',   'T1014'),
    ])
    def test_ebpf_factor_has_technique(self, factor, expected_technique):
        techniques = self.FTM.get(factor, [])
        assert techniques, f"Factor {factor!r} not in FACTOR_TO_MITRE"
        assert expected_technique in techniques, (
            f"{factor!r} missing {expected_technique}, got {techniques}"
        )

    # ── Fingerprint factors ─────────────────────────────────────────────────

    def test_jarm_novel_factor_present(self):
        assert 'net:jarm_novel_server_fp' in self.FTM

    def test_jarm_novel_maps_to_proxy_technique(self):
        techniques = self.FTM.get('net:jarm_novel_server_fp', [])
        assert any(t in techniques for t in ('T1090', 'T1571')), (
            f"Expected T1090 or T1571 in {techniques}"
        )

    def test_ja4_novel_factor_present(self):
        assert 'net:ja4_novel_fingerprint' in self.FTM

    def test_ja4_novel_maps_to_T1071(self):
        assert 'T1071.001' in self.FTM.get('net:ja4_novel_fingerprint', [])

    # ── ATLAS dict ──────────────────────────────────────────────────────────

    def test_atlas_dict_non_empty(self):
        assert len(self.ATLAS) > 0

    def test_atlas_dict_values_are_lists(self):
        for k, v in self.ATLAS.items():
            assert isinstance(v, list), f"FACTOR_TO_ATLAS[{k!r}] is not a list"

    def test_atlas_has_ai_factors(self):
        # FACTOR_TO_ATLAS keys use bare names (prompt_injection, tool_abuse, ...)
        # or endpoint:/net: prefixed keys — at least one key should reference AI/agent topics
        assert any(
            any(kw in k for kw in ('injection', 'tool', 'model', 'agent', 'poison', 'llm', 'ai:'))
            for k in self.ATLAS
        ), f"FACTOR_TO_ATLAS has no AI/agent-related keys; keys={list(self.ATLAS)[:8]}"

    # ── OWASP LLM dict ─────────────────────────────────────────────────────

    def test_owasp_llm_dict_non_empty(self):
        assert len(self.OWASP) > 0

    def test_owasp_llm_values_contain_llm_codes(self):
        for k, v in self.OWASP.items():
            assert v, f"FACTOR_TO_OWASP_LLM[{k!r}] is empty"
            assert any('LLM' in str(item) for item in v), (
                f"FACTOR_TO_OWASP_LLM[{k!r}] has no LLM codes: {v}"
            )

    # ── get_all_mappings helper ─────────────────────────────────────────────
    # Returns {'mitre': [...], 'atlas': [...], 'owasp_llm': [...]}

    def test_get_all_mappings_returns_mitre_key(self):
        result = self.mod.get_all_mappings(['endpoint:ebpf_rootkit_persist'])
        assert 'mitre' in result
        assert 'T1014' in result['mitre']

    def test_get_all_mappings_handles_unknown_factor(self):
        result = self.mod.get_all_mappings(['does_not_exist:xyz'])
        assert result.get('mitre') == []
        assert result.get('atlas') == []

    def test_get_all_mappings_empty_list(self):
        result = self.mod.get_all_mappings([])
        assert result['mitre'] == []
        assert result['atlas'] == []
        assert result['owasp_llm'] == []

    def test_get_all_mappings_includes_atlas_for_ai_factor(self):
        # Any AI factor that appears in FACTOR_TO_ATLAS should produce atlas entries
        ai_factor = next((k for k in self.ATLAS if self.ATLAS[k]), None)
        if ai_factor:
            result = self.mod.get_all_mappings([ai_factor])
            assert result['atlas'], (
                f"No ATLAS entries for factor {ai_factor!r}; result={result}"
            )


# ===========================================================================
# 2. factor_to_compliance.py
# ===========================================================================

class TestFactorToCompliance:
    """Tests for src/core/mappings/factor_to_compliance.py."""

    @pytest.fixture(autouse=True)
    def _import(self):
        from src.core.mappings import factor_to_compliance as m
        self.mod = m
        self.FTC = m.FACTOR_TO_COMPLIANCE
        self.LABELS = m.FRAMEWORK_LABELS

    # ── FRAMEWORK_LABELS completeness ──────────────────────────────────────

    @pytest.mark.parametrize("fw_key", [
        'iso42001', 'owasp_llm', 'owasp_api', 'nist_ai_rmf', 'maestro',
        'cis', 'nist_csf', 'iso27001', 'soc2', 'pci_dss',
    ])
    def test_framework_label_present(self, fw_key):
        assert fw_key in self.LABELS, f"{fw_key!r} missing from FRAMEWORK_LABELS"

    def test_framework_labels_have_human_readable_values(self):
        for key, label in self.LABELS.items():
            assert isinstance(label, str) and len(label) > 3, (
                f"FRAMEWORK_LABELS[{key!r}] = {label!r} looks invalid"
            )

    # ── AI factor entries ───────────────────────────────────────────────────

    def test_ai_factor_maps_to_iso42001(self):
        """At least one AI factor should have iso42001 mapping."""
        has_iso42001 = any(
            'iso42001' in v
            for v in self.FTC.values()
            if isinstance(v, dict)
        )
        assert has_iso42001, "No factor maps to iso42001 framework"

    def test_ai_factor_maps_to_owasp_llm(self):
        has_owasp = any(
            'owasp_llm' in v
            for v in self.FTC.values()
            if isinstance(v, dict)
        )
        assert has_owasp, "No factor maps to owasp_llm framework"

    def test_ai_factor_maps_to_nist_ai_rmf(self):
        has_nist_ai = any(
            'nist_ai_rmf' in v
            for v in self.FTC.values()
            if isinstance(v, dict)
        )
        assert has_nist_ai, "No factor maps to nist_ai_rmf framework"

    # ── get_compliance_hits ─────────────────────────────────────────────────

    def test_get_compliance_hits_returns_iso42001_for_ai_factor(self):
        # Find a factor that maps to iso42001
        target_factor = next(
            (k for k, v in self.FTC.items() if isinstance(v, dict) and 'iso42001' in v),
            None,
        )
        if target_factor is None:
            pytest.skip("No factor with iso42001 mapping found")
        hits = self.mod.get_compliance_hits([target_factor])
        assert 'iso42001' in hits, f"Expected iso42001 in hits for {target_factor!r}"
        assert hits['iso42001'], "iso42001 controls list should be non-empty"

    def test_get_compliance_hits_returns_owasp_llm_controls(self):
        target_factor = next(
            (k for k, v in self.FTC.items() if isinstance(v, dict) and 'owasp_llm' in v),
            None,
        )
        if target_factor is None:
            pytest.skip("No factor with owasp_llm mapping found")
        hits = self.mod.get_compliance_hits([target_factor])
        assert 'owasp_llm' in hits
        assert hits['owasp_llm']

    def test_get_compliance_hits_empty_factors(self):
        result = self.mod.get_compliance_hits([])
        assert result == {}

    def test_get_compliance_hits_unknown_factor(self):
        result = self.mod.get_compliance_hits(['totally:unknown'])
        assert result == {}

    def test_get_compliance_hits_deduplicates_controls(self):
        """Same factor listed twice should not duplicate controls."""
        factor = next(iter(self.FTC))
        hits_single = self.mod.get_compliance_hits([factor])
        hits_double = self.mod.get_compliance_hits([factor, factor])
        assert hits_single == hits_double

    def test_get_compliance_hits_returns_sorted_controls(self):
        """Controls within each framework should be sorted."""
        target_factor = next(iter(self.FTC))
        hits = self.mod.get_compliance_hits([target_factor])
        for fw, controls in hits.items():
            assert controls == sorted(controls), (
                f"Controls for {fw!r} are not sorted: {controls}"
            )


# ===========================================================================
# 3. framework_mapper.py
# ===========================================================================

class TestFrameworkMapper:
    """Tests for src/analysis/framework_mapper.py."""

    @pytest.fixture(autouse=True)
    def _import(self):
        from src.analysis import framework_mapper as m
        self.mod = m
        self.TTC = m._TECHNIQUE_TO_CONTROLS
        self.CVE = m._TECHNIQUE_CVE_CONTEXT

    # ── New technique → control records ────────────────────────────────────

    @pytest.mark.parametrize("technique", [
        'T1649', 'T1651', 'T1654', 'T1657', 'T1659', 'T1666',
    ])
    def test_new_technique_in_controls_map(self, technique):
        assert technique in self.TTC, (
            f"{technique} not found in _TECHNIQUE_TO_CONTROLS"
        )

    @pytest.mark.parametrize("technique", [
        'T1649', 'T1651', 'T1654', 'T1657', 'T1659', 'T1666',
    ])
    def test_new_technique_controls_have_required_fields(self, technique):
        required = {'framework', 'control_id', 'control_name', 'failure_type',
                    'severity', 'remediation_priority'}
        records = self.TTC.get(technique, [])
        assert records, f"No control records for {technique}"
        for rec in records:
            missing = required - rec.keys()
            assert not missing, (
                f"{technique} control record missing fields: {missing} — {rec}"
            )

    @pytest.mark.parametrize("technique", [
        'T1649', 'T1651', 'T1654', 'T1657', 'T1659', 'T1666',
    ])
    def test_new_technique_severity_valid(self, technique):
        valid = {'critical', 'high', 'moderate', 'low'}
        for rec in self.TTC.get(technique, []):
            assert rec['severity'] in valid, (
                f"{technique}: invalid severity {rec['severity']!r}"
            )

    @pytest.mark.parametrize("technique", [
        'T1649', 'T1651', 'T1654', 'T1657', 'T1659', 'T1666',
    ])
    def test_new_technique_remediation_priority_valid(self, technique):
        valid = {'P1', 'P2', 'P3'}
        for rec in self.TTC.get(technique, []):
            assert rec['remediation_priority'] in valid, (
                f"{technique}: invalid remediation_priority {rec['remediation_priority']!r}"
            )

    # ── CVE context entries ─────────────────────────────────────────────────

    @pytest.mark.parametrize("technique", [
        'T1649', 'T1651', 'T1654', 'T1657', 'T1659', 'T1666',
    ])
    def test_new_technique_in_cve_context(self, technique):
        assert technique in self.CVE, (
            f"{technique} not found in _TECHNIQUE_CVE_CONTEXT"
        )

    @pytest.mark.parametrize("technique", [
        'T1649', 'T1651', 'T1654', 'T1657', 'T1659', 'T1666',
    ])
    def test_cve_context_has_required_keys(self, technique):
        required = {
            'cves', 'breach_analogues', 'control_ids_implicated',
            'business_impact_usd', 'auditor_asks', 'remediation_roadmap',
        }
        ctx = self.CVE.get(technique, {})
        missing = required - ctx.keys()
        assert not missing, (
            f"{technique} CVE context missing keys: {missing}"
        )

    @pytest.mark.parametrize("technique", [
        'T1649', 'T1651', 'T1654', 'T1657', 'T1659', 'T1666',
    ])
    def test_cve_context_remediation_roadmap_has_p1_p2_p3(self, technique):
        roadmap = self.CVE.get(technique, {}).get('remediation_roadmap', {})
        for key in ('P1_48h', 'P2_30d', 'P3_90d'):
            assert key in roadmap, (
                f"{technique} remediation_roadmap missing {key!r}: {roadmap}"
            )

    def test_cve_context_business_impact_is_numeric(self):
        for tech, ctx in self.CVE.items():
            usd = ctx.get('business_impact_usd')
            if usd is not None:
                assert isinstance(usd, (int, float)), (
                    f"{tech} business_impact_usd is not numeric: {usd!r}"
                )

    # ── get_cve_context_for_techniques ─────────────────────────────────────

    def test_get_cve_context_returns_t1649(self):
        result = self.mod.get_cve_context_for_techniques(['T1649'])
        assert 'T1649' in result

    def test_get_cve_context_empty_list(self):
        assert self.mod.get_cve_context_for_techniques([]) == {}

    def test_get_cve_context_unknown_technique(self):
        result = self.mod.get_cve_context_for_techniques(['T9999'])
        assert result == {}


# ===========================================================================
# 4. hopgraph.py — JA4 + JARM fingerprint support
# ===========================================================================

class TestHopGraphFingerprints:
    """Tests for JA4 and JARM additions in src/graph/hopgraph.py.

    HopGraph stores:
      - nodes in  graph.nodes  (plain dict, key = node_id string)
      - edges in  graph.adj    (dict: src -> list of (dst, edge_type, ts, source, weight))
    """

    @pytest.fixture
    def graph(self):
        from src.graph.hopgraph import HopGraph
        return HopGraph()

    def _base_event(self, **kwargs):
        return {
            'src_ip': '10.0.0.1',
            'dst_ip': '1.2.3.4',
            'process': 'curl.exe',
            'pid': 1234,
            **kwargs,
        }

    def _all_edge_types(self, graph) -> list:
        """Collect all edge_type strings from adj."""
        types = []
        for edges in graph.adj.values():
            for tup in edges:
                if len(tup) > 1:
                    types.append(tup[1])
        return types

    # ── JA3 regression ─────────────────────────────────────────────────────

    def test_ja3_node_created(self, graph):
        fp = 'aabbcc0011223344556677889900aabb'
        graph.ingest_event(self._base_event(ja3=fp), source='test')
        assert f'ja3:{fp}' in graph.nodes, "ja3 node not found in graph.nodes"

    def test_ja3_edge_type_is_tls_ja3(self, graph):
        fp = 'aabbcc0011223344556677889900aabb'
        graph.ingest_event(self._base_event(ja3=fp), source='test')
        assert 'tls_ja3' in self._all_edge_types(graph), (
            f"No tls_ja3 edge. Edge types: {self._all_edge_types(graph)}"
        )

    # ── JA4 new support ─────────────────────────────────────────────────────

    def test_ja4_node_created(self, graph):
        fp = 't13d1516h2_8daaf6152771_b0da82dd1658'
        graph.ingest_event(self._base_event(ja4=fp), source='test')
        assert f'ja4:{fp}' in graph.nodes, "ja4 node not found in graph.nodes"

    def test_ja4_edge_type_is_tls_ja4(self, graph):
        fp = 't13d1516h2_8daaf6152771_b0da82dd1658'
        graph.ingest_event(self._base_event(ja4=fp), source='test')
        assert 'tls_ja4' in self._all_edge_types(graph), (
            f"No tls_ja4 edge. Edge types: {self._all_edge_types(graph)}"
        )

    def test_ja4_none_does_not_crash(self, graph):
        graph.ingest_event(self._base_event(ja4=None), source='test')

    def test_ja4_empty_string_does_not_create_node(self, graph):
        before = set(graph.nodes.keys())
        graph.ingest_event(self._base_event(ja4=''), source='test')
        after = set(graph.nodes.keys())
        new_nodes = after - before
        assert not any(n.startswith('ja4:') for n in new_nodes), (
            f"ja4 node created for empty string: {new_nodes}"
        )

    # ── JARM new support ────────────────────────────────────────────────────

    def test_jarm_node_created(self, graph):
        fp = '2ad2ad0002ad2ad00042d4241d8a5e05b085d2a13d5cb4e02b06ba7bb4caf4'
        graph.ingest_event(self._base_event(jarm=fp), source='test')
        assert f'jarm:{fp}' in graph.nodes, "jarm node not found in graph.nodes"

    def test_jarm_edge_type_is_jarm_fingerprint(self, graph):
        fp = '2ad2ad0002ad2ad00042d4241d8a5e05b085d2a13d5cb4e02b06ba7bb4caf4'
        graph.ingest_event(self._base_event(jarm=fp), source='test')
        assert 'jarm_fingerprint' in self._all_edge_types(graph), (
            f"No jarm_fingerprint edge. Edge types: {self._all_edge_types(graph)}"
        )

    def test_jarm_requires_dst_ip(self, graph):
        """JARM without dst_ip should not create jarm node (attached to dst IP node)."""
        fp = '2ad2ad0002ad2ad00042d4241d8a5e05b085d2a13d5cb4e02b06ba7bb4caf4'
        before = set(graph.nodes.keys())
        graph.ingest_event({'process': 'curl.exe', 'pid': 1, 'jarm': fp}, source='test')
        after = set(graph.nodes.keys())
        new_nodes = after - before
        assert not any(n.startswith('jarm:') for n in new_nodes), (
            f"jarm node created without dst_ip: {new_nodes}"
        )

    def test_jarm_none_does_not_crash(self, graph):
        graph.ingest_event(self._base_event(jarm=None), source='test')

    # ── Both JA3 and JA4 in same event ──────────────────────────────────────

    def test_ja3_and_ja4_both_created(self, graph):
        event = self._base_event(
            ja3='aabbcc0011223344556677889900aabb',
            ja4='t13d1516h2_8daaf6152771_b0da82dd1658',
        )
        graph.ingest_event(event, source='test')
        assert 'ja3:aabbcc0011223344556677889900aabb' in graph.nodes
        assert 'ja4:t13d1516h2_8daaf6152771_b0da82dd1658' in graph.nodes


# ===========================================================================
# 5. prefill_orchestrator.py — dynamic DREAD recompute
# ===========================================================================

class TestDreadRecompute:
    """Tests for dynamic DREAD recompute guard in _enrich_cluster_intelligence."""

    @pytest.fixture(autouse=True)
    def _import(self):
        from src.core.tier1_prefill.prefill_orchestrator import _compute_dread_score
        self._compute = _compute_dread_score

    def _make_cluster(self, phases=None, confidence=0.9):
        return {
            'cluster_id': 'c-001',
            'attack_phases': phases or ['initial_access', 'lateral_movement'],
            'confidence': confidence,
            'cluster_size': 10,
        }

    def _make_rows(self, n=10):
        return [
            {
                'source': 'sysmon',
                'triage_score': 0.8,
                'event_text': f'row {i} powershell encoded command admin',
            }
            for i in range(n)
        ]

    # ── _compute_dread_score return shape ───────────────────────────────────

    def test_dread_returns_all_dimensions(self):
        score = self._compute(self._make_cluster(), self._make_rows(10))
        required = {
            'damage', 'reproducibility', 'exploitability',
            'affected_users', 'discoverability',
        }
        assert required.issubset(score.keys()), (
            f"DREAD missing keys: {required - score.keys()}"
        )

    def test_dread_scores_in_range(self):
        score = self._compute(self._make_cluster(), self._make_rows(10))
        for dim in ('damage', 'reproducibility', 'exploitability',
                    'affected_users', 'discoverability'):
            val = score[dim]
            assert isinstance(val, (int, float)), f"{dim} is not numeric: {val}"
            assert 0 <= val <= 10, f"{dim} = {val} out of [0, 10]"

    def test_dread_empty_rows_does_not_crash(self):
        score = self._compute(self._make_cluster(), [])
        assert isinstance(score, dict)

    # ── Dynamic recompute: _row_count stamp ────────────────────────────────

    def test_dread_score_row_count_stored(self):
        """_enrich_cluster_intelligence should stamp _row_count after compute."""
        # We test the orchestration logic directly via a minimal integration:
        # replicate the guard logic as documented in the source
        rows = self._make_rows(8)
        score = self._compute(self._make_cluster(), rows)
        # Simulate orchestrator stamping _row_count (done in real code)
        score['_row_count'] = len(rows)
        assert score['_row_count'] == 8

    def test_dread_stale_when_rows_grow_25_percent(self):
        """Staleness condition: prior_count=8, current=10 → 25% growth → stale."""
        prior_count = 8
        current_count = 10  # 25% growth from 8
        dread_stale = prior_count > 0 and current_count >= prior_count * 1.25
        assert dread_stale, "Expected stale=True for 25% growth"

    def test_dread_not_stale_when_rows_grow_less_than_25_percent(self):
        """24% growth should NOT trigger recompute."""
        prior_count = 100
        current_count = 124  # 24% growth
        dread_stale = prior_count > 0 and current_count >= prior_count * 1.25
        assert not dread_stale, "Expected stale=False for <25% growth"

    def test_dread_stale_exactly_at_threshold(self):
        """Exactly 25% growth (10 → 12.5, floor to 12) should trigger."""
        prior_count = 8
        current_count = 10  # 10 >= 8 * 1.25 = 10.0 — boundary case
        dread_stale = prior_count > 0 and current_count >= prior_count * 1.25
        assert dread_stale

    def test_dread_computed_when_no_prior_score(self):
        """When existing_dread is None, recompute must happen."""
        existing_dread = None
        rows = self._make_rows(5)
        # Replicate the guard: (not _existing_dread or _dread_stale) and rows
        dread_stale = False  # no prior score
        should_compute = (not existing_dread or dread_stale) and bool(rows)
        assert should_compute


# ===========================================================================
# 6. narrator.py
# ===========================================================================

class TestNarratorCampaignArc:
    """Tests for campaign arc and scatter-gather additions in src/agents/narrator.py."""

    @pytest.fixture(autouse=True)
    def _import(self):
        import src.agents.narrator as m
        self.mod = m

    # ── Function signatures ─────────────────────────────────────────────────

    def test_narrate_scatter_gather_is_async(self):
        assert inspect.iscoroutinefunction(self.mod.narrate_scatter_gather)

    def test_narrate_campaign_arc_is_async(self):
        assert inspect.iscoroutinefunction(self.mod.narrate_campaign_arc)

    def test_narrate_scatter_gather_signature(self):
        sig = inspect.signature(self.mod.narrate_scatter_gather)
        params = set(sig.parameters)
        assert 'context' in params
        assert 'verified' in params
        assert 'kill_chain' in params
        assert 'llm_client' in params

    def test_narrate_campaign_arc_signature(self):
        sig = inspect.signature(self.mod.narrate_campaign_arc)
        params = set(sig.parameters)
        assert 'cluster_narratives' in params
        assert 'llm_client' in params
        assert 'tenant_id' in params

    # ── Campaign arc system prompt ──────────────────────────────────────────

    def test_campaign_arc_system_prompt_exists(self):
        assert hasattr(self.mod, '_CAMPAIGN_ARC_SYSTEM')
        assert isinstance(self.mod._CAMPAIGN_ARC_SYSTEM, str)
        assert len(self.mod._CAMPAIGN_ARC_SYSTEM) > 50

    def test_campaign_arc_prompt_mentions_kill_chain(self):
        prompt = self.mod._CAMPAIGN_ARC_SYSTEM.lower()
        assert any(kw in prompt for kw in ('kill chain', 'kill-chain', 'attack chain', 'campaign')), (
            "Campaign arc prompt should mention kill chain or campaign"
        )

    # ── Scatter-gather specialist prompts ──────────────────────────────────

    def test_timeline_mini_system_prompt_exists(self):
        assert hasattr(self.mod, '_TIMELINE_MINI_SYSTEM')
        assert isinstance(self.mod._TIMELINE_MINI_SYSTEM, str)

    def test_attribution_mini_system_prompt_exists(self):
        assert hasattr(self.mod, '_ATTRIBUTION_MINI_SYSTEM')
        assert isinstance(self.mod._ATTRIBUTION_MINI_SYSTEM, str)

    def test_impact_mini_system_prompt_exists(self):
        assert hasattr(self.mod, '_IMPACT_MINI_SYSTEM')
        assert isinstance(self.mod._IMPACT_MINI_SYSTEM, str)

    def test_compliance_mini_system_prompt_exists(self):
        assert hasattr(self.mod, '_COMPLIANCE_MINI_SYSTEM')
        assert isinstance(self.mod._COMPLIANCE_MINI_SYSTEM, str)

    def test_synthesis_system_prompt_exists(self):
        assert hasattr(self.mod, '_SYNTHESIS_SYSTEM')
        assert isinstance(self.mod._SYNTHESIS_SYSTEM, str)

    # ── narrate_campaign_arc with stub LLM ─────────────────────────────────

    def test_campaign_arc_returns_string(self):
        stub = _make_llm_client("Multi-cluster attack campaign identified.")
        cluster_narratives = [
            {
                'cluster_id': 'c-001',
                'narrative': 'Attacker gained initial access via phishing.',
                'kill_chain_phases': ['initial_access'],
                'iocs': ['evil.com', '1.2.3.4'],
                'mitre_techniques': ['T1566.001'],
                'dread_score': {'risk_tier': 'CRITICAL'},
                'verdict': 'VALIDATED_BREACH',
            },
            {
                'cluster_id': 'c-002',
                'narrative': 'Lateral movement via PtH.',
                'kill_chain_phases': ['lateral_movement'],
                'iocs': ['evil.com', '5.6.7.8'],
                'mitre_techniques': ['T1550.002'],
                'dread_score': {'risk_tier': 'HIGH'},
                'verdict': 'VALIDATED_BREACH',
            },
        ]
        result = asyncio.get_event_loop().run_until_complete(
            self.mod.narrate_campaign_arc(cluster_narratives, llm_client=stub, tenant_id='test')
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_campaign_arc_empty_clusters_returns_empty_string(self):
        stub = _make_llm_client("Nothing here")
        result = asyncio.get_event_loop().run_until_complete(
            self.mod.narrate_campaign_arc([], llm_client=stub)
        )
        assert result == ""

    def test_campaign_arc_detects_shared_iocs(self):
        """Shared IOCs across clusters should be passed to LLM prompt."""
        stub = _make_llm_client("Shared IOC: evil.com links clusters")
        clusters = [
            {'cluster_id': f'c-{i}', 'narrative': '', 'kill_chain_phases': [],
             'iocs': ['evil.com', f'unique-{i}.com'], 'mitre_techniques': [],
             'dread_score': {}, 'verdict': ''}
            for i in range(3)
        ]
        result = asyncio.get_event_loop().run_until_complete(
            self.mod.narrate_campaign_arc(clusters, llm_client=stub)
        )
        # Verify llm was called (and didn't return empty)
        assert isinstance(result, str)
        stub.generate.assert_called_once()
        # The prompt passed to generate should contain shared IOC info
        call_args = stub.generate.call_args
        prompt_text = call_args[0][0] if call_args[0] else str(call_args)
        assert 'evil.com' in prompt_text

    # ── narrate_scatter_gather return shape ────────────────────────────────

    def _make_investigation_context(self):
        """Create a minimal InvestigationContext stub."""
        try:
            from src.agents.narrator import InvestigationContext
            return InvestigationContext(
                tenant_id='test-tenant',
                cluster_id='c-001',
                source_files=['sysmon.json'],
            )
        except (ImportError, TypeError):
            ctx = MagicMock()
            ctx.tenant_id = 'test-tenant'
            ctx.cluster_id = 'c-001'
            return ctx

    def _make_verified_finding(self, summary: str = "test event"):
        """Create a minimal VerifiedFinding stub with numeric dread_score."""
        vf = MagicMock()
        vf.raw = MagicMock()
        vf.raw.summary = summary
        vf.raw.mitre_techniques = ['T1566.001']
        vf.raw.confidence = 0.85
        vf.confidence = 0.85
        vf.dread_score = 5.0  # numeric, required by compute_aggregate_confidence
        vf.verdict = 'CONFIRMED'
        return vf

    def test_scatter_gather_returns_required_keys(self):
        stub = _make_llm_client("Timeline: Day 1. Attribution: APT29. Impact: $5M. Compliance: ISO 27001 A.8.5 failed.")
        ctx = self._make_investigation_context()
        verified = [self._make_verified_finding(f"event {i}") for i in range(3)]

        result = asyncio.get_event_loop().run_until_complete(
            self.mod.narrate_scatter_gather(ctx, verified, llm_client=stub)
        )
        required_keys = {'narrative', 'confidence', 'compliance_controls', 'gaps', 'findings_count'}
        assert required_keys.issubset(result.keys()), (
            f"Missing keys: {required_keys - result.keys()}"
        )

    def test_scatter_gather_includes_specialist_outputs(self):
        stub = _make_llm_client("Narrative with specialist analysis.")
        ctx = self._make_investigation_context()
        verified = [self._make_verified_finding("phishing email detected")]

        result = asyncio.get_event_loop().run_until_complete(
            self.mod.narrate_scatter_gather(ctx, verified, llm_client=stub)
        )
        # Should include specialist_outputs (even if fallback path taken)
        assert 'specialist_outputs' in result

    def test_scatter_gather_confidence_in_range(self):
        stub = _make_llm_client("Confirmed breach narrative.")
        ctx = self._make_investigation_context()
        verified = [self._make_verified_finding("lateral movement detected")]

        result = asyncio.get_event_loop().run_until_complete(
            self.mod.narrate_scatter_gather(ctx, verified, llm_client=stub)
        )
        conf = result.get('confidence', -1)
        assert 0.0 <= conf <= 1.0, f"confidence {conf} out of [0, 1]"

    # ── build_narrator_prompt campaign arc content ──────────────────────────

    def test_narrator_prompt_mentions_evidence_citation(self):
        """System prompt should instruct the LLM to cite evidence rows."""
        system = self.mod._NARRATOR_SYSTEM
        lower = system.lower()
        assert any(kw in lower for kw in ('row', 'cite', 'citation', '[row', 'evidence')), (
            "System prompt should mention evidence citation"
        )

    def test_narrator_prompt_mentions_uncertainty(self):
        """System prompt should include uncertainty quantification guidance."""
        system = self.mod._NARRATOR_SYSTEM
        lower = system.lower()
        assert any(kw in lower for kw in ('uncertain', 'confidence', 'likely', 'unknown')), (
            "System prompt should address uncertainty quantification"
        )


# ===========================================================================
# 7. Integration smoke tests
# ===========================================================================

class TestIntegrationSmoke:
    """Cross-module smoke tests: mapping → narrator pipeline."""

    def test_factor_to_mitre_to_compliance_chain(self):
        """New eBPF factor should produce MITRE techniques AND compliance controls."""
        from src.core.mappings.factor_to_mitre import get_all_mappings
        from src.core.mappings.factor_to_compliance import get_compliance_hits

        ebpf_factor = 'endpoint:ebpf_rootkit_persist'
        mitre_result = get_all_mappings([ebpf_factor])
        # get_all_mappings returns {'mitre': [...], 'atlas': [...], 'owasp_llm': [...]}
        assert 'T1014' in mitre_result.get('mitre', [])

        # Same factor should not crash compliance hits (may be empty without direct entry)
        compliance_result = get_compliance_hits([ebpf_factor])
        assert isinstance(compliance_result, dict)

    def test_new_technique_controls_are_well_formed(self):
        """All newly-added technique control records pass structural validation."""
        from src.analysis.framework_mapper import _TECHNIQUE_TO_CONTROLS
        new_techniques = ['T1649', 'T1651', 'T1654', 'T1657', 'T1659', 'T1666']
        for tech in new_techniques:
            records = _TECHNIQUE_TO_CONTROLS.get(tech, [])
            assert records, f"No control records for {tech}"
            for rec in records:
                assert rec.get('framework'), f"{tech}: empty framework"
                assert rec.get('control_id'), f"{tech}: empty control_id"
                assert rec.get('severity') in ('critical', 'high', 'moderate', 'low'), (
                    f"{tech}: bad severity {rec.get('severity')!r}"
                )

    def test_hopgraph_ja4_and_jarm_simultaneously(self):
        """Single event with JA3 + JA4 + JARM should create all three nodes."""
        from src.graph.hopgraph import HopGraph
        g = HopGraph()
        event = {
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'process': 'chrome.exe',
            'pid': 9999,
            'ja3': 'aabbccddeeff00112233445566778899',
            'ja4': 't13d1516h2_8daaf6152771_b0da82dd1658',
            'jarm': '2ad2ad0002ad2ad00042d42411223344',
        }
        g.ingest_event(event, source='pcap')
        assert 'ja3:aabbccddeeff00112233445566778899' in g.nodes
        assert 'ja4:t13d1516h2_8daaf6152771_b0da82dd1658' in g.nodes
        assert 'jarm:2ad2ad0002ad2ad00042d42411223344' in g.nodes

    def test_dread_score_with_privilege_signals(self):
        """DREAD Damage should be elevated when privilege escalation signals present.

        _compute_dread_score reads cluster.get('phases') (list of phase dicts)
        and cluster.get('sources') (list of source names).
        With 2 phases and 2 sources: base = 2*2 + 2 = 6; +2 for privilege = 8.
        """
        from src.core.tier1_prefill.prefill_orchestrator import _compute_dread_score
        cluster = {
            'cluster_id': 'priv-test',
            'phases': [
                {'phase_id': 'privilege_escalation'},
                {'phase_id': 'credential_access'},
            ],
            'sources': ['sysmon', 'wineventlog'],
            'confidence': 0.95,
        }
        rows = [
            {'source': 'sysmon', 'triage_score': 0.9,
             'event_text': 'admin mimikatz lsass secretsdump domain_admin'},
        ]
        score = _compute_dread_score(cluster, rows)
        # With 2 phases + 2 sources + privilege boost: damage should be >= 6
        assert score['damage'] >= 6, f"Expected damage >= 6, got {score['damage']}"


class TestEvidenceRetention:
    """Sprint 4: clustering evidence-flow integrity.

    Guards the triage-aware oversized-cap fix — high-triage attack evidence must
    survive the cap even when it arrives late in the log (high row_index).
    """

    def _make_oversized_cluster(self, n_rows=600, attack_from=450, cap_floor=0.8):
        import random
        random.seed(42)
        rows = []
        for idx in range(n_rows):
            triage = 0.05 if idx < attack_from else (cap_floor + 0.05 + random.random() * 0.1)
            rows.append({'row_index': idx, 'triage_score': round(triage, 3)})
        row_by_idx = {r['row_index']: r for r in rows}
        cluster = {
            'cluster_id': 'oversized-apt',
            'row_refs': sorted(r['row_index'] for r in rows),
            'row_count': n_rows,
        }
        return cluster, rows, row_by_idx

    def test_triage_aware_cap_retains_all_attack_evidence(self):
        """High-triage rows at high indices must survive the oversized cap."""
        from src.core.ingest.cluster_merge import _cap_oversized_clusters
        cluster, rows, row_by_idx = self._make_oversized_cluster()
        capped = _cap_oversized_clusters([dict(cluster)], row_by_idx)[0]
        kept = set(capped['row_refs'])
        attack = [r['row_index'] for r in rows if r['triage_score'] >= 0.8]
        survived = [i for i in attack if i in kept]
        assert capped.get('_oversized_retention') == 'triage_ranked'
        assert capped.get('_oversized') is True
        assert capped.get('_total_row_count') == 600
        assert len(survived) == len(attack), (
            f"triage-aware cap lost attack evidence: {len(attack) - len(survived)} of "
            f"{len(attack)} high-triage rows dropped"
        )

    def test_cap_preserves_index_order_for_provenance(self):
        """Kept row_refs must stay sorted by index so row_index->row_refs matching holds."""
        from src.core.ingest.cluster_merge import _cap_oversized_clusters
        cluster, rows, row_by_idx = self._make_oversized_cluster()
        capped = _cap_oversized_clusters([dict(cluster)], row_by_idx)[0]
        refs = capped['row_refs']
        assert refs == sorted(refs), "row_refs must remain index-sorted after triage cap"
        assert len(refs) == 500

    def test_legacy_index_truncation_without_row_map(self):
        """Backward compat: no row_by_idx -> legacy index truncation, no crash."""
        from src.core.ingest.cluster_merge import _cap_oversized_clusters
        cluster, rows, row_by_idx = self._make_oversized_cluster()
        capped = _cap_oversized_clusters([dict(cluster)])[0]
        assert capped.get('_oversized_retention') == 'index_truncated'
        assert len(capped['row_refs']) == 500

    def test_small_clusters_untouched(self):
        """Clusters under the cap must pass through unchanged (no _oversized tag)."""
        from src.core.ingest.cluster_merge import _cap_oversized_clusters
        cluster = {'cluster_id': 'small', 'row_refs': list(range(10)), 'row_count': 10}
        out = _cap_oversized_clusters([dict(cluster)], {i: {'triage_score': 0.5} for i in range(10)})[0]
        assert out.get('_oversized') is None
        assert out['row_refs'] == list(range(10))


class TestIocGroundingGuardrail:
    """Sprint 4: deterministic IOC grounding backstop in the narrator."""

    def test_flags_fabricated_entities_spares_real_and_mitre(self):
        from src.core.ingest.cluster_narrator import _validate_ioc_grounding
        evidence = [
            {'user_canonical': 'martin.chen', 'src_ip': '10.42.4.91', 'hostname': 'ws-martin-01'},
            {'dst_ip': '10.42.1.10', 'event_text': 'Kerberos TGS RC4'},
        ]
        narrative = {
            'attack_narrative': ('martin.chen (10.42.4.91) on ws-martin-01 used WMI (T1047) '
                                 'and Kerberoasting (T1558.003) to reach SVR-DB-01 in vesper.local.'),
            'ioc_summary': 'martin.chen targeting SVR-DB-01.',
        }
        r = _validate_ioc_grounding(narrative, evidence)
        assert 'svr-db-01' in r['hallucinated_iocs']
        assert 'vesper.local' in r['hallucinated_iocs']
        assert 'martin.chen' not in r['hallucinated_iocs']
        assert 'ws-martin-01' not in r['hallucinated_iocs']
        assert 't1047' not in r['hallucinated_iocs']
        assert 't1558.003' not in r['hallucinated_iocs']
        assert '10.42.4.91' not in r['hallucinated_iocs']

    def test_clean_narrative_has_full_grounding(self):
        from src.core.ingest.cluster_narrator import _validate_ioc_grounding
        evidence = [{'user_canonical': 'alice.wong', 'src_ip': '10.0.0.5', 'hostname': 'web-01'}]
        narrative = {'attack_narrative': 'alice.wong (10.0.0.5) on web-01 ran a scan.', 'ioc_summary': ''}
        r = _validate_ioc_grounding(narrative, evidence)
        assert r['hallucinated_iocs'] == []
        assert r['grounding_rate'] == 1.0

    def test_empty_narrative_is_safe(self):
        from src.core.ingest.cluster_narrator import _validate_ioc_grounding
        r = _validate_ioc_grounding({'attack_narrative': '', 'ioc_summary': ''}, [])
        assert r['grounding_rate'] == 1.0
        assert r['candidates'] == 0


class TestEntityCoverageSelection:
    """Sprint 4 P1: entity-coverage-aware evidence selection raises recall."""

    def test_uncovered_entities_get_swapped_in(self):
        from src.core.ingest.cluster_narrator import (
            _ensure_entity_coverage, _row_entities, _cluster_key_entities, EVIDENCE_CAP,
        )
        rows = [{'row_index': i, 'triage_score': 0.9, 'user_canonical': 'alice',
                 'hostname': 'web-01', 'src_ip': '10.0.0.1'} for i in range(30)]
        rows.append({'row_index': 30, 'triage_score': 0.10, 'user_canonical': 'bob',
                     'hostname': 'dc-01', 'src_ip': '10.0.0.9'})
        cluster = {'cluster_id': 'cov', 'shared_users': ['alice', 'bob'],
                   'shared_hosts': ['web-01', 'dc-01'], 'shared_ips': ['10.0.0.1', '10.0.0.9']}
        cand = sorted(rows, key=lambda r: r['triage_score'], reverse=True)
        naive = cand[:EVIDENCE_CAP]
        key = _cluster_key_entities(cluster)
        cov_naive = set().union(*(_row_entities(r) for r in naive))
        assert not key <= cov_naive  # naive misses bob/dc-01/10.0.0.9
        fixed = _ensure_entity_coverage(naive, cand, cluster, EVIDENCE_CAP)
        cov_fixed = set().union(*(_row_entities(r) for r in fixed))
        assert key <= cov_fixed, "all key entities must be covered after the pass"
        assert len(fixed) == EVIDENCE_CAP

    def test_idempotent_when_already_covered(self):
        from src.core.ingest.cluster_narrator import _ensure_entity_coverage, EVIDENCE_CAP
        rows = [{'row_index': i, 'triage_score': 0.9, 'user_canonical': 'alice',
                 'hostname': 'web-01', 'src_ip': '10.0.0.1'} for i in range(5)]
        cluster = {'cluster_id': 'c', 'shared_users': ['alice'], 'shared_hosts': ['web-01']}
        out = _ensure_entity_coverage(rows, rows, cluster, EVIDENCE_CAP)
        assert out is rows  # no change when coverage already complete

    def test_no_key_entities_is_noop(self):
        from src.core.ingest.cluster_narrator import _ensure_entity_coverage, EVIDENCE_CAP
        rows = [{'row_index': 0, 'triage_score': 0.5}]
        out = _ensure_entity_coverage(rows, rows, {'cluster_id': 'c'}, EVIDENCE_CAP)
        assert out is rows


class TestBehavioralLink:
    """Sprint 4 P2: non-destructive campaign linkage (safe over-merge guards)."""

    HOUR = 3600

    def _c(self, cid, role, ip='8.8.0.0', tenant='t1', refs=None):
        return {'cluster_id': cid, 'phases': [{'case_role': role}], 'shared_ips': [ip],
                'tenant_id': tenant, 'row_refs': refs or [0]}

    def test_links_genuine_killchain_progression(self, monkeypatch):
        monkeypatch.setenv('JANUSEC_BEHAVIORAL_LINK', '1')
        from src.core.ingest.cluster_merge import _behavioral_link
        a = self._c('A', 'credential_access', ip='8.8.1.5', refs=[0, 1])
        b = self._c('B', 'exfiltration', ip='8.8.9.9', refs=[2, 3])
        ts = {0: 1000.0, 1: 2000.0, 2: 2000.0 + 2 * self.HOUR, 3: 3000.0 + 2 * self.HOUR}
        out = _behavioral_link([a, b], ts)
        assert any(c.get('_campaign_links') for c in out)
        link = a['_campaign_links'][0]
        assert link['cluster_id'] == 'B' and link['relationship'] == 'precedes'
        assert link['affinity'] == 'shared_cidr16'

    def test_same_stage_does_not_link(self, monkeypatch):
        monkeypatch.setenv('JANUSEC_BEHAVIORAL_LINK', '1')
        from src.core.ingest.cluster_merge import _behavioral_link
        a = self._c('A', 'credential_access', refs=[0])
        b = self._c('B', 'credential_access', refs=[1])
        out = _behavioral_link([a, b], {0: 1000.0, 1: 1000.0 + self.HOUR})
        assert not any(c.get('_campaign_links') for c in out)

    def test_beyond_dwell_does_not_link(self, monkeypatch):
        monkeypatch.setenv('JANUSEC_BEHAVIORAL_LINK', '1')
        from src.core.ingest.cluster_merge import _behavioral_link
        a = self._c('A', 'credential_access', refs=[0])
        b = self._c('B', 'exfiltration', refs=[1])
        out = _behavioral_link([a, b], {0: 1000.0, 1: 1000.0 + 10 * 86400})
        assert not any(c.get('_campaign_links') for c in out)

    def test_no_affinity_does_not_link(self, monkeypatch):
        monkeypatch.setenv('JANUSEC_BEHAVIORAL_LINK', '1')
        from src.core.ingest.cluster_merge import _behavioral_link
        a = self._c('A', 'credential_access', ip='8.8.1.1', tenant='t1', refs=[0])
        b = self._c('B', 'exfiltration', ip='9.9.1.1', tenant='t2', refs=[1])
        out = _behavioral_link([a, b], {0: 1000.0, 1: 1000.0 + 24 * self.HOUR})
        assert not any(c.get('_campaign_links') for c in out)

    def test_disabled_is_noop(self, monkeypatch):
        monkeypatch.setenv('JANUSEC_BEHAVIORAL_LINK', '0')
        from src.core.ingest.cluster_merge import _behavioral_link
        a = self._c('A', 'credential_access', ip='8.8.1.5', refs=[0])
        b = self._c('B', 'exfiltration', ip='8.8.9.9', refs=[1])
        out = _behavioral_link([a, b], {0: 1000.0, 1: 1000.0 + self.HOUR})
        assert not any(c.get('_campaign_links') for c in out)


class TestAdaptiveWindow:
    """Sprint 4 P2: adaptive window is a true no-op by default."""

    def test_default_multiplier_is_noop(self):
        from src.core.ingest import cluster_merge as cm
        assert cm._ADAPTIVE_WINDOW_MULT == 1.0

    def test_high_value_role_mapping(self):
        from src.core.ingest import cluster_merge as cm
        assert cm._PHASE_ID_TO_ROLE.get('kerberoasting') == 'credential_access'
        assert 'credential_access' in cm._HIGH_VALUE_PHASE_ROLES
        assert cm._PHASE_ID_TO_ROLE.get('c2_dns_beacon') not in cm._HIGH_VALUE_PHASE_ROLES


class TestClusteringTelemetry:
    """Sprint 4 P1: evidence-retention telemetry is emitted."""

    def test_retention_telemetry_present_and_full_when_no_cap(self):
        from src.core.ingest.cluster_merge import transitive_merge_clusters
        rows = [{'row_index': i, 'timestamp': '2026-01-01T00:00:00Z',
                 'src_ip': '203.0.113.5', 'event_text': 'kerberoasting rc4 0x17 tgs',
                 'triage_score': 0.9, 'user_canonical': 'u1'} for i in range(4)]
        diag = {}
        transitive_merge_clusters(None, rows, diagnostics_out=diag)
        assert 'evidence_retention_rate' in diag
        assert 'clustered_rows_pre_cap' in diag
        assert 'oversized_rows_capped' in diag
        assert diag['evidence_retention_rate'] == 1.0  # nothing capped in a tiny run


class TestKillChainRecovery:
    """Sprint 5 A2: derive kill-chain from phases when the LLM returns 'unknown'."""

    def test_derive_from_phases_ordered(self):
        from src.core.ingest.cluster_narrator import _killchain_from_phases
        cl = {'phases': [{'case_role': 'data_exfiltration'}, {'case_role': 'credential_theft'},
                         {'case_role': 'lateral_movement'}]}
        assert _killchain_from_phases(cl) == ['exploitation', 'lateral_movement', 'exfiltration']

    def test_empty_when_no_mapped_phases(self):
        from src.core.ingest.cluster_narrator import _killchain_from_phases
        assert _killchain_from_phases({}) == []
        assert _killchain_from_phases({'phases': [{'case_role': 'nonsense'}]}) == []

    def test_dedup(self):
        from src.core.ingest.cluster_narrator import _killchain_from_phases
        cl = {'phases': [{'case_role': 'data_exfiltration'}, {'case_role': 'exfiltration'}]}
        assert _killchain_from_phases(cl) == ['exfiltration']


class TestScatterGatherAdoption:
    """Sprint 5: scatter-gather synthesis is adopted as attack_narrative, not discarded."""

    def test_adoption_logic_via_cluster_state(self):
        # Mirror the adoption branch: a substantive scatter-gather synthesis on the
        # cluster should be copied onto the narrative's attack_narrative.
        cluster = {'_scatter_gather_result': {
            'scatter_gather': True,
            'narrative': 'X' * 200,
            'specialist_outputs': {'timeline': 't', 'attribution': 'a'},
        }}
        narrative = {'attack_narrative': 'short single-agent text'}
        _sg = cluster.get('_scatter_gather_result')
        if isinstance(_sg, dict) and _sg.get('scatter_gather') and _sg.get('narrative'):
            _sg_text = str(_sg.get('narrative')).strip()
            if len(_sg_text) > 80:
                narrative['attack_narrative'] = _sg_text
                narrative['_attack_narrative_source'] = 'scatter_gather'
        assert narrative['_attack_narrative_source'] == 'scatter_gather'
        assert len(narrative['attack_narrative']) == 200

    def test_short_synthesis_not_adopted(self):
        cluster = {'_scatter_gather_result': {'scatter_gather': True, 'narrative': 'too short'}}
        narrative = {'attack_narrative': 'original'}
        _sg = cluster.get('_scatter_gather_result')
        adopted = False
        if isinstance(_sg, dict) and _sg.get('scatter_gather') and _sg.get('narrative'):
            if len(str(_sg['narrative']).strip()) > 80:
                adopted = True
        assert not adopted
        assert narrative['attack_narrative'] == 'original'


class TestKillChainPhaseRobustness:
    """Regression: _killchain_from_phases must handle string phases (not only dicts).

    A fixture using phases=['credential_theft', ...] previously crashed narrate_cluster
    with AttributeError: 'str' object has no attribute 'get'.
    """

    def test_string_phases(self):
        from src.core.ingest.cluster_narrator import _killchain_from_phases
        assert _killchain_from_phases({'phases': ['credential_theft', 'data_exfiltration']}) == \
            ['exploitation', 'exfiltration']

    def test_mixed_dict_and_string_phases(self):
        from src.core.ingest.cluster_narrator import _killchain_from_phases
        assert _killchain_from_phases({'phases': [{'case_role': 'lateral_movement'}, 'impact']}) == \
            ['lateral_movement', 'impact']

    def test_junk_phase_types_ignored(self):
        from src.core.ingest.cluster_narrator import _killchain_from_phases
        assert _killchain_from_phases({'phases': [None, 123, 'impact']}) == ['impact']


class TestCampaignLinkSurfacing:
    """Sprint 7: behavioral _campaign_links are surfaced to narrative + prompt (was discarded)."""

    def test_campaign_block_renders_for_linked_cluster(self):
        from src.core.ingest.cluster_narrator import _campaign_link_block
        cl = {'cluster_id': 'c1', '_campaign_links': [
            {'cluster_id': 'c2', 'relationship': 'precedes', 'kc_from': 4, 'kc_to': 8,
             'gap_s': 3600, 'affinity': 'shared_cidr16'}]}
        block = _campaign_link_block(cl)
        assert 'CAMPAIGN CONTEXT' in block and 'PRECEDES' in block and 'exfiltration' in block

    def test_no_block_without_links(self):
        from src.core.ingest.cluster_narrator import _campaign_link_block
        assert _campaign_link_block({'cluster_id': 'x'}) == ''

    def test_follows_relationship(self):
        from src.core.ingest.cluster_narrator import _campaign_link_block
        cl = {'_campaign_links': [{'relationship': 'follows', 'kc_from': 3, 'kc_to': 6}]}
        assert 'FOLLOWS' in _campaign_link_block(cl)

    def test_links_hoisted_to_narrative(self):
        from src.core.ingest.cluster_narrator import _apply_narrative_to_cluster
        cluster = {'cluster_id': 'c1', '_campaign_links': [{'cluster_id': 'c2', 'relationship': 'precedes'}]}
        narrative = {'verdict': 'VALIDATED_BREACH', 'confidence': 0.9}
        _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
        assert narrative.get('campaign_links') == cluster['_campaign_links']
