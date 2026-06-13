"""Scatter-gather narration: production-grade integration tests.

Scatter-gather runs 4 lens-agents (timeline/attribution/impact/compliance) over the
SAME evidence then synthesizes — a narration-DEPTH tool for top clusters, not an
evidence/clustering one. It was silently dead for the feature's lifetime (3 bugs:
wrong InvestigationContext kwargs, a stub missing compliance_controls, output discarded).
These tests lock in the now-robust integration so it can't silently regress.

CI-safe: uses the deterministic LLM client (no Ollama needed).
"""
from __future__ import annotations

import asyncio
import os

os.environ.setdefault("PLATFORM_LITE_INIT", "1")
os.environ.setdefault("TEST_HELPERS_ENABLED", "1")  # force LocalDeterministicClient


class TestBuildVerifiedFindings:
    def test_builds_canonical_dataclasses(self):
        from src.core.ingest.cluster_narrator import _build_verified_findings
        from src.agents.types import VerifiedFinding, RawFinding
        rows = [
            {"event_text": "kerberoasting RC4 TGS", "triage_score": 0.9,
             "mitre_techniques": ["T1558.003"], "source_type": "iam"},
            {"event_name": "rclone exfil", "triage_score": 0.8, "source_type": "endpoint"},
        ]
        vfs = _build_verified_findings(rows)
        assert len(vfs) == 2
        assert all(isinstance(v, VerifiedFinding) for v in vfs)
        assert all(isinstance(v.raw, RawFinding) for v in vfs)
        # the exact attributes the narrator accesses must be present
        assert vfs[0].confidence == 0.9
        assert vfs[0].dread_score == 5.0
        assert vfs[0].compliance_controls == []
        assert "kerberoasting" in vfs[0].raw.summary
        assert vfs[0].raw.mitre_techniques == ["T1558.003"]

    def test_skips_non_dict_rows(self):
        from src.core.ingest.cluster_narrator import _build_verified_findings
        assert _build_verified_findings([None, "x", {"event_text": "ok", "triage_score": 0.5}])  # no crash
        assert len(_build_verified_findings([None, 1])) == 0


class TestScatterGatherRuns:
    def test_scatter_gather_completes_without_error(self):
        """The 4 lens-agents + synthesis must run end-to-end and return a result dict
        (the integration that was broken by 3 bugs). Deterministic client → no Ollama."""
        from src.agents.narrator import narrate_scatter_gather, InvestigationContext
        from src.core.ingest.cluster_narrator import _build_verified_findings

        ctx = InvestigationContext(assessment_id="t", tenant_id="t",
                                   initial_hypothesis="cluster c1")
        verified = _build_verified_findings([
            {"event_text": "martin.chen WMI lateral T1047", "triage_score": 0.9,
             "mitre_techniques": ["T1047"], "source_type": "endpoint"},
            {"event_text": "kerberoasting RC4", "triage_score": 0.85,
             "mitre_techniques": ["T1558.003"], "source_type": "iam"},
        ])
        result = asyncio.run(narrate_scatter_gather(ctx, verified))
        assert isinstance(result, dict)
        # specialist_outputs present whether or not synthesis was substantive
        assert "specialist_outputs" in result
        assert set(result["specialist_outputs"].keys()) == {
            "timeline", "attribution", "impact", "compliance"}
