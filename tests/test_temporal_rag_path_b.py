"""Phase 3.15 — TemporalRAG wired into Path B (cluster_narrator).

Path B (the headline narrator) previously had zero RAG. It now retrieves
cross-assessment corroboration from the tenant-history corpus as CONTEXT ONLY
(the allow-list + scrub keep named entities grounded in the current cluster).
"""
import pytest

from src.ai.temporal_rag import get_engine
from src.core.ingest.cluster_narrator import _temporal_rag_block

pytestmark = pytest.mark.acceptance


def test_rag_block_empty_when_corpus_empty():
    # Unknown tenant -> nothing indexed -> safe no-op (no block).
    assert _temporal_rag_block({"shared_users": ["nobody"]}, "tenant-with-no-history") == ""


def test_rag_block_retrieves_and_is_context_only():
    eng = get_engine()
    eng.index_rows(
        [
            {"user": "martin.chen", "severity": "high", "event_type": "kerberoasting",
             "description": "TGS RC4 request", "timestamp": 1000},
            {"user": "martin.chen", "severity": "critical", "event_type": "wmi_exec",
             "description": "remote exec", "timestamp": 1100},
        ],
        tenant="acme-rag-test",
        assessment_id=None,
    )
    block = _temporal_rag_block({"shared_users": ["martin.chen"], "mitre_techniques": ["T1558.003"]}, "acme-rag-test")
    assert block, "expected a RAG block once the tenant corpus is populated"
    # Must be framed as context-only so it can't smuggle in citeable/nameable entities.
    assert "CONTEXT ONLY" in block
    assert "do NOT cite" in block or "Do NOT" in block


def test_rag_respects_disable_flag(monkeypatch):
    monkeypatch.setenv("JANUSEC_TEMPORAL_RAG_NARRATE", "0")
    get_engine().index_rows(
        [{"user": "x", "description": "y", "severity": "low", "timestamp": 1}],
        tenant="acme-rag-off", assessment_id=None,
    )
    assert _temporal_rag_block({"shared_users": ["x"]}, "acme-rag-off") == ""
