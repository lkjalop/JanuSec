from src.core.evidence_contract.retrieval_adapters import TemporalRAGDenseEvidenceAdapter


def test_dense_adapter_only_returns_eligible_case_ids(monkeypatch):
    class Engine:
        def index_rows(self, *args, **kwargs):
            return len(args[0])

        def query(self, *args, **kwargs):
            return [{"evidence_id": "ev-good"}, {"evidence_id": "ev-other"}]

    monkeypatch.setattr("src.ai.temporal_rag.get_engine", lambda: Engine())
    adapter = TemporalRAGDenseEvidenceAdapter(tenant_id="t1", assessment_id="a1")
    assert adapter("credential theft", [{"evidence_id": "ev-good"}], 20) == ["ev-good"]
