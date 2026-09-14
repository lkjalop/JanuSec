def test_vector_index_survives_engine_restart(tmp_path, monkeypatch):
    import src.ai.temporal_rag as temporal_rag

    monkeypatch.setattr(temporal_rag, "_INDEX_PATH", tmp_path / "vectors.sqlite3")
    monkeypatch.setattr(temporal_rag, "_EMBED_MODE", "off")
    first = temporal_rag.TemporalRAGEngine()
    first.index_rows(
        [{"evidence_id": "ev-1", "event_type": "cloud_object_collection", "user": "alice"}],
        tenant="tenant-a", assessment_id="case-a", ts_override=100.0,
    )
    restarted = temporal_rag.TemporalRAGEngine()
    rows = restarted.query(
        "cloud object collection", tenant="tenant-a", assessment_id="case-a",
        mode="historical", recency_weight=0.0,
    )
    assert rows and rows[0]["evidence_id"] == "ev-1"
