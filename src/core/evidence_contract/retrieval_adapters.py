"""Adapters that keep dense and prior-case retrieval contextual, not evidentiary."""

from __future__ import annotations

from typing import Any

from .records import canonical_hash


_DENSE_INDEXED_SCOPES: dict[str, str] = {}


class TemporalRAGDenseEvidenceAdapter:
    """Promote only records already present in the eligible case corpus.

    TemporalRAG uses configured embeddings and falls back to BM25 when the
    embedding provider is unhealthy. The Evidence Pack compiler re-checks each
    returned ID against tenant, case, bitemporal, and partition eligibility.
    """

    def __init__(self, *, tenant_id: str, assessment_id: str, case_id: str | None = None) -> None:
        self.tenant_id = tenant_id
        self.assessment_id = assessment_id
        self.case_id = case_id or assessment_id

    def __call__(self, query: str, eligible: list[dict[str, Any]], limit: int) -> list[str]:
        if not query.strip():
            return []
        from src.ai.temporal_rag import get_engine
        from src.core.workload_budgets import embedding_slot

        def join_key(row: dict[str, Any]) -> tuple[str, ...]:
            groups = (
                ("occurred_at", "event_time", "timestamp", "ts", "eventTime"),
                ("actor_id", "principal_id", "user_canonical", "user", "username"),
                ("action_name", "eventName", "operationName", "operation", "action"),
                ("process_id", "pid", "ProcessId"),
                ("resource_id", "target_resource", "object_key", "path"),
                ("src_ip", "source_ip", "sourceIPAddress"),
                ("dst_ip", "destination_ip", "DestinationIp"),
                ("sha256", "file_hash", "hash"),
            )
            values = []
            for group_index, names in enumerate(groups):
                value = next((row.get(name) for name in names if row.get(name) not in (None, "")), None)
                if value is not None:
                    values.append(f"{group_index}:{str(value).strip().lower()}")
            return tuple(values)

        eligible_ids = {str(row.get("evidence_id") or row.get("record_id") or row.get("id") or "") for row in eligible}
        by_key: dict[tuple[str, ...], list[str]] = {}
        for row in eligible:
            key = join_key(row)
            rid = str(row.get("evidence_id") or row.get("record_id") or row.get("id") or "")
            if rid and len(key) >= 2:
                by_key.setdefault(key, []).append(rid)
        with embedding_slot():
            engine = get_engine()
            dense_scope = f"{self.assessment_id}:{self.case_id}"
            scope_key = f"{self.tenant_id}:{dense_scope}"
            corpus_hash = canonical_hash(sorted(value for value in eligible_ids if value))
            if _DENSE_INDEXED_SCOPES.get(scope_key) != corpus_hash:
                # Index only the already eligible case corpus. This is bounded by
                # the Evidence Pack partition, not the assessment-wide event lake.
                engine.index_rows(eligible, tenant=self.tenant_id, assessment_id=dense_scope)
                _DENSE_INDEXED_SCOPES[scope_key] = corpus_hash
            rows = engine.query(
                query, tenant=self.tenant_id, assessment_id=dense_scope,
                top_k=max(1, min(limit, 200)), mode="historical", recency_weight=0.0,
            )
        output: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            rid = str(row.get("evidence_id") or row.get("record_id") or row.get("id") or "")
            if not rid and row.get("row_index") is not None:
                try:
                    from .projection_builder import evidence_id_for_row
                    from .semantic_adapters import normalize_semantics
                    rid = evidence_id_for_row(self.assessment_id, int(row["row_index"]), normalize_semantics(dict(row)))
                except (TypeError, ValueError):
                    rid = ""
            if not rid or rid not in eligible_ids:
                # TemporalRAG may contain the pre-normalized row. Promote only
                # an unambiguous strong multi-field join back into the eligible
                # corpus; never resolve on IP, username, hostname, or PID alone.
                matches = by_key.get(join_key(row), [])
                rid = matches[0] if len(matches) == 1 else ""
            if rid and rid in eligible_ids:
                output.append(rid)
        return output


class TemporalRAGContextAdapter:
    def __init__(self, *, scope: str) -> None:
        if scope not in {"case", "tenant_history"}:
            raise ValueError("invalid_temporal_rag_scope")
        self.scope = scope

    def __call__(self, query: str, tenant_id: str, case_id: str, limit: int) -> list[dict[str, Any]]:
        from src.ai.temporal_rag import get_engine

        engine = get_engine()
        rows = engine.query(
            query,
            tenant=tenant_id,
            assessment_id=case_id if self.scope == "case" else None,
            top_k=max(1, min(limit, 50)),
            mode="historical",
        )
        output = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if self.scope == "tenant_history" and str(row.get("assessment_id") or row.get("case_id") or "") == case_id:
                continue
            output.append({
                "retrieval_provider": "temporal_rag",
                "retrieval_scope": self.scope,
                "source_case_id": row.get("assessment_id") or row.get("case_id"),
                "document": row,
            })
        return output


__all__ = ["TemporalRAGContextAdapter", "TemporalRAGDenseEvidenceAdapter"]
