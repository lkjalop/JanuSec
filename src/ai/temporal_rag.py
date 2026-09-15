"""temporal_rag.py — Time-windowed evidence retrieval for JanuSec pipeline.

TemporalRAG indexes evidence rows as they arrive (from manual upload OR live
connectors), then retrieves the most relevant prior events before LLM
summarisation, giving each persona report genuine historical context.

Architecture
------------
  TemporalCorpus     — per-tenant ring-buffer of (embedding, row, timestamp)
  TemporalRAGEngine  — singleton, manages corpora, drives embed + query + fallback
  get_engine()       — module-level accessor (lazy-init, safe to import)

Embedding modes (selected via TEMPORAL_RAG_EMBED env var):
  "ollama"    — Ollama /api/embeddings  (uses OllamaClient from oss_models.py)
  "off"       — BM25-style keyword fallback (zero extra deps, air-gap safe)

The fallback is always engaged automatically when Ollama is unreachable.
"""
from __future__ import annotations

import collections
import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_EMBED_MODE: str = os.getenv("TEMPORAL_RAG_EMBED", "ollama").lower()
_EMBED_MODEL: str = os.getenv("TEMPORAL_RAG_MODEL", "nomic-embed-text")
_OLLAMA_HOST: str = (
    os.getenv("TEMPORAL_RAG_OLLAMA_HOST")
    or os.getenv("OLLAMA_HOST")
    or os.getenv("OLLAMA_URL")
    or "http://localhost:11434"
)
_CORPUS_MAX_ROWS: int = int(os.getenv("TEMPORAL_RAG_CORPUS_SIZE", "2000"))
_WINDOW_SECONDS: int = int(os.getenv("TEMPORAL_RAG_WINDOW_SECONDS", "7200"))  # 2h default
_DEFAULT_TOP_K: int = int(os.getenv("TEMPORAL_RAG_TOP_K", "5"))
_RECENCY_WEIGHT: float = float(os.getenv("TEMPORAL_RAG_RECENCY_WEIGHT", "0.3"))
_INDEX_PATH = Path(os.getenv("TEMPORAL_RAG_INDEX_PATH", "data/temporal_rag/vector_index.sqlite3"))
_BATCH_SIZE = max(1, int(os.getenv("TEMPORAL_RAG_EMBED_BATCH_SIZE", "64")))


class _PersistentVectorIndex:
    """Derived, rebuildable cache; evidentiary truth remains in the ledger."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS embedding_cache (
                  model TEXT NOT NULL, text_hash TEXT NOT NULL, vector_json TEXT NOT NULL,
                  created_at REAL NOT NULL, PRIMARY KEY(model, text_hash)
                );
                CREATE TABLE IF NOT EXISTS corpus_entries (
                  scope TEXT NOT NULL, record_id TEXT NOT NULL, text_hash TEXT NOT NULL,
                  text_value TEXT NOT NULL, row_json TEXT NOT NULL, event_ts REAL NOT NULL,
                  model TEXT NOT NULL, PRIMARY KEY(scope, record_id)
                );
                CREATE INDEX IF NOT EXISTS ix_corpus_entries_scope_ts ON corpus_entries(scope, event_ts DESC);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def embedding(self, model: str, text_hash: str) -> list[float] | None:
        with self._lock, self._connect() as db:
            row = db.execute(
                "SELECT vector_json FROM embedding_cache WHERE model=? AND text_hash=?", (model, text_hash),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put_embedding(self, model: str, text_hash: str, vector: list[float]) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO embedding_cache(model,text_hash,vector_json,created_at) VALUES(?,?,?,?)",
                (model, text_hash, json.dumps(vector, separators=(",", ":")), time.time()),
            )

    def put_entry(self, scope: str, record_id: str, text_hash: str, text: str, row: dict,
                  event_ts: float, model: str) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT INTO corpus_entries(scope,record_id,text_hash,text_value,row_json,event_ts,model)
                   VALUES(?,?,?,?,?,?,?) ON CONFLICT(scope,record_id) DO UPDATE SET
                   text_hash=excluded.text_hash,text_value=excluded.text_value,row_json=excluded.row_json,
                   event_ts=excluded.event_ts,model=excluded.model""",
                (scope, record_id, text_hash, text, json.dumps(row, default=str, separators=(",", ":")), event_ts, model),
            )

    def load(self, scope: str, limit: int) -> list[tuple[str, dict, float, list[float] | None]]:
        with self._lock, self._connect() as db:
            rows = db.execute(
                """SELECT c.text_value,c.row_json,c.event_ts,e.vector_json
                   FROM corpus_entries c LEFT JOIN embedding_cache e
                   ON e.model=c.model AND e.text_hash=c.text_hash
                   WHERE c.scope=? ORDER BY c.event_ts DESC LIMIT ?""", (scope, limit),
            ).fetchall()
        return [(text, json.loads(row), float(ts), json.loads(vector) if vector else None) for text, row, ts, vector in reversed(rows)]


# ---------------------------------------------------------------------------
# Corpus entry
# ---------------------------------------------------------------------------
class _Entry:
    __slots__ = ("embedding", "row", "ts", "text", "tokens")

    def __init__(self, text: str, row: dict, ts: float, embedding: list[float] | None):
        self.text = text
        self.row = row
        self.ts = ts
        self.embedding = embedding
        self.tokens: list[str] | None = None  # cached lazily on first BM25 query


# ---------------------------------------------------------------------------
# Per-tenant corpus (ring buffer)
# ---------------------------------------------------------------------------
class TemporalCorpus:
    def __init__(self, max_size: int = _CORPUS_MAX_ROWS):
        self._max = max_size
        self._entries: collections.deque[_Entry] = collections.deque(maxlen=max_size)

    def add(self, entry: _Entry) -> None:
        self._entries.append(entry)

    def __len__(self) -> int:
        return len(self._entries)

    def entries_in_window(self, window_seconds: int, now: float | None = None) -> list[_Entry]:
        now = now or time.time()
        cutoff = now - window_seconds
        return [e for e in self._entries if e.ts >= cutoff]

    def all_entries(self) -> list[_Entry]:
        return list(self._entries)


# ---------------------------------------------------------------------------
# Embedding helpers
# ---------------------------------------------------------------------------
def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


_ROW_TEXT_FIELDS = (
    "entity", "description", "event_type", "action", "user",
    "ip", "domain", "process", "file_hash", "severity",
    "factors", "threat_name", "source", "domain_name",
    "mitre_technique", "factor_tags", "kill_chain_phase",
)


def _row_to_text(row: dict) -> str:
    """Convert an evidence row to a short text blob suitable for embedding."""
    parts = []
    for field in _ROW_TEXT_FIELDS:
        val = row.get(field)
        if val is None:
            continue
        if isinstance(val, list):
            parts.append(" ".join(str(v) for v in val))
        else:
            parts.append(str(val))
    return " ".join(parts)[:512]


# ---------------------------------------------------------------------------
# Deterministic BM25-style fallback (no deps)
# ---------------------------------------------------------------------------
_STOP_WORDS = frozenset(
    "a an the and or is in of to for with by at be as on this that from are was were"
    .split()
)

def _tokenize(text: str) -> list[str]:
    return [t for t in re.sub(r"[^a-z0-9]", " ", text.lower()).split() if t not in _STOP_WORDS]


def _bm25_score(query_tokens: list[str], entry_tokens: list[str]) -> float:
    """Simplified BM25 relevance score."""
    k1, b, avg_dl = 1.5, 0.75, 20.0
    dl = len(entry_tokens)
    tf_map: dict[str, int] = {}
    for t in entry_tokens:
        tf_map[t] = tf_map.get(t, 0) + 1
    score = 0.0
    for qt in query_tokens:
        tf = tf_map.get(qt, 0)
        norm_tf = (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * dl / avg_dl))
        score += norm_tf  # IDF simplified to 1.0 per term (small corpus)
    return score


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------
class TemporalRAGEngine:
    """Manages per-tenant corpora and drives embed + retrieval."""

    def __init__(self) -> None:
        self._corpora: dict[str, TemporalCorpus] = {}
        self._ollama_ok: bool | None = None   # None = untested
        self._ollama_client: Any = None
        self._hydrated_scopes: set[str] = set()
        self._persistent = _PersistentVectorIndex(_INDEX_PATH)

    # -- Corpus access -------------------------------------------------------
    def corpus(self, tenant: str = "default", assessment_id: str | None = None) -> TemporalCorpus:
        key = f"{tenant}:{assessment_id}" if assessment_id else tenant
        if key not in self._corpora:
            self._corpora[key] = TemporalCorpus()
        if key not in self._hydrated_scopes:
            for text, row, event_ts, embedding in self._persistent.load(key, _CORPUS_MAX_ROWS):
                self._corpora[key].add(_Entry(text=text, row=row, ts=event_ts, embedding=embedding))
            self._hydrated_scopes.add(key)
        return self._corpora[key]

    # -- Ollama probe --------------------------------------------------------
    def _get_ollama_client(self) -> Any | None:
        if _EMBED_MODE == "off":
            return None
        if self._ollama_client is not None:
            return self._ollama_client
        try:
            import pathlib
            from src.ai.oss_models import _OllamaClient  # type: ignore
            client = _OllamaClient(
                host=_OLLAMA_HOST,
                root=pathlib.Path(os.getenv("OLLAMA_ROOT", "D:/Ollama")),
            )
            self._ollama_client = client
            return client
        except Exception:
            return None

    def _embed(self, text: str) -> list[float] | None:
        """Return embedding or None (triggers BM25 fallback)."""
        if _EMBED_MODE == "off":
            return None
        text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        cached = self._persistent.embedding(_EMBED_MODEL, text_hash)
        if cached is not None:
            return cached
        client = self._get_ollama_client()
        if client is None:
            return None
        # Periodic retry: re-attempt after 60s of degraded BM25 mode
        if self._ollama_ok is False:
            now = time.time()
            if now - getattr(self, '_ollama_fail_ts', 0) < 60:
                return None
            self._ollama_fail_ts = now
        try:
            vec = client.embed(_EMBED_MODEL, text)
            if self._ollama_ok is False:
                logger.info("TemporalRAG: Ollama recovered — embedding mode restored")
            self._ollama_ok = True
            if vec:
                self._persistent.put_embedding(_EMBED_MODEL, text_hash, vec)
            return vec
        except Exception as exc:
            if self._ollama_ok is not False:
                logger.warning("TemporalRAG: Ollama embed failed (%s) — degrading to BM25 fallback", exc)
            self._ollama_ok = False
            self._ollama_fail_ts = time.time()
            return None

    # -- Index ---------------------------------------------------------------
    def index_rows(
        self,
        rows: list[dict],
        tenant: str = "default",
        ts_override: float | None = None,
        assessment_id: str | None = None,
    ) -> int:
        """Embed and store evidence rows in the tenant corpus. Returns indexed count."""
        corp = self.corpus(tenant, assessment_id)
        indexed = 0
        now = ts_override or time.time()
        prepared: list[tuple[dict, float, str, str, str]] = []
        scope = f"{tenant}:{assessment_id}" if assessment_id else tenant
        for position, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            # Extract timestamp from row if present
            row_ts = _extract_ts(row) or now
            text = _row_to_text(row)
            if not text.strip():
                continue
            text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
            record_id = str(row.get("evidence_id") or row.get("record_id") or row.get("id") or f"row-{position}-{text_hash}")
            prepared.append((row, row_ts, text, text_hash, record_id))
        embeddings: dict[str, list[float] | None] = {}
        missing: list[tuple[str, str]] = []
        missing_hashes: set[str] = set()
        for _, _, text, text_hash, _ in prepared:
            cached = self._persistent.embedding(_EMBED_MODEL, text_hash)
            if cached is not None:
                embeddings[text_hash] = cached
            elif text_hash not in missing_hashes:
                missing.append((text_hash, text))
                missing_hashes.add(text_hash)
        client = self._get_ollama_client()
        if client is not None and _EMBED_MODE != "off":
            for start in range(0, len(missing), _BATCH_SIZE):
                batch = missing[start:start + _BATCH_SIZE]
                try:
                    vectors = client.embed_many(_EMBED_MODEL, [item[1] for item in batch])
                    self._ollama_ok = True
                except Exception as exc:
                    logger.warning("TemporalRAG batch embed failed (%s); retaining BM25 fallback", exc)
                    vectors = [None] * len(batch)
                    self._ollama_ok = False
                    self._ollama_fail_ts = time.time()
                for (text_hash, _), vector in zip(batch, vectors):
                    embeddings[text_hash] = vector
                    if vector:
                        self._persistent.put_embedding(_EMBED_MODEL, text_hash, vector)
        for row, row_ts, text, text_hash, record_id in prepared:
            embedding = embeddings.get(text_hash)
            corp.add(_Entry(text=text, row=row, ts=row_ts, embedding=embedding))
            self._persistent.put_entry(scope, record_id, text_hash, text, row, row_ts, _EMBED_MODEL)
            indexed += 1
        return indexed

    # -- Query ---------------------------------------------------------------
    def query(
        self,
        query_text: str,
        tenant: str = "default",
        top_k: int = _DEFAULT_TOP_K,
        window_seconds: int = _WINDOW_SECONDS,
        recency_weight: float = _RECENCY_WEIGHT,
        assessment_id: str | None = None,
        mode: str = "live",
    ) -> list[dict]:
        """Return top_k most relevant evidence rows from the tenant corpus.

        Scoring = (1 - recency_weight) * semantic_score + recency_weight * recency_score
        Falls back to BM25 when embeddings are unavailable.
        mode='live' applies the time window; mode='historical' uses all entries.
        """
        corp = self.corpus(tenant, assessment_id)
        if mode == "historical":
            candidates = corp.all_entries()
        else:
            candidates = corp.entries_in_window(window_seconds) or corp.all_entries()
        if not candidates:
            return []

        now = time.time()
        oldest_ts = min(e.ts for e in candidates)
        ts_range = max(now - oldest_ts, 1.0)

        query_embedding = self._embed(query_text) if query_text else None
        query_tokens = _tokenize(query_text) if query_text else []
        use_embed = query_embedding is not None and len(query_embedding) > 0

        scored: list[tuple[float, dict]] = []
        for entry in candidates:
            if use_embed and entry.embedding:
                sem = _cosine_similarity(query_embedding, entry.embedding)
            elif query_tokens:
                if entry.tokens is None:
                    entry.tokens = _tokenize(entry.text)
                raw_bm25 = _bm25_score(query_tokens, entry.tokens)
                sem = min(1.0, raw_bm25 / 10.0)  # normalise to ~[0,1]
            else:
                sem = 0.5
            recency = (entry.ts - oldest_ts) / ts_range  # 0=oldest, 1=newest
            score = (1.0 - recency_weight) * sem + recency_weight * recency
            scored.append((score, entry.row))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [row for _, row in scored[:top_k]]

    # -- Context block for persona reports ------------------------------------
    def build_context_block(
        self,
        query_text: str,
        tenant: str = "default",
        top_k: int = _DEFAULT_TOP_K,
        window_seconds: int = _WINDOW_SECONDS,
        assessment_id: str | None = None,
        mode: str = "live",
    ) -> dict:
        """Return a structured context block ready for LLM prompt injection."""
        neighbours = self.query(
            query_text, tenant=tenant, top_k=top_k,
            window_seconds=window_seconds, assessment_id=assessment_id, mode=mode,
        )
        if not neighbours:
            return {
                "rag_available": False,
                "neighbour_count": 0,
                "window_seconds": window_seconds,
                "neighbours": [],
                "summary_hint": "",
            }
        # Aggregate severity counts
        sev_counts: dict[str, int] = {}
        for r in neighbours:
            s = str(r.get("severity") or "unknown").lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        sev_parts = [f"{v} {k}" for k, v in sorted(sev_counts.items())]
        window_h = window_seconds // 3600
        summary_hint = (
            f"{len(neighbours)} similar event(s) in the prior {window_h}h window "
            f"({', '.join(sev_parts) if sev_parts else 'mixed severity'}). "
            "See neighbours for corroborating evidence."
        )
        snippets = []
        for r in neighbours:
            snippets.append({
                "entity": r.get("entity") or r.get("user") or r.get("ip"),
                "severity": r.get("severity"),
                "description": (r.get("description") or r.get("event_type") or "")[:120],
                "ts": r.get("ts") or r.get("timestamp"),
                "source": r.get("source"),
            })
        return {
            "rag_available": True,
            "neighbour_count": len(neighbours),
            "window_seconds": window_seconds,
            "neighbours": snippets,
            "summary_hint": summary_hint,
        }

    def stats(self) -> dict:
        """Return lightweight corpus stats for runtime health endpoints."""
        now = time.time()
        tenants: dict[str, dict[str, Any]] = {}
        total_entries = 0
        total_window_entries = 0
        for tenant, corpus in self._corpora.items():
            entries = corpus.all_entries()
            window_entries = corpus.entries_in_window(_WINDOW_SECONDS, now=now)
            total_entries += len(entries)
            total_window_entries += len(window_entries)
            tenants[tenant] = {
                "entries": len(entries),
                "window_entries": len(window_entries),
                "oldest_ts": min((e.ts for e in entries), default=None),
                "newest_ts": max((e.ts for e in entries), default=None),
            }
        return {
            "available": True,
            "tenant_count": len(self._corpora),
            "entities": total_entries,
            "indexed_rows": total_entries,
            "window_entries": total_window_entries,
            "embedding_mode": _EMBED_MODE,
            "embedding_model": _EMBED_MODEL if _EMBED_MODE != "off" else None,
            "ollama_ok": self._ollama_ok,
            "corpus_max_rows": _CORPUS_MAX_ROWS,
            "window_seconds": _WINDOW_SECONDS,
            "tenants": tenants,
        }


# ---------------------------------------------------------------------------
# Timestamp extractor
# ---------------------------------------------------------------------------
_TS_FIELDS = (
    "ts", "timestamp", "eventTime", "time", "createdDateTime",
    "activityDateTime", "TimeGenerated", "start", "date", "datetime",
    "@timestamp", "event_time", "UpdatedDateTime",
)


def _extract_ts(row: dict) -> float | None:
    for field in _TS_FIELDS:
        val = row.get(field) or (row.get("raw") or {}).get(field)
        if not val:
            continue
        if isinstance(val, (int, float)):
            # Epoch seconds vs milliseconds heuristic
            return float(val) if val < 1e12 else float(val) / 1000.0
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_ENGINE: TemporalRAGEngine | None = None


def get_engine() -> TemporalRAGEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = TemporalRAGEngine()
    return _ENGINE


__all__ = ["TemporalRAGEngine", "TemporalCorpus", "get_engine"]
