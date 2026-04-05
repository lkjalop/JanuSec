from __future__ import annotations
"""Embedding Service Stub

Purpose:
 - Provide unified interface for generating embeddings for events and factor sets.
 - Falls back to deterministic hash-based vectors when ML model unavailable.
 - Prepared for pgvector integration (see docs/pgvector_integration.md).

Production Path (future):
 - Install sentence-transformers
 - Use a lightweight model (e.g., all-MiniLM-L6-v2) for <1KB text payloads.
 - Batch encode to reduce overhead.

Deterministic Fallback:
 - Hash tokens into fixed-length vector (e.g. dimension=64) for testability without external deps.
"""

from typing import List, Dict, Any
import os, hashlib, math, time
from functools import lru_cache


DEFAULT_MODEL = os.getenv("EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
FALLBACK_DIM = 64


class EmbeddingService:
    def __init__(self, model_name: str = DEFAULT_MODEL, dim: int | None = None):
        self.model_name = model_name
        self._model = None
        # Allow override of fallback dimension for latency/quality tradeoff
        self.dim = int(os.getenv('EMBED_DIM', str(dim or FALLBACK_DIM)) or FALLBACK_DIM)
        # Adaptive skip threshold (seconds of inactivity before re-embedding factors skipped)
        self.inactive_skip_seconds = float(os.getenv('EMBED_INACTIVE_SKIP_SECONDS','900') or 900)
        # Cache last factor embedding times
        self._factor_last_ts: Dict[str, float] = {}

    def _ensure_model(self) -> None:
        if self._model is not None:
            return
        # Lazy import; absence triggers fallback mode.
        try:  # pragma: no cover
            from sentence_transformers import SentenceTransformer  # type: ignore
            self._model = SentenceTransformer(self.model_name)
        except Exception:
            self._model = None

    # ---------------- Fallback Hash Vector -----------------
    def _hash_vector(self, text: str, dim: int | None = None) -> List[float]:
        dim = dim or self.dim
        if not text:
            return [0.0] * dim
        # Split by non-alnum boundaries for rough tokenization
        import re
        tokens = [t.lower() for t in re.split(r"[^A-Za-z0-9]+", text) if t]
        if not tokens:
            return [0.0] * dim
        vec = [0.0] * dim
        for t in tokens:
            h = hashlib.sha256(t.encode("utf-8")).hexdigest()
            # Use chunks of hash to distribute weight
            for i in range(0, len(h), 8):
                idx = int(h[i:i+8], 16) % dim
                vec[idx] += 1.0
        # Normalize L2
        norm = math.sqrt(sum(v*v for v in vec)) or 1.0
        return [round(v / norm, 6) for v in vec]

    @lru_cache(maxsize=2048)
    def _cached_fallback(self, text: str) -> List[float]:
        return self._hash_vector(text, self.dim)

    def embed_texts(self, items: List[str]) -> List[List[float]]:
        self._ensure_model()
        if not items:
            return []
        if self._model is None:  # fallback
            return [self._cached_fallback(t) for t in items]
        try:  # pragma: no cover
            emb = self._model.encode(items, batch_size=min(32, len(items)))
            # Convert numpy to python list, round for stability
            out: List[List[float]] = []
            for row in emb:
                out.append([round(float(x), 6) for x in list(row)])
            return out
        except Exception:
            return [self._hash_vector(t) for t in items]

    def embed_event(self, event: Dict[str, Any]) -> List[float]:
        # Concatenate salient fields
        parts: List[str] = []
        for key in ("domain","ingest_source","kill_chain_hint"):
            v = event.get(key)
            if isinstance(v, list):
                parts.extend([str(x) for x in v])
            elif v:
                parts.append(str(v))
        actor = event.get("actor") or {}
        if actor.get("principal_id"):
            parts.append(str(actor.get("principal_id")))
        api = event.get("api") or {}
        if api.get("path"):
            parts.append(str(api.get("path")))
        if api.get("method"):
            parts.append(str(api.get("method")))
        cloud = event.get("cloud") or {}
        if cloud.get("resource_id"):
            parts.append(str(cloud.get("resource_id")))
        email = event.get("email") or {}
        if email.get("subject"):
            parts.append(str(email.get("subject")))
        # Add factors to enrich semantic space
        for f in event.get("factors", []) or []:
            parts.append(str(f))
        text = " ".join(parts)
        return self.embed_texts([text])[0] if text else [0.0] * FALLBACK_DIM

    def embed_factors(self, factors: List[str]) -> List[float]:
        if not factors:
            return [0.0] * self.dim
        now = time.time()
        actives = []
        for f in factors:
            last = self._factor_last_ts.get(f, 0)
            if (now - last) < self.inactive_skip_seconds:
                actives.append(f)
            else:
                # Mark for fresh embedding
                self._factor_last_ts[f] = now
                actives.append(f)
        joined = " ".join(sorted(set(actives)))
        return self.embed_texts([joined])[0]


_GLOBAL_EMBED: EmbeddingService | None = None


def get_embedding_service() -> EmbeddingService:
    global _GLOBAL_EMBED
    if _GLOBAL_EMBED is None:
        _GLOBAL_EMBED = EmbeddingService()
    return _GLOBAL_EMBED


__all__ = [
    "EmbeddingService",
    "get_embedding_service"
]