"""Repository for factor embeddings (semantic search)

Supports optional pgvector acceleration. If pgvector extension & vector column are
available, similarity queries are delegated to Postgres using cosine distance.
Otherwise falls back to loading a sample into memory and computing cosine in Python.
"""
from __future__ import annotations
import json
from typing import List, Dict, Any, Optional, Tuple
from db.database import execute, fetch, with_retry

INSERT = """
INSERT INTO factor_embeddings (event_id, factor, embedding, embedding_json)
VALUES ($1,$2,$3,$4::jsonb)
"""

INSERT_FALLBACK = """
INSERT INTO factor_embeddings (event_id, factor, embedding_json)
VALUES ($1,$2,$3::jsonb)
"""

SELECT_SAMPLE = """
SELECT event_id, factor, embedding_json
FROM factor_embeddings
LIMIT $1
"""

VECTOR_SIMILAR = """
SELECT event_id, factor, 1 - (embedding <=> $1::vector) AS similarity
FROM factor_embeddings
WHERE embedding IS NOT NULL
ORDER BY embedding <=> $1::vector
LIMIT $2
"""

async def _pgvector_available() -> bool:
    """Best-effort detection of pgvector usability by querying pg_extension & column presence."""
    try:
        from db.database import get_pool
        pool = await get_pool()
        async with pool.acquire() as conn:
            ext = await conn.fetchval("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector')")
            if not ext:
                return False
            col = await conn.fetchval("""
                SELECT 1 FROM information_schema.columns
                WHERE table_name='factor_embeddings' AND column_name='embedding'
            """)
            return bool(col)
    except Exception:
        return False

async def insert_embedding(event_id: str, factor: str, embedding: List[float]):
    """Insert embedding (vector + json fallback). If pgvector not available, only JSON stored."""
    async def _do():
        if await _pgvector_available():
            vec = embedding[:384]
            # Postgres vector expects array cast; asyncpg maps Python list -> array
            return await execute(INSERT, event_id, factor, vec, json.dumps(vec))
        else:
            return await execute(INSERT_FALLBACK, event_id, factor, json.dumps(embedding[:384]))
    return await with_retry(_do)

async def load_sample(limit: int = 2000):
    rows = await fetch(SELECT_SAMPLE, limit)
    return [dict(r) for r in rows]

def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b:
        return 0.0
    n = min(len(a), len(b))
    num = sum(a[i]*b[i] for i in range(n))
    da = sum(a[i]*a[i] for i in range(n)) ** 0.5
    db = sum(b[i]*b[i] for i in range(n)) ** 0.5
    if da == 0 or db == 0:
        return 0.0
    return num/(da*db)

async def similarity_search(query_embedding: List[float], limit: int = 10) -> List[Dict[str, Any]]:
    """Return similarity results using pgvector if present, else fallback in Python."""
    if await _pgvector_available():
        try:
            from db.database import get_pool
            pool = await get_pool()
            async with pool.acquire() as conn:
                rows = await conn.fetch(VECTOR_SIMILAR, query_embedding[:384], limit)
                return [dict(r) for r in rows]
        except Exception:
            pass  # fallback below
    # Fallback path
    sample = await load_sample(limit=2000)
    scored: List[Tuple[float, Dict[str, Any]]] = []
    for r in sample:
        emb = r.get('embedding_json')
        if isinstance(emb, list):
            s = _cosine(query_embedding, emb)
            scored.append((s, r))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [ {**r, 'similarity': s} for s, r in scored[:limit] ]

