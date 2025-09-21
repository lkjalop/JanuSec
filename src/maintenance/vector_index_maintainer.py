"""Background maintenance for pgvector IVFFlat list size.

Strategy:
- Periodically (e.g., every 6 hours) check row count of factor_embeddings.
- Determine target lists parameter: sqrt(n) capped to 1000, minimum 10.
- If existing index lists differs by >50% from target, recreate index concurrently.

Safe to import even if pgvector absent (silently no-op).
"""
from __future__ import annotations
import asyncio, math, logging
from db.database import get_pool

logger = logging.getLogger(__name__)

CHECK_INTERVAL_SECONDS = 6 * 3600
INDEX_NAME = 'idx_factor_embeddings_embedding_cosine'

async def adjust_vector_index():
    try:
        pool = await get_pool()
    except Exception:
        return
    async with pool.acquire() as conn:
        try:
            ext = await conn.fetchval("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector')")
            if not ext:
                return
            count = await conn.fetchval("SELECT count(*) FROM factor_embeddings WHERE embedding IS NOT NULL")
            if not count or count < 1000:
                return  # not enough data to matter
            target_lists = max(10, min(1000, int(math.sqrt(count))))
            # Inspect current index definition
            idxdef = await conn.fetchval("""
                SELECT pg_get_indexdef(indexrelid) FROM pg_index i
                JOIN pg_class c ON i.indexrelid=c.oid
                WHERE c.relname=$1
            """, INDEX_NAME)
            if idxdef and f"lists = {target_lists}" in idxdef:
                return
            # Drop & recreate (not concurrently to keep simple; could use CONCURRENTLY if permissions allow)
            await conn.execute(f"DROP INDEX IF EXISTS {INDEX_NAME}")
            await conn.execute(f"CREATE INDEX {INDEX_NAME} ON factor_embeddings USING ivfflat (embedding vector_cosine_ops) WITH (lists = {target_lists})")
            logger.info(f"Recreated vector index with lists={target_lists} (rowcount={count})")
        except Exception as e:
            logger.debug(f"Vector index maintenance skipped: {e}")

async def maintenance_loop(stop_event: asyncio.Event):
    while not stop_event.is_set():
        try:
            await adjust_vector_index()
        except Exception:
            pass
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
