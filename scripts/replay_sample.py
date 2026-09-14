"""Replay sampling script: reprocess a random sample of historical decisions to measure verdict deltas.

Usage (example):
  python scripts/replay_sample.py --limit 100 --since '7 days'

Outputs JSON lines with fields:
  event_id, original_verdict, new_verdict, original_confidence, new_confidence, confidence_delta

Assumes access to db via db.database.get_pool and orchestrator processing function.
"""
from __future__ import annotations
import asyncio, argparse, random, json, datetime, uuid
from typing import List, Dict, Any
try:
    from prometheus_client import Counter
    replay_delta_counter = Counter('replay_deltas_processed_total','Replay deltas processed')
except Exception:
    replay_delta_counter = None

async def sample_event_ids(limit: int, since: str) -> List[str]:
    from db.database import get_pool
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT event_id, created_at
            FROM decisions
            WHERE created_at >= (NOW() - $1::interval)
            ORDER BY random()
            LIMIT $2
            """, since, limit)
        return [r['event_id'] for r in rows]

async def load_event(event_id: str) -> Dict[str, Any] | None:
    from db.database import get_pool
    async with (await get_pool()).acquire() as conn:
        row = await conn.fetchrow("SELECT e.* FROM events e WHERE e.id=$1", event_id)
        return dict(row) if row else None

async def load_original_decision(event_id: str) -> Dict[str, Any] | None:
    from db.database import get_pool
    async with (await get_pool()).acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM decisions WHERE event_id=$1", event_id)
        return dict(row) if row else None

async def process_event_fresh(event: Dict[str, Any]):
    from main import SecurityOrchestrator
    orch = SecurityOrchestrator()
    await orch.initialize()
    res = await orch.process_event(event)
    await orch.shutdown()
    return {
        'event_id': res.event_id,
        'verdict': 'malicious' if res.confidence >= 0.9 else ('suspicious' if res.confidence >=0.6 else 'benign'),
        'confidence': res.confidence
    }

async def run(limit: int, since: str, output: str | None):
    ids = await sample_event_ids(limit, since)
    results = []
    sample_run_id = str(uuid.uuid4())
    synthetic_event = {
        'id': f'synthetic-sbom-{sample_run_id[:8]}',
        'event_type': 'process_start',
        'process_name': 'libfoo',
        'process_hash': 'deadbeefcafebabesynthetic',
        'timestamp': str(datetime.datetime.utcnow()),
        'details': {'synthetic': True, 'purpose': 'sbom_coverage'}
    }
    try:
        fresh_syn = await process_event_fresh(synthetic_event)
        print(json.dumps({'event_id': synthetic_event['id'], 'synthetic': True, 'verdict': fresh_syn['verdict'], 'confidence': fresh_syn['confidence']}))
    except Exception:
        pass
    for eid in ids:
        original = await load_original_decision(eid)
        event = await load_event(eid)
        if not original or not event:
            continue
        fresh = await process_event_fresh(event)
        delta = {
            'event_id': eid,
            'original_verdict': original['verdict'],
            'new_verdict': fresh['verdict'],
            'original_confidence': float(original['confidence']),
            'new_confidence': fresh['confidence'],
            'confidence_delta': fresh['confidence'] - float(original['confidence'])
        }
        results.append(delta)
        print(json.dumps(delta))
        # Persist (best effort)
        try:
            from repositories import replay_deltas_repo
            await replay_deltas_repo.insert_delta(delta, since, sample_run_id)
        except Exception:
            pass
        try:
            if replay_delta_counter:
                replay_delta_counter.inc()
        except Exception:
            pass
    if output:
        with open(output,'w', encoding='utf-8') as f:
            for r in results:
                f.write(json.dumps(r)+'\n')

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=50)
    ap.add_argument('--since', type=str, default='7 days')
    ap.add_argument('--output', type=str, default=None)
    args = ap.parse_args()
    asyncio.run(run(args.limit, args.since, args.output))
