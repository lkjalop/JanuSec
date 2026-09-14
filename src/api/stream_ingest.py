from __future__ import annotations

import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from .runtime_state import EVENT_QUEUE
from .tenant_helpers import resolve_tenant_id

router = APIRouter(prefix="/api/v1/ingest", tags=["Streaming Ingest"])  # small, focused surface

# Simple per-tenant token-bucket rate limiter (in-memory, best-effort for tests)
_buckets: dict[str, dict] = {}
BUCKET_RATE = float(os.getenv('STREAM_INGEST_RATE_PER_SEC', '1.0'))  # tokens per second
BUCKET_CAPACITY = int(os.getenv('STREAM_INGEST_BURST_CAP', '2'))

# Max allowed upload size (bytes)
MAX_BYTES = int(os.getenv('STREAM_INGEST_MAX_BYTES', str(10 * 1024 * 1024)))  # default 10MB

# Queue backpressure policy: drop_oldest | reject | block
QUEUE_POLICY = os.getenv('STREAM_QUEUE_POLICY', 'drop_oldest')
# If utilization above this fraction, consider 'full'
QUEUE_UTIL_HIGH = float(os.getenv('STREAM_QUEUE_UTIL_HIGH', '0.95'))

# Idempotency (per-tenant recent body hash set) and toggles
STREAM_IDEMPOTENCY_ENABLED = os.getenv('STREAM_IDEMPOTENCY_ENABLED', '1').lower() not in {'0','false','no'}
_recent_hashes: dict[str, dict[str, float]] = {}
_recent_hash_max = int(os.getenv('STREAM_IDEMPOTENCY_MAX', '5000') or 5000)
_recent_hash_ttl = float(os.getenv('STREAM_IDEMPOTENCY_TTL_SEC', '900') or 900.0)  # 15m default

# Metrics wiring (reuse central registry)
try:
    from src.api.metrics_init import (
        ensure_metrics,
        ingest_events_counter,
        ingest_failures_counter,
        ingest_validation_errors,
        ingest_parse_failures_gauge,
        ingest_signature_failures,
        ingest_rate_drops,
    )  # type: ignore
    ensure_metrics()
except Exception:
    ingest_events_counter = ingest_failures_counter = ingest_validation_errors = ingest_parse_failures_gauge = ingest_signature_failures = ingest_rate_drops = None  # type: ignore


def _allow_token(tenant_id: str) -> bool:
    now = time.time()
    b = _buckets.setdefault(tenant_id, {'tokens': BUCKET_CAPACITY, 'last': now})
    elapsed = now - b['last']
    b['last'] = now
    # refill
    b['tokens'] = min(BUCKET_CAPACITY, b['tokens'] + elapsed * BUCKET_RATE)
    if b['tokens'] >= 1.0:
        b['tokens'] -= 1.0
        return True
    return False


def _detect_pcap_magic(head: bytes) -> bool:
    if not head or len(head) < 4:
        return False
    # pcap magic numbers (little/big endian) and pcapng
    if head.startswith(b'\xd4\xc3\xb2\xa1') or head.startswith(b'\xa1\xb2\xc3\xd4'):
        return True
    if head.startswith(b'\x0a\x0d\x0d\x0a'):
        return True
    return False


def _maybe_idempotent(tenant_id: str, body_hash: str) -> bool:
    if not STREAM_IDEMPOTENCY_ENABLED:
        return False
    now = time.time()
    bucket = _recent_hashes.setdefault(tenant_id, {})
    # purge expired entries occasionally (cheap sweep)
    if len(bucket) > _recent_hash_max:
        try:
            for k, ts in list(bucket.items())[: len(bucket)//5 or 1]:
                if now - ts > _recent_hash_ttl:
                    bucket.pop(k, None)
        except Exception:
            pass
    if body_hash in bucket:
        return True
    bucket[body_hash] = now
    # enforce max size
    if len(bucket) > _recent_hash_max:
        try:
            # drop oldest ~10%
            for k, _ in list(sorted(bucket.items(), key=lambda kv: kv[1]))[: max(1, _recent_hash_max//10)]:
                bucket.pop(k, None)
        except Exception:
            pass
    return False


@router.post('/stream-pcap')
async def stream_pcap(request: Request, x_api_key: str | None = Header(None, alias='X-API-Key'), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id')):
    """Accept a raw PCAP stream in the request body and enqueue it for async processing.

    Enhancements: file size limit, magic checks, queue backpressure policy handling,
    and cleaning up temp files if enqueue is rejected.
    """
    expected = os.getenv('INGEST_API_KEY')
    if expected and x_api_key != expected:
        try:
            if ingest_signature_failures:
                ingest_signature_failures.labels(reason='invalid_api_key').inc()
        except Exception:
            pass
        raise HTTPException(status_code=401, detail='invalid_api_key')

    tenant = resolve_tenant_id(request, x_tenant_id) or os.getenv('DEFAULT_TENANT') or 'public'
    # Rate limiting
    if not _allow_token(tenant):
        try:
            if ingest_rate_drops:
                ingest_rate_drops.labels(tenant_id=str(tenant), source='zeek').inc()
        except Exception:
            pass
        raise HTTPException(status_code=429, detail='rate_limited')

    tmp_dir = Path(tempfile.gettempdir()) / 'janusec_stream_ingest'
    tmp_dir.mkdir(parents=True, exist_ok=True)
    sess_id = uuid.uuid4().hex
    tmp_path = tmp_dir / f'{sess_id}.pcap'

    # Prefer a direct body read in tests/short uploads to avoid request.stream()
    # edge cases in TestClient transports, then fall back to true streaming.
    total = 0
    head = b''
    try:
        with open(tmp_path, 'wb') as fh:
            body = b''
            try:
                body = await request.body()
            except Exception:
                body = b''
            if body:
                total = len(body)
                head = body[:64]
                if total > MAX_BYTES:
                    fh.write(body[:MAX_BYTES])
                    try:
                        if ingest_failures_counter:
                            ingest_failures_counter.labels(reason='payload_too_large').inc()  # type: ignore
                    except Exception:
                        pass
                    raise HTTPException(status_code=413, detail='payload_too_large')
                fh.write(body)
            else:
                async for chunk in request.stream():
                    if not chunk:
                        continue
                    if total < 64:
                        need = 64 - len(head)
                        head += chunk[:need]
                    total += len(chunk)
                    if total > MAX_BYTES:
                        # abort and cleanup
                        fh.write(chunk[:max(0, MAX_BYTES - (total - len(chunk)))])
                        try:
                            if ingest_failures_counter:
                                ingest_failures_counter.labels(reason='payload_too_large').inc()  # type: ignore
                        except Exception:
                            pass
                        raise HTTPException(status_code=413, detail='payload_too_large')
                    fh.write(chunk)
    except HTTPException:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise
    except Exception as exc:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f'write_failed:{exc}')

    # Validate magic
    if not _detect_pcap_magic(head):
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        # metrics: validation error
        try:
            if ingest_validation_errors:
                ingest_validation_errors.labels(field='pcap_magic').inc()
        except Exception:
            pass
        raise HTTPException(status_code=400, detail='invalid_pcap_format')

    job = {'type': 'pcap_stream', 'path': str(tmp_path), 'tenant_id': tenant, 'session_id': sess_id, 'ts': time.time()}

    queued = False
    # Backpressure awareness
    try:
        # Resolve EVENT_QUEUE at call time to respect runtime monkeypatching in tests
        from . import runtime_state as _rs
        q = getattr(_rs, 'EVENT_QUEUE', None)
        if q:
            stats = None
            try:
                stats = q.stats() if hasattr(q, 'stats') else None
            except Exception:
                stats = None
            full = False
            if stats and stats.get('max_size'):
                util = (stats.get('depth', 0) or 0) / float(stats.get('max_size') or 1)
                if util >= QUEUE_UTIL_HIGH:
                    full = True

            if full and QUEUE_POLICY == 'reject':
                # reject immediately and cleanup file
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass
                raise HTTPException(status_code=503, detail='queue_full')

            if hasattr(q, 'enqueue'):
                import asyncio
                if QUEUE_POLICY == 'block' and full:
                    # block until enqueue completes (await)
                    queued = await q.enqueue(job)
                else:
                    # schedule enqueue in background; if queue is drop_oldest, the queue will manage
                    try:
                        asyncio.create_task(q.enqueue(job))
                        queued = True
                    except Exception:
                        queued = False
    except HTTPException:
        raise
    except Exception:
        queued = False

    # If job wasn't queued, clean up file proactively to avoid temp accumulation
    if not queued:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass

    # Metrics: treat each accepted pcap as an ingestion unit (count=1)
    try:
        if ingest_events_counter:
            ingest_events_counter.labels(source='pcap_stream').inc(1)  # type: ignore
        try:
            from .metrics_init import ingest_events_tenant_counter  # type: ignore
            if ingest_events_tenant_counter:
                ingest_events_tenant_counter.labels(tenant_id=str(tenant), source='pcap_stream').inc(1)  # type: ignore
        except Exception:
            pass
    except Exception:
        pass
    return JSONResponse({'status': 'accepted', 'queued': queued, 'session_id': sess_id, 'path': str(tmp_path)})


@router.post('/zeek-json')
async def zeek_json_ingest(request: Request, x_api_key: str | None = Header(None, alias='X-API-Key'), x_tenant_id: str | None = Header(None, alias='X-Tenant-Id')):
    """Accept Zeek NDJSON or JSON array and enqueue normalized events.

    Headers:
      - X-API-Key: optional shared key (INGEST_API_KEY checks when set)
      - X-Tenant-Id: tenant routing
    """
    expected = os.getenv('INGEST_API_KEY')
    if expected and x_api_key != expected:
        try:
            if ingest_failures_counter:
                ingest_failures_counter.labels(reason='invalid_api_key').inc()  # type: ignore
        except Exception:
            pass
        raise HTTPException(status_code=401, detail='invalid_api_key')
    tenant = resolve_tenant_id(request, x_tenant_id) or os.getenv('DEFAULT_TENANT') or 'public'
    # Rate limiting (per-tenant)
    if not _allow_token(tenant):
        try:
            if ingest_failures_counter:
                ingest_failures_counter.labels(reason='rate_limited').inc()  # type: ignore
        except Exception:
            pass
        raise HTTPException(status_code=429, detail='rate_limited')

    # Read full body (Zeek log chunks are typically modest per request)
    try:
        body = await request.body()
    except Exception as exc:
        try:
            if ingest_failures_counter:
                ingest_failures_counter.labels(reason='read_failed').inc()  # type: ignore
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=f'read_failed:{exc}')

    # Idempotency check
    try:
        import hashlib as _h
        bhash = _h.sha256(body).hexdigest()
        if _maybe_idempotent(tenant, bhash):
            return JSONResponse({'status': 'duplicate', 'accepted': False})
    except Exception:
        pass

    text = body.decode('utf-8', errors='replace').strip()
    rows = []
    import json as _json
    try:
        if text.startswith('['):
            data = _json.loads(text)
            rows = data if isinstance(data, list) else []
        else:
            # NDJSON
            rows = [ _json.loads(l) for l in text.splitlines() if l.strip() ]
    except Exception:
        try:
            if ingest_validation_errors:
                ingest_validation_errors.labels(field='zeek_json').inc()
            if ingest_parse_failures_gauge:
                ingest_parse_failures_gauge.labels(source='zeek').inc()
        except Exception:
            pass
        raise HTTPException(status_code=400, detail='invalid_json')

    # Normalize a subset of conn/dns/ssl/http fields
    def _norm(r: dict) -> dict:
        src = r.get('id.orig_h') or r.get('orig_h') or r.get('src')
        dst = r.get('id.resp_h') or r.get('resp_h') or r.get('dst')
        sport = r.get('id.orig_p') or r.get('orig_p') or r.get('sport')
        dport = r.get('id.resp_p') or r.get('resp_p') or r.get('dport')
        proto = (r.get('proto') or r.get('_proto') or '').upper()
        host = dst or r.get('host')
        sni = r.get('server_name') or r.get('ssl.server_name') or r.get('sni')
        ja3 = r.get('ja3') or r.get('ssl.ja3')
        tags = ['network', 'zeek']
        if 'conn' in (r.get('_path') or ''):
            tags.append('conn')
        if 'dns' in (r.get('_path') or ''):
            tags.append('dns')
        if 'ssl' in (r.get('_path') or '') or 'tls' in (r.get('_path') or ''):
            tags.append('ssl')
        if 'http' in (r.get('_path') or ''):
            tags.append('http')
        return {
            'src_ip': src,
            'dst_ip': dst,
            'src_port': sport,
            'dst_port': dport,
            'dest_port': dport,
            'host': host,
            'protocol': proto,
            'sni': sni,
            'ja3': ja3,
            'tags': tags,
            'ingest_source': 'zeek_json',
            'raw_event': r,
        }

    normalized = [_norm(r) for r in rows if isinstance(r, dict)]

    # Metrics: accepted events
    try:
        if ingest_events_counter:
            ingest_events_counter.labels(source='zeek').inc(len(normalized))  # type: ignore
        try:
            from .metrics_init import ingest_events_tenant_counter  # type: ignore
            if ingest_events_tenant_counter:
                ingest_events_tenant_counter.labels(tenant_id=str(tenant), source='zeek').inc(len(normalized))  # type: ignore
        except Exception:
            pass
    except Exception:
        pass

    # Enqueue (best-effort)
    queued = 0
    try:
        from . import runtime_state as _rs
        q = getattr(_rs, 'EVENT_QUEUE', None)
        if q and hasattr(q, 'enqueue'):
            import asyncio
            for ev in normalized[:5000]:  # cap to avoid abuse
                try:
                    asyncio.create_task(q.enqueue(ev))
                    queued += 1
                except Exception:
                    break
    except Exception:
        pass
    return JSONResponse({'status': 'accepted', 'received': len(rows), 'enqueued': queued})
