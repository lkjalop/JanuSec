from __future__ import annotations

import io
import os
import time
from typing import Any, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/forensics", tags=["Forensics"])

# In-memory parsed artifacts storage (best-effort; consider TTL eviction if needed)
_PCAP_CACHE: dict[str, dict[str, Any]] = {}
try:
    from src.artifact.memory_pipeline import MemoryPipeline  # type: ignore
except Exception:  # pragma: no cover
    MemoryPipeline = None  # type: ignore
try:  # pragma: no cover
    from src.artifact.memory_acquisition import MemoryAcquisitionGuide  # type: ignore
except Exception:  # pragma: no cover
    MemoryAcquisitionGuide = None  # type: ignore
try:  # pragma: no cover
    from src.security.hsm_attestor import get_latest_attestor  # type: ignore
except Exception:  # pragma: no cover
    def get_latest_attestor():
        return None

_MEMORY_PIPELINE = MemoryPipeline() if MemoryPipeline else None
_ACQ_GUIDE = MemoryAcquisitionGuide() if MemoryAcquisitionGuide else None


def _pcap_enabled() -> bool:
    return os.getenv('FORENSICS_PCAP_ENABLED', '0').lower() in {'1','true','yes'}


def _evtx_enabled() -> bool:
    return os.getenv('FORENSICS_EVTX_ENABLED', '0').lower() in {'1','true','yes'}


def _memory_enabled() -> bool:
    return os.getenv('FORENSICS_MEMORY_ENABLED', '0').lower() in {'1', 'true', 'yes'}


class MemoryAcquisitionRequest(BaseModel):
    host: str
    os_family: str = "windows"
    case_id: Optional[str] = None
    tenant_id: Optional[str] = None
    courier_profile: Optional[str] = None


class MemoryAttestationRequest(BaseModel):
    event: str = "uploaded"
    operator: Optional[str] = None
    checksum: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None



@router.post('/pcap/parse')
async def parse_pcap(file: UploadFile = File(...), max_packets: int = Query(100000, le=1000000), timeout_seconds: float = Query(5.0, le=30.0)):
    if not _pcap_enabled():
        raise HTTPException(status_code=503, detail='pcap_forensics_disabled')
    try:
        content = await file.read()
    except Exception:
        raise HTTPException(status_code=400, detail='read_failed')
    # Size cap (50MB default)
    try:
        max_bytes = int(os.getenv('FORENSICS_PCAP_MAX_BYTES', str(50*1024*1024)))
    except Exception:
        max_bytes = 50*1024*1024
    if len(content) > max_bytes:
        content = content[:max_bytes]
    # Parse with timeout
    try:
        from parsers.pcap_parser import parse_pcap_bytes  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail='pcap_parser_not_available')
    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(parse_pcap_bytes, content, max_packets)
            parsed = fut.result(timeout=timeout_seconds)
    except concurrent.futures.TimeoutError:
        raise HTTPException(status_code=504, detail='pcap_parse_timeout')
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'pcap_parse_error: {exc}')
    # Store flows for optional paging
    pid = f"pcap-{int(time.time()*1000)}-{len(content)}"
    _PCAP_CACHE[pid] = parsed or {}
    summary = {
        'id': pid,
        'filename': file.filename,
        'size': len(content),
        'flow_count': len((parsed or {}).get('flows') or []),
        'dns_count': len((parsed or {}).get('dns') or []),
        'tls_count': len((parsed or {}).get('tls') or []),
    }
    return { 'summary': summary, 'preview': {
        'flows': (parsed or {}).get('flows', [])[:10],
        'dns': (parsed or {}).get('dns', [])[:10],
        'tls': (parsed or {}).get('tls', [])[:10],
    }}


@router.get('/pcap/flows')
async def pcap_flows(id: str, offset: int = Query(0, ge=0), limit: int = Query(200, le=2000)):
    if not _pcap_enabled():
        raise HTTPException(status_code=503, detail='pcap_forensics_disabled')
    data = _PCAP_CACHE.get(id)
    if not data:
        raise HTTPException(status_code=404, detail='not_found')
    flows = data.get('flows') or []
    end = min(len(flows), offset + limit)
    return { 'id': id, 'offset': offset, 'limit': limit, 'returned': max(0, end - offset), 'total': len(flows), 'flows': flows[offset:end] }


@router.post('/evtx/parse')
async def parse_evtx(file: UploadFile = File(...), timeout_seconds: float = Query(5.0, le=30.0)):
    if not _evtx_enabled():
        raise HTTPException(status_code=503, detail='evtx_forensics_disabled')
    try:
        content = await file.read()
    except Exception:
        raise HTTPException(status_code=400, detail='read_failed')
    try:
        from parsers.evtx_parser import parse_evtx_bytes  # type: ignore
    except Exception:
        raise HTTPException(status_code=503, detail='evtx_parser_not_available')
    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(parse_evtx_bytes, content)
            parsed = fut.result(timeout=timeout_seconds)
    except concurrent.futures.TimeoutError:
        raise HTTPException(status_code=504, detail='evtx_parse_timeout')
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'evtx_parse_error: {exc}')
    # Minimal summary
    return {
        'summary': {
            'size': len(content),
            'events': len((parsed or {}).get('events') or []),
            'hints': (parsed or {}).get('hints') or {},
        },
        'preview': (parsed or {}).get('events', [])[:20]
    }


@router.post('/memory/acquisition')
async def issue_memory_acquisition_plan(req: MemoryAcquisitionRequest):
    if not _memory_enabled():
        raise HTTPException(status_code=503, detail='memory_pipeline_disabled')
    if not _ACQ_GUIDE:
        raise HTTPException(status_code=503, detail='memory_acquisition_disabled')
    plan = _ACQ_GUIDE.issue_plan(
        host=req.host,
        os_family=req.os_family,
        case_id=req.case_id,
        tenant_id=req.tenant_id,
        courier_profile=req.courier_profile,
    )
    return plan.to_dict()


@router.post('/memory/acquisition/{attestation_id}/attest')
async def record_memory_attestation(attestation_id: str, body: MemoryAttestationRequest):
    if not _memory_enabled():
        raise HTTPException(status_code=503, detail='memory_pipeline_disabled')
    if not _ACQ_GUIDE:
        raise HTTPException(status_code=503, detail='memory_acquisition_disabled')
    try:
        plan = _ACQ_GUIDE.record_event(
            attestation_id,
            event=body.event,
            operator=body.operator,
            checksum=body.checksum,
            metadata=body.metadata,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail='attestation_not_found')
    return plan.to_dict()


@router.post('/memory/upload')
async def upload_memory_dump(
    file: UploadFile = File(...),
    host: str = Form(...),
    case_id: str | None = Form(None),
    profile: str | None = Form(None),
    auto_analyze: bool = Form(True),
    tenant_id: str | None = Form(None),
):
    if not _memory_enabled() or not _MEMORY_PIPELINE:
        raise HTTPException(status_code=503, detail='memory_pipeline_disabled')
    try:
        content = await file.read()
    except Exception:
        raise HTTPException(status_code=400, detail='read_failed')
    max_bytes = int(os.getenv('FORENSICS_MEMORY_MAX_BYTES', str(512 * 1024 * 1024)))
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail='memory_dump_too_large')
    metadata = {'profile': profile, 'filename': file.filename, 'tenant_id': tenant_id}
    job = _MEMORY_PIPELINE.submit_job(
        host=host,
        case_id=case_id,
        filename=file.filename or f"{host}_memory.raw",
        dump_bytes=content,
        metadata=metadata,
    )
    analysis: Dict[str, Any] | None = None
    if auto_analyze:
        job = _MEMORY_PIPELINE.process_job(job.job_id, auto_cleanup=False)
        analysis = job.metadata.get('analysis')
    return {
        'job_id': job.job_id,
        'status': job.status,
        'host': job.host,
        'analysis': analysis,
    }


@router.get('/memory/{job_id}')
async def get_memory_job(job_id: str):
    if not _memory_enabled() or not _MEMORY_PIPELINE:
        raise HTTPException(status_code=503, detail='memory_pipeline_disabled')
    job = _MEMORY_PIPELINE.jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='job_not_found')
    return {
        'job_id': job.job_id,
        'status': job.status,
        'host': job.host,
        'case_id': job.case_id,
        'factors': job.factors,
        'metadata': job.metadata,
        'requested_plugins': job.requested_plugins,
    }


@router.get('/memory/hsm_health')
async def get_hsm_health(run_check: bool = Query(False)):
    attestor = get_latest_attestor()
    if not attestor:
        raise HTTPException(status_code=404, detail='attestor_inactive')
    if run_check:
        attestor.run_health_check()
    return {
        'enabled': attestor.enabled(),
        'snapshot': attestor.health_snapshot(),
    }

__all__ = ['router']
@router.get('/memory/acquisition')
async def list_memory_acquisition(limit: int = Query(10, ge=1, le=50)):
    if not _memory_enabled():
        raise HTTPException(status_code=503, detail='memory_pipeline_disabled')
    if not _ACQ_GUIDE:
        raise HTTPException(status_code=503, detail='memory_acquisition_disabled')
    plans = _ACQ_GUIDE.list_plans(limit=limit)
    return {'plans': plans}
