from __future__ import annotations
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import logging
import time

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/capture', tags=['Capture'])


class CaptureRequest(BaseModel):
    scope: Optional[str] = None
    reason: Optional[str] = None
    duration_seconds: Optional[int] = 60
    profile: Optional[str] = None
    interface: Optional[str] = None
    bpf_filter: Optional[str] = None
    full_payload: bool = False


# Approval audit — tracks pending + approved/rejected decisions
_audit: Dict[str, Dict[str, Any]] = {}

# Approved captures go here; the driver is only started after approval
_approved: set[str] = set()


def _require_approval(cid: str) -> None:
    entry = _audit.get(cid)
    if not entry:
        raise HTTPException(status_code=404, detail='capture_not_found')
    if entry['status'] != 'approved':
        raise HTTPException(status_code=403, detail='capture_not_approved')


# ── PCAP endpoints ────────────────────────────────────────────────────

@router.post('/pcap/start')
async def start_pcap(req: CaptureRequest) -> Dict[str, Any]:
    """Submit a PCAP capture request (requires /pcap/approve before capture starts)."""
    duration = min(int(req.duration_seconds or 60), 300)
    cid = f"pcap-{int(time.time()*1000)}"
    _audit[cid] = {
        'id': cid,
        'type': 'pcap',
        'status': 'pending_approval',
        'created_ts': time.time(),
        'scope': req.scope,
        'reason': req.reason,
        'interface': req.interface,
        'bpf_filter': req.bpf_filter,
        'duration_seconds': duration,
        'full_payload': req.full_payload,
        'expected_costs': {'cpu_hint': 'moderate', 'storage_hint': 'moderate'},
        'privacy_notes': {'payload': 'first 128 bytes only unless full_payload approved'},
    }
    return _audit[cid]


@router.post('/pcap/approve')
async def approve_pcap(capture_id: str, analyst: str = 'system') -> Dict[str, Any]:
    """Analyst approves a pending PCAP capture — triggers the actual driver."""
    entry = _audit.get(capture_id)
    if not entry or entry['type'] != 'pcap':
        raise HTTPException(status_code=404, detail='capture_not_found')
    if entry['status'] == 'running':
        raise HTTPException(status_code=409, detail='already_running')

    entry['status'] = 'approved'
    entry['approved_by'] = analyst
    entry['approved_ts'] = time.time()

    try:
        from src.drivers.pcap_driver import PcapDriver, CaptureSpec, get_pcap_driver
        spec = CaptureSpec(
            capture_id=capture_id,
            interface=entry.get('interface'),
            bpf_filter=entry.get('bpf_filter'),
            duration_seconds=entry.get('duration_seconds', 60),
            full_payload=entry.get('full_payload', False),
            scope=entry.get('scope'),
            reason=entry.get('reason'),
        )
        driver = get_pcap_driver()
        driver.start(spec)
        entry['status'] = 'running'
        _approved.add(capture_id)
    except PermissionError as exc:
        entry['status'] = 'error'
        entry['error'] = str(exc)
        raise HTTPException(status_code=503, detail=f'pcap_driver_unavailable: {exc}')
    except Exception as exc:
        entry['status'] = 'error'
        entry['error'] = str(exc)
        logger.error('PCAP start error for %s: %s', capture_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail='pcap_start_failed')

    return entry


@router.post('/pcap/stop')
async def stop_pcap(capture_id: str) -> Dict[str, Any]:
    """Stop a running PCAP capture and return results."""
    entry = _audit.get(capture_id)
    if not entry or entry['type'] != 'pcap':
        raise HTTPException(status_code=404, detail='capture_not_found')

    try:
        from src.drivers.pcap_driver import get_pcap_driver
        driver = get_pcap_driver()
        result = driver.stop(capture_id)
        entry['status'] = result.state.value.lower()
        entry['stopped_ts'] = result.stopped_ts
        entry['packet_count'] = result.packet_count
        entry['dropped_count'] = result.dropped_count
        entry['pcap_path'] = result.pcap_path
        entry['backend'] = result.backend
        return {
            **entry,
            'packets': [
                {
                    'ts': p.ts,
                    'src': p.src,
                    'dst': p.dst,
                    'proto': p.proto,
                    'length': p.length,
                }
                for p in result.packets[:200]
            ],
        }
    except KeyError:
        raise HTTPException(status_code=404, detail='driver_session_not_found')
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get('/pcap/status/{capture_id}')
async def pcap_status(capture_id: str) -> Dict[str, Any]:
    """Get live status of a PCAP capture."""
    entry = _audit.get(capture_id)
    if not entry:
        raise HTTPException(status_code=404, detail='capture_not_found')

    if capture_id in _approved:
        try:
            from src.drivers.pcap_driver import get_pcap_driver
            result = get_pcap_driver().status(capture_id)
            if result:
                entry['backend'] = result.backend
                entry['packet_count'] = result.packet_count
                entry['state'] = result.state.value
        except Exception:
            pass

    return entry


# ── eBPF endpoints (approval + profile gating) ────────────────────────

@router.post('/ebpf/start')
async def start_ebpf(req: CaptureRequest) -> Dict[str, Any]:
    """Submit an eBPF capture request (requires /ebpf/approve before activation)."""
    cid = f"ebpf-{int(time.time()*1000)}"
    _audit[cid] = {
        'id': cid,
        'type': 'ebpf',
        'status': 'pending_approval',
        'created_ts': time.time(),
        'scope': req.scope,
        'reason': req.reason,
        'duration_seconds': min(int(req.duration_seconds or 60), 300),
        'profile': req.profile or 'net+proc-min',
        'expected_costs': {'cpu_hint': 'low', 'storage_hint': 'low'},
        'privacy_notes': {'args': 'process args redacted; no payload capture'},
    }
    return _audit[cid]


@router.post('/ebpf/approve')
async def approve_ebpf(capture_id: str, analyst: str = 'system') -> Dict[str, Any]:
    """Analyst approves an eBPF capture — activates via Falco relay."""
    entry = _audit.get(capture_id)
    if not entry or entry['type'] != 'ebpf':
        raise HTTPException(status_code=404, detail='capture_not_found')

    entry['status'] = 'approved'
    entry['approved_by'] = analyst
    entry['approved_ts'] = time.time()
    # Falco consumes the profile via its relay — activation is push-model
    entry['activation_note'] = 'Falco relay notified; events will appear in /api/v1/ingest/ebpf stream'
    return entry


@router.get('/list')
async def list_captures() -> Dict[str, Any]:
    """List all capture audit records."""
    return {'captures': list(_audit.values()), 'count': len(_audit)}


__all__ = ['router']
