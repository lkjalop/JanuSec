from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import time
from datetime import datetime

router = APIRouter(prefix="/api/v1/remote_access", tags=["remote_access"])


class RemoteAccessIn(BaseModel):
    src_ip: str = Field(..., description="Source IP address")
    user: str = Field(..., description="User or account name")
    dest_host: str = Field(..., description="Destination host or resource")
    dest_port: Optional[int] = Field(None, description="Destination port")
    protocol: Optional[str] = Field("vpn", description="vpn|rdp|bastion")
    timestamp: Optional[str] = Field(None, description="ISO timestamp or epoch")
    raw: Optional[Dict[str, Any]] = Field(None, description="Raw event payload")
    # Optional enrichments for advanced detections
    geo_lat: Optional[float] = Field(None, description="Latitude of source IP geo")
    geo_lon: Optional[float] = Field(None, description="Longitude of source IP geo")
    mfa_used: Optional[bool] = Field(None, description="Was MFA used for this session?")


def _parse_ts(ts: Optional[str]) -> float:
    if ts is None:
        return time.time()
    try:
        # epoch
        if ts.isdigit():
            return float(ts)
    except Exception:
        pass
    try:
        # ISO 8601
        return datetime.fromisoformat(ts.replace('Z','+00:00')).timestamp()
    except Exception:
        return time.time()


async def _ingest_common(event: RemoteAccessIn, request: Request, proto_override: Optional[str] = None):
    """Ingest a VPN/RDP/Bastion event and create HopGraph nodes/edges.

    If `app.GLOBAL_HOPGRAPH` is available it will be used. Otherwise the
    endpoint returns a mock payload for local testing.
    """
    # Lazy import to avoid startup-time heavy imports
    app = request.app
    try:
        hopgraph = getattr(app, "GLOBAL_HOPGRAPH", None)
        if hopgraph is None:
            hopgraph = getattr(getattr(app, 'state', object()), 'hopgraph', None)
    except Exception:
        hopgraph = None

    # Import local helper lazily
    try:
        from src.core.graph.remote_access_hopgraph import RemoteAccessEvent, ingest_to_hopgraph
    except Exception:
        # fallback for older import style
        from core.graph.remote_access_hopgraph import RemoteAccessEvent, ingest_to_hopgraph

    # Advanced detections: impossible travel and MFA
    raw = dict(event.raw or {})
    try:
        from src.core.geo_velocity import GEO_VELOCITY
        lat = event.geo_lat if event.geo_lat is not None else raw.get('geo_lat') or raw.get('lat')
        lon = event.geo_lon if event.geo_lon is not None else raw.get('geo_lon') or raw.get('lon')
        if lat is not None and lon is not None:
            tsf = _parse_ts(event.timestamp)
            res = await GEO_VELOCITY.update('user', event.user, float(lat), float(lon), ts=tsf)
            if res.get('anomaly'):
                raw.setdefault('signals', {}).update({'impossible_travel': True, 'speed_kmh': round(res.get('speed_kmh',0.0),2)})
    except Exception:
        pass
    if event.mfa_used is not None:
        raw.setdefault('signals', {}).update({'mfa_used': bool(event.mfa_used)})

    # Organization geofencing: env ORG_ALLOWED_COUNTRIES=US,CA,GB
    try:
        import os
        allowed = os.getenv('ORG_ALLOWED_COUNTRIES')
        country = raw.get('country') or raw.get('geo_country') or raw.get('src_country')
        if allowed and country:
            allowset = {c.strip().upper() for c in allowed.split(',') if c.strip()}
            if str(country).strip().upper() not in allowset:
                raw.setdefault('signals', {}).update({'geo_out_of_policy': True, 'country': country})
    except Exception:
        pass

    # Simple user baseline (in-memory, best-effort): flag first-seen country change
    try:
        _BASE = getattr(_ingest_common, '_user_geo_base', {})
        country = raw.get('country') or raw.get('geo_country') or raw.get('src_country')
        if country:
            prev = _BASE.get(event.user)
            if prev and str(prev).upper() != str(country).upper():
                raw.setdefault('signals', {}).update({'user_geo_new_country': True, 'prev_country': prev})
            _BASE[event.user] = country
        _ingest_common._user_geo_base = _BASE  # type: ignore[attr-defined]
    except Exception:
        pass

    # DPI-style tunnel anomaly hints (heuristic):
    try:
        up = raw.get('bytes_up') or raw.get('tx_bytes')
        down = raw.get('bytes_down') or raw.get('rx_bytes')
        if isinstance(up, (int,float)) and isinstance(down, (int,float)):
            ratio = (max(up,1.0) / max(down,1.0)) if down else 0.0
            if ratio > float(os.getenv('VPN_DPI_RATIO_THRESHOLD','50') or 50) or ratio < (1.0/float(os.getenv('VPN_DPI_RATIO_THRESHOLD','50') or 50)):
                raw.setdefault('signals', {}).update({'dpi_suspect': True, 'ratio': round(ratio,2)})
    except Exception:
        pass

    evt = RemoteAccessEvent(
        src_ip=event.src_ip,
        user=event.user,
        dest_host=event.dest_host,
        dest_port=event.dest_port,
        protocol=(proto_override or event.protocol or "vpn"),
        timestamp=event.timestamp,
        raw=raw,
    )

    try:
        result = ingest_to_hopgraph(evt, hopgraph)
        # Phase 2 IAM: impossible travel factoring (feature-flagged)
        try:
            from src.core.detectors.iam_phase2 import detect_remote_access_phase2  # type: ignore
            ef, atts = detect_remote_access_phase2({'user': event.user, 'dest_host': event.dest_host, 'raw': raw})
            if hopgraph is not None and ef:
                for nid, fac in atts:
                    try:
                        hopgraph.add_node_attr(nid, type=(nid.split(':',1)[0] if ':' in nid else 'node'))
                        hopgraph.add_node_factor(nid, fac)
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ingest failed: {e}")

    return {"status": "accepted", "result": result}


@router.post("/ingest")
async def ingest_remote_access(event: RemoteAccessIn, request: Request):
    return await _ingest_common(event, request)


@router.post("/vpn/ingest")
async def ingest_vpn(event: RemoteAccessIn, request: Request):
    return await _ingest_common(event, request, proto_override='vpn')


@router.post("/rdp/ingest")
async def ingest_rdp(event: RemoteAccessIn, request: Request):
    return await _ingest_common(event, request, proto_override='rdp')


@router.post("/bastion/ingest")
async def ingest_bastion(event: RemoteAccessIn, request: Request):
    # Add quick heuristics for suspicious commands if provided
    try:
        cmd = (event.raw or {}).get('command')
        if isinstance(cmd, str) and cmd:
            raw = dict(event.raw or {})
            sig = raw.setdefault('signals', {})
            low = cmd.lower()
            if 'sudo ' in low or 'sudo su' in low:
                sig['bastion_priv_escalation'] = True
            if 'mysqldump' in low or 'pg_dump' in low or 'mongoexport' in low:
                sig['bastion_database_dump'] = True
            if 'scp ' in low or 'rsync ' in low:
                sig['bastion_file_transfer'] = True
            # Artifact stub path for session recorder
            try:
                from datetime import datetime as _dt
                ts = event.timestamp or _dt.utcnow().isoformat()
                art = f"artifacts/bastion/{event.user}/{ts.replace(':','-')}.log"
                sig['artifact_path'] = art
            except Exception:
                pass
            event.raw = raw
    except Exception:
        pass
    return await _ingest_common(event, request, proto_override='bastion')
