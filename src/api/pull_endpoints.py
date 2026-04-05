from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Request, HTTPException, Depends

from src.security.auth import require_api_key
from src.security.roles import require_roles
from src.api.auth_rate_limit import alerts_auth
import src.api.metrics_init as metrics
from src.api.metrics_init import ensure_metrics
from src.api import runtime_state
from src.monitoring.log_pull_contracts import get_contract
from src.repositories.audit_repo import append_audit, get_last_hash

router = APIRouter()


def _require_tenant(request: Request) -> str:
    tid = request.headers.get('x-tenant-id') or request.headers.get('X-Tenant-Id') or os.getenv('DEFAULT_TENANT','default')
    return tid


def _enforce_tenant_quota(tenant: str, kind: str) -> None:
    try:
        # Per-tenant sliding window counter stored in runtime tenant partition
        tmap = runtime_state.get_tenant_runtime(None, tenant)
        key = 'pull_timestamps'
        arr = tmap.get(key) or []
        # normalize to list of floats
        try:
            arr = [float(x) for x in arr]
        except Exception:
            arr = list(arr)
        now = time.time()
        window = int(os.getenv('TENANT_PULL_WINDOW_SECONDS', '3600') or 3600)
        # prune old
        cutoff = now - window
        arr = [t for t in arr if t >= cutoff]
        maxpulls = int(os.getenv('TENANT_PULL_MAX_PER_WINDOW', '100') or 100)
        if len(arr) >= maxpulls:
            raise HTTPException(status_code=429, detail='tenant_pull_quota_exceeded')
        # record tentative entry (we'll persist after successful dispatch)
        arr.append(now)
        tmap[key] = arr
    except HTTPException:
        raise
    except Exception:
        # best-effort: if runtime_state not available, skip quota enforcement
        return


def _summarize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    keep = {}
    for key in ("users", "hosts", "domains", "start", "end", "center", "window_minutes", "ttl_seconds"):
        if key in payload:
            keep[key] = payload.get(key)
    return keep


def _hash_payload(data: Dict[str, Any]) -> str:
    blob = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


async def _record_custody(
    tenant: str,
    source: str,
    payload: Dict[str, Any],
    request_id: str,
    contract_id: str | None,
) -> Dict[str, Any]:
    event_id = f"logpull:{tenant}:{source}:{request_id}"
    prev = await get_last_hash(event_id, tenant_id=tenant)
    summary = _summarize_payload(payload)
    custody_hash = _hash_payload({
        "tenant_id": tenant,
        "source": source,
        "request_id": request_id,
        "payload": summary,
    })
    await append_audit(
        event_id=event_id,
        action="log_pull",
        details={
            "source": source,
            "request_id": request_id,
            "contract_id": contract_id,
            "payload_summary": summary,
        },
        custody_hash=custody_hash,
        prev_hash=prev,
        tenant_id=tenant,
    )
    return {"event_id": event_id, "custody_hash": custody_hash, "prev_hash": prev}


def _parse_ts(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return float(value)
        except Exception:
            return None
    if isinstance(value, str):
        txt = value.strip()
        try:
            return float(txt)
        except Exception:
            pass
        try:
            return datetime.fromisoformat(txt.replace("Z", "")).timestamp()
        except Exception:
            return None
    return None


def _time_window(payload: Dict[str, Any], default_hours: int = 24) -> tuple[float, float]:
    now = time.time()
    start = _parse_ts(payload.get("start"))
    end = _parse_ts(payload.get("end"))
    if end is None:
        end = now
    if start is None:
        start = end - (default_hours * 3600)
    return float(start), float(end)


def _extract_recipients(raw: Dict[str, Any]) -> list[str]:
    recipients: list[str] = []
    try:
        to_recips = raw.get("toRecipients") or raw.get("to") or []
        if isinstance(to_recips, list):
            for entry in to_recips:
                if isinstance(entry, dict):
                    addr = entry.get("emailAddress", {}).get("address") or entry.get("address")
                    if addr:
                        recipients.append(str(addr))
                elif isinstance(entry, str):
                    recipients.append(entry)
        elif isinstance(to_recips, str):
            recipients.extend([v.strip() for v in to_recips.split(",") if v.strip()])
    except Exception:
        pass
    try:
        payload = raw.get("payload") or {}
        headers = payload.get("headers") or []
        if isinstance(headers, list):
            for hdr in headers:
                if isinstance(hdr, dict) and str(hdr.get("name", "")).lower() == "to":
                    val = hdr.get("value") or ""
                    recipients.extend([v.strip() for v in str(val).split(",") if v.strip()])
    except Exception:
        pass
    return [r for r in recipients if r]


def _extract_sender(raw: Dict[str, Any]) -> str | None:
    for key in ("from", "sender"):
        val = raw.get(key)
        if isinstance(val, dict):
            addr = val.get("emailAddress", {}).get("address") or val.get("address")
            if addr:
                return str(addr)
        if isinstance(val, str) and val:
            return val
    try:
        payload = raw.get("payload") or {}
        headers = payload.get("headers") or []
        if isinstance(headers, list):
            for hdr in headers:
                if isinstance(hdr, dict) and str(hdr.get("name", "")).lower() == "from":
                    return str(hdr.get("value") or "")
    except Exception:
        pass
    return None


def _extract_message_id(raw: Dict[str, Any]) -> str | None:
    for key in ("message_id", "messageId", "internetMessageId", "id"):
        val = raw.get(key)
        if val:
            return str(val)
    try:
        payload = raw.get("payload") or {}
        headers = payload.get("headers") or []
        if isinstance(headers, list):
            for hdr in headers:
                if isinstance(hdr, dict) and str(hdr.get("name", "")).lower() == "message-id":
                    return str(hdr.get("value") or "")
    except Exception:
        pass
    return None


def _extract_received_ts(raw: Dict[str, Any]) -> float | None:
    for key in ("receivedDateTime", "timestamp", "ts", "internalDate"):
        if key not in raw:
            continue
        val = raw.get(key)
        if key == "internalDate":
            try:
                return float(val) / 1000.0
            except Exception:
                return None
        parsed = _parse_ts(val)
        if parsed is not None:
            return parsed
    return None


async def _fetch_delivery_events(tenant: str, recipients: list[str], start_ts: float) -> list[Dict[str, Any]]:
    events: list[Dict[str, Any]] = []
    recipient_set = {r.lower() for r in recipients if isinstance(r, str)}
    try:
        from src.collectors.email_o365_adapter import O365EmailCollector
        from src.collectors.email_gmail_adapter import GmailEmailCollector
        collectors = [O365EmailCollector(), GmailEmailCollector()]
        for collector in collectors:
            try:
                rows = collector.fetch_events(start_ts)
            except Exception:
                rows = []
            for raw in rows or []:
                if not isinstance(raw, dict):
                    continue
                recips = _extract_recipients(raw)
                if recipient_set and not any(r.lower() in recipient_set for r in recips):
                    continue
                ts = _extract_received_ts(raw) or time.time()
                events.append({
                    "recipient": recips[0] if recips else None,
                    "message_id": _extract_message_id(raw),
                    "sender": _extract_sender(raw),
                    "disposition": "delivered",
                    "ts": int(ts),
                })
    except Exception:
        pass
    return events


async def _fetch_click_events(users: list[str], start_ts: float, end_ts: float) -> list[Dict[str, Any]]:
    events: list[Dict[str, Any]] = []
    user_set = {u.lower() for u in users if isinstance(u, str)}
    try:
        from src.connectors.email.click_store import fetch_recent_clicks
        rows = fetch_recent_clicks(limit=500)
        for row in rows:
            ts = row.get("timestamp") or row.get("ts")
            ts_val = _parse_ts(ts) or 0
            if ts_val < start_ts or ts_val > end_ts:
                continue
            user = row.get("user")
            if user_set and (not user or str(user).lower() not in user_set):
                continue
            meta = row.get("meta") if isinstance(row.get("meta"), dict) else {}
            events.append({
                "user": user,
                "url": row.get("url"),
                "device_id": meta.get("device_id"),
                "ts": int(ts_val),
            })
    except Exception:
        pass
    return events


def _is_quarantine_event(evt) -> bool:
    try:
        verdict = ""
        for key in ("verdict", "triage_verdict", "triage_status", "event_type"):
            val = getattr(evt, key, None) if not isinstance(evt, dict) else evt.get(key)
            if val:
                verdict += f" {val}"
        verdict = verdict.lower()
        return "quarantine" in verdict or "quarantined" in verdict
    except Exception:
        return False


async def _fetch_quarantine_events(tenant: str, since_dt: datetime, recipients: list[str] | None = None) -> list[Dict[str, Any]]:
    events: list[Dict[str, Any]] = []
    recipient_set = {r.lower() for r in (recipients or []) if isinstance(r, str)}
    try:
        from src.integrations.auth.token_store import TokenStore
        token_store = TokenStore()
    except Exception:
        token_store = None

    async def _collect_from_abnormal():
        try:
            from src.connectors.email.abnormal import AbnormalConfig, AbnormalConnector
            cfg = AbnormalConfig(
                base_url=os.getenv("ABNORMAL_BASE_URL", AbnormalConfig.base_url),
                token_endpoint=os.getenv("ABNORMAL_TOKEN_ENDPOINT", AbnormalConfig.token_endpoint),
                alerts_endpoint=os.getenv("ABNORMAL_ALERTS_ENDPOINT", AbnormalConfig.alerts_endpoint),
                client_id=os.getenv("ABNORMAL_CLIENT_ID"),
                client_secret=os.getenv("ABNORMAL_CLIENT_SECRET"),
            )
            if not (cfg.client_id and cfg.client_secret) or token_store is None:
                return []
            connector = AbnormalConnector(cfg, token_store)
            rows = await connector.fetch_alerts(tenant, since=since_dt, limit=200)
            await connector.close()
            return rows
        except Exception:
            return []

    async def _collect_from_mimecast():
        try:
            from src.connectors.email.mimecast import MimecastConfig, MimecastConnector
            cfg = MimecastConfig(
                base_url=os.getenv("MIMECAST_BASE_URL", MimecastConfig.base_url),
                token_endpoint=os.getenv("MIMECAST_TOKEN_ENDPOINT", MimecastConfig.token_endpoint),
                detections_endpoint=os.getenv("MIMECAST_DETECTIONS_ENDPOINT", MimecastConfig.detections_endpoint),
                client_id=os.getenv("MIMECAST_CLIENT_ID"),
                client_secret=os.getenv("MIMECAST_CLIENT_SECRET"),
            )
            if not (cfg.client_id and cfg.client_secret) or token_store is None:
                return []
            connector = MimecastConnector(cfg, token_store)
            rows = await connector.fetch_detections(tenant, since=since_dt, limit=200)
            await connector.close()
            return rows
        except Exception:
            return []

    async def _collect_from_defender():
        try:
            from src.connectors.email.microsoft_graph_defender import GraphConfig, DefenderConnector
            tenant_id = os.getenv("DEFENDER_TENANT_ID") or os.getenv("AZURE_TENANT_ID")
            client_id = os.getenv("DEFENDER_CLIENT_ID") or os.getenv("AZURE_CLIENT_ID")
            client_secret = os.getenv("DEFENDER_CLIENT_SECRET") or os.getenv("AZURE_CLIENT_SECRET")
            if not (tenant_id and client_id and client_secret) or token_store is None:
                return []
            cfg = GraphConfig(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
            connector = DefenderConnector(cfg, token_store)
            rows = await connector.fetch_security_alerts(tenant, top=200)
            await connector.close()
            return rows
        except Exception:
            return []

    for collector in (_collect_from_abnormal, _collect_from_mimecast, _collect_from_defender):
        rows = await collector()
        for evt in rows or []:
            if not _is_quarantine_event(evt):
                continue
            try:
                ts = getattr(evt, "timestamp", None) if not isinstance(evt, dict) else evt.get("timestamp")
                if isinstance(ts, datetime):
                    ts_val = int(ts.timestamp())
                else:
                    ts_val = int(_parse_ts(ts) or time.time())
                if isinstance(evt, dict):
                    recipient = evt.get("recipient") or evt.get("user")
                    message_id = evt.get("message_id") or evt.get("messageId")
                    reason = evt.get("threat_type") or evt.get("triage_verdict") or evt.get("verdict")
                else:
                    recipient = getattr(evt, "recipient", None)
                    message_id = getattr(evt, "message_id", None)
                    reason = getattr(evt, "threat_type", None) or getattr(evt, "triage_verdict", None)
                if recipient_set and (not recipient or str(recipient).lower() not in recipient_set):
                    continue
                events.append({
                    "recipient": recipient,
                    "message_id": message_id,
                    "action": "quarantined",
                    "reason": reason,
                    "ts": ts_val,
                })
            except Exception:
                continue
    return events


def _load_contract(source: str) -> Dict[str, Any] | None:
    contract = get_contract(source)
    if not contract:
        return None
    contract["contract_id"] = contract.get("id") or source
    return contract


@router.post('/api/v1/identity/pull')
async def identity_pull(payload: dict, request: Request, _auth = require_api_key, rl = alerts_auth):
    """Return identity events for given users in a small time window. Enforce tenant scope and simple rate-limit."""
    ensure_metrics()
    tenant = _require_tenant(request)
    users = payload.get('users') or []
    start = payload.get('start')
    end = payload.get('end')
    ttl = int(payload.get('ttl_seconds', 1800))
    if not users:
        raise HTTPException(status_code=400, detail='users_required')
    # Simple per-tenant quota enforcement
    _enforce_tenant_quota(tenant, 'identity')
    start = time.time()
    request_id = payload.get("request_id") or request.headers.get("x-request-id") or str(uuid.uuid4())
    contract = _load_contract("identity_auth_logs")
    contract_id = contract.get("contract_id") if contract else None
    custody = await _record_custody(tenant, "identity_auth_logs", payload, request_id, contract_id)
    # Simulate a pull by returning a compact corroboration payload (real impl calls connector)
    now = int(time.time())
    resp = {
        'tenant_id': tenant,
        'source': 'identity_auth_logs',
        'fetched_at': now,
        'ttl_seconds': ttl,
        'events': [{'user': u, 'device_id': f'dev-{u}', 'risk': 'low', 'ts': now - 60} for u in users],
        'request_id': request_id,
        'contract_id': contract_id,
        'contract': contract,
        'custody': custody,
    }
    # Metrics
    try:
        metrics.ensure_metrics()
        try:
            metrics.asks_sent_total.labels(endpoint='identity', status='ok').inc(1)
        except Exception:
            try:
                metrics.asks_sent_total.labels('identity','ok').inc(1)
            except Exception:
                pass
        try:
            metrics.asks_dispatch_latency_seconds.labels(endpoint='identity').observe(max(0.0, time.time() - start))
        except Exception:
            pass
    except Exception:
        pass
    return resp


@router.post('/api/v1/edr/process_tree/pull')
async def edr_process_tree_pull(payload: dict, request: Request, _auth = require_api_key, rl = alerts_auth):
    ensure_metrics()
    tenant = _require_tenant(request)
    hosts = payload.get('hosts') or []
    center = payload.get('center')
    window = int(payload.get('window_minutes', 30))
    ttl = int(payload.get('ttl_seconds', 1800))
    if not hosts:
        raise HTTPException(status_code=400, detail='hosts_required')
    _enforce_tenant_quota(tenant, 'edr')
    start = time.time()
    request_id = payload.get("request_id") or request.headers.get("x-request-id") or str(uuid.uuid4())
    contract = _load_contract("endpoint_edr_heartbeat")
    contract_id = contract.get("contract_id") if contract else None
    custody = await _record_custody(tenant, "endpoint_edr_heartbeat", payload, request_id, contract_id)
    now = int(time.time())
    # Return fake process tree snippets for hosts
    events = []
    for h in hosts:
        events.append({'host': h, 'process_tree': [{'proc':'cmd.exe','pid':1000,'parent':1},{'proc':'malware.exe','pid':1001,'parent':1000}], 'center': center, 'ts': now - 30})
    out = {
        'tenant_id': tenant,
        'source': 'endpoint_edr_heartbeat',
        'fetched_at': now,
        'ttl_seconds': ttl,
        'events': events,
        'request_id': request_id,
        'contract_id': contract_id,
        'contract': contract,
        'custody': custody,
    }
    # Metrics
    try:
        metrics.ensure_metrics()
        try:
            metrics.asks_sent_total.labels(endpoint='edr', status='ok').inc(1)
        except Exception:
            try:
                metrics.asks_sent_total.labels('edr','ok').inc(1)
            except Exception:
                pass
        try:
            metrics.asks_dispatch_latency_seconds.labels(endpoint='edr').observe(max(0.0, time.time() - start))
        except Exception:
            pass
    except Exception:
        pass
    return out


@router.post('/api/v1/dns/lookup/pull')
async def dns_lookup_pull(payload: dict, request: Request, _auth = require_api_key, rl = alerts_auth):
    ensure_metrics()
    tenant = _require_tenant(request)
    domains = payload.get('domains') or []
    hosts = payload.get('hosts') or []
    start = payload.get('start')
    end = payload.get('end')
    ttl = int(payload.get('ttl_seconds', 1800))
    if not domains and not hosts:
        raise HTTPException(status_code=400, detail='domains_or_hosts_required')
    _enforce_tenant_quota(tenant, 'dns')
    start = time.time()
    request_id = payload.get("request_id") or request.headers.get("x-request-id") or str(uuid.uuid4())
    contract = _load_contract("dns_query_logs")
    contract_id = contract.get("contract_id") if contract else None
    custody = await _record_custody(tenant, "dns_query_logs", payload, request_id, contract_id)
    now = int(time.time())
    records = []
    for d in domains:
        records.append({'domain': d, 'qtype': 'A','answer':'1.2.3.4','ts': now - 10})
    out = {
        'tenant_id': tenant,
        'source': 'dns_query_logs',
        'fetched_at': now,
        'ttl_seconds': ttl,
        'records': records,
        'request_id': request_id,
        'contract_id': contract_id,
        'contract': contract,
        'custody': custody,
    }
    try:
        metrics.ensure_metrics()
        try:
            metrics.asks_sent_total.labels(endpoint='dns', status='ok').inc(1)
        except Exception:
            try:
                metrics.asks_sent_total.labels('dns','ok').inc(1)
            except Exception:
                pass
        try:
            metrics.asks_dispatch_latency_seconds.labels(endpoint='dns').observe(max(0.0, time.time() - start))
        except Exception:
            pass
    except Exception:
        pass
    return out


@router.post('/api/v1/email/delivery/pull')
async def email_delivery_pull(payload: dict, request: Request, _auth = require_api_key, rl = alerts_auth):
    ensure_metrics()
    tenant = _require_tenant(request)
    recipients = payload.get('recipients') or payload.get('users') or []
    ttl = int(payload.get('ttl_seconds', 86400))
    if not recipients:
        raise HTTPException(status_code=400, detail='recipients_required')
    _enforce_tenant_quota(tenant, 'email_delivery')
    start_t = time.time()
    request_id = payload.get("request_id") or request.headers.get("x-request-id") or str(uuid.uuid4())
    contract = _load_contract("email_delivery_logs")
    contract_id = contract.get("contract_id") if contract else None
    custody = await _record_custody(tenant, "email_delivery_logs", payload, request_id, contract_id)
    now = int(time.time())
    start_ts, _ = _time_window(payload)
    events = await _fetch_delivery_events(tenant, recipients, start_ts)
    out = {
        'tenant_id': tenant,
        'source': 'email_delivery_logs',
        'fetched_at': now,
        'ttl_seconds': ttl,
        'events': events,
        'request_id': request_id,
        'contract_id': contract_id,
        'contract': contract,
        'custody': custody,
    }
    try:
        metrics.ensure_metrics()
        try:
            metrics.asks_sent_total.labels(endpoint='email_delivery', status='ok').inc(1)
        except Exception:
            try:
                metrics.asks_sent_total.labels('email_delivery','ok').inc(1)
            except Exception:
                pass
        try:
            metrics.asks_dispatch_latency_seconds.labels(endpoint='email_delivery').observe(max(0.0, time.time() - start_t))
        except Exception:
            pass
    except Exception:
        pass
    return out


@router.post('/api/v1/email/click/pull')
async def email_click_pull(payload: dict, request: Request, _auth = require_api_key, rl = alerts_auth):
    ensure_metrics()
    tenant = _require_tenant(request)
    users = payload.get('users') or payload.get('recipients') or []
    ttl = int(payload.get('ttl_seconds', 86400))
    if not users:
        raise HTTPException(status_code=400, detail='users_required')
    _enforce_tenant_quota(tenant, 'email_click')
    start_t = time.time()
    request_id = payload.get("request_id") or request.headers.get("x-request-id") or str(uuid.uuid4())
    contract = _load_contract("email_click_logs")
    contract_id = contract.get("contract_id") if contract else None
    custody = await _record_custody(tenant, "email_click_logs", payload, request_id, contract_id)
    now = int(time.time())
    start_ts, end_ts = _time_window(payload)
    events = await _fetch_click_events(users, start_ts, end_ts)
    out = {
        'tenant_id': tenant,
        'source': 'email_click_logs',
        'fetched_at': now,
        'ttl_seconds': ttl,
        'events': events,
        'request_id': request_id,
        'contract_id': contract_id,
        'contract': contract,
        'custody': custody,
    }
    try:
        metrics.ensure_metrics()
        try:
            metrics.asks_sent_total.labels(endpoint='email_click', status='ok').inc(1)
        except Exception:
            try:
                metrics.asks_sent_total.labels('email_click','ok').inc(1)
            except Exception:
                pass
        try:
            metrics.asks_dispatch_latency_seconds.labels(endpoint='email_click').observe(max(0.0, time.time() - start_t))
        except Exception:
            pass
    except Exception:
        pass
    return out


@router.post('/api/v1/email/quarantine/pull')
async def email_quarantine_pull(payload: dict, request: Request, _auth = require_api_key, rl = alerts_auth):
    ensure_metrics()
    tenant = _require_tenant(request)
    recipients = payload.get('recipients') or payload.get('users') or []
    ttl = int(payload.get('ttl_seconds', 86400))
    if not recipients:
        raise HTTPException(status_code=400, detail='recipients_required')
    _enforce_tenant_quota(tenant, 'email_quarantine')
    start_t = time.time()
    request_id = payload.get("request_id") or request.headers.get("x-request-id") or str(uuid.uuid4())
    contract = _load_contract("email_quarantine_logs")
    contract_id = contract.get("contract_id") if contract else None
    custody = await _record_custody(tenant, "email_quarantine_logs", payload, request_id, contract_id)
    now = int(time.time())
    start_ts, _ = _time_window(payload)
    since_dt = datetime.utcfromtimestamp(start_ts)
    events = await _fetch_quarantine_events(tenant, since_dt, recipients)
    out = {
        'tenant_id': tenant,
        'source': 'email_quarantine_logs',
        'fetched_at': now,
        'ttl_seconds': ttl,
        'events': events,
        'request_id': request_id,
        'contract_id': contract_id,
        'contract': contract,
        'custody': custody,
    }
    try:
        metrics.ensure_metrics()
        try:
            metrics.asks_sent_total.labels(endpoint='email_quarantine', status='ok').inc(1)
        except Exception:
            try:
                metrics.asks_sent_total.labels('email_quarantine','ok').inc(1)
            except Exception:
                pass
        try:
            metrics.asks_dispatch_latency_seconds.labels(endpoint='email_quarantine').observe(max(0.0, time.time() - start_t))
        except Exception:
            pass
    except Exception:
        pass
    return out


@router.post('/api/v1/cloudtrail/admin/pull')
async def cloudtrail_admin_pull(payload: dict, request: Request, auth=Depends(require_roles('admin')), _auth = require_api_key, rl = alerts_auth):
    ensure_metrics()
    tenant = _require_tenant(request)
    start = payload.get('start')
    end = payload.get('end')
    ttl = int(payload.get('ttl_seconds', 7200))
    _enforce_tenant_quota(tenant, 'cloudtrail_admin')
    start_t = time.time()
    request_id = payload.get("request_id") or request.headers.get("x-request-id") or str(uuid.uuid4())
    contract = _load_contract("cloudtrail_admin_events")
    contract_id = contract.get("contract_id") if contract else None
    custody = await _record_custody(tenant, "cloudtrail_admin_events", payload, request_id, contract_id)
    now = int(time.time())
    events = [
        {'event_name': 'CreateUser', 'user': 'admin', 'source_ip': '203.0.113.5', 'resource': 'iam:user/admin', 'ts': now - 300}
    ]
    out = {
        'tenant_id': tenant,
        'source': 'cloudtrail_admin_events',
        'fetched_at': now,
        'ttl_seconds': ttl,
        'events': events,
        'request_id': request_id,
        'contract_id': contract_id,
        'contract': contract,
        'custody': custody,
    }
    try:
        metrics.ensure_metrics()
        try:
            metrics.asks_sent_total.labels(endpoint='cloudtrail_admin', status='ok').inc(1)
        except Exception:
            try:
                metrics.asks_sent_total.labels('cloudtrail_admin','ok').inc(1)
            except Exception:
                pass
        try:
            metrics.asks_dispatch_latency_seconds.labels(endpoint='cloudtrail_admin').observe(max(0.0, time.time() - start_t))
        except Exception:
            pass
    except Exception:
        pass
    return out
