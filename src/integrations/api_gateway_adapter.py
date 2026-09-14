from __future__ import annotations

import json
import time
from typing import Any, Dict, Iterable, List, Optional


def normalize_gateway_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize API gateway access log record into API security event shape."""
    identity = raw.get("identity") or {}
    request_ctx = raw.get("requestContext") or {}
    headers = raw.get("headers") or {}
    path = raw.get("path") or raw.get("resourcePath") or request_ctx.get("path") or ""
    method = raw.get("httpMethod") or request_ctx.get("httpMethod") or headers.get("X-HTTP-Method-Override")
    status = raw.get("status") or raw.get("statusCode") or request_ctx.get("status")
    user = (
        raw.get("user")
        or identity.get("user")
        or identity.get("caller")
        or request_ctx.get("authorizer", {}).get("principalId")
        or request_ctx.get("identity", {}).get("user")
    )
    source_ip = (
        raw.get("sourceIp")
        or identity.get("sourceIp")
        or request_ctx.get("identity", {}).get("sourceIp")
        or headers.get("X-Forwarded-For", "").split(",")[0].strip()
    )
    latency = raw.get("integrationLatency") or raw.get("latency") or request_ctx.get("latency")
    response_len = raw.get("responseLength") or raw.get("response_length")
    request_id = raw.get("requestId") or request_ctx.get("requestId") or raw.get("request_id")
    ts = raw.get("requestTimeEpoch") or raw.get("timestamp") or time.time()
    if isinstance(ts, str):
        try:
            ts = float(ts)
        except Exception:
            ts = time.time()
    if ts and ts > 1e12:
        ts = ts / 1000.0
    event = {
        "event_type": "api_request",
        "uri": path,
        "method": method,
        "status": status,
        "auth_user": user,
        "ip": source_ip,
        "request_id": request_id,
        "response_size_bytes": response_len,
        "latency_ms": latency,
        "headers": headers,
        "api_gateway": raw.get("api_gateway") or raw.get("gateway") or "gateway",
        "ts": ts,
    }
    return event


def normalize_gateway_batch(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        out.append(normalize_gateway_record(rec))
    return out


def load_gateway_logs(path: str) -> List[Dict[str, Any]]:
    """Load gateway logs from JSON or JSONL."""
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read().strip()
    if not raw:
        return []
    if raw.startswith("["):
        try:
            payload = json.loads(raw)
            return payload if isinstance(payload, list) else []
        except Exception:
            return []
    events: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                events.append(obj)
        except Exception:
            continue
    return events


__all__ = ["normalize_gateway_record", "normalize_gateway_batch", "load_gateway_logs"]
