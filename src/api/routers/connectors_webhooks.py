"""Inbound connector webhooks (CrowdStrike / Microsoft Sentinel / Splunk HEC).

Each endpoint verifies an HMAC signature + replay window, then routes the
verified body into the streaming ingest pipeline. Previously these handlers
verified the signature, incremented events_ingested_total, and returned OK
WITHOUT parsing or storing the body — so the "events ingested" metric was a
lie and no webhook event was ever ingested. They now parse the payload and
push it through StreamingAssessmentSession.ingest (normalisation, dedup, and
circuit-breaking included), and the counter reflects the real accepted count.
"""
import json
import logging

from fastapi import APIRouter, Request, Response

from src.api.webhook_verification import verify_hmac_signature, within_replay_window
from src.core.security.secret_provider import SecretProvider
from src.core.metrics.connectors_metrics import events_ingested_total, ingest_errors_total

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks")

sp = SecretProvider()

# Envelope keys under which vendors nest their event array.
_ENVELOPE_KEYS = ("events", "resources", "data", "records", "value", "result", "alerts")


def _parse_webhook_rows(body: bytes) -> list[dict]:
    """Best-effort parse of a webhook body into a list of event dicts.

    Handles a single JSON object, a JSON array, a common envelope
    ({events|resources|data|records|value|result|alerts: [...]}), and
    newline-delimited JSON (Splunk HEC style)."""
    text = (body or b"").decode("utf-8", "replace").strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return [r for r in obj if isinstance(r, dict)]
        if isinstance(obj, dict):
            for key in _ENVELOPE_KEYS:
                v = obj.get(key)
                if isinstance(v, list):
                    return [r for r in v if isinstance(r, dict)]
            return [obj]
    except Exception:
        # Fall through to NDJSON parsing (one JSON object per line).
        pass
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
            if isinstance(o, dict):
                rows.append(o)
        except Exception:
            continue
    return rows


async def _ingest_webhook(source: str, body: bytes) -> int:
    """Route a verified webhook body into the streaming ingest pipeline.

    Returns the number of accepted (post-dedup) events. Never raises — an
    ingest failure is recorded on ingest_errors_total and reported as 0."""
    rows = _parse_webhook_rows(body)
    if not rows:
        return 0
    try:
        try:
            from src.pipeline.streaming_ingest import get_or_create_session
        except Exception:  # pragma: no cover - dual-import fallback
            from pipeline.streaming_ingest import get_or_create_session  # type: ignore
        session = get_or_create_session(f"webhook-{source}", org="default")
        result = await session.ingest(rows, source=source)
        return int(result.get("accepted", 0))
    except Exception as exc:
        logger.exception("webhook ingest failed for %s: %s", source, exc)
        ingest_errors_total.labels(source, "ingest").inc()
        return 0


async def _handle(request: Request, *, source: str, sig_header: str, ts_header: str, secret_name: str):
    body = await request.body()
    sig = request.headers.get(sig_header, "")
    ts = int(request.headers.get(ts_header, "0") or 0)
    secret = sp.get(secret_name, "")
    if not (secret and sig and within_replay_window(ts) and verify_hmac_signature(body, sig, secret)):
        ingest_errors_total.labels(source, "signature").inc()
        return Response(status_code=401)
    accepted = await _ingest_webhook(source, body)
    if accepted:
        events_ingested_total.labels(source).inc(accepted)
    return {"status": "ok", "accepted": accepted}


@router.post("/crowdstrike")
async def crowdstrike_webhook(request: Request):
    return await _handle(
        request, source="crowdstrike",
        sig_header="x-signature", ts_header="x-timestamp",
        secret_name="CROWDSTRIKE_WEBHOOK_SECRET",
    )


@router.post("/sentinel")
async def sentinel_webhook(request: Request):
    return await _handle(
        request, source="sentinel",
        sig_header="x-ms-signature", ts_header="x-ms-timestamp",
        secret_name="SENTINEL_WEBHOOK_SECRET",
    )


@router.post("/splunk")
async def splunk_webhook(request: Request):
    return await _handle(
        request, source="splunk",
        sig_header="x-hec-signature", ts_header="x-hec-timestamp",
        secret_name="SPLUNK_HEC_SHARED_SECRET",
    )
