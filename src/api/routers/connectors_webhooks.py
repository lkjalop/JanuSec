from fastapi import APIRouter, Request, Response
from src.api.webhook_verification import verify_hmac_signature, within_replay_window
from src.core.security.secret_provider import SecretProvider
from src.core.metrics.connectors_metrics import events_ingested_total, ingest_errors_total

router = APIRouter(prefix="/api/v1/webhooks")

sp = SecretProvider()

@router.post("/crowdstrike")
async def crowdstrike_webhook(request: Request):
    body = await request.body()
    sig = request.headers.get("x-signature", "")
    ts = int(request.headers.get("x-timestamp", "0") or 0)
    secret = sp.get("CROWDSTRIKE_WEBHOOK_SECRET", "")
    if not (secret and sig and within_replay_window(ts) and verify_hmac_signature(body, sig, secret)):
        ingest_errors_total.labels("crowdstrike", "signature").inc()
        return Response(status_code=401)
    events_ingested_total.labels("crowdstrike").inc()
    return {"status": "ok"}

@router.post("/sentinel")
async def sentinel_webhook(request: Request):
    body = await request.body()
    sig = request.headers.get("x-ms-signature", "")
    ts = int(request.headers.get("x-ms-timestamp", "0") or 0)
    secret = sp.get("SENTINEL_WEBHOOK_SECRET", "")
    if not (secret and sig and within_replay_window(ts) and verify_hmac_signature(body, sig, secret)):
        ingest_errors_total.labels("sentinel", "signature").inc()
        return Response(status_code=401)
    events_ingested_total.labels("sentinel").inc()
    return {"status": "ok"}

@router.post("/splunk")
async def splunk_webhook(request: Request):
    body = await request.body()
    sig = request.headers.get("x-hec-signature", "")
    ts = int(request.headers.get("x-hec-timestamp", "0") or 0)
    secret = sp.get("SPLUNK_HEC_SHARED_SECRET", "")
    if not (secret and sig and within_replay_window(ts) and verify_hmac_signature(body, sig, secret)):
        ingest_errors_total.labels("splunk", "signature").inc()
        return Response(status_code=401)
    events_ingested_total.labels("splunk").inc()
    return {"status": "ok"}
