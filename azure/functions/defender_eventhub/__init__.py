# Azure Function: Event Hub trigger for Defender/Policy events
# Normalizes events and POSTs to the platform compliance posture API

import os
import json
import time
import uuid
import hmac
import hashlib
import logging
import random
import requests

try:
    import azure.functions as func  # type: ignore
except Exception:
    # Allow local import/test without azure-functions dependency
    func = None  # type: ignore

from .mapper import build_posture_payload

API_BASE = os.getenv('PLATFORM_API_BASE', 'http://localhost:8080')
API_KEY = os.getenv('PLATFORM_API_KEY', os.getenv('AZURE_DEF_SCHED_API_KEY', 'devkey123'))
TENANT_ID = os.getenv('TENANT_ID')
TIMEOUT = float(os.getenv('PLATFORM_POST_TIMEOUT', '10'))
DEV_ALLOW_HTTP = os.getenv('DEV_ALLOW_HTTP', '0') in {'1', 'true', 'yes', 'on'}
BATCH_MAX = int(os.getenv('BATCH_MAX', '1000') or 1000)
MAX_RETRIES = int(os.getenv('POST_MAX_RETRIES', '5') or 5)
BASE_BACKOFF = float(os.getenv('POST_BACKOFF_BASE', '0.6') or 0.6)

logger = logging.getLogger(__name__)

def _kv_resolve_api_key() -> str | None:
    """Optionally resolve API key from Key Vault using Managed Identity.
    Requires KEYVAULT_URI and SECRET_NAME env vars and azure-identity/keyvault libs.
    """
    kv_uri = os.getenv('KEYVAULT_URI')
    sec_name = os.getenv('SECRET_NAME') or os.getenv('PLATFORM_API_SECRET_NAME')
    if not (kv_uri and sec_name):
        return None
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.keyvault.secrets import SecretClient  # type: ignore
        cred = DefaultAzureCredential()
        client = SecretClient(vault_url=kv_uri, credential=cred)
        secret = client.get_secret(sec_name)
        return secret.value
    except Exception as e:
        logger.warning('Key Vault resolve failed: %s', e)
        return None


def _tls_guard() -> bool:
    if API_BASE.startswith('http://') and not DEV_ALLOW_HTTP:
        logger.error('Insecure API_BASE (%s). Set DEV_ALLOW_HTTP=1 for local dev.', API_BASE)
        return False
    return True


def _headers(base_headers: dict | None = None) -> dict:
    hdrs = {'Content-Type': 'application/json'}
    if API_KEY:
        hdrs['x-api-key'] = API_KEY
    if TENANT_ID:
        hdrs['X-Tenant-ID'] = TENANT_ID
    if base_headers:
        hdrs.update(base_headers)
    return hdrs


def _post_with_retry(url: str, payload: dict, headers: dict) -> None:
    last_err: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
            # Treat 429/5xx as retryable
            if r.status_code in {429, 500, 502, 503, 504}:
                raise RuntimeError(f'HTTP {r.status_code}')
            r.raise_for_status()
            return
        except Exception as e:
            last_err = e
            # Exponential backoff with jitter
            sleep_s = (BASE_BACKOFF * (2 ** (attempt - 1))) + random.uniform(0, 0.3)
            time.sleep(min(8.0, sleep_s))
    # After retries, raise
    if last_err:
        raise last_err


def _chunk_findings(findings: list[dict]) -> list[list[dict]]:
    if not findings:
        return []
    n = max(1, BATCH_MAX)
    return [findings[i:i+n] for i in range(0, len(findings), n)]


def _idem_key_for_chunk(tenant: str | None, chunk: list[dict]) -> str:
    # Stable HMAC of a bounded, sorted snapshot of the chunk to avoid huge strings
    try:
        fingerprint = json.dumps([{k: v for k, v in sorted(e.items()) if k in {'id','resource','type','source_ts'}} for e in chunk], separators=(',', ':'), ensure_ascii=False)
    except Exception:
        fingerprint = f"{len(chunk)}:{time.time():.0f}"
    key_material = (tenant or '') + '|' + fingerprint[:2000]
    h = hmac.new(b'az_func_idem', key_material.encode('utf-8'), hashlib.sha256).hexdigest()
    return h


def _dlq_write(items: list) -> None:
    path = os.getenv('DLQ_PATH', os.path.join(os.getcwd(), 'artifacts', 'dlq', 'azure_defender.jsonl'))
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'a', encoding='utf-8') as fh:
            for it in items:
                fh.write(json.dumps(it) + '\n')
    except Exception as e:
        logger.warning('DLQ write failed: %s', e)


# Function entry point
# Event Hub trigger batch: list of bytes payloads
if func:
    def main(events: func.EventHubEvent):  # type: ignore
        batch = []
        try:
            for event in events:
                body = event.get_body()
                try:
                    if isinstance(body, bytes):
                        body = body.decode('utf-8')
                    obj = json.loads(body) if isinstance(body, str) else body
                except Exception:
                    obj = {}
                if isinstance(obj, dict):
                    batch.append(obj)
        except Exception:
            # single event fallback
            try:
                body = events.get_body()
                if isinstance(body, bytes):
                    body = body.decode('utf-8')
                obj = json.loads(body) if isinstance(body, str) else body
                if isinstance(obj, dict):
                    batch.append(obj)
            except Exception:
                pass
        if not batch:
            return
        # TLS guard
        if not _tls_guard():
            _dlq_write(batch)
            return
        # Optionally resolve API key from Key Vault once per invocation
        global API_KEY
        if not API_KEY:
            API_KEY = _kv_resolve_api_key() or API_KEY
        # Build findings and split into chunks
        payload_full = build_posture_payload(batch)
        findings = payload_full.get('findings') or []
        chunks = _chunk_findings(findings)
        request_id = os.getenv('REQUEST_ID') or str(uuid.uuid4())
        url = f"{API_BASE.rstrip('/')}/api/v1/compliance/posture"
        failures: list[dict] = []
        for ch in chunks:
            payload = {'findings': ch}
            idem = _idem_key_for_chunk(TENANT_ID, ch)
            hdrs = _headers({'X-Request-ID': request_id, 'X-Idempotency-Key': idem})
            try:
                _post_with_retry(url, payload, hdrs)
            except Exception as e:
                logger.warning('POST chunk failed (size=%d): %s', len(ch), e)
                failures.extend(ch)
        if failures:
            _dlq_write(failures)
