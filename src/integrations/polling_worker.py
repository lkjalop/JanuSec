"""Polling worker for mailbox ingestion (Option A implementation).

Features:
- Load per-tenant tokens from `tenant_store.TenantStore`
- Refresh tokens when expired via connector.refresh_token()
- Poll MS Graph delta or Gmail list/get and parse messages
- Write canonical events to CSV or POST to a pipeline input endpoint
- Simple retry/backoff on HTTP failures and 429 handling

This is a development-friendly implementation intended as a quick win.
Replace file-based token store with a secrets manager in production.
"""
from __future__ import annotations

import csv
import logging
import os
import time
from datetime import datetime
from typing import Dict, Optional

from core.rate_limit import RateLimiter
from integrations.gmail_connector import GmailConnector
from integrations.msgraph_connector import MSGraphConnector
from integrations.polling_state import PollingStateStore
from integrations.tenant_store import TenantStore
import requests
from requests import HTTPError
from integrations._backoff import retry_with_backoff
try:
    from prometheus_client import Counter, Gauge
    METRICS_AVAILABLE = True
except Exception:
    METRICS_AVAILABLE = False

if METRICS_AVAILABLE:
    try:
        CIRCUIT_OPENS = Counter('connector_circuit_opens_total', 'Total connector circuit opens', ['tenant', 'provider'])
        CIRCUIT_OPEN = Gauge('connector_circuit_open', 'Circuit open state (1=open,0=closed)', ['tenant', 'provider'])
        TENANT_THROTTLED = Counter('connector_tenant_throttled_total', 'Times tenant was throttled', ['tenant', 'provider'])
    except ValueError:
        # Metrics already registered (likely during repeated imports in tests).
        # Fall back to no-op to avoid failing test runs.
        CIRCUIT_OPENS = TENANT_THROTTLED = CIRCUIT_OPEN = None
else:
    CIRCUIT_OPENS = TENANT_THROTTLED = CIRCUIT_OPEN = None

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


_GLOBAL_RATE_LIMITER: Optional[RateLimiter] = None


def get_global_rate_limiter() -> RateLimiter:
    global _GLOBAL_RATE_LIMITER
    if _GLOBAL_RATE_LIMITER is None:
        cap = int(os.environ.get("POLLING_GLOBAL_RATE_CAPACITY", "100"))
        refill = float(os.environ.get("POLLING_GLOBAL_RATE_REFILL", "10"))
        ttl = int(os.environ.get("POLLING_GLOBAL_RATE_TTL", "60"))
        _GLOBAL_RATE_LIMITER = RateLimiter(capacity=cap, refill_rate_per_sec=refill, ttl_seconds=ttl)
    return _GLOBAL_RATE_LIMITER


class CircuitOpenError(RuntimeError):
    pass


class MailPollingWorker:
    def __init__(self, tenant_id: str, provider: str, pipeline_endpoint: Optional[str] = None):
        self.tenant_id = tenant_id
        self.provider = provider.lower()
        self.store = TenantStore()
        self.state_store = PollingStateStore()
        self.pipeline_endpoint = pipeline_endpoint or os.environ.get("PIPELINE_ENDPOINT")
        self.max_attempts = int(os.environ.get("POLLING_MAX_ATTEMPTS", "5"))
        self.backoff_base = float(os.environ.get("POLLING_BACKOFF_BASE", "1.0"))
        self.rate_limiter = self._init_rate_limiter()
        self.app_rate_limiter = get_global_rate_limiter()

        # Circuit breaker state (simple): failures in window -> open
        self._fail_count = 0
        self._fail_window_ts = 0.0
        self._circuit_open_until = 0.0
        self.circuit_fail_threshold = int(os.environ.get("POLLING_CIRCUIT_FAIL_THRESHOLD", "5"))
        self.circuit_window_seconds = int(os.environ.get("POLLING_CIRCUIT_WINDOW_SECONDS", "60"))
        self.circuit_open_seconds = int(os.environ.get("POLLING_CIRCUIT_OPEN_SECONDS", "120"))

        # Connectors expect client credentials in token payload stored for now
        tokens = self.store.load_tokens(self.tenant_id) or {}
        client_id = tokens.get("client_id") or os.environ.get(f"{self.provider.upper()}_CLIENT_ID")
        client_secret = tokens.get("client_secret") or os.environ.get(f"{self.provider.upper()}_CLIENT_SECRET")
        redirect = tokens.get("redirect_uri") or os.environ.get(f"{self.provider.upper()}_REDIRECT")

        if self.provider == "msgraph":
            self.conn = MSGraphConnector(client_id, client_secret, redirect)
        elif self.provider == "gmail":
            self.conn = GmailConnector(client_id, client_secret, redirect)
        else:
            raise ValueError("Unsupported provider: msgraph|gmail")

    def _init_rate_limiter(self) -> Optional[RateLimiter]:
        cap = int(os.environ.get("POLLING_TENANT_RATE_CAPACITY", "5"))
        refill = float(os.environ.get("POLLING_TENANT_RATE_REFILL", "1.0"))
        ttl = int(os.environ.get("POLLING_TENANT_RATE_TTL", "60"))
        if cap <= 0 or refill <= 0:
            return None
        try:
            return RateLimiter(capacity=cap, refill_rate_per_sec=refill, ttl_seconds=ttl)
        except Exception:
            logger.exception("Unable to initialize polling rate limiter; continuing without throttling.")
            return None

    def _save_tokens(self, token_payload: Dict) -> None:
        # Ensure client_id/secret persist alongside tokens for the demo
        stored = token_payload.copy()
        if not stored.get("client_id"):
            stored["client_id"] = getattr(self.conn, "client_id", None)
        if not stored.get("client_secret"):
            stored["client_secret"] = getattr(self.conn, "client_secret", None)
        if not stored.get("redirect_uri"):
            stored["redirect_uri"] = getattr(self.conn, "redirect_uri", None)
        self.store.save_tokens(self.tenant_id, stored)

    def _ensure_valid_token(self, tokens: Dict) -> Dict:
        # Tokens expected shape from OAuth: access_token, refresh_token, expires_at (epoch)
        now = int(time.time())
        if not tokens:
            raise RuntimeError("No tokens for tenant; perform OAuth flow first")
        expires_at = tokens.get("expires_at")
        if expires_at and now > (expires_at - 60):
            # Refresh
            logger.info("Refreshing access token for tenant %s", self.tenant_id)
            refreshed = self.conn.refresh_token(tokens.get("refresh_token"))
            # compute expires_at if expires_in present
            if refreshed.get("expires_in"):
                refreshed["expires_at"] = int(time.time()) + int(refreshed.get("expires_in"))
            # preserve refresh token if provider didn't return a new one
            if not refreshed.get("refresh_token"):
                refreshed["refresh_token"] = tokens.get("refresh_token")
            self._save_tokens(refreshed)
            return refreshed
        return tokens

    def _acquire_rate_limit(self) -> bool:
        if not self.rate_limiter:
            return True
        # Tenant-level
        bucket = self.rate_limiter.registry.get(self.tenant_id, self.provider, self.rate_limiter.capacity, self.rate_limiter.refill)
        if not bucket.try_consume(1.0):
            logger.info("Tenant %s (%s) is throttled by polling rate limiter; skipping cycle.", self.tenant_id, self.provider)
            return False
        # App-level
        global_bucket = self.app_rate_limiter.registry.get(self.tenant_id, self.provider, self.app_rate_limiter.capacity, self.app_rate_limiter.refill)
        if not global_bucket.try_consume(1.0):
            logger.info("Tenant %s (%s) is throttled by global rate limiter; skipping cycle.", self.tenant_id, self.provider)
            return False
        return True

    def _handle_token_revocation(self) -> None:
        logger.error("Token revoked or expired for tenant %s (%s); clearing persisted tokens.", self.tenant_id, self.provider)
        self.store.delete_tokens(self.tenant_id)
        self.state_store.clear(self.tenant_id, self.provider)
        # Notify a status endpoint if configured so UI can react
        try:
            status_endpoint = os.environ.get("CONNECTOR_STATUS_ENDPOINT") or self.pipeline_endpoint
            if status_endpoint:
                payload = self._token_status_payload(status="revoked")
                try:
                    requests.post(status_endpoint, json=payload, timeout=3)
                except Exception:
                    logger.debug("Unable to post token status notification")
        except Exception:
            logger.exception("Error sending token revocation notification")
        raise RuntimeError(f"Tenant {self.tenant_id} must re-authorize {self.provider} connector")

    def _execute_with_backoff(self, func, *args, token_sensitive: bool = True, **kwargs):
        def _call():
            try:
                return func(*args, **kwargs)
            except HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                # Immediate handling for auth issues
                if status == 401 and token_sensitive:
                    self._handle_token_revocation()
                # Extract Retry-After if provided to let retry_with_backoff honor it via exception attrs
                ra = None
                try:
                    if exc.response is not None:
                        ra = exc.response.headers.get("Retry-After")
                except Exception:
                    ra = None
                if ra is not None:
                    # attach for retry helper
                    setattr(exc, "retry_after", ra)
                raise

        # Simple circuit-breaker check
        now = time.time()
        if now < getattr(self, "_circuit_open_until", 0):
            raise CircuitOpenError("Circuit open for tenant %s" % self.tenant_id)

        try:
            result = retry_with_backoff(lambda: _call(), attempts=self.max_attempts, base_sleep=self.backoff_base, jitter=self.backoff_base * 0.1)
            # on success, reset failure counters
            self._fail_count = 0
            self._fail_window_ts = 0.0
            # mark circuit closed in metrics
            try:
                if METRICS_AVAILABLE:
                    CIRCUIT_OPEN.labels(self.tenant_id, self.provider).set(0)
            except Exception:
                pass
            return result
        except Exception as e:
            # update circuit counters
            ts = time.time()
            if ts - self._fail_window_ts > self.circuit_window_seconds:
                self._fail_count = 1
                self._fail_window_ts = ts
            else:
                self._fail_count += 1
            if self._fail_count >= self.circuit_fail_threshold:
                self._circuit_open_until = ts + self.circuit_open_seconds
                logger.warning("Opening circuit for tenant %s until %s", self.tenant_id, self._circuit_open_until)
                try:
                    if METRICS_AVAILABLE:
                        CIRCUIT_OPENS.labels(self.tenant_id, self.provider).inc()
                        CIRCUIT_OPEN.labels(self.tenant_id, self.provider).set(1)
                except Exception:
                    pass
            raise

    def poll_once(self) -> int:
        if not self._acquire_rate_limit():
            return 0
        tokens = self.store.load_tokens(self.tenant_id)
        if tokens is None:
            raise RuntimeError("No tokens persisted for tenant; run OAuth flow first")
        tokens = self._ensure_valid_token(tokens)
        access_token = tokens.get("access_token")

        state = self.state_store.load_state(self.tenant_id, self.provider)
        if self.provider == "msgraph":
            events, state = self._collect_msgraph_events(access_token, state)
        else:
            events, state = self._collect_gmail_events(access_token, state)
        state = state or {}
        state["last_polled"] = int(time.time())
        self.state_store.save_state(self.tenant_id, self.provider, state)

        count = self._emit_events(events)
        logger.info("Polled %d events for tenant %s (%s)", count, self.tenant_id, self.provider)
        return count

    def _collect_msgraph_events(self, access_token: str, state: Dict) -> (list, Dict):
        state = dict(state or {})
        delta_link = state.get("delta_link")
        payload = self._execute_with_backoff(self.conn.poll_delta, access_token, delta_link=delta_link)
        events = self.conn.parse_messages_to_events(payload)
        new_delta = payload.get("@odata.deltaLink") or payload.get("@odata.nextLink")
        if new_delta:
            state["delta_link"] = new_delta
        return events, state

    def _collect_gmail_events(self, access_token: str, state: Dict) -> (list, Dict):
        state = dict(state or {})
        history_id = state.get("history_id")
        events = []
        if history_id:
            history_payload = self._execute_with_backoff(self.conn.list_history, access_token, history_id)
            events.extend(self._events_from_history(history_payload, access_token))
            new_history = history_payload.get("historyId")
            if not new_history:
                history = history_payload.get("history") or []
                if history:
                    new_history = history[-1].get("id")
            if new_history:
                state["history_id"] = new_history
        else:
            listing = self._execute_with_backoff(self.conn.list_messages, access_token, max_results=50)
            for m in listing.get("messages", []):
                mid = m.get("id")
                if not mid:
                    continue
                raw = self._execute_with_backoff(self.conn.get_message, access_token, mid)
                parsed = self.conn.parse_raw_message(raw)
                events.append(
                    {
                        "id": mid,
                        "headers": parsed.get("headers"),
                        "parts": parsed.get("parts"),
                    }
                )
                if raw.get("historyId"):
                    state["history_id"] = raw["historyId"]
        return events, state

    def _events_from_history(self, history_payload: Dict, access_token: str) -> list:
        events = []
        for entry in history_payload.get("history", []) or []:
            for added in entry.get("messagesAdded", []) or []:
                mid = (added.get("message") or {}).get("id")
                if not mid:
                    continue
                raw = self._execute_with_backoff(self.conn.get_message, access_token, mid)
                parsed = self.conn.parse_raw_message(raw)
                events.append(
                    {
                        "id": mid,
                        "headers": parsed.get("headers"),
                        "parts": parsed.get("parts"),
                    }
                )
        return events

    def _emit_events(self, events) -> int:
        count = 0
        if not events:
            return 0
        if self.pipeline_endpoint:
            for ev in events:
                try:
                    self._execute_with_backoff(self._post_event, ev, token_sensitive=False)
                    count += 1
                except HTTPError:
                    logger.exception("Pipeline rejected event for tenant %s", self.tenant_id)
                except RuntimeError:
                    raise
                except Exception:
                    logger.exception("Failed posting event to pipeline")
        else:
            outdir = os.path.join(os.path.dirname(__file__), "..", "data", "polled_events")
            os.makedirs(outdir, exist_ok=True)
            outpath = os.path.join(outdir, f"{self.tenant_id}_{self.provider}.csv")
            with open(outpath, "a", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                for ev in events:
                    writer.writerow([self.tenant_id, self.provider, datetime.utcnow().isoformat(), str(ev)])
                    count += 1
        return count

    def _post_event(self, event: Dict) -> bool:
        r = requests.post(self.pipeline_endpoint, json=event, timeout=10)
        if r.status_code in (200, 201, 202):
            return True
        if r.status_code == 429:
            delay = float(r.headers.get("Retry-After", 2))
            logger.warning("Pipeline rate limited (Retry-After=%s). Sleeping before retry.", delay)
            time.sleep(delay)
        err = HTTPError(f"pipeline responded with {r.status_code}", response=r)
        raise err


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("tenant_id")
    parser.add_argument("provider", choices=["msgraph", "gmail"])
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()

    worker = MailPollingWorker(args.tenant_id, args.provider)
    try:
        if args.loop:
            while True:
                try:
                    worker.poll_once()
                except Exception:
                    logger.exception("Polling error")
                time.sleep(args.interval)
        else:
            worker.poll_once()
    except KeyboardInterrupt:
        logger.info("Shutting down")


if __name__ == "__main__":
    main()
