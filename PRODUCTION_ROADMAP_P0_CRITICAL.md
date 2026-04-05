# JanuSec Platform - P0 CRITICAL Production Roadmap
## Must-Have Features for Production Launch

**Priority Level:** P0 - CRITICAL
**Timeline:** 4-8 Weeks
**Business Impact:** HIGH - Required for market competitiveness and customer acquisition
**Dependencies:** LLM API keys, OAuth credentials, VirusTotal API

---

## EXECUTIVE SUMMARY

This roadmap covers the **4 critical features** that will transform JanuSec from a batch analysis tool to a **full-featured, real-time threat detection platform**:

1. **Email Live Ingestion** - Real-time phishing and BEC detection
2. **IAM Live Monitoring** - Identity threat detection and insider risk
3. **Enhanced LLM Summaries (Tier 1/2)** - AI-powered triage and narratives
4. **Production-Ready Binary Analysis** - Malware detection and sandbox integration

**Expected Outcome:** Platform ready for **enterprise SaaS deployment** with real-time multi-domain correlation and AI-powered analysis.

---

## P0-1: EMAIL LIVE INGESTION (OAuth Integration)

### Current State
- ✅ **Strong foundation:** BEC detection logic, phishing analysis, DKIM/DMARC checks implemented
- ✅ **Working features:** Email CSV upload and analysis functional
- ❌ **Missing:** OAuth adapters for Office 365, Gmail, live polling, token management

### Business Value
- **Critical for:** 85% of customers require email threat detection
- **Competitive gap:** Most competitors offer real-time email monitoring
- **Revenue impact:** Potential blocker for enterprise deals

### Technical Architecture

#### Components to Build

```
┌─────────────────────────────────────────────────────────────┐
│                    Email Ingestion Pipeline                  │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐      ┌──────────────┐     ┌─────────────┐│
│  │  OAuth       │      │   Token      │     │  Polling    ││
│  │  Providers   │─────▶│   Storage    │────▶│  Service    ││
│  │ (MS/Google)  │      │  (Vault)     │     │  (Delta)    ││
│  └──────────────┘      └──────────────┘     └─────────────┘│
│         │                                           │        │
│         │                                           ▼        │
│         │                              ┌──────────────────┐ │
│         │                              │  Email Parser    │ │
│         │                              │  & Enrichment    │ │
│         │                              └──────────────────┘ │
│         │                                           │        │
│         ▼                                           ▼        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │          Event Pipeline (Existing)                   │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌────────┐ │  │
│  │  │  BEC    │  │ Phish   │  │ DMARC   │  │HopGraph│ │  │
│  │  │Detector │  │Detector │  │Validator│  │  Link  │ │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └────────┘ │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Plan

#### Phase 1: OAuth Foundation (Week 1-2)

**File: `src/integrations/auth/oauth_providers.py`** (NEW)

```python
"""
OAuth 2.0 provider implementations for Email and IAM integrations.
Supports MSAL (Microsoft), Google OAuth, and generic OAuth2 flows.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional, Any
import httpx
import asyncio
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class OAuthProvider(ABC):
    """Base class for OAuth providers."""

    def __init__(self, client_id: str, client_secret: str, tenant_id: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self._token_cache: Optional[Dict[str, Any]] = None
        self._token_expiry: Optional[datetime] = None

    @abstractmethod
    async def get_access_token(self) -> str:
        """Get valid access token, refreshing if necessary."""
        pass

    @abstractmethod
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh an expired access token."""
        pass

    async def _is_token_valid(self) -> bool:
        """Check if cached token is still valid."""
        if not self._token_cache or not self._token_expiry:
            return False
        # Refresh 5 minutes before expiry
        return datetime.utcnow() < (self._token_expiry - timedelta(minutes=5))


class MSALProvider(OAuthProvider):
    """Microsoft Authentication Library provider for Office 365."""

    AUTHORITY_URL = "https://login.microsoftonline.com/{tenant_id}"
    GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]

    async def get_access_token(self) -> str:
        """Get access token using client credentials flow."""
        if await self._is_token_valid():
            return self._token_cache["access_token"]

        token_url = f"{self.AUTHORITY_URL.format(tenant_id=self.tenant_id)}/oauth2/v2.0/token"

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": " ".join(self.GRAPH_SCOPE),
            "grant_type": "client_credentials"
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(token_url, data=data, timeout=30.0)
                response.raise_for_status()
                token_data = response.json()

                self._token_cache = token_data
                self._token_expiry = datetime.utcnow() + timedelta(seconds=token_data.get("expires_in", 3600))

                logger.info(f"MSAL token acquired for tenant {self.tenant_id}, expires in {token_data.get('expires_in')}s")
                return token_data["access_token"]

            except httpx.HTTPStatusError as e:
                logger.error(f"MSAL auth failed: {e.response.status_code} - {e.response.text}")
                raise
            except Exception as e:
                logger.error(f"MSAL token acquisition failed: {e}")
                raise

    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh token (client credentials flow auto-renews)."""
        # Client credentials flow doesn't use refresh tokens
        return await self.get_access_token()


class GoogleOAuthProvider(OAuthProvider):
    """Google OAuth2 provider for Gmail and Workspace."""

    TOKEN_URL = "https://oauth2.googleapis.com/token"
    SCOPES = [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.metadata"
    ]

    async def get_access_token(self) -> str:
        """Get access token using service account or OAuth flow."""
        if await self._is_token_valid():
            return self._token_cache["access_token"]

        # For service accounts, use JWT assertion
        # For user OAuth, use refresh token flow
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self._get_stored_refresh_token()
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(self.TOKEN_URL, data=data, timeout=30.0)
                response.raise_for_status()
                token_data = response.json()

                self._token_cache = token_data
                self._token_expiry = datetime.utcnow() + timedelta(seconds=token_data.get("expires_in", 3600))

                logger.info(f"Google OAuth token acquired, expires in {token_data.get('expires_in')}s")
                return token_data["access_token"]

            except httpx.HTTPStatusError as e:
                logger.error(f"Google OAuth failed: {e.response.status_code} - {e.response.text}")
                raise

    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh Google OAuth token."""
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(self.TOKEN_URL, data=data, timeout=30.0)
            response.raise_for_status()
            return response.json()

    def _get_stored_refresh_token(self) -> str:
        """Retrieve refresh token from secure storage."""
        # TODO: Integrate with Vault/secret store
        raise NotImplementedError("Refresh token storage not implemented")
```

**File: `src/integrations/auth/token_store.py`** (NEW)

```python
"""
Secure token storage using HashiCorp Vault or fallback to encrypted database.
Handles token persistence, rotation, and expiry tracking.
"""

import asyncio
import json
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import logging

from src.db.database import DatabaseManager

logger = logging.getLogger(__name__)


class TokenStore:
    """Manages secure storage and retrieval of OAuth tokens."""

    def __init__(self, db: DatabaseManager, encryption_key: Optional[bytes] = None):
        self.db = db
        self.cipher = Fernet(encryption_key or Fernet.generate_key())
        self._cache: Dict[str, Dict[str, Any]] = {}

    async def store_token(
        self,
        tenant_id: str,
        provider: str,
        token_data: Dict[str, Any],
        expiry: datetime
    ) -> None:
        """Store OAuth token securely."""
        encrypted_token = self.cipher.encrypt(json.dumps(token_data).encode())

        async with self.db.get_connection() as conn:
            await conn.execute("""
                INSERT INTO oauth_tokens (tenant_id, provider, encrypted_token, expiry, created_at)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (tenant_id, provider)
                DO UPDATE SET
                    encrypted_token = EXCLUDED.encrypted_token,
                    expiry = EXCLUDED.expiry,
                    updated_at = NOW()
            """, tenant_id, provider, encrypted_token, expiry, datetime.utcnow())

        # Update cache
        cache_key = f"{tenant_id}:{provider}"
        self._cache[cache_key] = {
            "token_data": token_data,
            "expiry": expiry
        }

        logger.info(f"Stored {provider} token for tenant {tenant_id}, expires {expiry}")

    async def get_token(self, tenant_id: str, provider: str) -> Optional[Dict[str, Any]]:
        """Retrieve OAuth token if valid."""
        cache_key = f"{tenant_id}:{provider}"

        # Check cache first
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if datetime.utcnow() < cached["expiry"]:
                return cached["token_data"]
            else:
                del self._cache[cache_key]

        # Fetch from database
        async with self.db.get_connection() as conn:
            row = await conn.fetchrow("""
                SELECT encrypted_token, expiry
                FROM oauth_tokens
                WHERE tenant_id = $1 AND provider = $2
                  AND expiry > NOW()
            """, tenant_id, provider)

            if not row:
                return None

            try:
                decrypted = self.cipher.decrypt(row["encrypted_token"])
                token_data = json.loads(decrypted.decode())

                # Update cache
                self._cache[cache_key] = {
                    "token_data": token_data,
                    "expiry": row["expiry"]
                }

                return token_data
            except Exception as e:
                logger.error(f"Failed to decrypt token for {tenant_id}:{provider} - {e}")
                return None

    async def revoke_token(self, tenant_id: str, provider: str) -> None:
        """Revoke and delete a stored token."""
        async with self.db.get_connection() as conn:
            await conn.execute("""
                DELETE FROM oauth_tokens
                WHERE tenant_id = $1 AND provider = $2
            """, tenant_id, provider)

        cache_key = f"{tenant_id}:{provider}"
        if cache_key in self._cache:
            del self._cache[cache_key]

        logger.info(f"Revoked {provider} token for tenant {tenant_id}")
```

**Database Migration: `migrations/021_oauth_tokens.sql`** (NEW)

```sql
-- OAuth token storage for Email and IAM integrations
CREATE TABLE IF NOT EXISTS oauth_tokens (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,  -- 'microsoft', 'google', 'okta', 'azure_ad'
    encrypted_token BYTEA NOT NULL,
    expiry TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    UNIQUE (tenant_id, provider)
);

CREATE INDEX idx_oauth_tokens_tenant_provider ON oauth_tokens(tenant_id, provider);
CREATE INDEX idx_oauth_tokens_expiry ON oauth_tokens(expiry) WHERE expiry > NOW();

COMMENT ON TABLE oauth_tokens IS 'Encrypted OAuth tokens for third-party integrations';
```

#### Phase 2: Email Polling Service (Week 2-3)

**File: `src/collectors/email/office365_collector.py`** (NEW)

```python
"""
Office 365 email collector using Microsoft Graph API.
Implements delta queries for incremental polling and BEC detection.
"""

import asyncio
import httpx
from typing import List, Dict, Any, Optional, AsyncIterator
from datetime import datetime, timedelta
import logging

from src.integrations.auth.oauth_providers import MSALProvider
from src.integrations.auth.token_store import TokenStore
from src.live.event_models import EmailEvent

logger = logging.getLogger(__name__)


class Office365Collector:
    """Collects emails from Office 365 using Microsoft Graph API."""

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    BATCH_SIZE = 100  # Messages per page
    POLL_INTERVAL = 300  # 5 minutes

    def __init__(
        self,
        tenant_id: str,
        oauth_provider: MSALProvider,
        token_store: TokenStore
    ):
        self.tenant_id = tenant_id
        self.oauth_provider = oauth_provider
        self.token_store = token_store
        self._delta_link: Optional[str] = None
        self._checkpoint_cursor: Optional[str] = None

    async def start_polling(self) -> AsyncIterator[EmailEvent]:
        """Start continuous polling for new emails."""
        logger.info(f"Starting Office 365 email polling for tenant {self.tenant_id}")

        while True:
            try:
                async for email_event in self._poll_messages():
                    yield email_event

                # Wait before next poll
                await asyncio.sleep(self.POLL_INTERVAL)

            except Exception as e:
                logger.error(f"Email polling error for tenant {self.tenant_id}: {e}")
                await asyncio.sleep(60)  # Backoff on error

    async def _poll_messages(self) -> AsyncIterator[EmailEvent]:
        """Poll for new messages using delta query."""
        access_token = await self.oauth_provider.get_access_token()
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        # Use delta link if available, otherwise initial query
        if self._delta_link:
            url = self._delta_link
        else:
            # Get messages from last 7 days on first run
            filter_date = (datetime.utcnow() - timedelta(days=7)).isoformat() + "Z"
            url = (
                f"{self.GRAPH_BASE}/users/delta?"
                f"$select=receivedDateTime,subject,from,toRecipients,hasAttachments,internetMessageHeaders"
                f"&$filter=receivedDateTime ge {filter_date}"
                f"&$top={self.BATCH_SIZE}"
            )

        async with httpx.AsyncClient(timeout=60.0) as client:
            while url:
                try:
                    response = await client.get(url, headers=headers)
                    response.raise_for_status()
                    data = response.json()

                    # Process messages
                    for msg in data.get("value", []):
                        event = await self._parse_message(msg)
                        if event:
                            yield event

                    # Update delta link for next poll
                    if "@odata.deltaLink" in data:
                        self._delta_link = data["@odata.deltaLink"]
                        await self._save_checkpoint()
                        url = None  # Exit pagination
                    else:
                        url = data.get("@odata.nextLink")

                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 401:
                        # Token expired, will refresh on next iteration
                        logger.warning("Access token expired, refreshing...")
                        break
                    logger.error(f"Graph API error: {e.response.status_code} - {e.response.text}")
                    break

    async def _parse_message(self, msg: Dict[str, Any]) -> Optional[EmailEvent]:
        """Parse Graph API message into EmailEvent."""
        try:
            # Extract email metadata
            received = datetime.fromisoformat(msg.get("receivedDateTime", "").replace("Z", "+00:00"))
            subject = msg.get("subject", "")
            from_addr = msg.get("from", {}).get("emailAddress", {}).get("address", "")
            from_name = msg.get("from", {}).get("emailAddress", {}).get("name", "")
            to_addrs = [
                recip.get("emailAddress", {}).get("address", "")
                for recip in msg.get("toRecipients", [])
            ]

            # Extract headers for DKIM/DMARC
            headers = {
                h.get("name"): h.get("value")
                for h in msg.get("internetMessageHeaders", [])
            }

            dkim_result = headers.get("Authentication-Results", "")
            dmarc_pass = "dmarc=pass" in dkim_result.lower()
            spf_pass = "spf=pass" in dkim_result.lower()

            # Build EmailEvent
            event = EmailEvent(
                timestamp=received,
                tenant_id=self.tenant_id,
                source="office365",
                sender=from_addr,
                sender_display_name=from_name,
                recipients=to_addrs,
                subject=subject,
                has_attachments=msg.get("hasAttachments", False),
                dkim_pass="dkim=pass" in dkim_result.lower(),
                spf_pass=spf_pass,
                dmarc_pass=dmarc_pass,
                headers=headers,
                message_id=msg.get("id"),
                raw_event=msg
            )

            return event

        except Exception as e:
            logger.error(f"Failed to parse message: {e}")
            return None

    async def _save_checkpoint(self) -> None:
        """Save delta link for recovery."""
        # Store in database or cache
        pass  # TODO: Implement checkpoint persistence
```

**File: `src/collectors/email/gmail_collector.py`** (NEW)

```python
"""
Gmail collector using Google Gmail API.
Implements history-based polling for incremental message retrieval.
"""

import asyncio
import httpx
from typing import List, Dict, Any, Optional, AsyncIterator
from datetime import datetime, timedelta
import logging
import base64

from src.integrations.auth.oauth_providers import GoogleOAuthProvider
from src.live.event_models import EmailEvent

logger = logging.getLogger(__name__)


class GmailCollector:
    """Collects emails from Gmail using Google Gmail API."""

    GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1"
    BATCH_SIZE = 100
    POLL_INTERVAL = 300  # 5 minutes

    def __init__(
        self,
        tenant_id: str,
        oauth_provider: GoogleOAuthProvider,
        user_email: str
    ):
        self.tenant_id = tenant_id
        self.oauth_provider = oauth_provider
        self.user_email = user_email
        self._history_id: Optional[str] = None

    async def start_polling(self) -> AsyncIterator[EmailEvent]:
        """Start continuous polling for new emails."""
        logger.info(f"Starting Gmail polling for {self.user_email}")

        while True:
            try:
                async for email_event in self._poll_messages():
                    yield email_event

                await asyncio.sleep(self.POLL_INTERVAL)

            except Exception as e:
                logger.error(f"Gmail polling error: {e}")
                await asyncio.sleep(60)

    async def _poll_messages(self) -> AsyncIterator[EmailEvent]:
        """Poll for new messages using history API."""
        access_token = await self.oauth_provider.get_access_token()
        headers = {"Authorization": f"Bearer {access_token}"}

        # If we have a history ID, use incremental sync
        if self._history_id:
            url = f"{self.GMAIL_BASE}/users/{self.user_email}/history?startHistoryId={self._history_id}"
        else:
            # Initial sync: get messages from last 7 days
            query_time = int((datetime.utcnow() - timedelta(days=7)).timestamp())
            url = f"{self.GMAIL_BASE}/users/{self.user_email}/messages?q=after:{query_time}&maxResults={self.BATCH_SIZE}"

        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json()

                # Process message IDs
                for msg_ref in data.get("messages", []):
                    msg_id = msg_ref.get("id")
                    event = await self._fetch_message(client, headers, msg_id)
                    if event:
                        yield event

                # Update history ID
                if "historyId" in data:
                    self._history_id = data["historyId"]

            except httpx.HTTPStatusError as e:
                logger.error(f"Gmail API error: {e.response.status_code}")

    async def _fetch_message(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        msg_id: str
    ) -> Optional[EmailEvent]:
        """Fetch full message details."""
        url = f"{self.GMAIL_BASE}/users/{self.user_email}/messages/{msg_id}?format=full"

        try:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            msg = response.json()

            # Parse message
            headers_list = msg.get("payload", {}).get("headers", [])
            headers_dict = {h["name"]: h["value"] for h in headers_list}

            subject = headers_dict.get("Subject", "")
            from_addr = headers_dict.get("From", "")
            to_addr = headers_dict.get("To", "")
            received = headers_dict.get("Date", "")

            # Parse DKIM/SPF/DMARC from Authentication-Results
            auth_results = headers_dict.get("Authentication-Results", "")

            event = EmailEvent(
                timestamp=datetime.utcnow(),  # TODO: Parse Date header
                tenant_id=self.tenant_id,
                source="gmail",
                sender=from_addr,
                sender_display_name=from_addr.split("<")[0].strip(),
                recipients=[to_addr],
                subject=subject,
                has_attachments=bool(msg.get("payload", {}).get("parts")),
                dkim_pass="dkim=pass" in auth_results.lower(),
                spf_pass="spf=pass" in auth_results.lower(),
                dmarc_pass="dmarc=pass" in auth_results.lower(),
                headers=headers_dict,
                message_id=msg_id,
                raw_event=msg
            )

            return event

        except Exception as e:
            logger.error(f"Failed to fetch message {msg_id}: {e}")
            return None
```

#### Phase 3: Integration with Event Pipeline (Week 3-4)

**File: `src/core/event_pipeline/stages/email.py`** (NEW)

```python
"""
Email-specific pipeline stages for enrichment and correlation.
Integrates with existing BEC detection and HopGraph linking.
"""

import asyncio
from typing import Dict, Any, Optional
import logging

from src.core.event_pipeline.stages.base import PipelineStage
from src.live.event_models import EmailEvent
from src.core.hunt.lanes.email_bec import EmailBECDetector
from src.artifact.factors import FactorEmitter

logger = logging.getLogger(__name__)


class EmailEnrichmentStage(PipelineStage):
    """Enriches email events with threat intel and factor analysis."""

    def __init__(self):
        super().__init__("email_enrichment")
        self.bec_detector = EmailBECDetector()
        self.factor_emitter = FactorEmitter()

    async def process(self, event: EmailEvent, context: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich email event with BEC detection and factors."""

        # Run BEC detection (existing logic)
        bec_factors = await self.bec_detector.analyze(event)

        # Emit factors
        for factor in bec_factors:
            self.factor_emitter.emit(
                factor_name=factor["name"],
                value=factor["value"],
                confidence=factor.get("confidence", 0.7),
                metadata=factor.get("metadata", {})
            )

        # Enrich context
        context["email_factors"] = bec_factors
        context["is_bec_candidate"] = any(
            f["name"].startswith("email_bec_") for f in bec_factors
        )
        context["phishing_score"] = self._calculate_phishing_score(bec_factors)

        return context

    def _calculate_phishing_score(self, factors: list) -> float:
        """Calculate aggregate phishing score from factors."""
        phish_factors = [
            "email_bec_display_spoof",
            "email_phishing_urgency",
            "email_suspicious_attachment",
            "email_dmarc_fail"
        ]

        score = 0.0
        for factor in factors:
            if factor["name"] in phish_factors:
                score += factor.get("confidence", 0.5)

        return min(score, 1.0)


class EmailToEndpointCorrelator(PipelineStage):
    """Correlates email events with endpoint activity (email → LOLBin execution)."""

    def __init__(self, graph_session):
        super().__init__("email_endpoint_correlation")
        self.graph = graph_session

    async def process(self, event: EmailEvent, context: Dict[str, Any]) -> Dict[str, Any]:
        """Link email to subsequent endpoint activity."""

        # Extract potential IoCs from email
        attachment_hashes = context.get("attachment_hashes", [])
        suspicious_urls = context.get("urls", [])

        # Query HopGraph for matching endpoint events (within 1 hour window)
        if attachment_hashes:
            endpoint_events = await self.graph.query_recent_events(
                event_type="process_create",
                field_match={"hash": attachment_hashes},
                time_window=3600  # 1 hour
            )

            if endpoint_events:
                context["correlated_execution"] = endpoint_events
                context["email_to_exec_chain"] = True
                logger.warning(
                    f"Email attachment led to execution: {event.subject} → "
                    f"{len(endpoint_events)} processes"
                )

        return context
```

### Testing & Validation

**File: `tests/integrations/test_email_collectors.py`** (NEW)

```python
"""
Integration tests for email collectors using mock OAuth and API responses.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from src.collectors.email.office365_collector import Office365Collector
from src.collectors.email.gmail_collector import GmailCollector
from src.integrations.auth.oauth_providers import MSALProvider, GoogleOAuthProvider


@pytest.mark.asyncio
async def test_office365_collector_delta_query():
    """Test Office 365 incremental polling with delta queries."""

    # Mock OAuth provider
    oauth_mock = AsyncMock(spec=MSALProvider)
    oauth_mock.get_access_token.return_value = "mock_token_12345"

    # Mock Graph API response
    mock_response = {
        "value": [
            {
                "id": "msg_001",
                "receivedDateTime": "2025-12-21T10:00:00Z",
                "subject": "Urgent: Wire Transfer Needed",
                "from": {
                    "emailAddress": {
                        "address": "ceo@evil.com",
                        "name": "CEO (Spoofed)"
                    }
                },
                "toRecipients": [{"emailAddress": {"address": "finance@company.com"}}],
                "hasAttachments": False,
                "internetMessageHeaders": [
                    {"name": "Authentication-Results", "value": "dkim=fail; spf=fail; dmarc=fail"}
                ]
            }
        ],
        "@odata.deltaLink": "https://graph.microsoft.com/v1.0/delta?$deltatoken=abc123"
    }

    collector = Office365Collector(
        tenant_id="test_tenant",
        oauth_provider=oauth_mock,
        token_store=MagicMock()
    )

    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = mock_response

        events = []
        async for event in collector._poll_messages():
            events.append(event)
            break  # Get first event only

        assert len(events) == 1
        assert events[0].subject == "Urgent: Wire Transfer Needed"
        assert events[0].dmarc_pass is False
        assert collector._delta_link == mock_response["@odata.deltaLink"]


@pytest.mark.asyncio
async def test_gmail_collector_history_sync():
    """Test Gmail history-based incremental sync."""

    oauth_mock = AsyncMock(spec=GoogleOAuthProvider)
    oauth_mock.get_access_token.return_value = "mock_gmail_token"

    mock_history = {
        "messages": [{"id": "msg_gmail_001"}],
        "historyId": "54321"
    }

    mock_message = {
        "id": "msg_gmail_001",
        "payload": {
            "headers": [
                {"name": "Subject", "value": "Click here to claim prize!"},
                {"name": "From", "value": "phisher@evil.com"},
                {"name": "To", "value": "victim@company.com"},
                {"name": "Authentication-Results", "value": "spf=pass; dkim=pass; dmarc=fail"}
            ]
        }
    }

    collector = GmailCollector(
        tenant_id="test_tenant",
        oauth_provider=oauth_mock,
        user_email="user@company.com"
    )

    with patch("httpx.AsyncClient.get") as mock_get:
        # First call: history list
        # Second call: message details
        mock_get.side_effect = [
            MagicMock(status_code=200, json=lambda: mock_history),
            MagicMock(status_code=200, json=lambda: mock_message)
        ]

        events = []
        async for event in collector._poll_messages():
            events.append(event)

        assert len(events) == 1
        assert "prize" in events[0].subject.lower()
        assert collector._history_id == "54321"
```

### Deployment & Configuration

**Configuration: `config/integrations/email.yaml`** (NEW)

```yaml
email_collectors:
  office365:
    enabled: true
    poll_interval_seconds: 300  # 5 minutes
    batch_size: 100
    delta_sync: true
    max_history_days: 7

    # Per-tenant configuration
    tenants:
      - tenant_id: "customer_001"
        microsoft_tenant_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        client_id: "${OFFICE365_CLIENT_ID}"
        client_secret: "${OFFICE365_CLIENT_SECRET}"
        mailboxes:
          - "security@customer001.com"
          - "finance@customer001.com"

  gmail:
    enabled: true
    poll_interval_seconds: 300
    batch_size: 100
    use_history_sync: true

    tenants:
      - tenant_id: "customer_002"
        service_account_json: "${GMAIL_SERVICE_ACCOUNT_PATH}"
        delegated_users:
          - "security@customer002.com"

email_enrichment:
  bec_detection: true
  phishing_detection: true
  attachment_scanning: true
  url_extraction: true

  # Correlation settings
  email_to_endpoint_window_seconds: 3600  # 1 hour
  email_to_network_window_seconds: 1800   # 30 minutes
```

### Success Criteria

- [ ] OAuth authentication working for Office 365 and Gmail
- [ ] Delta/history queries fetching incremental emails
- [ ] Token storage and refresh automatic
- [ ] Email events flowing into event pipeline
- [ ] BEC/phishing detection running on live emails
- [ ] Email-to-endpoint correlation in HopGraph
- [ ] <1% message loss rate during polling
- [ ] <5 minute detection latency (email arrival → alert)
- [ ] Prometheus metrics for collector health
- [ ] Integration tests passing with 90%+ coverage

**Timeline:** 4 weeks
**Complexity:** HIGH
**Dependencies:** OAuth credentials from customers, Vault/KMS for token storage

---

## P0-2: IAM LIVE MONITORING (Identity Threat Detection)

### Current State
- ✅ **Working:** IAM policy change detection in CloudTrail logs
- ✅ **Working:** Risky login detection logic
- ❌ **Missing:** OAuth adapters for Okta, Azure AD, Google Workspace
- ❌ **Missing:** SCIM event polling, real-time identity sync

### Business Value
- **Critical for:** Insider threat detection, privileged access monitoring
- **Compliance:** Required for SOC 2, ISO 27001 identity controls
- **Use cases:** Detect privilege escalation, lateral movement via stolen credentials

### Technical Architecture

```
┌──────────────────────────────────────────────────────────┐
│              IAM Monitoring Pipeline                      │
├──────────────────────────────────────────────────────────┤
│                                                            │
│  ┌────────────┐    ┌───────────┐    ┌────────────────┐  │
│  │   Okta     │    │ Azure AD  │    │ Google Workspace│  │
│  │  Events    │    │  Events   │    │    Events      │  │
│  └─────┬──────┘    └─────┬─────┘    └────────┬───────┘  │
│        │                  │                    │          │
│        └──────────────────┼────────────────────┘          │
│                           ▼                               │
│               ┌──────────────────────┐                    │
│               │  IAM Event Parser    │                    │
│               │  (Normalize Schema)  │                    │
│               └──────────────────────┘                    │
│                           │                               │
│              ┌────────────┼────────────┐                  │
│              ▼            ▼            ▼                  │
│      ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│      │ Risky    │  │ Privilege│  │ Anomalous│           │
│      │ Login    │  │Escalation│  │ Access   │           │
│      │Detector  │  │ Detector │  │ Detector │           │
│      └──────────┘  └──────────┘  └──────────┘           │
│              │            │            │                  │
│              └────────────┼────────────┘                  │
│                           ▼                               │
│                  ┌────────────────┐                       │
│                  │   HopGraph     │                       │
│                  │  (User Nodes)  │                       │
│                  └────────────────┘                       │
└──────────────────────────────────────────────────────────┘
```

### Implementation Plan

*(Similar detailed structure as Email, with OAuth providers for Okta, Azure AD, Google Workspace, SCIM polling, and IAM event normalization)*

**Key Files:**
- `src/collectors/iam/okta_collector.py`
- `src/collectors/iam/azure_ad_collector.py`
- `src/collectors/iam/google_workspace_collector.py`
- `src/core/event_pipeline/stages/iam.py`
- `src/core/detectors/privilege_escalation.py`
- `src/core/detectors/risky_login.py`

**Timeline:** 6 weeks
**Complexity:** HIGH (3 providers, complex event schemas)

---

## P0-3: ENHANCED LLM SUMMARIES (Tier 1 & Tier 2)

### Current State
- ✅ **Framework complete:** Multi-provider support, fallback logic
- ⚠️ **Using stubs:** Deterministic templates without LLM API calls
- ❌ **Missing:** Streaming output, context-aware narratives, risk delta optimization

### Business Value
- **Key differentiator:** AI-powered triage reduces analyst time by 60-80%
- **Customer demand:** #1 requested feature in pilot feedback
- **Competitive moat:** Advanced LLM integration vs. rule-based competitors

### Enhancement Roadmap

#### Enhancement 1: Context-Aware Prompting (Week 1)

**File: `src/ai/llm_prompts.py`** (ENHANCE)

```python
"""
Enhanced LLM prompts with full context injection for Tier 1/2 summaries.
"""

from typing import Dict, Any, List
import json


class ContextualPromptBuilder:
    """Builds context-rich prompts for LLM analysis."""

    @staticmethod
    def build_tier1_prompt(
        artifact: Dict[str, Any],
        factors: List[Dict[str, Any]],
        threat_intel: Dict[str, Any],
        tenant_context: Dict[str, Any]
    ) -> str:
        """Build Tier 1 fast summary prompt with full context."""

        # Extract key details
        artifact_type = artifact.get("type", "unknown")
        verdict = artifact.get("verdict", "UNKNOWN")
        risk_score = artifact.get("risk_score", 0.0)

        # Top 5 factors
        top_factors = sorted(factors, key=lambda f: f.get("weight", 0), reverse=True)[:5]
        factor_summary = "\n".join([
            f"  - {f['name']}: {f.get('value', 'N/A')} (confidence: {f.get('confidence', 0):.2f})"
            for f in top_factors
        ])

        # Threat intel hits
        intel_hits = threat_intel.get("matches", [])
        intel_summary = "\n".join([
            f"  - {hit.get('source', 'Unknown')}: {hit.get('indicator', 'N/A')} ({hit.get('category', 'generic')})"
            for hit in intel_hits[:3]
        ])

        # Industry context
        industry = tenant_context.get("industry", "unknown")
        sensitivity = tenant_context.get("data_sensitivity", "medium")

        prompt = f"""You are a cybersecurity analyst providing a CONCISE 2-3 sentence summary for a SOC analyst.

**Artifact Analysis:**
- Type: {artifact_type}
- Verdict: {verdict}
- Risk Score: {risk_score:.2f}/1.0

**Top Detection Factors:**
{factor_summary}

**Threat Intelligence Matches:**
{intel_summary or "  - No threat intel matches"}

**Customer Context:**
- Industry: {industry}
- Data Sensitivity: {sensitivity}

**Task:** Provide a clear, actionable summary explaining:
1. WHAT was detected (in plain language)
2. WHY it's suspicious or malicious
3. RECOMMENDED next action for the analyst

Keep it under 100 words. Focus on IMPACT and ACTION, not technical jargon.
"""
        return prompt

    @staticmethod
    def build_tier2_prompt(
        artifact: Dict[str, Any],
        all_factors: List[Dict[str, Any]],
        hopgraph_chains: List[Dict[str, Any]],
        threat_intel: Dict[str, Any],
        mitre_techniques: List[str],
        tenant_context: Dict[str, Any]
    ) -> str:
        """Build Tier 2 deep analysis prompt with attack narrative."""

        # Group factors by category
        factor_groups = {}
        for f in all_factors:
            category = f.get("category", "other")
            if category not in factor_groups:
                factor_groups[category] = []
            factor_groups[category].append(f)

        # Format attack chains
        chain_summary = ""
        for i, chain in enumerate(hopgraph_chains[:3], 1):
            steps = " → ".join([node.get("label", "unknown") for node in chain.get("nodes", [])])
            chain_summary += f"\n  Chain {i}: {steps}"

        # MITRE techniques
        mitre_summary = ", ".join(mitre_techniques[:5]) if mitre_techniques else "None mapped"

        prompt = f"""You are a senior threat analyst providing an IN-DEPTH attack analysis for investigation.

**Artifact Overview:**
- Type: {artifact.get('type')}
- Verdict: {artifact.get('verdict')}
- Risk: {artifact.get('risk_score', 0):.2f}/1.0
- MITRE Techniques: {mitre_summary}

**Detection Factors by Category:**
{json.dumps(factor_groups, indent=2)}

**Attack Chains (HopGraph):**
{chain_summary or "  No multi-hop chains detected"}

**Threat Intelligence:**
{json.dumps(threat_intel.get("matches", []), indent=2)}

**Customer Environment:**
- Industry: {tenant_context.get('industry', 'unknown')}
- Critical Assets: {', '.join(tenant_context.get('critical_assets', ['unknown']))}
- Threat Model: {tenant_context.get('threat_model', 'general')}

**Task:** Provide a comprehensive 200-300 word analysis covering:

1. **Attack Narrative**: Tell the story of what happened, from initial access to impact
2. **Technical Evidence**: Reference specific factors and their significance
3. **Attack Chain Analysis**: Explain lateral movement, persistence, or exfiltration patterns
4. **Business Impact**: Potential damage to THIS specific customer (consider industry/assets)
5. **Recommended Response**: Prioritized investigation steps and containment actions

Write for a technical audience (Tier 2/3 analyst or incident responder). Use precise language and reference MITRE techniques where relevant.
"""
        return prompt
```

#### Enhancement 2: Streaming LLM Output (Week 2)

**File: `src/api/tier2_endpoints.py`** (ENHANCE)

```python
"""
Enhanced Tier 2 endpoint with SSE streaming for progressive narrative.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from typing import AsyncIterator
import json
import asyncio

from src.ai.oss_models import get_llm_client
from src.ai.llm_prompts import ContextualPromptBuilder

router = APIRouter()


@router.get("/api/v1/llm/tier2/{artifact_id}/stream")
async def stream_tier2_analysis(
    artifact_id: str,
    tenant_id: str = Depends(get_tenant_id)
) -> StreamingResponse:
    """Stream Tier 2 analysis with progressive token generation."""

    async def generate_stream() -> AsyncIterator[str]:
        """Generate SSE stream of LLM tokens."""

        # Fetch artifact and context
        artifact = await get_artifact(artifact_id, tenant_id)
        factors = await get_artifact_factors(artifact_id)
        hopgraph_chains = await get_hopgraph_chains(artifact_id)
        threat_intel = await get_threat_intel(artifact)
        mitre_techniques = await get_mitre_techniques(factors)
        tenant_context = await get_tenant_context(tenant_id)

        # Build prompt
        prompt_builder = ContextualPromptBuilder()
        prompt = prompt_builder.build_tier2_prompt(
            artifact=artifact,
            all_factors=factors,
            hopgraph_chains=hopgraph_chains,
            threat_intel=threat_intel,
            mitre_techniques=mitre_techniques,
            tenant_context=tenant_context
        )

        # Stream LLM response
        llm_client = get_llm_client(tenant_id)

        async for chunk in llm_client.stream_completion(prompt):
            # Send SSE event
            sse_data = json.dumps({
                "type": "chunk",
                "content": chunk,
                "timestamp": datetime.utcnow().isoformat()
            })
            yield f"data: {sse_data}\n\n"

        # Send completion event
        completion_data = json.dumps({
            "type": "complete",
            "cost_estimate": llm_client.get_last_cost(),
            "tokens_used": llm_client.get_last_token_count()
        })
        yield f"data: {completion_data}\n\n"

    return StreamingResponse(
        generate_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"  # Disable nginx buffering
        }
    )
```

#### Enhancement 3: Risk Delta Optimization (Week 3)

**Current Issue:** Risk delta capped at 0.08, may suppress legitimate threats

**File: `src/artifact/llm_refine.py`** (FIX)

```python
# BEFORE (Current)
risk_delta = max(-0.08, min(0.08, llm_risk_adjustment))  # Too restrictive

# AFTER (Enhanced)
def calculate_risk_delta(
    base_risk: float,
    llm_risk_adjustment: float,
    confidence: float,
    threat_intel_boost: float = 0.0
) -> float:
    """
    Calculate LLM risk delta with dynamic capping based on confidence.

    High confidence adjustments get wider range, low confidence stays conservative.
    """
    # Base cap increases with confidence
    if confidence >= 0.9:
        max_delta = 0.20  # High confidence: allow large adjustments
    elif confidence >= 0.75:
        max_delta = 0.12  # Medium-high: moderate adjustments
    else:
        max_delta = 0.08  # Low confidence: conservative

    # Apply threat intel boost (external validation increases confidence)
    if threat_intel_boost > 0:
        max_delta += 0.05

    # Cap the delta
    risk_delta = max(-max_delta, min(max_delta, llm_risk_adjustment))

    # Prevent pushing low-risk items too high without strong evidence
    if base_risk < 0.3 and risk_delta > 0:
        risk_delta *= 0.5  # Dampen upward adjustments for low baseline

    return risk_delta
```

### Success Criteria

- [ ] LLM prompts include full context (factors, HopGraph, threat intel, tenant data)
- [ ] Tier 2 streaming working with <3 second first token latency
- [ ] Risk delta optimization reduces false negatives by 20%+
- [ ] Cost per analysis <$0.50 for Tier 1, <$2.00 for Tier 2
- [ ] Narrative quality validated by 3+ SOC analysts (subjective review)
- [ ] 90%+ of summaries mention specific MITRE techniques
- [ ] A/B testing shows 50%+ reduction in analyst triage time

**Timeline:** 3 weeks
**Complexity:** MEDIUM

---

## P0-4: PRODUCTION-READY BINARY ANALYSIS

### Current State
- ✅ **Working:** PE header analysis, entropy detection, signature validation
- ✅ **Working:** Behavior clustering via embeddings
- ⚠️ **Prototype:** VirusTotal hash lookup (queue exists, needs API key)
- ❌ **Missing:** Sandboxing integration, YARA rule scanning, dynamic analysis

### Business Value
- **Essential for:** Malware detection, incident response, threat hunting
- **Customer demand:** Required for endpoint security use cases
- **Compliance:** Malware analysis required for many frameworks

### Enhancement Roadmap

#### Enhancement 1: VirusTotal Integration (Week 1)

**File: `src/integrations/virustotal_client.py`** (NEW)

```python
"""
VirusTotal API v3 client with rate limiting and quota management.
"""

import asyncio
import httpx
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class VirusTotalClient:
    """VirusTotal API v3 client."""

    BASE_URL = "https://www.virustotal.com/api/v3"
    RATE_LIMIT_REQUESTS = 4  # Free tier: 4 req/min
    RATE_LIMIT_WINDOW = 60   # seconds

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
        self._request_timestamps: list = []

    async def get_file_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get file analysis report by hash (SHA256, SHA1, or MD5)."""

        await self._rate_limit()

        url = f"{self.BASE_URL}/files/{file_hash}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(url, headers=self.headers)

                if response.status_code == 404:
                    logger.info(f"Hash {file_hash} not found in VT")
                    return None

                response.raise_for_status()
                data = response.json()

                # Extract key fields
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                result = {
                    "hash": file_hash,
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "undetected_count": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()),
                    "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                    "first_seen": attributes.get("first_submission_date"),
                    "last_seen": attributes.get("last_analysis_date"),
                    "names": attributes.get("names", []),
                    "tags": attributes.get("tags", []),
                    "reputation": attributes.get("reputation", 0),
                    "raw_response": data
                }

                logger.info(f"VT report for {file_hash}: {result['detection_ratio']} detections")
                return result

            except httpx.HTTPStatusError as e:
                logger.error(f"VT API error: {e.response.status_code}")
                return None

    async def submit_file(self, file_path: str) -> Optional[str]:
        """Submit file for analysis, returns analysis ID."""

        await self._rate_limit()

        url = f"{self.BASE_URL}/files"

        async with httpx.AsyncClient(timeout=120.0) as client:
            with open(file_path, "rb") as f:
                files = {"file": f}
                response = await client.post(url, headers=self.headers, files=files)
                response.raise_for_status()

                data = response.json()
                analysis_id = data.get("data", {}).get("id")

                logger.info(f"Submitted {file_path} to VT, analysis ID: {analysis_id}")
                return analysis_id

    async def _rate_limit(self):
        """Enforce rate limiting (4 req/min for free tier)."""
        now = datetime.utcnow()

        # Remove timestamps older than window
        self._request_timestamps = [
            ts for ts in self._request_timestamps
            if now - ts < timedelta(seconds=self.RATE_LIMIT_WINDOW)
        ]

        # If at limit, wait
        if len(self._request_timestamps) >= self.RATE_LIMIT_REQUESTS:
            oldest = self._request_timestamps[0]
            wait_time = (oldest + timedelta(seconds=self.RATE_LIMIT_WINDOW) - now).total_seconds()
            if wait_time > 0:
                logger.debug(f"VT rate limit reached, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)

        self._request_timestamps.append(now)
```

#### Enhancement 2: YARA Rule Scanning (Week 2)

**File: `src/artifact/yara_scanner.py`** (NEW)

```python
"""
YARA rule scanner for static binary analysis.
Includes community rules and custom threat-specific signatures.
"""

import yara
from typing import List, Dict, Any
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class YaraScanner:
    """YARA rule scanner for malware detection."""

    def __init__(self, rules_dir: str = "data/yara_rules"):
        self.rules_dir = Path(rules_dir)
        self.compiled_rules = self._compile_rules()

    def _compile_rules(self) -> yara.Rules:
        """Compile all YARA rules in directory."""
        rule_files = {}

        for rule_file in self.rules_dir.glob("**/*.yar"):
            namespace = rule_file.stem
            rule_files[namespace] = str(rule_file)

        logger.info(f"Compiling {len(rule_files)} YARA rule files")
        return yara.compile(filepaths=rule_files)

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan file with YARA rules."""
        matches = self.compiled_rules.match(file_path)

        results = []
        for match in matches:
            result = {
                "rule_name": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "strings": [
                    {
                        "offset": s[0],
                        "identifier": s[1],
                        "data": s[2].decode("utf-8", errors="replace")[:100]
                    }
                    for s in match.strings
                ],
                "metadata": match.meta
            }
            results.append(result)

        if results:
            logger.warning(f"YARA matches in {file_path}: {[r['rule_name'] for r in results]}")

        return results
```

**YARA Rules: `data/yara_rules/malware_common.yar`** (NEW)

```yara
rule Suspicious_PE_Packed {
    meta:
        description = "Detects packed PE files with high entropy"
        severity = "medium"
        mitre = "T1027.002"  // Obfuscated Files or Information: Software Packing

    strings:
        $upx = { 55 50 58 21 }  // UPX header
        $aspack = "ASPack"
        $pecompact = "PECompact"

    condition:
        uint16(0) == 0x5A4D and  // PE header
        (
            $upx at 0 or
            $aspack or
            $pecompact
        )
}

rule LOLBin_Embedded_PowerShell {
    meta:
        description = "Detects embedded PowerShell commands in binaries"
        severity = "high"
        mitre = "T1059.001"  // Command and Scripting Interpreter: PowerShell

    strings:
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        $encoded = "-encodedcommand" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase

    condition:
        uint16(0) == 0x5A4D and
        ($ps1 or $ps2) and
        ($encoded or $bypass or $hidden)
}

rule Ransomware_File_Extension_Change {
    meta:
        description = "Detects ransomware-like file extension operations"
        severity = "critical"
        mitre = "T1486"  // Data Encrypted for Impact

    strings:
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypted" nocase
        $readme = "README" nocase
        $bitcoin = "bitcoin" nocase

    condition:
        2 of ($ext*) or
        ($readme and $bitcoin)
}
```

#### Enhancement 3: Sandbox Integration (Week 3-4)

**File: `src/integrations/cuckoo_client.py`** (NEW)

```python
"""
Cuckoo Sandbox API client for dynamic malware analysis.
Alternative: Joe Sandbox, Any.Run, or custom sandbox.
"""

import asyncio
import httpx
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class CuckooSandboxClient:
    """Cuckoo Sandbox REST API client."""

    def __init__(self, base_url: str = "http://cuckoo:8090", api_token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}

    async def submit_file(
        self,
        file_path: str,
        timeout: int = 120,
        options: Optional[Dict[str, Any]] = None
    ) -> int:
        """Submit file for sandbox analysis."""

        url = f"{self.base_url}/tasks/create/file"

        async with httpx.AsyncClient(timeout=60.0) as client:
            with open(file_path, "rb") as f:
                files = {"file": f}
                data = {
                    "timeout": timeout,
                    "options": options or {},
                    "priority": 2  # Normal priority
                }

                response = await client.post(url, headers=self.headers, files=files, data=data)
                response.raise_for_status()

                result = response.json()
                task_id = result.get("task_id")

                logger.info(f"Submitted {file_path} to Cuckoo, task ID: {task_id}")
                return task_id

    async def get_report(self, task_id: int) -> Optional[Dict[str, Any]]:
        """Get analysis report."""

        url = f"{self.base_url}/tasks/report/{task_id}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=self.headers)

            if response.status_code == 404:
                return None

            response.raise_for_status()
            report = response.json()

            # Extract key findings
            summary = {
                "task_id": task_id,
                "status": report.get("info", {}).get("status"),
                "score": report.get("info", {}).get("score", 0),
                "signatures": [
                    {
                        "name": sig.get("name"),
                        "severity": sig.get("severity"),
                        "description": sig.get("description"),
                        "mitre": sig.get("ttp", [])
                    }
                    for sig in report.get("signatures", [])
                ],
                "network_activity": {
                    "http_requests": len(report.get("network", {}).get("http", [])),
                    "dns_queries": len(report.get("network", {}).get("dns", [])),
                    "tcp_connections": len(report.get("network", {}).get("tcp", []))
                },
                "file_operations": {
                    "created": len(report.get("behavior", {}).get("summary", {}).get("files_created", [])),
                    "deleted": len(report.get("behavior", {}).get("summary", {}).get("files_deleted", []))
                },
                "registry_operations": {
                    "keys_set": len(report.get("behavior", {}).get("summary", {}).get("regkey_written", []))
                },
                "raw_report": report
            }

            return summary

    async def wait_for_completion(self, task_id: int, max_wait: int = 600) -> Dict[str, Any]:
        """Wait for analysis to complete and return report."""

        start_time = asyncio.get_event_loop().time()

        while True:
            report = await self.get_report(task_id)

            if report and report["status"] == "reported":
                return report

            if asyncio.get_event_loop().time() - start_time > max_wait:
                raise TimeoutError(f"Sandbox analysis {task_id} timed out after {max_wait}s")

            await asyncio.sleep(10)  # Poll every 10 seconds
```

### Testing & Deployment

**Configuration: `config/integrations/binary_analysis.yaml`** (NEW)

```yaml
binary_analysis:
  virustotal:
    enabled: true
    api_key: "${VIRUSTOTAL_API_KEY}"
    rate_limit_rpm: 4  # Free tier
    auto_submit_unknowns: false  # Don't auto-submit customer binaries
    cache_ttl_hours: 24

  yara:
    enabled: true
    rules_directory: "data/yara_rules"
    auto_update_rules: true
    community_rules:
      - "https://github.com/Yara-Rules/rules"
      - "https://github.com/elastic/protections-artifacts"

  sandbox:
    enabled: false  # Enable when Cuckoo deployed
    provider: "cuckoo"  # cuckoo, joe, anyrun
    endpoint: "http://cuckoo:8090"
    api_token: "${CUCKOO_API_TOKEN}"
    timeout_seconds: 120
    auto_submit_suspicious: true  # Auto-sandbox if risk > 0.7
```

### Success Criteria

- [ ] VirusTotal integration working with rate limiting
- [ ] YARA scanner detecting common malware families
- [ ] Sandbox integration functional (Cuckoo or alternative)
- [ ] <30 second analysis time for VT + YARA (no sandbox)
- [ ] <5 minute analysis time with sandboxing
- [ ] 95%+ detection rate for known malware (test corpus)
- [ ] <1% false positive rate on benign software
- [ ] Prometheus metrics for binary analysis pipeline

**Timeline:** 4 weeks
**Complexity:** MEDIUM

---

## INTEGRATION & TESTING

### End-to-End Testing

**File: `tests/e2e/test_p0_features_integration.py`** (NEW)

```python
"""
End-to-end integration tests for P0 critical features.
"""

import pytest
import asyncio
from datetime import datetime, timedelta


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_email_to_endpoint_correlation():
    """Test email phishing → LOLBin execution chain."""

    # 1. Simulate phishing email arrival
    email_event = {
        "sender": "attacker@evil.com",
        "subject": "Urgent: Click here",
        "attachment_hash": "abc123...",
        "recipient": "victim@company.com"
    }

    email_response = await api_client.post("/api/v1/events", json=email_event)
    assert email_response.status_code == 200

    # 2. Simulate user clicking attachment (process execution)
    await asyncio.sleep(2)  # Wait for email processing

    process_event = {
        "event_type": "process_create",
        "user": "victim@company.com",
        "process_name": "powershell.exe",
        "command_line": "powershell -enc base64encodedcommand",
        "parent_hash": "abc123...",  # Same hash as email attachment
        "timestamp": datetime.utcnow().isoformat()
    }

    process_response = await api_client.post("/api/v1/events", json=process_event)
    assert process_response.status_code == 200

    # 3. Wait for correlation
    await asyncio.sleep(5)

    # 4. Check HopGraph for email → execution chain
    graph_response = await api_client.get("/api/v1/graph/sessions/recent")
    sessions = graph_response.json()

    # Should have a session linking email to execution
    email_exec_chain = [
        s for s in sessions
        if "email" in s["triggers"] and "lolbin" in s["techniques"]
    ]

    assert len(email_exec_chain) > 0, "Email-to-execution chain not detected"

    # 5. Check Tier 2 LLM summary mentions the attack chain
    session_id = email_exec_chain[0]["session_id"]
    llm_response = await api_client.get(f"/api/v1/llm/tier2/{session_id}")
    narrative = llm_response.json()["narrative"]

    assert "phishing" in narrative.lower()
    assert "powershell" in narrative.lower()
    assert "execution" in narrative.lower()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_iam_privilege_escalation_detection():
    """Test IAM role change → suspicious login → data access chain."""

    # Simulate IAM privilege escalation, risky login, then data access
    # Verify HopGraph correlation and LLM summary
    pass  # TODO: Implement


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_binary_analysis_full_pipeline():
    """Test binary upload → VT lookup → YARA scan → verdict."""

    # Upload suspicious binary
    # Verify VT integration, YARA detection, and final verdict
    pass  # TODO: Implement
```

---

## SUCCESS METRICS

### Technical Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Email ingestion latency | <5 min | Time from email arrival to alert |
| IAM event latency | <2 min | Time from IAM change to alert |
| LLM Tier 1 response time | <30 sec | API response time |
| LLM Tier 2 response time | <90 sec | API response time |
| Binary analysis time (no sandbox) | <30 sec | VT + YARA |
| Binary analysis time (with sandbox) | <5 min | Full dynamic analysis |
| Email collector uptime | >99.5% | Prometheus uptime metric |
| OAuth token refresh success | >99.9% | Token store metrics |
| False positive rate (Email/IAM) | <5% | Feedback analysis |

### Business Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Analyst triage time reduction | >50% | Pre/post LLM deployment survey |
| Multi-domain correlation rate | >20% | % of alerts with 2+ domains |
| Customer adoption (Email live) | >80% | % of customers enabling feature |
| LLM cost per analysis | <$2.00 | Average T1+T2 cost |
| Binary malware detection rate | >95% | Test corpus validation |

---

## DEPLOYMENT TIMELINE

### Week 1-2: Email OAuth & IAM OAuth
- Implement OAuth providers (MSAL, Google, Okta, Azure AD)
- Build token storage with encryption
- Database migration for oauth_tokens table

### Week 3-4: Email & IAM Collectors
- Office 365 delta query polling
- Gmail history sync
- Okta/Azure AD event polling
- Integration with event pipeline

### Week 5-6: LLM Enhancements
- Context-aware prompting
- Streaming SSE output
- Risk delta optimization
- A/B testing framework

### Week 7-8: Binary Analysis Production
- VirusTotal integration
- YARA scanner deployment
- Sandbox integration (optional)
- Performance optimization

### Week 9: Integration Testing
- End-to-end tests (email → endpoint, IAM → data access)
- Performance testing (1000 emails/hour, 100 IAM events/min)
- Load testing LLM endpoints

### Week 10: Documentation & Training
- Operator runbooks (OAuth setup, token rotation, troubleshooting)
- Customer onboarding guides
- SOC analyst training materials
- Sales enablement docs

---

## DEPENDENCIES & RISKS

### External Dependencies

| Dependency | Status | Risk | Mitigation |
|-----------|--------|------|------------|
| Microsoft Graph API | Available | LOW | Well-documented, stable |
| Gmail API | Available | LOW | Mature API, good docs |
| Okta API | Available | MEDIUM | Complex event schema |
| Azure AD API | Available | MEDIUM | Multi-version confusion |
| OpenAI/Anthropic API | Available | MEDIUM | Rate limits, cost |
| VirusTotal API | Available | LOW | Free tier sufficient for pilot |
| Cuckoo Sandbox | Needs deployment | HIGH | Self-hosted complexity |

### Technical Risks

1. **OAuth Token Management** - Risk of token expiry causing ingestion gaps
   - *Mitigation:* Proactive refresh, monitoring, alerting

2. **LLM Cost Overruns** - Risk of unexpected API costs at scale
   - *Mitigation:* Per-tenant budgets, caching, fallback to deterministic

3. **Email Polling Delays** - Risk of missing time-sensitive threats
   - *Mitigation:* Webhook support (future), SLA monitoring

4. **Sandbox Performance** - Risk of analysis backlog
   - *Mitigation:* Async queuing, priority tiers, timeout enforcement

### Business Risks

1. **Customer OAuth Consent** - Risk of customers blocking API access
   - *Mitigation:* Clear security messaging, minimal permissions, audit logs

2. **Competitive Pressure** - Risk of competitors shipping faster
   - *Mitigation:* Focus on quality over speed, strong differentiation

---

## CONCLUSION

Completing these **4 P0 critical features** transforms JanuSec from a **batch analysis tool** to a **real-time, AI-powered threat detection platform** competitive with established vendors.

**Estimated Total Effort:** 8-10 weeks with 2-3 engineers

**Recommended Approach:**
1. **Weeks 1-4:** Email & IAM live ingestion (highest customer demand)
2. **Weeks 5-6:** LLM enhancements (key differentiator)
3. **Weeks 7-8:** Binary analysis (completes core capabilities)
4. **Weeks 9-10:** Testing & documentation (production readiness)

**Go-Live Readiness:** End of Week 10 for pilot customers, Week 12 for general availability.
