# ADVANCED EMAIL THREAT DETECTION ENHANCEMENT GUIDE v2.0

**Date:** 2025-12-17  
**Purpose:** Comprehensive email security integration for JanuSec XDR  
**Scope:** Phishing, Ransomware, BEC, Supply Chain Attack Detection  
**Key Addition:** Human signal integration + Supply chain correlation chains

---

## EXECUTIVE SUMMARY

Email remains the **#1 initial access vector** for:
- **91%** of ransomware attacks start with phishing
- **BEC** caused **$2.9B** in losses (FBI IC3 2023)
- **Supply chain attacks** (Shai-Hulud) use credential phishing as precursor

This guide provides:
1. **12+ email connector integrations** with API/webhook/syslog patterns
2. **Human signal pipelines** (user-reported phishing = fastest detection)
3. **Normalized telemetry schema** for cross-platform correlation
4. **Advanced detection rules** with multi-signal correlation
5. **Supply chain attack chains** (Email → Identity → Repo/CI → Endpoint)

---

## PART 1: EMAIL CONNECTOR ARCHITECTURE

### 1.1 Connector Priority Matrix

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    EMAIL SECURITY CONNECTOR TIERS                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TIER 1: CLOUD EMAIL PLATFORMS (Native Mailbox Telemetry)                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │ Microsoft 365    │  │ Google Workspace │  │ Exchange On-Prem │          │
│  │ Graph API        │  │ Admin SDK        │  │ Message Tracking │          │
│  │ Defender for O365│  │ Alert Center     │  │ Transport Logs   │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│                                                                              │
│  TIER 2: EMAIL SECURITY GATEWAYS (SEG/ICES - Richest Signals)               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │ Proofpoint TAP   │  │ Mimecast         │  │ Abnormal Security│          │
│  │ SIEM API         │  │ Event Push       │  │ REST API         │          │
│  │ URL Defense      │  │ S3 Export        │  │ BEC Detection    │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │ Barracuda ESG    │  │ Cisco Secure     │  │ Check Point      │          │
│  │ Syslog           │  │ Email (IronPort) │  │ Harmony (Avanan) │          │
│  │ CEF Format       │  │ Syslog/API       │  │ REST API         │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│  ┌──────────────────┐  ┌──────────────────┐                                │
│  │ Trend Micro      │  │ Cloudflare       │                                │
│  │ Email Security   │  │ Area 1           │                                │
│  │ REST API         │  │ Webhooks/Logs    │                                │
│  └──────────────────┘  └──────────────────┘                                │
│                                                                              │
│  TIER 3: HUMAN SIGNAL PIPELINES (Fastest Phishing Detection)                │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │ Cofense Vision   │  │ Report-Phish     │  │ KnowBe4 PhishER  │          │
│  │ Triage API       │  │ Mailbox Intake   │  │ Reported Emails  │          │
│  │ User Reports     │  │ Ticketing        │  │ Simulation Data  │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Detailed Connector Specifications

| Vendor | Connector Type | Latency | Key Signals | Priority | Docs |
|--------|---------------|---------|-------------|----------|------|
| **Proofpoint TAP** | REST API (SIEM API) | Near real-time | URL clicks, sandbox verdicts, campaign clusters | P0 | [SIEM API](https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API) |
| **Mimecast** | Event Push / S3 | Real-time | Message events, URL rewrites, impersonation | P0 | [Event Push](https://mimecastsupport.zendesk.com/hc/en-us/articles/46199274657683) |
| **Microsoft Defender O365** | Graph API / Streaming | Real-time | AIR investigations, safe links, safe attachments | P0 | Graph Security API |
| **Google Workspace** | Admin SDK / Alert Center | Minutes | Gmail logs, phishing verdicts, DLP | P0 | Admin SDK |
| **Abnormal Security** | REST API | Near real-time | BEC detection, account takeover, VEC | P0 | [Abnormal API](https://abnormal.ai/resources/abnormal-technology-integrations) |
| **Barracuda ESG** | Syslog (CEF) | Real-time | Gateway verdicts, quarantine, ATP | P1 | [Syslog Integration](https://campus.barracuda.com/product/emailgatewaydefense/doc/167976685/syslog-integration/) |
| **Cisco Secure Email** | Syslog / API | Real-time | IronPort verdicts, URL filtering, AMP | P1 | [Chronicle Parser](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/cisco-email-security) |
| **Check Point Harmony** | REST API | Near real-time | Avanan detections, collaboration security | P1 | [API Reference](https://sc1.checkpoint.com/documents/Harmony_Email_and_Collaboration_API_Reference/) |
| **Trend Micro Email** | REST API | Minutes | Policy events, mail tracking, sandbox | P1 | [Service Integration](https://docs.trendmicro.com/en-us/documentation/article/trend-micro-email-security-online-help-service-integration) |
| **Cloudflare Area 1** | Webhooks / Log Ingest | Near real-time | Phishing verdicts, BEC, credential theft | P2 | [Humio Integration](https://library.humio.com/integrations/integrations-cloudflare-package-area1-config.html) |
| **Cofense Vision** | REST API | User-driven | Reported phishing, triage verdicts, IOCs | P1 | [Vision API](https://xsoar.pan.dev/docs/reference/integrations/cofense-vision) |
| **KnowBe4 PhishER** | REST API | User-driven | User reports, simulation results | P2 | PhishER API |

### 1.3 Integration Pattern Selection

```python
# File: src/connectors/email/integration_patterns.py

"""
Email Connector Integration Patterns

PATTERN SELECTION GUIDE:
- Push (webhooks/event push): Best for "minutes matter" phishing response
- Pull (polling REST APIs): Good for backfill and rate-limited sources
- Syslog/CEF: Universal connector for legacy/on-prem systems
- S3 Push: Best for high-volume long-term analytics
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Optional


class IntegrationPattern(str, Enum):
    """Integration pattern types."""
    WEBHOOK_PUSH = "webhook_push"      # Real-time, event-driven
    REST_POLL = "rest_poll"            # Periodic polling
    SYSLOG_CEF = "syslog_cef"          # Universal log forwarding
    S3_PUSH = "s3_push"                # Batch analytics
    GRAPH_STREAMING = "graph_stream"   # Microsoft Graph subscriptions


@dataclass
class ConnectorConfig:
    """Connector configuration template."""
    vendor: str
    pattern: IntegrationPattern
    latency_seconds: int
    supports_backfill: bool
    requires_webhook_endpoint: bool
    rate_limit_per_minute: Optional[int]
    event_types: List[str]
    
    # Authentication
    auth_type: str  # "api_key", "oauth2", "basic", "certificate"
    
    # Endpoint details
    base_url: Optional[str] = None
    webhook_path: Optional[str] = None
    syslog_port: Optional[int] = None


# Recommended configurations per vendor
CONNECTOR_CONFIGS = {
    "proofpoint_tap": ConnectorConfig(
        vendor="Proofpoint TAP",
        pattern=IntegrationPattern.REST_POLL,
        latency_seconds=60,
        supports_backfill=True,
        requires_webhook_endpoint=False,
        rate_limit_per_minute=60,
        event_types=[
            "clicks_blocked", "clicks_permitted",
            "messages_blocked", "messages_delivered"
        ],
        auth_type="basic",
        base_url="https://tap-api-v2.proofpoint.com"
    ),
    
    "mimecast": ConnectorConfig(
        vendor="Mimecast",
        pattern=IntegrationPattern.WEBHOOK_PUSH,
        latency_seconds=5,
        supports_backfill=False,
        requires_webhook_endpoint=True,
        rate_limit_per_minute=None,  # Push = no rate limit
        event_types=[
            "url_protect", "attachment_protect",
            "impersonation_protect", "message_release"
        ],
        auth_type="api_key",
        webhook_path="/webhooks/mimecast/events"
    ),
    
    "abnormal": ConnectorConfig(
        vendor="Abnormal Security",
        pattern=IntegrationPattern.REST_POLL,
        latency_seconds=30,
        supports_backfill=True,
        requires_webhook_endpoint=False,
        rate_limit_per_minute=100,
        event_types=[
            "account_takeover", "bec_attack",
            "vendor_email_compromise", "malware"
        ],
        auth_type="oauth2",
        base_url="https://api.abnormalsecurity.com"
    ),
    
    "barracuda": ConnectorConfig(
        vendor="Barracuda ESG",
        pattern=IntegrationPattern.SYSLOG_CEF,
        latency_seconds=1,
        supports_backfill=False,
        requires_webhook_endpoint=False,
        rate_limit_per_minute=None,
        event_types=[
            "message_blocked", "message_quarantined",
            "atp_scan", "outbound_blocked"
        ],
        auth_type="certificate",
        syslog_port=514
    ),
    
    "cisco_secure_email": ConnectorConfig(
        vendor="Cisco Secure Email (IronPort)",
        pattern=IntegrationPattern.SYSLOG_CEF,
        latency_seconds=1,
        supports_backfill=False,
        requires_webhook_endpoint=False,
        rate_limit_per_minute=None,
        event_types=[
            "message_filter", "content_filter",
            "amp_verdict", "url_filtering"
        ],
        auth_type="certificate",
        syslog_port=514
    ),
    
    "microsoft_defender": ConnectorConfig(
        vendor="Microsoft Defender for Office 365",
        pattern=IntegrationPattern.GRAPH_STREAMING,
        latency_seconds=10,
        supports_backfill=True,
        requires_webhook_endpoint=True,
        rate_limit_per_minute=1000,
        event_types=[
            "safe_links_click", "safe_attachments_verdict",
            "zap_action", "air_investigation",
            "threat_explorer_event"
        ],
        auth_type="oauth2",
        base_url="https://graph.microsoft.com/v1.0/security"
    ),
    
    "cofense_vision": ConnectorConfig(
        vendor="Cofense Vision",
        pattern=IntegrationPattern.REST_POLL,
        latency_seconds=60,
        supports_backfill=True,
        requires_webhook_endpoint=False,
        rate_limit_per_minute=60,
        event_types=[
            "user_reported_phish", "triage_verdict",
            "ioc_extraction", "quarantine_action"
        ],
        auth_type="api_key",
        base_url="https://vision.cofense.com/api"
    ),
}
```

---

## PART 2: HUMAN SIGNAL INTEGRATION (FASTEST DETECTION)

### 2.1 Why Human Signals Matter

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PHISHING DETECTION SPEED COMPARISON                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Detection Method              │ Typical Time to Detect │ False Positive %  │
│  ─────────────────────────────┼────────────────────────┼─────────────────── │
│  User Reports (Cofense/etc)   │ 1-5 minutes            │ 30-40% (triageable)│
│  Behavioral AI (Abnormal)     │ 5-15 minutes           │ 5-10%              │
│  Email Gateway (Proofpoint)   │ 0-60 minutes           │ 10-20%             │
│  Threat Intel Feeds           │ Hours to days          │ 5%                 │
│  Retrospective Analysis       │ Days to weeks          │ <1%                │
│                                                                              │
│  KEY INSIGHT: User reports are often the FIRST signal for novel phishing    │
│  campaigns because humans detect social engineering that AI misses.         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Cofense Vision Integration

```python
# File: src/connectors/email/cofense_vision.py

"""
Cofense Vision Connector

USER-REPORTED PHISHING = GOLD SIGNAL

CAPABILITIES:
- Ingest user-reported phishing emails
- Automated triage and IOC extraction
- Quarantine/retract similar messages
- Cluster analysis for campaign detection

API DOCS: https://cofense.com/knowledge-center-hub/email-security-resources/vision-solution-brief
"""

import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.schemas.email import NormalizedEmailEvent, EmailVerdict, ThreatType


@dataclass
class CofenseConfig:
    """Cofense Vision API configuration."""
    api_token: str
    base_url: str = "https://vision.cofense.com/api/v2"
    poll_interval_seconds: int = 60


class CofenseVisionConnector:
    """
    Cofense Vision connector for user-reported phishing.
    
    WHY THIS MATTERS:
    - Users detect novel phishing that bypasses SEG
    - Human intuition catches social engineering
    - Reported emails become IOC sources
    - Enables "crowd-sourced" threat intelligence
    """
    
    def __init__(self, config: CofenseConfig):
        self.config = config
        self._last_poll = datetime.utcnow() - timedelta(hours=1)
    
    async def fetch_reported_threats(self) -> List[NormalizedEmailEvent]:
        """
        Fetch user-reported phishing emails.
        
        RETURNS:
        - Reported emails with triage status
        - Extracted IOCs (URLs, domains, hashes)
        - Cluster/campaign information
        """
        events = []
        
        async with aiohttp.ClientSession() as session:
            # Fetch new reports since last poll
            headers = {
                "Authorization": f"Bearer {self.config.api_token}",
                "Content-Type": "application/json"
            }
            
            # Get reported messages
            reports_url = f"{self.config.base_url}/reports"
            params = {
                "createdAfter": self._last_poll.isoformat(),
                "status": "new,triaged,malicious",
                "limit": 100
            }
            
            async with session.get(reports_url, headers=headers, params=params) as resp:
                if resp.status != 200:
                    raise Exception(f"Cofense API error: {resp.status}")
                
                data = await resp.json()
                
                for report in data.get("reports", []):
                    event = self._normalize_report(report)
                    events.append(event)
            
            # Also fetch triage verdicts
            triage_url = f"{self.config.base_url}/triage/verdicts"
            params = {
                "updatedAfter": self._last_poll.isoformat(),
                "limit": 100
            }
            
            async with session.get(triage_url, headers=headers, params=params) as resp:
                if resp.status == 200:
                    triage_data = await resp.json()
                    for verdict in triage_data.get("verdicts", []):
                        # Update corresponding report with verdict
                        self._update_verdict(events, verdict)
        
        self._last_poll = datetime.utcnow()
        return events
    
    def _normalize_report(self, report: Dict[str, Any]) -> NormalizedEmailEvent:
        """
        Normalize user-reported phishing to unified schema.
        
        USER REPORTS INCLUDE:
        - Original email headers/body
        - Reporter identity
        - Report timestamp (critical for response time)
        - Extracted IOCs
        """
        # Extract IOCs from report
        iocs = report.get("indicators", {})
        urls = [{"url": u, "verdict": "suspicious"} for u in iocs.get("urls", [])]
        
        return NormalizedEmailEvent(
            event_id=f"cofense_{report.get('id', '')}",
            event_type="user_reported_phishing",
            timestamp=datetime.fromisoformat(report.get("reportedAt", "").replace("Z", "")),
            source_platform="cofense_vision",
            
            # Original message details
            message_id=report.get("originalMessageId"),
            sender=report.get("sender"),
            sender_domain=self._extract_domain(report.get("sender", "")),
            recipient=report.get("recipient"),
            subject=report.get("subject"),
            
            # User report metadata (HIGH VALUE)
            was_reported=True,
            reported_by=report.get("reporterEmail"),
            report_timestamp=datetime.fromisoformat(report.get("reportedAt", "").replace("Z", "")),
            reporter_comment=report.get("reporterComment"),
            
            # Triage status
            triage_status=report.get("triageStatus", "pending"),
            triage_verdict=self._map_triage_verdict(report.get("verdict")),
            
            # Extracted IOCs
            urls=urls,
            url_count=len(urls),
            has_suspicious_url=len(urls) > 0,
            
            # Attachments
            attachments=[
                {
                    "filename": a.get("filename"),
                    "sha256": a.get("sha256"),
                    "md5": a.get("md5"),
                }
                for a in report.get("attachments", [])
            ],
            attachment_count=len(report.get("attachments", [])),
            
            # Cluster/campaign
            cluster_id=report.get("clusterId"),
            similar_reports_count=report.get("similarReportsCount", 0),
            
            # Verdict
            verdict=EmailVerdict.UNKNOWN,  # Pending triage
            threat_type=ThreatType.PHISHING,  # User suspected phishing
            threat_score=0.7,  # User reports have baseline credibility
            
            # User signal confidence boost
            human_reported=True,
            human_confidence_boost=0.2,  # Add 20% to any AI verdict
            
            raw_event=report
        )
    
    def _map_triage_verdict(self, verdict: Optional[str]) -> str:
        """Map Cofense triage verdict to normalized status."""
        mapping = {
            "malicious": "confirmed_threat",
            "suspicious": "likely_threat",
            "spam": "spam",
            "clean": "false_positive",
            "simulation": "simulation",
        }
        return mapping.get(verdict, "pending")
    
    def _update_verdict(self, events: List[NormalizedEmailEvent], verdict: Dict):
        """Update event with triage verdict."""
        report_id = verdict.get("reportId")
        for event in events:
            if event.event_id == f"cofense_{report_id}":
                event.triage_verdict = self._map_triage_verdict(verdict.get("verdict"))
                event.triage_analyst = verdict.get("analystEmail")
                event.triage_timestamp = datetime.fromisoformat(
                    verdict.get("verdictAt", "").replace("Z", "")
                )
                
                # Update threat score based on verdict
                if verdict.get("verdict") == "malicious":
                    event.threat_score = 0.95
                    event.verdict = EmailVerdict.BLOCKED
                elif verdict.get("verdict") == "clean":
                    event.threat_score = 0.1
                    event.verdict = EmailVerdict.DELIVERED
                break
    
    def _extract_domain(self, email: str) -> Optional[str]:
        """Extract domain from email address."""
        if "@" in email:
            return email.split("@")[-1].lower()
        return None
    
    async def search_similar_messages(
        self,
        iocs: Dict[str, List[str]],
        tenant_id: str
    ) -> List[Dict[str, Any]]:
        """
        Search for similar messages across tenant.
        
        USE CASE: After user reports phishing, find all similar 
        messages delivered to other users for bulk remediation.
        """
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.config.api_token}"}
            
            search_url = f"{self.config.base_url}/messages/search"
            
            # Search by sender, subject patterns, URLs
            search_queries = []
            
            if iocs.get("email"):
                search_queries.append({"field": "sender", "values": iocs["email"]})
            
            if iocs.get("domain"):
                search_queries.append({"field": "senderDomain", "values": iocs["domain"]})
            
            if iocs.get("url"):
                search_queries.append({"field": "urlContains", "values": iocs["url"][:10]})
            
            results = []
            for query in search_queries:
                async with session.post(search_url, headers=headers, json=query) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results.extend(data.get("messages", []))
            
            return results
    
    async def quarantine_similar_messages(
        self,
        message_ids: List[str],
        reason: str
    ) -> Dict[str, Any]:
        """
        Quarantine similar messages after confirmed threat.
        
        RESPONSE ACTION: Remove threats from other mailboxes.
        """
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {self.config.api_token}"}
            
            quarantine_url = f"{self.config.base_url}/messages/quarantine"
            payload = {
                "messageIds": message_ids,
                "reason": reason,
                "notifyUsers": True
            }
            
            async with session.post(quarantine_url, headers=headers, json=payload) as resp:
                return await resp.json()
```

### 2.3 Report-Phish Mailbox Integration

```python
# File: src/connectors/email/report_phish_mailbox.py

"""
Report-Phish Mailbox Connector

For organizations without Cofense/KnowBe4, a simple report-phish
mailbox (e.g., phishing@company.com) is the minimum viable human signal.

INTEGRATION:
- Monitor shared mailbox via Graph API / IMAP
- Auto-extract reported email as attachment
- Parse headers/body for IOCs
- Create triage ticket
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import email
from email import policy
import base64
import hashlib
import re

from src.schemas.email import NormalizedEmailEvent, ThreatType, EmailVerdict


class ReportPhishMailboxConnector:
    """
    Monitor a report-phish mailbox for user-reported threats.
    
    SETUP REQUIREMENTS:
    1. Create shared mailbox: phishing@company.com
    2. Train users to forward suspicious emails as attachments
    3. Grant API access to this connector
    4. Configure auto-triage rules
    """
    
    # Common report-phish mailbox patterns
    REPORT_MAILBOX_PATTERNS = [
        "phishing@", "reportphish@", "spam@", "abuse@",
        "security@", "suspicious@", "phish@"
    ]
    
    def __init__(self, graph_client, mailbox_address: str):
        self.graph_client = graph_client
        self.mailbox = mailbox_address
    
    async def fetch_new_reports(self, since: datetime) -> List[NormalizedEmailEvent]:
        """
        Fetch new phishing reports from mailbox.
        
        EXPECTED FORMAT:
        - User forwards suspicious email AS ATTACHMENT (.eml or .msg)
        - Subject line may contain "[SUSPICIOUS]" or similar
        """
        events = []
        
        # Query mailbox for new messages
        messages = await self.graph_client.get_messages(
            mailbox=self.mailbox,
            filter=f"receivedDateTime ge {since.isoformat()}",
            select="id,subject,from,receivedDateTime,hasAttachments,body"
        )
        
        for msg in messages:
            if msg.get("hasAttachments"):
                # Get attachments (the reported email)
                attachments = await self.graph_client.get_attachments(msg["id"])
                
                for att in attachments:
                    if att.get("name", "").endswith((".eml", ".msg")):
                        # Parse the reported email
                        reported_email = self._parse_reported_email(att)
                        
                        if reported_email:
                            event = NormalizedEmailEvent(
                                event_id=f"rpmb_{msg['id']}_{att['id']}",
                                event_type="user_reported_phishing",
                                timestamp=datetime.fromisoformat(
                                    msg["receivedDateTime"].replace("Z", "")
                                ),
                                source_platform="report_phish_mailbox",
                                
                                # Reporter info
                                reported_by=msg["from"]["emailAddress"]["address"],
                                report_timestamp=datetime.fromisoformat(
                                    msg["receivedDateTime"].replace("Z", "")
                                ),
                                
                                # Reported email details
                                sender=reported_email.get("from"),
                                sender_domain=reported_email.get("from_domain"),
                                recipient=reported_email.get("to"),
                                subject=reported_email.get("subject"),
                                message_id=reported_email.get("message_id"),
                                
                                # Extracted IOCs
                                urls=reported_email.get("urls", []),
                                url_count=len(reported_email.get("urls", [])),
                                
                                attachments=reported_email.get("attachments", []),
                                attachment_count=len(reported_email.get("attachments", [])),
                                
                                # Auth results from headers
                                spf_result=reported_email.get("spf"),
                                dkim_result=reported_email.get("dkim"),
                                dmarc_result=reported_email.get("dmarc"),
                                
                                # Verdict
                                was_reported=True,
                                human_reported=True,
                                verdict=EmailVerdict.UNKNOWN,
                                threat_type=ThreatType.PHISHING,
                                threat_score=0.6,  # Baseline for user report
                                
                                raw_event={"report_msg": msg, "reported_email": reported_email}
                            )
                            events.append(event)
        
        return events
    
    def _parse_reported_email(self, attachment: Dict) -> Optional[Dict[str, Any]]:
        """
        Parse the forwarded email attachment.
        
        EXTRACTS:
        - Headers (From, To, Subject, Message-ID)
        - Authentication results (SPF, DKIM, DMARC)
        - URLs in body
        - Attachment hashes
        """
        try:
            # Decode attachment content
            content = base64.b64decode(attachment.get("contentBytes", ""))
            
            # Parse email
            msg = email.message_from_bytes(content, policy=policy.default)
            
            result = {
                "from": msg.get("From", ""),
                "from_domain": self._extract_domain(msg.get("From", "")),
                "to": msg.get("To", ""),
                "subject": msg.get("Subject", ""),
                "message_id": msg.get("Message-ID", ""),
                "date": msg.get("Date", ""),
            }
            
            # Parse authentication results
            auth_results = msg.get("Authentication-Results", "")
            result["spf"] = self._extract_auth_result(auth_results, "spf")
            result["dkim"] = self._extract_auth_result(auth_results, "dkim")
            result["dmarc"] = self._extract_auth_result(auth_results, "dmarc")
            
            # Extract URLs from body
            body = self._get_email_body(msg)
            result["urls"] = self._extract_urls(body)
            
            # Extract attachment info
            result["attachments"] = []
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    filename = part.get_filename()
                    content = part.get_payload(decode=True)
                    if content:
                        result["attachments"].append({
                            "filename": filename,
                            "sha256": hashlib.sha256(content).hexdigest(),
                            "size": len(content),
                            "content_type": part.get_content_type(),
                        })
            
            return result
            
        except Exception as e:
            print(f"Failed to parse reported email: {e}")
            return None
    
    def _get_email_body(self, msg) -> str:
        """Extract email body (prefer HTML, fallback to text)."""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/html":
                    body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    break
                elif content_type == "text/plain" and not body:
                    body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
        else:
            body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
        
        return body
    
    def _extract_urls(self, text: str) -> List[Dict[str, str]]:
        """Extract URLs from email body."""
        # URL regex pattern
        url_pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
        urls = re.findall(url_pattern, text)
        
        return [{"url": url, "verdict": "unknown"} for url in set(urls)]
    
    def _extract_domain(self, email_addr: str) -> Optional[str]:
        """Extract domain from email address."""
        match = re.search(r'@([a-zA-Z0-9.-]+)', email_addr)
        return match.group(1).lower() if match else None
    
    def _extract_auth_result(self, auth_header: str, check_type: str) -> Optional[str]:
        """Extract SPF/DKIM/DMARC result from Authentication-Results header."""
        pattern = rf'{check_type}=(\w+)'
        match = re.search(pattern, auth_header.lower())
        return match.group(1) if match else None
```

---

## PART 3: SUPPLY CHAIN ATTACK CORRELATION

### 3.1 The Shai-Hulud Attack Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              SHAI-HULUD STYLE SUPPLY CHAIN ATTACK CHAIN                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  STAGE 1: INITIAL ACCESS (Email)                                            │
│  ┌─────────────────────────────────────────┐                                │
│  │ Phishing email targeting developer       │                                │
│  │ - npm/PyPI account credential theft      │                                │
│  │ - OAuth consent for GitHub/GitLab        │                                │
│  │ - CI/CD secret exfiltration             │                                │
│  └──────────────────┬──────────────────────┘                                │
│                     │                                                        │
│                     ▼                                                        │
│  STAGE 2: CREDENTIAL COMPROMISE (Identity)                                   │
│  ┌─────────────────────────────────────────┐                                │
│  │ Stolen credentials used to:              │                                │
│  │ - Login to package registry              │                                │
│  │ - OAuth token grants repo access         │                                │
│  │ - Access CI/CD secrets                   │                                │
│  └──────────────────┬──────────────────────┘                                │
│                     │                                                        │
│                     ▼                                                        │
│  STAGE 3: CODE COMPROMISE (Cloud/DevOps)                                     │
│  ┌─────────────────────────────────────────┐                                │
│  │ Malicious code injection:                │                                │
│  │ - Publish poisoned npm/PyPI package      │                                │
│  │ - Modify CI/CD pipeline                  │                                │
│  │ - Add backdoor to repository             │                                │
│  └──────────────────┬──────────────────────┘                                │
│                     │                                                        │
│                     ▼                                                        │
│  STAGE 4: DOWNSTREAM IMPACT (Endpoint/Network)                               │
│  ┌─────────────────────────────────────────┐                                │
│  │ Malware execution:                       │                                │
│  │ - Developer machines infected            │                                │
│  │ - Build servers compromised              │                                │
│  │ - Customer deployments backdoored        │                                │
│  └─────────────────────────────────────────┘                                │
│                                                                              │
│  DETECTION OPPORTUNITY: Email is Stage 1 - earliest intervention point      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

Reference: [Microsoft Shai-Hulud 2.0 Guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)

### 3.2 Supply Chain Detection Rules

```python
# File: src/detection/supply_chain_rules.py

"""
Supply Chain Attack Detection Rules

Detects Shai-Hulud style attacks by correlating:
- Email (phishing targeting developers)
- Identity (credential theft, OAuth grants)
- Cloud/DevOps (repo access, package publishing)
- Endpoint (malicious package execution)

CRITICAL: These rules target the EARLIEST stage (email)
to prevent downstream supply chain compromise.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass

from src.schemas.email import NormalizedEmailEvent, ThreatType
from src.detection.base import DetectionRule, RuleMatch, Severity


class DeveloperTargetedPhishing(DetectionRule):
    """
    RULE: Phishing email specifically targeting developers
    
    SEVERITY: HIGH (supply chain risk)
    
    SIGNALS:
    - Recipient role: developer, engineer, devops, SRE
    - Content mentions: npm, pypi, github, gitlab, CI/CD
    - URLs to: package registries, code platforms
    - OAuth consent requests
    
    WHY THIS MATTERS:
    Developer credentials are the keys to the software supply chain.
    A single compromised developer can poison packages used by millions.
    """
    
    rule_id = "EMAIL-SC-001"
    rule_name = "Developer-Targeted Phishing (Supply Chain Risk)"
    mitre_techniques = ["T1566", "T1195.002", "T1528"]
    
    # Keywords indicating developer targeting
    DEVELOPER_KEYWORDS = [
        # Package managers
        "npm", "pypi", "pip", "yarn", "nuget", "rubygems", "cargo", "maven",
        "package", "dependency", "module", "library",
        
        # Code platforms
        "github", "gitlab", "bitbucket", "azure devops", "codecommit",
        "repository", "repo", "commit", "pull request", "merge",
        
        # CI/CD
        "jenkins", "travis", "circleci", "github actions", "gitlab ci",
        "pipeline", "build", "deploy", "ci/cd", "workflow",
        
        # Credentials
        "api key", "access token", "secret", "credential", "ssh key",
        "personal access token", "pat", "deploy key",
        
        # OAuth
        "oauth", "authorize", "permission", "grant access", "connect app",
    ]
    
    # High-risk domains in URLs
    SUPPLY_CHAIN_DOMAINS = [
        "npmjs.com", "npmjs.org", "registry.npmjs.org",
        "pypi.org", "pypi.python.org", "files.pythonhosted.org",
        "github.com", "gitlab.com", "bitbucket.org",
        "rubygems.org", "nuget.org", "crates.io",
    ]
    
    # Developer role patterns
    DEVELOPER_ROLES = [
        "dev", "developer", "engineer", "swe", "sde",
        "devops", "sre", "platform", "infrastructure",
        "security", "secops", "appsec", "devsecops",
        "data", "ml", "ai", "backend", "frontend", "fullstack",
    ]
    
    def evaluate(self, event: NormalizedEmailEvent) -> Optional[RuleMatch]:
        signals = []
        severity = Severity.MEDIUM
        
        # Check 1: Is recipient a developer?
        recipient = (event.recipient or "").lower()
        is_developer = any(role in recipient for role in self.DEVELOPER_ROLES)
        
        if is_developer:
            signals.append(f"Targeting developer role: {event.recipient}")
        
        # Check 2: Supply chain keywords in subject/body
        subject = (event.subject or "").lower()
        body = (event.body_preview or "").lower()
        content = subject + " " + body
        
        found_keywords = [kw for kw in self.DEVELOPER_KEYWORDS if kw in content]
        if found_keywords:
            signals.append(f"Supply chain keywords: {', '.join(found_keywords[:5])}")
            severity = Severity.HIGH
        
        # Check 3: URLs to package registries / code platforms
        for url_info in event.urls:
            url = (url_info.get("url") or url_info.url if hasattr(url_info, "url") else "").lower()
            domain = url_info.get("domain") or ""
            
            if any(scd in url or scd in domain for scd in self.SUPPLY_CHAIN_DOMAINS):
                signals.append(f"Link to supply chain platform: {url[:100]}")
                severity = Severity.HIGH
        
        # Check 4: OAuth consent indicators
        if event.oauth_consent_attempted:
            signals.append("OAuth consent request detected")
            severity = Severity.CRITICAL
        
        # Check 5: Impersonation of code platform
        sender_domain = (event.sender_domain or "").lower()
        if any(platform in sender_domain for platform in ["github", "gitlab", "npm", "pypi"]):
            # Check if it's spoofed (auth failures)
            if event.spf_result == "fail" or event.dmarc_result == "fail":
                signals.append(f"Spoofed code platform sender: {event.sender}")
                severity = Severity.CRITICAL
        
        # Check 6: Lookalike domains for code platforms
        lookalike_patterns = [
            "github", "git-hub", "g1thub", "githuub",
            "gitlab", "git-lab", "g1tlab",
            "npmjs", "npm-js", "nprnjs",
        ]
        if any(pattern in sender_domain for pattern in lookalike_patterns):
            if sender_domain not in ["github.com", "gitlab.com", "npmjs.com"]:
                signals.append(f"Lookalike domain: {sender_domain}")
                severity = Severity.CRITICAL
        
        # Need developer targeting + at least one supply chain signal
        if is_developer and len(signals) >= 2:
            return RuleMatch(
                rule_id=self.rule_id,
                severity=severity,
                confidence=min(0.5 + len(signals) * 0.1, 0.95),
                description=f"Supply chain phishing targeting developer {event.recipient}",
                evidence=signals + [
                    f"Sender: {event.sender}",
                    f"Subject: {event.subject}",
                ],
                recommended_actions=[
                    f"Block email and quarantine immediately",
                    f"Alert {event.recipient} - DO NOT click links or authorize apps",
                    "Check if user has npm/PyPI maintainer access",
                    "Review recent OAuth grants for user",
                    "Check repository access logs",
                    "Notify security team for supply chain investigation",
                ],
                supply_chain_context={
                    "risk_type": "credential_theft_for_supply_chain",
                    "potential_impact": "package_poisoning",
                    "urgency": "prevent_before_credential_use",
                },
                decision_gate={
                    "question": f"Block sender domain {event.sender_domain} and alert developer?",
                    "urgency": "immediate",
                    "auto_action_timeout_minutes": 10,
                }
            )
        
        return None


class SupplyChainAttackChain(DetectionRule):
    """
    RULE: Multi-stage supply chain attack detected
    
    CORRELATION CHAIN:
    Email → Identity → DevOps/Cloud → Endpoint
    
    STAGES:
    1. Phishing email to developer (email)
    2. Credential compromise / OAuth grant (identity)
    3. Repository/Package access (cloud)
    4. Malicious code execution (endpoint)
    """
    
    rule_id = "EMAIL-SC-002"
    rule_name = "Supply Chain Attack Chain Detected"
    mitre_techniques = ["T1566", "T1078", "T1195.002", "T1059"]
    
    async def evaluate_chain(
        self,
        email_event: NormalizedEmailEvent,
        identity_events: List[Dict],
        devops_events: List[Dict],
        endpoint_events: List[Dict],
        time_window_hours: int = 24
    ) -> Optional[RuleMatch]:
        """
        Correlate email with downstream supply chain activity.
        """
        stages = []
        chain_start = email_event.timestamp
        
        # Stage 1: Phishing email (already detected)
        stages.append({
            "stage": 1,
            "name": "Developer Phishing Email",
            "timestamp": email_event.timestamp,
            "evidence": f"Email to {email_event.recipient}: {email_event.subject}",
            "confidence": 0.7
        })
        
        # Stage 2: Identity compromise
        user = email_event.recipient
        for id_event in sorted(identity_events, key=lambda e: e.get("timestamp", datetime.min)):
            event_time = id_event.get("timestamp")
            if not self._in_window(chain_start, event_time, time_window_hours):
                continue
            
            event_type = id_event.get("event_type", "")
            
            # OAuth grant to suspicious app
            if event_type == "oauth_grant":
                app_name = id_event.get("app_name", "").lower()
                scopes = id_event.get("scopes", [])
                
                if any(s in str(scopes).lower() for s in ["repo", "write", "admin", "package"]):
                    stages.append({
                        "stage": 2,
                        "name": "OAuth Token Granted",
                        "timestamp": event_time,
                        "evidence": f"App: {app_name}, Scopes: {scopes}",
                        "confidence": 0.85
                    })
            
            # Login from new location
            elif event_type == "login" and id_event.get("risk_level") in ["high", "medium"]:
                stages.append({
                    "stage": 2,
                    "name": "Suspicious Login",
                    "timestamp": event_time,
                    "evidence": f"Login from {id_event.get('ip')} ({id_event.get('geo')})",
                    "confidence": 0.75
                })
            
            # npm/PyPI login
            elif event_type in ["npm_login", "pypi_login"]:
                stages.append({
                    "stage": 2,
                    "name": "Package Registry Login",
                    "timestamp": event_time,
                    "evidence": f"Registry: {event_type.replace('_login', '')}",
                    "confidence": 0.9
                })
        
        # Stage 3: DevOps/Cloud activity
        for devops_event in sorted(devops_events, key=lambda e: e.get("timestamp", datetime.min)):
            event_time = devops_event.get("timestamp")
            if not self._in_window(chain_start, event_time, time_window_hours):
                continue
            
            event_type = devops_event.get("event_type", "")
            
            # Repository access
            if event_type == "repo_clone" or event_type == "repo_push":
                stages.append({
                    "stage": 3,
                    "name": "Repository Access",
                    "timestamp": event_time,
                    "evidence": f"Repo: {devops_event.get('repo_name')}, Action: {event_type}",
                    "confidence": 0.8
                })
            
            # Package publish
            elif event_type in ["npm_publish", "pypi_publish"]:
                stages.append({
                    "stage": 3,
                    "name": "Package Published",
                    "timestamp": event_time,
                    "evidence": f"Package: {devops_event.get('package_name')}, Version: {devops_event.get('version')}",
                    "confidence": 0.95
                })
            
            # CI/CD modification
            elif event_type == "pipeline_modified":
                stages.append({
                    "stage": 3,
                    "name": "CI/CD Pipeline Modified",
                    "timestamp": event_time,
                    "evidence": f"Pipeline: {devops_event.get('pipeline_name')}",
                    "confidence": 0.85
                })
            
            # Secret access
            elif event_type == "secret_accessed":
                stages.append({
                    "stage": 3,
                    "name": "CI/CD Secret Accessed",
                    "timestamp": event_time,
                    "evidence": f"Secret: {devops_event.get('secret_name')}",
                    "confidence": 0.9
                })
        
        # Stage 4: Endpoint execution (malicious package installed)
        for ep_event in sorted(endpoint_events, key=lambda e: e.get("timestamp", datetime.min)):
            event_time = ep_event.get("timestamp")
            if not self._in_window(chain_start, event_time, time_window_hours):
                continue
            
            event_type = ep_event.get("event_type", "")
            
            # npm/pip install of suspicious package
            if event_type == "package_install":
                stages.append({
                    "stage": 4,
                    "name": "Malicious Package Installed",
                    "timestamp": event_time,
                    "evidence": f"Package: {ep_event.get('package_name')} on {ep_event.get('hostname')}",
                    "confidence": 0.9
                })
            
            # Suspicious process from node_modules or site-packages
            elif event_type == "process_create":
                process_path = ep_event.get("process_path", "").lower()
                if "node_modules" in process_path or "site-packages" in process_path:
                    stages.append({
                        "stage": 4,
                        "name": "Code Execution from Package",
                        "timestamp": event_time,
                        "evidence": f"Process: {ep_event.get('process_name')} from {process_path}",
                        "confidence": 0.85
                    })
        
        # Need at least 2 stages to form chain
        if len(stages) >= 2:
            # Calculate chain severity
            if len(stages) >= 4:
                severity = Severity.CRITICAL
            elif len(stages) >= 3:
                severity = Severity.HIGH
            else:
                severity = Severity.HIGH
            
            avg_confidence = sum(s["confidence"] for s in stages) / len(stages)
            
            return RuleMatch(
                rule_id=self.rule_id,
                severity=severity,
                confidence=avg_confidence,
                description=f"Supply chain attack chain: {len(stages)} stages detected starting from phishing email",
                evidence=[f"Stage {s['stage']}: {s['name']} - {s['evidence']}" for s in stages],
                attack_chain={
                    "chain_type": "supply_chain",
                    "stages": stages,
                    "timeline": [
                        {"stage": s["stage"], "timestamp": s["timestamp"].isoformat() if hasattr(s["timestamp"], "isoformat") else str(s["timestamp"])}
                        for s in stages
                    ],
                },
                recommended_actions=[
                    "CRITICAL: Potential supply chain compromise",
                    f"Revoke all OAuth tokens for {user}",
                    "Audit recent package publishes",
                    "Check for modified CI/CD pipelines",
                    "Scan all developer endpoints for malware",
                    "Review repository commit history",
                    "Consider public disclosure if packages were poisoned",
                ],
                decision_gate={
                    "question": "Initiate supply chain incident response?",
                    "urgency": "immediate",
                    "options": ["Full IR", "Targeted Investigation", "Monitor"],
                }
            )
        
        return None
    
    def _in_window(self, start: datetime, event_time, hours: int) -> bool:
        """Check if event is within time window."""
        if not event_time:
            return False
        if isinstance(event_time, str):
            event_time = datetime.fromisoformat(event_time.replace("Z", ""))
        return start <= event_time <= start + timedelta(hours=hours)
```

---

## PART 4: ENHANCED NORMALIZED SCHEMA

### File: `src/schemas/email.py` (Extended)

```python
# Add these fields to NormalizedEmailEvent for supply chain and human signal support

class NormalizedEmailEvent(BaseModel):
    """Extended schema with supply chain and human signal fields."""
    
    # ... (existing fields from previous version) ...
    
    # ==========================================================================
    # HUMAN SIGNAL FIELDS (User Reports)
    # ==========================================================================
    
    was_reported: bool = False
    reported_by: Optional[str] = None
    report_timestamp: Optional[datetime] = None
    reporter_comment: Optional[str] = None
    
    # Triage workflow
    triage_status: Optional[str] = None  # "pending", "in_progress", "completed"
    triage_verdict: Optional[str] = None  # "confirmed_threat", "likely_threat", "false_positive"
    triage_analyst: Optional[str] = None
    triage_timestamp: Optional[datetime] = None
    
    # Human signal confidence
    human_reported: bool = False
    human_confidence_boost: float = 0.0  # Add to AI confidence
    
    # Similar message clustering
    cluster_id: Optional[str] = None
    similar_reports_count: int = 0
    
    # ==========================================================================
    # SUPPLY CHAIN ATTACK FIELDS
    # ==========================================================================
    
    # Developer targeting indicators
    targets_developer: bool = False
    developer_role_detected: Optional[str] = None  # "backend", "devops", "security"
    
    # Package registry indicators
    references_package_registry: bool = False
    package_registries_mentioned: List[str] = Field(default_factory=list)  # ["npm", "pypi"]
    
    # Code platform indicators
    references_code_platform: bool = False
    code_platforms_mentioned: List[str] = Field(default_factory=list)  # ["github", "gitlab"]
    
    # CI/CD indicators
    references_cicd: bool = False
    cicd_platforms_mentioned: List[str] = Field(default_factory=list)  # ["jenkins", "actions"]
    
    # OAuth/Token theft indicators
    oauth_consent_attempted: bool = False
    oauth_scopes_requested: List[str] = Field(default_factory=list)
    
    # Supply chain risk score (0-1)
    supply_chain_risk_score: float = 0.0
    
    # ==========================================================================
    # CROSS-DOMAIN CORRELATION FIELDS
    # ==========================================================================
    
    # For correlating with identity events
    affected_user_id: Optional[str] = None
    affected_user_roles: List[str] = Field(default_factory=list)
    
    # For correlating with endpoint events
    affected_endpoint: Optional[str] = None
    
    # For correlating with cloud/DevOps events
    related_repositories: List[str] = Field(default_factory=list)
    related_packages: List[str] = Field(default_factory=list)
    
    # Chain membership
    attack_chain_id: Optional[str] = None
    attack_chain_stage: Optional[int] = None
    
    def calculate_supply_chain_risk(self) -> float:
        """
        Calculate supply chain risk score based on signals.
        
        SCORING:
        - Developer targeting: +0.3
        - Package registry reference: +0.2
        - Code platform reference: +0.2
        - CI/CD reference: +0.2
        - OAuth attempt: +0.3
        - Auth failures: +0.1
        """
        score = 0.0
        
        if self.targets_developer:
            score += 0.3
        
        if self.references_package_registry:
            score += 0.2
        
        if self.references_code_platform:
            score += 0.2
        
        if self.references_cicd:
            score += 0.2
        
        if self.oauth_consent_attempted:
            score += 0.3
        
        if self.spf_result == "fail" or self.dmarc_result == "fail":
            score += 0.1
        
        self.supply_chain_risk_score = min(score, 1.0)
        return self.supply_chain_risk_score
```

---

## PART 5: IMPLEMENTATION ROADMAP

### Priority Matrix

| Priority | Component | Files | Effort | Impact |
|----------|-----------|-------|--------|--------|
| **P0** | Proofpoint TAP connector | `proofpoint_tap.py` | 2 days | High - click-time verdicts |
| **P0** | Mimecast Event Push | `mimecast.py` | 1 day | High - real-time push |
| **P0** | Cofense Vision (human signals) | `cofense_vision.py` | 2 days | **Critical** - fastest detection |
| **P0** | Supply chain phishing rules | `supply_chain_rules.py` | 2 days | **Critical** - Shai-Hulud defense |
| **P1** | Abnormal Security connector | `abnormal.py` | 1 day | High - BEC detection |
| **P1** | Report-phish mailbox | `report_phish_mailbox.py` | 1 day | Medium - backup human signal |
| **P1** | Microsoft Defender O365 | `defender_o365.py` | 2 days | High - native M365 |
| **P1** | Supply chain correlation | `supply_chain_correlation.py` | 3 days | High - multi-stage detection |
| **P2** | Barracuda syslog | `barracuda.py` | 1 day | Medium - legacy support |
| **P2** | Cisco IronPort syslog | `cisco_email.py` | 1 day | Medium - legacy support |

### Week-by-Week Plan

**Week 1-2: Core Connectors**
- Proofpoint TAP API integration
- Mimecast Event Push webhook handler
- Normalized email schema v2

**Week 3-4: Human Signals**
- Cofense Vision integration
- Report-phish mailbox monitoring
- User report → IOC extraction pipeline

**Week 5-6: Supply Chain Detection**
- Developer-targeted phishing rules
- Supply chain attack chain correlation
- Identity + DevOps data integration

**Week 7-8: Advanced Correlation**
- Cross-domain correlation engine
- Multi-stage attack chain detection
- Persona-specific email reports

---

## EXPECTED OUTCOMES

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Time to detect novel phishing | 4 hours | **5 minutes** (human reports) | 98% faster |
| BEC detection rate | 50% | 92% | +84% |
| Supply chain attack visibility | 0% | 85% | ∞ |
| Developer credential theft detection | 20% | 90% | +350% |
| False positive rate | 25% | 8% | 68% reduction |
| Cross-domain attack chain detection | None | Full chain | ∞ |

---

## KEY INSIGHTS

### 1. Human Signals are Gold
User-reported phishing is often the **fastest** detection signal because:
- Users detect social engineering that AI misses
- Novel campaigns bypass SEG before signatures exist
- Internal context (unusual sender behavior) is human intuition

**Implementation**: Prioritize Cofense Vision or report-phish mailbox integration.

### 2. Click-Time Verdicts > Delivery-Time
Proofpoint/Mimecast URL rewriting enables **click-time analysis**:
- URLs can change after delivery (time-delayed activation)
- Click-time verdict is the ground truth
- Click events include user context (IP, user agent)

**Implementation**: Ensure connectors capture click events, not just delivery events.

### 3. Supply Chain is the New Frontier
Shai-Hulud proves that email is the first stage of supply chain attacks:
- Developers are high-value targets (npm/PyPI maintainer access)
- OAuth consent phishing grants persistent code access
- One compromised developer can poison packages with millions of weekly downloads

**Implementation**: Prioritize developer-targeted phishing detection and cross-domain correlation.

### 4. Multi-Signal Correlation Reduces FP
Single-signal detection (email only) has high FP rates. Correlation with:
- Identity (was credential used after click?)
- Endpoint (was attachment opened?)
- Cloud/DevOps (was repo accessed?)

...dramatically increases confidence and reduces alert fatigue.

**Implementation**: Build correlation engine that joins email → identity → endpoint → cloud.
