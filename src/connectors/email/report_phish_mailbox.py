from typing import List, Dict, Any, Optional
import time
import hashlib
import asyncio
import base64
import re
from datetime import datetime
from email import policy, message_from_bytes

from src.schemas.email import NormalizedEmailEvent
from src.enrichment.email_auth import enrich_email_auth
from src.enrichment.url_normalizer import enrich_urls
from src.enrichment.sandbox_enrichment import enrich_sandbox


class ReportPhishMailboxConnector:
    """Polling connector for a report mailbox that supports both sync and async graph clients.

    The connector will call `graph.get_messages(mailbox, since=...)` and
    `graph.get_attachments(message_id)`; if those return coroutines the
    connector will await them using the running event loop.
    """

    def __init__(self, graph_client=None, mailbox_address: str = "phishing@tenant.local"):
        self.graph_client = graph_client
        self.mailbox = mailbox_address

    def _hash_attachment(self, content_bytes: bytes) -> str:
        return hashlib.sha256(content_bytes).hexdigest()

    def _maybe_await(self, val):
        if asyncio.iscoroutine(val):
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Running loop: create a new task and wait synchronously (best-effort)
                    return loop.run_until_complete(val)
                else:
                    return loop.run_until_complete(val)
            except Exception:
                return asyncio.run(val)
        return val

    def fetch_new_reports(self, since: Optional[datetime] = None) -> List[NormalizedEmailEvent]:
        events: List[NormalizedEmailEvent] = []
        if not self.graph_client:
            return events

        msgs = self._maybe_await(self.graph_client.get_messages(self.mailbox, since=since))
        for msg in msgs or []:
            # Support two patterns: attachments provided inline on the message
            # dict (test-friendly) or provided via graph_client.get_attachments
            attachments = msg.get("attachments") or []
            if not attachments and msg.get("hasAttachments"):
                attachments = self._maybe_await(self.graph_client.get_attachments(msg.get("id")))

            for att in attachments or []:
                name = att.get("name", "")
                if not name.lower().endswith((".eml", ".msg")):
                    continue
                parsed = self._parse_attachment(att)
                if not parsed:
                    continue
                ne = NormalizedEmailEvent(
                    event_id=f"rpmb_{msg.get('id')}_{att.get('id')}",
                    timestamp=parsed.get("timestamp") or time.time(),
                    source_platform="report_phish_mailbox",
                    message_id=parsed.get("message_id"),
                    sender=parsed.get("from"),
                    sender_domain=parsed.get("from_domain"),
                    recipient=parsed.get("to"),
                    subject=parsed.get("subject"),
                    urls=[{"url": u, "verdict": "unknown"} for u in parsed.get("urls", [])],
                    url_count=len(parsed.get("urls", [])),
                    attachments=parsed.get("attachments", []),
                    attachment_count=len(parsed.get("attachments", [])),
                    was_reported=True,
                    human_reported=True,
                    raw_event={"report_msg": msg, "reported_email": parsed},
                )
                # Immediate enrichment after ingestion
                try:
                    enrich_email_auth(ne)
                    enrich_urls(ne)
                    enrich_sandbox(ne)
                except Exception:
                    # best-effort; do not block ingestion
                    pass
                # fingerprint original attached .eml if content present
                content_raw = att.get("contentBytes") or att.get("content")
                if content_raw:
                    try:
                        if isinstance(content_raw, str):
                            content_bytes = content_raw.encode("utf-8")
                        else:
                            content_bytes = content_raw
                        fp = self._hash_attachment(content_bytes)
                        ne.raw_event["forwarded_eml_hash"] = fp
                    except Exception:
                        pass
                events.append(ne)

        return events

    def _parse_attachment(self, attachment: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            content_b64 = attachment.get("contentBytes") or attachment.get("content") or b""
            # Some collectors provide raw text instead of base64; try to decode safely
            if isinstance(content_b64, str):
                try:
                    content = base64.b64decode(content_b64)
                except Exception:
                    content = content_b64.encode("utf-8")
            else:
                # bytes
                try:
                    content = base64.b64decode(content_b64)
                except Exception:
                    content = content_b64
            msg = message_from_bytes(content, policy=policy.default)
            result: Dict[str, Any] = {}
            result["from"] = msg.get("From")
            result["from_domain"] = self._extract_domain(result["from"] or "")
            result["to"] = msg.get("To")
            result["subject"] = msg.get("Subject")
            result["message_id"] = msg.get("Message-ID")
            # best-effort timestamp
            result["timestamp"] = None
            body = self._get_body(msg)
            result["urls"] = list(set(self._extract_urls(body)))
            result["attachments"] = []
            for part in msg.iter_attachments():
                payload = part.get_payload(decode=True)
                if payload:
                    result["attachments"].append({
                        "filename": part.get_filename(),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size": len(payload),
                        "content_type": part.get_content_type(),
                    })
            return result
        except Exception:
            return None

    def _get_body(self, msg) -> str:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    return part.get_payload(decode=True).decode(errors="ignore")
                if part.get_content_type() == "text/plain":
                    return part.get_payload(decode=True).decode(errors="ignore")
            return ""
        else:
            return msg.get_payload(decode=True).decode(errors="ignore")

    def _extract_urls(self, text: str) -> List[str]:
        pattern = r'https?://[^\s<>"]+|www\.[^\s<>\"]+'
        return re.findall(pattern, text or "")

    def _extract_domain(self, email_addr: str) -> Optional[str]:
        m = re.search(r"@([A-Za-z0-9.-]+)", email_addr)
        return m.group(1).lower() if m else None


__all__ = ["ReportPhishMailboxConnector"]
