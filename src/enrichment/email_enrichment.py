from __future__ import annotations

"""Email enrichment stage: extract URLs/attachments, basic phishing heuristics,
and emit factors/nodes for HopGraph ingestion.
"""
from typing import Dict, Any, List
import logging
import re

from src.live.event_models import EmailEvent

logger = logging.getLogger(__name__)


URL_RE = re.compile(r"https?://[\w\.-/:?&=%]+")


def extract_urls_from_preview(ev: EmailEvent) -> List[str]:
    text = (ev.body_preview or '') + ' ' + ' '.join(ev.headers.keys() if ev.headers else [])
    return list(set(URL_RE.findall(text)))


def basic_phish_signals(ev: EmailEvent) -> List[str]:
    signals = []
    try:
        subj = (ev.subject or '').lower()
        sender = (ev.sender or '').lower()
        # Subject-sender mismatch heuristics
        if subj and sender and any(w in subj for w in ['invoice', 'payment', 'urgent', 'password']):
            if '@' in sender and not sender.endswith(('@trusted.com', '@example.com')):
                signals.append('subject_action_urgent')
        # suspicious domain in sender
        if sender and 'noreply' in sender:
            signals.append('noreply_sender')
    except Exception:
        pass
    return signals


def enrich_email(ev: EmailEvent) -> Dict[str, Any]:
    """Return enrichment dict with urls, attachments metadata, and factors."""
    urls = extract_urls_from_preview(ev)
    signals = basic_phish_signals(ev)
    attachments = []
    try:
        # naive attachments detection from has_attachments and headers
        if ev.has_attachments:
            attachments.append({'count': 1})
    except Exception:
        pass

    enrichment = {
        'email_enrichment': {
            'urls': urls,
            'attachments': attachments,
            'signals': signals,
        }
    }

    # Hook: append to HopGraph ingestion (simple stub). Real implementation should
    # call HopGraph client helpers to create nodes/edges.
    try:
        # import here to avoid hard dependency
        from src.graph import hopgraph_client as _hg  # type: ignore
        # Example: create minimal artifact nodes for urls
        for u in urls:
            try:
                _hg.ingest_artifact({'type': 'url', 'value': u, 'source': ev.source, 'tenant_id': ev.tenant_id})
            except Exception:
                logger.debug('HopGraph ingest stub failed for url %s', u)
    except Exception:
        # If hopgraph client not available, skip
        pass

    return enrichment


__all__ = ['enrich_email', 'extract_urls_from_preview', 'basic_phish_signals']
