"""Ingestion worker skeleton.

This worker accepts normalized events from parsers and forwards them to
correlation hooks (HopGraph or other correlation engines). It is lightweight
and intended as a scaffold.
"""
from typing import Dict, Any, Iterable
import logging

from ..hopgraph.ingest_queue import enqueue_event

logger = logging.getLogger(__name__)


def process_event_batch(events: Iterable[Dict[str, Any]], correlate: bool = True) -> Dict[str, Any]:
    """Process a batch of normalized events and enqueue to HopGraph queue.

    Returns a summary containing processed count and affected session ids.
    """
    processed = 0
    sessions = set()
    for ev in events:
        try:
            _index_event(ev)
            if correlate:
                try:
                    sid = enqueue_event(ev)
                    sessions.add(sid)
                except Exception:
                    logger.exception('failed enqueuing to hopgraph')
            processed += 1
        except Exception:
            logger.exception('failed processing event')

    return {'processed': processed, 'sessions': list(sessions)}


def _index_event(ev: Dict[str, Any]) -> None:
    # In production, index to Elastic/Clickhouse, etc. Here we just log.
    logger.debug('index_event: %s', {k: ev.get(k) for k in ('type','src_ip','dst_ip')})
