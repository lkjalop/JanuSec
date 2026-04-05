"""EVTX Ingestion Scaffold

Parses Windows EVTX logs using optional python-evtx dependency; falls back to
line-oriented heuristic if library missing. Normalizes events for downstream
pipeline consumption.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from typing import Any, Dict

logger = logging.getLogger(__name__)

try:  # optional heavy dependency
    from Evtx.Evtx import Evtx  # type: ignore
except Exception:  # pragma: no cover
    Evtx = None  # type: ignore


def _heuristic_iter(raw: bytes) -> Iterable[dict[str, Any]]:
    # Split by newline and fabricate minimal events (useful for tests / dry runs)
    lines = raw.decode(errors='ignore').splitlines()
    base_ts = time.time()
    out = []
    for i, line in enumerate(lines[:500]):  # cap to 500 to bound memory
        if not line.strip():
            continue
        out.append({
            'timestamp': base_ts + i * 0.001,
            'event_id': 0,
            'provider': 'heuristic',
            'channel': 'Unknown',
            'message': line.strip()[:400],
            'ingest_source': 'evtx_heuristic'
        })
    return out


def parse_evtx_bytes(raw: bytes) -> Iterable[dict[str, Any]]:
    if Evtx is None:
        return _heuristic_iter(raw)
    try:
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(raw)
            path = f.name
        out = []
        with Evtx(path) as log:  # type: ignore
            for i, record in enumerate(log.records()):  # type: ignore
                if i >= 5000:  # safety cap
                    break
                try:
                    eid = int(record.event_id())  # type: ignore
                except Exception:
                    eid = 0
                try:
                    provider = record.provider_name()  # type: ignore
                except Exception:
                    provider = 'Unknown'
                try:
                    channel = record.channel()  # type: ignore
                except Exception:
                    channel = 'Unknown'
                msg = ''
                try:
                    xml = record.xml()  # type: ignore
                    msg = xml[:600]
                except Exception:
                    pass
                out.append({
                    'timestamp': time.time(),
                    'event_id': eid,
                    'provider': provider,
                    'channel': channel,
                    'message': msg,
                    'ingest_source': 'evtx_lib'
                })
        try:
            os.unlink(path)
        except Exception:
            pass
        return out
    except Exception as exc:  # pragma: no cover
        logger.debug('EVTX parse failed; fallback heuristic: %s', exc)
        return _heuristic_iter(raw)
