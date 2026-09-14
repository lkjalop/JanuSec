"""IPFIX adapter: use pyfixbuf if available, otherwise fallback to CSV parsing.

This module exposes `parse_ipfix_stream(stream)` which yields normalized
flow records. In production prefer a dedicated IPFIX collector; this adapter
provides a convenient local alternative.
"""
from __future__ import annotations

from typing import Iterable, Dict
import importlib
import logging

logger = logging.getLogger(__name__)
from pathlib import Path
import json
import time

TEMPLATE_STORE = Path('data/sessions/templates')
TEMPLATE_STORE.mkdir(parents=True, exist_ok=True)


def _exporter_key(exporter: dict) -> str:
    ip = exporter.get('ip')
    port = exporter.get('port')
    return f"{ip}_{port}"


def merge_templates_for_exporter(exporter: dict, templates) -> dict:
    """Merge incoming templates for an exporter into the persistent registry.

    `templates` may be a list or mapping. We keep track of template ids, first_seen, last_seen, and count.
    Returns the merged registry for the exporter.
    """
    if not exporter or not isinstance(exporter, dict):
        return {}
    key = _exporter_key(exporter)
    path = TEMPLATE_STORE / f"{key}.json"
    now = time.time()
    existing = {'templates': {}}
    if path.exists():
        try:
            existing = json.loads(path.read_text())
        except Exception:
            existing = {'templates': {}}

    tmpl_map = existing.get('templates', {}) or {}

    # normalize incoming templates into a dict keyed by template_id if present
    incoming = {}
    if isinstance(templates, dict):
        incoming = templates
    else:
        try:
            for t in templates:
                tid = None
                if isinstance(t, dict):
                    tid = t.get('template_id') or t.get('id')
                if tid is None:
                    # fallback: use hash of representation
                    tid = str(hash(json.dumps(t, sort_keys=True)))
                incoming[tid] = t
        except Exception:
            incoming = {}

    # merge
    for tid, t in incoming.items():
        if tid in tmpl_map:
            entry = tmpl_map[tid]
            entry['last_seen'] = now
            entry['count'] = entry.get('count', 1) + 1
        else:
            tmpl_map[tid] = {'template': t, 'first_seen': now, 'last_seen': now, 'count': 1}

    out = {'templates': tmpl_map, 'updated_ts': now}
    try:
        path.write_text(json.dumps(out))
    except Exception:
        pass
    return out


def list_templates(exporter: dict | None = None):
    """List template registries. If exporter provided, return that registry."""
    if exporter:
        key = _exporter_key(exporter)
        path = TEMPLATE_STORE / f"{key}.json"
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                return {}
        return {}
    # list all
    out = {}
    for p in TEMPLATE_STORE.glob('*.json'):
        k = p.stem
        try:
            out[k] = json.loads(p.read_text())
        except Exception:
            out[k] = {}
    return out


def _has_pyfixbuf() -> bool:
    try:
        importlib.import_module('pyfixbuf')
        return True
    except Exception:
        return False


def parse_ipfix_stream(stream: Iterable[bytes]) -> Iterable[Dict[str, any]]:
    """Parse an iterable of IPFIX messages (bytes) or CSV text lines.

    If `pyfixbuf` is installed, use it to decode records. Otherwise treat the
    input as UTF-8 lines and forward to the CSV netflow parser.
    """
    if _has_pyfixbuf():
        # Use pyfixbuf to decode flow records into dictionaries
        pyfixbuf = importlib.import_module('pyfixbuf')

        # Map common IPFIX field names to canonical keys
        FIELD_MAP = {
            'sourceIPv4Address': 'src_ip',
            'sourceIPv6Address': 'src_ip',
            'destinationIPv4Address': 'dst_ip',
            'destinationIPv6Address': 'dst_ip',
            'sourceTransportPort': 'src_port',
            'destinationTransportPort': 'dst_port',
            'protocolIdentifier': 'protocol',
            'packetDeltaCount': 'packets',
            'octetDeltaCount': 'bytes',
            'flowStartMilliseconds': 'timestamp',
            'flowEndMilliseconds': 'end_ts',
            'sourceMacAddress': 'src_mac',
            'destinationMacAddress': 'dst_mac',
        }

        try:
            # Create ONE collector for the entire stream so record indices are
            # global across all messages (each message is a PDU in the same
            # session). Creating a new Collector per message resets the
            # enumeration counter and produces duplicate index values.
            col = pyfixbuf.Collector()
            for msg in stream:
                try:
                    col.addMsg(msg)
                except Exception:
                    try:
                        col.add(msg)
                    except Exception:
                        pass

            recs = []
            try:
                for rec in col:
                    recs.append(rec)
            except Exception:
                # Fallback: try convenience decode per accumulated messages
                try:
                    recs = pyfixbuf.decode(col)
                except Exception:
                    recs = []

            for r in recs:
                out = {'type': 'ipfix.record', 'raw': r}
                # r might be a mapping-like object; ensure attribute access
                for k, v in FIELD_MAP.items():
                    try:
                        if k in r:
                            out[v] = r.get(k)
                    except Exception:
                        try:
                            out[v] = getattr(r, k)
                        except Exception:
                            continue

                # numeric coercions
                for p in ('src_port', 'dst_port', 'packets', 'bytes'):
                    if p in out and out[p] is not None:
                        try:
                            out[p] = int(out[p])
                        except Exception:
                            pass
                # timestamp normalization if present
                if 'timestamp' in out and out['timestamp'] is not None:
                    try:
                        out['timestamp'] = float(out['timestamp']) / 1000.0
                    except Exception:
                        try:
                            out['timestamp'] = float(out['timestamp'])
                        except Exception:
                            pass

                # best-effort: persist template info per-exporter if present
                try:
                    exporter = r.get('exporter') if isinstance(r, dict) else None
                    if exporter and isinstance(exporter, dict):
                        templates = r.get('_templates') or r.get('templates')
                        if templates:
                            try:
                                merge_templates_for_exporter(exporter, templates)
                            except Exception:
                                pass
                except Exception:
                    pass
                yield out
        except Exception:
            # If anything fails, fall back to CSV parsing below
            pass
        else:
            # If the pyfixbuf path completed without exception, don't run
            # the CSV fallback to avoid duplicating records.
            return

    # fallback: treat the stream as text lines for the CSV parser
    from .netflow_parser import parse_netflow_csv_lines

    # decode bytes if necessary
    lines = []
    for item in stream:
        if isinstance(item, bytes):
            try:
                lines.append(item.decode('utf-8'))
            except Exception:
                lines.append(str(item))
        else:
            lines.append(str(item))

    for ev in parse_netflow_csv_lines(lines):
        yield ev
