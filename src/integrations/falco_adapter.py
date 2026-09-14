"""Adapter to consume Falco JSON events (file or stream), enrich via ebpf_correlation,
and emit incidents into the platform."""
from __future__ import annotations

import json
from typing import Iterable, Dict, Any

from src.core import ebpf_correlation


def process_falco_stream(lines: Iterable[str]) -> int:
    """Process an iterable of Falco JSON lines. Returns number of incidents emitted."""
    count = 0
    batch = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        ev = ebpf_correlation.parse_falco_event(obj)
        batch.append(ev)
        # process in small batches
        if len(batch) >= 10:
            enriched = ebpf_correlation.correlate_batch(batch)
            for e in enriched:
                res = ebpf_correlation.emit_incident(e)
                if res.get('status'):
                    count += 1
            batch = []
    # flush remaining
    if batch:
        enriched = ebpf_correlation.correlate_batch(batch)
        for e in enriched:
            res = ebpf_correlation.emit_incident(e)
            if res.get('status'):
                count += 1
    return count


def process_falco_file(path: str) -> int:
    with open(path, 'r', encoding='utf-8') as fh:
        return process_falco_stream(fh)
from typing import Any, Dict, List, Optional, Tuple
import time

try:
    from .connector_base import ConnectorBase
except Exception:
    from src.integrations.connector_base import ConnectorBase  # type: ignore

def _lookup_vulns(file_hash: str) -> List[Dict[str, Any]]:
    try:
        from src.integrations.sbom import lookup_vulns_for_hash  # type: ignore
        return lookup_vulns_for_hash(file_hash)
    except Exception:
        try:
            from src.integrations.vuln_enrichment import enrich_components  # type: ignore
            comps = [{"name": "binary", "version": file_hash, "hash": file_hash}]
            enriched = enrich_components(comps)
            return enriched or []
        except Exception:
            return [{"cve": "CVE-TEST-0001", "severity": "medium"}]


class FalcoAdapter(ConnectorBase):
    """
    Falco eBPF consumer scaffold. Normalizes event and enriches via SBOM lookup.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._cursor: Optional[str] = None

    async def connect(self) -> bool:
        return True

    async def fetch_since(self, since: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        base_ts = int(time.time())
        events: List[Dict[str, Any]] = []
        for i in range(2):
            raw = {
                "ts": base_ts + i,
                "process": f"falco_target{i}",
                "file_hash": f"deadbeef{i}",
                "event": "write",
                "user": "root",
            }
            ev = self.canonical_event(raw)
            ev["vulns"] = _lookup_vulns(ev.get("file_hash") or "")
            # Optionally add KEV/EPSS if available
            try:
                from src.integrations.vuln_enrichment import kev_lookup, epss_lookup  # type: ignore
                kev = kev_lookup(ev["vulns"]) if ev.get("vulns") else {}
                epss = epss_lookup(ev["vulns"]) if ev.get("vulns") else {}
                ev["kev"] = kev
                ev["epss"] = epss
            except Exception:
                pass
            events.append(ev)
        return events, str(base_ts + 2)

    async def ack(self, cursor: Optional[str]) -> bool:
        self._cursor = cursor or self._cursor
        return True

    async def health(self) -> Dict[str, Any]:
        return {"connected": True, "cursor": self._cursor}

    def canonical_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ts": raw.get("ts") or int(time.time()),
            "process": raw.get("process"),
            "file_hash": raw.get("file_hash"),
            "event": raw.get("event"),
            "user": raw.get("user"),
        }
