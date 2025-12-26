"""SBOM Vulnerability Aggregation Repository

Maintains per-tenant component vulnerability severity counts and metadata.
Lightweight in-memory structure with optional JSONL persistence for restart resilience.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from typing import Dict, Optional, Tuple

_LOCK = threading.Lock()
_AGG: dict[tuple[str,str], SbomVulnAggregate] = {}
_PERSIST_PATH = os.getenv('SBOM_VULN_AGG_PATH','data/sbom_vuln_aggregates.jsonl')

@dataclass
class SbomVulnAggregate:
    tenant: str
    component_key: str  # name:version
    severity_counts: dict[str,int]
    first_seen: float
    last_seen: float
    oldest_vuln_ts: float  # earliest vulnerability observation
    total_vulns: int
    # Optional: track the maximum observed CVSS base score for this component
    cvss_max: float = 0.0

    def update(self, sev: str, ts: float):
        self.last_seen = ts
        self.severity_counts[sev] = self.severity_counts.get(sev,0) + 1
        self.total_vulns += 1
        if ts < self.oldest_vuln_ts:
            self.oldest_vuln_ts = ts

def _persist_line(rec: SbomVulnAggregate):  # append only
    try:
        os.makedirs(os.path.dirname(_PERSIST_PATH), exist_ok=True)
        with open(_PERSIST_PATH,'a',encoding='utf-8') as fh:
            fh.write(json.dumps(asdict(rec))+"\n")
    except Exception:
        pass

def record_vulnerability(tenant: str, component_key: str, severity: str, ts: float | None=None, cvss_score: float | None = None):
    ts = ts or time.time()
    sev = (severity or 'unknown').lower()
    if sev not in ('critical','high','medium','low','unknown'):
        sev = 'unknown'
    key = (tenant, component_key)
    with _LOCK:
        agg = _AGG.get(key)
        if not agg:
            agg = SbomVulnAggregate(
                tenant=tenant,
                component_key=component_key,
                severity_counts={},
                first_seen=ts,
                last_seen=ts,
                oldest_vuln_ts=ts,
                total_vulns=0,
                cvss_max=0.0
            )
            _AGG[key] = agg
        agg.update(sev, ts)
        try:
            if cvss_score is not None:
                score = float(cvss_score)
                if score > agg.cvss_max:
                    agg.cvss_max = score
        except Exception:
            pass
        _persist_line(agg)

def get_aggregate(tenant: str, component_key: str) -> SbomVulnAggregate | None:
    return _AGG.get((tenant, component_key))

def snapshot(tenant: str | None=None):
    out = []
    for (t, _ck), agg in list(_AGG.items()):
        if tenant and t != tenant:
            continue
        out.append(asdict(agg))
    return out

def load_existing():
    if not os.path.exists(_PERSIST_PATH):
        return
    try:
        with open(_PERSIST_PATH,encoding='utf-8') as fh:
            for line in fh:
                line=line.strip()
                if not line: continue
                try:
                    data=json.loads(line)
                    agg = SbomVulnAggregate(
                        tenant=data.get('tenant'),
                        component_key=data.get('component_key'),
                        severity_counts=data.get('severity_counts',{}),
                        first_seen=data.get('first_seen',time.time()),
                        last_seen=data.get('last_seen',time.time()),
                        oldest_vuln_ts=data.get('oldest_vuln_ts',time.time()),
                        total_vulns=data.get('total_vulns',0),
                        cvss_max=float(data.get('cvss_max', 0.0) or 0.0),
                    )
                    _AGG[(agg.tenant, agg.component_key)] = agg
                except Exception:
                    continue
    except Exception:
        pass

# Auto-load on import (best-effort)
try: load_existing()
except Exception: pass
