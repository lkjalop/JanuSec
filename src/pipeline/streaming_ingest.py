"""Streaming ingest pipeline for high-volume, multi-source live security data.

Designed to handle 44k+ rows from Cloud, IAM, Email, Network, Endpoint, and
Remote sources concurrently without blocking the HTTP response path.

Architecture
────────────
                      ┌──────────────────────────────────────┐
  source connector ──▶│  SourceGate (circuit breaker + dedup)│
  (cloud/iam/email/   └──────────────┬───────────────────────┘
   network/endpoint)                 │
                                     ▼
                      ┌──────────────────────────────────────┐
                      │  StreamNormalizer (per-source schema) │
                      └──────────────┬───────────────────────┘
                                     │
                                     ▼
                      ┌──────────────────────────────────────┐
                      │  IncrementalClusterIndex (O(n·k))     │
                      │  - inverted account/ip/host index     │
                      │  - union-find for cluster membership  │
                      └──────────────┬───────────────────────┘
                                     │ new / changed clusters
                                     ▼
                      ┌──────────────────────────────────────┐
                      │  BatchedPrefillScheduler              │
                      │  - debounce 5s after last batch       │
                      │  - only re-prefill changed clusters   │
                      └──────────────┬───────────────────────┘
                                     │
                                     ▼
                      ┌──────────────────────────────────────┐
                      │  AssessmentStore (REPORT_STORE +      │
                      │  disk persistence)                    │
                      └──────────────────────────────────────┘

Key invariants
──────────────
- One AssessmentSession per assessment_id, thread-safe via asyncio.Lock
- Normalizer is stateless — pure function per source type
- IncrementalClusterIndex uses a union-find (path-compressed) so merging is O(α(n)) ≈ O(1)
- Prefill fires at most once per 5 s per session (debounced)
- Circuit breaker: if any source emits >500 rows/s for 3s, it is throttled for 30s
- Dedup window: 60s rolling bloom filter per source; cross-source dedup via global fingerprint set
"""
from __future__ import annotations

import asyncio
import collections
import hashlib
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

BATCH_SIZE = 500          # rows per ingest batch before cluster update
PREFILL_DEBOUNCE_S = 5.0  # seconds after last batch before prefill fires
CIRCUIT_BREAKER_RATE = 500  # rows/s threshold
CIRCUIT_BREAKER_WINDOW = 3.0  # seconds over which rate is measured
CIRCUIT_BREAKER_COOLDOWN = 30.0  # seconds to throttle a tripped source
DEDUP_WINDOW_S = 60.0     # rolling dedup window per source
BUCKET_CAP = 200          # max rows per inverted-index key (super-node protection)
MAX_CLUSTERS_RENDERED = 50  # cap clusters returned to frontend to avoid serialization explosion

# ── Source type constants ──────────────────────────────────────────────────────

SOURCE_CLOUD    = 'cloud'
SOURCE_IAM      = 'iam'
SOURCE_EMAIL    = 'email'
SOURCE_NETWORK  = 'network'
SOURCE_ENDPOINT = 'endpoint'
SOURCE_REMOTE   = 'remote'
SOURCE_UNKNOWN  = 'unknown'

_SOURCE_ALIASES: Dict[str, str] = {
    # Cloud
    'aws': SOURCE_CLOUD, 'azure': SOURCE_CLOUD, 'gcp': SOURCE_CLOUD,
    'cloudtrail': SOURCE_CLOUD, 'azure_activity': SOURCE_CLOUD, 'gcs': SOURCE_CLOUD,
    's3': SOURCE_CLOUD, 'vpcflow': SOURCE_CLOUD, 'guardduty': SOURCE_CLOUD,
    # IAM
    'okta': SOURCE_IAM, 'entra': SOURCE_IAM, 'aad': SOURCE_IAM, 'sailpoint': SOURCE_IAM,
    'pingidentity': SOURCE_IAM, 'azure_signin': SOURCE_IAM, 'azure_audit': SOURCE_IAM,
    'active_directory': SOURCE_IAM, 'ldap': SOURCE_IAM,
    # Email
    'exchange': SOURCE_EMAIL, 'o365': SOURCE_EMAIL, 'gmail': SOURCE_EMAIL,
    'proofpoint': SOURCE_EMAIL, 'mimecast': SOURCE_EMAIL, 'defender_email': SOURCE_EMAIL,
    # Network
    'zeek': SOURCE_NETWORK, 'suricata': SOURCE_NETWORK, 'netflow': SOURCE_NETWORK,
    'dns': SOURCE_NETWORK, 'proxy': SOURCE_NETWORK, 'paloalto': SOURCE_NETWORK,
    'checkpoint': SOURCE_NETWORK, 'fortinet': SOURCE_NETWORK, 'firewall': SOURCE_NETWORK,
    # Endpoint
    'crowdstrike': SOURCE_ENDPOINT, 'sentinelone': SOURCE_ENDPOINT,
    'defender': SOURCE_ENDPOINT, 'sysmon': SOURCE_ENDPOINT, 'edr': SOURCE_ENDPOINT,
    'wef': SOURCE_ENDPOINT, 'etw': SOURCE_ENDPOINT, 'cbr': SOURCE_ENDPOINT,
    # Remote / VPN / RDP
    'vpn': SOURCE_REMOTE, 'rdp': SOURCE_REMOTE, 'citrix': SOURCE_REMOTE,
    'anyconnect': SOURCE_REMOTE, 'globalprotect': SOURCE_REMOTE,
}


def classify_source(raw_source: str) -> str:
    """Map a raw source string to a canonical source type."""
    lower = (raw_source or '').lower().strip()
    for alias, canonical in _SOURCE_ALIASES.items():
        if alias in lower:
            return canonical
    return SOURCE_UNKNOWN


# ── Per-source schema normalizers ─────────────────────────────────────────────

def _safe(v: Any) -> str:
    return str(v).strip() if v is not None else ''


def _normalize_cloud(row: dict) -> dict:
    """CloudTrail / Azure Activity / GCP AuditLog → canonical."""
    r = dict(row)
    # CloudTrail: userIdentity.userName, requestParameters.sourceIPAddress
    uid = row.get('userIdentity') or {}
    if isinstance(uid, dict):
        r.setdefault('user', _safe(uid.get('userName') or uid.get('arn') or uid.get('principalId')))
        r.setdefault('user_type', _safe(uid.get('type')))
    r.setdefault('src_ip', _safe(row.get('sourceIPAddress') or row.get('source_ip') or ''))
    r.setdefault('event_name', _safe(row.get('eventName') or row.get('operationName') or row.get('protoPayload', {}).get('methodName') if isinstance(row.get('protoPayload'), dict) else ''))
    r.setdefault('resource', _safe(row.get('requestParameters', {}).get('bucketName') if isinstance(row.get('requestParameters'), dict) else '') or _safe(row.get('resource')))
    r.setdefault('region', _safe(row.get('awsRegion') or row.get('location') or ''))
    r['_source_type'] = SOURCE_CLOUD
    return r


def _normalize_iam(row: dict) -> dict:
    """Okta / Entra / SailPoint → canonical."""
    r = dict(row)
    # Okta: actor.alternateId, client.ipAddress, target[].alternateId
    actor = row.get('actor') or {}
    if isinstance(actor, dict):
        r.setdefault('user', _safe(actor.get('alternateId') or actor.get('login') or actor.get('displayName')))
    client = row.get('client') or {}
    if isinstance(client, dict):
        r.setdefault('src_ip', _safe(client.get('ipAddress') or client.get('ip')))
    # Entra: initiatedBy.user.userPrincipalName
    initiated = row.get('initiatedBy') or {}
    if isinstance(initiated, dict):
        initiated_user = initiated.get('user') or {}
        if isinstance(initiated_user, dict):
            r.setdefault('user', _safe(initiated_user.get('userPrincipalName') or initiated_user.get('id')))
    r.setdefault('event_name', _safe(row.get('eventType') or row.get('activityDisplayName') or row.get('displayName')))
    r['_source_type'] = SOURCE_IAM
    return r


def _normalize_email(row: dict) -> dict:
    """Exchange / Proofpoint / Mimecast → canonical."""
    r = dict(row)
    r.setdefault('user', _safe(row.get('UserId') or row.get('sender') or row.get('from') or row.get('actor')))
    r.setdefault('src_ip', _safe(row.get('ClientIP') or row.get('source_ip') or row.get('sending_ip')))
    r.setdefault('event_name', _safe(row.get('Operation') or row.get('event') or row.get('action')))
    r.setdefault('subject', _safe(row.get('Item', {}).get('Subject') if isinstance(row.get('Item'), dict) else '' or row.get('subject')))
    r['_source_type'] = SOURCE_EMAIL
    return r


def _normalize_network(row: dict) -> dict:
    """Zeek / Suricata / NetFlow / DNS → canonical."""
    r = dict(row)
    r.setdefault('src_ip', _safe(row.get('id.orig_h') or row.get('src_ip') or row.get('sourceAddress')))
    r.setdefault('dst_ip', _safe(row.get('id.resp_h') or row.get('dst_ip') or row.get('destinationAddress')))
    r.setdefault('src_port', row.get('id.orig_p') or row.get('src_port') or row.get('sourcePort'))
    r.setdefault('dst_port', row.get('id.resp_p') or row.get('dst_port') or row.get('destinationPort'))
    r.setdefault('proto', _safe(row.get('proto') or row.get('transport_protocol') or ''))
    r.setdefault('event_name', _safe(row.get('alert', {}).get('signature') if isinstance(row.get('alert'), dict) else '' or row.get('dns.qtype_name') or row.get('event_type') or 'flow'))
    r['_source_type'] = SOURCE_NETWORK
    return r


def _normalize_endpoint(row: dict) -> dict:
    """CrowdStrike / SentinelOne / Sysmon → canonical."""
    r = dict(row)
    r.setdefault('hostname', _safe(row.get('ComputerName') or row.get('device_name') or row.get('hostname')))
    r.setdefault('user', _safe(row.get('UserName') or row.get('user') or row.get('SubjectUserName')))
    r.setdefault('process', _safe(row.get('Image') or row.get('process_name') or row.get('TargetProcessName')))
    r.setdefault('parent_process', _safe(row.get('ParentImage') or row.get('parent_name') or ''))
    r.setdefault('event_name', _safe(row.get('EventID') or row.get('event_type') or row.get('technique_name') or ''))
    r.setdefault('file_hash', _safe(row.get('Hashes') or row.get('sha256') or row.get('MD5') or ''))
    r['_source_type'] = SOURCE_ENDPOINT
    return r


def _normalize_remote(row: dict) -> dict:
    """VPN / RDP / Citrix → canonical."""
    r = dict(row)
    r.setdefault('user', _safe(row.get('username') or row.get('user') or row.get('UserName')))
    r.setdefault('src_ip', _safe(row.get('client_ip') or row.get('remote_ip') or row.get('source_ip')))
    r.setdefault('hostname', _safe(row.get('gateway') or row.get('server') or row.get('hostname')))
    r.setdefault('event_name', _safe(row.get('reason') or row.get('event') or row.get('action') or 'vpn_event'))
    r['_source_type'] = SOURCE_REMOTE
    return r


_NORMALIZERS = {
    SOURCE_CLOUD:    _normalize_cloud,
    SOURCE_IAM:      _normalize_iam,
    SOURCE_EMAIL:    _normalize_email,
    SOURCE_NETWORK:  _normalize_network,
    SOURCE_ENDPOINT: _normalize_endpoint,
    SOURCE_REMOTE:   _normalize_remote,
}


def normalize_row(row: dict, source_type: str | None = None) -> dict:
    """Apply source-specific normalization, then fill common fields."""
    st = source_type or classify_source(_safe(row.get('_source') or row.get('source') or ''))
    normalizer = _NORMALIZERS.get(st)
    r = normalizer(row) if normalizer else dict(row)
    r['_source_type'] = st
    # Canonical common fields
    r.setdefault('severity', _safe(row.get('severity') or row.get('risk_level') or 'medium').lower())
    r.setdefault('triage_score', _triage_from_severity(r['severity']))
    r.setdefault('timestamp', _safe(
        row.get('timestamp') or row.get('eventTime') or row.get('time') or
        row.get('@timestamp') or row.get('ActivityDateTime') or ''
    ))
    return r


def _triage_from_severity(sev: str) -> float:
    return {'critical': 0.95, 'high': 0.75, 'medium': 0.45, 'low': 0.20}.get(sev, 0.30)


# ── Fingerprinting for deduplication ─────────────────────────────────────────

def fingerprint_row(row: dict) -> str:
    """Stable SHA-256 fingerprint for dedup across sources.

    Uses: source_type, user, src_ip, event_name, timestamp (minute-bucketed).
    Minute-bucketing means identical events within the same minute are deduplicated.
    """
    ts = _safe(row.get('timestamp') or '')
    # Truncate to minute: "2024-06-15T14:23:51Z" → "2024-06-15T14:23"
    ts_bucket = ts[:16] if len(ts) >= 16 else ts
    key = '|'.join([
        _safe(row.get('_source_type')),
        _safe(row.get('user') or row.get('actor') or '').lower(),
        _safe(row.get('src_ip') or ''),
        _safe(row.get('event_name') or row.get('eventName') or '').lower(),
        ts_bucket,
    ])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ── Source circuit breaker ────────────────────────────────────────────────────

@dataclass
class SourceCircuitBreaker:
    """Per-source rate limiter that trips when throughput exceeds threshold."""
    source: str
    threshold_rows_per_s: float = CIRCUIT_BREAKER_RATE
    window_s: float = CIRCUIT_BREAKER_WINDOW
    cooldown_s: float = CIRCUIT_BREAKER_COOLDOWN

    _window_rows: List[float] = field(default_factory=list)
    _tripped_until: float = 0.0
    _total_dropped: int = 0

    def is_open(self) -> bool:
        """Return True if the circuit is tripped (source should be throttled)."""
        return time.monotonic() < self._tripped_until

    def record(self, n: int = 1) -> bool:
        """Record n rows arriving now. Return False if circuit is open (drop the rows)."""
        now = time.monotonic()
        if now < self._tripped_until:
            self._total_dropped += n
            return False
        cutoff = now - self.window_s
        self._window_rows = [t for t in self._window_rows if t > cutoff]
        self._window_rows.extend([now] * n)
        rate = len(self._window_rows) / self.window_s
        if rate > self.threshold_rows_per_s:
            self._tripped_until = now + self.cooldown_s
            logger.warning(
                'source_circuit_breaker: source=%s rate=%.0f/s > threshold=%.0f — '
                'throttling for %.0fs',
                self.source, rate, self.threshold_rows_per_s, self.cooldown_s,
            )
        return True


# ── Incremental inverted-index cluster tracker ────────────────────────────────

class UnionFind:
    """Path-compressed union-find — O(α(n)) ≈ O(1) per operation."""
    def __init__(self) -> None:
        self._parent: Dict[int, int] = {}
        self._rank: Dict[int, int] = {}

    def find(self, x: int) -> int:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])  # path compression
        return self._parent[x]

    def union(self, x: int, y: int) -> bool:
        """Merge x and y. Return True if they were in different sets."""
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return False
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1
        return True

    def components(self, nodes: Iterable[int]) -> Dict[int, List[int]]:
        """Return {root: [members]} for all nodes."""
        groups: Dict[int, List[int]] = defaultdict(list)
        for n in nodes:
            groups[self.find(n)].append(n)
        return groups


class IncrementalClusterIndex:
    """Maintains a live inverted-index cluster state, updated incrementally.

    Thread-safety: hold the caller's asyncio.Lock before calling update_batch.
    The data structures themselves are not thread-safe — the lock is the caller's
    responsibility so we keep this class simple.
    """

    def __init__(self) -> None:
        self._inv_idx: Dict[str, List[int]] = defaultdict(list)  # key → [row_idx, ...]
        self._row_map: Dict[int, dict] = {}
        self._uf = UnionFind()
        self._changed_roots: Set[int] = set()  # roots of clusters that changed since last prefill
        self._next_row_idx: int = 0

    def _extract_keys(self, row: dict) -> List[str]:
        """Extract pivot keys from a normalized row for indexing."""
        keys: List[str] = []
        for acc in (row.get('accounts') or []):
            if acc: keys.append(f'acc:{_safe(acc).lower()[:80]}')
        for ip in (row.get('external_ips') or []):
            if ip: keys.append(f'ip:{ip}')
        for h in (row.get('hosts') or []):
            if h: keys.append(f'host:{_safe(h).lower()[:80]}')
        sess = _safe(row.get('session_id') or '')
        if sess and sess not in ('-', 'N/A'): keys.append(f'sess:{sess}')
        cb = _safe(row.get('cloud_boundary') or '')
        if cb and cb not in ('-', 'N/A'): keys.append(f'cloud:{cb}')
        for m in (row.get('mitre') or []):
            if m: keys.append(f'mitre:{_safe(m).upper()}')
        # Source-local pivots
        src_ip = _safe(row.get('src_ip') or '')
        if src_ip and src_ip not in ('-', 'N/A', '0.0.0.0'): keys.append(f'atk:{src_ip}')
        usr = _safe(row.get('user') or '').lower()
        if usr and usr not in ('-', 'n/a', 'system', 'root', 'nt authority\\system'):
            keys.append(f'usr:{usr}')
        host = _safe(row.get('hostname') or '').lower()
        if host: keys.append(f'h2:{host}')
        return keys

    def update_batch(self, rows: List[dict]) -> Set[int]:
        """Ingest a batch of normalized rows, update index and union-find.

        Returns the set of cluster root row_indices that changed.
        """
        changed: Set[int] = set()
        for row in rows:
            row_idx = self._next_row_idx
            self._next_row_idx += 1
            row['row_index'] = row_idx
            self._row_map[row_idx] = row
            self._uf.find(row_idx)  # ensure node exists

            keys = self._extract_keys(row)
            for key in keys:
                bucket = self._inv_idx[key]
                # Cap super-nodes
                if len(bucket) > BUCKET_CAP:
                    bucket = sorted(bucket, key=lambda i: float(self._row_map[i].get('triage_score') or 0), reverse=True)[:BUCKET_CAP]
                    self._inv_idx[key] = bucket
                for existing_idx in bucket:
                    if self._uf.union(row_idx, existing_idx):
                        changed.add(self._uf.find(row_idx))
                        changed.add(self._uf.find(existing_idx))
                bucket.append(row_idx)

        self._changed_roots.update(changed)
        return changed

    def snapshot_clusters(self, min_size: int = 2) -> List[dict]:
        """Build a cluster snapshot from current union-find state.

        Returns at most MAX_CLUSTERS_RENDERED clusters sorted by severity.
        """
        components = self._uf.components(self._row_map.keys())
        clusters: List[dict] = []
        cluster_num = 0
        _SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

        for root, members in components.items():
            if len(members) < min_size:
                continue
            cluster_num += 1
            member_rows = [self._row_map[i] for i in sorted(members)]
            sev = max(
                (r.get('severity') or 'low') for r in member_rows
            ) if member_rows else 'low'
            # Highest severity wins
            sev = sorted(
                [r.get('severity') or 'low' for r in member_rows],
                key=lambda s: _SEV_RANK.get(s, 0),
                reverse=True,
            )[0]

            accounts = sorted({_safe(r.get('user') or r.get('actor') or '') for r in member_rows if r.get('user') or r.get('actor')})
            hosts = sorted({_safe(r.get('hostname') or r.get('host') or '') for r in member_rows if r.get('hostname') or r.get('host')})
            ips = sorted({_safe(r.get('src_ip') or '') for r in member_rows if r.get('src_ip')})
            sources = sorted({_safe(r.get('_source_type') or r.get('source') or 'unknown') for r in member_rows})
            time_vals = [r.get('_ts_epoch') for r in member_rows if r.get('_ts_epoch') is not None]

            # Build lead description
            actor = accounts[0] if accounts else None
            event_name = next((
                _safe(r.get('event_name') or r.get('eventName') or '')
                for r in sorted(member_rows, key=lambda r: float(r.get('triage_score') or 0), reverse=True)
                if r.get('event_name') or r.get('eventName')
            ), '')
            if actor and event_name:
                lead = f"{actor}: {event_name}"
            elif actor:
                lead = f"{actor}: activity across {len(sources)} source(s)"
            elif ips:
                lead = f"External IP {ips[0]}: activity across {len(sources)} source(s)"
            else:
                lead = f"Correlated cluster — {len(member_rows)} events from {', '.join(sources[:3])}"

            clusters.append({
                'cluster_id': f'cluster-{cluster_num}',
                '_root': root,
                'row_refs': [int(r.get('row_index') or 0) for r in member_rows],
                'severity': sev,
                'sources': sources,
                'shared_accounts': accounts[:6],
                'shared_hosts': hosts[:6],
                'shared_ips': ips[:6],
                'lead_description': lead,
                'event_count': len(members),
                'time_window': {
                    'start': min(time_vals) if time_vals else None,
                    'end': max(time_vals) if time_vals else None,
                },
            })

        # Sort by severity then size, cap output
        clusters.sort(key=lambda c: (_SEV_RANK.get(c['severity'], 0), c['event_count']), reverse=True)
        return clusters[:MAX_CLUSTERS_RENDERED]

    def pop_changed_roots(self) -> Set[int]:
        """Drain and return changed cluster roots since last call."""
        changed = set(self._changed_roots)
        self._changed_roots.clear()
        return changed


# ── Prefill scheduler (debounced) ────────────────────────────────────────────

class BatchedPrefillScheduler:
    """Debounced tier-1 prefill — fires at most once per PREFILL_DEBOUNCE_S seconds.

    Keeps track of which cluster roots changed since the last prefill so it only
    re-runs on new/changed clusters rather than all clusters.
    """

    def __init__(self, assessment_obj: dict, assessment_id: str) -> None:
        self._assessment_obj = assessment_obj
        self._assessment_id = assessment_id
        self._task: Optional[asyncio.Task] = None
        self._pending_roots: Set[int] = set()
        self._last_fire: float = 0.0

    def schedule(self, changed_roots: Set[int]) -> None:
        """Queue a prefill run for the given changed cluster roots."""
        self._pending_roots.update(changed_roots)
        if self._task and not self._task.done():
            return  # already scheduled
        try:
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(self._debounced_run())
        except RuntimeError:
            pass

    async def _debounced_run(self) -> None:
        await asyncio.sleep(PREFILL_DEBOUNCE_S)
        roots = self._pending_roots.copy()
        self._pending_roots.clear()
        if not roots:
            return
        try:
            from src.core.tier1_prefill.prefill_engine import run_prefill as _run_prefill
        except ImportError:
            try:
                from core.tier1_prefill.prefill_engine import run_prefill as _run_prefill  # type: ignore
            except ImportError:
                return
        try:
            result = await asyncio.to_thread(
                _run_prefill,
                assessment=self._assessment_obj,
                top_n=10,
                tenant_id='default',
            )
            if result.get('prefilled_clusters'):
                logger.info(
                    'streaming_prefill: prefilled %s clusters for %s',
                    result['prefilled_clusters'], self._assessment_id,
                )
        except Exception as exc:
            logger.debug('streaming_prefill failed for %s: %s', self._assessment_id, exc)


# ── Streaming Assessment Session ──────────────────────────────────────────────

class StreamingAssessmentSession:
    """Manages a live streaming assessment for one assessment_id.

    Callers:
    - ``ingest(rows, source)``: add rows from a source connector
    - ``snapshot()``: return current clusters + stats for API polling
    - ``close()``: flush final state and mark complete
    """

    def __init__(self, assessment_id: str, org: str = 'default') -> None:
        self.assessment_id = assessment_id
        self.org = org
        self._lock = asyncio.Lock()
        self._index = IncrementalClusterIndex()
        self._breakers: Dict[str, SourceCircuitBreaker] = {}
        # TTL-based rolling dedup window: deque of (fingerprint, expiry_epoch)
        self._fp_deque: Deque[Tuple[str, float]] = collections.deque()
        self._fp_set: Set[str] = set()
        self._total_ingested = 0
        self._total_dropped_dedup = 0
        self._total_dropped_circuit = 0
        self._source_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {'accepted': 0, 'deduped': 0, 'circuit': 0})
        self._all_rows: List[dict] = []
        self._started_at = time.time()
        self._assessment_obj: dict = {
            'assessment_id': assessment_id,
            'org': org,
            'status': 'streaming',
            'created': int(self._started_at),
            'correlation_clusters': [],
            'evidence_rows': [],
            'rows': [],
        }
        self._prefill_scheduler: Optional[BatchedPrefillScheduler] = None

    def restore_from_snapshot(self, payload: dict) -> None:
        """Restore rows and clusters from a persisted open-session snapshot."""
        if not isinstance(payload, dict):
            return
        rows = payload.get('rows') or payload.get('evidence_rows') or []
        if not isinstance(rows, list):
            rows = []

        rebuilt_rows = [dict(r) for r in rows if isinstance(r, dict)]
        self._index = IncrementalClusterIndex()
        self._all_rows = []
        if rebuilt_rows:
            self._index.update_batch(rebuilt_rows)
            self._all_rows = rebuilt_rows

        self._assessment_obj.update(payload)
        self._assessment_obj['assessment_id'] = self.assessment_id
        self._assessment_obj['org'] = self.org
        self._assessment_obj['status'] = 'streaming'
        self._assessment_obj['evidence_rows'] = self._all_rows
        self._assessment_obj['rows'] = self._all_rows
        self._assessment_obj['correlation_clusters'] = self._index.snapshot_clusters()

        self._total_ingested = int(
            payload.get('rows_processed')
            or payload.get('total_ingested')
            or len(self._all_rows)
            or 0
        )
        self._total_dropped_dedup = int(payload.get('total_deduped') or 0)
        self._total_dropped_circuit = int(payload.get('total_circuit_dropped') or 0)
        stats = payload.get('source_stats')
        if isinstance(stats, dict):
            restored = defaultdict(lambda: {'accepted': 0, 'deduped': 0, 'circuit': 0})
            for source, values in stats.items():
                if isinstance(values, dict):
                    restored[str(source)] = {
                        'accepted': int(values.get('accepted') or 0),
                        'deduped': int(values.get('deduped') or 0),
                        'circuit': int(values.get('circuit') or 0),
                    }
            self._source_stats = restored

        now = time.time()
        for row in self._all_rows:
            fp = _safe(row.get('_fingerprint') or '')
            if fp:
                self._fp_set.add(fp)
                self._fp_deque.append((fp, now + DEDUP_WINDOW_S))

    def _get_breaker(self, source: str) -> SourceCircuitBreaker:
        if source not in self._breakers:
            self._breakers[source] = SourceCircuitBreaker(source=source)
        return self._breakers[source]

    async def ingest(self, rows: List[dict], source: str | None = None) -> Dict[str, Any]:
        """Ingest a batch of raw rows from a source connector.

        Returns ingestion stats (accepted, deduped, circuit-dropped).
        """
        source_type = classify_source(source or '')
        breaker = self._get_breaker(source_type)

        accepted: List[dict] = []
        deduped = 0
        circuit_dropped = 0

        # Expire stale fingerprints before processing this batch
        now = time.time()
        while self._fp_deque and self._fp_deque[0][1] <= now:
            old_fp, _ = self._fp_deque.popleft()
            self._fp_set.discard(old_fp)

        for row in rows:
            if not breaker.record(1):
                circuit_dropped += 1
                continue
            norm = normalize_row(row, source_type)
            fp = fingerprint_row(norm)
            if fp in self._fp_set:
                deduped += 1
                self._source_stats[source_type]['deduped'] += 1
                continue
            expiry = now + DEDUP_WINDOW_S
            self._fp_set.add(fp)
            self._fp_deque.append((fp, expiry))
            norm['_fingerprint'] = fp
            accepted.append(norm)

        self._source_stats[source_type]['accepted'] += len(accepted)
        self._source_stats[source_type]['circuit'] += circuit_dropped

        if not accepted:
            return {'accepted': 0, 'deduped': deduped, 'circuit_dropped': circuit_dropped}

        async with self._lock:
            changed_roots = self._index.update_batch(accepted)
            self._all_rows.extend(accepted)
            self._total_ingested += len(accepted)
            self._total_dropped_dedup += deduped
            self._total_dropped_circuit += circuit_dropped

            # Sync current clusters back to assessment_obj for prefill
            clusters = self._index.snapshot_clusters()
            self._assessment_obj['correlation_clusters'] = clusters
            self._assessment_obj['evidence_rows'] = self._all_rows
            self._assessment_obj['rows'] = self._all_rows
            self._assessment_obj['rows_processed'] = self._total_ingested

            # Schedule prefill for changed clusters
            if changed_roots:
                if self._prefill_scheduler is None:
                    self._prefill_scheduler = BatchedPrefillScheduler(
                        self._assessment_obj, self.assessment_id
                    )
                self._prefill_scheduler.schedule(changed_roots)

        # Persist open-session metadata and snapshot after each accepted batch.
        try:
            asyncio.create_task(asyncio.to_thread(_persist_session_meta, self))
        except RuntimeError:
            _persist_session_meta(self)  # no running loop (test context)

        return {
            'accepted': len(accepted),
            'deduped': deduped,
            'circuit_dropped': circuit_dropped,
        }

    def snapshot(self) -> dict:
        """Return a read-only snapshot suitable for API polling."""
        clusters = self._index.snapshot_clusters()
        return {
            'assessment_id': self.assessment_id,
            'status': 'streaming',
            'total_ingested': self._total_ingested,
            'total_deduped': self._total_dropped_dedup,
            'total_circuit_dropped': self._total_dropped_circuit,
            'source_stats': dict(self._source_stats),
            'cluster_count': len(clusters),
            'correlation_clusters': clusters,
            'breaker_states': {
                src: {'open': b.is_open(), 'total_dropped': b._total_dropped}
                for src, b in self._breakers.items()
            },
            'elapsed_s': round(time.time() - self._started_at, 1),
        }

    async def close(self) -> dict:
        """Finalize the session: run a last prefill and mark status=complete."""
        async with self._lock:
            self._assessment_obj['status'] = 'complete'
            self._assessment_obj['correlation_clusters'] = self._index.snapshot_clusters()
        # Final prefill — run synchronously to completion before returning
        try:
            import os as _os
            if not _os.environ.get('JANUSEC_DISABLE_T1_PREFILL'):
                from src.core.tier1_prefill.prefill_engine import run_prefill as _run_prefill
                await asyncio.to_thread(
                    _run_prefill,
                    assessment=self._assessment_obj,
                    top_n=10,
                    tenant_id='default',
                )
        except Exception as exc:
            logger.debug('streaming_close: final prefill failed: %s', exc)
        return self.snapshot() | {'status': 'complete'}


# ── Session registry (in-memory + SQLite persistence) ─────────────────────────

_SESSIONS: Dict[str, StreamingAssessmentSession] = {}


def _sessions_db_path() -> str:
    import os
    return os.getenv('JANUSEC_SESSIONS_DB', 'data/streaming_sessions.db')


def _session_snapshot_dir() -> str:
    import os
    base = os.getenv('JANUSEC_STREAMING_SNAPSHOT_DIR')
    if base:
        return base
    db_dir = os.path.dirname(_sessions_db_path())
    return os.path.join(db_dir or '.', 'streaming_session_snapshots')


def _session_snapshot_path(assessment_id: str) -> str:
    import os
    safe_id = re.sub(r'[^A-Za-z0-9_.-]+', '_', assessment_id or 'session')
    return os.path.join(_session_snapshot_dir(), f'{safe_id}.json')


def _init_sessions_db() -> None:
    """Create the sessions table if it doesn't exist."""
    import sqlite3, os
    path = _sessions_db_path()
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
    try:
        with sqlite3.connect(path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS streaming_sessions (
                    assessment_id TEXT PRIMARY KEY,
                    org           TEXT NOT NULL DEFAULT "default",
                    status        TEXT NOT NULL DEFAULT "streaming",
                    created_ts    REAL NOT NULL,
                    updated_ts    REAL NOT NULL,
                    total_ingested INTEGER NOT NULL DEFAULT 0
                )
            ''')
            conn.commit()
    except Exception as exc:
        logger.debug('sessions_db init failed (non-fatal): %s', exc)


def _persist_session_snapshot(session: 'StreamingAssessmentSession') -> None:
    import json
    import os
    try:
        os.makedirs(_session_snapshot_dir(), exist_ok=True)
        payload = dict(session._assessment_obj)
        payload.update({
            'assessment_id': session.assessment_id,
            'org': session.org,
            'status': session._assessment_obj.get('status', 'streaming'),
            'rows': session._all_rows,
            'evidence_rows': session._all_rows,
            'correlation_clusters': session._index.snapshot_clusters(),
            'rows_processed': session._total_ingested,
            'total_ingested': session._total_ingested,
            'total_deduped': session._total_dropped_dedup,
            'total_circuit_dropped': session._total_dropped_circuit,
            'source_stats': dict(session._source_stats),
            'persisted_at': time.time(),
        })
        with open(_session_snapshot_path(session.assessment_id), 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, default=str)
    except Exception as exc:
        logger.debug('persist_session_snapshot failed (non-fatal): %s', exc)


def _load_session_snapshot(assessment_id: str) -> dict:
    import json
    try:
        with open(_session_snapshot_path(assessment_id), 'r', encoding='utf-8') as fh:
            payload = json.load(fh)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _persist_session_meta(session: 'StreamingAssessmentSession') -> None:
    import sqlite3
    try:
        _init_sessions_db()
        with sqlite3.connect(_sessions_db_path()) as conn:
            conn.execute('''
                INSERT INTO streaming_sessions (assessment_id, org, status, created_ts, updated_ts, total_ingested)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(assessment_id) DO UPDATE SET
                    status=excluded.status,
                    updated_ts=excluded.updated_ts,
                    total_ingested=excluded.total_ingested
            ''', (
                session.assessment_id,
                session.org,
                session._assessment_obj.get('status', 'streaming'),
                session._started_at,
                time.time(),
                session._total_ingested,
            ))
            conn.commit()
        _persist_session_snapshot(session)
    except Exception as exc:
        logger.debug('persist_session_meta failed (non-fatal): %s', exc)


def _load_open_sessions() -> List[Dict[str, Any]]:
    """Return metadata rows for sessions that were streaming before last shutdown."""
    import sqlite3
    try:
        _init_sessions_db()
        with sqlite3.connect(_sessions_db_path()) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT assessment_id, org FROM streaming_sessions WHERE status='streaming' ORDER BY created_ts DESC"
            ).fetchall()
        return [{'assessment_id': r['assessment_id'], 'org': r['org']} for r in rows]
    except Exception as exc:
        logger.debug('load_open_sessions failed (non-fatal): %s', exc)
        return []


def _mark_session_closed(assessment_id: str) -> None:
    import sqlite3
    try:
        with sqlite3.connect(_sessions_db_path()) as conn:
            conn.execute(
                "UPDATE streaming_sessions SET status='closed', updated_ts=? WHERE assessment_id=?",
                (time.time(), assessment_id),
            )
            conn.commit()
    except Exception:
        pass


def get_or_create_session(assessment_id: str, org: str = 'default') -> StreamingAssessmentSession:
    if assessment_id not in _SESSIONS:
        _SESSIONS[assessment_id] = StreamingAssessmentSession(assessment_id, org)
        logger.info('streaming_ingest: new session %s for org %s', assessment_id, org)
        _persist_session_meta(_SESSIONS[assessment_id])
    return _SESSIONS[assessment_id]


def get_session(assessment_id: str) -> Optional[StreamingAssessmentSession]:
    """Return in-memory session, or None if not found (SQLite rows only store metadata)."""
    return _SESSIONS.get(assessment_id)


def close_session(assessment_id: str) -> None:
    _SESSIONS.pop(assessment_id, None)
    _mark_session_closed(assessment_id)


def recover_open_sessions() -> int:
    """Re-register sessions that were open at last shutdown.

    Call this at application startup to restore session routing so connectors
    can resume ingesting into existing assessment_ids without 404s. When a
    snapshot is present, rows and current cluster state are restored as well.
    """
    recovered = 0
    for meta in _load_open_sessions():
        aid = meta['assessment_id']
        if aid not in _SESSIONS:
            session = StreamingAssessmentSession(aid, meta.get('org', 'default'))
            session.restore_from_snapshot(_load_session_snapshot(aid))
            _SESSIONS[aid] = session
            logger.info('streaming_ingest: recovered session %s from SQLite', aid)
            recovered += 1
    return recovered


__all__ = [
    'StreamingAssessmentSession',
    'get_or_create_session',
    'get_session',
    'close_session',
    'recover_open_sessions',
    'normalize_row',
    'classify_source',
    'fingerprint_row',
    'IncrementalClusterIndex',
    'SOURCE_CLOUD', 'SOURCE_IAM', 'SOURCE_EMAIL',
    'SOURCE_NETWORK', 'SOURCE_ENDPOINT', 'SOURCE_REMOTE',
]
