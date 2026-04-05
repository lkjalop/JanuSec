"""Cross-cloud IAM correlation engine.

Unifies identity events from AWS CloudTrail and Azure Entra ID into a single
graph space, allowing analysts to see pivot chains that cross cloud boundaries:

    user:alice@corp.com  ──[aws:AssumeRole]──>  role:arn:aws:iam::123:role/Admin
                          ──[az:Entra:signin]──>  host:device-9f2a
                          ──[az:token:refresh]──>  app:microsoft-graph

Key capabilities:
  1. Federated identity merging — AWS IAM ARN ↔ Azure UPN linked by ``identity_key``
  2. Escalation chain detection — AssumeRole → privileged action sequences
  3. Temporal correlation — flag events that cross cloud in < T seconds (default 60 s)
  4. Lateral movement scoring — same user in both clouds within session window
  5. Composite risk signal emission — returns normalised risk + contributing factors

Design:
  - Fronts the existing ``IdentityHopGraph`` (adds cross-cloud edges on top)
  - Thread-safe; accepts raw canonical envelopes from the connectors
  - No external dependencies beyond the existing graph infrastructure

Usage::

    from src.core.graph.crosscloud_iam import CrossCloudIAMCorrelator

    correlator = CrossCloudIAMCorrelator()
    correlator.ingest_aws(cloudtrail_event)
    correlator.ingest_azure(entra_event)
    results = correlator.correlate_identity('alice@corp.com')
    # results.cross_cloud_chains, results.risk_score, results.factors
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────

# Time window in which events from different clouds are considered correlated
_CROSS_CLOUD_WINDOW_SECONDS = 120
# Minimum events in both clouds to flag as cross-cloud correlation
_CROSS_CLOUD_MIN_EVENTS = 2


# ── Data classes ──────────────────────────────────────────────────────

@dataclass
class IAMEvent:
    """Normalised IAM event from any cloud provider."""
    cloud: str                   # 'aws' | 'azure'
    identity_key: str            # canonical identity (email / UPN)
    event_type: str              # e.g. 'AssumeRole', 'Entra:signin', 'token:refresh'
    resource: str                # target ARN / resource id
    ts: float
    raw: Dict[str, Any] = field(default_factory=dict)
    region: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True


@dataclass
class CrossCloudChain:
    """A correlated sequence of events across cloud boundaries."""
    identity_key: str
    events: List[IAMEvent]       # sorted by ts
    cloud_sequence: List[str]    # e.g. ['azure', 'aws']
    delta_seconds: float         # time between first and last event
    suspicious: bool
    reasons: List[str]           # human-readable indicators


@dataclass
class CorrelationResult:
    identity_key: str
    aws_events: List[IAMEvent]
    azure_events: List[IAMEvent]
    cross_cloud_chains: List[CrossCloudChain]
    risk_score: float            # 0.0 – 1.0
    factors: List[Dict[str, Any]]
    total_events: int


# ── Normalisation helpers ─────────────────────────────────────────────

def _identity_key_from_aws(event: Dict[str, Any]) -> Optional[str]:
    """Extract a canonical identity key from a CloudTrail event dict."""
    uid = event.get('userIdentity') or {}
    # Prefer email-style principalId; fall back to ARN user part
    for field_name in ('userName', 'principalId', 'arn'):
        val = uid.get(field_name)
        if val and '@' in str(val):
            return str(val).lower()
    # Extract from ARN: arn:aws:sts::123:assumed-role/RoleName/user@corp.com
    arn = uid.get('arn') or ''
    if '/' in arn:
        last = arn.rsplit('/', 1)[-1]
        if '@' in last:
            return last.lower()
    # fallback: use ARN as-is
    return (uid.get('arn') or uid.get('userName') or '').lower() or None


def _identity_key_from_azure(event: Dict[str, Any]) -> Optional[str]:
    """Extract a canonical identity key from an Entra ID / Graph event dict."""
    for field_name in ('userPrincipalName', 'userId', 'initiatedBy'):
        val = event.get(field_name)
        if val and isinstance(val, str):
            return val.lower()
    # Nested: properties.initiatedBy.user.userPrincipalName
    props = event.get('properties') or {}
    init = props.get('initiatedBy') or {}
    user = init.get('user') or {}
    upn = user.get('userPrincipalName')
    if upn:
        return upn.lower()
    return None


def _normalize_aws(event: Dict[str, Any]) -> Optional[IAMEvent]:
    """Convert a CloudTrail event dict to IAMEvent."""
    key = _identity_key_from_aws(event)
    if not key:
        return None
    event_name = event.get('eventName') or ''
    resource = ''
    req = event.get('requestParameters') or {}
    if 'roleArn' in req:
        resource = req['roleArn']
    elif 'userName' in req:
        resource = req['userName']
    elif 'bucketName' in req:
        resource = req['bucketName']
    ts_str = event.get('eventTime') or ''
    try:
        import datetime
        ts = datetime.datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp()
    except Exception:
        ts = time.time()

    return IAMEvent(
        cloud='aws',
        identity_key=key,
        event_type=event_name,
        resource=resource,
        ts=ts,
        raw=event,
        region=event.get('awsRegion'),
        ip=event.get('sourceIPAddress'),
        user_agent=event.get('userAgent'),
        success=event.get('errorCode') is None,
    )


def _normalize_azure(event: Dict[str, Any]) -> Optional[IAMEvent]:
    """Convert an Entra ID / Graph audit event to IAMEvent."""
    key = _identity_key_from_azure(event)
    if not key:
        return None
    op = (event.get('operationType') or event.get('activityDisplayName')
          or event.get('category') or 'unknown')
    resource = (event.get('targetResources') or [{}])[0].get('displayName') or ''
    ts_str = event.get('activityDateTime') or event.get('createdDateTime') or ''
    try:
        import datetime
        ts = datetime.datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp()
    except Exception:
        ts = time.time()

    return IAMEvent(
        cloud='azure',
        identity_key=key,
        event_type=f'Entra:{op}',
        resource=resource,
        ts=ts,
        raw=event,
        ip=(event.get('ipAddress') or
            (event.get('location') or {}).get('ipAddress')),
        success=(event.get('result') or 'success').lower() == 'success',
    )


# ── Correlation logic ─────────────────────────────────────────────────

_SUSPICIOUS_AWS_EVENTS = {
    'AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity',
    'CreateAccessKey', 'AttachUserPolicy', 'AttachRolePolicy',
    'PutUserPolicy', 'PutRolePolicy', 'CreateLoginProfile',
    'UpdateLoginProfile', 'AddUserToGroup',
}

_SUSPICIOUS_AZURE_EVENTS = {
    'Add member to role', 'Add owner to application', 'Add app role assignment',
    'Update user', 'Reset user password', 'Delete user',
    'Consent to application', 'Add service principal',
}


def _score_chain(chain: CrossCloudChain) -> Tuple[float, List[str]]:
    """Compute a 0-1 risk score and reasons for a cross-cloud chain."""
    score = 0.0
    reasons: List[str] = []

    delta = chain.delta_seconds
    if delta < 60:
        score += 0.40
        reasons.append(f'cross_cloud_within_{int(delta)}s')
    elif delta < 300:
        score += 0.20
        reasons.append('cross_cloud_within_5min')

    aws_types = {e.event_type for e in chain.events if e.cloud == 'aws'}
    az_types = {e.event_type for e in chain.events if e.cloud == 'azure'}

    if aws_types & _SUSPICIOUS_AWS_EVENTS:
        score += 0.25
        reasons.append('suspicious_aws_privesc')
    if az_types & {e for e in az_types if any(s in e for s in _SUSPICIOUS_AZURE_EVENTS)}:
        score += 0.20
        reasons.append('suspicious_azure_admin_op')

    ips = {e.ip for e in chain.events if e.ip}
    if len(ips) > 1:
        score += 0.10
        reasons.append(f'multi_ip_cross_cloud:{len(ips)}_distinct_ips')

    failures = [e for e in chain.events if not e.success]
    if failures:
        score += 0.05 * min(len(failures), 3)
        reasons.append(f'{len(failures)}_failed_events')

    return round(min(1.0, score), 3), reasons


# ── Main correlator ───────────────────────────────────────────────────

class CrossCloudIAMCorrelator:
    """Accepts events from both cloud connectors and correlates by identity."""

    def __init__(
        self,
        window_seconds: int = _CROSS_CLOUD_WINDOW_SECONDS,
        max_events_per_identity: int = 1000,
    ):
        self.window_seconds = window_seconds
        self.max_events_per_identity = max_events_per_identity
        # identity_key -> list of IAMEvents
        self._store: Dict[str, List[IAMEvent]] = defaultdict(list)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest_aws(self, raw_event: Dict[str, Any]) -> Optional[IAMEvent]:
        """Normalise and store an AWS CloudTrail event."""
        ev = _normalize_aws(raw_event)
        if ev:
            self._add(ev)
        return ev

    def ingest_azure(self, raw_event: Dict[str, Any]) -> Optional[IAMEvent]:
        """Normalise and store an Azure Entra ID / audit event."""
        ev = _normalize_azure(raw_event)
        if ev:
            self._add(ev)
        return ev

    def ingest_canonical(self, canonical: Dict[str, Any]) -> Optional[IAMEvent]:
        """Ingest from a pre-normalised canonical envelope (cloud field required)."""
        cloud = (canonical.get('cloud') or canonical.get('source') or '').lower()
        if 'aws' in cloud:
            return self.ingest_aws(canonical)
        elif 'azure' in cloud or 'entra' in cloud:
            return self.ingest_azure(canonical)
        return None

    def _add(self, ev: IAMEvent) -> None:
        with self._lock:
            bucket = self._store[ev.identity_key]
            bucket.append(ev)
            bucket.sort(key=lambda e: e.ts)
            # cap + prune old events
            if len(bucket) > self.max_events_per_identity:
                self._store[ev.identity_key] = bucket[-self.max_events_per_identity:]
            self._prune_ttl(ev.identity_key)

    def _prune_ttl(self, key: str) -> None:
        cutoff = time.time() - max(self.window_seconds * 10, 3600)
        self._store[key] = [e for e in self._store[key] if e.ts >= cutoff]

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def correlate_identity(self, identity_key: str) -> CorrelationResult:
        """Produce a cross-cloud correlation report for an identity."""
        identity_key = identity_key.lower()
        with self._lock:
            events = list(self._store.get(identity_key, []))

        aws_events = [e for e in events if e.cloud == 'aws']
        azure_events = [e for e in events if e.cloud == 'azure']

        chains = self._find_chains(aws_events, azure_events)
        risk, factors = self._aggregate_risk(chains, aws_events, azure_events)

        return CorrelationResult(
            identity_key=identity_key,
            aws_events=aws_events,
            azure_events=azure_events,
            cross_cloud_chains=chains,
            risk_score=risk,
            factors=factors,
            total_events=len(events),
        )

    def top_risks(self, n: int = 10) -> List[CorrelationResult]:
        """Return the top N riskiest identities across all ingested events."""
        with self._lock:
            keys = list(self._store.keys())

        results = []
        for key in keys:
            result = self.correlate_identity(key)
            if result.total_events > 0:
                results.append(result)
        results.sort(key=lambda r: r.risk_score, reverse=True)
        return results[:n]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            keys = list(self._store.keys())
            total = sum(len(v) for v in self._store.values())
        return {
            'tracked_identities': len(keys),
            'total_events': total,
        }

    # ------------------------------------------------------------------
    # Internal chain detection
    # ------------------------------------------------------------------

    def _find_chains(
        self,
        aws: List[IAMEvent],
        azure: List[IAMEvent],
    ) -> List[CrossCloudChain]:
        """Find temporal windows where the same identity appears in both clouds."""
        if not aws or not azure:
            return []

        chains: List[CrossCloudChain] = []
        # sliding window: for each AWS event, find Azure events within window
        all_events = sorted(aws + azure, key=lambda e: e.ts)

        i = 0
        while i < len(all_events):
            anchor = all_events[i]
            window_end = anchor.ts + self.window_seconds
            window_events = [e for e in all_events if anchor.ts <= e.ts <= window_end]
            clouds_in_window = {e.cloud for e in window_events}

            if len(clouds_in_window) > 1 and len(window_events) >= _CROSS_CLOUD_MIN_EVENTS:
                delta = window_events[-1].ts - window_events[0].ts
                chain = CrossCloudChain(
                    identity_key=anchor.identity_key,
                    events=window_events,
                    cloud_sequence=[e.cloud for e in window_events],
                    delta_seconds=delta,
                    suspicious=False,
                    reasons=[],
                )
                score, reasons = _score_chain(chain)
                chain.suspicious = score >= 0.30
                chain.reasons = reasons
                chains.append(chain)
                # skip past this window
                i += len(window_events)
            else:
                i += 1

        # Deduplicate overlapping chains
        seen: Set[str] = set()
        deduped = []
        for c in chains:
            sig = '|'.join(sorted(e.event_type + str(e.ts) for e in c.events))
            if sig not in seen:
                seen.add(sig)
                deduped.append(c)
        return deduped

    def _aggregate_risk(
        self,
        chains: List[CrossCloudChain],
        aws: List[IAMEvent],
        azure: List[IAMEvent],
    ) -> Tuple[float, List[Dict[str, Any]]]:
        """Compute aggregate risk and factor list."""
        factors: List[Dict[str, Any]] = []
        score = 0.0

        for chain in chains:
            chain_score, reasons = _score_chain(chain)
            if chain_score > score:
                score = chain_score
            if chain_score >= 0.20:
                factors.append({
                    'factor_name': 'cross_cloud_iam_correlation',
                    'score': chain_score,
                    'reasons': reasons,
                    'clouds': list({e.cloud for e in chain.events}),
                    'delta_seconds': round(chain.delta_seconds, 1),
                    'mitre': ['TA0004', 'TA0003'],  # Privilege Escalation, Persistence
                })

        failed_aws = [e for e in aws if not e.success]
        if len(failed_aws) >= 3:
            factors.append({
                'factor_name': 'aws_repeated_failures',
                'count': len(failed_aws),
                'score': 0.15,
                'mitre': ['TA0006'],
            })
            score = min(1.0, score + 0.10)

        failed_az = [e for e in azure if not e.success]
        if len(failed_az) >= 3:
            factors.append({
                'factor_name': 'azure_repeated_failures',
                'count': len(failed_az),
                'score': 0.15,
                'mitre': ['TA0006'],
            })
            score = min(1.0, score + 0.10)

        return round(score, 3), factors


# ── Singleton ─────────────────────────────────────────────────────────

_GLOBAL_CORRELATOR: Optional[CrossCloudIAMCorrelator] = None


def get_crosscloud_correlator() -> CrossCloudIAMCorrelator:
    global _GLOBAL_CORRELATOR
    if _GLOBAL_CORRELATOR is None:
        _GLOBAL_CORRELATOR = CrossCloudIAMCorrelator()
    return _GLOBAL_CORRELATOR
