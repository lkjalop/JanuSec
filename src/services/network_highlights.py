from __future__ import annotations

import os
import time
import threading
from collections import Counter, deque
from typing import Any, Deque, Dict, List, Optional

WINDOW_SECONDS = int(os.getenv('NETWORK_HIGHLIGHT_WINDOW_SECONDS', '900') or 900)
MISSING_TTL = int(os.getenv('NETWORK_HIGHLIGHT_MISSING_TTL', '900') or 900)


def _now_ts(event: Dict[str, Any]) -> float:
    ts = event.get('ts') or event.get('timestamp')
    if isinstance(ts, (int, float)):
        return float(ts)
    return time.time()


def _infer_flow_stage(flow: Dict[str, Any]) -> str:
    if flow.get('beacon_score') or flow.get('avg_period') or flow.get('beacon_period'):
        return 'Command and Control'
    bytes_sent = float(flow.get('bytes') or 0)
    if bytes_sent > 5_000_000:
        return 'Exfiltration'
    dst_port = int(flow.get('dst_port') or 0)
    if dst_port in {3389, 445, 22}:
        return 'Lateral Movement'
    return 'Delivery'


def _infer_syslog_stage(event: Dict[str, Any]) -> str:
    severity = event.get('severity')
    message = (event.get('message') or '').lower()
    if severity is not None and severity <= 2:
        return 'Installation'
    if any(token in message for token in ('privilege', 'sudo', 'authentication failure', 'pam_unix')):
        return 'Privilege Escalation'
    if any(token in message for token in ('blocked', 'denied', 'firewall')):
        return 'Delivery'
    return 'Reconnaissance'


try:
    # Prefer unified DREAD scoring used across API/UI surfaces
    from src.core.threat_modeling.factor_taxonomy import compute_dread_score  # type: ignore
except Exception:  # pragma: no cover - fallback when taxonomy module unavailable
    compute_dread_score = None  # type: ignore


def _build_dread(flow_records: List[Dict[str, Any]]) -> Dict[str, float]:
    """Compute DREAD for LIVE console using unified engine when available.

    Returns legacy keys for UI compatibility (damage, reproducibility, exploitability,
    affected_users, discoverability, score) while sourcing the primary score from
    compute_dread_score when possible.
    """
    total_bytes = sum(float(rec.get('bytes') or 0) for rec in flow_records)
    host_count = len({rec.get('src_ip') for rec in flow_records if rec.get('src_ip')})

    if compute_dread_score is not None and flow_records:
        try:
            # Map inferred kill chain stages to representative factors
            factors: List[str] = []
            for rec in flow_records:
                st = str(rec.get('stage') or '')
                if st == 'Command and Control':
                    factors.append('net:beacon_periodic')
                elif st == 'Exfiltration':
                    factors.append('net:flow_microcluster_exfil')
                elif st == 'Lateral Movement':
                    factors.append('endpoint:lateral_exec_remote_tool')
                else:
                    # Delivery/other – include lightweight network factor
                    factors.append('net:port_protocol_misuse')
            # Deduplicate
            factors = list(dict.fromkeys(factors))
            # Build minimal context from flows to inform mapping/diversity/status
            ctx: Dict[str, Any] = {}
            first = flow_records[0]
            ctx['src_ip'] = first.get('src_ip')
            ctx['dst_ip'] = first.get('dst_ip')
            # Signal suspicious status when C2 or Exfil stages observed
            stages = {str(r.get('stage') or '') for r in flow_records}
            if {'Command and Control', 'Exfiltration'} & stages:
                ctx['verdict'] = 'SUSPICIOUS'
            # Modest mapping semantics hint from present fields
            present = 0
            for key in ('src_ip', 'dst_ip'):
                if ctx.get(key):
                    present += 1
            ctx['mapping_semantics_score'] = min(1.0, present / 4.0)
            res = compute_dread_score(factors, context=ctx)  # type: ignore
            # Components are 0..1 – scale to legacy 0..10 UI values
            comps = (res or {}).get('components') or {}
            damage = min(10.0, round(float(comps.get('damage') or 0.0) * 10.0, 2))
            exploitability = min(10.0, round(float(comps.get('exploitability') or 0.0) * 10.0, 2))
            discoverability = min(10.0, round(float(comps.get('discoverability') or 0.0) * 10.0, 2))
            # Keep reproducibility/affected_users derived from host fan-out for compatibility
            reproducibility = min(10.0, round(2 + host_count * 0.8, 2))
            affected_users = min(10.0, round(host_count * 1.2, 2))
            score = float((res or {}).get('score') or 0.0)
            return {
                'damage': damage,
                'reproducibility': reproducibility,
                'exploitability': exploitability,
                'affected_users': affected_users,
                'discoverability': discoverability,
                'score': round(score, 2),
            }
        except Exception:
            # Fall back to legacy heuristic below
            pass

    # Legacy heuristic when unified engine unavailable or errors
    damage = min(10.0, round((total_bytes / 1_000_000) + host_count * 0.6, 2))
    reproducibility = min(10.0, round(2 + host_count * 0.8, 2))
    exploitability = min(10.0, round(3 + len(flow_records) * 0.2, 2))
    affected_users = min(10.0, round(host_count * 1.2, 2))
    discoverability = min(10.0, 10 - min(6.5, severity_weight(flow_records)))
    score = round((damage + reproducibility + exploitability + affected_users + discoverability) / 5, 2)
    return {
        'damage': damage,
        'reproducibility': reproducibility,
        'exploitability': exploitability,
        'affected_users': affected_users,
        'discoverability': discoverability,
        'score': score,
    }


def severity_weight(flow_records: List[Dict[str, Any]]) -> float:
    beacons = sum(1 for rec in flow_records if rec.get('stage') == 'Command and Control')
    exfil = sum(1 for rec in flow_records if rec.get('stage') == 'Exfiltration')
    return float(beacons * 1.5 + exfil * 1.2)


def _map_pasta_stage(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    if snapshot.get('beacon_findings'):
        return {'stage_id': 6, 'stage': 'Attack & Exploit', 'note': 'Beacons indicate active exploitation.'}
    if snapshot.get('suspicious_asn'):
        return {'stage_id': 5, 'stage': 'Vulnerability & Exposure', 'note': 'Unknown ASN observed in outbound flows.'}
    if snapshot.get('missing_log', {}).get('flag'):
        return {'stage_id': 2, 'stage': 'Threat Modeling', 'note': 'Telemetry gap requires additional modeling.'}
    return {'stage_id': 3, 'stage': 'Attack Surface Analysis', 'note': 'Monitoring steady-state network telemetry.'}


class NetworkHighlightsAggregator:
    def __init__(self, window_seconds: int = WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        self._lock = threading.RLock()
        self._tenants: Dict[str, Dict[str, Any]] = {}

    def _state(self, tenant: str) -> Dict[str, Any]:
        with self._lock:
            return self._tenants.setdefault(
                tenant,
                {
                    'flows': deque(),
                    'syslogs': deque(),
                    'asn_catalog': set(),
                    'new_asn': deque(),
                    'last_event_ts': 0.0,
                },
            )

    def _prune(self, state: Dict[str, Any], now: float) -> None:
        window = self.window_seconds
        flows: Deque[Dict[str, Any]] = state['flows']
        while flows and (now - flows[0]['ts']) > window:
            flows.popleft()
        syslogs: Deque[Dict[str, Any]] = state['syslogs']
        while syslogs and (now - syslogs[0]['ts']) > window:
            syslogs.popleft()
        new_asn: Deque[Dict[str, Any]] = state['new_asn']
        while new_asn and (now - new_asn[0]['ts']) > window:
            new_asn.popleft()

    def add_syslog_event(self, tenant: str, event: Dict[str, Any]) -> None:
        state = self._state(tenant)
        now = _now_ts(event)
        record = {
            'ts': now,
            'severity': event.get('severity'),
            'host': event.get('host'),
            'app': event.get('app'),
            'message': event.get('message'),
            'stage': _infer_syslog_stage(event),
            'persona': event.get('persona') or 'IR',
        }
        with self._lock:
            state['syslogs'].append(record)
            state['last_event_ts'] = max(state['last_event_ts'], now)
            self._prune(state, now)

    def add_netflow_event(self, tenant: str, flow: Dict[str, Any]) -> None:
        state = self._state(tenant)
        now = _now_ts(flow)
        stage = _infer_flow_stage(flow)
        record = {
            'ts': now,
            'src_ip': flow.get('src_ip'),
            'dst_ip': flow.get('dst_ip'),
            'bytes': float(flow.get('bytes') or 0),
            'packets': int(flow.get('packets') or 0),
            'dst_as': flow.get('dst_as'),
            'stage': stage,
            'beacon_score': flow.get('beacon_score') or flow.get('avg_period'),
        }
        with self._lock:
            state['flows'].append(record)
            state['last_event_ts'] = max(state['last_event_ts'], now)
            if record['dst_as'] and record['dst_as'] not in state['asn_catalog']:
                state['asn_catalog'].add(record['dst_as'])
                state['new_asn'].append({'ts': now, 'asn': record['dst_as'], 'src_ip': record['src_ip'], 'dst_ip': record['dst_ip']})
            self._prune(state, now)

    def snapshot(self, tenant: str) -> Optional[Dict[str, Any]]:
        state = self._tenants.get(tenant)
        if not state:
            return None
        now = time.time()
        with self._lock:
            self._prune(state, now)
            flows = list(state['flows'])
            syslogs = list(state['syslogs'])
            if not flows and not syslogs:
                idle = now - state['last_event_ts'] if state['last_event_ts'] else None
                if idle and idle > MISSING_TTL:
                    return {
                        'generated_at': now,
                        'window_seconds': self.window_seconds,
                        'missing_log': {'flag': True, 'idle_seconds': round(idle, 1), 'threshold': MISSING_TTL},
                        'narrative': [f'Telemetry gap detected: {round(idle/60,1)}m since last network event.'],
                    }
                return None

            top_talkers = []
            if flows:
                counter = Counter(rec.get('src_ip') for rec in flows if rec.get('src_ip'))
                for ip, count in counter.most_common(5):
                    stage = next((rec['stage'] for rec in flows if rec.get('src_ip') == ip), 'Delivery')
                    top_talkers.append({'ip': ip, 'count': count, 'stage': stage})

            beacon_findings = [
                {
                    'src_ip': rec.get('src_ip'),
                    'dst_ip': rec.get('dst_ip'),
                    'score': rec.get('beacon_score'),
                    'stage': rec['stage'],
                }
                for rec in flows
                if rec.get('stage') == 'Command and Control'
            ][:5]

            suspicious_asn = list(state['new_asn'])[-5:]
            stage_counts = Counter(rec['stage'] for rec in flows + syslogs if rec.get('stage'))
            dominant_stage = stage_counts.most_common(1)[0][0] if stage_counts else None

            dread = _build_dread(flows) if flows else {'damage': 0, 'reproducibility': 0, 'exploitability': 0, 'affected_users': 0, 'discoverability': 0, 'score': 0}
            missing_log = None
            idle = now - state['last_event_ts'] if state['last_event_ts'] else None
            if idle and idle > MISSING_TTL:
                missing_log = {'flag': True, 'idle_seconds': round(idle, 1), 'threshold': MISSING_TTL}

            narrative: List[str] = []
            if top_talkers:
                top = top_talkers[0]
                narrative.append(f"{top['ip']} generated {top['count']} flows (Kill Chain: {top['stage']}).")
            if suspicious_asn:
                entry = suspicious_asn[-1]
                narrative.append(f"New ASN {entry['asn']} seen from {entry.get('src_ip')} to {entry.get('dst_ip')}.")
            if beacon_findings:
                beacon = beacon_findings[0]
                narrative.append(f"Beacon-like pattern from {beacon['src_ip']} to {beacon['dst_ip']} with score {beacon['score']}.")
            if missing_log:
                narrative.append(f"Telemetry gap: {round(missing_log['idle_seconds']/60, 2)}m without network events.")
            if dread.get('score'):
                narrative.append(
                    f"DREAD score {dread['score']}/10 (Damage {dread['damage']}, Exploitability {dread['exploitability']})."
                )

            snapshot = {
                'generated_at': now,
                'window_seconds': self.window_seconds,
                'top_talkers': top_talkers,
                'beacon_findings': beacon_findings,
                'suspicious_asn': list(suspicious_asn),
                'kill_chain': {
                    'stage_counts': stage_counts,
                    'dominant_stage': dominant_stage,
                },
                'dread': dread,
                'missing_log': missing_log or {'flag': False},
                'narrative': narrative,
            }
            snapshot['pasta'] = _map_pasta_stage(snapshot)
            return snapshot


_AGGREGATOR: Optional[NetworkHighlightsAggregator] = None


def get_network_highlights_aggregator() -> NetworkHighlightsAggregator:
    global _AGGREGATOR
    if _AGGREGATOR is None:
        _AGGREGATOR = NetworkHighlightsAggregator()
    return _AGGREGATOR


def get_network_highlights_snapshot(tenant: Optional[str]) -> Optional[Dict[str, Any]]:
    if not tenant:
        tenant = os.getenv('DEFAULT_TENANT', 'default')
    return get_network_highlights_aggregator().snapshot(tenant)


__all__ = ['get_network_highlights_aggregator', 'get_network_highlights_snapshot', 'NetworkHighlightsAggregator']
