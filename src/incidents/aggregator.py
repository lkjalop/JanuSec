"""Incident Aggregator Skeleton

Groups events into lightweight incidents over a sliding window based on:
 - Host identity
 - Overlapping factors
 - Temporal proximity

This is intentionally minimal; scoring & enrichment added later.
"""
from __future__ import annotations
from typing import Dict, List, Any
import time, uuid, threading, json, os
import asyncio
try:
    from analysis.factor_mapping import enrich_factors  # type: ignore
except Exception:  # pragma: no cover
    def enrich_factors(factors: List[str]):  # type: ignore
        return {}

try:  # pragma: no cover
    from src.artifact.memory_repository import MEMORY_JOB_STORE  # type: ignore
except Exception:  # pragma: no cover
    MEMORY_JOB_STORE = None  # type: ignore

class IncidentAggregator:
    def __init__(self, window_seconds: int = 900, factor_overlap: int = 1):
        self.window = window_seconds
        self.factor_overlap = factor_overlap
        self._lock = threading.RLock()
        self.incidents: Dict[str, dict] = {}
        self.snapshot_path = os.getenv('INCIDENT_SNAPSHOT_PATH','data/incidents_snapshot.json')
        try:
            from pathlib import Path
            Path(self.snapshot_path).parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def _prune(self):
        cutoff = time.time() - self.window
        stale = [iid for iid, inc in self.incidents.items() if inc['last_ts'] < cutoff]
        for iid in stale:
            self.incidents.pop(iid, None)

    def _resolve_risk_score(self, event: dict, factors: set[str], ts: float, confidence: float):
        try:
            from src.core.risk_score import compose_risk_score
            decision_like = {
                'factors': sorted(list(factors)),
                'confidence': confidence,
                'ts': ts,
            }
            rs = compose_risk_score(decision_like, tenant_id=event.get('tenant_id'))
            if hasattr(rs, '__await__'):
                try:
                    loop = asyncio.get_event_loop()
                except Exception:
                    loop = None
                if loop and loop.is_running():
                    try:
                        rs.close()
                    except Exception:
                        pass
                    return None
                try:
                    rs = asyncio.run(rs)
                except Exception:
                    try:
                        rs.close()
                    except Exception:
                        pass
                    return None
            return rs if isinstance(rs, dict) else None
        except Exception:
            return None

    def ingest(self, event: dict, factors: List[str]) -> dict:
        host = (event.get('src_host') or event.get('host') or event.get('hostname') or '').lower()
        ts = float(event.get('ts') or time.time())
        fset = set(factors)
        with self._lock:
            self._prune()
            # Find matching incident
            for inc in self.incidents.values():
                # Prefer merging by exact host match (same host -> same incident).
                # This keeps incidents per-host coherent even when factors change.
                if host and inc['host'] == host:
                    inc['events'].append({'id': event.get('event_id'), 'ts': ts, 'factors': factors})
                    inc['factors'].update(fset)
                    inc['last_ts'] = ts
                    inc['score'] = min(1.0, inc['score'] + 0.05 * len(fset))
                    try:
                        inc['framework_enrichment'] = enrich_factors(sorted(list(inc['factors'])))
                    except Exception:
                        pass
                    # Attach business impact lenses (best-effort)
                    try:
                        from src.enrichment.business_impact import map_business_impacts  # type: ignore
                    except Exception:
                        map_business_impacts = None  # type: ignore
                    try:
                        if map_business_impacts:
                            inc['business_impact'] = map_business_impacts(sorted(list(inc['factors'])))
                    except Exception:
                        pass
                    # Persist full ingested event for evidence and analyst review
                    try:
                        inc.setdefault('ingested_events_full', []).append(event)
                    except Exception:
                        pass
                    # Attach / refresh graph explanation (best-effort)
                    self._maybe_attach_graph_explanation(inc, host)
                    self._merge_correlation_context(inc, event)
                    self._attach_memory_jobs(inc, host)
                    # Allow incident-level severity/playbook from event to be visible
                    try:
                        if 'severity' in event:
                            inc['severity'] = event.get('severity')
                        if 'playbook' in event:
                            inc['playbook'] = event.get('playbook')
                    except Exception:
                        pass
                    # Recompute risk score for the updated incident (best-effort async compat)
                    rs = self._resolve_risk_score(event, inc['factors'], inc.get('last_ts') or ts, float(inc.get('score') or 0.0))
                    if isinstance(rs, dict):
                        inc['risk'] = rs
                    return inc
                # If no host match, allow merging by factor overlap when above threshold
                if not host and len(fset & inc['factors']) >= self.factor_overlap:
                    inc['events'].append({'id': event.get('event_id'), 'ts': ts, 'factors': factors})
                    inc['factors'].update(fset)
                    inc['last_ts'] = ts
                    inc['score'] = min(1.0, inc['score'] + 0.05 * len(fset))
                    try:
                        inc['framework_enrichment'] = enrich_factors(sorted(list(inc['factors'])))
                    except Exception:
                        pass
                    # Attach business impact lenses (best-effort)
                    try:
                        from src.enrichment.business_impact import map_business_impacts  # type: ignore
                    except Exception:
                        map_business_impacts = None  # type: ignore
                    try:
                        if map_business_impacts:
                            inc['business_impact'] = map_business_impacts(sorted(list(inc['factors'])))
                    except Exception:
                        pass
                    try:
                        inc.setdefault('ingested_events_full', []).append(event)
                    except Exception:
                        pass
                    self._maybe_attach_graph_explanation(inc, host)
                    self._merge_correlation_context(inc, event)
                    self._attach_memory_jobs(inc, host)
                    try:
                        if 'severity' in event:
                            inc['severity'] = event.get('severity')
                        if 'playbook' in event:
                            inc['playbook'] = event.get('playbook')
                    except Exception:
                        pass
                    return inc
            # New incident
            iid = str(uuid.uuid4())
            inc = {
                'id': iid,
                'host': host,
                'created_ts': ts,
                'last_ts': ts,
                'events': [{'id': event.get('event_id'), 'ts': ts, 'factors': factors}],
                'factors': set(fset),
                'score': min(1.0, 0.1 * len(fset)),
                'framework_enrichment': enrich_factors(sorted(list(fset))) if fset else {},
                'ingested_events_full': [event],
                'human_comments': [],
            }
            # Business impact lenses (best‑effort)
            try:
                from src.enrichment.business_impact import map_business_impacts  # type: ignore
            except Exception:
                map_business_impacts = None  # type: ignore
            try:
                if map_business_impacts:
                    inc['business_impact'] = map_business_impacts(sorted(list(fset)))
            except Exception:
                pass
            self.incidents[iid] = inc
            # Compute initial risk for the new incident
            rs = self._resolve_risk_score(event, fset, inc.get('created_ts') or ts, float(inc.get('score') or 0.0))
            if isinstance(rs, dict):
                inc['risk'] = rs
            self._maybe_attach_graph_explanation(inc, host)
            self._merge_correlation_context(inc, event)
            self._attach_memory_jobs(inc, host)
            return inc

    def list_incidents(self) -> List[dict]:
        with self._lock:
            out = []
            for inc in self.incidents.values():
                out.append({
                    'id': inc['id'],
                    'host': inc['host'],
                    'factors': sorted(list(inc['factors'])),
                    'score': inc['score'],
                    'events': inc['events'],
                    'created_ts': inc['created_ts'],
                    'last_ts': inc['last_ts'],
                    'graph_explanation': inc.get('graph_explanation'),
                    'framework_enrichment': inc.get('framework_enrichment'),
                    'correlation_insights': inc.get('correlation_insights'),
                    'recommendation_catalog': inc.get('recommendation_catalog'),
                    'recommendation_actions': list((inc.get('recommendation_actions') or {}).values()),
                    'hopgraph_context': inc.get('hopgraph_context'),
                    'correlation_timeline': inc.get('correlation_timeline'),
                    'human_comments': inc.get('human_comments') or [],
                    'crq': inc.get('crq'),
                    'persona_routes': inc.get('persona_routes'),
                })
            return sorted(out, key=lambda x: x['score'], reverse=True)

    # ---------------- Persistence -----------------
    def save_snapshot(self):  # pragma: no cover (IO)
        with self._lock:
            try:
                serial = {
                    'ts': time.time(),
                    'incidents': [
                        {**{k:v for k,v in inc.items() if k not in ('factors','graph_explanation','framework_enrichment') and not str(k).startswith('_')},
                         'factors': list(inc['factors']),
                         'graph_explanation': inc.get('graph_explanation'),
                         'framework_enrichment': inc.get('framework_enrichment')}
                        for inc in self.incidents.values()
                    ]
                }
                with open(self.snapshot_path,'w',encoding='utf-8') as f:
                    json.dump(serial,f)
            except Exception:
                pass

    def load_snapshot(self):  # pragma: no cover (IO)
        try:
            with open(self.snapshot_path,'r',encoding='utf-8') as f:
                data = json.load(f)
            recs = data.get('incidents') or []
            with self._lock:
                for r in recs:
                    r['factors'] = set(r.get('factors',[]))
                    self.incidents[r['id']] = r
        except Exception:
            pass

    # ---------------- Graph Explainability (best-effort) -----------------
    def _maybe_attach_graph_explanation(self, inc: dict, host: str):
        if not host:
            return
        # Avoid spamming; refresh if missing or older than 60s
        now = time.time()
        ge = inc.get('graph_explanation')
        if ge and (now - ge.get('generated_ts', 0)) < 60:
            return
        try:
            from graph.unified import UG  # type: ignore
            # best-effort: use unified graph facade if available
            if not UG:
                return
            node_id = f'host:{host}'
            explanation = UG.explain_chain(node_id, max_depth=4, beam_width=5, top_k=2)
            explanation['generated_ts'] = now
            # Keep only lightweight subgraph
            inc['graph_explanation'] = {
                'score': explanation['chains'][0]['score'] if explanation['chains'] else 0.0,
                'top_chain': explanation['chains'][0] if explanation['chains'] else None,
                'subgraph': explanation['subgraph']
            }
        except Exception:
            pass

    def _merge_correlation_context(self, inc: dict, event: dict) -> None:
        """Persist correlation insights/recommendation catalog into the incident record."""
        if not isinstance(event, dict):
            return
        raw = event.get('correlation_insights') or event.get('correlationInsights')
        if not raw or not isinstance(raw, list):
            return
        existing = inc.setdefault('correlation_insights', [])
        seen: set = inc.setdefault('_correlation_seen', set())  # type: ignore[assignment]
        catalog = inc.setdefault('recommendation_catalog', [])
        catalog_seen: set = inc.setdefault('_catalog_seen', set())  # type: ignore[assignment]
        action_states: dict[str, dict[str, Any]] = inc.setdefault('recommendation_actions', {})  # type: ignore[assignment]
        now = time.time()
        for insight in raw:
            if not isinstance(insight, dict):
                continue
            token = None
            chain_id = insight.get('chain_id') or insight.get('id')
            if chain_id:
                token = f"{insight.get('type','insight')}|{chain_id}|{int(insight.get('generated_at') or now)}"
            if token and token in seen:
                continue
            if token:
                seen.add(token)
            cloned = dict(insight)
            if 'ttl_seconds' not in cloned and isinstance(cloned.get('expires_at'), (int, float)):
                cloned['ttl_seconds'] = max(0.0, float(cloned['expires_at']) - now)
            existing.append(cloned)
            hop_ctx = cloned.get('hopgraph_context')
            if hop_ctx:
                inc['hopgraph_context'] = hop_ctx
            catalog_entries = cloned.get('recommendation_catalog') or []
            if isinstance(catalog_entries, list):
                for entry in catalog_entries:
                    if not isinstance(entry, dict):
                        continue
                    action = entry.get('action')
                    if not action:
                        continue
                    domain = entry.get('domain') or 'multi'
                    key = f"{domain}|{action}"
                    if key in catalog_seen:
                        continue
                    catalog_seen.add(key)
                    entry_id = str(entry.get('id') or key)
                    catalog_row = {
                        'id': entry_id,
                        'domain': domain,
                        'action': action,
                        'priority': entry.get('priority') or '',
                    }
                    catalog.append(catalog_row)
                    if entry_id not in action_states:
                        action_states[entry_id] = {
                            'id': entry_id,
                            'domain': domain,
                            'action': action,
                            'priority': entry.get('priority') or '',
                            'status': 'pending',
                            'created_ts': now,
                            'updated_ts': now,
                        }
            timeline = inc.setdefault('correlation_timeline', [])
            timeline.append({
                'ts': now,
                'chain_id': cloned.get('chain_id'),
                'ttl_seconds': cloned.get('ttl_seconds'),
                'recommendation_actions': list(action_states.values()),
                'narrative': cloned.get('narrative'),
            })
            if len(timeline) > 25:
                del timeline[0]
            mem_jobs = cloned.get('memory_jobs')
            if mem_jobs:
                existing_jobs = {job.get('job_id') for job in inc.get('memory_jobs', []) if job.get('job_id')}
                merged_jobs = list(inc.get('memory_jobs', []))
                for job in mem_jobs:
                    if not isinstance(job, dict):
                        continue
                    jid = job.get('job_id')
                    if jid and jid in existing_jobs:
                        continue
                    merged_jobs.append(job)
                    if jid:
                        existing_jobs.add(jid)
                inc['memory_jobs'] = merged_jobs[:5]

    def update_recommendation_action(self, incident_id: str, action_id: str, status: str, actor: str | None = None) -> dict | None:
        """Update the status of a recommendation catalog action."""
        if not incident_id or not action_id:
            return None
        clean_status = str(status or '').lower()
        if clean_status not in {'pending', 'completed', 'acknowledged'}:
            clean_status = 'completed' if clean_status else 'pending'
        now = time.time()
        with self._lock:
            inc = self.incidents.get(incident_id)
            if not inc:
                return None
            action_states: dict[str, dict[str, Any]] = inc.setdefault('recommendation_actions', {})  # type: ignore[assignment]
            record = action_states.get(action_id)
            if record is None:
                return None
            record['status'] = clean_status
            record['updated_ts'] = now
            if actor:
                record['actor'] = actor
            history = inc.setdefault('recommendation_action_history', [])  # type: ignore[assignment]
            history.append({
                'id': action_id,
                'status': clean_status,
                'actor': actor,
                'ts': now,
            })
            return {
                'action': dict(record),
                'actions': list(action_states.values()),
                'history': list(history)[-20:],
            }

    def add_human_comment(self, incident_id: str, comment: dict) -> dict | None:
        """Append a human analyst comment to an incident.

        Comment fields: {text, actor, role, timestamp, impact_tag, suggested_action, status}
        Status transitions are free-form here; UI enforces {proposed, endorsed, contested, archived}.
        """
        if not incident_id or not isinstance(comment, dict):
            return None
        now = time.time()
        payload = {
            'text': str(comment.get('text') or ''),
            'actor': comment.get('actor'),
            'role': comment.get('role'),
            'timestamp': int(comment.get('timestamp') or now),
            'impact_tag': comment.get('impact_tag'),
            'suggested_action': comment.get('suggested_action'),
            'status': str(comment.get('status') or 'proposed'),
        }
        with self._lock:
            inc = self.incidents.get(incident_id)
            if not inc:
                return None
            arr = inc.setdefault('human_comments', [])
            arr.append(payload)
            audit = inc.setdefault('human_comment_history', [])
            audit.append({**payload, 'ts': now})
            # Keep a small rolling window for history
            if len(audit) > 100:
                del audit[0]
            return {
                'comment': payload,
                'comments': list(arr)[-20:],
                'history': list(audit)[-50:],
            }

    def _attach_memory_jobs(self, inc: dict, host: str | None) -> None:
        if not (MEMORY_JOB_STORE and host):
            return
        jobs = MEMORY_JOB_STORE.recent(host=host, limit=5)
        if not jobs:
            return
        existing = {job.get('job_id') for job in inc.get('memory_jobs', []) if job.get('job_id')}
        merged = list(inc.get('memory_jobs', []))
        for job in jobs:
            if not isinstance(job, dict):
                continue
            jid = job.get('job_id')
            if jid and jid in existing:
                continue
            merged.append(job)
            if jid:
                existing.add(jid)
        inc['memory_jobs'] = merged[:5]

GLOBAL_INCIDENTS = IncidentAggregator()

__all__ = ['IncidentAggregator','GLOBAL_INCIDENTS']
