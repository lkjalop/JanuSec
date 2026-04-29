"""TemporalRAG retrieval for persona dispatch.

Grounds persona dispatch suggestions in prior decisions for similar
incidents, time-filtered so audit replay doesn't leak future knowledge.

Three retrieval modes:
  - retrieve_similar_incidents: cosine on hashed-feature signature
  - retrieve_prior_decisions: technique+persona prior dispatches
  - retrieve_action_outcomes: prior action template outcomes
"""
from __future__ import annotations

import hashlib
import logging
import math
import sqlite3
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Protocol

from .bitemporal_dispatch_trace import DispatchDecision, DecisionTraceStore

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Feature signatures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IncidentSignature:
    mitre_techniques: tuple[str, ...]
    kill_chain_stage: str
    sensitivity: str
    data_classes: tuple[str, ...]
    principal_types: tuple[str, ...]
    verdict: str

    def feature_vector(self, n_dims: int = 256) -> list[float]:
        v = [0.0] * n_dims
        tokens: list[str] = []
        for t in self.mitre_techniques:
            tokens.append(f'mitre:{t}')
        tokens.append(f'kc:{self.kill_chain_stage}')
        tokens.append(f'sens:{self.sensitivity}')
        for c in self.data_classes:
            tokens.append(f'class:{c}')
        for p in self.principal_types:
            tokens.append(f'prin:{p}')
        tokens.append(f'verdict:{self.verdict}')
        for tok in tokens:
            for salt in ('a', 'b'):
                h = int(hashlib.sha1(f'{salt}|{tok}'.encode()).hexdigest(), 16)
                v[h % n_dims] += 1.0
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / norm for x in v]


def _signature_from_narrative(narrative: dict) -> IncidentSignature:
    affected_data = narrative.get('affected_data') or {}
    principals = narrative.get('affected_principals') or {}

    principal_types: list[str] = []
    if principals.get('users'):
        principal_types.append('human_user')
    if principals.get('service_accounts'):
        principal_types.append('service_account')
    if principals.get('cloud_roles') or principals.get('cloud_access_keys'):
        principal_types.append('cloud_identity')
    if principals.get('hosts'):
        principal_types.append('endpoint')

    return IncidentSignature(
        mitre_techniques=tuple(sorted(narrative.get('mitre_techniques') or [])),
        kill_chain_stage=str(narrative.get('kill_chain_stage') or 'unknown'),
        sensitivity=str(affected_data.get('sensitivity') or 'unknown'),
        data_classes=tuple(sorted(affected_data.get('classes') or [])),
        principal_types=tuple(sorted(set(principal_types))),
        verdict=str(narrative.get('verdict') or 'unknown'),
    )


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


# ─────────────────────────────────────────────────────────────────────────────
#  Index storage
# ─────────────────────────────────────────────────────────────────────────────

class IncidentIndexStore(Protocol):
    def index_incident(self, *,
                       tenant_id: str,
                       cluster_id: str,
                       signature: IncidentSignature,
                       valid_time_start: str,
                       valid_time_end: str,
                       transaction_time: str,
                       narrative_summary: str,
                       outcome_summary: Optional[str] = None) -> None: ...

    def query(self, *,
              tenant_id: str,
              query_signature: IncidentSignature,
              k: int,
              valid_time_after: str,
              as_of_transaction_time: str,
              technique_filter: Optional[set[str]] = None) -> list[dict]: ...


class SQLiteIncidentIndexStore:
    """Reference impl. Brute-force cosine after time filtering.
    Swap for pgvector at >50K incidents per tenant."""

    def __init__(self, path: str = ':memory:'):
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                tenant_id TEXT NOT NULL,
                cluster_id TEXT NOT NULL,
                valid_time_start TEXT,
                valid_time_end TEXT,
                transaction_time TEXT NOT NULL,
                signature_json TEXT NOT NULL,
                vector_json TEXT NOT NULL,
                narrative_summary TEXT,
                outcome_summary TEXT,
                techniques_json TEXT,
                PRIMARY KEY (tenant_id, cluster_id, transaction_time)
            )
        ''')
        self._conn.execute('CREATE INDEX IF NOT EXISTS ix_inc_tenant_time '
                          'ON incidents (tenant_id, transaction_time)')
        self._conn.commit()

    def index_incident(self, *, tenant_id, cluster_id, signature,
                       valid_time_start, valid_time_end, transaction_time,
                       narrative_summary, outcome_summary=None):
        import json as _json
        vec = signature.feature_vector()
        with self._lock:
            self._conn.execute(
                'INSERT OR REPLACE INTO incidents '
                '(tenant_id, cluster_id, valid_time_start, valid_time_end, '
                ' transaction_time, signature_json, vector_json, '
                ' narrative_summary, outcome_summary, techniques_json) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (tenant_id, cluster_id, valid_time_start, valid_time_end,
                 transaction_time, _json.dumps(signature.__dict__),
                 _json.dumps(vec), narrative_summary, outcome_summary,
                 _json.dumps(list(signature.mitre_techniques))),
            )
            self._conn.commit()

    def query(self, *, tenant_id, query_signature, k,
              valid_time_after, as_of_transaction_time,
              technique_filter=None):
        import json as _json
        with self._lock:
            rows = self._conn.execute(
                'SELECT cluster_id, valid_time_start, valid_time_end, '
                ' transaction_time, signature_json, vector_json, '
                ' narrative_summary, outcome_summary, techniques_json '
                'FROM incidents '
                'WHERE tenant_id = ? '
                '  AND transaction_time <= ? '
                '  AND (valid_time_end IS NULL OR valid_time_end >= ?)',
                (tenant_id, as_of_transaction_time, valid_time_after),
            ).fetchall()

        qv = query_signature.feature_vector()
        scored: list[dict] = []
        for r in rows:
            techs = set(_json.loads(r[8] or '[]'))
            if technique_filter and not (technique_filter & techs):
                continue
            try:
                sim = _cosine(qv, _json.loads(r[5]))
            except Exception:
                sim = 0.0
            scored.append({
                'cluster_id': r[0],
                'valid_time_start': r[1],
                'valid_time_end': r[2],
                'transaction_time': r[3],
                'signature': _json.loads(r[4]),
                'narrative_summary': r[6],
                'outcome_summary': r[7],
                'techniques': sorted(techs),
                'similarity': sim,
            })
        scored.sort(key=lambda x: x['similarity'], reverse=True)
        return scored[:k]


# ─────────────────────────────────────────────────────────────────────────────
#  Provider — the public interface persona_dispatch consumes
# ─────────────────────────────────────────────────────────────────────────────

class TemporalRAGProvider:
    """Composable retrieval provider. Falls back to empty results silently
    if the index store is unavailable."""

    def __init__(self, *,
                 incident_store: IncidentIndexStore,
                 decision_store: DecisionTraceStore,
                 tenant_id: str):
        self._incidents = incident_store
        self._decisions = decision_store
        self._tenant = tenant_id

    def retrieve_similar_incidents(self,
                                   narrative: dict,
                                   k: int = 5,
                                   lookback_days: int = 90,
                                   as_of: Optional[str] = None) -> list[dict]:
        try:
            sig = _signature_from_narrative(narrative)
            as_of_tt = as_of or datetime.now(timezone.utc).isoformat()
            valid_after = (datetime.now(timezone.utc) -
                           timedelta(days=lookback_days)).isoformat()
            return self._incidents.query(
                tenant_id=self._tenant,
                query_signature=sig,
                k=k,
                valid_time_after=valid_after,
                as_of_transaction_time=as_of_tt,
                technique_filter=set(sig.mitre_techniques) or None,
            )
        except Exception as e:
            logger.warning('TemporalRAG retrieve_similar_incidents failed: %s', e)
            return []

    def retrieve_prior_decisions(self,
                                 technique_ids: list[str],
                                 persona: str,
                                 k: int = 5,
                                 as_of: Optional[str] = None) -> list[dict]:
        try:
            similar_incidents = self.retrieve_similar_incidents(
                narrative={'mitre_techniques': technique_ids},
                k=k * 4,
                lookback_days=180,
                as_of=as_of,
            )
            out: list[dict] = []
            for inc in similar_incidents:
                vts_end = inc.get('valid_time_end')
                if not vts_end:
                    continue
                decisions = self._decisions.find_at_transaction_time(
                    cluster_id=inc['cluster_id'],
                    persona=persona,
                    tenant_id=self._tenant,
                    as_of=as_of or datetime.now(timezone.utc).isoformat(),
                )
                decisions.sort(key=lambda d: d.transaction_time, reverse=True)
                if decisions:
                    d = decisions[0]
                    out.append({
                        'cluster_id': inc['cluster_id'],
                        'transaction_time': d.transaction_time,
                        'valid_time_end': vts_end,
                        'similarity': inc['similarity'],
                        'verdict': d.verdict,
                        'confidence': d.confidence,
                        'headline': (d.payload or {}).get('headline'),
                        'action_count': len((d.payload or {}).get('required_actions') or []),
                        'action_outcomes_summary': _summarise_outcomes(d.action_outcomes),
                        'tactic_summary': inc.get('outcome_summary'),
                    })
                if len(out) >= k:
                    break
            return out
        except Exception as e:
            logger.warning('TemporalRAG retrieve_prior_decisions failed: %s', e)
            return []

    def retrieve_action_outcomes(self,
                                 action_template_id: str,
                                 k: int = 10,
                                 as_of: Optional[str] = None) -> list[dict]:
        # Stubbed — implement via a dedicated outcomes table indexed by template prefix
        return []


def _summarise_outcomes(outcomes: Optional[list[dict]]) -> str:
    if not outcomes:
        return 'no_outcomes_recorded'
    c = Counter(o.get('outcome') for o in outcomes)
    return ', '.join(f'{k}={v}' for k, v in c.most_common())


# ─────────────────────────────────────────────────────────────────────────────
#  Helper: render TemporalRAG context for persona LLM prompt
# ─────────────────────────────────────────────────────────────────────────────

def render_rag_context_for_prompt(prior_decisions: list[dict],
                                  similar_incidents: list[dict]) -> str:
    lines: list[str] = []
    if prior_decisions:
        lines.append('PRIOR DECISIONS (this tenant, similar techniques):')
        for d in prior_decisions[:5]:
            outcomes = d.get('action_outcomes_summary') or 'no_outcomes'
            lines.append(
                f"  - {d.get('transaction_time','?')[:10]}: "
                f"{d.get('headline','')} "
                f"(verdict={d.get('verdict','?')}, "
                f"actions={d.get('action_count',0)}, "
                f"outcomes={outcomes})"
            )
    if similar_incidents:
        if lines:
            lines.append('')
        lines.append('SIMILAR INCIDENTS (this tenant, last 90d):')
        for inc in similar_incidents[:5]:
            lines.append(
                f"  - {inc.get('valid_time_start','?')[:10]} -> "
                f"{inc.get('valid_time_end','?')[:10]}: "
                f"{inc.get('narrative_summary','(no summary)')[:140]} "
                f"[similarity={inc.get('similarity', 0):.2f}, "
                f"techniques={','.join(inc.get('techniques', [])[:4])}]"
            )
    if not lines:
        return '(no prior decisions or similar incidents on file)'
    lines.append('')
    lines.append('Use these to anchor your suggestions in actual prior practice.')
    lines.append('Note any divergence from prior pattern explicitly.')
    return '\n'.join(lines)


__all__ = [
    'TemporalRAGProvider',
    'IncidentSignature',
    'IncidentIndexStore',
    'SQLiteIncidentIndexStore',
    'render_rag_context_for_prompt',
]
