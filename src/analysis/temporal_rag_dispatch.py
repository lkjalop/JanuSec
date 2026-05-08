"""TemporalRAG retrieval for persona dispatch.

Grounds persona dispatch suggestions in prior decisions for similar
incidents, time-filtered so audit replay doesn't leak future knowledge.

Five retrieval modes:
  - retrieve_similar_incidents: cosine on hashed-feature signature
  - retrieve_prior_decisions: technique+persona prior dispatches
  - retrieve_action_outcomes: prior action template outcomes
  - retrieve_identity_context: lateral-movement paths from IdentityGraph
  - retrieve_chrono_anomalies: long-horizon volume z-scores from ChronoGraph
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


# Compact factor_tag → MITRE technique mapping for ML anomaly indexing
_FACTOR_MITRE_MAP: dict[str, list[str]] = {
    "iam:kerberoasting":                    ["T1558.003"],
    "iam:golden_ticket":                    ["T1558.001"],
    "iam:as_rep_roasting":                  ["T1558.004"],
    "iam:service_principal_credential_add": ["T1098.001"],
    "iam:oauth_consent_grant_suspicious_app": ["T1528"],
    "iam:azure_device_code_phishing":       ["T1528"],
    "recon:sustained_offhours_sequence":    ["T1087.002", "T1069.002"],
    "exfil:cumulative_bytes_anomaly":       ["T1048", "T1567"],
    "exfil:cumulative_cloud_bytes_anomaly": ["T1567", "T1048.002"],
    "token_reuse_foreign_asn":              ["T1550.001", "T1078.004"],
    "endpoint:first_seen_host_access":      ["T1021"],
    "endpoint:wmi_lateral_exec":            ["T1047"],
    "identity:iso_cross_source_anomaly":    [],
    "identity:ml_risk_spike":               [],
    "identity:ewma_behavioral_spike":       [],
}


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

    def retrieve_identity_context(
        self,
        principals: list[str],
        depth: int = 3,
        path_limit: int = 5,
    ) -> list[dict]:
        """Pull top lateral-movement paths for each principal from IdentityGraph."""
        out: list[dict] = []
        try:
            from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as _ig
            for principal in principals[:4]:
                node = principal if principal.startswith("user:") else f"user:{principal}"
                paths = _ig.find_top_paths(node, limit=path_limit, depth=depth)
                for p in paths[:3]:
                    explanation = _ig.explain_path(p.get("path") or [])
                    out.append({
                        "principal": principal,
                        "path": " -> ".join(p.get("path") or []),
                        "score": round(float(p.get("score") or 0), 3),
                        "risk_label": explanation.get("risk_label") or "",
                        "edge_types": explanation.get("edge_types") or [],
                    })
        except Exception as exc:
            logger.debug("retrieve_identity_context failed: %s", exc)
        return out

    def index_ml_anomaly(
        self,
        user: str,
        iso_score: float,
        z_scores: dict,
        factor_tags: list[str],
        assessment_id: str,
        ts: float,
    ) -> None:
        """Index an ML-detected anomaly as a synthetic incident for future RAG retrieval.

        Stores the anomaly so that future assessments' retrieve_prior_ml_anomalies()
        returns this user's historical ML signals — grounding LLM prompts in actual
        observed anomaly history, not just rule-based incidents.
        """
        try:
            import json as _json
            from datetime import datetime, timezone
            _ts_str = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            sig = IncidentSignature(
                mitre_techniques=tuple(sorted(
                    t for f in (factor_tags or [])
                    for t in (_FACTOR_MITRE_MAP.get(f) or [])
                )),
                kill_chain_stage="ml_detected",
                sensitivity="unknown",
                data_classes=tuple(sorted(factor_tags or [])),
                principal_types=("human_user",),
                verdict="ml_anomaly",
            )
            self._incidents.index_incident(
                tenant_id=self._tenant,
                cluster_id=f"ml:{user}:{assessment_id}",
                signature=sig,
                valid_time_start=_ts_str,
                valid_time_end=_ts_str,
                transaction_time=datetime.now(timezone.utc).isoformat(),
                narrative_summary=(
                    f"ML anomaly: user={user} iso={iso_score:.3f} "
                    f"factors={','.join(factor_tags[:4])} "
                    f"z_offhours={z_scores.get('off_hours_recon_events', 0):.1f} "
                    f"z_bytes={z_scores.get('bytes_out', 0):.1f}"
                ),
                outcome_summary="ml_anomaly",
            )
        except Exception as exc:
            logger.debug("index_ml_anomaly failed for %s: %s", user, exc)

    def retrieve_prior_ml_anomalies(
        self,
        principals: list[str],
        k: int = 5,
        lookback_days: int = 90,
        as_of: Optional[str] = None,
    ) -> list[dict]:
        """Return previously indexed ML anomalies for these principals.

        Gives the LLM a fifth retrieval silo: historical ML-detected anomalies
        for the same users, distinct from rule-based incident history.
        """
        out: list[dict] = []
        try:
            from datetime import datetime, timezone, timedelta
            as_of_tt = as_of or datetime.now(timezone.utc).isoformat()
            valid_after = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
            for principal in principals[:4]:
                dummy_sig = IncidentSignature(
                    mitre_techniques=(),
                    kill_chain_stage="ml_detected",
                    sensitivity="unknown",
                    data_classes=(),
                    principal_types=("human_user",),
                    verdict="ml_anomaly",
                )
                results = self._incidents.query(
                    tenant_id=self._tenant,
                    query_signature=dummy_sig,
                    k=k * 2,
                    valid_time_after=valid_after,
                    as_of_transaction_time=as_of_tt,
                )
                for r in results:
                    cid = r.get("cluster_id") or ""
                    if f"ml:{principal}" in cid or f"ml:{principal.lower()}" in cid:
                        out.append({
                            "principal": principal,
                            "date": (r.get("valid_time_start") or "?")[:10],
                            "summary": r.get("narrative_summary") or "",
                            "factors": r.get("techniques") or [],
                        })
                if len(out) >= k:
                    break
        except Exception as exc:
            logger.debug("retrieve_prior_ml_anomalies failed: %s", exc)
        return out[:k]

    def retrieve_chrono_anomalies(
        self,
        principals: list[str],
        hosts: list[str],
        window_seconds: float = 86400 * 7,
        z_threshold: float = 2.5,
    ) -> list[dict]:
        """Return ChronoGraph z-score anomalies for principals and hosts."""
        out: list[dict] = []
        try:
            from src.core.chrono.sketch_store import CHRONO as _chrono
            for entity_type, entities in (("user", principals[:4]), ("host", hosts[:4])):
                for entity_id in entities:
                    if not entity_id:
                        continue
                    metrics = _chrono.entity_metrics(entity_type, entity_id, window_seconds)
                    for metric, data in metrics.items():
                        if data.get("anomaly") or abs(float(data.get("z") or 0)) >= z_threshold:
                            out.append({
                                "entity_type": entity_type,
                                "entity_id": entity_id,
                                "metric": metric,
                                "z": data.get("z"),
                                "current": data.get("current"),
                                "mean": data.get("mean"),
                                "window_days": round(window_seconds / 86400, 1),
                            })
        except Exception as exc:
            logger.debug("retrieve_chrono_anomalies failed: %s", exc)
        return out


def _summarise_outcomes(outcomes: Optional[list[dict]]) -> str:
    if not outcomes:
        return 'no_outcomes_recorded'
    c = Counter(o.get('outcome') for o in outcomes)
    return ', '.join(f'{k}={v}' for k, v in c.most_common())


# ─────────────────────────────────────────────────────────────────────────────
#  Helper: render TemporalRAG context for persona LLM prompt
# ─────────────────────────────────────────────────────────────────────────────

def render_rag_context_for_prompt(
    prior_decisions: list[dict],
    similar_incidents: list[dict],
    identity_paths: list[dict] | None = None,
    chrono_anomalies: list[dict] | None = None,
    prior_ml_anomalies: list[dict] | None = None,
    compliance_violations: dict | None = None,
) -> str:
    """Render all five retrieval silos + compliance block into an LLM-prompt context block.

    Parameters
    ----------
    prior_decisions:      from TemporalRAGProvider.retrieve_prior_decisions()
    similar_incidents:    from TemporalRAGProvider.retrieve_similar_incidents()
    identity_paths:       from TemporalRAGProvider.retrieve_identity_context()
    chrono_anomalies:     from TemporalRAGProvider.retrieve_chrono_anomalies()
    prior_ml_anomalies:   from TemporalRAGProvider.retrieve_prior_ml_anomalies()
    compliance_violations: from compliance_mapper.map_factors_to_controls()
    """
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

    if identity_paths:
        if lines:
            lines.append('')
        lines.append('IDENTITY LATERAL-MOVEMENT PATHS (IdentityGraph, this assessment):')
        for p in identity_paths[:6]:
            edge_str = ', '.join((p.get('edge_types') or [])[:3])
            lines.append(
                f"  - {p.get('principal','?')}: {p.get('path','?')} "
                f"[score={p.get('score',0):.2f}, edges={edge_str or 'n/a'}, "
                f"risk={p.get('risk_label') or 'unknown'}]"
            )

    if chrono_anomalies:
        if lines:
            lines.append('')
        lines.append('LONG-HORIZON VOLUME ANOMALIES (ChronoGraph, z>=2.5):')
        for a in chrono_anomalies[:6]:
            lines.append(
                f"  - {a.get('entity_type','?')}:{a.get('entity_id','?')} "
                f"{a.get('metric','?')} z={a.get('z',0):.2f} "
                f"(current={a.get('current',0):.1f}, "
                f"hist_mean={a.get('mean',0):.1f}, "
                f"window={a.get('window_days',7)}d)"
            )

    if prior_ml_anomalies:
        if lines:
            lines.append('')
        lines.append('PRIOR ML ANOMALIES (historical ISO/EWMA signals for these users):')
        for a in prior_ml_anomalies[:5]:
            lines.append(
                f"  - {a.get('date','?')}: {a.get('principal','?')} — "
                f"{a.get('summary','')[:120]}"
            )

    if compliance_violations and compliance_violations.get('violations'):
        if lines:
            lines.append('')
        lines.append('COMPLIANCE CONTROLS VIOLATED (from factor analysis):')
        for v in compliance_violations['violations'][:6]:
            nist = ', '.join(v.get('nist_800_53') or [])
            lines.append(f"  [{v.get('severity','?').upper()}] {v.get('label','?')} — NIST: {nist or 'N/A'}")
        soc2 = ', '.join(compliance_violations.get('soc2_cc') or [])
        if soc2:
            lines.append(f"  SOC 2: {soc2}")

    if not lines:
        return '(no prior decisions, similar incidents, identity paths, volume anomalies, or ML signals on file)'
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
    '_FACTOR_MITRE_MAP',
]
