"""Report aggregation helpers for ingestion report endpoint.

This module gathers:
 - Recent alerts (normalized ring + persisted recent) via PlatformState
 - Decision cache (best-effort) for verdict/severity counts
 - Tabular session summaries + suspicious pattern rollups
 - Basic MITRE technique frequency

Caching: In-memory short TTL cache keyed by tuple(session_ids, limit, include_alerts)
"""
from __future__ import annotations

import json
import os
import time
import re
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Depends

from .dependencies import get_platform_state
try:
    from src.services.network_highlights import get_network_highlights_snapshot
except Exception:  # pragma: no cover
    def get_network_highlights_snapshot(_tenant: Optional[str]) -> Optional[Dict[str, Any]]:  # type: ignore
        return None

# Centralize decision cache lookups via runtime_state at call sites.

from core.threat_modeling.factor_taxonomy import aggregate_threat_model, controls_for_factors  # type: ignore
from core.threat_modeling.scenario_engine import ENGINE as SCEN_ENGINE  # type: ignore
from core.mappings.factor_to_mitre import get_all_mappings  # type: ignore
try:  # type: ignore[import]
    from core.factors.taxonomy_loader import factor_index  # type: ignore
except Exception:  # pragma: no cover
    factor_index = None  # type: ignore

from .upload_endpoints import TABULAR_SESSIONS
from .sbom_endpoints import get_active_exceptions  # type: ignore
try:
    # Internal helpers from SBOM endpoints to avoid HTTP roundtrips
    from .sbom_endpoints import get_recent_sbom_ids, get_sbom_vulns_data  # type: ignore
except Exception:  # pragma: no cover
    def get_recent_sbom_ids() -> list[str]:  # type: ignore
        return []
    def get_sbom_vulns_data(sbom_id: str, include_suppressed: bool = False) -> list[dict[str, Any]]:  # type: ignore
        return []

# ---- FinOps Cost Model (heuristic constants) ----
# These can later be externalized to configuration or a tuning endpoint.
FINOPS_COST_MODEL = {
    'ingest_event_unit_cost': 0.0004,          # Estimated $ per raw event normalized
    'alert_triage_unit_cost': 4.25,            # Estimated $ labor cost per manual alert triage
    'storage_row_unit_cost': 0.000001,         # Estimated $ per stored tabular row (amortized)
    'suspicious_cell_review_min': 0.25,        # Analyst minutes avoided per auto-flagged suspicious cell
    'analyst_minute_cost': 1.50,               # $ cost per analyst minute (blended)
}

_REPORT_CACHE: dict[str, dict[str, Any]] = {}
_REPORT_TTL = 60  # seconds

_TAXONOMY_CACHE: dict[str, dict[str, Any]] | None = None
_API_ROADMAP_CACHE: dict[str, Any] | None = None
_API_ROADMAP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'docs', 'domain_maturity', 'API_DOMAIN_PRODUCTION_ROADMAP.md'))

def _cache_key(
    sessions: list[str],
    include_alerts: bool,
    limit_alerts: int,
    tenant_id: str | None,
    alerts_offset: int,
    include_scenarios: bool,
    include_model: bool,
    persona: str | None,
    variant: str | None,
) -> str:
    return json.dumps(
        [
            sorted(sessions),
            include_alerts,
            limit_alerts,
            tenant_id,
            alerts_offset,
            include_scenarios,
            include_model,
            persona,
            variant,
        ],
        sort_keys=True,
    )


def _normalize_persona(persona: Optional[str]) -> Optional[str]:
    if not persona:
        return None
    try:
        token = str(persona).strip().lower()
        return token or None
    except Exception:
        return None


def _filter_by_persona(items: list[dict[str, Any]], persona: Optional[str]) -> list[dict[str, Any]]:
    if not persona:
        return list(items)
    filtered: list[dict[str, Any]] = []
    for rec in items:
        tags = rec.get('persona_tags')
        if not tags:
            filtered.append(rec)
            continue
        normalized: list[str] = []
        if isinstance(tags, str):
            normalized = [tags.strip().lower()]
        elif isinstance(tags, list):
            normalized = [
                str(tag).strip().lower()
                for tag in tags
                if isinstance(tag, (str, bytes)) and str(tag).strip()
            ]
        else:
            try:
                normalized = [str(tags).strip().lower()]
            except Exception:
                normalized = []
        if persona in normalized:
            filtered.append(rec)
    return filtered


def _build_network_artifacts(snapshot: Optional[dict[str, Any]]) -> list[dict[str, Any]]:
    if not snapshot:
        return []
    artifacts: list[dict[str, Any]] = []

    def _entry(entry_type: str, data: Any, personas: list[str]) -> dict[str, Any]:
        return {'type': entry_type, 'data': data, 'persona_tags': personas}

    window = snapshot.get('window_seconds')
    if snapshot.get('narrative'):
        artifacts.append(
            _entry(
                'narrative',
                snapshot['narrative'],
                ['executive', 'soc_analyst', 'threat_hunter'],
            )
        )
    if snapshot.get('top_talkers'):
        artifacts.append(
            _entry('top_talkers', snapshot['top_talkers'], ['soc_analyst', 'threat_hunter'])
        )
    if snapshot.get('beacon_findings'):
        artifacts.append(
            _entry(
                'beacon_findings',
                snapshot['beacon_findings'],
                ['soc_analyst', 'threat_hunter'],
            )
        )
    if snapshot.get('suspicious_asn'):
        artifacts.append(
            _entry(
                'suspicious_asn',
                snapshot['suspicious_asn'],
                ['threat_hunter', 'soc_analyst'],
            )
        )
    kill_chain = snapshot.get('kill_chain')
    if kill_chain:
        artifacts.append(
            _entry('kill_chain', kill_chain, ['executive', 'threat_hunter', 'soc_analyst'])
        )
    dread = snapshot.get('dread')
    if dread:
        artifacts.append(
            _entry('dread', dread, ['executive', 'soc_analyst', 'threat_hunter'])
        )
    pasta = snapshot.get('pasta')
    if pasta:
        artifacts.append(
            _entry('pasta', pasta, ['executive', 'soc_analyst', 'threat_hunter'])
        )
    missing_log = snapshot.get('missing_log')
    if missing_log and missing_log.get('flag'):
        artifacts.append(
            _entry(
                'missing_log',
                {'window_seconds': window, **missing_log},
                ['executive', 'soc_analyst'],
            )
        )
    return artifacts


def _extract_mitre_from_factor(factor: str) -> list[str]:
    """Return list of normalized MITRE tokens extracted from a factor.

    Normal forms returned include:
      - Technique codes like 'T1059' or 'T1566.001'
      - Tactic codes like 'TA0008'
    This function tolerates prefixes (mitre:, mitre_, mitre-) and mixed forms.
    """
    out: list[str] = []
    if not isinstance(factor, str):
        return out
    s = factor.strip()
    # Normalize common prefixes to simplify matching
    low = s.lower()
    if low.startswith('mitre:') or low.startswith('mitre_') or low.startswith('mitre-'):
        if ':' in s:
            s = s.split(':', 1)[1]
        elif '_' in s:
            s = s.split('_', 1)[1]
        elif '-' in s:
            s = s.split('-', 1)[1]
        s = s.strip()
    # Find techniques and tactics
    for m in re.findall(r'T\d{4}(?:\.\d{3})?', s, flags=re.IGNORECASE):
        out.append(m.upper())
    for m in re.findall(r'TA\d{4}', s, flags=re.IGNORECASE):
        out.append(m.upper())
    return out

def _now() -> float:
    return time.time()


def _compute_decision_cache_fingerprint(items: list) -> str:
    """Compute a stable short fingerprint for a list of decision-like items.

    This uses a sorted, minimal representation (id and last_seen/timestamp) to
    avoid cache misses caused by differing insertion orders across module
    aliasing. Returns a short hex string suitable for cache keys.
    """
    try:
        import hashlib
        import json as _json
        minimal = []
        for d in items:
            try:
                # support dict-like and object-like decisions
                if isinstance(d, dict):
                    id_ = d.get('event_id') or d.get('id') or d.get('event') or ''
                    ts = d.get('last_seen') or d.get('ts') or d.get('timestamp') or ''
                else:
                    id_ = getattr(d, 'event_id', None) or getattr(d, 'id', None) or ''
                    ts = getattr(d, 'last_seen', None) or getattr(d, 'ts', None) or getattr(d, 'timestamp', None) or ''
                minimal.append((str(id_), str(ts)))
            except Exception:
                try:
                    minimal.append((repr(d), ''))
                except Exception:
                    minimal.append(('', ''))
        minimal.sort()
        blob = _json.dumps(minimal, separators=(',', ':'), ensure_ascii=False)
        return hashlib.sha1(blob.encode('utf-8')).hexdigest()[:12]
    except Exception:
        return ''

def _taxonomy_index() -> dict[str, dict[str, Any]]:
    global _TAXONOMY_CACHE
    if _TAXONOMY_CACHE is not None:
        return _TAXONOMY_CACHE
    try:
        if factor_index:
            _TAXONOMY_CACHE = factor_index()
        else:  # pragma: no cover - fallback when taxonomy unavailable
            _TAXONOMY_CACHE = {}
    except Exception:
        _TAXONOMY_CACHE = {}
    return _TAXONOMY_CACHE

def _domain_for_factor(name: Any) -> str | None:
    if not isinstance(name, str):
        return None
    try:
        dom = _taxonomy_index().get(name, {}).get('domain')
        if dom:
            return str(dom)
    except Exception:
        dom = None
    if ':' in name:
        return name.split(':', 1)[0]
    return None

def _load_api_domain_status() -> dict[str, Any] | None:
    global _API_ROADMAP_CACHE
    if _API_ROADMAP_CACHE is not None:
        return _API_ROADMAP_CACHE
    try:
        with open(_API_ROADMAP_PATH, 'r', encoding='utf-8') as fh:
            text = fh.read()
    except Exception:
        _API_ROADMAP_CACHE = None
        return None
    status: dict[str, Any] = {'source_path': _API_ROADMAP_PATH}
    maturity = re.search(r'Current Maturity:\s*([0-9]+)%.*Target:\s*([0-9]+)%', text, flags=re.IGNORECASE | re.DOTALL)
    if maturity:
        status['current_maturity_pct'] = int(maturity.group(1))
        status['target_maturity_pct'] = int(maturity.group(2))
    current = re.search(r'Current API Factors\s*\((\d+)\s*Total', text, flags=re.IGNORECASE)
    if current:
        status['current_factor_count'] = int(current.group(1))
    target = re.search(r'Target State.*?(\d+)\s*factors', text, flags=re.IGNORECASE | re.DOTALL)
    if target:
        status['target_factor_count'] = int(target.group(1))
    roadmap_factors = sorted({tok.lower() for tok in re.findall(r'`(api:[a-z0-9_:-]+)`', text, flags=re.IGNORECASE)})
    if roadmap_factors:
        status['roadmap_factors'] = roadmap_factors
    _API_ROADMAP_CACHE = status
    return status

def _severity_from(decision: Any) -> str:
    # Support both object-like decisions and dict-like (legacy _record_decision uses dicts)
    def _g(obj, name, default=None):
        try:
            if isinstance(obj, dict):
                return obj.get(name, default)
        except Exception:
            pass
        return getattr(obj, name, default)

    verdict = (str(_g(decision, 'verdict', '') or '')).lower()
    score = float(_g(decision, 'confidence', 0.0) or 0.0)
    if verdict in ('malicious','block','escalate') and score >= 0.9:
        return 'critical'
    if score >= 0.75:
        return 'high'
    if score >= 0.55:
        return 'medium'
    return 'low'

def aggregate_decisions(limit: int = 500) -> dict[str, Any]:
    # Avoid stale module-level DECISION_CACHE created during circular imports by
    # importing the runtime DECISION_CACHE at call time.
    try:
        # Collect DECISION_CACHE values from possible runtime_state modules to
        # guard against test imports that create multiple module objects.
        import importlib
        from collections import OrderedDict
        caches = []
        try:
            mod = importlib.import_module('src.api.runtime_state')
            caches.append(getattr(mod, 'DECISION_CACHE'))
        except Exception:
            pass
        try:
            mod2 = importlib.import_module('api.runtime_state')
            caches.append(getattr(mod2, 'DECISION_CACHE'))
        except Exception:
            pass
        try:
            srv = importlib.import_module('src.api.server')
            caches.append(getattr(srv, 'DECISION_CACHE'))
        except Exception:
            pass
        try:
            srv2 = importlib.import_module('api.server')
            caches.append(getattr(srv2, 'DECISION_CACHE'))
        except Exception:
            pass
        try:
            app_mod = importlib.import_module('src.api.app')
            caches.append(getattr(app_mod, 'DECISION_CACHE'))
        except Exception:
            pass
        try:
            app_mod2 = importlib.import_module('api.app')
            caches.append(getattr(app_mod2, 'DECISION_CACHE'))
        except Exception:
            pass
        try:
            # local package path
            from .runtime_state import DECISION_CACHE as local_cache  # type: ignore
            caches.append(local_cache)
        except Exception:
            pass
        # Merge caches preserving insertion order; prefer later caches' values when keys collide
        merged = OrderedDict()
        for c in caches:
            try:
                for k, v in (getattr(c, 'items', lambda: list(c.items()))()):
                    merged[k] = v
            except Exception:
                try:
                    # c might be a plain dict-like
                    for k, v in list(c.items()):
                        merged[k] = v
                except Exception:
                    pass
        # Use the merged set of decisions but limit to the most recent `limit`
        # entries to avoid older test artifacts dominating the top_mitre list.
        # We merge caches first (to collect values from multiple runtime_state
        # instances) then slice to the last `limit` values which represent the
        # most-recent insertion order across the merged view.
        items = list(merged.values())[-limit:]
    except Exception:
        items = []
    verdict_counts: dict[str,int] = {}
    severity_counts: dict[str,int] = {'critical':0,'high':0,'medium':0,'low':0}
    top_mitre: dict[str,int] = {}
    flagged: list[dict[str,Any]] = []
    autoblocked: list[dict[str,Any]] = []
    def _g(obj, name, default=None):
        try:
            if isinstance(obj, dict):
                return obj.get(name, default)
        except Exception:
            pass
        return getattr(obj, name, default)

    for d in items:
        verdict = (str(_g(d, 'verdict', 'UNKNOWN') or 'UNKNOWN')).lower()
        verdict_counts[verdict] = verdict_counts.get(verdict,0)+1
        sev = _severity_from(d)
        severity_counts[sev] = severity_counts.get(sev,0)+1
        # factors -> pseudo mitre tags (placeholder)
        factors = _g(d, 'factors', []) or []
        # Build a per-decision set of techniques combining explicit tokens
        # and mapping-derived techniques to avoid double counting.
        per_decision_mitre: set[str] = set()
        try:
            # Explicit techniques embedded in factor strings
            for f in factors:
                if not isinstance(f, str):
                    continue
                for token in _extract_mitre_from_factor(f):
                    per_decision_mitre.add(token)
            # Derived techniques via mapping helper
            try:
                mapped = get_all_mappings(list(factors)).get('mitre', [])
                for t in mapped or []:
                    if isinstance(t, str) and t:
                        per_decision_mitre.add(t)
            except Exception:
                pass
        except Exception:
            per_decision_mitre = set()
        for token in per_decision_mitre:
            top_mitre[token] = top_mitre.get(token, 0) + 1
        raw_tags = _g(d, 'persona_tags', None)
        persona_tags: list[str] = []
        if isinstance(raw_tags, (list, tuple, set)):
            persona_tags = [str(tag) for tag in raw_tags if tag is not None]
        elif raw_tags not in (None, ''):
            persona_tags = [str(raw_tags)]
        rec = {
            'event_id': _g(d, 'event_id', None),
            'verdict': _g(d, 'verdict', None),
            'confidence': _g(d, 'confidence', None),
            'factors': list(factors)[:10]
        }
        if persona_tags:
            rec['persona_tags'] = persona_tags
        if verdict in ('review','escalate','suspicious'):
            if len(flagged) < 25:
                flagged.append(rec)
        if verdict in ('block','malicious'):
            if len(autoblocked) < 25:
                autoblocked.append(rec)
    top_mitre_sorted = sorted(top_mitre.items(), key=lambda kv: kv[1], reverse=True)[:15]
    # Debug hook: print detailed info when requested to help triage test ordering/fixtures
    try:
        if os.getenv('DEBUG_MITRE'):
            try:
                print('DEBUG_MITRE: items_count=', len(items))
                for idx, it in enumerate(items[-25:], start=1):
                    facs = []
                    try:
                        facs = list((_g(it,'factors',[]) or []) )
                    except Exception:
                        facs = []
                    print(f'  ITEM[{idx}]: event_id={_g(it,"event_id",None)} verdict={_g(it,"verdict",None)} factors={facs}')
                print('DEBUG_MITRE: top_mitre_dict=', top_mitre)
            except Exception:
                pass
    except Exception:
        pass
    return {
        'total': len(items),
        'verdict_counts': verdict_counts,
        'severity_distribution': severity_counts,
        'top_mitre': [{'technique': t,'count': c} for t,c in top_mitre_sorted],
        'flagged_events': flagged,
        'autoblocked_samples': autoblocked
    }

def aggregate_alerts(state, limit: int = 300, offset: int = 0, tenant_id: str | None = None) -> tuple[list[dict[str,Any]], int]:
    try:
        snaps = state.recent_alerts(limit=limit+offset+50, tenant_id=tenant_id)
        rows = [s.model_dump() for s in snaps]
        total = len(rows)
        slice_rows = rows[offset: offset + limit]
        return slice_rows, total
    except Exception:
        return [], 0

def collect_tabular_sessions(session_ids: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    out = []
    pattern_rollup = {
        'suspicious_cells': 0,
        'base64_matches': 0,
        'powershell_matches': 0,
        'examples': {'base64': [], 'powershell': []}
    }
    for sid in session_ids:
        meta = TABULAR_SESSIONS.get(sid)
        if not meta:
            continue
        pats = meta.get('patterns') or {}
        totals = pats.get('totals', {})
        pattern_rollup['suspicious_cells'] += totals.get('suspicious_cells',0)
        pattern_rollup['base64_matches'] += totals.get('base64_matches',0)
        pattern_rollup['powershell_matches'] += totals.get('powershell_matches',0)
        # collect limited examples
        for cat in ('base64','powershell'):
            if len(pattern_rollup['examples'][cat]) < 5:
                pattern_rollup['examples'][cat].extend((pats.get('examples', {}) or {}).get(cat, [])[:5 - len(pattern_rollup['examples'][cat])])
        out.append({
            'session': sid,
            'filename': meta.get('filename'),
            'file_type': meta.get('file_type'),
            'total_rows': meta.get('total_rows'),
            'headers': meta.get('headers')[:50],
            'created': meta.get('created'),
            'suspicious_cells': totals.get('suspicious_cells',0)
        })
    return out, pattern_rollup

def _apply_tenant(decisions: dict[str,Any], tenant_id: str | None) -> dict[str,Any]:
    if not tenant_id:
        return decisions
    default_tenant = os.getenv('DEFAULT_TENANT', 'default')
    # Filter flagged/autoblocked lists based on tenant_id attribute if present
    def _filt(lst: list[dict[str,Any]]) -> list[dict[str,Any]]:
        out: list[dict[str,Any]] = []
        for rec in lst:
            evt_id = rec.get('event_id')
            try:
                from .runtime_state import DECISION_CACHE as RUNTIME_DECISION_CACHE  # type: ignore
                dec_obj = RUNTIME_DECISION_CACHE.get(evt_id)
            except Exception:
                dec_obj = None
            if dec_obj is None:
                continue
            dec_tenant = getattr(dec_obj, 'tenant_id', None)
            if dec_tenant is None and tenant_id == default_tenant:
                out.append(rec)
                continue
            if dec_tenant == tenant_id:
                out.append(rec)
        return out
    filtered_flagged = _filt(decisions.get('flagged_events', []))
    filtered_auto = _filt(decisions.get('autoblocked_samples', []))
    # Recompute severity & verdict counts from union of filtered lists (approximation) since we lack tenant-partitioned full set
    verdict_counts: dict[str,int] = {}
    severity_distribution: dict[str,int] = {'critical':0,'high':0,'medium':0,'low':0}
    for rec in filtered_flagged + filtered_auto:
        v = (rec.get('verdict') or 'unknown').lower()
        verdict_counts[v] = verdict_counts.get(v,0)+1
        rec.get('dread','')  # placeholder not used for severity; derive from decision object
        evt_id = rec.get('event_id')
        try:
            from .runtime_state import DECISION_CACHE as RUNTIME_DECISION_CACHE  # type: ignore
            dec_obj = RUNTIME_DECISION_CACHE.get(evt_id)
        except Exception:
            dec_obj = None
        if dec_obj is not None:
            sev_label = _severity_from(dec_obj)
            severity_distribution[sev_label] = severity_distribution.get(sev_label,0)+1
    # Approximate total as sum of recomputed verdicts
    total_events = sum(verdict_counts.values())
    new_verdict_stats = {
        'total_events': total_events,
        **verdict_counts
    }
    return {
        **decisions,
        'flagged_events': filtered_flagged,
        'autoblocked_samples': filtered_auto,
        'severity_distribution': severity_distribution,
        'verdict_counts': verdict_counts,
        'tenant_scoped': True,
        'tenant_verdict_stats': new_verdict_stats,
    }

def _unified_threat_model(factors: list[str]) -> dict[str,Any]:
    try:
        model = aggregate_threat_model(factors)
    except Exception:
        return {}
    dread_avg = model.get('dread', {}).get('average', {}) or {}
    try:
        comps = [v for v in dread_avg.values() if isinstance(v,(int,float))]
        composite = round(sum(comps)/len(comps),2) if comps else None
    except Exception:
        composite = None
    model['dread']['composite'] = composite
    try:
        phases = model.get('maestro', {}).get('phases', []) or []
        if phases:
            top_vals = [p[1] for p in phases[:3]]
            m_comp = round(sum(top_vals)/len(top_vals),2)
            model['maestro']['composite'] = m_comp
    except Exception:
        pass
    return model

def _build_framework_summary(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not records:
        return None
    stride_set: set[str] = set()
    stride_counts: dict[str,int] = {}
    dread_acc = {'damage':0.0,'reproducibility':0.0,'exploitability':0.0,'affected_users':0.0,'discoverability':0.0}
    dread_samples = 0
    maestro_phase_counts: dict[str,int] = {}
    pasta_stage_counts: dict[int,int] = {}
    cvss_counts: dict[str, dict[str,int]] = {}
    controls_set: set[str] = set()
    for rec in records:
        tm = rec.get('threat_model') or {}
        stride = (tm.get('stride') or {}).get('categories', []) or []
        for s in stride:
            stride_set.add(s)
            stride_counts[s] = stride_counts.get(s, 0) + 1
        dread = (tm.get('dread') or {}).get('average', {}) or {}
        if dread:
            dread_samples += 1
            for k in dread_acc:
                v = dread.get(k)
                if isinstance(v,(int,float)):
                    dread_acc[k] += float(v)
        for phase,count in (tm.get('maestro') or {}).get('phases', []) or []:
            try:
                maestro_phase_counts[phase] = maestro_phase_counts.get(phase,0) + int(count)
            except Exception:
                maestro_phase_counts[phase] = maestro_phase_counts.get(phase,0) + 1
        for st in (tm.get('pasta_stages') or tm.get('pasta_stage') or []):
            try:
                st_i = int(st)
            except Exception:
                continue
            pasta_stage_counts[st_i] = pasta_stage_counts.get(st_i, 0) + 1
        cv = tm.get('cvss') or {}
        for dim, val in cv.items():
            dim_key = str(dim).lower()
            val_map = cvss_counts.setdefault(dim_key, {})
            val_map[str(val).upper()] = val_map.get(str(val).upper(), 0) + 1
        try:
            for c in controls_for_factors(rec.get('factors', []) or []):
                ctrl = c.get('control') if isinstance(c, dict) else str(c)
                controls_set.add(ctrl)
        except Exception:
            pass
    dread_avg = None
    if dread_samples:
        dread_avg = {k: round(v/max(dread_samples,1),2) for k,v in dread_acc.items()}
    return {
        'stride_categories': sorted(stride_set),
        'stride_counts': sorted(stride_counts.items(), key=lambda x: (-x[1], x[0])),
        'dread_average_across_events': dread_avg,
        'maestro_phase_density': sorted(maestro_phase_counts.items(), key=lambda x: (-x[1], x[0]))[:15],
        'pasta_stage_distribution': sorted(pasta_stage_counts.items(), key=lambda x: x[0]),
        'cvss_distribution': {dim: sorted(vals.items(), key=lambda x: (-x[1], x[0])) for dim, vals in cvss_counts.items()},
        'controls': sorted(controls_set),
    }

def _compute_domain_rollups(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        return {}
    rollups: dict[str, dict[str, Any]] = {}
    for rec in records:
        factors = rec.get('factors', []) or []
        if not factors:
            continue
        domains: set[str] = set()
        for f in factors:
            dom = _domain_for_factor(f)
            if not dom:
                continue
            entry = rollups.setdefault(dom, {
                'count': 0,
                'factors': set(),
                'stride': {},
                'maestro': {},
                'pasta': {},
                'cvss': {},
            })
            entry['count'] += 1
            entry['factors'].add(f)
            domains.add(dom)
        if not domains:
            continue
        tm = rec.get('threat_model') or {}
        stride = (tm.get('stride') or {}).get('categories', []) or []
        maestro = (tm.get('maestro') or {}).get('phases', []) or []
        pasta = (tm.get('pasta_stages') or tm.get('pasta_stage') or []) or []
        cvss = tm.get('cvss') or {}
        for dom in domains:
            entry = rollups[dom]
            for s in stride:
                entry['stride'][s] = entry['stride'].get(s, 0) + 1
            for ph, cnt in maestro:
                try:
                    entry['maestro'][ph] = entry['maestro'].get(ph,0) + int(cnt)
                except Exception:
                    entry['maestro'][ph] = entry['maestro'].get(ph,0) + 1
            for st in pasta:
                entry['pasta'][st] = entry['pasta'].get(st,0) + 1
            for dim, val in cvss.items():
                dim_key = str(dim).lower()
                val_key = str(val).upper()
                dim_map = entry['cvss'].setdefault(dim_key, {})
                dim_map[val_key] = dim_map.get(val_key, 0) + 1
    normalized: dict[str, Any] = {}
    for dom, data in rollups.items():
        normalized[dom] = {
            'count': data.get('count', 0),
            'factors': sorted(data.get('factors', [])),
            'stride': sorted((data.get('stride') or {}).items(), key=lambda x: (-x[1], x[0])),
            'maestro': sorted((data.get('maestro') or {}).items(), key=lambda x: (-x[1], x[0])),
            'pasta': sorted((data.get('pasta') or {}).items(), key=lambda x: (-x[1], x[0])),
            'cvss': {dim: sorted(vals.items(), key=lambda x: (-x[1], x[0])) for dim, vals in (data.get('cvss') or {}).items()},
        }
    return normalized

def _sbom_vuln_rollup(include_suppressed_vex: bool = False) -> dict[str, Any] | None:
    """Aggregate recent SBOM vulnerability data into severity buckets and top CVEs.

    Returns a dict like:
      {
        'sbom_ids': [...],
        'severity_distribution': {'critical': n, 'high': n, 'medium': n, 'low': n, 'unknown': n},
        'top_cves': [{'cve': 'CVE-YYYY-XXXX', 'count': n}, ...],
        'total_vulns': N
      }
    or None if no SBOM data present.
    """
    try:
        sbom_ids = get_recent_sbom_ids()
    except Exception:
        sbom_ids = []
    if not sbom_ids:
        return None
    sev_counts: dict[str,int] = {'critical':0,'high':0,'medium':0,'low':0,'unknown':0}
    cve_counts: dict[str,int] = {}
    comp_counts: dict[str,int] = {}
    total = 0
    accepted_count = 0
    kev_total = 0
    epss_weighted_crit_30d = 0.0
    # Exposure metric accumulators (severity-weighted EPSS across all non‑suppressed vulns)
    epss_weighted_exposure = 0.0
    severity_weights = {'critical': 1.0, 'high': 0.6, 'medium': 0.3, 'low': 0.1}
    # Critical aging buckets (open critical vulns not covered by exception)
    crit_aging = {'le_7d': 0, 'd8_30d': 0, 'gt_30d': 0}
    # Accepted vs open tracking per severity
    accepted_by_sev: dict[str,int] = {'critical':0,'high':0,'medium':0,'low':0,'unknown':0}
    open_by_sev: dict[str,int] = {'critical':0,'high':0,'medium':0,'low':0,'unknown':0}
    # For reachability (very light heuristic): map component name -> reachable flag if any sanitized event shows matching service/port
    reachable_components: dict[str,bool] = {}
    try:
        # Peek into recent sanitized events from runtime
        from .runtime_state import _RUNTIME as _RT  # type: ignore
        rt = _RT
        items = []
        try:
            # best-effort lockless glance
            items = list(rt.sanitized_events)[:500]
        except Exception:
            items = []
        # Record service/port exposure markers by domain/component-ish hints
        open_ports: set[int] = set()
        for ev in items:
            p = ev.get('dst_port') or ev.get('destination_port') or ev.get('port')
            try:
                if p: open_ports.add(int(p))
            except Exception:
                pass
        # Heuristic: map common components to canonical service ports
        common_map = {
            'openssl': {443, 8443},
            'httpd': {80, 8080, 8000, 443},
            'nginx': {80, 443, 8080},
            'tomcat': {8080, 8443},
            'struts': {8080, 8443},
            'log4j': set(),  # indirect, assume reachable if any Java web port is open
        }
    except Exception:
        common_map = {}
        open_ports = set()
    import time as _t
    now_ts = _t.time()
    horizon = 30*86400
    for sid in sbom_ids:
        try:
            vulns = get_sbom_vulns_data(sid, include_suppressed=include_suppressed_vex) or []
        except Exception:
            vulns = []
        # Apply exceptions: mark accepted risk so we can report separately
        try:
            exc = get_active_exceptions(sid)
        except Exception:
            exc = []
        try:
            accepted_count += len(exc)
        except Exception:
            pass
        accepted_components = {(e.get('component') or '').strip().lower() for e in exc}
        for v in vulns:
            sev = str(v.get('severity') or 'unknown').lower()
            if sev not in sev_counts:
                sev = 'unknown'
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            cve = (v.get('cve') or '').strip()
            if cve:
                cve_counts[cve] = cve_counts.get(cve, 0) + 1
                if v.get('kev'):
                    kev_total += 1
                # approximate last 30 days EPSS weighted criticals if EPSS present and severity critical
                if sev == 'critical':
                    try:
                        obs = float(v.get('observed_ts') or 0)
                    except Exception:
                        obs = 0.0
                    if obs and (now_ts - obs) <= horizon:
                        try:
                            epss = float(v.get('epss') or 0.0)
                        except Exception:
                            epss = 0.0
                        epss_weighted_crit_30d += epss
            comp = (v.get('component') or '').strip()
            if comp:
                comp_counts[comp] = comp_counts.get(comp, 0) + 1
                # Reachability heuristic
                lc = comp.lower()
                reachable = False
                for key, ports in (common_map or {}).items():
                    if key in lc and (not ports or (open_ports & ports)):
                        reachable = True
                        break
                # PURL/CPE hints
                try:
                    purl = str(v.get('purl') or '').lower()
                    cpe = str(v.get('cpe') or '').lower()
                    def _hints(text: str) -> set[int]:
                        out = set()
                        if not text:
                            return out
                        if 'nginx' in text or 'httpd' in text or 'apache:http_server' in text:
                            out |= {80,443,8080,8443}
                        if 'tomcat' in text or 'struts' in text:
                            out |= {8080,8443}
                        if 'openssl' in text:
                            out |= {443,8443}
                        return out
                    hinted = _hints(purl) | _hints(cpe)
                    if hinted and (open_ports & hinted):
                        reachable = True
                except Exception:
                    pass
                if reachable:
                    reachable_components[comp] = True
            # Exposure metric accumulation (non-suppressed only)
            try:
                if not v.get('suppressed'):
                    epss_val = float(v.get('epss') or 0.0)
                    epss_weighted_exposure += epss_val * severity_weights.get(sev, 0.05)
            except Exception:
                pass
            # Open vs accepted classification
            try:
                comp_l = comp.lower()
                key_match = any((e.get('component') or '').strip().lower() == comp_l and (not cve or not e.get('cve') or e.get('cve')==cve) for e in exc)
                if key_match:
                    accepted_by_sev[sev] = accepted_by_sev.get(sev,0)+1
                else:
                    open_by_sev[sev] = open_by_sev.get(sev,0)+1
            except Exception:
                pass
            # Critical aging buckets (only for open, critical severity)
            if sev == 'critical':
                try:
                    obs = float(v.get('observed_ts') or 0)
                except Exception:
                    obs = 0.0
                if obs:
                    age_days = (now_ts - obs)/86400.0
                    try:
                        if key_match:  # skip accepted in aging open buckets
                            pass
                        else:
                            if age_days <= 7:
                                crit_aging['le_7d'] += 1
                            elif age_days <= 30:
                                crit_aging['d8_30d'] += 1
                            else:
                                crit_aging['gt_30d'] += 1
                    except Exception:
                        pass
            total += 1
    top_cves = sorted(cve_counts.items(), key=lambda x: (-x[1], x[0]))[:15]
    # Sort components by reachability first, then count
    top_components = sorted(comp_counts.items(), key=lambda x: ((0 if reachable_components.get(x[0]) else 1), -x[1], x[0]))[:15]
    return {
        'sbom_ids': sbom_ids,
        'severity_distribution': sev_counts,
        'top_cves': [{'cve': c, 'count': n} for c,n in top_cves],
        'top_components': [{'component': c, 'count': n, 'reachable': bool(reachable_components.get(c))} for c,n in top_components],
        'total_vulns': total,
        'kev_present_count': kev_total,
        'epss_weighted_critical_last_30d': round(epss_weighted_crit_30d, 3),
        'accepted_exceptions_count': accepted_count,
        'epss_weighted_exposure': round(epss_weighted_exposure, 3),
        'critical_aging': crit_aging,
        'accepted_by_severity': accepted_by_sev,
        'open_by_severity': open_by_sev,
    }

def _scenario_summary(decisions: dict[str,Any]) -> dict[str,Any]:
    scen_counts: dict[str, dict[str, Any]] = {}
    def _acc(recs: list[dict[str,Any]]):
        for r in recs:
            for scen in r.get('scenarios', []) or []:
                sid = scen.get('id')
                if not sid:
                    continue
                entry = scen_counts.setdefault(sid, {
                    'id': sid,
                    'status_counts': {},
                    'max_risk': 0.0,
                    'occurrences': 0,
                    'tags': scen.get('tags') or []
                })
                status = scen.get('status','unknown')
                entry['status_counts'][status] = entry['status_counts'].get(status,0)+1
                cr = scen.get('composite_risk') or 0.0
                if isinstance(cr,(int,float)) and cr > entry['max_risk']:
                    entry['max_risk'] = cr
                entry['occurrences'] += 1
    _acc(decisions.get('flagged_events', []))
    _acc(decisions.get('autoblocked_samples', []))
    if not scen_counts:
        return {'scenarios': [], 'observed_count': 0}
    scenarios_list = sorted(scen_counts.values(), key=lambda x: (-x['max_risk'], -x['occurrences'], x['id']))
    observed_total = sum(v['occurrences'] for v in scenarios_list)
    return {
        'scenarios': scenarios_list,
        'observed_count': observed_total,
        'top': scenarios_list[0] if scenarios_list else None
    }

def build_ingestion_report(
    session_ids: list[str],
    include_alerts: bool,
    limit_alerts: int,
    state,
    tenant_id: str | None = None,
    alerts_offset: int = 0,
    include_scenarios: bool = False,
    include_model: bool = False,
    include_suppressed_vex: bool = False,
    persona: str | None = None,
    variant: str | None = None,
) -> dict[str, Any]:
    # Add a lightweight marker from the decision cache (last few keys) so that
    # the report cache is invalidated when new decisions are added during
    # tests or runtime activity. We keep this best-effort and non-critical.
    decision_marker = None
    try:
        from . import runtime_state as _rs  # type: ignore
        try:
            # Build a small fingerprint of the most recent decisions to invalidate
            # cached reports deterministically when decisions change across tests.
            all_vals = list(_rs.DECISION_CACHE.values())
            tail = all_vals[-50:]
            fp = _compute_decision_cache_fingerprint(tail)
            if fp:
                decision_marker = fp
        except Exception:
            decision_marker = None
    except Exception:
        decision_marker = None
    persona_norm = _normalize_persona(persona)
    variant_norm = (variant or '').strip().lower() or None
    key = _cache_key(
        session_ids,
        include_alerts,
        limit_alerts,
        tenant_id,
        alerts_offset,
        include_scenarios,
        include_model,
        persona_norm,
        variant_norm,
    )
    if decision_marker:
        key = key + '::' + decision_marker
    cached = _REPORT_CACHE.get(key)
    if cached and _now() - cached['generated_at'] < _REPORT_TTL:
        return cached['report']

    decisions = _apply_tenant(aggregate_decisions(), tenant_id)
    flagged_filtered = _filter_by_persona(decisions.get('flagged_events', []), persona_norm)
    auto_filtered = _filter_by_persona(decisions.get('autoblocked_samples', []), persona_norm)
    decisions['flagged_events'] = flagged_filtered
    decisions['autoblocked_samples'] = auto_filtered
    alerts, total_alerts = aggregate_alerts(state, limit=limit_alerts, offset=alerts_offset, tenant_id=tenant_id) if include_alerts else ([],0)
    if include_alerts:
        alerts = _filter_by_persona(alerts, persona_norm)
    sessions, pattern_rollup = collect_tabular_sessions(session_ids)

    # Decorate flagged/autoblocked with unified model & optional scenarios
    for rec in decisions.get('flagged_events', []):
        factors = rec.get('factors', [])
        model = _unified_threat_model(factors)
        if model:
            rec['threat_model'] = model
            rec['dread'] = model.get('dread', {})
            rec['maestro'] = model.get('maestro', {})
        if include_scenarios:
            rec['scenarios'] = SCEN_ENGINE.evaluate(factors)
    for rec in decisions.get('autoblocked_samples', []):
        factors = rec.get('factors', [])
        model = _unified_threat_model(factors)
        if model:
            rec['threat_model'] = model
            rec['dread'] = model.get('dread', {})
            rec['maestro'] = model.get('maestro', {})
        if include_scenarios:
            rec['scenarios'] = SCEN_ENGINE.evaluate(factors)

    # ---------------- FinOps Metrics (computed heuristics) ----------------
    finops: dict[str, Any] | None = None
    try:
        ingest_events = decisions.get('total', 0)
        total_alerts_returned = len(alerts)
        autoblocked_samples_count = len(decisions.get('autoblocked_samples', []))
        suspicious_cells = pattern_rollup.get('suspicious_cells', 0)

        # Derived storage row count from sessions metadata
        total_rows = 0
        for s in sessions:
            try:
                total_rows += int(s.get('total_rows') or 0)
            except Exception:
                pass

        cm = FINOPS_COST_MODEL
        ingest_cost = round(ingest_events * cm['ingest_event_unit_cost'], 4)
        storage_cost = round(total_rows * cm['storage_row_unit_cost'], 4)
        alert_triage_cost = round(total_alerts_returned * cm['alert_triage_unit_cost'], 2)
        avoided_manual_triage_cost = round(autoblocked_samples_count * cm['alert_triage_unit_cost'], 2)
        suspicious_review_minutes_saved = suspicious_cells * cm['suspicious_cell_review_min']
        suspicious_review_cost_saved = round(suspicious_review_minutes_saved * cm['analyst_minute_cost'], 2)
        net_savings = round(avoided_manual_triage_cost + suspicious_review_cost_saved - alert_triage_cost, 2)
        roi_ratio = None
        baseline_cost = alert_triage_cost + ingest_cost + storage_cost
        if baseline_cost > 0:
            roi_ratio = round((net_savings / baseline_cost), 3)

        finops = {
            'model': cm,
            'ingest_events': ingest_events,
            'ingest_cost_estimate': ingest_cost,
            'storage_rows': total_rows,
            'storage_cost_estimate': storage_cost,
            'alerts_returned': total_alerts_returned,
            'alert_triage_cost_estimate': alert_triage_cost,
            'autoblocked_events_sampled': autoblocked_samples_count,
            'avoided_manual_triage_cost_estimate': avoided_manual_triage_cost,
            'suspicious_cells': suspicious_cells,
            'suspicious_cell_minutes_saved_estimate': round(suspicious_review_minutes_saved, 2),
            'suspicious_cell_cost_saved_estimate': suspicious_review_cost_saved,
            'net_savings_estimate': net_savings,
            'roi_ratio_estimate': roi_ratio,
        }
    except Exception:
        finops = None

    scenario_block = _scenario_summary(decisions) if include_scenarios else None
    combined_records = decisions.get('flagged_events', []) + decisions.get('autoblocked_samples', [])
    framework_summary = _build_framework_summary(combined_records)
    model_summary: dict[str, Any] | None = framework_summary if include_model and framework_summary else None

    # Business impact summary across combined records (best-effort)
    try:
        from src.enrichment.business_impact import summarize_business_impact  # type: ignore
    except Exception:
        summarize_business_impact = None  # type: ignore
    impact_summary = None
    try:
        if summarize_business_impact:
            impact_summary = summarize_business_impact(combined_records)
    except Exception:
        impact_summary = None

    # SBOM vulnerability rollup (executive overlay)
    sbom_summary = _sbom_vuln_rollup(include_suppressed_vex)

    # Snapshot active feature flags (for audit / reproducibility)
    try:
        from core.feature_flags import all_flags as _all_flags  # type: ignore
        _flags_snapshot = _all_flags()
    except Exception:
        _flags_snapshot = []
    # Build compliance control references at the top-level from decisions
    try:
        top_controls: set[str] = set()
        for rec in decisions.get('flagged_events', []) + decisions.get('autoblocked_samples', []):
            try:
                for c in controls_for_factors(rec.get('factors', []) or []):
                    try:
                        ctrl = c.get('control') if isinstance(c, dict) else str(c)
                    except Exception:
                        ctrl = str(c)
                    top_controls.add(ctrl)
            except Exception:
                pass
        def _group_controls(items: list[str]) -> dict[str, list[str]]:
            grp = {'iso': [], 'nist': [], 'cis': []}
            for c in items:
                u = c.upper()
                if u.startswith('ISO'):
                    grp['iso'].append(c)
                elif u.startswith('NIST'):
                    grp['nist'].append(c)
                elif u.startswith('CIS-'):
                    grp['cis'].append(c)
            for k in grp:
                grp[k] = sorted(set(grp[k]))
            return grp
        compliance_controls = {'controls': sorted(top_controls), **_group_controls(sorted(top_controls))}
    except Exception:
        compliance_controls = {'controls': []}

    try:
        network_tenant = tenant_id or os.getenv('DEFAULT_TENANT', 'public')
        network_snapshot = get_network_highlights_snapshot(network_tenant)
    except Exception:
        network_snapshot = None
    persona_network_artifacts = _filter_by_persona(_build_network_artifacts(network_snapshot), persona_norm)

    report = {
        'generated_at': _now(),
        'source_files': sessions,
        'verdict_stats': {
            'total_events': decisions['total'],
            **decisions['verdict_counts']
        },
        'severity_distribution': decisions['severity_distribution'],
        'top_mitre_techniques': decisions['top_mitre'],
        'flagged_events': decisions['flagged_events'],
        'sample_autoblocked': decisions['autoblocked_samples'],
        'alerts': alerts,
        'alerts_pagination': {
            'offset': alerts_offset,
            'limit': limit_alerts,
            'returned': len(alerts),
            'total_estimate': total_alerts,
            'next_offset': (alerts_offset + len(alerts)) if (alerts_offset + len(alerts)) < total_alerts else None
        },
        'suspicious_patterns_rollup': pattern_rollup,
        'tenant_id': tenant_id,
        'finops': finops,
        'recommendations': _derive_recommendations(decisions, alerts),
        'compliance_controls': compliance_controls,
        'network_artifacts': persona_network_artifacts,
        'business_impact_summary': impact_summary,
         'meta': {
            # Report version reverted to 2 for backward compatibility with existing tests.
            # Increment to 3+ only when introducing a breaking schema change and update tests accordingly.
            'report_version': 2,
            'platform_version': os.getenv('PLATFORM_VERSION','unknown'),
            'sbom_include_suppressed_vex': include_suppressed_vex,
            'persona': persona_norm or 'soc_analyst',
            'variant': variant_norm,
         }
     }
    report['network_highlights'] = network_snapshot
    # Cross-framework rollups
    top_stride = []
    pasta_rollup = []
    cvss_rollup: dict[str, list[dict[str, Any]]] = {}
    maestro_rollup = []
    dread_average = None
    controls_overview = []
    if framework_summary:
        top_stride = [{'category': cat, 'count': cnt} for cat, cnt in (framework_summary.get('stride_counts') or [])[:15]]
        pasta_rollup = [{'stage': stage, 'count': count} for stage, count in (framework_summary.get('pasta_stage_distribution') or [])]
        cvss_rollup = {
            dim: [{'value': value, 'count': count} for value, count in vals]
            for dim, vals in (framework_summary.get('cvss_distribution') or {}).items()
        }
        maestro_rollup = [{'phase': phase, 'count': count} for phase, count in (framework_summary.get('maestro_phase_density') or [])]
        dread_average = framework_summary.get('dread_average_across_events')
        controls_overview = framework_summary.get('controls', [])
    report['top_stride'] = top_stride
    report['pasta_stages'] = pasta_rollup
    report['cvss_summary'] = cvss_rollup
    report['maestro_phases'] = maestro_rollup
    report['kill_chain_phases'] = list(maestro_rollup)
    report['dread_average'] = dread_average
    report['controls_overview'] = controls_overview

    domain_rollups = _compute_domain_rollups(combined_records)
    report['domain_rollups'] = domain_rollups

    # Dependency health snapshot and confidence band helper
    try:
        from src.api.graph_sessions import _check_dependency_status  # type: ignore
        dep_status = _check_dependency_status()
    except Exception:
        dep_status = None
    if dep_status:
        report['dependency_status'] = dep_status

    hopgraph_summary = None
    try:
        if (os.getenv('REPORT_INCLUDE_GRAPH_SUMMARY','0') or '0').lower() in {'1','true','yes'} and combined_records:
            seed: dict[str, Any] = {}
            for rec in combined_records:
                for key in ('user','host','process','proc'):
                    val = rec.get(key)
                    if val:
                        seed[key] = val
                if seed:
                    break
            if seed:
                from src.core.graph.hopgraph_lite import get_graph as _get_lite  # type: ignore
                ctx = _get_lite().reconstruct_attack(seed, depth=3)
                edges = list((ctx or {}).get('edges') or [])
                phase_counts: dict[str,int] = {}
                for e in edges:
                    ph = e.get('phase') or 'unknown'
                    phase_counts[ph] = phase_counts.get(ph, 0) + 1
                hopgraph_summary = {
                    'edge_count': len(edges),
                    'phase_counts': sorted(phase_counts.items(), key=lambda x: (-x[1], x[0]))[:10]
                }
    except Exception:
        hopgraph_summary = None
    if hopgraph_summary:
        report['hopgraph_summary'] = hopgraph_summary

    # ---------------- Playbook Recommendations Integration ----------------
    # Build a seed factor set from flagged/autoblocked events plus lightweight heuristics so
    # playbook recommendation scoring can surface prescriptive next actions.
    try:
        seed: set[str] = set()
        for rec in report.get('flagged_events', []) + report.get('sample_autoblocked', []):
            for f in rec.get('factors', []) or []:
                if isinstance(f, str):
                    seed.add(f)
        # Heuristic enrichment: pattern rollup presence -> synthetic factors for matching
        try:
            pr = report.get('suspicious_patterns_rollup') or {}
            if (pr.get('suspicious_cells') or 0) > 0:
                seed.add('suspicious_cells_present')
            if (pr.get('powershell_matches') or 0) > 0:
                seed.add('powershell_activity_detected')
            if (pr.get('base64_matches') or 0) > 0:
                seed.add('encoded_payloads_detected')
        except Exception:
            pass
        # Supply chain / SBOM derived hints
        try:
            sb = report.get('sbom_vuln_summary') or {}
            sev_dist = sb.get('severity_distribution') or {}
            if int(sev_dist.get('critical',0)) > 0:
                seed.add('vuln:cvss_critical')
            if int(sev_dist.get('high',0)) >= 5:
                seed.add('vuln:cvss_high_cluster')
            if (sb.get('total_vulns') or 0) > 0:
                seed.add('sbom:coverage_present')
        except Exception:
            pass
        # Mapping richness hint if both path_length & distinct_phase_count present across any session factors
        if {'path_length','distinct_phase_count'} & seed:
            seed.add('mapping_semantics_rich')
        # Multi-source correlation synthetic indicator if we saw diversity across factor prefixes
        try:
            prefixes = {f.split(':',1)[0] for f in seed if ':' in f}
            if len(prefixes) >= 3:
                seed.add('multi_source_correlation')
        except Exception:
            pass
        # Import internal recommender; graceful degrade if unavailable
        try:
            from .playbooks_endpoints import recommend_playbooks as _rec_playbooks  # type: ignore
        except Exception:
            _rec_playbooks = None  # type: ignore
        playbook_recs: list[dict[str, Any]] = []
        if _rec_playbooks and seed:
            try:
                res = _rec_playbooks(','.join(sorted(seed)), limit=7)  # type: ignore
                if isinstance(res, dict):
                    playbook_recs = res.get('recommendations') or []
            except Exception:
                playbook_recs = []
        if playbook_recs:
            report['playbook_recommendations'] = playbook_recs
            report['playbook_factor_seed'] = sorted(seed)
        else:
            report['playbook_recommendations'] = []
            report['playbook_factor_seed'] = sorted(seed)
    except Exception:
        # Ensure keys exist even if failures occur for stability in downstream hashing/tests
        report.setdefault('playbook_recommendations', [])
        if 'playbook_factor_seed' not in report:
            report['playbook_factor_seed'] = []
    if _flags_snapshot:
        report['meta']['feature_flags'] = _flags_snapshot
    if sbom_summary:
        report['sbom_vuln_summary'] = sbom_summary
        # Add remediation plan draft (top 5 by risk score sum, prioritizing reachable + KEV/EPSS)
        try:
            actions: dict[str, dict[str, Any]] = {}
            # Build a flat list of enriched vulns again for action scoring
            for sid in sbom_summary.get('sbom_ids', []):
                vulns = get_sbom_vulns_data(sid, include_suppressed=include_suppressed_vex) or []
                for v in vulns:
                    comp = (v.get('component') or '').strip()
                    if not comp:
                        continue
                    score = float(v.get('risk_score') or 0.0)
                    if v.get('kev'):
                        score += 0.2
                    try:
                        score += min(float(v.get('epss') or 0.0), 0.3)
                    except Exception:
                        pass
                    if any(tc.get('component') == comp and tc.get('reachable') for tc in (sbom_summary.get('top_components') or [])):
                        score += 0.15
                    entry = actions.setdefault(comp, {'component': comp, 'suppressed_risk': 0.0, 'items': 0})
                    entry['suppressed_risk'] += score
                    entry['items'] += 1
            # SLA targets by severity (simple defaults)
            sla = {'critical': 7, 'high': 14, 'medium': 30}
            plan = sorted(actions.values(), key=lambda x: (-x['suppressed_risk'], -x['items'], x['component']))[:5]
            for p in plan:
                p['target_sla_days'] = sla['critical']  # keep simple for now
            report['sbom_fix_plan'] = plan
        except Exception:
            pass
    if scenario_block:
        if include_scenarios and scenario_block.get('observed_count', 0) == 0:
            fallback_count = len(decisions.get('flagged_events', [])) + len(decisions.get('autoblocked_samples', []))
            if fallback_count > 0:
                # Synthesize a minimal placeholder scenario if none were emitted
                if not scenario_block.get('scenarios'):
                    scenario_block['scenarios'] = [{
                        'id': 'SCN-SYNTH-PLACEHOLDER',
                        'status_counts': {'observed': fallback_count},
                        'max_risk': 0.0,
                        'occurrences': fallback_count,
                        'tags': ['synthetic','fallback']
                    }]
                scenario_block['observed_count'] = fallback_count
                scenario_block.setdefault('meta', {})['fallback_observed'] = True
        report['scenario_summary'] = scenario_block
    if model_summary:
        report['threat_model_summary'] = model_summary

    # Optional: surface Identity/Cloud path explainability tags (best-effort)
    try:
        identity_tags: list[dict[str, Any]] = []
        cloud_tags: list[dict[str, Any]] = []
        try:
            from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as _IG  # type: ignore
            # Prefer explicit `nodes` mapping when available; fall back to internal
            # `_adj` keys only when necessary (read-only access).
            nodes_map = getattr(_IG, 'nodes', None)
            if isinstance(nodes_map, dict):
                users = [n for n in nodes_map.keys() if isinstance(n, str) and n.startswith('user:')]
            else:
                users = [n for n in list(getattr(_IG, 'adj', {}).keys()) if isinstance(n, str) and n.startswith('user:')]
            for u in users[:3]:
                paths = _IG.find_top_paths(u, limit=1)
                if paths:
                    meta = _IG.explain_path(paths[0]['path'])
                    identity_tags.append({'user': u, 'risk': paths[0].get('risk'), **meta})
        except Exception:
            pass
        try:
            from src.core.graph.cloud_hopgraph import GLOBAL_CLOUD_GRAPH as _CG  # type: ignore
            internet_key = 'internet:*'
            targets: list[str] = []
            try:
                # Use the join_helpers accessor to read adjacency in a duck-typed way
                from src.core.rules.join_helpers import _get_adj_list  # type: ignore
                adj_accessor = _get_adj_list(getattr(_CG, 'adj', _CG))
                cnt = 0
                for e in adj_accessor(internet_key) or ():
                    try:
                        dst = e[0]
                    except Exception:
                        continue
                    if isinstance(dst, str):
                        targets.append(dst)
                        cnt += 1
                        if cnt >= 5:
                            break
            except Exception:
                # Fallback to direct mapping read (best-effort, read-only)
                adj = getattr(_CG, 'adj', {})
                if isinstance(adj, dict) and internet_key in adj:
                    try:
                        for (dst, _t, _ts, _w) in adj.get(internet_key, [])[:5]:
                            if isinstance(dst, str):
                                targets.append(dst)
                    except Exception:
                        pass
            for t in targets[:3]:
                paths = _CG.find_paths(internet_key, t, limit=1)
                if paths:
                    meta = _CG.explain_path(paths[0]['path'])
                    cloud_tags.append({'entry': internet_key, 'target': t, 'risk': paths[0].get('risk'), **meta})
        except Exception:
            pass
        if identity_tags:
            report['identity_path_tags'] = identity_tags
        if cloud_tags:
            report['cloud_path_tags'] = cloud_tags
    except Exception:
        pass

    # Append SBOM-specific recommendations (lightweight heuristics)
    try:
        if sbom_summary and isinstance(report.get('recommendations'), list):
            sev = (sbom_summary.get('severity_distribution') or {})
            crit = int(sev.get('critical', 0))
            high = int(sev.get('high', 0))
            total_v = int(sbom_summary.get('total_vulns', 0))
            if crit > 0:
                report['recommendations'].append('Address SBOM critical vulnerabilities with urgent patches or compensating controls.')
            if high >= 5:
                report['recommendations'].append('Prioritize remediation of high-severity SBOM vulns (>=5).')
            if total_v == 0:
                report['recommendations'].append('SBOM posture clean in current snapshot; maintain patch cadence.')
    except Exception:
        pass

    _REPORT_CACHE[key] = {
        'generated_at': _now(),
        'report': report
    }
    # Optional: surface example risk ablation deltas for recent decisions (flag-gated)
    try:
        if os.getenv('INCLUDE_RISK_ABLATION'):
            from .runtime_state import DECISION_CACHE as _DC  # type: ignore
            from core.risk_score import compose_risk_score  # type: ignore
            recent = list(_DC.values())[-5:]
            examples: list[dict[str, Any]] = []
            for d in reversed(recent):
                try:
                    if isinstance(d, dict):
                        ev_id = d.get('event_id')
                        fs = list(d.get('factors') or [])
                        conf = float(d.get('confidence') or 0.0)
                    else:
                        ev_id = getattr(d, 'event_id', None)
                        fs = list(getattr(d, 'factors', []) or [])
                        conf = float(getattr(d, 'confidence', 0.0) or 0.0)
                    if not fs:
                        continue
                    res = compose_risk_score({'factors': fs, 'confidence': conf, 'debug_explain': True})
                    abl = res.get('ablation') if isinstance(res, dict) else None
                    if abl:
                        examples.append({'event_id': ev_id, 'top_ablation': abl[:5]})
                    if len(examples) >= 3:
                        break
                except Exception:
                    continue
            if examples:
                report['risk_ablation_examples'] = examples
    except Exception:
        pass
    return report

def _derive_recommendations(decisions: dict[str, Any], alerts: list[dict[str,Any]]) -> list[str]:
    recs: list[str] = []
    sev = decisions.get('severity_distribution', {})
    if sev.get('critical',0) > 3:
        recs.append('Investigate elevated critical event volume (>3).')
    if len(alerts) > 200:
        recs.append('High alert velocity detected; consider tuning suppression rules.')
    if not recs:
        recs.append('Environment appears stable; continue baseline monitoring.')
    return recs

__all__ = ['build_ingestion_report']
