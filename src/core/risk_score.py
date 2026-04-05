"""Risk score composer: aggregate heterogeneous signal contributions.
    # simple file cache load
    try:
        if _flag_enabled('predictive_lm'):
            import os
            ttl = float(os.getenv('PREDICTIVE_CACHE_TTL','60') or 60)
            pred_path = os.getenv('PREDICTIVE_OUTPUT', 'artifacts/predictive/lm_daily.jsonl')
            if pred_path:
                _load_predictive_cache(pred_path, ttl)
    except Exception:
        pass

Stage 3 Core Spec Alignment:
----------------------------
Aggregates contributions from:
    * Rule / scenario factors (existing 'factors' list)
    * Baseline |z| normalization (optional mapping via RISK_FACTOR_TO_METRIC_MAP)
    * Geo anomalies (geo:velocity_improbable) (already integrated)
    * Cluster novelty (cluster:novelty:<bucket>) if present on decision
    * Completeness penalty (penalty:incomplete) if missing expected factor classes

Outputs:
    - score: float (0..1 after optional sigmoid calibration)
    - raw_score: pre-calibration aggregated score
    - breakdown: list[{factor, weight, contribution, type?}]
    - method: fusion method string
    - confidence: original decision confidence (if any)
    - variance: population variance of contributions (for simple CI)
    - ci95: (low, high) 95% confidence interval on mean contribution fused heuristic

Explainability endpoint will sort breakdown by descending contribution.

Environment / Config:
    RISK_FACTOR_WEIGHTS="factor=0.8,other=0.3"
    RISK_HIGH_THRESHOLD=0.8 (injects risk:high factor in decision cache if crossed)
    RISK_COMPLETENESS_EXPECTED_CLASSES="scenario,net,dns,endpoint" (comma list)
    RISK_COMPLETENESS_MIN_PRESENT=1 (minimum distinct classes before penalty removed)
    RISK_COMPLETENESS_PENALTY=0.15 (penalty weight if insufficient coverage)
    RISK_SIGMOID_CALIBRATION=1 (enable sigmoid calibration)
    RISK_SIGMOID_K=4.0 (slope) RISK_SIGMOID_X0=0.5 (midpoint)
    RISK_CLUSTER_NOVELTY_MAX=0.4 (cap cluster novelty contribution)
    RISK_CLUSTER_NOVELTY_SCALE=1.0 (scaling multiplier before cap)

Design Notes:
The aggregation base remains multiplicative independence fusion, but we track
individual contributions for variance. Variance & CI are heuristic: they treat
contributions as samples; CI is on the *mean contribution* not score.

This module remains deterministic aside from external service lookups.
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import time
from typing import Any, Dict, Iterable

from core.baseline_service import BASELINES
from core.geo_velocity import GEO_VELOCITY
from core.learner_service import apply_decay, get_learned_weights
from core.metrics.registry import metric_counter, metric_histogram
from datetime import datetime, timezone

try:  # pragma: no cover
    from src.core.correlation.factor_synthesis import (
        Factor,
        FactorCategory,
    )
except Exception:  # pragma: no cover
    Factor = None  # type: ignore
    FactorCategory = None  # type: ignore
try:  # pragma: no cover
    from src.core.correlation.factor_synthesis_runtime import (
        factor_category_for_name,
        get_factor_synthesis_engine,
    )
except Exception:  # pragma: no cover
    factor_category_for_name = None  # type: ignore
    get_factor_synthesis_engine = None  # type: ignore
try:  # pragma: no cover
    from src.core.correlation import factor_synthesis_runtime as _factor_synthesis_runtime
except Exception:  # pragma: no cover
    _factor_synthesis_runtime = None
try:  # pragma: no cover
    from src.core.quality.factor_quality import get_quality_manager
except Exception:  # pragma: no cover
    def get_quality_manager():  # type: ignore
        return None

# Lazy metric holders to avoid import-time registry races
_RISK_SCORE_HIST = None
_RISK_HIGH_COUNTER = None
_RISK_TOD_COUNTER = None
_RISK_ROLE_COUNTER = None

# Testing hooks to allow monkeypatching cached factor synthesis engine/signature
_FACTOR_SYNTHESIS_ENGINE = None
_FACTOR_SYNTHESIS_SIGNATURE = None
_FACTOR_SYNTHESIS_BASE_CACHE = None
_FACTOR_SYNTHESIS_BASE_PATH = None
_FACTOR_SYNTHESIS_BASE_MTIME = None

# Runtime sigmoid override (applied when present)
_SIGMOID_OVERRIDE: dict | None = None
_PRED_CACHE: dict[str, float] = {}
_PRED_LAST_LOAD: float | None = None
def _load_predictive_cache(path: str, ttl: float = 60.0) -> None:
    global _PRED_CACHE, _PRED_LAST_LOAD
    import os, json, time as _t
    now = _t.time()
    if _PRED_LAST_LOAD is not None and (now - _PRED_LAST_LOAD) < max(1.0, ttl):
        return
    try:
        cache: dict[str, float] = {}
        if os.path.exists(path):
            with open(path, encoding='utf-8') as f:
                for line in f:
                    try:
                        j = json.loads(line)
                    except Exception:
                        continue
                    ent = str(j.get('entity') or '').lower()
                    if ent:
                        try:
                            cache[ent] = float(j.get('risk') or 0.0)
                        except Exception:
                            continue
        _PRED_CACHE = cache
        _PRED_LAST_LOAD = now
    except Exception:
        _PRED_CACHE = {}
        _PRED_LAST_LOAD = now


def apply_sigmoid_override(k: float, x0: float) -> None:
    global _SIGMOID_OVERRIDE
    try:
        _SIGMOID_OVERRIDE = {'k': float(k), 'x0': float(x0)}
    except Exception:
        _SIGMOID_OVERRIDE = None


def _ensure_metrics():
    global _RISK_SCORE_HIST, _RISK_HIGH_COUNTER, _RISK_TOD_COUNTER, _RISK_ROLE_COUNTER
    if _RISK_SCORE_HIST is None:
        try:
            _RISK_SCORE_HIST = metric_histogram(
                'risk',
                'score_distribution',
                'Risk score distribution',
                labels=['tenant_id'],
                unit_seconds=False,
            )
        except Exception:
            _RISK_SCORE_HIST = None
    if _RISK_HIGH_COUNTER is None:
        try:
            _RISK_HIGH_COUNTER = metric_counter('risk', 'high', 'High risk decisions', labels=['tenant_id'])
        except Exception:
            _RISK_HIGH_COUNTER = None
    if _RISK_TOD_COUNTER is None:
        try:
            _RISK_TOD_COUNTER = metric_counter('risk', 'offhours', 'Off-hours contributions applied', labels=['tenant_id'])
        except Exception:
            _RISK_TOD_COUNTER = None
    if _RISK_ROLE_COUNTER is None:
        try:
            _RISK_ROLE_COUNTER = metric_counter('risk', 'role_mismatch', 'Role mismatch contributions applied', labels=['tenant_id'])
        except Exception:
            _RISK_ROLE_COUNTER = None


def _parse_weights_env() -> dict[str, float]:
    raw = os.getenv('RISK_FACTOR_WEIGHTS', '') or ''
    if not raw:
        return {}
    out: dict[str, float] = {}
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
            try:
                out[k.strip()] = float(v.strip())
            except Exception:
                continue
    return out


_ENV_WEIGHTS = _parse_weights_env()

# ---------------- YAML Hot Reload (Optional) -----------------
_YAML_PATH = os.getenv('RISK_WEIGHTS_YAML')
_YAML_LAST_INFO: tuple[float,int] | None = None
_YAML_CACHE: dict[str, float] = {}

def _maybe_reload_yaml() -> None:
    global _YAML_LAST_INFO, _YAML_CACHE, _YAML_PATH
    path = os.getenv('RISK_WEIGHTS_YAML', '') or ''
    if not path:
        return
    # update module-level path so callers/readers see the current value
    _YAML_PATH = path
    try:
        st = os.stat(path)
    except Exception:
        return
    mtime = getattr(st, 'st_mtime', None)
    size = getattr(st, 'st_size', None)
    if mtime is None or size is None:
        return
    # Compare both mtime and size to detect changes even when mtime resolution is coarse
    if _YAML_LAST_INFO is not None:
        last_mtime, last_size = _YAML_LAST_INFO
        if mtime <= last_mtime and size == last_size:
            return  # unchanged
    # Reload
    try:
        import yaml  # type: ignore
    except Exception:
        return
    try:
        with open(_YAML_PATH, encoding='utf-8') as fh:
            data = yaml.safe_load(fh) or {}
        if isinstance(data, dict):
            new_map: dict[str, float] = {}
            for k, v in data.items():
                try:
                    new_map[str(k)] = float(v)
                except Exception:
                    continue
            # Mutate the existing cache dict instead of rebinding so callers
            # holding a reference (e.g., yaml_cache_local) observe updates.
            _YAML_CACHE.clear()
            _YAML_CACHE.update(new_map)
            _YAML_LAST_INFO = (mtime, size)
    except Exception:
        pass


def _build_synthesis_context(decision: dict[str, Any]) -> dict[str, Any]:
    ctx: Dict[str, Any] = {}
    role = str(decision.get('role') or '').lower()
    if role:
        ctx['user_role'] = role
    severity = str(decision.get('severity') or '').lower()
    if severity:
        ctx['severity'] = severity
    source = str(decision.get('source') or '').lower()
    if source:
        ctx['source'] = source
    return ctx


def _tenant_weights(tenant_id: str | None) -> dict[str, float]:
    """Look for tenant-specific env override: RISK_FACTOR_WEIGHTS_<TENANT>"""
    if not tenant_id:
        return {}
    key = f'RISK_FACTOR_WEIGHTS_{tenant_id.upper()}'
    raw = os.getenv(key, '') or ''
    if not raw:
        return {}
    out: dict[str, float] = {}
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
            try:
                out[k.strip()] = float(v.strip())
            except Exception:
                continue
    return out


def _parse_wildcard_maps() -> list[tuple[str, dict[str, float]]]:
    """Parse RISK_FACTOR_WEIGHTS_PATTERNS env var of the form:
    "pattern->f1=0.2,f2=0.1;other*=g1=0.3" where pattern supports '*' wildcard.
    Returns list of (pattern, mapping) in order.
    """
    raw = os.getenv('RISK_FACTOR_WEIGHTS_PATTERNS', '') or ''
    res: list[tuple[str, dict[str, float]]] = []
    if not raw:
        return res
    for part in raw.split(';'):
        part = part.strip()
        if '->' not in part:
            continue
        pat, mapping = part.split('->', 1)
        pat = pat.strip()
        m: dict[str, float] = {}
        for kv in mapping.split(','):
            kv = kv.strip()
            if '=' in kv:
                k, v = kv.split('=', 1)
                try:
                    m[k.strip()] = float(v.strip())
                except Exception:
                    continue
        if pat:
            res.append((pat, m))
    return res


_WILDCARD_MAPS = _parse_wildcard_maps()


def _default_weight_for_factor(factor: str) -> float:
    # Priority: explicit env mapping, prefix heuristics, fallback small weight
    if factor in _ENV_WEIGHTS:
        return max(0.0, min(1.0, float(_ENV_WEIGHTS[factor] or 0.0)))
    # simple prefix heuristics
    if factor.startswith('scenario:critical'):
        return 0.95
    if factor.startswith('scenario:high'):
        return 0.75
    if factor.startswith('net:'):
        return 0.6
    if factor.startswith('dns:'):
        return 0.45
    if factor.startswith('endpoint:'):
        return 0.5
    if factor.startswith('resource:'):
        return 0.4
    # conservative default
    return 0.05


def _sigmoid(x: float, k: float, x0: float) -> float:
    import math
    return 1.0 / (1.0 + math.exp(-k * (x - x0)))


def _compute_variance(samples: list[float]) -> tuple[float, float, tuple[float, float]]:
    """Return (mean, variance, ci95_tuple) for list of bounded samples [0,1]."""
    import math
    if not samples:
        return 0.0, 0.0, (0.0, 0.0)
    n = len(samples)
    mean = sum(samples) / n
    var = sum((s - mean) ** 2 for s in samples) / max(1, n - 1)
    # 95% CI using normal approximation (boundedness ignored for simplicity)
    se = math.sqrt(var / n) if n > 0 else 0.0
    ci_low = max(0.0, mean - 1.96 * se)
    ci_high = min(1.0, mean + 1.96 * se)
    return mean, var, (ci_low, ci_high)


async def _compose_risk_score_async(decision: dict[str, Any], tenant_id: str | None = None) -> dict[str, Any]:
    """Async compose a risk score from a decision-like object.

    This version can query BASELINES and GEO_VELOCITY live for richer signals.
    Returns a dict: {score, breakdown, method, confidence}.
    """
    # Normalize factor names early so downstream logic uses canonical taxonomy
    try:
        from src.core.threat_modeling.factor_aliases import normalize_factors
    except Exception:
        normalize_factors = lambda x: list(x or [])
    factors: list[str] = normalize_factors(list(decision.get('factors') or []))
    confidence = float(decision.get('confidence') or 0.0)

    breakdown: list[dict[str, Any]] = []
    contributions: list[float] = []  # numeric contributions captured for stats

    # Refresh env-derived weights at call time so test-suite ordering that sets
    # environment variables earlier in the run cannot leak into later tests.
    # When FAST_TEST_MODE is enabled, disable optional env/feature-driven
    # adjustments to keep unit tests deterministic and order-independent.
    try:
        fast = str(os.getenv('FAST_TEST_MODE', '0')).lower() in {'1', 'true', 'yes'}
    except Exception:
        fast = False
    try:
        # If tests explicitly set RISK_FACTOR_WEIGHTS, honor that even in FAST_TEST_MODE
        raw_env = os.getenv('RISK_FACTOR_WEIGHTS', '') or ''
        if raw_env:
            _env_weights_local = _parse_weights_env()
        else:
            _env_weights_local = {} if fast else _parse_weights_env()
    except Exception:
        _env_weights_local = {}
    # Avoid using module-level YAML cache in fast test mode to prevent prior
    # tests that exercise YAML hot-reload from polluting later test expectations.
    try:
        yaml_path = os.getenv('RISK_WEIGHTS_YAML', '') or ''
        # If FAST_TEST_MODE and no explicit YAML path is provided, avoid using
        # the shared module YAML cache to prevent ordering leaks. If a test
        # explicitly sets RISK_WEIGHTS_YAML, allow YAML hot-reload to operate.
        if fast and not yaml_path:
            yaml_cache_local = {}
        else:
            yaml_cache_local = _YAML_CACHE
    except Exception:
        yaml_cache_local = {}

    # Merge learned weights, env weights, wildcard maps, tenant-specific overrides
    learned = get_learned_weights() or {}
    tenant_map = _tenant_weights(tenant_id)

    # Runtime rollout support: merge in candidate weights from factor_rollout
    def _get_runtime_weights(event_decision: dict[str, Any]) -> dict[str, float]:
        try:
            from src.core.factor_rollout import get_current_weights, get_rollout_pct
            from src.core.canary import pick_by_event
        except Exception:
            return {}
        try:
            runtime = get_current_weights() or {}
            pct = float(get_rollout_pct() or 0.0)
        except Exception:
            return {}
        if not runtime or pct <= 0.0:
            return {}
        event_id = str(event_decision.get('event_id') or event_decision.get('id') or event_decision.get('decision_id') or '')
        if not event_id:
            return {}
        try:
            if pick_by_event(event_id, pct):
                return {k: float(v) for k, v in runtime.items()}
        except Exception:
            return {}
        return {}

    # Factor to metric mapping (optional) allows config to map factors -> baseline metric names
    factor_metric_map_raw = os.getenv('RISK_FACTOR_TO_METRIC_MAP', '') or ''
    factor_metric_map = {}
    if factor_metric_map_raw:
        try:
            factor_metric_map = json.loads(factor_metric_map_raw)
        except Exception:
            # fallback to empty
            factor_metric_map = {}

    # YAML hot reload (best-effort, cheap periodic check)
    try:
        _maybe_reload_yaml()
    except Exception:
        pass

    factor_entries: list[dict[str, Any]] = []
    synthesis_inputs: list[Factor] = []
    factor_ts = float(decision.get('ts') or time.time())
    factor_dt = datetime.fromtimestamp(factor_ts, tz=timezone.utc).replace(tzinfo=None)

    for f in factors:
        w = None  # initialize per-factor
        # learned weight has highest priority
        if f in learned:
            w = learned[f]
        elif f in yaml_cache_local:
            w = yaml_cache_local[f]
        # exact tenant override
        elif f in tenant_map:
            w = tenant_map[f]
        # exact global env weights (refresh per-call)
        elif f in _env_weights_local:
            w = _env_weights_local[f]
        else:
            # wildcard maps: first match wins
            matched = False
            for pat, mapping in _WILDCARD_MAPS:
                if fnmatch.fnmatch(tenant_id or '', pat):
                    if f in mapping:
                        w = mapping[f]
                        matched = True
                        break
            if not matched:
                w = _default_weight_for_factor(f)

        # If the factor maps to a baseline metric, query baseline z-score and adjust weight
        try:
            if not fast:
                metric_name = factor_metric_map.get(f)
                if metric_name and BASELINES is not None:
                    # BASELINES.get_z may be sync or async
                    get_z = getattr(BASELINES, 'get_z', None)
                    if get_z is not None:
                        if asyncio.iscoroutinefunction(get_z):
                            z = await get_z(metric_name, decision)
                        else:
                            loop = asyncio.get_event_loop()
                            z = await loop.run_in_executor(None, get_z, metric_name, decision)
                        # convert z to a multiplier in (0.5, 1.5)
                        mult = 1.0 + max(min(z, 3.0), -3.0) * 0.1
                        w = float(w) * float(mult)
        except Exception:
            pass

        if w is None:
            # fallback in rare case all branches missed
            w = _default_weight_for_factor(f)
        # Apply runtime candidate weights if event selected for canary rollout
        try:
            runtime_w = _get_runtime_weights(decision)
            if runtime_w and f in runtime_w:
                w = float(runtime_w.get(f) or w)
        except Exception:
            pass
        entry = {'factor': f, 'weight': float(w)}
        factor_entries.append(entry)
        if Factor is not None and FactorCategory is not None and factor_category_for_name is not None:
            try:
                category = factor_category_for_name(f)
            except Exception:
                category = FactorCategory.META
            try:
                synthesis_inputs.append(
                    Factor(
                        name=f,
                        category=category,
                        timestamp=factor_dt,
                        base_weight=float(w),
                        metadata={},
                    )
                )
            except Exception:
                synthesis_inputs = []
                FactorCategory  # silence mypy

    if _factor_synthesis_runtime is not None:
        try:
            _factor_synthesis_runtime.get_quality_manager = get_quality_manager
        except Exception:
            pass
    engine = get_factor_synthesis_engine() if get_factor_synthesis_engine else None
    # In FAST_TEST_MODE, disable synthesis engine unless explicitly enabled via
    # RISK_SYNTHESIS_FEATURE *or* FACTOR_SYNTHESIS_CONFIG is explicitly provided
    # (the latter allows integration tests to supply a config and run synthesis).
    try:
        allow_engine = str(os.getenv('RISK_SYNTHESIS_FEATURE', '0')).lower() in {'1', 'true', 'yes'}
        if not allow_engine and os.getenv('FACTOR_SYNTHESIS_CONFIG'):
            allow_engine = True
    except Exception:
        allow_engine = False
    if fast and not allow_engine:
        engine = None
    globals()['_FACTOR_SYNTHESIS_ENGINE'] = engine
    globals()['_FACTOR_SYNTHESIS_SIGNATURE'] = getattr(engine, 'config_signature', None) if engine else None
    if engine and synthesis_inputs:
        try:
            synthesis_result = engine.synthesize(
                synthesis_inputs,
                context=_build_synthesis_context(decision),
            )
            contributions.append(synthesis_result.final_score)
            breakdown.append({
                'factor': 'factor_synthesis',
                'weight': synthesis_result.final_score,
                'contribution': synthesis_result.final_score,
                'source': 'factor',
                'metadata': {
                    'contributing_factors': synthesis_result.contributing_factors,
                    'synergies': synthesis_result.synergies_detected,
                    'context_multiplier': synthesis_result.context_multiplier,
                    'decay': synthesis_result.decay_applied,
                    'explanation': synthesis_result.explanation,
                }
            })
            decision.setdefault('correlation_insights', []).append({
                'type': 'factor_synthesis',
                'confidence': synthesis_result.confidence,
                'mitre': synthesis_result.mitre_tactics,
                'synergies': synthesis_result.synergies_detected,
                'details': synthesis_result.contributing_factors,
            })
        except Exception:
            engine = None

    if not engine:
        for entry in factor_entries:
            contrib = max(0.0, min(1.0, float(entry['weight'])))
            entry.update({'contribution': contrib, 'source': 'factor'})
            breakdown.append(entry)
            contributions.append(contrib)

    # Query geo_velocity live for involved resources if available (skip in fast test mode)
    try:
        if not fast and GEO_VELOCITY is not None:
            lookup = getattr(GEO_VELOCITY, 'lookup', None)
            if lookup is not None:
                if asyncio.iscoroutinefunction(lookup):
                    geo_res = await lookup(decision)
                else:
                    loop = asyncio.get_event_loop()
                    geo_res = await loop.run_in_executor(None, lookup, decision)
                if geo_res and geo_res.get('anomaly'):
                    sf = 'geo:velocity_improbable'
                    w = 0.8
                    breakdown.append({'factor': sf, 'weight': w, 'contribution': w, 'source': 'geo'})
                    contributions.append(w)
    except Exception:
        pass

    # Cluster novelty (if decision contains cluster metadata or novelty score)
    try:
        novelty = None
        # Accept either decision['cluster'] dict or direct novelty_score
        if isinstance(decision.get('cluster'), dict):
            novelty = decision['cluster'].get('novelty_score')
        if novelty is None:
            novelty = decision.get('novelty_score')
        if isinstance(novelty, (int, float)) and novelty > 0:
            max_c = float(os.getenv('RISK_CLUSTER_NOVELTY_MAX', '0.4') or 0.4)
            scale = float(os.getenv('RISK_CLUSTER_NOVELTY_SCALE', '1.0') or 1.0)
            val = min(max_c, float(novelty) * scale)
            if val > 0:
                breakdown.append({'factor': 'cluster:novelty', 'weight': val, 'contribution': val, 'source': 'cluster'})
                contributions.append(val)
    except Exception:
        pass

    # Vulnerability component (CVSS/VPR/Exploitability) — optional, small weight
    try:
        vuln_ctx = decision.get('vuln_context') if isinstance(decision.get('vuln_context'), dict) else {}
        max_cvss = float((vuln_ctx or {}).get('max_cvss', 0.0) or 0.0)
        vpr_score = float((vuln_ctx or {}).get('vpr_score', 0.0) or 0.0)
        exploit_avail = bool((vuln_ctx or {}).get('exploit_available', False))
        # Consider factor-based exploit hints if context not present
        if not exploit_avail:
            if any(str(f) in ('exploit:kev','exploit:high_epss') for f in factors):
                exploit_avail = True
        # Prefer VPR if provided, else CVSS base normalized
        vuln_norm = (vpr_score / 10.0) if vpr_score > 0 else (max_cvss / 10.0)
        if exploit_avail and vuln_norm > 0:
            vuln_norm = min(1.0, vuln_norm * 1.2)
        # Weight for vulnerability channel
        try:
            vuln_w = float(os.getenv('RISK_VULN_WEIGHT','0.25') or 0.25)
        except Exception:
            vuln_w = 0.25
        vuln_contrib = max(0.0, min(1.0, vuln_norm * max(0.0, min(1.0, vuln_w))))
        # Fallback: infer from factors when no context provided
        if vuln_contrib == 0.0 and max_cvss <= 0.0 and vpr_score <= 0.0:
            fb = 0.0
            if any(str(f) == 'vuln:cvss_ge_9' for f in factors):
                fb = 0.06
            elif any(str(f) == 'sbom:cve_critical' for f in factors):
                fb = 0.05
            try:
                fb_env = float(os.getenv('RISK_VULN_FALLBACK','0.06') or 0.06)
                if fb > 0:
                    fb = min(fb, fb_env)
            except Exception:
                pass
            vuln_contrib = fb
        if vuln_contrib > 0:
            breakdown.append({'factor': 'vuln:cvss_vpr', 'weight': vuln_contrib, 'contribution': vuln_contrib, 'source': 'vuln'})
            contributions.append(vuln_contrib)
    except Exception:
        pass

    # Completeness penalty (if expected factor classes not sufficiently covered)
    try:
        expected_raw = os.getenv('RISK_COMPLETENESS_EXPECTED_CLASSES', '') or ''
        if expected_raw:
            expected = {p.strip().lower() for p in expected_raw.split(',') if p.strip()}
            min_present = int(os.getenv('RISK_COMPLETENESS_MIN_PRESENT', '1') or 1)
            penalty_weight = float(os.getenv('RISK_COMPLETENESS_PENALTY', '0.15') or 0.15)
            present_classes = {f.split(':', 1)[0].lower() for f in factors if ':' in f}
            coverage = len(expected.intersection(present_classes))
            if coverage < max(0, min_present):
                # Add penalty by reducing final multiplicative complement (represented as a negative weight effect)
                pw = max(0.0, min(1.0, penalty_weight))
                breakdown.append({
                    'factor': 'penalty:incomplete',
                    'weight': -pw,
                    'contribution': -pw,
                    'source': 'penalty'
                })
                contributions.append(0.0)  # do not treat negative in variance of positive contributions
    except Exception:
        pass

    # multiplicative fusion: combined = 1 - prod(1 - contrib) while applying penalties
    prod = 1.0
    for item in breakdown:
        c = float(item['contribution'])
        if c < 0:  # penalty: shrink existing combined space by (1+penalty) factor
            # Represent penalty as increasing prod (reducing final score)
            prod *= (1.0 + abs(c) * 0.5)  # linear scaling; heuristic
        else:
            prod *= (1.0 - c)
    combined = 1.0 - prod
    combined = max(0.0, min(1.0, combined))

    raw_score = combined

    # ---------------- Time-of-day and Role Profile Contributions ----------------
    try:
        # Allow tests (or explicit env) to enable TOD/ROLE features even when
        # FAST_TEST_MODE is active. Many unit tests set these env vars via
        # monkeypatch.setenv and expect the contributions to be present.
        enable_tod = str(os.getenv('RISK_TOD_FEATURE', '0')).lower() in {'1', 'true', 'yes'}
        enable_role = str(os.getenv('RISK_ROLE_FEATURE', '0')).lower() in {'1', 'true', 'yes'}
        label_tenant = (tenant_id or decision.get('tenant_id') or os.getenv('DEFAULT_TENANT','default'))
        # Off-hours: if event timestamp exists and falls outside [start,end] local (or UTC), add a small contribution
        if enable_tod:
            # Accept decision['ts'] epoch seconds; default now
            ts = float(decision.get('ts') or time.time())
            # Define off-hours window via env: e.g., 20-7 means off-hours are 8pm-7am
            window = os.getenv('RISK_TOD_OFFHOURS','20-7')
            try:
                start_s, end_s = window.split('-',1)
                start_h = int(start_s); end_h = int(end_s)
            except Exception:
                start_h, end_h = 20, 7
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)  # use UTC for determinism
            h = dt.hour
            off = False
            if start_h <= end_h:
                off = (h < start_h) or (h >= end_h)
            else:
                # wraps midnight, e.g., 20-7
                off = (h >= start_h) or (h < end_h)
            if off:
                tod_w = float(os.getenv('RISK_TOD_WEIGHT','0.08') or 0.08)
                w = max(0.0, min(1.0, tod_w))
                breakdown.append({'factor': 'context:off_hours', 'weight': w, 'contribution': w, 'source': 'context'})
                contributions.append(w)
                try:
                    _ensure_metrics()
                    if _RISK_TOD_COUNTER is not None:
                        _RISK_TOD_COUNTER.labels(tenant_id=label_tenant).inc()
                except Exception:
                    pass
        # Role profile: if a declared role is lower-privilege and sensitive factor present, add contribution
        if enable_role:
            role = str(decision.get('role') or '').lower()
            # Define sensitive factor prefixes via env (comma list)
            sens_raw = os.getenv('RISK_ROLE_SENSITIVE_PREFIXES','scenario:critical,scenario:high')
            sensitive_prefixes = [p.strip() for p in sens_raw.split(',') if p.strip()]
            if role and any(str(f).startswith(tuple(sensitive_prefixes)) for f in factors):
                # Role weights map via env: e.g., user=0.1,contractor=0.15,service=0.05
                rmap_raw = os.getenv('RISK_ROLE_WEIGHTS','user=0.1,contractor=0.15,service=0.05')
                rmap: dict[str,float] = {}
                try:
                    for part in rmap_raw.split(','):
                        if '=' in part:
                            k,v = part.split('=',1)
                            rmap[k.strip().lower()] = float(v)
                except Exception:
                    rmap = {'user':0.1,'contractor':0.15,'service':0.05}
                rw = float(rmap.get(role, 0.0))
                if rw > 0:
                    w = max(0.0, min(1.0, rw))
                    breakdown.append({'factor': f'role:{role}:sensitive_activity', 'weight': w, 'contribution': w, 'source': 'role'})
                    contributions.append(w)
                    try:
                        _ensure_metrics()
                        if _RISK_ROLE_COUNTER is not None:
                            _RISK_ROLE_COUNTER.labels(tenant_id=label_tenant).inc()
                    except Exception:
                        pass
    except Exception:
        pass

    # Lateral Movement Composite (optional promotion)
    try:
        from core.feature_flags import is_enabled as _flag_enabled  # type: ignore
    except Exception:
        def _flag_enabled(_name: str) -> bool:  # type: ignore
            return False
    try:
        if not fast and _flag_enabled('fusion_lm_composite'):
            lm_pool_prefixes = (
                'lane_host_pivot:',
                'lane_privilege_misuse:',
            )
            lm_signals = 0
            for f in factors:
                fstr = str(f)
                if fstr.startswith(lm_pool_prefixes) or fstr in (
                    'graph_motif_user_proc_auth',
                    'lane_host_pivot:first_time_peer_off_hours',
                    'lane_host_pivot:rapid_peer_fanout',
                ):
                    lm_signals += 1
            if lm_signals >= 2:
                w = float(os.getenv('RISK_LM_COMPOSITE_WEIGHT','0.2') or 0.2)
                w = max(0.0, min(1.0, w))
                breakdown.append({'factor': 'lateral_movement_composite', 'weight': w, 'contribution': w, 'source': 'fusion'})
                contributions.append(w)
    except Exception:
        pass

    # Predictive LM risk (optional, very low weight)
    try:
        from core.feature_flags import is_enabled as _flag_enabled  # type: ignore
    except Exception:
        def _flag_enabled(_name: str) -> bool: return False
    try:
        if not fast and _flag_enabled('predictive_lm'):
            # Resolve entity id (user or host)
            entity = str(decision.get('user') or decision.get('host') or '').lower()
            if entity:
                # Ensure tiny cache is warm and use it (avoids per-decision file rereads)
                try:
                    ttl = float(os.getenv('PREDICTIVE_CACHE_TTL','60') or 60)
                except Exception:
                    ttl = 60.0
                pred_path = os.getenv('PREDICTIVE_OUTPUT', 'artifacts/predictive/lm_daily.jsonl')
                if pred_path:
                    _load_predictive_cache(pred_path, ttl)
                risk_val = _PRED_CACHE.get(entity)
                if isinstance(risk_val, float) and risk_val > 0:
                    w = min(0.15, max(0.0, risk_val) * 0.2)
                    breakdown.append({'factor': 'predictive:lm_risk', 'weight': w, 'contribution': w, 'source': 'predictive'})
                    contributions.append(w)
    except Exception:
        pass
    # Optional sigmoid calibration (enable only for explicit truthy env values)
    try:
        # Allow tests to enable sigmoid calibration by setting the env var even
        # when FAST_TEST_MODE is active; check the env var directly.
        if str(os.getenv('RISK_SIGMOID_CALIBRATION', '0')).lower() in {'1', 'true', 'yes'}:
            # prefer runtime override if present
            if _SIGMOID_OVERRIDE and isinstance(_SIGMOID_OVERRIDE, dict):
                k = float(_SIGMOID_OVERRIDE.get('k', float(os.getenv('RISK_SIGMOID_K', '4.0') or 4.0)))
                x0 = float(_SIGMOID_OVERRIDE.get('x0', float(os.getenv('RISK_SIGMOID_X0', '0.5') or 0.5)))
            else:
                k = float(os.getenv('RISK_SIGMOID_K', '4.0') or 4.0)
                x0 = float(os.getenv('RISK_SIGMOID_X0', '0.5') or 0.5)
            combined = _sigmoid(combined, k, x0)
    except Exception:
        pass

    # scale by confidence (decision classifier score)
    final = float(max(0.0, min(1.0, combined * (confidence or 1.0))))

    # Compute variance & CI over positive contributions only
    pos_contribs = [c for c in contributions if c >= 0]
    mean_c, var_c, ci95 = _compute_variance(pos_contribs)

    # Inject risk:high factor if above threshold (not altering score; for consumers)
    try:
        high_thr = float(os.getenv('RISK_HIGH_THRESHOLD','0.8') or 0.8)
    except Exception:
        high_thr = 0.8
    if final >= high_thr:
        breakdown.append({'factor': 'risk:high', 'weight': 0.0, 'contribution': 0.0, 'source': 'meta'})

    # Observe metrics (best-effort)
    try:
        _ensure_metrics()
        label = (tenant_id or decision.get('tenant_id') or os.getenv('DEFAULT_TENANT','default'))
        if _RISK_SCORE_HIST is not None:
            try:
                _RISK_SCORE_HIST.labels(tenant_id=label).observe(final)
            except Exception:
                pass
        try:
            high_thr = float(os.getenv('RISK_HIGH_THRESHOLD','0.8') or 0.8)
        except Exception:
            high_thr = 0.8
        if final >= high_thr and _RISK_HIGH_COUNTER is not None:
            try:
                _RISK_HIGH_COUNTER.labels(tenant_id=label).inc()
            except Exception:
                pass
    except Exception:
        pass

    # Apply decay to learned weights to age them slightly
    try:
        for f in list(get_learned_weights().keys()):
            try:
                apply_decay(f)
            except Exception:
                continue
    except Exception:
        pass

    # Sort breakdown by absolute contribution desc (positive first, then penalties)
    breakdown.sort(key=lambda x: (x['contribution'] >= 0, abs(x['contribution'])), reverse=True)
    # Verdict calibration: if signals lack factor diversity, optionally reduce score
    try:
        calib_enabled = str(os.getenv('RISK_VERDICT_CALIBRATION_ENABLED', '0')).lower() in {'1', 'true', 'yes'}
    except Exception:
        calib_enabled = False
    try:
        calib_min_diversity = int(os.getenv('RISK_VERDICT_MIN_DIVERSITY', '2') or 2)
    except Exception:
        calib_min_diversity = 2

    result: dict[str, Any] = {
        'score': final,
        # `triage_score`: unified severity used for autoranking/backfill priority
        # Derived from raw_score before confidence scaling to keep ordering stable
        'triage_score': float(max(0.0, min(1.0, raw_score))),
        'raw_score': raw_score,
        'breakdown': breakdown,
        'method': 'multiplicative',
        'confidence': confidence,
        'variance': var_c,
        'ci95': ci95,
        'mean_contribution': mean_c,
    }

    # Apply calibration guardrail (best-effort): detect factor diversity by prefix
    try:
        if calib_enabled:
            prefixes = set()
            for f in factors:
                try:
                    p = str(f).split(':', 1)[0]
                except Exception:
                    p = str(f)
                prefixes.add(p)
            diversity = len(prefixes)
            if diversity < max(1, calib_min_diversity):
                # reduce score conservatively (e.g., halve it) and mark reason
                old_score = float(result.get('score') or 0.0)
                new_score = max(0.0, min(1.0, old_score * 0.5))
                result['score'] = new_score
                result['calibrated'] = True
                result['calibration_reason'] = f'low_factor_diversity({diversity}<{calib_min_diversity})'
            else:
                result['calibrated'] = False
    except Exception:
        try:
            result['calibrated'] = False
        except Exception:
            pass

    # Attach unified threat model and compliance controls (best-effort, cheap) for explainability
    try:
        from src.core.threat_modeling.factor_taxonomy import aggregate_threat_model, controls_for_factors  # type: ignore
        tm = aggregate_threat_model(factors)
        result['threat_model'] = tm
        result['controls'] = controls_for_factors(factors)
        # include canonical factor list for consumers
        result['factors_normalized'] = factors
    except Exception:
        # Optional; ignore failures
        pass

    # Optional Shapley-lite ablation (cheap, up to N factors)
    try:
        if not decision.get('__skip_ablation') and (decision.get('debug_explain') or os.getenv('RISK_ABLATION')):
            try:
                topn = int(os.getenv('RISK_ABLATION_TOPN', '6') or 6)
            except Exception:
                topn = 6
            # unique factor order by contribution desc
            seen_f: set[str] = set()
            top_factors: list[str] = []
            for b in breakdown:
                f = str(b.get('factor') or '')
                if not f or f in seen_f:
                    continue
                seen_f.add(f)
                top_factors.append(f)
                if len(top_factors) >= max(1, topn):
                    break
            ablation: list[dict[str, Any]] = []
            for f in top_factors:
                mod = dict(decision)
                mod['factors'] = [x for x in factors if x != f]
                mod['__skip_ablation'] = True
                new = await _compose_risk_score_async(mod, tenant_id=tenant_id)
                new_score = float(new.get('score') or 0.0)
                ablation.append({'factor': f, 'delta': max(0.0, final - new_score), 'new_score': new_score})
            ablation.sort(key=lambda x: x['delta'], reverse=True)
            result['ablation'] = ablation
    except Exception:
        pass

    return result



def compose_risk_score(decision: dict[str, Any], tenant_id: str | None = None):
    """Compatibility wrapper: returns dict when called synchronously, or a coroutine when called within an event loop.

    - If called from sync code: runs async impl via asyncio.run and returns result dict.
    - If called from async code (running loop): returns coroutine which callers should await.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # return coroutine for await
        return _compose_risk_score_async(decision, tenant_id=tenant_id)
    # sync path: run to completion
    return asyncio.run(_compose_risk_score_async(decision, tenant_id=tenant_id))
