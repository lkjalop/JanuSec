from __future__ import annotations

from .base import StageContext, StageResult, timed_stage
import os
from typing import Any, Dict

from src.core.detectors.token_theft import TokenTelemetryAnalyzer


@timed_stage('identity')
async def identity_stage(event: dict, ctx: StageContext) -> StageResult:
    """Emit lightweight identity factors from auth/login events.

    - identity:lateral_movement when user logs in remotely (src_host != dest/host)
    - identity:priv_escalation when role/group suggests elevation or explicit action (su/runas/assume_role)
    - identity:cloud_pivot when a cloud principal/resource is involved
    """
    factors: list[str] = []
    metadata: Dict[str, Any] | None = None
    try:
        # Normalize common fields
        etype = str(event.get('event_type') or '').lower()
        action = str(event.get('action') or '').lower()
        user = event.get('user') or event.get('username')
        src_h = event.get('src_host') or event.get('source_host')
        dst_h = event.get('dest_host') or event.get('host') or event.get('hostname')

        # Lateral movement (remote interactive logins, or any login with src != dest)
        login_type = str(event.get('login_type') or '').lower()
        if user and (
            (etype in {'login','auth','authentication'} and src_h and dst_h and str(src_h) != str(dst_h)) or
            ('remote' in login_type or 'interactive' in login_type)
        ):
            factors.append('identity:lateral_movement')

        # Privilege escalation
        groups = [str(g).lower() for g in (event.get('groups') or []) if g]
        new_role = str(event.get('new_role') or event.get('target_role') or '').lower()
        if any(x in action for x in ('su','runas','assume_role')) or any('admin' in g or 'sudo' in g for g in groups) or ('admin' in new_role):
            factors.append('identity:priv_escalation')

        # Cloud pivot
        principal = str(event.get('principal_arn') or event.get('principal') or '').lower()
        cloud_res = str(event.get('cloud_resource') or event.get('resource_arn') or '').lower()
        if ('arn:aws:' in principal or 'azure' in principal or 'gcp' in principal) or cloud_res:
            factors.append('identity:cloud_pivot')

        # Privilege delta (per-tenant threshold)
        tenant_id = str(event.get('tenant_id') or os.getenv('DEFAULT_TENANT','default'))
        try:
            from src.core.config.tenant_overrides import get_overrides  # type: ignore
            overrides = get_overrides(tenant_id) or {}
        except Exception:
            overrides = {}
        priv_thresh = float(overrides.get('iam_privilege_delta_threshold', 2))
        risky_fail_thresh = int(overrides.get('risky_login_failed_count', 5))

        delta_count = None
        iam_block = event.get('iam') or {}
        if isinstance(iam_block, dict):
            delta_count = iam_block.get('privilege_delta_count')
        if delta_count is None:
            # attempt to compute via roles_before/after lists
            before = set((iam_block.get('roles_before') or event.get('roles_before') or []) or [])
            after = set((iam_block.get('roles_after') or event.get('roles_after') or []) or [])
            try:
                delta_count = max(0, len(list(after - before)))
            except Exception:
                delta_count = 0
        try:
            if isinstance(delta_count, (int, float)) and float(delta_count) >= priv_thresh:
                factors.append('iam:privilege_delta_high')
        except Exception:
            pass

        # Risky login (simple heuristic): many failures or MFA disabled
        failed = int(event.get('failed_count') or event.get('auth_failures') or 0)
        mfa_state = str(iam_block.get('mfa_state_change') or event.get('mfa_state_change') or '').lower()
        if failed >= risky_fail_thresh or ('disable' in mfa_state and 'enable' not in mfa_state):
            factors.append('iam:risky_login')
    except Exception:
        pass

    # Best-effort: auto-ingest identity events into IdentityHopGraph when factors emitted
    try:
        if any(str(f).startswith('identity:') for f in factors):
            from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as _G  # type: ignore
            _G.ingest_identity_event(event)
    except Exception:
        # Do not block pipeline if graph module is unavailable
        pass

    # Path scoring metadata (lightweight): sum of identity factor weights
    try:
        score = 0.0
        for f in factors:
            if f.endswith('priv_escalation'):
                score += 0.4
            elif f.endswith('lateral_movement'):
                score += 0.3
            elif f.endswith('cloud_pivot'):
                score += 0.2
            elif f.endswith('privilege_delta_high'):
                score += 0.25
            elif f.endswith('risky_login'):
                score += 0.15
        metadata = {'identity_path_score': round(min(1.0, score), 4)}
    except Exception:
        metadata = {}

    # Record identity event flags for metrics
    try:
        from src.metrics.identity_metrics import record_event_flags  # type: ignore
        flags = {
            'privilege_delta_high': ('iam:privilege_delta_high' in factors),
            'risky_login': ('iam:risky_login' in factors),
            'priv_escalation': ('identity:priv_escalation' in factors),
            'lateral_movement': ('identity:lateral_movement' in factors),
            'cloud_pivot': ('identity:cloud_pivot' in factors),
        }
        record_event_flags(flags)
    except Exception:
        pass

    telemetry_result = None
    try:
        analyzer = ctx.state.setdefault('token_telemetry_analyzer', TokenTelemetryAnalyzer())
        telemetry_result = analyzer.analyze(event)
    except Exception:
        telemetry_result = None

    if telemetry_result and telemetry_result.factors:
        for factor in telemetry_result.factors:
            if factor not in factors:
                factors.append(factor)
        metadata = metadata or {}
        metadata.setdefault('token_security_alerts', []).extend(telemetry_result.alerts)
        cache = ctx.state.setdefault('enrichment_cache', {})
        bucket = cache.setdefault('token_security', {'alerts': []})
        bucket['alerts'].extend(telemetry_result.alerts)
        if telemetry_result.hopgraph_observations:
            try:
                from src.core.graph.hopgraph_lite import get_graph  # type: ignore

                graph = get_graph()
                for obs in telemetry_result.hopgraph_observations:
                    graph.observe(obs)
            except Exception:
                pass

    metadata = metadata or {}
    return StageResult(name='identity', factors=factors, metadata=metadata)
