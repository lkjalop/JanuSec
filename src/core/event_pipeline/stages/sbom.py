from __future__ import annotations

from typing import List

from repositories.sbom_exec_repo import get_sbom_exec_repo

from .base import StageContext, StageResult, maybe_await, timed_stage


@timed_stage('sbom_exec')
async def sbom_execution_stage(event: dict, ctx: StageContext) -> StageResult:
    proc = event.get('process') if isinstance(event.get('process'), dict) else {}
    child_name = proc.get('name') if isinstance(proc, dict) else None
    process_name = event.get('process_name') or event.get('image_name') or child_name
    proc_hash = event.get('process_hash') or event.get('image_hash') or (proc.get('hash') if isinstance(proc, dict) else None)
    tenant = event.get('tenant_id') or 'default'
    factors: list[str] = []
    component_key = None
    if proc_hash and process_name:
        try:
            link = get_sbom_exec_repo().observe_execution(tenant, str(proc_hash), str(process_name), None)
            component_key = link.get('component_key')
            drift = bool(link.get('drift'))
            baseline_missing = component_key and component_key.endswith(':unknown') and not drift
            if baseline_missing:
                factors.append('non_sbom_component_exec')
            if drift:
                factors.append('component_hash_drift')
        except Exception as exc:
            try:
                ctx.logger.debug('SBOM execution stage error: %s', exc)
            except Exception:
                pass
    if component_key:
        ctx.state['sbom_component_key'] = component_key
    return StageResult(name='sbom_exec', factors=factors)


@timed_stage('sbom_vuln')
async def sbom_vulnerability_stage(event: dict, ctx: StageContext) -> StageResult:
    component_key = ctx.state.get('sbom_component_key')
    if not component_key:
        return StageResult(name='sbom_vuln', factors=[])
    module = await ctx.resolve_module('sbom_vuln_mapper')
    if not module or not hasattr(module, 'map_event'):
        return StageResult(name='sbom_vuln', factors=[])
    tenant = event.get('tenant_id') or 'default'
    existing_factors = list(ctx.state.get('factors') or [])
    new_factors: list[str] = []
    delta = 0.0
    metadata = None
    try:
        res = await maybe_await(module.map_event(tenant, component_key, existing_factors))  # type: ignore[arg-type]
        if isinstance(res, dict):
            new_factors.extend(list(res.get('factors') or []))
            delta = float(res.get('delta') or 0.0)
            meta = res.get('meta') or {}
            # Inject lightweight vuln_context (cvss, exploit markers) for risk composer
            try:
                vc = {
                    'max_cvss': float(meta.get('cvss_max') or 0.0),
                    # best-effort exploit flag from factors if present
                    'exploit_available': any(f in ('exploit:kev','exploit:high_epss') for f in new_factors),
                }
                ctx.state['vuln_context'] = vc
                metadata = {'vuln_context': vc}
            except Exception:
                metadata = None
    except Exception as exc:
        try:
            ctx.logger.debug('SBOM vulnerability stage error: %s', exc)
        except Exception:
            pass
    return StageResult(name='sbom_vuln', factors=new_factors, confidence_delta=delta, metadata=metadata)
