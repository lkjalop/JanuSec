from __future__ import annotations

from typing import Any, Dict, List

from ..utils import cfg_get
from .base import StageContext, StageResult, timed_stage


def _flatten_values(value: Any, limit: int = 40) -> List[str]:
    """Collect string-like values from a nested structure for quick heuristics."""
    stack: List[Any] = [value]
    seen: List[str] = []
    while stack and len(seen) < limit:
        item = stack.pop()
        if item is None:
            continue
        if isinstance(item, str):
            stripped = item.strip()
            if stripped:
                seen.append(stripped)
        elif isinstance(item, (list, tuple, set)):
            stack.extend(list(item))
        elif isinstance(item, dict):
            stack.extend(list(item.values()))
        else:
            try:
                text = str(item)
                if text and text != 'None':
                    seen.append(text)
            except Exception:
                continue
    return seen


def _ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    if isinstance(value, tuple):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _supply_cfg(ctx: StageContext, section: str) -> Dict[str, Any]:
    pipeline_cfg = cfg_get(ctx.config, 'pipeline', {})
    supply_cfg = cfg_get(pipeline_cfg, 'supply_chain', {})
    return cfg_get(supply_cfg, section, {})


def _enrichment_bucket(ctx: StageContext, bucket: str) -> Dict[str, Any]:
    cache = ctx.state.setdefault('enrichment_cache', {})
    supply_bucket = cache.setdefault('supply_chain', {})
    return supply_bucket.setdefault(bucket, {})


@timed_stage('supply_chain_npm')
async def npm_stage(event: dict, ctx: StageContext) -> StageResult:
    cfg = _supply_cfg(ctx, 'npm')
    if not cfg_get(cfg, 'enabled', True):
        return StageResult(name='supply_chain_npm', factors=[])

    details = event.get('details') or {}
    scripts = details.get('lifecycle_scripts') or details.get('scripts') or event.get('lifecycle_scripts')
    package_name = details.get('package') or event.get('package')
    package_version = details.get('version') or event.get('package_version')
    text_blob = ' '.join(_flatten_values(event, limit=50)).lower()

    suspicious_scripts: List[str] = []
    factors: List[str] = []

    for script in _ensure_list(scripts):
        normalized = script.lower()
        if any(keyword in normalized for keyword in ('preinstall', 'postinstall', 'prepare', 'install')):
            suspicious_scripts.append(script)
            if 'curl' in normalized or 'wget' in normalized or 'bash' in normalized:
                factors.append('supply_chain:npm_lifecycle_script_exec')
            else:
                factors.append('supply_chain:npm_lifecycle_script')

    if '.npmrc' in text_blob or 'npm_token' in text_blob or 'npm_' in text_blob:
        factors.append('supply_chain:npm_credential_access')

    if 'api.github.com' in text_blob or 'github.com' in text_blob:
        factors.append('supply_chain:github_repo_exfil')

    metadata = {
        'package': package_name,
        'version': package_version,
        'scripts': suspicious_scripts,
    }
    if cfg_get(cfg, 'capture_text', False):
        metadata['preview'] = text_blob[:800]

    npm_bucket = _enrichment_bucket(ctx, 'npm')
    npm_bucket.update({k: v for k, v in metadata.items() if v})
    event.setdefault('supply_chain', {}).setdefault('npm', {}).update(npm_bucket)

    confidence = float(cfg_get(cfg, 'confidence_delta', 0.05) or 0.05) if factors else 0.0
    return StageResult(name='supply_chain_npm', factors=factors, confidence_delta=confidence)


@timed_stage('supply_chain_cicd')
async def cicd_stage(event: dict, ctx: StageContext) -> StageResult:
    cfg = _supply_cfg(ctx, 'cicd')
    if not cfg_get(cfg, 'enabled', True):
        return StageResult(name='supply_chain_cicd', factors=[])

    details = event.get('details') or {}
    workflow = details.get('workflow') or event.get('workflow')
    job_name = details.get('job') or details.get('step')
    repo = details.get('repository') or details.get('repo') or event.get('repository')
    text_blob = ' '.join(_flatten_values(event, limit=60)).lower()

    factors: List[str] = []
    anomalies: List[str] = []

    if 'runner.worker' in text_blob or 'gcore' in text_blob or '/proc/self/mem' in text_blob:
        factors.append('supply_chain:cicd_memory_dump')
        anomalies.append('memory_dump')
    if '::set-output' in text_blob or 'git tag' in text_blob and 'checkout' in text_blob:
        factors.append('supply_chain:workflow_tag_manipulation')
        anomalies.append('tag_override')
    if 'workflow_dispatch' in text_blob or 'pull_request_target' in text_blob:
        factors.append('supply_chain:workflow_privilege_escalation')
        anomalies.append('auto_dispatch')

    metadata = {
        'workflow': workflow,
        'job': job_name,
        'repository': repo,
        'anomalies': anomalies,
    }
    cicd_bucket = _enrichment_bucket(ctx, 'cicd')
    cicd_bucket.update({k: v for k, v in metadata.items() if v})
    event.setdefault('supply_chain', {}).setdefault('cicd', {}).update(cicd_bucket)

    confidence = float(cfg_get(cfg, 'confidence_delta', 0.04) or 0.04) if factors else 0.0
    return StageResult(name='supply_chain_cicd', factors=factors, confidence_delta=confidence)


def _collect_binary_entries(event: dict) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    keys = ('binaries', 'binary', 'artifacts', 'dropped_files', 'payloads', 'files')
    containers: List[Any] = []
    details = event.get('details') or {}
    for key in keys:
        val = event.get(key)
        if val:
            containers.append(val)
        detail_val = details.get(key)
        if detail_val:
            containers.append(detail_val)
    for container in containers:
        if isinstance(container, list):
            for item in container:
                if isinstance(item, dict):
                    candidates.append(item)
        elif isinstance(container, dict):
            candidates.append(container)
    return candidates


@timed_stage('binary_payload')
async def binary_payload_stage(event: dict, ctx: StageContext) -> StageResult:
    cfg = _supply_cfg(ctx, 'binary')
    if not cfg_get(cfg, 'enabled', True):
        return StageResult(name='binary_payload', factors=[])

    entries = _collect_binary_entries(event)
    if not entries:
        return StageResult(name='binary_payload', factors=[])

    factors: List[str] = []
    high_entropy: List[str] = []
    unsigned: List[str] = []

    for entry in entries:
        path = entry.get('path') or entry.get('file_path') or entry.get('name')
        entropy = float(entry.get('entropy') or 0.0)
        signed = entry.get('signed')
        sha256 = entry.get('sha256') or entry.get('hash')
        if path:
            factors.append('binary:payload_dropped')
        if entropy and entropy >= float(cfg_get(cfg, 'entropy_threshold', 7.2) or 7.2):
            high_entropy.append(path or sha256 or f'entry{len(high_entropy)+1}')
        if signed is False and path:
            unsigned.append(path)

    if high_entropy:
        factors.append('binary:high_entropy_payload')
    if unsigned:
        factors.append('binary:unsigned_payload')

    metadata = {
        'artifacts': entries[: cfg_get(cfg, 'metadata_limit', 5)],
        'high_entropy': high_entropy,
        'unsigned': unsigned,
    }
    binary_bucket = ctx.state.setdefault('enrichment_cache', {}).setdefault('binary', {})
    binary_bucket.update(metadata)
    event.setdefault('binary_artifacts', []).extend(entries)

    confidence = float(cfg_get(cfg, 'confidence_delta', 0.03) or 0.03) if factors else 0.0
    return StageResult(name='binary_payload', factors=factors, confidence_delta=confidence)
