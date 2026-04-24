from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/v1/config", tags=["config"])

_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'data'))
_DEFAULT_CJ = os.path.join(_DATA_DIR, 'crown_jewels.json')

# All supported sections — order matters for PATCH validation only
_ALL_SECTIONS = ('assets', 'accounts', 'destinations', 'subnets', 'cloud_accounts')

# Severity ladder: lower index = higher criticality
_TIER_ORDER = ['crown_jewel', 'tier_1', 'tier_2', 'tier_3', 'not_sensitive']


# ── Storage helpers ──────────────────────────────────────────────────────────

def _cj_path(tenant_id: str) -> str:
    safe = ''.join(c for c in tenant_id if c.isalnum() or c in ('-', '_'))[:64] or 'default'
    return os.path.join(_DATA_DIR, f'crown_jewels_{safe}.json')


def _load_crown_jewels(tenant_id: str) -> dict:
    path = _cj_path(tenant_id)
    if os.path.exists(path):
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    if os.path.exists(_DEFAULT_CJ):
        with open(_DEFAULT_CJ, encoding='utf-8') as f:
            return json.load(f)
    return {s: {} for s in _ALL_SECTIONS}


def _save_crown_jewels(tenant_id: str, data: dict) -> None:
    path = _cj_path(tenant_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


# ── Tier resolution ──────────────────────────────────────────────────────────

def _effective_tier(entry: dict) -> str:
    """Return the human-overridden tier when a confirmed/escalated/downgraded review
    exists; otherwise return the original auto-detected tier."""
    review = entry.get('_human_review') or {}
    if review.get('status') in ('confirmed', 'escalated', 'downgraded') and review.get('override_tier'):
        return review['override_tier']
    return entry.get('tier', '')


def _review_badge(entry: dict) -> str:
    """Return a short status label for UI display."""
    review = entry.get('_human_review') or {}
    status = review.get('status', '')
    return {
        'confirmed':  'human-confirmed',
        'escalated':  'human-escalated',
        'downgraded': 'human-downgraded',
    }.get(status, 'pending-review')


def _tier_index(tier: str) -> int:
    try:
        return _TIER_ORDER.index(tier)
    except ValueError:
        return len(_TIER_ORDER)


def _derive_review_status(original_tier: str, override_tier: str) -> str:
    orig_idx = _tier_index(original_tier)
    new_idx  = _tier_index(override_tier)
    if new_idx == orig_idx:
        return 'confirmed'
    return 'escalated' if new_idx < orig_idx else 'downgraded'


# ── CIDR subnet matching ─────────────────────────────────────────────────────

def _ip_in_subnet(ip_str: str, subnets: dict) -> tuple[str, dict] | None:
    """Return (cidr_key, entry) if ip_str falls within any registered subnet.
    Returns None on invalid IP or no match."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    for cidr, entry in subnets.items():
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return (cidr, entry)
        except ValueError:
            continue
    return None


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get('/tenant/{tenant_id}/crown-jewels')
async def get_crown_jewels(tenant_id: str) -> dict:
    """Return the full crown jewels registry with computed effective_tier and review_badge
    annotations on each entry for display purposes."""
    try:
        cj = _load_crown_jewels(tenant_id)
        for section in _ALL_SECTIONS:
            for entry in (cj.get(section) or {}).values():
                if isinstance(entry, dict):
                    entry['_effective_tier'] = _effective_tier(entry)
                    entry['_review_badge'] = _review_badge(entry)
        return cj
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'failed to load crown jewels: {exc}')


@router.patch('/tenant/{tenant_id}/crown-jewels')
async def patch_crown_jewels(tenant_id: str, request: Request) -> dict:
    """Merge-patch the crown jewels registry.

    Accepts any subset of top-level sections: assets, accounts, destinations,
    subnets, cloud_accounts. Per-section entries are merged at key level.
    Set a value to null to remove the key.

    Subnet keys must be CIDR notation (e.g. "10.0.4.0/24").
    Cloud account keys should be the account/subscription/project ID.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid JSON body')
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='body must be a JSON object')

    current = _load_crown_jewels(tenant_id)
    for section in _ALL_SECTIONS:
        if section not in body:
            continue
        patch = body[section]
        if not isinstance(patch, dict):
            raise HTTPException(status_code=400, detail=f'{section} must be an object')
        current.setdefault(section, {})
        for key, val in patch.items():
            if val is None:
                current[section].pop(key, None)
            else:
                current[section][key] = val

    _save_crown_jewels(tenant_id, current)
    return {'status': 'ok', 'tenant_id': tenant_id, 'crown_jewels': current}


@router.post('/tenant/{tenant_id}/crown-jewels/{section}/{key}/review')
async def review_crown_jewel(
    tenant_id: str,
    section: str,
    key: str,
    request: Request,
) -> dict:
    """Human gate: escalate or downgrade the effective tier of a crown jewels entry.

    Body fields:
      override_tier  (required)  — one of: crown_jewel | tier_1 | tier_2 | tier_3 | not_sensitive
      reason         (required)  — free-text rationale, stored in audit trail
      reviewer       (optional)  — reviewer identity (email or username); defaults to 'unknown'

    The system derives the review status automatically:
      confirmed   — override_tier matches the original tier (human validates auto-tag)
      escalated   — override_tier is higher criticality than original (e.g. tier_2 → crown_jewel)
      downgraded  — override_tier is lower criticality than original (e.g. crown_jewel → tier_2)

    The effective_tier field on the entry will reflect the override from this point forward,
    propagating into DREAD fragments, verdict gating, and notification trigger logic.
    """
    if section not in _ALL_SECTIONS:
        raise HTTPException(
            status_code=400,
            detail=f'unknown section "{section}". Must be one of: {list(_ALL_SECTIONS)}',
        )

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid JSON body')

    override_tier = str(body.get('override_tier') or '').strip()
    reason        = str(body.get('reason') or '').strip()
    reviewer      = str(body.get('reviewer') or 'unknown').strip()

    if override_tier not in _TIER_ORDER:
        raise HTTPException(
            status_code=400,
            detail=f'override_tier must be one of: {_TIER_ORDER}',
        )
    if not reason:
        raise HTTPException(status_code=400, detail='reason is required for audit trail')

    current = _load_crown_jewels(tenant_id)
    section_data = current.get(section) or {}
    entry = section_data.get(key)

    if entry is None:
        raise HTTPException(status_code=404, detail=f'{section}/{key} not found in crown jewels')
    if not isinstance(entry, dict):
        raise HTTPException(status_code=422, detail=f'{section}/{key} is not an object entry')

    original_tier  = entry.get('tier', '')
    review_status  = _derive_review_status(original_tier, override_tier)

    entry['_human_review'] = {
        'override_tier': override_tier,
        'original_tier': original_tier,
        'status':        review_status,
        'reason':        reason,
        'reviewer':      reviewer,
        'reviewed_at':   datetime.now(timezone.utc).isoformat(),
    }
    current.setdefault(section, {})[key] = entry
    _save_crown_jewels(tenant_id, current)

    return {
        'status':        'ok',
        'section':       section,
        'key':           key,
        'original_tier': original_tier,
        'override_tier': override_tier,
        'review_status': review_status,
        'effective_tier': _effective_tier(entry),
        'reviewer':      reviewer,
    }


@router.delete('/tenant/{tenant_id}/crown-jewels/{section}/{key}/review')
async def clear_crown_jewel_review(tenant_id: str, section: str, key: str) -> dict:
    """Remove a human review override, reverting this entry to its auto-detected tier."""
    if section not in _ALL_SECTIONS:
        raise HTTPException(status_code=400, detail=f'unknown section: {section}')
    current = _load_crown_jewels(tenant_id)
    entry = (current.get(section) or {}).get(key)
    if entry is None:
        raise HTTPException(status_code=404, detail=f'{section}/{key} not found')
    if isinstance(entry, dict):
        entry.pop('_human_review', None)
        _save_crown_jewels(tenant_id, current)
    return {'status': 'ok', 'section': section, 'key': key, 'review': 'cleared'}


@router.get('/tenant/{tenant_id}/crown-jewels/resolve')
async def resolve_asset(
    tenant_id: str,
    ip: str = '',
    account: str = '',
    asset: str = '',
    cloud_account: str = '',
) -> dict:
    """Resolve one or more identifiers to their effective tier.

    - ip:            checked against subnets via CIDR matching
    - account:       exact key match in accounts section
    - asset:         exact key match in assets section
    - cloud_account: exact key match in cloud_accounts section

    Returns a list of matches. An entry absent from the registry returns nothing
    (not a 404 — absence means untagged, not error).
    """
    cj = _load_crown_jewels(tenant_id)
    results: list[dict] = []

    if ip:
        match = _ip_in_subnet(ip, cj.get('subnets') or {})
        if match:
            cidr, entry = match
            results.append({
                'lookup': ip, 'type': 'subnet', 'key': cidr,
                'entry': entry,
                'effective_tier': _effective_tier(entry),
                'review_badge': _review_badge(entry),
            })

    for lookup_val, section in (
        (account,       'accounts'),
        (asset,         'assets'),
        (cloud_account, 'cloud_accounts'),
    ):
        if lookup_val:
            entry = (cj.get(section) or {}).get(lookup_val)
            if entry and isinstance(entry, dict):
                results.append({
                    'lookup': lookup_val, 'type': section, 'key': lookup_val,
                    'entry': entry,
                    'effective_tier': _effective_tier(entry),
                    'review_badge': _review_badge(entry),
                })

    return {'tenant_id': tenant_id, 'matches': results, 'count': len(results)}


# ── Assessment defaults ──────────────────────────────────────────────────────

@router.get('/assessment_defaults')
async def get_assessment_defaults() -> dict:
    """Return the assessment defaults YAML as JSON."""
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    cfg_path = os.path.join(repo_root, 'config', 'assessment_defaults.yml')
    if not os.path.exists(cfg_path):
        raise HTTPException(status_code=404, detail='assessment_defaults not found')
    try:
        try:
            import yaml  # type: ignore
            with open(cfg_path, 'r', encoding='utf-8') as fh:
                data = yaml.safe_load(fh)
            return data or {}
        except Exception:
            def _simple_yaml_parse(text: str) -> dict:
                out: dict = {}
                stack = [out]
                indent_stack = [0]
                for line in text.splitlines():
                    if not line.strip() or line.strip().startswith('#'):
                        continue
                    indent = len(line) - len(line.lstrip(' '))
                    if ':' in line:
                        key, val = line.split(':', 1)
                        key = key.strip()
                        val = val.strip()
                        while indent_stack and indent < indent_stack[-1]:
                            stack.pop(); indent_stack.pop()
                        if val == '':
                            node: dict = {}
                            stack[-1][key] = node
                            stack.append(node)
                            indent_stack.append(indent + 2)
                        else:
                            if val.lower() in ('true', 'false'):
                                v: object = val.lower() == 'true'
                            else:
                                try:
                                    v = float(val) if '.' in val else int(val)
                                except Exception:
                                    v = val
                            stack[-1][key] = v
                return out

            with open(cfg_path, 'r', encoding='utf-8') as fh:
                raw = fh.read()
            parsed = _simple_yaml_parse(raw)
            return parsed if parsed else {'raw': raw}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'failed to load config: {exc}')
