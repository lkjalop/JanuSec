"""Account privilege tier classification.

Assigns each account in a cluster to a tier:
  Tier 0 — Domain/Global/Enterprise Admins, service accounts with unrestricted
            privilege, PAM-managed accounts, KRBTGT, Azure Global Admin.
  Tier 1 — Local admins, service accounts, helpdesk, cloud power users.
  Tier 2 — Standard end-users.

A cluster touching a Tier-0 account gets an immediate severity/confidence
uplift because credential compromise at that tier typically equals full
domain/tenant takeover.

Usage::
    from src.core.enrichment.account_tiers import classify_cluster_accounts
    classify_cluster_accounts(cluster, rows)   # mutates cluster in-place

Populates:
    cluster['account_tiers']        — {account: tier (0/1/2)}
    cluster['min_account_tier']     — lowest (most privileged) tier found
    cluster['tier0_accounts']       — list of Tier-0 accounts
    cluster['tier1_accounts']       — list of Tier-1 accounts
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── Tier-0 patterns (any match → immediate Tier 0) ────────────────────────────
_TIER0_RE = re.compile(
    r'\bdomain.?admin|\bda\b|enterprise.?admin|\bea\b|schema.?admin|'
    r'\bkrbtgt\b|global.?admin|company.?admin|'
    r'\\administrator$|^administrator$|'   # local admin (built-in)
    r'\broot\b|'
    r'service.?account.*(svc|admin|priv)|'
    r'privileged.?access|pam.?account|'
    r'azure.?global|cloud.?admin|tenant.?admin|'
    r'@.*\.onmicrosoft\.com.*admin|'
    r'\bbreak.?glass\b',
    re.I,
)

# ── Tier-1 patterns ────────────────────────────────────────────────────────────
_TIER1_RE = re.compile(
    r'\blocal.?admin|\bsvc[-_.]|[-_.]svc\b|svc\d+@|'
    r'service@|help.?desk|it.?support|noc[-_.]|'
    r'\bbackup.?operator|\bprint.?operator|\bserver.?operator|'
    r'power.?user|account.?operator|'
    r'cloud.?operator|devops|ci[-_.]cd|build.?agent|deploy.?account|'
    r'\badmin\b',  # generic "admin" prefix — not global/domain
    re.I,
)


def _tier_for_account(account: str) -> int:
    """Return 0, 1, or 2 for the given account string."""
    if not account:
        return 2
    if _TIER0_RE.search(account):
        return 0
    if _TIER1_RE.search(account):
        return 1
    return 2


def classify_cluster_accounts(cluster: dict, rows: list[dict]) -> None:
    """Classify accounts in *cluster* and tag privilege tiers.

    Mutates cluster with:
      ``account_tiers``        — {account: tier}
      ``min_account_tier``     — most-privileged tier (0 = worst)
      ``tier0_accounts``       — Tier-0 accounts (domain/global admin, etc.)
      ``tier1_accounts``       — Tier-1 accounts (local admin, service accts)
    """
    # Collect accounts from cluster-level and per-row fields
    all_accounts: set[str] = set()
    for field in ('shared_accounts', 'affected_accounts'):
        for acct in cluster.get(field) or []:
            if acct:
                all_accounts.add(str(acct))
    for row in rows or []:
        for field in ('accounts', 'user', 'username', 'actor', 'initiatedBy'):
            val = row.get(field)
            if isinstance(val, str) and val:
                all_accounts.add(val)
            elif isinstance(val, list):
                all_accounts.update(str(v) for v in val if v)

    tiers: dict[str, int] = {}
    for acct in all_accounts:
        tiers[acct] = _tier_for_account(acct)

    tier0 = sorted(a for a, t in tiers.items() if t == 0)
    tier1 = sorted(a for a, t in tiers.items() if t == 1)
    min_tier = min(tiers.values()) if tiers else 2

    cluster['account_tiers'] = tiers
    cluster['min_account_tier'] = min_tier
    cluster['tier0_accounts'] = tier0[:8]
    cluster['tier1_accounts'] = tier1[:8]

    if not tiers:
        return

    # Severity and confidence uplift for privileged account involvement
    if min_tier == 0:
        # Tier-0 compromise → always at least 'critical'
        cluster['severity'] = 'critical'
        cm = cluster.setdefault('confidence_meter', {})
        cm['total'] = min(100.0, float(cm.get('total') or 0.0) + 20.0)
        cm['tier0_account_boost'] = 20.0
        logger.debug(
            'account_tiers: Tier-0 account in cluster %s — uplifted to critical',
            cluster.get('cluster_id'),
        )
    elif min_tier == 1:
        from .crown_jewels import _severity_rank
        if _severity_rank(cluster.get('severity') or 'medium') < 3:
            cluster['severity'] = 'high'
        cm = cluster.setdefault('confidence_meter', {})
        cm['total'] = min(100.0, float(cm.get('total') or 0.0) + 8.0)
        cm['tier1_account_boost'] = 8.0


__all__ = ['classify_cluster_accounts', '_tier_for_account']
