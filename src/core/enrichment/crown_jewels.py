"""Crown Jewels asset tagging.

Identifies whether a cluster touches high-value infrastructure assets and:
  - Sets cluster['crown_jewel'] = True / False
  - Populates cluster['crown_jewel_assets'] with which assets matched
  - Boosts cluster severity and verdict confidence when a crown jewel is hit

Crown jewels are configured via CROWN_JEWELS_ASSETS env var (JSON list of
hostname/IP/resource strings) plus built-in patterns for common high-value
roles (domain controllers, databases, PKI servers, backup infrastructure,
payment systems, secret stores).

Usage::
    from src.core.enrichment.crown_jewels import tag_cluster_crown_jewels
    tag_cluster_crown_jewels(cluster, rows)  # mutates cluster in-place
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── Built-in high-value hostname/resource patterns ────────────────────────────
# Ordered from most-specific to least.
_BUILTIN_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Domain controllers / AD
    (re.compile(r'\bdc\d*[.\-_]|domain.?controller|\bpdc\b|\bbdc\b|\\\\[a-z0-9\-]+dc\d', re.I), 'domain_controller'),
    # Certificate authorities / PKI
    (re.compile(r'\bpki\b|cert.?author|ca-server|\.ca\b|certsrv|adcs', re.I), 'certificate_authority'),
    # Privileged Access Workstations / PAM
    (re.compile(r'\bpaw\b|pam.?(server|host|vault)|cyberark|beyond.?trust|hashicorp.vault|secrets?-server', re.I), 'pam_vault'),
    # Database servers
    (re.compile(r'\bsql[.\-_]|sqlsrv|mssql|mysql|postgres|oracle[.\-_]|\bdb\d*[.\-_]|db-srv|mongodb|cassandra|aurora|rds\b', re.I), 'database_server'),
    # Backup / DR
    (re.compile(r'\bbackup[.\-_]|veeam|commvault|netbackup|backup.?exec|dr-srv|replication.?srv', re.I), 'backup_server'),
    # Payment / finance
    (re.compile(r'\bpayment|billing\b|finance[.\-_]|treasury|erp[.\-_]|sap[.\-_]|oracle.?fin|swift\b', re.I), 'payment_system'),
    # Source code / CI/CD
    (re.compile(r'\bgithub\.com|gitlab\b|bitbucket|jenkins[.\-_]|build-srv|cicd|nexus\b|artifactory', re.I), 'code_repository'),
    # Management / bastion
    (re.compile(r'\bjumpbox|bastion|mgmt-srv|management[.\-_]|jump[.\-_]srv|admin\.', re.I), 'management_host'),
    # Email infrastructure
    (re.compile(r'\bexchange|smtp-srv|mail[.\-_]srv|mta\b|postfix', re.I), 'mail_server'),
    # Secret stores / HSMs
    (re.compile(r'\bhsm\b|key.?vault|kms[.\-_]|vault\b|secrets?-mgr', re.I), 'secret_store'),
]

# Built-in critical IP ranges (RFC private is not enough; also catch OT/ICS)
_CRITICAL_IP_RE = re.compile(
    r'^10\.0\.0\.\d+$|^192\.168\.0\.\d+$|'    # gateway addresses — common DC placement
    r'^172\.16\.\d+\.1$',                        # default gateway of class B private
    re.I,
)


def _load_custom_assets() -> list[str]:
    """Load operator-defined crown jewel identifiers from env."""
    raw = os.getenv('CROWN_JEWELS_ASSETS') or ''
    if not raw.strip():
        return []
    try:
        items = json.loads(raw)
        if isinstance(items, list):
            return [str(x).lower() for x in items if x]
    except Exception:
        # Plain comma-separated list fallback
        return [x.strip().lower() for x in raw.split(',') if x.strip()]
    return []


def _classify_asset(identifier: str) -> str | None:
    """Return a role label if the identifier matches a crown jewel pattern."""
    ident_lower = identifier.lower()
    for pat, role in _BUILTIN_PATTERNS:
        if pat.search(ident_lower):
            return role
    if _CRITICAL_IP_RE.match(identifier):
        return 'gateway_host'
    return None


def _severity_rank(sev: str) -> int:
    return {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(str(sev).lower(), 1)


def _severity_label(rank: int) -> str:
    return {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}.get(rank, 'medium')


def tag_cluster_crown_jewels(cluster: dict, rows: list[dict]) -> None:
    """Tag *cluster* in-place with crown jewel context.

    Sets:
      ``cluster['crown_jewel']``       — bool
      ``cluster['crown_jewel_assets']`` — [{asset, role, source}]
      ``cluster['crown_jewel_roles']``  — sorted list of distinct role labels

    Also upgrades severity to at least 'high' and bumps confidence_meter.total
    by up to +15 when a crown jewel is touched.
    """
    custom = set(_load_custom_assets())
    matched: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _check(ident: str, source: str) -> None:
        if not ident or ident in seen:
            return
        seen.add(ident)
        lo = ident.lower()
        if lo in custom:
            matched.append({'asset': ident, 'role': 'operator_defined', 'source': source})
            return
        role = _classify_asset(ident)
        if role:
            matched.append({'asset': ident, 'role': role, 'source': source})

    # Check cluster-level aggregated fields
    for field in ('shared_accounts', 'shared_hosts', 'affected_assets',
                  'shared_external_ips', 'shared_resources'):
        for item in cluster.get(field) or []:
            _check(str(item), field)

    # Check individual row fields for fine-grained coverage
    for row in rows or []:
        for field in ('host', 'hostname', 'Computer', 'server', 'resource',
                      'dst_ip', 'ip', 'target_host', 'object_name'):
            val = row.get(field)
            if val:
                _check(str(val), f'row.{field}')
        for item in row.get('hosts') or []:
            _check(str(item), 'row.hosts')
        for item in row.get('resources') or []:
            _check(str(item), 'row.resources')

    is_cj = bool(matched)
    cluster['crown_jewel'] = is_cj
    cluster['crown_jewel_assets'] = matched[:12]
    cluster['crown_jewel_roles'] = sorted({m['role'] for m in matched})

    if not is_cj:
        return

    # Severity uplift: crown jewel touches are at minimum 'high'
    current_sev = cluster.get('severity') or 'medium'
    if _severity_rank(current_sev) < _severity_rank('high'):
        cluster['severity'] = 'high'
        logger.debug(
            'crown_jewels: uplifted cluster %s from %s→high',
            cluster.get('cluster_id'), current_sev,
        )

    # Confidence boost: +5 per unique role, max +15
    unique_roles = len(cluster['crown_jewel_roles'])
    boost = min(15.0, unique_roles * 5.0)
    cm = cluster.setdefault('confidence_meter', {})
    cm['total'] = min(100.0, float(cm.get('total') or 0.0) + boost)
    cm['crown_jewel_boost'] = boost


__all__ = ['tag_cluster_crown_jewels']
