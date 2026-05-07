"""Infrastructure role classification for clusters.

Assigns roles (domain_controller, database_server, jump_server, etc.) to
hosts/IPs observed in a cluster using hostname patterns and port/service
heuristics.  This gives downstream analysis a precise answer to "was a
high-value server targeted?" rather than relying on generic severity labels.

Usage::
    from src.core.enrichment.infra_roles import classify_cluster_infra
    classify_cluster_infra(cluster, rows)  # mutates cluster in-place

Populates:
    cluster['infra_roles']            — {role: [asset, …]}
    cluster['high_value_targets']     — subset of roles that are Tier-1 infra
    cluster['lateral_to_hv_target']   — True when lateral movement reached HV infra
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── Role → (hostname_pattern, critical_ports, description) ───────────────────
_ROLE_RULES: list[dict[str, Any]] = [
    {
        'role': 'domain_controller',
        'tier': 0,
        'host_re': re.compile(
            r'\bdc\d*[.\-_]|[.\-_]dc\d*\b|domain.?controller|addc|ad-srv|'
            r'kerberos|kdc\b|ldap.?srv',
            re.I,
        ),
        'ports': {88, 389, 636, 3268, 3269, 445},  # Kerberos, LDAP(S), LDAP-GC, SMB
        'mitre_affinity': ['T1558', 'T1207', 'T1484', 'T1003.006'],  # Kerberoast, DRSUAPI
    },
    {
        'role': 'certificate_authority',
        'tier': 0,
        'host_re': re.compile(r'\bpki\b|adcs|cert.?srv|ca[-_.]srv|issuing[-_.]ca|root[-_.]ca', re.I),
        'ports': {80, 443, 135},  # certsrv / DCOM
        'mitre_affinity': ['T1649', 'T1552.004'],  # Steal or forge certs
    },
    {
        'role': 'pam_vault',
        'tier': 0,
        'host_re': re.compile(
            r'cyberark|beyond.?trust|hashicorp.vault|secrets?[-_.]mgr|pam[-_.]srv|'
            r'vault[-_.]srv|conjur',
            re.I,
        ),
        'ports': {8200, 8443},
        'mitre_affinity': ['T1555', 'T1552'],
    },
    {
        'role': 'database_server',
        'tier': 1,
        'host_re': re.compile(
            r'\bsql[-_.]|sqlsrv|mssql|mysql[-_.]|postgres[-_.]|oracle[-_.]|'
            r'\bdb\d*[-_.]|mongodb|cassandra[-_.]|aurora[-_.]',
            re.I,
        ),
        'ports': {1433, 1521, 3306, 5432, 5984, 27017, 6379, 9200},  # MSSQL Oracle MySQL Pg CouchDB Mongo Redis ES
        'mitre_affinity': ['T1190', 'T1567', 'T1005'],
    },
    {
        'role': 'backup_server',
        'tier': 1,
        'host_re': re.compile(r'\bbackup[-_.]|veeam|commvault|netbackup|backup.?exec|dr[-_.]srv', re.I),
        'ports': {9443, 2500, 2501, 10000},
        'mitre_affinity': ['T1490', 'T1485'],  # Inhibit recovery, data destruction
    },
    {
        'role': 'management_host',
        'tier': 1,
        'host_re': re.compile(r'\bjumpbox|bastion|mgmt[-_.]|jump[-_.]srv|admin\.internal', re.I),
        'ports': {22, 3389, 5985, 5986},  # SSH RDP WinRM
        'mitre_affinity': ['T1021', 'T1563'],
    },
    {
        'role': 'hypervisor',
        'tier': 1,
        'host_re': re.compile(r'\besxi|vcenter|hyper-?v|proxmox|nutanix|xen[-_.]|kvm[-_.]', re.I),
        'ports': {443, 902, 9100},
        'mitre_affinity': ['T1611'],  # Container/VM escape
    },
    {
        'role': 'mail_server',
        'tier': 1,
        'host_re': re.compile(r'\bexchange|smtp[-_.]srv|mail[-_.]srv|mta\b|postfix[-_.]', re.I),
        'ports': {25, 465, 587, 993, 995},
        'mitre_affinity': ['T1114', 'T1534'],
    },
    {
        'role': 'web_server',
        'tier': 2,
        'host_re': re.compile(r'\bwww\d*\.|web[-_.]srv|nginx[-_.]|apache[-_.]|iis[-_.]|api[-_.]gw', re.I),
        'ports': {80, 443, 8080, 8443},
        'mitre_affinity': ['T1190', 'T1505.003'],
    },
]

# Tier labels for display
_TIER_LABELS = {0: 'Tier-0 (Crown-Jewel)', 1: 'Tier-1 (High-Value)', 2: 'Tier-2 (Standard)'}

# Lateral movement MITRE techniques
_LATERAL_MITRE = frozenset([
    'T1021', 'T1021.001', 'T1021.002', 'T1021.004', 'T1021.006',
    'T1563', 'T1534', 'T1550', 'T1550.002', 'T1550.003',
    'T1570', 'T1105', 'T1210',
])


def _extract_port(row: dict) -> set[int]:
    """Extract any port numbers from a row."""
    ports: set[int] = set()
    for field in ('dst_port', 'port', 'service_port', 'target_port'):
        val = row.get(field)
        try:
            ports.add(int(val))
        except (TypeError, ValueError):
            pass
    return ports


def classify_cluster_infra(cluster: dict, rows: list[dict]) -> None:
    """Classify infrastructure roles for a cluster and tag high-value targets.

    Mutates cluster with:
      ``infra_roles``         — {role_label: [assets]}
      ``high_value_targets``  — list of role labels where tier <= 1
      ``lateral_to_hv_target`` — True if lateral movement MITRE + HV target coexist
      ``infra_tier``          — 0 (Tier-0), 1, 2 or None
    """
    infra_roles: dict[str, list[str]] = {}
    matched_tiers: list[int] = []

    # Gather all host/IP identifiers from cluster and rows
    candidates: list[str] = []
    for field in ('shared_hosts', 'affected_assets', 'shared_external_ips', 'shared_resources'):
        candidates.extend(str(v) for v in (cluster.get(field) or []) if v)
    for row in rows or []:
        for field in ('host', 'hostname', 'Computer', 'dst_ip', 'server', 'target_host'):
            val = row.get(field)
            if val:
                candidates.append(str(val))
        candidates.extend(str(v) for v in (row.get('hosts') or []) if v)

    row_ports: set[int] = set()
    for row in rows or []:
        row_ports.update(_extract_port(row))

    seen: set[str] = set()
    for rule in _ROLE_RULES:
        role = rule['role']
        pat: re.Pattern = rule['host_re']
        tier: int = rule['tier']
        crit_ports: set[int] = rule['ports']

        matches: list[str] = []
        for ident in candidates:
            lo = ident.lower()
            if lo in seen:
                continue
            if pat.search(lo) or (crit_ports & row_ports and pat.search(lo)):
                matches.append(ident)
                seen.add(lo)

        # Port-only match (no hostname available but matching port)
        if not matches and crit_ports & row_ports:
            # Can't name the asset — tag the role with the port as hint
            for port in sorted(crit_ports & row_ports)[:3]:
                hint = f'port:{port}'
                if hint not in seen:
                    matches.append(hint)
                    seen.add(hint)

        if matches:
            infra_roles[role] = matches[:6]
            matched_tiers.append(tier)

    hv_targets = [
        role
        for rule_data in _ROLE_RULES
        if rule_data['role'] in infra_roles and rule_data['tier'] <= 1
        for role in [rule_data['role']]
    ]

    # Determine if lateral movement MITRE tags are present in this cluster
    cluster_mitre = set(cluster.get('top_mitre') or [])
    for row in rows or []:
        cluster_mitre.update(row.get('mitre') or [])
    # Match both exact sub-technique and base technique
    expanded_mitre: set[str] = set()
    for t in cluster_mitre:
        expanded_mitre.add(t)
        expanded_mitre.add(t.split('.')[0])  # parent technique
    has_lateral = bool(_LATERAL_MITRE & expanded_mitre)

    cluster['infra_roles'] = infra_roles
    cluster['high_value_targets'] = hv_targets
    cluster['lateral_to_hv_target'] = has_lateral and bool(hv_targets)
    cluster['infra_tier'] = min(matched_tiers) if matched_tiers else None

    # Severity uplift for Tier-0 infrastructure involvement
    if matched_tiers and min(matched_tiers) == 0:
        from .crown_jewels import _severity_rank, _severity_label
        current_rank = _severity_rank(cluster.get('severity') or 'medium')
        if current_rank < 3:  # < high
            cluster['severity'] = 'high'
        cm = cluster.setdefault('confidence_meter', {})
        cm['total'] = min(100.0, float(cm.get('total') or 0.0) + 10.0)
        cm['infra_tier0_boost'] = 10.0


__all__ = ['classify_cluster_infra']
