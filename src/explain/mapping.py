"""Mapping of observed enrichments/actions to explainable frameworks (MITRE/STRIDE/DREAD).

This module contains simple rule tables and lookup helpers. It's intentionally
small and deterministic to aid explainability and unit testing.

The public function `map_enrichments` accepts either:
 - a list of enrichment key strings (legacy), or
 - a dict mapping enrichment key -> observed value/context

The return shape is a dict with `mitre`, `stride`, `dread` (components), and `details`.
"""
from __future__ import annotations

from typing import Dict, List, Any, Union

# Expanded MITRE/STRIDE lookup tables (compact subset)
MITRE_TABLE = {
    # Infrastructure / container
    'ebpf:container_escape': ['T1610'],
    'ebpf:priv_escalation': ['T1548'],
    'falco_rule:shell_spawn': ['T1059.001'],
    # Network
    'network:port_scan': ['T1595'],
    # Lateral movement
    'lateral:ssh': ['T1021.004'],
    'lateral:smb': ['T1021.002'],
    # Supply chain
    'supply_chain:download_component': ['T1195'],
    # Identity — Credential Access
    'iam:kerberoasting': ['T1558.003'],
    'iam:rc4_downgrade': ['T1558.003'],
    'iam:pass_the_hash': ['T1550.002'],
    'iam:pass_the_ticket': ['T1550.003'],
    'iam:golden_ticket': ['T1558.001'],
    'iam:silver_ticket': ['T1558.002'],
    'iam:dcsync': ['T1003.006'],
    'iam:brute_force': ['T1110'],
    'iam:password_spray': ['T1110.003'],
    # Identity — Persistence / Privilege Escalation
    'iam:service_principal_credential_add': ['T1098.001'],
    'iam:new_admin_account': ['T1136.001'],
    'iam:privileged_role_assigned': ['T1078.004'],
    'iam:mfa_disabled': ['T1556.006'],
    'iam:oauth_app_consent': ['T1550.001'],
    # Cloud / Azure AAD
    'cloud:conditional_access_bypass': ['T1078.004'],
    'cloud:foreign_asn_signin': ['T1078'],
    'cloud:global_admin_pim': ['T1078.004'],
    'cloud:sharepoint_lookalike': ['T1566.002'],
    # Endpoint / Execution
    'endpoint:lolbin_execution': ['T1218'],
    'endpoint:encoded_powershell': ['T1059.001', 'T1027'],
    'endpoint:wmi_exec': ['T1047'],
    'endpoint:first_seen_host_access': ['T1021'],
    'endpoint:defense_evasion': ['T1562'],
    # Data / Exfiltration
    'data:large_extract': ['T1030'],
    'data:external_transfer': ['T1567'],
    'data:cumulative_bytes_anomaly': ['T1030'],
    # OAuth / Token
    'token_reuse_foreign_asn': ['T1078', 'T1550.001'],
    'token_foreign_signin': ['T1078'],
    # Behavioral / ML
    'off_hours_recon_sequence': ['T1595', 'T1046'],
    'identity:ml_risk_spike': ['T1078'],
    'identity:ewma_behavioral_spike': ['T1078'],
    'identity:iso_cross_source_anomaly': ['T1078'],
    # Reconnaissance
    'network:recon': ['T1046'],
    'network:c2_beacon': ['T1071'],
}

STRIDE_TABLE = {
    'ebpf:container_escape': ['Tampering'],
    'ebpf:priv_escalation': ['Elevation of Privilege'],
    'falco_rule:shell_spawn': ['Tampering'],
    'network:port_scan': ['Information Disclosure'],
    'iam:kerberoasting': ['Elevation of Privilege'],
    'iam:rc4_downgrade': ['Elevation of Privilege'],
    'iam:pass_the_hash': ['Spoofing', 'Elevation of Privilege'],
    'iam:pass_the_ticket': ['Spoofing', 'Elevation of Privilege'],
    'iam:golden_ticket': ['Spoofing', 'Elevation of Privilege'],
    'iam:dcsync': ['Information Disclosure'],
    'iam:brute_force': ['Spoofing'],
    'iam:service_principal_credential_add': ['Elevation of Privilege', 'Tampering'],
    'iam:privileged_role_assigned': ['Elevation of Privilege'],
    'iam:mfa_disabled': ['Elevation of Privilege', 'Tampering'],
    'cloud:conditional_access_bypass': ['Elevation of Privilege'],
    'cloud:foreign_asn_signin': ['Spoofing'],
    'endpoint:encoded_powershell': ['Defense Evasion', 'Tampering'],
    'endpoint:lolbin_execution': ['Defense Evasion'],
    'data:large_extract': ['Information Disclosure'],
    'data:external_transfer': ['Exfiltration'],
    'token_reuse_foreign_asn': ['Spoofing'],
    'off_hours_recon_sequence': ['Information Disclosure'],
}

# RULES map enrichment key -> mapping metadata used by explainers
RULES: Dict[str, Dict[str, Any]] = {
    'ebpf:container_escape': {
        'mitre': MITRE_TABLE['ebpf:container_escape'],
        'stride': STRIDE_TABLE.get('ebpf:container_escape', []),
        'dread': {'damage': 0.9, 'exploit': 0.8}
    },
    'ebpf:priv_escalation': {
        'mitre': MITRE_TABLE['ebpf:priv_escalation'],
        'stride': STRIDE_TABLE.get('ebpf:priv_escalation', []),
        'dread': {'damage': 0.8, 'exploit': 0.7}
    },
    'falco_rule:shell_spawn': {
        # include parent technique T1059 in addition to sub-technique T1059.001
        'mitre': ['T1059'] + MITRE_TABLE['falco_rule:shell_spawn'],
        'stride': STRIDE_TABLE.get('falco_rule:shell_spawn', []),
        'dread': {'discover': 0.6}
    },
    'network:port_scan': {
        'mitre': MITRE_TABLE['network:port_scan'],
        'stride': STRIDE_TABLE.get('network:port_scan', []),
        'dread': {'discover': 0.5}
    },
    'lateral:ssh': {
        'mitre': MITRE_TABLE['lateral:ssh'],
        'stride': STRIDE_TABLE.get('lateral:ssh', []),
        'dread': {'damage': 0.6}
    },
    # ── Identity / Credential Access ──────────────────────────────────────────
    'iam:kerberoasting': {
        'mitre': MITRE_TABLE['iam:kerberoasting'],
        'stride': STRIDE_TABLE.get('iam:kerberoasting', []),
        'dread': {'damage': 0.8, 'exploit': 0.7, 'discover': 0.6}
    },
    'iam:rc4_downgrade': {
        'mitre': MITRE_TABLE['iam:rc4_downgrade'],
        'stride': STRIDE_TABLE.get('iam:rc4_downgrade', []),
        'dread': {'damage': 0.7, 'exploit': 0.7}
    },
    'iam:pass_the_hash': {
        'mitre': MITRE_TABLE['iam:pass_the_hash'],
        'stride': STRIDE_TABLE.get('iam:pass_the_hash', []),
        'dread': {'damage': 0.85, 'exploit': 0.75, 'repro': 0.8}
    },
    'iam:pass_the_ticket': {
        'mitre': MITRE_TABLE['iam:pass_the_ticket'],
        'stride': STRIDE_TABLE.get('iam:pass_the_ticket', []),
        'dread': {'damage': 0.85, 'exploit': 0.75}
    },
    'iam:golden_ticket': {
        'mitre': MITRE_TABLE['iam:golden_ticket'],
        'stride': STRIDE_TABLE.get('iam:golden_ticket', []),
        'dread': {'damage': 0.95, 'exploit': 0.7, 'repro': 0.9}
    },
    'iam:silver_ticket': {
        'mitre': MITRE_TABLE['iam:silver_ticket'],
        'stride': STRIDE_TABLE.get('iam:silver_ticket', []),
        'dread': {'damage': 0.8, 'exploit': 0.7}
    },
    'iam:dcsync': {
        'mitre': MITRE_TABLE['iam:dcsync'],
        'stride': STRIDE_TABLE.get('iam:dcsync', []),
        'dread': {'damage': 0.95, 'exploit': 0.8}
    },
    'iam:brute_force': {
        'mitre': MITRE_TABLE['iam:brute_force'],
        'stride': STRIDE_TABLE.get('iam:brute_force', []),
        'dread': {'damage': 0.7, 'exploit': 0.6, 'repro': 0.9}
    },
    'iam:password_spray': {
        'mitre': MITRE_TABLE['iam:password_spray'],
        'stride': STRIDE_TABLE.get('iam:password_spray', []),
        'dread': {'damage': 0.7, 'exploit': 0.7, 'repro': 0.9}
    },
    # ── Identity — Persistence / Privilege Escalation ─────────────────────────
    'iam:service_principal_credential_add': {
        'mitre': MITRE_TABLE['iam:service_principal_credential_add'],
        'stride': STRIDE_TABLE.get('iam:service_principal_credential_add', []),
        'dread': {'damage': 0.85, 'exploit': 0.6, 'repro': 0.8}
    },
    'iam:new_admin_account': {
        'mitre': MITRE_TABLE['iam:new_admin_account'],
        'stride': STRIDE_TABLE.get('iam:new_admin_account', []),
        'dread': {'damage': 0.8, 'exploit': 0.5}
    },
    'iam:privileged_role_assigned': {
        'mitre': MITRE_TABLE['iam:privileged_role_assigned'],
        'stride': STRIDE_TABLE.get('iam:privileged_role_assigned', []),
        'dread': {'damage': 0.8, 'exploit': 0.5}
    },
    'iam:mfa_disabled': {
        'mitre': MITRE_TABLE['iam:mfa_disabled'],
        'stride': STRIDE_TABLE.get('iam:mfa_disabled', []),
        'dread': {'damage': 0.75, 'exploit': 0.8, 'repro': 0.9}
    },
    'iam:oauth_app_consent': {
        'mitre': MITRE_TABLE['iam:oauth_app_consent'],
        'stride': STRIDE_TABLE.get('iam:oauth_app_consent', []),
        'dread': {'damage': 0.75, 'exploit': 0.65}
    },
    # ── Cloud / Azure ─────────────────────────────────────────────────────────
    'cloud:conditional_access_bypass': {
        'mitre': MITRE_TABLE['cloud:conditional_access_bypass'],
        'stride': STRIDE_TABLE.get('cloud:conditional_access_bypass', []),
        'dread': {'damage': 0.8, 'exploit': 0.7}
    },
    'cloud:foreign_asn_signin': {
        'mitre': MITRE_TABLE['cloud:foreign_asn_signin'],
        'stride': STRIDE_TABLE.get('cloud:foreign_asn_signin', []),
        'dread': {'damage': 0.7, 'exploit': 0.5}
    },
    'cloud:global_admin_pim': {
        'mitre': MITRE_TABLE['cloud:global_admin_pim'],
        'stride': [],
        'dread': {'damage': 0.9, 'exploit': 0.5}
    },
    'cloud:sharepoint_lookalike': {
        'mitre': MITRE_TABLE['cloud:sharepoint_lookalike'],
        'stride': [],
        'dread': {'damage': 0.7, 'exploit': 0.7}
    },
    # ── Endpoint / Execution ──────────────────────────────────────────────────
    'endpoint:lolbin_execution': {
        'mitre': MITRE_TABLE['endpoint:lolbin_execution'],
        'stride': STRIDE_TABLE.get('endpoint:lolbin_execution', []),
        'dread': {'damage': 0.7, 'exploit': 0.65}
    },
    'endpoint:encoded_powershell': {
        'mitre': MITRE_TABLE['endpoint:encoded_powershell'],
        'stride': STRIDE_TABLE.get('endpoint:encoded_powershell', []),
        'dread': {'damage': 0.75, 'exploit': 0.7}
    },
    'endpoint:wmi_exec': {
        'mitre': MITRE_TABLE['endpoint:wmi_exec'],
        'stride': [],
        'dread': {'damage': 0.75, 'exploit': 0.7}
    },
    'endpoint:first_seen_host_access': {
        'mitre': MITRE_TABLE['endpoint:first_seen_host_access'],
        'stride': [],
        'dread': {'damage': 0.6, 'exploit': 0.5}
    },
    'endpoint:defense_evasion': {
        'mitre': MITRE_TABLE['endpoint:defense_evasion'],
        'stride': [],
        'dread': {'damage': 0.7, 'exploit': 0.6}
    },
    # ── Data / Exfiltration ───────────────────────────────────────────────────
    'data:large_extract': {
        'mitre': MITRE_TABLE['data:large_extract'],
        'stride': STRIDE_TABLE.get('data:large_extract', []),
        'dread': {'damage': 0.85, 'exploit': 0.6}
    },
    'data:external_transfer': {
        'mitre': MITRE_TABLE['data:external_transfer'],
        'stride': STRIDE_TABLE.get('data:external_transfer', []),
        'dread': {'damage': 0.9, 'exploit': 0.6}
    },
    'data:cumulative_bytes_anomaly': {
        'mitre': MITRE_TABLE['data:cumulative_bytes_anomaly'],
        'stride': STRIDE_TABLE.get('data:cumulative_bytes_anomaly', []),
        'dread': {'damage': 0.8, 'exploit': 0.5}
    },
    # ── Token / OAuth ─────────────────────────────────────────────────────────
    'token_reuse_foreign_asn': {
        'mitre': MITRE_TABLE['token_reuse_foreign_asn'],
        'stride': STRIDE_TABLE.get('token_reuse_foreign_asn', []),
        'dread': {'damage': 0.8, 'exploit': 0.65}
    },
    'token_foreign_signin': {
        'mitre': MITRE_TABLE['token_foreign_signin'],
        'stride': [],
        'dread': {'damage': 0.7, 'exploit': 0.5}
    },
    # ── Behavioral / ML ───────────────────────────────────────────────────────
    'off_hours_recon_sequence': {
        'mitre': MITRE_TABLE['off_hours_recon_sequence'],
        'stride': STRIDE_TABLE.get('off_hours_recon_sequence', []),
        'dread': {'damage': 0.65, 'discover': 0.5}
    },
    'identity:ml_risk_spike': {
        'mitre': MITRE_TABLE['identity:ml_risk_spike'],
        'stride': [],
        'dread': {'damage': 0.7}
    },
    'identity:ewma_behavioral_spike': {
        'mitre': MITRE_TABLE['identity:ewma_behavioral_spike'],
        'stride': [],
        'dread': {'damage': 0.65}
    },
    'identity:iso_cross_source_anomaly': {
        'mitre': MITRE_TABLE['identity:iso_cross_source_anomaly'],
        'stride': [],
        'dread': {'damage': 0.7}
    },
    # ── Network ───────────────────────────────────────────────────────────────
    'network:recon': {
        'mitre': MITRE_TABLE['network:recon'],
        'stride': ['Information Disclosure'],
        'dread': {'discover': 0.6}
    },
    'network:c2_beacon': {
        'mitre': MITRE_TABLE['network:c2_beacon'],
        'stride': ['Tampering'],
        'dread': {'damage': 0.85, 'exploit': 0.7}
    },
}


def map_enrichments(enrichments: Union[List[str], Dict[str, Any]]) -> Dict[str, Any]:
    mitre: List[str] = []
    stride: List[str] = []
    dread = {'damage': 0.0, 'repro': 0.5, 'exploit': 0.5, 'affected': 0.5, 'discover': 0.5}
    details: List[Dict[str, Any]] = []

    # normalize input to dict: key -> observed_value
    items: Dict[str, Any]
    if isinstance(enrichments, list):
        items = {k: True for k in enrichments}
    else:
        items = enrichments or {}

    for k, observed in items.items():
        rule = RULES.get(k)
        if rule:
            mitre += rule.get('mitre', [])
            stride += rule.get('stride', [])
            for dk, dv in rule.get('dread', {}).items():
                dread[dk] = max(dread.get(dk, 0.0), float(dv))
            details.append({'enrichment': k, 'mapped': rule, 'observed': observed})

    return {'mitre': sorted(set(mitre)), 'stride': sorted(set(stride)), 'dread': dread, 'details': details}

