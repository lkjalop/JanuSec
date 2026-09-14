"""Mapping scaffolds for MITRE, DREAD heuristic weights, CVSS hints."""
from typing import Dict, Any, List

MITRE_MAP: Dict[str, List[str]] = {
    'suspicious_sender_domain': ['T1566'],
    'attachment_macro': ['T1566.001','T1204'],
    'dns_nxdomain_spike': ['T1595'],
    'lateral_move_edge_sequence': ['T1021'],
    'privilege_escalation': ['T1068'],
    'outbound_volume_spike': ['T1041'],
    'mass_download_pattern': ['T1074'],
    'living_off_the_land_tool_use': ['T1085','T1059'],
    'vpn_bruteforce_pattern': ['T1110'],
    'persistence_registry_change': ['T1060','T1547'],
    'new_autorun_entry': ['T1060'],
    'beaconing_interval_regular': ['T1071','T1008'],
    'sudden_c2_domain_contact': ['T1071'],
    'inactive_role_reactivation': ['T1098'],
    'compression_before_transfer': ['T1560','T1041'],
    'auth_token_reuse_across_ips': ['T1550'],
    'data_staging_then_exfil': ['T1074','T1041'],
    'data_staging_phase': ['T1074'],
    'exfil_after_staging': ['T1041']
}

DREAD_WEIGHTS: Dict[str, Dict[str, float]] = {
    'suspicious_sender_domain': {'D':0.4,'R':0.5,'E':0.3,'A':0.2,'Dscr':0.6},
    'privilege_escalation': {'D':0.8,'R':0.5,'E':0.7,'A':0.6,'Dscr':0.7},
    'outbound_volume_spike': {'D':0.9,'R':0.4,'E':0.5,'A':0.7,'Dscr':0.5},
    'persistence_registry_change': {'D':0.7,'R':0.5,'E':0.6,'A':0.6,'Dscr':0.6},
    'new_autorun_entry': {'D':0.65,'R':0.45,'E':0.55,'A':0.55,'Dscr':0.55},
    'beaconing_interval_regular': {'D':0.75,'R':0.5,'E':0.6,'A':0.4,'Dscr':0.6},
    'sudden_c2_domain_contact': {'D':0.8,'R':0.55,'E':0.6,'A':0.45,'Dscr':0.65},
    'inactive_role_reactivation': {'D':0.6,'R':0.5,'E':0.55,'A':0.5,'Dscr':0.5},
    'compression_before_transfer': {'D':0.7,'R':0.45,'E':0.5,'A':0.65,'Dscr':0.55},
    'auth_token_reuse_across_ips': {'D':0.75,'R':0.5,'E':0.6,'A':0.55,'Dscr':0.6},
    'data_staging_then_exfil': {'D':0.85,'R':0.5,'E':0.55,'A':0.7,'Dscr':0.6},
    'data_staging_phase': {'D':0.5,'R':0.4,'E':0.45,'A':0.35,'Dscr':0.5},
    'exfil_after_staging': {'D':0.85,'R':0.5,'E':0.55,'A':0.7,'Dscr':0.6}
}

CVSS_HINTS: Dict[str, str] = {
    'privilege_escalation': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L',
    'outbound_volume_spike': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:M/A:L',
    'persistence_registry_change': 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:M',
    'new_autorun_entry': 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:M/I:M/A:M',
    'beaconing_interval_regular': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:L/A:L',
    'sudden_c2_domain_contact': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:M/A:M',
    'compression_before_transfer': 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L',
    'auth_token_reuse_across_ips': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:M',
    'data_staging_then_exfil': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L',
    'exfil_after_staging': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:M/A:M'
}

def build_explanations(factors: List[Dict[str, Any]], kill_chain: List[Dict[str, Any]]) -> Dict[str, Any]:
    mitre = []
    dread_scores = {}
    cvss = []
    for f in factors:
        name = f.get('name')
        if not name:
            continue
        if name in MITRE_MAP:
            mitre.append({'factor': name, 'techniques': MITRE_MAP[name]})
        if name in DREAD_WEIGHTS:
            w = DREAD_WEIGHTS[name]
            dread_scores[name] = sum(w.values())/len(w.values())
        if name in CVSS_HINTS:
            cvss.append({'factor': name, 'vector': CVSS_HINTS[name]})
    return {
        'mitre_techniques': mitre,
        'dread_scores': dread_scores,
        'cvss_vectors': cvss,
        'kill_chain_summary': [k['stage'] for k in kill_chain]
    }
