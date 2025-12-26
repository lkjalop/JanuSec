from __future__ import annotations

from typing import Any, Dict, List, Set

# Static mapping (expand later)
FACTOR_TO_MITRE = {
    'lolbin_misuse': ['T1218'],
    'tunneling_utility': ['T1572'],
    'macro_autoexec': ['T1059','T1566.001'],
    'macro_obfuscated': ['T1027'],
    'pdf_embedded_js': ['T1059.007'],
    'script_encoded_block': ['T1027.010','T1059'],
    'script_obfuscation_high': ['T1027'],
    'fresh_download': ['T1105'],
    'persistence_registry': ['T1060','T1547'],
    'scheduled_task_hidden': ['T1053.005'],
    'wmi_persistence_consumer': ['T1546.003'],
    'malicious_neighbor': ['T1059'],
    'cluster_malicious_density_high': ['T1082'],
    'rapid_multi_host_appearance': ['T1078'],
    'unsigned_binary': ['T1036'],
    'high_entropy_section': ['T1027'],
    'compile_time_recent': ['T1027'],
    # Enriched exploitability
    'exploit:kev': ['T1190', 'T1210']
    ,
    # Reconnaissance: Active Scanning
    # Horizontal scans across many hosts on a given port map to IP block scanning
    'net:possible_portscan_horizontal': ['T1595','T1595.001','T1046'],
    # Vertical scans of many ports on a single host map to active/vulnerability scanning
    'net:possible_portscan_vertical': ['T1595','T1595.002','T1046']
    ,
    # Expanded Reconnaissance families
    'recon:network_info': ['T1590'],
    'recon:bgp_asn_query': ['T1590','T1593'],
    'recon:dns_enumeration': ['T1590','T1596'],
    'recon:host_info': ['T1592'],
    'recon:service_banner_grab': ['T1592'],
    'recon:org_info': ['T1591'],
    'recon:public_docs_scrape': ['T1591'],
    'recon:tech_db_lookup': ['T1593'],
    'recon:shodan_censys': ['T1593','T1596'],
    'recon:victim_site_probe': ['T1594'],
    'recon:open_web_search': ['T1596'],
    'recon:whois_query': ['T1596'],
    'recon:social_media_profile': ['T1597']
}

FACTOR_TO_STRIDE = {
    'lolbin_misuse': ['Tampering','Elevation'],
    'tunneling_utility': ['Information Disclosure','Repudiation'],
    'macro_autoexec': ['Elevation'],
    'script_encoded_block': ['Tampering'],
    'script_obfuscation_high': ['Tampering'],
    'persistence_registry': ['Tampering','Elevation'],
    'scheduled_task_hidden': ['Elevation'],
    'wmi_persistence_consumer': ['Elevation','Tampering'],
    'fresh_download': ['Spoofing'],
    'rapid_multi_host_appearance': ['Elevation'],
    'malicious_neighbor': ['Elevation'],
    # Reconnaissance generally exposes information about the environment
    'net:possible_portscan_horizontal': ['Information Disclosure'],
    'net:possible_portscan_vertical': ['Information Disclosure'],
    # Recon generally exposes victim information across domains
    'recon:network_info': ['Information Disclosure'],
    'recon:bgp_asn_query': ['Information Disclosure'],
    'recon:dns_enumeration': ['Information Disclosure'],
    'recon:host_info': ['Information Disclosure'],
    'recon:service_banner_grab': ['Information Disclosure'],
    'recon:org_info': ['Information Disclosure'],
    'recon:public_docs_scrape': ['Information Disclosure'],
    'recon:tech_db_lookup': ['Information Disclosure'],
    'recon:shodan_censys': ['Information Disclosure'],
    'recon:victim_site_probe': ['Information Disclosure'],
    'recon:open_web_search': ['Information Disclosure'],
    'recon:whois_query': ['Information Disclosure'],
    'recon:social_media_profile': ['Information Disclosure'],
}

# Placeholder CVE patterns (expand with signature heuristics later)
FACTOR_TO_CVE_HINT = {
    'high_entropy_section': ['POTENTIAL_PACKED'],
    'script_obfuscation_high': ['POTENTIAL_OBF_CHAIN']
}

def apply_mapping(factors: list[str]) -> dict[str, Any]:
    mitre: set[str] = set()
    stride: set[str] = set()
    cves: set[str] = set()
    for f in factors:
        for t in FACTOR_TO_MITRE.get(f, []):
            mitre.add(t)
        for s in FACTOR_TO_STRIDE.get(f, []):
            stride.add(s)
        for c in FACTOR_TO_CVE_HINT.get(f, []):
            cves.add(c)
    return {
        'mitre': sorted(mitre),
        'stride': sorted(stride),
        'cve_hints': sorted(cves)
    }
