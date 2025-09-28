from __future__ import annotations
from typing import List, Dict, Any, Set

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
    'compile_time_recent': ['T1027']
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
}

# Placeholder CVE patterns (expand with signature heuristics later)
FACTOR_TO_CVE_HINT = {
    'high_entropy_section': ['POTENTIAL_PACKED'],
    'script_obfuscation_high': ['POTENTIAL_OBF_CHAIN']
}

def apply_mapping(factors: List[str]) -> Dict[str, Any]:
    mitre: Set[str] = set()
    stride: Set[str] = set()
    cves: Set[str] = set()
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
