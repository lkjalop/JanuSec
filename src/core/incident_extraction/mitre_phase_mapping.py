"""MITRE ATT&CK technique → kill-chain phase mapping."""

MITRE_TO_KILLCHAIN_PHASE: dict[str, str] = {
    'T1595': 'reconnaissance', 'T1589': 'reconnaissance',
    'T1590': 'reconnaissance', 'T1591': 'reconnaissance', 'T1592': 'reconnaissance',
    'T1583': 'resource_development', 'T1586': 'resource_development',
    'T1587': 'resource_development',
    'T1566': 'initial_access', 'T1566.001': 'initial_access',
    'T1566.002': 'initial_access', 'T1189': 'initial_access',
    'T1190': 'initial_access', 'T1195': 'initial_access',
    'T1195.001': 'initial_access', 'T1195.002': 'initial_access',
    'T1199': 'initial_access', 'T1078': 'initial_access',
    'T1078.001': 'initial_access', 'T1078.003': 'initial_access',
    'T1078.004': 'initial_access', 'T1133': 'initial_access',
    'T1059': 'execution', 'T1059.001': 'execution', 'T1059.003': 'execution',
    'T1059.006': 'execution', 'T1059.007': 'execution',
    'T1204': 'execution', 'T1204.001': 'execution', 'T1204.002': 'execution',
    'T1053': 'execution',
    'T1547': 'persistence', 'T1136': 'persistence', 'T1098': 'persistence',
    'T1098.001': 'persistence', 'T1114.003': 'persistence',
    'T1556': 'persistence', 'T1556.006': 'persistence',
    'T1068': 'privilege_escalation', 'T1484': 'privilege_escalation',
    'T1070': 'defense_evasion', 'T1027': 'defense_evasion', 'T1620': 'defense_evasion',
    'T1110': 'credential_access', 'T1110.003': 'credential_access',
    'T1110.004': 'credential_access', 'T1621': 'credential_access',
    'T1003': 'credential_access', 'T1555': 'credential_access', 'T1539': 'credential_access',
    'T1087': 'discovery', 'T1018': 'discovery', 'T1046': 'discovery', 'T1016': 'discovery',
    'T1021': 'lateral_movement', 'T1021.001': 'lateral_movement',
    'T1021.004': 'lateral_movement', 'T1570': 'lateral_movement',
    'T1534': 'lateral_movement',
    'T1005': 'collection', 'T1114': 'collection', 'T1114.001': 'collection',
    'T1114.002': 'collection', 'T1560': 'collection',
    'T1071': 'command_and_control', 'T1071.001': 'command_and_control',
    'T1071.004': 'command_and_control', 'T1573': 'command_and_control',
    'T1105': 'command_and_control', 'T1599': 'command_and_control',
    'T1041': 'exfiltration', 'T1048': 'exfiltration', 'T1048.003': 'exfiltration',
    'T1567': 'exfiltration', 'T1567.002': 'exfiltration',
    'T1486': 'impact', 'T1490': 'impact', 'T1565': 'impact', 'T1657': 'impact',
}

KILLCHAIN_PHASE_ORDER: list[str] = [
    'reconnaissance', 'resource_development', 'initial_access', 'execution',
    'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
    'discovery', 'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact',
]


def technique_to_phase(technique: str) -> str:
    if technique in MITRE_TO_KILLCHAIN_PHASE:
        return MITRE_TO_KILLCHAIN_PHASE[technique]
    if '.' in technique:
        parent = technique.split('.')[0]
        return MITRE_TO_KILLCHAIN_PHASE.get(parent, 'unknown')
    return 'unknown'
