"""Minimal kill chain reconstruction using factor names -> stages mapping."""
from typing import List, Dict, Any
import math

try:
    from src.core.threat_modeling.factor_taxonomy import aggregate_threat_model  # type: ignore
except Exception:  # pragma: no cover
    aggregate_threat_model = None  # type: ignore

FACTOR_STAGE_MAP: Dict[str, str] = {
    # Delivery
    'suspicious_sender_domain': 'Delivery', 'attachment_macro': 'Delivery', 'url_shortener_risk': 'Delivery',
    # Exploitation
    'lateral_move_edge_sequence': 'Exploitation', 'dns_nxdomain_spike': 'Recon',
    'privilege_escalation': 'Exploitation', 'vpn_bruteforce_pattern': 'Recon', 'impossible_travel_login': 'Recon',
    'role_chaining_spike': 'Exploitation', 'mfa_disabled': 'Exploitation',
    # Installation
    'loads_hash_gt_sequence': 'Installation',
    # C2
    'anomalous_tls_ja3': 'C2',
    # Actions
    'mailbox_forward_rule_added': 'Actions', 'outbound_volume_spike': 'Actions', 'mass_download_pattern': 'Actions',
    'living_off_the_land_tool_use': 'Installation', 'unsigned_binary_exec_high_freq': 'Installation',
    'unusual_parent_process': 'Exploitation', 'large_email_attachment_exfil': 'Actions',
    'staging_directory_population': 'Installation', 'multi_stage_escalation_chain': 'Actions',
    'persistence_registry_change': 'Installation', 'new_autorun_entry': 'Installation',
    'beaconing_interval_regular': 'C2', 'sudden_c2_domain_contact': 'C2',
    'inactive_role_reactivation': 'Exploitation', 'compression_before_transfer': 'Actions',
    'auth_token_reuse_across_ips': 'Exploitation', 'data_staging_then_exfil': 'Actions',
    'data_staging_phase': 'Preparation', 'exfil_after_staging': 'Actions'
}

# AI domain factors mapping to generic stages
# - prompt_injection: often part of Delivery/Reconaissance via social/prompt manipulation; map to 'Delivery'
# - tool_abuse: misuse of tools/plugins post initial access; map to 'Installation'
# - sensitive_output_leak: data leakage; map to 'Actions'
# - model_evasion_adversarial: evasion attempts; map to 'Exploitation'
# - training_data_poisoning: pre-attack/prepare stage; map to 'Preparation'
FACTOR_STAGE_MAP.update({
    'prompt_injection': 'Delivery',
    'tool_abuse': 'Installation',
    'sensitive_output_leak': 'Actions',
    'model_evasion_adversarial': 'Exploitation',
    'training_data_poisoning': 'Preparation',
})

STAGE_ALIAS_MAP = {
    'recon': 'Recon',
    'weaponization': 'Weaponization',
    'delivery': 'Delivery',
    'initial_access': 'Delivery',
    'execution': 'Exploitation',
    'privilege_escalation': 'Exploitation',
    'lateral_movement': 'Exploitation',
    'persistence': 'Installation',
    'installation': 'Installation',
    'command_and_control': 'C2',
    'exfiltration': 'Actions',
    'collection': 'Actions',
    'actions_on_objectives': 'Actions',
}

FACTOR_STAGE_MAP.update({
    # Recon coverage
    'port_scan_horizontal': 'Recon',
    'port_scan_vertical': 'Recon',
    'dns_recon_spike': 'Recon',
    'network:port_scan_horizontal': 'Recon',
    'network:port_scan_vertical': 'Recon',
    'network:dns_recon_spike': 'Recon',
    # Weaponization / staging
    'sandbox:malicious': 'Weaponization',
    'yara:match': 'Weaponization',
    'threat_intel_hit': 'Weaponization',
    'intel:domain_hit': 'Weaponization',
    'intel:url_hit': 'Weaponization',
    'intel:ip_hit': 'Weaponization',
    'intel:hash_hit': 'Weaponization',
    'supply_chain:typosquat': 'Weaponization',
    'supply_chain:checksum_invalid': 'Weaponization',
})


def _normalize_factor_name(name: str) -> List[str]:
    if not name:
        return []
    parts = [name]
    if ':' in name:
        parts.append(name.split(':', 1)[1])
    return parts


def _stage_from_factor(f: Dict[str, Any]) -> str | None:
    name = str(f.get('name') or f.get('factor') or '')
    for cand in _normalize_factor_name(name):
        stage = FACTOR_STAGE_MAP.get(cand)
        if stage:
            return stage
    # Allow explicit stage hints on factor payload
    for key in ('kill_chain', 'kill_chain_phase', 'stage'):
        if f.get(key):
            stage = STAGE_ALIAS_MAP.get(str(f.get(key)).lower())
            if stage:
                return stage
    # Use taxonomy mapping when available
    if aggregate_threat_model and name:
        try:
            agg = aggregate_threat_model([name])
            phases = [p for p, _cnt in (agg.get('maestro', {}).get('phases') or []) if isinstance(p, str)]
            for ph in phases:
                stage = STAGE_ALIAS_MAP.get(ph.lower())
                if stage:
                    return stage
        except Exception:
            pass
    return None


def reconstruct_kill_chain(factors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Group factors by stage preserving chronological order
    counts: Dict[str, int] = {}
    for f in factors:
        name = str(f.get('name') or f.get('factor') or '')
        if name:
            counts[name] = counts.get(name, 0) + 1
    stage_entries: Dict[str, Dict[str, Any]] = {}
    ordered: List[Dict[str, Any]] = []
    for f in sorted(factors, key=lambda x: x.get('ts', 0)):
        name = f.get('name') or f.get('factor')
        stage = _stage_from_factor(f)
        if not stage:
            continue
        base_conf = float(f.get('confidence', 0.5))
        count = counts.get(str(name), 1)
        # Diminishing returns for repeated identical factors in a batch
        eff_conf = base_conf / math.sqrt(count) if count > 1 else base_conf
        ent = stage_entries.get(stage)
        if ent is None:
            ent = {'stage': stage, 'start_ts': f.get('ts'), 'end_ts': f.get('ts'), 'factors': [name], 'confidence': eff_conf}
            stage_entries[stage] = ent
            ordered.append(ent)
        else:
            ent['factors'].append(name)
            ent['end_ts'] = f.get('ts')
            ent['confidence'] = max(ent['confidence'], eff_conf)
    return ordered
