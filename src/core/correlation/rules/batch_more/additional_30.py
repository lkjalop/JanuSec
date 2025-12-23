from typing import Dict, Any
from ..registry import register_rule


# DUPLICATE_DISABLED decorator for rule cred_dump_lsass_trace in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule cred_dump_lsass_trace in src\core\correlation\rules\batch_more\additional_30.py
# @register_rule(name='cred_dump_lsass_trace', mitre=['T1003'], factors_required=['lsass_open','dump_tool_present'], window_seconds=3600, severity='critical', confidence_boost=0.6)
def cred_dump_lsass_trace(event: Dict[str, Any]) -> bool:
    if event.get('lsass_open') and event.get('dump_tool_present'):
        return True
    return False


# DUPLICATE_DISABLED decorator for rule filesystem_encryption_trigger in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule filesystem_encryption_trigger in src\core\correlation\rules\batch_more\additional_30.py
# @register_rule(name='filesystem_encryption_trigger', mitre=['T1486'], factors_required=['file_rename_count','ransom_note_like'], window_seconds=3600, severity='critical', confidence_boost=0.7)
def filesystem_encryption_trigger(event: Dict[str, Any]) -> bool:
    try:
        if int(event.get('file_rename_count',0)) > 100 and event.get('ransom_note_like'):
            return True
    except Exception:
        pass
    return False


# DUPLICATE_DISABLED decorator for rule cloud_role_escalation_from_vm in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule cloud_role_escalation_from_vm in src\core\correlation\rules\batch_more\additional_30.py
# @register_rule(name='cloud_role_escalation_from_vm', mitre=['T1538'], factors_required=['cloud_api_modify_iam','vm_agent_origin'], window_seconds=3600, severity='critical', confidence_boost=0.65)
def cloud_role_escalation_from_vm(event: Dict[str, Any]) -> bool:
    if event.get('cloud_api_modify_iam') and event.get('vm_agent_origin'):
        return True
    return False


# DUPLICATE_DISABLED decorator for rule defense_evasion_amsi_bypass_combo in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule defense_evasion_amsi_bypass_combo in src\core\correlation\rules\batch_more\additional_30.py
# @register_rule(name='defense_evasion_amsi_bypass_combo', mitre=['T1562'], factors_required=['powershell_encoded','amsi_disable_call'], window_seconds=3600, severity='critical', confidence_boost=0.6)
def defense_evasion_amsi_bypass_combo(event: Dict[str, Any]) -> bool:
    if event.get('powershell_encoded') and event.get('amsi_disable_call'):
        return True
    return False


# DUPLICATE_DISABLED decorator for rule c2_http_small_periodic_payload in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule c2_http_small_periodic_payload in src\core\correlation\rules\batch_more\additional_30.py
# @register_rule(name='c2_http_small_periodic_payload', mitre=['T1071.001'], factors_required=['http_post_small','beacon_periodicity'], window_seconds=3600, severity='high', confidence_boost=0.5)
def c2_http_small_periodic_payload(event: Dict[str, Any]) -> bool:
    if event.get('http_post_small') and event.get('beacon_periodicity'):
        return True
    return False


# DUPLICATE_DISABLED decorator for rule c2_ssl_odd_sni_beacon in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule c2_ssl_odd_sni_beacon in src\core\correlation\rules\batch_more\additional_30.py
# @register_rule(name='c2_ssl_odd_sni_beacon', mitre=['T1071.001'], factors_required=['tls_sni_rare','beacon_like_periodicity'], window_seconds=3600, severity='high', confidence_boost=0.5)
def c2_ssl_odd_sni_beacon(event: Dict[str, Any]) -> bool:
    if event.get('tls_sni_rare') and event.get('beacon_like_periodicity'):
        return True
    return False
"""Placeholder rule: additional_30 batch
"""
from typing import Any, Dict

def evaluate_rule(event: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    return {}

__all__ = ["evaluate_rule"]
from ..registry import register_rule

# Batch: 30 additional correlation rules

# DUPLICATE_DISABLED decorator for rule c2_http_small_periodic_payload in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule c2_http_small_periodic_payload in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='c2_http_small_periodic_payload', mitre=['T1071.001'],
               factors_required=['http_post_small','beacon_periodicity','rare_ua'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def c2_http_small_periodic_payload(e):
    return bool(e.get('http_post_small')) and bool(e.get('beacon_periodicity')) and bool(e.get('rare_ua'))


# DUPLICATE_DISABLED decorator for rule c2_ssl_odd_sni_beacon in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule c2_ssl_odd_sni_beacon in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='c2_ssl_odd_sni_beacon', mitre=['T1071.001'],
               factors_required=['tls_sni_rare','tls_issuer_rare','beacon_like_periodicity'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def c2_ssl_odd_sni_beacon(e):
    return bool(e.get('tls_sni_rare')) and bool(e.get('tls_issuer_rare')) and bool(e.get('beacon_like_periodicity'))


# DUPLICATE_DISABLED decorator for rule lateral_smb_admin_burst in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='lateral_smb_admin_burst', mitre=['T1021.002'],
               factors_required=['smb_admin_conn_count','off_hours'],
               window_seconds=1800, severity='high', confidence_boost=0.35)
def lateral_smb_admin_burst(e):
    try:
        return int(e.get('smb_admin_conn_count') or 0) >= 3 and bool(e.get('off_hours'))
    except Exception:
        return False


# DUPLICATE_DISABLED decorator for rule exfil_ftp_large_payload in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='exfil_ftp_large_payload', mitre=['T1041'],
               factors_required=['ftp_upload_bytes','rare_external_host'],
               window_seconds=7200, severity='high', confidence_boost=0.35)
def exfil_ftp_large_payload(e):
    try:
        return bool(e.get('rare_external_host')) and int(e.get('ftp_upload_bytes') or 0) > 1000000
    except Exception:
        return False


# DUPLICATE_DISABLED decorator for rule persistence_service_binary_change in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='persistence_service_binary_change', mitre=['T1547'],
               factors_required=['service_bin_changed','service_path_temp'],
               window_seconds=86400, severity='high', confidence_boost=0.40)
def persistence_service_binary_change(e):
    return bool(e.get('service_bin_changed')) and bool(e.get('service_path_temp'))


# DUPLICATE_DISABLED decorator for rule defense_evasion_amsi_bypass_combo in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule defense_evasion_amsi_bypass_combo in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='defense_evasion_amsi_bypass_combo', mitre=['T1562','T1059'],
               factors_required=['powershell_encoded','amsi_disable_call'],
               window_seconds=1800, severity='high', confidence_boost=0.45)
def defense_evasion_amsi_bypass_combo(e):
    return bool(e.get('powershell_encoded')) and bool(e.get('amsi_disable_call'))


# DUPLICATE_DISABLED decorator for rule discovery_dns_reverse_enum in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='discovery_dns_reverse_enum', mitre=['T1046'],
               factors_required=['dns_ptr_burst','subnet_scan_detected'],
               window_seconds=1200, severity='medium', confidence_boost=0.30)
def discovery_dns_reverse_enum(e):
    try:
        return bool(e.get('dns_ptr_burst')) and bool(e.get('subnet_scan_detected'))
    except Exception:
        return False


# DUPLICATE_DISABLED decorator for rule cred_dump_lsass_trace in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule cred_dump_lsass_trace in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='cred_dump_lsass_trace', mitre=['T1003'],
               factors_required=['lsass_open','dump_tool_present','http_bytes_out'],
               window_seconds=3600, severity='critical', confidence_boost=0.50)
def cred_dump_lsass_trace(e):
    try:
        return bool(e.get('lsass_open')) and bool(e.get('dump_tool_present')) and int(e.get('http_bytes_out') or 0) > 0
    except Exception:
        return False


# DUPLICATE_DISABLED decorator for rule staged_payload_chain in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='staged_payload_chain', mitre=['T1105','T1059'],
               factors_required=['download_stage1','exec_stage2','rare_chain'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def staged_payload_chain(e):
    return bool(e.get('download_stage1')) and bool(e.get('exec_stage2')) and bool(e.get('rare_chain'))


# DUPLICATE_DISABLED decorator for rule script_lateral_execution_by_wmi in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='script_lateral_execution_by_wmi', mitre=['T1047','T1021'],
               factors_required=['wmi_remote_exec','script_child_proc','remote_host_count'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def script_lateral_execution_by_wmi(e):
    try:
        return bool(e.get('wmi_remote_exec')) and bool(e.get('script_child_proc')) and int(e.get('remote_host_count') or 0) >= 2
    except Exception:
        return False


# DUPLICATE_DISABLED decorator for rule impostor_domain_beacon in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='impostor_domain_beacon', mitre=['T1583','T1071'],
               factors_required=['typosquat_domain','net:outbound_ja3_rare'],
               window_seconds=3600, severity='high', confidence_boost=0.38)
def impostor_domain_beacon(e):
    return bool(e.get('typosquat_domain')) and bool(e.get('net:outbound_ja3_rare'))


# DUPLICATE_DISABLED decorator for rule stealth_proc_injection_combo in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='stealth_proc_injection_combo', mitre=['T1055'],
               factors_required=['parent_mismatch','memory_module','suspicious_syscall_seq'],
               window_seconds=3600, severity='high', confidence_boost=0.45)
def stealth_proc_injection_combo(e):
    return bool(e.get('parent_mismatch')) and bool(e.get('memory_module')) and bool(e.get('suspicious_syscall_seq'))


@register_rule(name='exfil_smtp_large_attachment', mitre=['T1041'],
               factors_required=['smtp_attach_size','rare_recipient_domain'],
               window_seconds=7200, severity='medium', confidence_boost=0.30)
def exfil_smtp_large_attachment(e):
    try:
        return bool(e.get('rare_recipient_domain')) and int(e.get('smtp_attach_size') or 0) > 10_000_000
    except Exception:
        return False


# DUPLICATE_DISABLED decorator for rule config_file_tamper in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='config_file_tamper', mitre=['T1490','T1609'],
               factors_required=['config_hash_changed','service_restart_after_change'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def config_file_tamper(e):
    return bool(e.get('config_hash_changed')) and bool(e.get('service_restart_after_change'))


# DUPLICATE_DISABLED decorator for rule lateral_ssh_sweep_internal in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='lateral_ssh_sweep_internal', mitre=['T1021.004'],
               factors_required=['ssh_failed_count','ssh_success_unusual_ip'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def lateral_ssh_sweep_internal(e):
    try:
        return int(e.get('ssh_failed_count') or 0) >= 50 and bool(e.get('ssh_success_unusual_ip'))
    except Exception:
        return False


@register_rule(name='code_signer_spoofed', mitre=['T1553'],
               factors_required=['signed_binary','signer_unusual','hash_mismatch_source'],
               window_seconds=86400, severity='medium', confidence_boost=0.30)
def code_signer_spoofed(e):
    return bool(e.get('signed_binary')) and bool(e.get('signer_unusual')) and bool(e.get('hash_mismatch_source'))


# DUPLICATE_DISABLED decorator for rule filesystem_encryption_trigger in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule filesystem_encryption_trigger in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='filesystem_encryption_trigger', mitre=['T1486'],
               factors_required=['mass_rename_ext','vss_delete','ransom_note_created'],
               window_seconds=3600, severity='critical', confidence_boost=0.50)
def filesystem_encryption_trigger(e):
    try:
        # Strong canonical signal: mass rename + vss delete + ransom note
        if bool(e.get('mass_rename_ext')) and bool(e.get('vss_delete')) and bool(e.get('ransom_note_created')):
            return True
        # Fallback: very high file_rename_count with ransom_note_like
        if int(e.get('file_rename_count') or 0) >= 100 and bool(e.get('ransom_note_like')):
            return True
        # Another fallback: many distinct extensions changed in short window
        if int(e.get('distinct_extensions_changed') or 0) >= 5 and bool(e.get('ransom_note_like')):
            return True
    except Exception:
        pass
    return False


# DUPLICATE_DISABLED decorator for rule cloud_role_escalation_from_vm in src\core\correlation\rules\batch_more\additional_30.py
# DUPLICATE_DISABLED decorator for rule cloud_role_escalation_from_vm in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='cloud_role_escalation_from_vm', mitre=['T1538'],
               factors_required=['cloud_api_modify_iam','vm_agent_origin'],
               window_seconds=3600, severity='critical', confidence_boost=0.45)
def cloud_role_escalation_from_vm(e):
    return bool(e.get('cloud_api_modify_iam')) and bool(e.get('vm_agent_origin'))


@register_rule(name='insider_data_collection_pattern', mitre=['T1039','T1029'],
               factors_required=['sensitive_file_read_count','usb_write','user_activity_change'],
               window_seconds=86400, severity='high', confidence_boost=0.35)
def insider_data_collection_pattern(e):
    try:
        return int(e.get('sensitive_file_read_count') or 0) >= 10 and bool(e.get('usb_write')) and bool(e.get('user_activity_change'))
    except Exception:
        return False


# DUPLICATE_DISABLED decorator for rule supply_chain_downloader in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='supply_chain_downloader', mitre=['T1195'],
               factors_required=['git_clone_runtime','download_exec','nested_child_spawn'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def supply_chain_downloader(e):
    return bool(e.get('git_clone_runtime')) and bool(e.get('download_exec')) and bool(e.get('nested_child_spawn'))


@register_rule(name='lateral_rdp_brute_force_from_cloud', mitre=['T1110','T1021'],
               factors_required=['rdp_failed_count','src_asn_cloud','exposed_rdp_port'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def lateral_rdp_brute_force_from_cloud(e):
    try:
        return int(e.get('rdp_failed_count') or 0) >= 20 and bool(e.get('src_asn_cloud')) and bool(e.get('exposed_rdp_port'))
    except Exception:
        return False


@register_rule(name='exfil_dns_txt_chunks', mitre=['T1071.004'],
               factors_required=['dns_txt_chunk_count','high_entropy_queries'],
               window_seconds=3600, severity='high', confidence_boost=0.45)
def exfil_dns_txt_chunks(e):
    try:
        return int(e.get('dns_txt_chunk_count') or 0) >= 3 and bool(e.get('high_entropy_queries'))
    except Exception:
        return False


@register_rule(name='persistence_scheduled_task_shadowing', mitre=['T1053'],
               factors_required=['scheduled_task_created','lolbin_in_args','task_creator_unusual'],
               window_seconds=86400, severity='medium', confidence_boost=0.30)
def persistence_scheduled_task_shadowing(e):
    return bool(e.get('scheduled_task_created')) and bool(e.get('lolbin_in_args')) and bool(e.get('task_creator_unusual'))


@register_rule(name='lateral_http_proxy_tunnel', mitre=['T1090'],
               factors_required=['host_proxying_detected','multiple_internal_forwarding'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def lateral_http_proxy_tunnel(e):
    return bool(e.get('host_proxying_detected')) and bool(e.get('multiple_internal_forwarding'))


# DUPLICATE_DISABLED decorator for rule exfil_stealth_cloud_metadata in src\core\correlation\rules\batch_more\additional_30.py
@register_rule(name='exfil_stealth_cloud_metadata', mitre=['T1530','T1539'],
               factors_required=['cloud_metadata_access','cloud_api_unusual','http_bytes_out'],
               window_seconds=3600, severity='critical', confidence_boost=0.45)
def exfil_stealth_cloud_metadata(e):
    try:
        return bool(e.get('cloud_metadata_access')) and bool(e.get('cloud_api_unusual')) and int(e.get('http_bytes_out') or 0) > 0
    except Exception:
        return False


@register_rule(name='discovery_ad_credential_dump', mitre=['T1087'],
               factors_required=['ad_group_query_burst','kerberoast_service_ticket_request'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def discovery_ad_credential_dump(e):
    return bool(e.get('ad_group_query_burst')) and bool(e.get('kerberoast_service_ticket_request'))


@register_rule(name='process_hollowing_evidence_combo', mitre=['T1055'],
               factors_required=['suspicious_map_calls','child_thread_unusual'],
               window_seconds=3600, severity='high', confidence_boost=0.45)
def process_hollowing_evidence_combo(e):
    return bool(e.get('suspicious_map_calls')) and bool(e.get('child_thread_unusual'))


@register_rule(name='persistence_registry_run_once_args', mitre=['T1547'],
               factors_required=['registry_run_key_set','run_once_flag','temp_args_pattern'],
               window_seconds=86400, severity='medium', confidence_boost=0.30)
def persistence_registry_run_once_args(e):
    return bool(e.get('registry_run_key_set')) and bool(e.get('run_once_flag')) and bool(e.get('temp_args_pattern'))


@register_rule(name='lateral_smb_grooming_credential_harvest', mitre=['T1003','T1555'],
               factors_required=['smb_file_read_patterns','credential_file_matches'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def lateral_smb_grooming_credential_harvest(e):
    return bool(e.get('smb_file_read_patterns')) and bool(e.get('credential_file_matches'))


@register_rule(name='exfil_multipart_http_chunking', mitre=['T1041'],
               factors_required=['http_chunk_sequence','http_bytes_out','rare_upload_path'],
               window_seconds=7200, severity='high', confidence_boost=0.40)
def exfil_multipart_http_chunking(e):
    try:
        return bool(e.get('http_chunk_sequence')) and int(e.get('http_bytes_out') or 0) > 0 and bool(e.get('rare_upload_path'))
    except Exception:
        return False


# Domain: Exfiltration over HTTPS to rare ASN with large volume
@register_rule(name='exfil_large_https_rare_asn', mitre=['T1041'],
               factors_required=['http_bytes_out','asn_rare'],
               window_seconds=7200, severity='high', confidence_boost=0.40)
def exfil_large_https_rare_asn(e):
    try:
        return bool(e.get('asn_rare')) and int(e.get('http_bytes_out') or 0) > 3_000_000
    except Exception:
        return False


# IAM/Cloud anomaly: service-account policy drift indicative of privilege escalation
@register_rule(name='cloud_service_account_policy_drift', mitre=['T1098','T1538'],
               factors_required=['iam_policy_change','service_account_scope_expand'],
               window_seconds=7200, severity='high', confidence_boost=0.40)
def cloud_service_account_policy_drift(e):
    try:
        drift = bool(e.get('iam_policy_change')) and bool(e.get('service_account_scope_expand'))
        # Optional stronger hint: change initiated from VM agent or unusual actor
        actor_hint = bool(e.get('vm_agent_origin')) or bool(e.get('actor_service_account_unusual'))
        return drift or (drift and actor_hint)
    except Exception:
        return False

# IAM/Cloud anomaly: service-account access key creation (potential credential proliferation)
@register_rule(name='cloud_service_account_key_creation', mitre=['T1098'],
               factors_required=['service_account_key_create'],
               window_seconds=7200, severity='high', confidence_boost=0.40)
def cloud_service_account_key_creation(e):
    try:
        created = bool(e.get('service_account_key_create') or e.get('iam_create_access_key'))
        unusual_actor = bool(e.get('actor_service_account_unusual')) or bool(e.get('vm_agent_origin'))
        org_scope = bool(e.get('organization_wide_role')) or bool(e.get('role_scope_broad'))
        score = 0.0
        if created:
            score += 0.6
        if unusual_actor:
            score += 0.2
        if org_scope:
            score += 0.2
        # Emit enriched mapping for pipeline/report surfaces
        try:
            e.setdefault('correlation_emission', {})
            e['correlation_emission'].update({
                'rule': 'cloud_service_account_key_creation',
                'mitre': ['T1098'],
                'stride': ['Elevation of Privilege','Repudiation'],
                'dread': {'score': 7},
                'maestro': {'tags': ['privilege_escalation','credential_access']},
                'diamond': {'adversary': 'unknown', 'capability': ['account_manipulation']},
                'evidence': {
                    'service_account_key_create': bool(e.get('service_account_key_create') or e.get('iam_create_access_key')),
                    'actor_unusual': bool(e.get('actor_service_account_unusual') or e.get('vm_agent_origin')),
                    'scope_broad': org_scope,
                },
            })
        except Exception:
            pass
        return score >= 0.7
    except Exception:
        return False

# IAM/Cloud anomaly: broad policy attachment to roles (overbroad permissions)
@register_rule(name='cloud_policy_attach_broad_roles', mitre=['T1098'],
               factors_required=['iam_policy_attach','role_scope_broad'],
               window_seconds=7200, severity='critical', confidence_boost=0.45)
def cloud_policy_attach_broad_roles(e):
    try:
        attach = bool(e.get('iam_policy_attach') or e.get('attach_policy'))
        broad = bool(e.get('role_scope_broad') or e.get('organization_wide_role'))
        unusual_actor = bool(e.get('actor_service_account_unusual') or e.get('vm_agent_origin'))
        score = 0.0
        if attach and broad:
            score += 0.75
        if unusual_actor:
            score += 0.15
        try:
            e.setdefault('correlation_emission', {})
            e['correlation_emission'].update({
                'rule': 'cloud_policy_attach_broad_roles',
                'mitre': ['T1098'],
                'stride': ['Elevation of Privilege'],
                'dread': {'score': 8},
                'maestro': {'tags': ['privilege_escalation','policy_drift']},
                'diamond': {'adversary': 'unknown', 'capability': ['permission_escalation']},
                'evidence': {
                    'iam_policy_attach': attach,
                    'role_scope_broad': broad,
                    'actor_unusual': unusual_actor,
                },
            })
        except Exception:
            pass
        return score >= 0.75
    except Exception:
        return False

# IAM/Cloud anomaly: access key rotation anomalies
@register_rule(name='cloud_access_key_rotation_anomaly', mitre=['T1098'],
               factors_required=['iam_create_access_key','key_age_days'],
               window_seconds=7200, severity='high', confidence_boost=0.40)
def cloud_access_key_rotation_anomaly(e):
    try:
        created = bool(e.get('iam_create_access_key') or e.get('service_account_key_create'))
        key_age_days = int(e.get('key_age_days') or 0)
        active_keys = int(e.get('active_key_count') or 1)
        mfa = bool(e.get('mfa_enabled'))
        off_hours = bool(e.get('off_hours'))
        score = 0.0
        if created and key_age_days > 90:
            score += 0.4
        if active_keys >= 2:
            score += 0.2
        if not mfa:
            score += 0.2
        if off_hours:
            score += 0.1
        try:
            e.setdefault('correlation_emission', {})
            e['correlation_emission'].update({
                'rule': 'cloud_access_key_rotation_anomaly',
                'mitre': ['T1098'],
                'stride': ['Elevation of Privilege','Repudiation'],
                'dread': {'score': 6},
                'maestro': {'tags': ['credential_access','key_rotation']},
                'diamond': {'adversary': 'unknown', 'capability': ['account_manipulation']},
                'evidence': {
                    'created': created,
                    'key_age_days': key_age_days,
                    'active_key_count': active_keys,
                    'mfa_enabled': mfa,
                    'off_hours': off_hours,
                },
            })
        except Exception:
            pass
        return score >= 0.6
    except Exception:
        return False

# IAM/Cloud anomaly: org policy attached with wildcard resource
@register_rule(name='cloud_org_policy_attach_wildcard', mitre=['T1098'],
               factors_required=['org_policy_attach','resource_wildcard'],
               window_seconds=7200, severity='critical', confidence_boost=0.45)
def cloud_org_policy_attach_wildcard(e):
    try:
        attach = bool(e.get('org_policy_attach'))
        wildcard = bool(e.get('resource_wildcard')) or (str(e.get('resource') or '') == '*')
        org_wide = bool(e.get('organization_wide_role'))
        score = 0.0
        if attach and wildcard:
            score += 0.8
        if org_wide:
            score += 0.1
        try:
            e.setdefault('correlation_emission', {})
            e['correlation_emission'].update({
                'rule': 'cloud_org_policy_attach_wildcard',
                'mitre': ['T1098'],
                'stride': ['Elevation of Privilege'],
                'dread': {'score': 8},
                'maestro': {'tags': ['privilege_escalation','policy_drift']},
                'diamond': {'adversary': 'unknown', 'capability': ['permission_escalation']},
                'evidence': {
                    'org_policy_attach': attach,
                    'resource_wildcard': wildcard,
                    'organization_wide_role': org_wide,
                }
            })
        except Exception:
            pass
        return score >= 0.8
    except Exception:
        return False

# IAM/Cloud anomaly: access key creation without rotation from cross-account origin
@register_rule(name='cloud_access_key_creation_no_rotation_cross_account', mitre=['T1098'],
               factors_required=['iam_create_access_key','key_age_days','cross_account_origin'],
               window_seconds=7200, severity='critical', confidence_boost=0.5)
def cloud_access_key_creation_no_rotation_cross_account(e):
    try:
        created = bool(e.get('iam_create_access_key') or e.get('eventName') == 'CreateAccessKey' or e.get('service_account_key_create'))
        # Treat missing rotation or very old key age as risky
        key_age_days = e.get('key_age_days')
        no_rotation = (key_age_days is None) or (str(key_age_days).lower() in ('', 'none', 'null'))
        try:
            key_age_days_int = int(key_age_days) if key_age_days is not None else 0
        except Exception:
            key_age_days_int = 0
        stale = key_age_days_int >= 90

        # Cross-account: explicit flag, or actor/target account mismatch, or assumed role from different account
        cross_flag = bool(e.get('cross_account_origin'))
        actor_acct = str(e.get('actor_account_id') or e.get('source_account_id') or '')
        target_acct = str(e.get('target_account_id') or e.get('account_id') or e.get('recipientAccountId') or '')
        assumed_role_acct = str(e.get('assumed_role_account_id') or '')
        cross_by_mismatch = (actor_acct and target_acct and actor_acct != target_acct)
        cross_by_assume = (assumed_role_acct and target_acct and assumed_role_acct != target_acct)
        cross = cross_flag or cross_by_mismatch or cross_by_assume

        # Optional off-hours or unusual network origin boosts
        off_hours = bool(e.get('off_hours'))
        src_asn_cloud = bool(e.get('src_asn_cloud'))

        score = 0.0
        if created and cross and (no_rotation or stale):
            score += 0.75
        if off_hours:
            score += 0.1
        if src_asn_cloud:
            score += 0.05

        try:
            e.setdefault('correlation_emission', {})
            e['correlation_emission'].update({
                'rule': 'cloud_access_key_creation_no_rotation_cross_account',
                'mitre': ['T1098'],
                'stride': ['Elevation of Privilege','Repudiation'],
                'dread': {'score': 8},
                'maestro': {'tags': ['credential_access','account_manipulation']},
                'diamond': {'adversary': 'unknown', 'capability': ['account_manipulation']},
                'evidence': {
                    'created': created,
                    'no_rotation': no_rotation,
                    'key_age_days': key_age_days_int,
                    'cross_account': cross,
                    'actor_account_id': actor_acct,
                    'target_account_id': target_acct,
                    'assumed_role_account_id': assumed_role_acct,
                    'off_hours': off_hours,
                    'src_asn_cloud': src_asn_cloud,
                },
            })
        except Exception:
            pass

        return score >= 0.75
    except Exception:
        return False