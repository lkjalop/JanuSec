"""Placeholder rule: expanded_batch (weekX)
"""
from typing import Any, Dict

def evaluate_rule(event: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    return {}

__all__ = ["evaluate_rule"]
"""Batch 1 expanded correlation rules (Initial Access, Execution, Persistence,
Lateral Movement, Credential Access, Discovery).

These rules are conservative canaries. Factors listed in factors_required are
either existing event fields OR planned factor keys expected to appear via
enrichment/normalization. Tests use synthetic vectors supplying minimal fields.
"""
from ..registry import register_rule
from ..helpers.normalization import (
    has_proc_substr,
    domain_is_rare,
    cmdline_or_nested_has_http,
    get_http_bytes_out,
    normalize_service_stop_edr,
    get_cmdline,
)


def _normalize_legacy_service_event(e):
    """Compatibility shim: map legacy service stop events to normalized factors.

    If event uses `action: 'service_stop'` with a `service_name` that looks
    like a security/EDR product, set `service_stop_edr` and `admin_context_change`.
    """
    try:
        if not isinstance(e, dict):
            return
        act = str(e.get('action') or '').lower()
        svc = str(e.get('service_name') or '').lower()
        # also consider display name and binary fields
        svc_disp = str(e.get('service_display_name') or '').lower()
        svc_bin = str(e.get('service_binary') or '').lower()
        if act == 'service_stop' and svc:
            edr_indicators = (
                'defend', 'defender', 'windowsdefender', 'microsoft defender',
                'crowdstrike', 'carbon', 'mcafee', 'symantec', 'trend', 'sophos',
                'sentinel', 'sentinelone', 'carbonblack', 'tanium', 'osquery'
            )
            combined = ' '.join((svc, svc_disp, svc_bin))
            if any(tok in combined for tok in edr_indicators):
                e.setdefault('service_stop_edr', True)
                e.setdefault('admin_context_change', True)
    except Exception:
        pass

# ---------------- Initial Access ----------------

@register_rule(name='ia_html_smuggling', mitre=['T1204.002'],
               factors_required=['http:content_disposition_attachment','download_exe_temp','rare_domain'],
               window_seconds=1800, severity='high', confidence_boost=0.30)
def ia_html_smuggling(e):
    return bool(e.get('http:content_disposition_attachment')) and bool(e.get('download_exe_temp')) and bool(e.get('rare_domain'))


@register_rule(name='ia_zip_js_chain', mitre=['T1204'],
               factors_required=['archive_extract','js_exec_from_archive','lolbin_wscript_or_mshta'],
               window_seconds=1800, severity='high', confidence_boost=0.30)
def ia_zip_js_chain(e):
    return all(e.get(k) for k in ('archive_extract','js_exec_from_archive','lolbin_wscript_or_mshta'))


@register_rule(name='ia_lnk_lolbin', mitre=['T1204'],
               factors_required=['lnk_open','lolbin_child_spawn','downloads_path_exec'],
               window_seconds=1800, severity='medium', confidence_boost=0.25)
def ia_lnk_lolbin(e):
    return all(e.get(k) for k in ('lnk_open','lolbin_child_spawn','downloads_path_exec'))


@register_rule(name='ia_iso_mount_exec', mitre=['T1204'],
               factors_required=['iso_mount','proc_exec_from_iso'],
               window_seconds=1800, severity='medium', confidence_boost=0.25)
def ia_iso_mount_exec(e):
    return bool(e.get('iso_mount')) and bool(e.get('proc_exec_from_iso'))

# ---------------- Execution ----------------

@register_rule(name='exec_mshta_remote', mitre=['T1218.005'],
               factors_required=['proc_name','command_line','rare_domain'],
               window_seconds=1800, severity='high', confidence_boost=0.30)
def exec_mshta_remote(e):
    # Require mshta presence and rare domain, then http in cmdline/nested or top-level url/encoded block
    if not has_proc_substr(e, 'mshta'):
        return False
    rare = domain_is_rare(e)
    if not rare:
        return False
    if cmdline_or_nested_has_http(e):
        return True
    if any(k in e for k in ('url', 'encoded_block')):
        return True
    return False


@register_rule(name='exec_rundll32_suspicious', mitre=['T1218.011'],
               factors_required=['proc_name','command_line'],
               window_seconds=1800, severity='high', confidence_boost=0.30)
def exec_rundll32_suspicious(e):
    cl = get_cmdline(e).lower()
    return has_proc_substr(e, 'rundll32') and ('url.dll' in cl or 'javascript:' in cl)


@register_rule(name='exec_oab_formshell', mitre=['T1059.003'],
               factors_required=['parent_process','child_process'],
               window_seconds=1800, severity='high', confidence_boost=0.30)
def exec_oab_formshell(e):
    parent = str(e.get('parent_process') or '').lower()
    child = str(e.get('child_process') or '').lower()
    return 'outlook' in parent and ('powershell' in child or 'pwsh' in child)

# ---------------- Persistence ----------------

@register_rule(name='pers_registry_run_key_nonstd', mitre=['T1547.001'],
               factors_required=['registry_run_key_set','temp_path_exe'],
               window_seconds=86400, severity='high', confidence_boost=0.30)
def pers_registry_run_key_nonstd(e):
    return bool(e.get('registry_run_key_set')) and bool(e.get('temp_path_exe'))


@register_rule(name='pers_startup_folder_drop', mitre=['T1547.009'],
               factors_required=['startup_folder_write','subsequent_exec'],
               window_seconds=86400, severity='medium', confidence_boost=0.25)
def pers_startup_folder_drop(e):
    return bool(e.get('startup_folder_write')) and bool(e.get('subsequent_exec'))

# ---------------- Lateral Movement ----------------

@register_rule(name='lm_rdp_fanout', mitre=['T1021.001'],
               factors_required=['net:rdp_connection_count','off_hours'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def lm_rdp_fanout(e):
    try:
        return int(e.get('net:rdp_connection_count') or 0) >= 3 and bool(e.get('off_hours'))
    except Exception:
        return False

# ---------------- Credential Access ----------------

# DUPLICATE_DISABLED decorator for rule ca_lsass_access_seq in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='ca_lsass_access_seq', mitre=['T1003.001'],
               factors_required=['lsass_handle_open','dump_file_created','hash_tool_present'],
               window_seconds=3600, severity='critical', confidence_boost=0.40)
def ca_lsass_access_seq(e):
    # Normalize legacy 'sequence' style payloads into flags for easier matching
    try:
        if isinstance(e.get('sequence'), int) and e.get('sequence') >= 2:
            steps = e.get('steps') or []
            saw_open = any((s.get('target_process','').lower().endswith('lsass.exe') and 'open' in (s.get('action','') or '').lower()) for s in steps)
            saw_write = any((s.get('file_path','').lower().endswith('.dmp') or 'dump' in (s.get('action','') or '').lower()) for s in steps)
            if saw_open and saw_write:
                e.setdefault('lsass_handle_open', True)
                e.setdefault('dump_file_created', True)
                e.setdefault('hash_tool_present', e.get('hash_tool_present', True))
    except Exception:
        pass
    # Primary detection: direct LSASS handle open + dump + hashing tool present
    try:
        primary = all(e.get(k) for k in ('lsass_handle_open','dump_file_created','hash_tool_present'))
    except Exception:
        primary = False
    # Fallback: process_chain including lsass and explicit read_memory action or cred-dump tool present
    try:
        chain = e.get('process_chain') or []
        if isinstance(chain, str):
            chain = [chain]
        chain_has_lsass = any('lsass' in (str(p).lower()) for p in chain)
        fallback = chain_has_lsass and (e.get('action') == 'read_memory' or bool(e.get('cred_dump_tool')) or bool(e.get('dump_file_created')))
    except Exception:
        fallback = False
    return primary or fallback

# ---------------- Discovery ----------------

@register_rule(name='disc_net_enum_burst', mitre=['T1046'],
               factors_required=['net:portscan_hosts','internal_only'],
               window_seconds=1200, severity='medium', confidence_boost=0.25)
def disc_net_enum_burst(e):
    try:
        return int(e.get('net:portscan_hosts') or 0) >= 10 and bool(e.get('internal_only'))
    except Exception:
        return False

# ---------------- Defense Evasion ----------------

@register_rule(name='de_disable_av', mitre=['T1562.001'],
               factors_required=['defender_exclusions_set','event_log_clear'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def de_disable_av(e):
    return bool(e.get('defender_exclusions_set')) and bool(e.get('event_log_clear'))


@register_rule(name='de_timestomp', mitre=['T1070.006'],
               factors_required=['file_timestomp_detected'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def de_timestomp(e):
    return bool(e.get('file_timestomp_detected'))


@register_rule(name='de_sideload_dll', mitre=['T1574.002'],
               factors_required=['dll_next_to_signed_exe','immediate_load'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def de_sideload_dll(e):
    return bool(e.get('dll_next_to_signed_exe')) and bool(e.get('immediate_load'))


@register_rule(name='de_process_hollowing_hint', mitre=['T1055.012'],
               factors_required=['parent_mismatch','memory_only_module','net:beacon_periodic'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def de_process_hollowing_hint(e):
    return bool(e.get('parent_mismatch')) and bool(e.get('memory_only_module')) and bool(e.get('net:beacon_periodic'))


@register_rule(name='de_signed_binary_proxy', mitre=['T1218'],
               factors_required=['signed_parent','unsanctioned_child','rare_pairing'],
               window_seconds=3600, severity='high', confidence_boost=0.30)
def de_signed_binary_proxy(e):
    return bool(e.get('signed_parent')) and bool(e.get('unsanctioned_child')) and bool(e.get('rare_pairing'))

# ---------------- Privilege Escalation ----------------

# DUPLICATE_DISABLED decorator for rule pe_token_theft_combo in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='pe_token_theft_combo', mitre=['T1134'],
               factors_required=['se_debug_adjust','lsass_openprocess'],
               window_seconds=3600, severity='critical', confidence_boost=0.45)
def pe_token_theft_combo(e):
    """Detect token theft via LSASS access or suspicious impersonation chains."""
    # Strong signal: SE_DEBUG + LSASS open syscall
    has_debug_lsass = bool(e.get('se_debug_adjust')) and bool(e.get('lsass_openprocess'))
    # Auto-audit feeds may only provide token duplication + impersonation context.
    token_dup = bool(e.get('token_duplication') or e.get('token_duplicate') or e.get('token_theft'))
    chain = e.get('impersonation_chain') or []
    if isinstance(chain, str):
        chain = [chain]
    # If chain entries are dicts, extract process names
    try:
        norm_chain = []
        for item in chain:
            if isinstance(item, dict):
                norm_chain.append(item.get('process') or item.get('proc') or item.get('name'))
            else:
                norm_chain.append(item)
        chain = [str(x).lower() for x in norm_chain if x]
    except Exception:
        chain = [str(x).lower() for x in chain if x]
    impersonation_hint = bool(e.get('impersonation')) or bool(chain)
    process_name = str(e.get('process_name') or e.get('process') or '').lower()
    non_system_proc = process_name and process_name not in ('system', 'lsass.exe', 'wininit.exe')
    # Accept shorter chains when strong LSASS evidence exists
    chain_len_ok = len(chain) >= 2 or (len(chain) == 1 and token_dup)
    # Accept if token duplication + impersonation context + lsass indicators
    fallback_combo = token_dup and impersonation_hint and non_system_proc and chain_len_ok
    # Also accept if explicit indicators present (lsass_handle_open/dump_file_created)
    explicit_lsass = bool(e.get('lsass_handle_open')) or bool(e.get('dump_file_created')) or bool(e.get('lsass_openprocess'))
    # Conservative fallback: token duplication + any impersonation hint + non-system process
    fallback_combo = token_dup and impersonation_hint and non_system_proc and len(chain) >= 1
    # Stronger fallback: impersonation chain of length >=2 or explicit duplicate token + lsass access
    strong_combo = (token_dup and len(chain) >= 2) or (token_dup and bool(e.get('lsass_openprocess')))
    return has_debug_lsass or strong_combo or fallback_combo


# Note: 'cred_dump_lsass_trace' canonical implementation lives in
# src/core/correlation/rules/batch_more/additional_30.py to avoid duplicates.


# DUPLICATE_DISABLED decorator for rule pe_uac_bypass_fodhelper in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='pe_uac_bypass_fodhelper', mitre=['T1548.002'],
               factors_required=['registry_hijack_fodhelper','fodhelper_exec'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def pe_uac_bypass_fodhelper(e):
    return bool(e.get('registry_hijack_fodhelper')) and bool(e.get('fodhelper_exec'))


# DUPLICATE_DISABLED decorator for rule pe_namedpipe_impersonation in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='pe_namedpipe_impersonation', mitre=['T1134.001'],
               factors_required=['named_pipe_suspicious','admin_context_change'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def pe_namedpipe_impersonation(e):
    return bool(e.get('named_pipe_suspicious')) and bool(e.get('admin_context_change'))


# DUPLICATE_DISABLED decorator for rule pe_service_binpath_space in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='pe_service_binpath_space', mitre=['T1574.009'],
               factors_required=['service_unquoted_path','child_started_from_mid_path'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def pe_service_binpath_space(e):
    return bool(e.get('service_unquoted_path')) and bool(e.get('child_started_from_mid_path'))


# DUPLICATE_DISABLED decorator for rule pe_lolbin_msi_silent_elevated in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='pe_lolbin_msi_silent_elevated', mitre=['T1218.007'],
               factors_required=['msiexec_no_ui','parent_office_app'],
               window_seconds=3600, severity='high', confidence_boost=0.35)
def pe_lolbin_msi_silent_elevated(e):
    return bool(e.get('msiexec_no_ui')) and bool(e.get('parent_office_app'))

# ---------------- Exfiltration / Impact ----------------

# DUPLICATE_DISABLED decorator for rule exfil_cloud_storage_new in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='exfil_cloud_storage_new', mitre=['T1567'],
               factors_required=['cloud_api_calls_new','http_bytes_out'],
               window_seconds=7200, severity='high', confidence_boost=0.35)
def exfil_cloud_storage_new(e):
    try:
        return bool(e.get('cloud_api_calls_new')) and get_http_bytes_out(e) > 1000000
    except Exception:
        return False


# DUPLICATE_DISABLED decorator for rule exfil_paste_bin in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='exfil_paste_bin', mitre=['T1041'],
               factors_required=['pastebin_post','data_growth_trend'],
               window_seconds=7200, severity='medium', confidence_boost=0.25)
def exfil_paste_bin(e):
    return bool(e.get('pastebin_post')) and bool(e.get('data_growth_trend'))


# DUPLICATE_DISABLED decorator for rule imp_shadowcopy_delete in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='imp_shadowcopy_delete', mitre=['T1490'],
               factors_required=['vssadmin_delete','backup_service_stop'],
               window_seconds=3600, severity='critical', confidence_boost=0.45)
def imp_shadowcopy_delete(e):
    return bool(e.get('vssadmin_delete')) and bool(e.get('backup_service_stop'))


# DUPLICATE_DISABLED decorator for rule imp_stop_security_services in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='imp_stop_security_services', mitre=['T1562.001'],
               factors_required=['service_stop_edr','admin_context_change'],
               window_seconds=3600, severity='critical', confidence_boost=0.45)
def imp_stop_security_services(e):
    normalize_service_stop_edr(e)
    return bool(e.get('service_stop_edr')) and bool(e.get('admin_context_change'))

# ---------------- Batch 3: Collection, C2, Persistence variants, Discovery variants ----------------

@register_rule(name='col_browser_data_exfil', mitre=['T1020'],
               factors_required=['browser_profile_zip_created','cloud_api_calls_new'],
               window_seconds=7200, severity='high', confidence_boost=0.35)
def col_browser_data_exfil(e):
    return bool(e.get('browser_profile_zip_created')) and bool(e.get('cloud_api_calls_new'))


@register_rule(name='col_screencap_tool', mitre=['T1113'],
               factors_required=['screencap_tool_exec','screenshot_upload'],
               window_seconds=3600, severity='medium', confidence_boost=0.30)
def col_screencap_tool(e):
    return bool(e.get('screencap_tool_exec')) and bool(e.get('screenshot_upload'))


@register_rule(name='c2_rare_ja3_beacon', mitre=['T1071.001'],
               factors_required=['net:outbound_ja3_rare','beacon_like_periodicity'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def c2_rare_ja3_beacon(e):
    return bool(e.get('net:outbound_ja3_rare')) and bool(e.get('beacon_like_periodicity'))


# DUPLICATE_DISABLED decorator for rule c2_dns_tunnel_exfil in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='c2_dns_tunnel_exfil', mitre=['T1071.004'],
               factors_required=['dns_tunnel_detected','high_entropy_queries'],
               window_seconds=3600, severity='high', confidence_boost=0.45)
def c2_dns_tunnel_exfil(e):
    return bool(e.get('dns_tunnel_detected')) and bool(e.get('high_entropy_queries'))


@register_rule(name='pers_scheduled_task_lolbin_args', mitre=['T1053.005'],
               factors_required=['scheduled_task_created','lolbin_in_task_args'],
               window_seconds=86400, severity='high', confidence_boost=0.35)
def pers_scheduled_task_lolbin_args(e):
    # Normalize legacy flags
    created = bool(e.get('scheduled_task_created') or e.get('task_created') or e.get('schtasks_create'))
    # task arguments may be a string or list
    args = e.get('lolbin_in_task_args') or e.get('task_arguments') or e.get('task_args') or ''
    if isinstance(args, list):
        arg_text = ' '.join(str(x) for x in args).lower()
    else:
        arg_text = str(args).lower()
    lolbins = ('certutil','mshta','bitsadmin','regsvr32','rundll32','wmic','schtasks','psexec')
    has_lolbin_arg = any(tok in arg_text for tok in lolbins)
    # also accept when the task name suggests lolbin usage
    task_name = str(e.get('task_name') or '').lower()
    task_name_hint = any(tok in task_name for tok in ('install','update','patch','svc_'))
    return created and (bool(e.get('lolbin_in_task_args')) or has_lolbin_arg or task_name_hint)


@register_rule(name='pers_wmi_persistence', mitre=['T1047'],
               factors_required=['wmi_event_filter','wmi_consumer_created'],
               window_seconds=86400, severity='high', confidence_boost=0.40)
def pers_wmi_persistence(e):
    return bool(e.get('wmi_event_filter')) and bool(e.get('wmi_consumer_created'))


@register_rule(name='disc_credential_enum_burst', mitre=['T1087'],
               factors_required=['credential_enum_count','internal_only'],
               window_seconds=1800, severity='medium', confidence_boost=0.30)
def disc_credential_enum_burst(e):
    try:
        return int(e.get('credential_enum_count') or 0) >= 20 and bool(e.get('internal_only'))
    except Exception:
        return False


@register_rule(name='c2_ssh_bruteforce_multiple', mitre=['T1110.001'],
               factors_required=['ssh_failed_login_count','ssh_success_from_unusual_ip'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def c2_ssh_bruteforce_multiple(e):
    try:
        return int(e.get('ssh_failed_login_count') or 0) >= 50 and bool(e.get('ssh_success_from_unusual_ip'))
    except Exception:
        return False


# DUPLICATE_DISABLED decorator for rule col_keylogger_detected_exfil in src\core\correlation\rules\weekX\expanded_batch.py
@register_rule(name='col_keylogger_detected_exfil', mitre=['T1056.001'],
               factors_required=['keylogger_implant_detected','http_bytes_out'],
               window_seconds=7200, severity='critical', confidence_boost=0.45)
def col_keylogger_detected_exfil(e):
    try:
        implanted = bool(e.get('keylogger_implant_detected') or e.get('keylogger_detected') or e.get('system_keylogger_flag'))
        bytes_out = get_http_bytes_out(e)
        threshold = 250000
        return implanted and bytes_out > threshold
    except Exception:
        return False


@register_rule(name='c2_rare_cert_issuer_beacon', mitre=['T1071.001'],
               factors_required=['tls_cert_issuer_rare','beacon_like_periodicity'],
               window_seconds=3600, severity='high', confidence_boost=0.40)
def c2_rare_cert_issuer_beacon(e):
    return bool(e.get('tls_cert_issuer_rare')) and bool(e.get('beacon_like_periodicity'))


@register_rule(name='disc_exposed_rdp_hosts', mitre=['T1046'],
               factors_required=['external_rdp_exposed','rdp_bruteforce_attempts'],
               window_seconds=3600, severity='medium', confidence_boost=0.30)
def disc_exposed_rdp_hosts(e):
    try:
        return bool(e.get('external_rdp_exposed')) and int(e.get('rdp_bruteforce_attempts') or 0) >= 5
    except Exception:
        return False


@register_rule(name='pers_registry_wmi_combo', mitre=['T1546'],
               factors_required=['registry_persistence_set','wmi_consumer_created'],
               window_seconds=86400, severity='high', confidence_boost=0.38)
def pers_registry_wmi_combo(e):
    return bool(e.get('registry_persistence_set')) and bool(e.get('wmi_consumer_created'))
