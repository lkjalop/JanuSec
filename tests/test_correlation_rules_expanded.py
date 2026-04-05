import json
import os
import pytest

from src.core.correlation.rules import registry as reg
# Ensure batch rule modules are imported so decorators run and register rules
try:
    # direct import ensures the module-level register_rule decorators execute
    from src.core.correlation.rules.weekX import expanded_batch  # type: ignore
except Exception:
    # Best-effort; tests will still run but may fail if registration didn't occur
    expanded_batch = None  # type: ignore
try:
    from src.core.correlation.rules.batch_more import additional_30  # type: ignore
except Exception:
    additional_30 = None  # type: ignore

VECTORS = [
    ('ia_html_smuggling','tests/data/ia_html_smuggling_event.json'),
    ('ia_zip_js_chain','tests/data/ia_zip_js_chain_event.json'),
    ('ia_lnk_lolbin','tests/data/ia_lnk_lolbin_event.json'),
    ('ia_iso_mount_exec','tests/data/ia_iso_mount_exec_event.json'),
    ('exec_mshta_remote','tests/data/exec_mshta_remote_event.json'),
    ('exec_rundll32_suspicious','tests/data/exec_rundll32_suspicious_event.json'),
    ('exec_oab_formshell','tests/data/exec_oab_formshell_event.json'),
    ('pers_registry_run_key_nonstd','tests/data/pers_registry_run_key_nonstd_event.json'),
    ('pers_startup_folder_drop','tests/data/pers_startup_folder_drop_event.json'),
    ('lm_rdp_fanout','tests/data/lm_rdp_fanout_event.json'),
    ('ca_lsass_access_seq','tests/data/ca_lsass_access_seq_event.json'),
    ('disc_net_enum_burst','tests/data/disc_net_enum_burst_event.json'),
    ('de_disable_av','tests/data/de_disable_av_event.json'),
    ('de_timestomp','tests/data/de_timestomp_event.json'),
    ('de_sideload_dll','tests/data/de_sideload_dll_event.json'),
    ('de_process_hollowing_hint','tests/data/de_process_hollowing_hint_event.json'),
    ('de_signed_binary_proxy','tests/data/de_signed_binary_proxy_event.json'),
    ('pe_token_theft_combo','tests/data/pe_token_theft_combo_event.json'),
    ('pe_uac_bypass_fodhelper','tests/data/pe_uac_bypass_fodhelper_event.json'),
    ('pe_namedpipe_impersonation','tests/data/pe_namedpipe_impersonation_event.json'),
    ('pe_service_binpath_space','tests/data/pe_service_binpath_space_event.json'),
    ('pe_lolbin_msi_silent_elevated','tests/data/pe_lolbin_msi_silent_elevated_event.json'),
    ('exfil_cloud_storage_new','tests/data/exfil_cloud_storage_new_event.json'),
    ('exfil_paste_bin','tests/data/exfil_paste_bin_event.json'),
    ('imp_shadowcopy_delete','tests/data/imp_shadowcopy_delete_event.json'),
    ('imp_stop_security_services','tests/data/imp_stop_security_services_event.json'),
    ('col_browser_data_exfil','tests/data/col_browser_data_exfil_event.json'),
    ('col_screencap_tool','tests/data/col_screencap_tool_event.json'),
    ('c2_rare_ja3_beacon','tests/data/c2_rare_ja3_beacon_event.json'),
    ('c2_dns_tunnel_exfil','tests/data/c2_dns_tunnel_exfil_event.json'),
    ('pers_scheduled_task_lolbin_args','tests/data/pers_scheduled_task_lolbin_args_event.json'),
    ('pers_wmi_persistence','tests/data/pers_wmi_persistence_event.json'),
    ('disc_credential_enum_burst','tests/data/disc_credential_enum_burst_event.json'),
    ('c2_ssh_bruteforce_multiple','tests/data/c2_ssh_bruteforce_multiple_event.json'),
    ('col_keylogger_detected_exfil','tests/data/col_keylogger_detected_exfil_event.json'),
    ('c2_rare_cert_issuer_beacon','tests/data/c2_rare_cert_issuer_beacon_event.json'),
    ('disc_exposed_rdp_hosts','tests/data/disc_exposed_rdp_hosts_event.json'),
    ('pers_registry_wmi_combo','tests/data/pers_registry_wmi_combo_event.json'),
    ('c2_http_small_periodic_payload','tests/data/c2_http_small_periodic_payload_event.json'),
    ('c2_ssl_odd_sni_beacon','tests/data/c2_ssl_odd_sni_beacon_event.json'),
    ('lateral_smb_admin_burst','tests/data/lateral_smb_admin_burst_event.json'),
    ('exfil_ftp_large_payload','tests/data/exfil_ftp_large_payload_event.json'),
    ('persistence_service_binary_change','tests/data/persistence_service_binary_change_event.json'),
    ('defense_evasion_amsi_bypass_combo','tests/data/defense_evasion_amsi_bypass_combo_event.json'),
    ('discovery_dns_reverse_enum','tests/data/discovery_dns_reverse_enum_event.json'),
    ('cred_dump_lsass_trace','tests/data/cred_dump_lsass_trace_event.json'),
    ('staged_payload_chain','tests/data/staged_payload_chain_event.json'),
    ('script_lateral_execution_by_wmi','tests/data/script_lateral_execution_by_wmi_event.json'),
    ('impostor_domain_beacon','tests/data/impostor_domain_beacon_event.json'),
    ('stealth_proc_injection_combo','tests/data/stealth_proc_injection_combo_event.json'),
    ('exfil_smtp_large_attachment','tests/data/exfil_smtp_large_attachment_event.json'),
    ('config_file_tamper','tests/data/config_file_tamper_event.json'),
    ('lateral_ssh_sweep_internal','tests/data/lateral_ssh_sweep_internal_event.json'),
    ('code_signer_spoofed','tests/data/code_signer_spoofed_event.json'),
    ('filesystem_encryption_trigger','tests/data/filesystem_encryption_trigger_event.json'),
    ('cloud_role_escalation_from_vm','tests/data/cloud_role_escalation_from_vm_event.json'),
    ('insider_data_collection_pattern','tests/data/insider_data_collection_pattern_event.json'),
    ('supply_chain_downloader','tests/data/supply_chain_downloader_event.json'),
    ('lateral_rdp_brute_force_from_cloud','tests/data/lateral_rdp_brute_force_from_cloud_event.json'),
    ('exfil_dns_txt_chunks','tests/data/exfil_dns_txt_chunks_event.json'),
    ('persistence_scheduled_task_shadowing','tests/data/persistence_scheduled_task_shadowing_event.json'),
    ('lateral_http_proxy_tunnel','tests/data/lateral_http_proxy_tunnel_event.json'),
    ('exfil_stealth_cloud_metadata','tests/data/exfil_stealth_cloud_metadata_event.json'),
    ('discovery_ad_credential_dump','tests/data/discovery_ad_credential_dump_event.json'),
    ('process_hollowing_evidence_combo','tests/data/process_hollowing_evidence_combo_event.json'),
    ('persistence_registry_run_once_args','tests/data/persistence_registry_run_once_args_event.json'),
    ('lateral_smb_grooming_credential_harvest','tests/data/lateral_smb_grooming_credential_harvest_event.json'),
    ('exfil_multipart_http_chunking','tests/data/exfil_multipart_http_chunking_event.json'),
]


@pytest.mark.parametrize('rule_id,vector_path', VECTORS)
def test_expanded_rule_fires(rule_id, vector_path):
    full_path = os.path.join(os.getcwd(), vector_path)
    assert os.path.exists(full_path), f"Missing vector {vector_path}"
    with open(full_path, 'r', encoding='utf-8') as fh:
        payload = json.load(fh)
    hits = reg.CORRELATION_RULES.evaluate(payload)
    # Support both `.rule` and legacy `.name` on CorrelationRule instances
    hit_names = set()
    for h in hits:
        if hasattr(h, 'rule'):
            hit_names.add(getattr(h, 'rule'))
        elif hasattr(h, 'name'):
            hit_names.add(getattr(h, 'name'))
    assert rule_id in hit_names, f"Rule {rule_id} did not fire; hits={hit_names}"
