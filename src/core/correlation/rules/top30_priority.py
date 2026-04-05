from .registry import register_rule as _priority_register


# DUPLICATE_DISABLED decorator for exfil_stealth_cloud_metadata
# DUPLICATE_DISABLED decorator for exfil_stealth_cloud_metadata
# DUPLICATE_DISABLED decorator for exfil_stealth_cloud_metadata
# DUPLICATE_DISABLED decorator for exfil_stealth_cloud_metadata
@_priority_register(name="exfil_stealth_cloud_metadata", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def exfil_stealth_cloud_metadata(event):
    if event.get("cloud_metadata_access") and event.get("cloud_api_unusual") and int(event.get("http_bytes_out", 0) or 0) >= 500:
        return True
    if event.get("cloud_metadata_access", 0) >= 3 and event.get("http_post", False):
        return True
    return False


# DUPLICATE_DISABLED decorator for rule col_keylogger_detected_exfil in src\core\correlation\rules\top30_priority.py
# DUPLICATE_DISABLED decorator for col_keylogger_detected_exfil
# DUPLICATE_DISABLED decorator for col_keylogger_detected_exfil
# DUPLICATE_DISABLED decorator for col_keylogger_detected_exfil
# DUPLICATE_DISABLED decorator for col_keylogger_detected_exfil
@_priority_register(name="col_keylogger_detected_exfil_2", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def col_keylogger_detected_exfil_2(event):
    # duplicate-safe wrapper for slightly different metadata shapes
    if event.get("detection", "").lower().startswith("keylogger") and event.get("network_outbound", False):
        return True
    return False


@_priority_register(name="discovery_dns_reverse_enum", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.08)
def discovery_dns_reverse_enum(event):
    if event.get("dns_ptr_burst") and event.get("subnet_scan_detected"):
        return True
    if event.get("reverse_dns_queries", 0) > 20:
        return True
    return False


@_priority_register(name="staged_payload_chain", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def staged_payload_chain(event):
    if event.get("download_stage1") and event.get("exec_stage2") and event.get("rare_chain"):
        return True
    if event.get("staged_payloads", 0) >= 2 and event.get("network_outbound", False):
        return True
    return False


@_priority_register(name="script_lateral_execution_by_wmi", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def script_lateral_execution_by_wmi(event):
    if event.get("wmi_remote_exec") and event.get("script_child_proc"):
        return True
    if event.get("exec_method", "") == "wmi" and event.get("suspicious_script", False):
        return True
    return False


@_priority_register(name="impostor_domain_beacon", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.09)
def impostor_domain_beacon(event):
    if event.get("typosquat_domain") and event.get("net:outbound_ja3_rare"):
        return True
    if event.get("domain_similarity_score", 0.0) > 0.8 and event.get("beaconing", False):
        return True
    return False


@_priority_register(name="stealth_proc_injection_combo", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def stealth_proc_injection_combo(event):
    if event.get("parent_mismatch") and event.get("memory_module") and event.get("suspicious_syscall_seq"):
        return True
    if event.get("process_injection", False) and event.get("suspicious_parent", False):
        return True
    return False


@_priority_register(name="config_file_tamper", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.07)
def config_file_tamper(event):
    if event.get("config_hash_changed") and event.get("service_restart_after_change"):
        return True
    if event.get("file_modify", False) and event.get("file_path", "").lower().endswith(('.conf','.json','.yaml','.yml')):
        return True
    return False


@_priority_register(name="lateral_ssh_sweep_internal", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.08)
def lateral_ssh_sweep_internal(event):
    if int(event.get("ssh_failed_count", 0) or 0) >= 100 and event.get("ssh_success_unusual_ip"):
        return True
    if event.get("ssh_attempts_internal", 0) >= 10:
        return True
    return False


@_priority_register(name="supply_chain_downloader", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def supply_chain_downloader(event):
    if event.get("git_clone_runtime") and event.get("download_exec") and event.get("nested_child_spawn"):
        return True
    if event.get("downloader", False) and event.get("package_target", "").lower().endswith(('.msi','.exe','.rpm')):
        return True
    return False
