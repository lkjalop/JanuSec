from .registry import register_rule as _priority_register


# DUPLICATE_DISABLED decorator for rule pe_token_theft_combo in src\core\correlation\rules\top40_priority.py
# DUPLICATE_DISABLED decorator for pe_token_theft_combo
# DUPLICATE_DISABLED decorator for pe_token_theft_combo
# DUPLICATE_DISABLED decorator for pe_token_theft_combo
# DUPLICATE_DISABLED decorator for pe_token_theft_combo
@_priority_register(name="pe_token_theft_combo", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def pe_token_theft_combo_2(event):
    if event.get("se_debug_adjust") and event.get("lsass_openprocess"):
        return True
    if event.get("impersonation", False) and (event.get("target_process", "").lower().endswith("lsass.exe") or event.get("file_path", "").lower().endswith(".dmp")):
        return True
    return False


@_priority_register(name="pe_uac_bypass_fodhelper", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def pe_uac_bypass_fodhelper(event):
    if event.get("registry_hijack_fodhelper") and event.get("fodhelper_exec"):
        return True
    if event.get("registry_modify", False) and "fodhelper" in event.get("reg_path", "").lower():
        return True
    return False


@_priority_register(name="pe_namedpipe_impersonation", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def pe_namedpipe_impersonation(event):
    if event.get("named_pipe_suspicious") and event.get("admin_context_change"):
        return True
    if event.get("named_pipe_impersonation", False):
        return True
    return False


@_priority_register(name="pe_service_binpath_space", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.09)
def pe_service_binpath_space(event):
    if event.get("service_unquoted_path") and event.get("child_started_from_mid_path"):
        return True
    if event.get("action", "").lower() == "service_create" and ' ' in event.get("service_path", "") and not '"' in event.get("service_path", ""):
        return True
    return False


@_priority_register(name="pe_lolbin_msi_silent_elevated", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.08)
def pe_lolbin_msi_silent_elevated(event):
    if event.get("msiexec_no_ui") and event.get("parent_office_app"):
        return True
    if event.get("exec_lolbin", "") == "msiexec" and event.get("silent_install", False) and event.get("elevated", False):
        return True
    return False


@_priority_register(name="exfil_cloud_storage_new", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def exfil_cloud_storage_new(event):
    if event.get("cloud_api_calls_new") and int(event.get("http_bytes_out", 0) or 0) >= 2_000_000:
        return True
    if event.get("cloud_storage_uploads", 0) >= 3 and event.get("new_bucket", False):
        return True
    return False


@_priority_register(name="exfil_paste_bin", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.08)
def exfil_paste_bin(event):
    if event.get("pastebin_post") and event.get("data_growth_trend"):
        return True
    if event.get("paste_posts", 0) >= 5 and event.get("data_size", 0) > 1000:
        return True
    return False


# DUPLICATE_DISABLED decorator for rule imp_shadowcopy_delete in src\core\correlation\rules\top40_priority.py
# DUPLICATE_DISABLED decorator for imp_shadowcopy_delete
# DUPLICATE_DISABLED decorator for imp_shadowcopy_delete
# DUPLICATE_DISABLED decorator for imp_shadowcopy_delete
# DUPLICATE_DISABLED decorator for imp_shadowcopy_delete
@_priority_register(name="imp_shadowcopy_delete", mitre=[], factors_required=[], window_seconds=3600, severity="critical", confidence_boost=0.2)
def imp_shadowcopy_delete_2(event):
    if event.get("vssadmin_delete") and event.get("backup_service_stop"):
        return True
    if event.get("action", "").lower() in ("vssadmin delete shadows", "wbadmin delete catalog"):
        return True
    return False


# DUPLICATE_DISABLED decorator for rule imp_encrypt_pattern_canary in src\core\correlation\rules\top40_priority.py
@_priority_register(name="imp_encrypt_pattern_canary", mitre=['T1486'], factors_required=['file_rename_count','ransom_note_like','mass_rename_ext'], window_seconds=3600, severity="critical", confidence_boost=0.2)
def imp_encrypt_pattern_canary_2(event):
    try:
        # Strong signal: explicit mass_rename_ext + vss delete + ransom note
        if bool(event.get('mass_rename_ext')) and bool(event.get('vss_delete')) and bool(event.get('ransom_note_like') or event.get('ransom_note_created')):
            return True
        # Fallback: very high file rename count + ransom note
        if int(event.get('file_rename_count') or 0) >= 100 and bool(event.get('ransom_note_like') or event.get('ransom_note_created')):
            return True
        # Backwards compatibility: legacy key 'mass_rename' + vss_delete suffices
        if event.get('mass_rename', False) and event.get('vss_delete', False):
            return True
    except Exception:
        pass
    return False


@_priority_register(name="disc_ad_enum", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.08)
def disc_ad_enum(event):
    if event.get("ad_enum_ops", 0) >= 30:
        return True
    return False
