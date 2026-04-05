from .registry import register_rule


# canonical owner elsewhere; decorator intentionally removed to avoid duplicate registration
def cred_lsass_openprocess(event):
    # event is expected to have: process_name, target_process, caller_user, syscall
    tp = event.get("target_process", "").lower()
    if "lsass" in tp:
        caller = event.get("caller_user") or event.get("user")
        proc = event.get("process_name", "").lower()
        if caller and caller.lower() not in ("system", "nt authority\\system"):
            return True
    return False


# canonical owner elsewhere; decorator intentionally removed to avoid duplicate registration
def cred_dump_lsass_trace(event):
    # heuristic: read from lsass plus memory dump file or suspicious CreateToolhelp32Snapshot
    if event.get("source", "").lower().endswith("lsass.exe") or event.get("target_process", "").lower().endswith("lsass.exe"):
        action = event.get("action", "").lower()
        if "read" in action or "dump" in action or event.get("file_path", "").lower().endswith(".dmp"):
            return True
    return False


# canonical owner elsewhere; decorator intentionally removed to avoid duplicate registration
def ca_lsass_access_seq(event):
    # Simple sequence canary: a process opening LSASS then writing a dump file
    if event.get("sequence", 0) >= 2:
        steps = event.get("steps", [])
        saw_open = any((s.get("target_process", "").lower().endswith("lsass.exe") and ("open" in s.get("action", "").lower())) for s in steps)
        saw_write = any((s.get("file_path", "").lower().endswith(".dmp") or "dump" in s.get("action", "").lower()) for s in steps)
        if saw_open and saw_write:
            return True
    return False


# canonical owner elsewhere; decorator intentionally removed to avoid duplicate registration
def pe_token_theft_combo(event):
    # Token theft often followed by LSASS access; look for impersonation + lsass access
    if event.get("impersonation", False) and (event.get("target_process", "").lower().endswith("lsass.exe") or event.get("file_path", "").lower().endswith(".dmp")):
        return True
    return False


# canonical owner elsewhere; decorator intentionally removed to avoid duplicate registration
def filesystem_encryption_trigger(event):
    # heuristic: many file writes with extensions changed to e.g. .locked or high write rate
    if event.get("write_count", 0) >= 20:
        return True
    if event.get("file_path", "").lower().endswith(('.locked', '.encrypted', '.crypt', '.zepto')):
        return True
    return False


# canonical owner elsewhere; decorator intentionally removed to avoid duplicate registration
def cloud_role_escalation_from_vm(event):
    # VM principal using metadata service to fetch tokens then call iam:AttachRolePolicy or similar
    if event.get("source_type") == "vm" and event.get("api_call", "").lower().startswith("iam"):
        if any(k in event.get("api_call", "").lower() for k in ("attachrole", "assumerole", "putrolepolicy", "putrole")):
            return True
    return False


# canonical owner elsewhere; decorator intentionally removed to avoid duplicate registration
def imp_stop_security_services(event):
    # heuristic: service stop commands for av/security products
    if event.get("action", "").lower() in ("service_stop", "sc stop", "systemctl stop"):
        svc = event.get("service_name", "").lower()
        if any(x in svc for x in ("defender", "avsvc", "crowdstrike", "carbonblack", "symantec", "mcshield")):
            return True
    return False


# canonical owner elsewhere; decorator intentionally removed to avoid duplicate registration
def col_keylogger_detected_exfil(event):
    # heuristic: keylogger detected then HTTP posts to external host
    if event.get("detection", "").lower().startswith("keylogger") and event.get("network_outbound", False):
        return True
    return False


# canonical owner elsewhere; decorator intentionally removed to avoid duplicate registration
def imp_encrypt_pattern_canary(event):
    # heuristic: mass rename events followed by VSS disable
    if event.get("mass_rename", False) and event.get("vss_delete", False):
        return True
    return False


# canonical owner elsewhere; decorator intentionally removed to avoid duplicate registration
def imp_shadowcopy_delete(event):
    if event.get("action", "").lower() in ("vssadmin delete shadows", "wbadmin delete catalog"):
        return True
    return False
