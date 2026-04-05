from .registry import register_rule as _priority_register


# DUPLICATE_DISABLED decorator for c2_dns_tunnel_exfil
# DUPLICATE_DISABLED decorator for c2_dns_tunnel_exfil
# DUPLICATE_DISABLED decorator for c2_dns_tunnel_exfil
# DUPLICATE_DISABLED decorator for c2_dns_tunnel_exfil
@_priority_register(name="c2_dns_tunnel_exfil", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.1)
def c2_dns_tunnel_exfil(event):
    # heuristic: many TXT records or long base64-like queries to unusual domains
    q = event.get("dns_query", "")
    if event.get("dns_tunnel_detected") and event.get("high_entropy_queries"):
        return True
    if event.get("dns_qtype", "").lower() in ("txt",) and len(q) > 80:
        return True
    if event.get("txt_chunks", 0) >= 5:
        return True
    return False


# DUPLICATE_DISABLED decorator for defense_evasion_amsi_bypass_combo
# DUPLICATE_DISABLED decorator for defense_evasion_amsi_bypass_combo
# DUPLICATE_DISABLED decorator for defense_evasion_amsi_bypass_combo
# DUPLICATE_DISABLED decorator for defense_evasion_amsi_bypass_combo
@_priority_register(name="defense_evasion_amsi_bypass_combo", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def defense_evasion_amsi_bypass_combo(event):
    if event.get("powershell_encoded") and event.get("amsi_disable_call"):
        return True
    if event.get("action", "").lower() == "amsi_bypass" and event.get("post_activity", "").lower() == "powershell_exec":
        return True
    return False


# DUPLICATE_DISABLED decorator for graph_lateral_chain_burst
# DUPLICATE_DISABLED decorator for graph_lateral_chain_burst
# DUPLICATE_DISABLED decorator for graph_lateral_chain_burst
# DUPLICATE_DISABLED decorator for graph_lateral_chain_burst
@_priority_register(name="graph_lateral_chain_burst", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.08)
def graph_lateral_chain_burst(event):
    # event should contain a graph_summary with host_count and window_hours
    gs = event.get("graph_summary", {})
    if gs.get("host_count", 0) >= 3 and gs.get("window_hours", 0) <= 1:
        return True
    return False


# DUPLICATE_DISABLED decorator for exec_office_macro_chain
# DUPLICATE_DISABLED decorator for exec_office_macro_chain
# DUPLICATE_DISABLED decorator for exec_office_macro_chain
# DUPLICATE_DISABLED decorator for exec_office_macro_chain
@_priority_register(name="exec_office_macro_chain", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def exec_office_macro_chain(event):
    if event.get("source_type") == "office_macro" and event.get("network_outbound", False):
        return True
    return False


@_priority_register(name="persistence_new_service_nonstandard", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.08)
def persistence_new_service_nonstandard(event):
    path = event.get("file_path", "").lower()
    if event.get("action", "").lower() == "create_service" and not path.startswith("c:/windows/"):
        return True
    return False


# DUPLICATE_DISABLED decorator for c2_http_small_periodic_payload
# DUPLICATE_DISABLED decorator for c2_http_small_periodic_payload
# DUPLICATE_DISABLED decorator for c2_http_small_periodic_payload
# DUPLICATE_DISABLED decorator for c2_http_small_periodic_payload
@_priority_register(name="c2_http_small_periodic_payload", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.08)
def c2_http_small_periodic_payload(event):
    if event.get("http_post_small") and event.get("beacon_periodicity"):
        return True
    if event.get("http_periodic", False) and event.get("http_size", 0) < 512:
        return True
    return False


# DUPLICATE_DISABLED decorator for c2_ssl_odd_sni_beacon
# DUPLICATE_DISABLED decorator for c2_ssl_odd_sni_beacon
# DUPLICATE_DISABLED decorator for c2_ssl_odd_sni_beacon
# DUPLICATE_DISABLED decorator for c2_ssl_odd_sni_beacon
@_priority_register(name="c2_ssl_odd_sni_beacon", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.09)
def c2_ssl_odd_sni_beacon(event):
    sni = event.get("sni", "")
    if event.get("tls_sni_rare") and event.get("beacon_like_periodicity"):
        return True
    if event.get("tls", False) and sni and any(ch in sni for ch in ("~","_") ):
        return True
    return False


# DUPLICATE_DISABLED decorator for lateral_smb_admin_burst
# DUPLICATE_DISABLED decorator for lateral_smb_admin_burst
# DUPLICATE_DISABLED decorator for lateral_smb_admin_burst
# DUPLICATE_DISABLED decorator for lateral_smb_admin_burst
@_priority_register(name="lateral_smb_admin_burst", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.08)
def lateral_smb_admin_burst(event):
    if int(event.get("smb_admin_conn_count", 0) or 0) >= 5:
        return True
    if event.get("smb_admin_ops", 0) >= 4:
        return True
    return False


# DUPLICATE_DISABLED decorator for exfil_ftp_large_payload
# DUPLICATE_DISABLED decorator for exfil_ftp_large_payload
# DUPLICATE_DISABLED decorator for exfil_ftp_large_payload
# DUPLICATE_DISABLED decorator for exfil_ftp_large_payload
@_priority_register(name="exfil_ftp_large_payload", mitre=[], factors_required=[], window_seconds=3600, severity="high", confidence_boost=0.12)
def exfil_ftp_large_payload(event):
    if int(event.get("ftp_upload_bytes", 0) or 0) >= 2_000_000 and event.get("rare_external_host"):
        return True
    if event.get("protocol", "") == "ftp" and event.get("bytes_transferred", 0) > 10_000_000:
        return True
    return False


# DUPLICATE_DISABLED decorator for persistence_service_binary_change
# DUPLICATE_DISABLED decorator for persistence_service_binary_change
# DUPLICATE_DISABLED decorator for persistence_service_binary_change
# DUPLICATE_DISABLED decorator for persistence_service_binary_change
@_priority_register(name="persistence_service_binary_change", mitre=[], factors_required=[], window_seconds=3600, severity="medium", confidence_boost=0.08)
def persistence_service_binary_change(event):
    if event.get("service_bin_changed") and event.get("service_path_temp"):
        return True
    if event.get("action", "").lower() == "service_modify" and event.get("file_path", "").lower() != event.get("original_path", "").lower():
        return True
    return False
