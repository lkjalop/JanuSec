"""
Compliance-framework control tagging from breach evidence.

Maps the same evidence keywords used by DREAD fragments / SABSA coda to
concrete control IDs across ISO 27001:2022, Essential Eight ML2,
NIST CSF 2.0, NDB Scheme (Australia), and APRA CPS 234.

Usage:
    from src.prefill.compliance_tags import derive_controls_breached
    tags = derive_controls_breached(dread_fragments)
    # → [{'framework': 'ISO 27001:2022', 'control_id': 'A.5.17', ...}, ...]
"""
from __future__ import annotations


# (evidence_keywords, framework, control_id, control_name)
_COMPLIANCE_MAP: list[tuple[list[str], str, str, str]] = [
    # ── Credential / authentication breaches ─────────────────────────────────
    (['lsass', 'comsvcs', 'mimikatz', 'credential', 'password spray', 'mfa fatigue',
      'session_theft', 'token replay'],
     'ISO 27001:2022', 'A.5.17', 'Authentication information'),
    (['lsass', 'credential', 'mimikatz', 'session_theft', 'mfa fatigue',
      'token replay', 'password spray'],
     'Essential Eight', 'ML2-MFA', 'Multi-factor authentication'),
    (['lsass', 'credential', 'mimikatz', 'session_theft', 'password spray'],
     'NIST CSF 2.0', 'PR.AA-05', 'Identity authentication'),

    # ── Access control ───────────────────────────────────────────────────────
    (['privileged', 'admin', 'domain admin', 'global admin', 'sudo',
      'assumerole', 'assumerole', 'sts'],
     'ISO 27001:2022', 'A.5.15', 'Access control'),
    (['privileged', 'admin', 'domain admin', 'global admin', 'assumerole'],
     'ISO 27001:2022', 'A.8.2', 'Privileged access rights'),
    (['privileged', 'admin', 'domain admin', 'global admin'],
     'Essential Eight', 'ML2-ADMIN', 'Restrict administrative privileges'),

    # ── Data exfiltration / leakage ──────────────────────────────────────────
    (['rclone', 'backblaze', 'mega', 'azcopy', 'gsutil', 'exfil',
      'copy into', 'unload', 's3', 'data_exfiltration'],
     'ISO 27001:2022', 'A.8.12', 'Data leakage prevention'),
    (['rclone', 'mega', 'exfil', 'copy into', 'backblaze', 'unload',
      'data_exfiltration'],
     'NIST CSF 2.0', 'PR.DS-01', 'Data-at-rest protection'),
    (['rclone', 'mega', 'exfil', 'copy into', 'pii', 'customer',
      'manifest', 'patient', 'financial'],
     'NDB Scheme', 's26WA', 'Likely notifiable data breach — assess within 30 days'),
    (['rclone', 'mega', 'exfil', 'copy into', 'pii', 'customer',
      'manifest', 'patient', 'financial'],
     'APRA CPS 234', 'Para 36', 'Material information security incident notification'),

    # ── Lateral movement ─────────────────────────────────────────────────────
    (['lateral', 'psexec', 'wmiexec', 'rdp', 'smb', 'pass the hash'],
     'ISO 27001:2022', 'A.8.20', 'Network security'),
    (['lateral', 'psexec', 'wmiexec', 'rdp', 'smb'],
     'NIST CSF 2.0', 'PR.AC-05', 'Network segmentation'),

    # ── C2 / monitoring ──────────────────────────────────────────────────────
    (['c2', 'beacon', 'dns tunnel', 'command-and-control', 'cobalt'],
     'ISO 27001:2022', 'A.8.16', 'Monitoring activities'),
    (['c2', 'beacon', 'dns tunnel'],
     'NIST CSF 2.0', 'DE.CM-01', 'Networks monitored for anomalous activity'),
    (['c2', 'beacon', 'dns tunnel', 'cobalt'],
     'NIST CSF 2.0', 'DE.AE-02', 'Events analyzed for potential threats'),

    # ── Container / K8s escape ───────────────────────────────────────────────
    (['hostpid', 'hostnetwork', 'container escape', 'daemonset',
      'node compromise', 'docker.sock', 'kubelet'],
     'ISO 27001:2022', 'A.8.9', 'Configuration management'),
    (['container escape', 'daemonset', 'docker.sock', 'kubelet',
      'hostpid', 'hostnetwork'],
     'Essential Eight', 'ML2-APPC', 'Application control'),

    # ── Persistence / malware ────────────────────────────────────────────────
    (['persistence', 'scheduled task', 'registry run', 'service binary',
      'backdoor', 'rootkit', 'certutil'],
     'ISO 27001:2022', 'A.8.7', 'Protection against malware'),
    (['persistence', 'scheduled task', 'registry run', 'certutil'],
     'NIST CSF 2.0', 'DE.CM-09', 'Computing hardware/software monitored'),

    # ── Phishing / initial access ────────────────────────────────────────────
    (['phishing', 'spear-phish', 'bec', 'inbox rule', 'credential harvest'],
     'ISO 27001:2022', 'A.6.3', 'Information security awareness/training'),
    (['phishing', 'spear-phish', 'bec'],
     'Essential Eight', 'ML2-EMAIL', 'Email filtering'),

    # ── Identity management ──────────────────────────────────────────────────
    (['identity', 'okta', 'entra', 'azure ad', 'sso', 'saml'],
     'NIST CSF 2.0', 'PR.AA-01', 'Identities and credentials issued/managed'),

    # ── Cloud-specific ───────────────────────────────────────────────────────
    (['snowflake', 'aws', 'getsecretvalue', 'cloudtrail', 's3'],
     'ISO 27001:2022', 'A.5.23', 'Cloud services security'),

    # ── Detection gap ────────────────────────────────────────────────────────
    (['undetected', 'no detection', 'days undetected', 'mttd'],
     'ISO 27001:2022', 'A.8.16', 'Monitoring activities'),
    (['undetected', 'no detection', 'days undetected'],
     'Essential Eight', 'ML2-LOG', 'Regular audit log monitoring'),

    # ── Backup / recovery ────────────────────────────────────────────────────
    (['ransomware', 'shadow copy delete', 'vssadmin', 'encrypt'],
     'ISO 27001:2022', 'A.8.13', 'Information backup'),
    (['ransomware', 'shadow copy delete', 'vssadmin'],
     'Essential Eight', 'ML2-BACKUP', 'Regular backups'),
]


def derive_controls_breached(
    fragments: dict[str, str | None],
) -> list[dict]:
    """
    Return a de-duplicated list of breached compliance controls derived from
    evidence fragments (same dict shape as DREAD dread_narrative.fragments).

    Each entry: {framework, control_id, control_name}
    """
    combined = ' '.join(str(v or '') for v in fragments.values()).lower()
    seen: set[str] = set()
    out: list[dict] = []
    for keywords, framework, control_id, control_name in _COMPLIANCE_MAP:
        key = f'{framework}|{control_id}'
        if key not in seen and any(kw in combined for kw in keywords):
            seen.add(key)
            out.append({
                'framework': framework,
                'control_id': control_id,
                'control_name': control_name,
            })
    return out
