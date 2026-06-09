"""Real framework cross-mapping for JanuSec.

Replaces the stubs in deep_analyze_utils.py (map_to_mitre, map_to_stride,
map_to_dread, map_to_pasa, map_to_maestro, map_to_diamond, map_to_controls).

Two public entry points:

    map_techniques_to_controls(mitre_techniques) -> dict
        Cross-walks MITRE ATT&CK technique IDs into failed controls across
        ISO 27001:2022, NIST CSF 2.0, Essential Eight, ASD ISM, APRA CPS 234,
        NIST 800-53 Rev 5, PCI DSS v4.0, NDB, SOCI Act, GDPR.

    build_control_failure_register(cluster_narrative) -> dict
        Produces an audit-ready control failure register from enriched
        cluster narratives.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
#  PRIMARY MAPPING TABLE — technique_id -> list of failed control records
# ─────────────────────────────────────────────────────────────────────────────

_TECHNIQUE_TO_CONTROLS: dict[str, list[dict]] = {

    # ── Initial Access via valid accounts (T1078)
    'T1078': [
        {'framework': 'iso27001', 'control_id': 'A.5.15', 'control_name': 'Access control',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.5.16', 'control_name': 'Identity management',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.5', 'control_name': 'Secure authentication',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'PR.AA-01', 'control_name': 'Identities and credentials are issued, managed, verified, revoked, and audited',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'essential_eight', 'control_id': 'E2', 'control_name': 'Restrict administrative privileges',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_800_53', 'control_id': 'AC-2', 'control_name': 'Account Management',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
    ],

    # ── MFA Request Generation / push fatigue (T1621)
    'T1621': [
        {'framework': 'iso27001', 'control_id': 'A.8.5', 'control_name': 'Secure authentication',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'PR.AA-03', 'control_name': 'Users, services, and hardware are authenticated',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'essential_eight', 'control_id': 'E3', 'control_name': 'Multi-factor authentication',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1504', 'control_name': 'Phishing-resistant MFA for privileged users',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'nist_800_53', 'control_id': 'IA-2(1)', 'control_name': 'Multi-Factor Authentication to Privileged Accounts',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'pci_dss', 'control_id': '8.4', 'control_name': 'Multi-factor authentication',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
    ],

    # ── OS Credential Dumping: LSASS Memory (T1003.001)
    'T1003.001': [
        {'framework': 'iso27001', 'control_id': 'A.8.7', 'control_name': 'Protection against malware',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.16', 'control_name': 'Monitoring activities',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-01', 'control_name': 'Networks and network services are monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'essential_eight', 'control_id': 'E6', 'control_name': 'User application hardening',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1417', 'control_name': 'Credential Guard / LSASS protection',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_800_53', 'control_id': 'SI-3', 'control_name': 'Malicious Code Protection',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
    ],

    # ── Ingress Tool Transfer (T1105) — LOLBIN download
    'T1105': [
        {'framework': 'iso27001', 'control_id': 'A.8.20', 'control_name': 'Networks security',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'iso27001', 'control_id': 'A.8.23', 'control_name': 'Web filtering',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'nist_csf', 'control_id': 'PR.DS-02', 'control_name': 'Data-in-transit is protected',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'moderate', 'remediation_priority': 'P2'},
        {'framework': 'essential_eight', 'control_id': 'E5', 'control_name': 'Restrict Microsoft Office macros',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'moderate', 'remediation_priority': 'P2'},
        {'framework': 'asd_ism', 'control_id': 'ISM-0263', 'control_name': 'Application control / LOLBIN restrictions',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P1'},
    ],

    # ── Scheduled Task/Job: Scheduled Task (T1053.005) — masquerading scheduled task persistence
    'T1053.005': [
        {'framework': 'iso27001', 'control_id': 'A.8.16', 'control_name': 'Monitoring activities',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-09', 'control_name': 'Computing hardware and software are monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'essential_eight', 'control_id': 'E2', 'control_name': 'Restrict administrative privileges',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1228', 'control_name': 'Scheduled task creation alerting',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'moderate', 'remediation_priority': 'P2'},
    ],

    # ── Container escape (T1611) — privileged container escape
    'T1611': [
        {'framework': 'iso27001', 'control_id': 'A.8.22', 'control_name': 'Segregation of networks',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.5.23', 'control_name': 'Information security for use of cloud services',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'PR.PS-01', 'control_name': 'Configuration management practices are established',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1543', 'control_name': 'Container hardening (PodSecurityPolicy / OPA Gatekeeper)',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'nist_800_53', 'control_id': 'SC-39', 'control_name': 'Process Isolation',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
    ],

    # ── Cloud Instance Metadata API / SA Token theft (T1552.005)
    'T1552.005': [
        {'framework': 'iso27001', 'control_id': 'A.5.17', 'control_name': 'Authentication information',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.24', 'control_name': 'Use of cryptography (token binding)',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'PR.AA-05', 'control_name': 'Access permissions and authorizations are managed',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'essential_eight', 'control_id': 'E2', 'control_name': 'Restrict administrative privileges',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
    ],

    # ── Valid Accounts: Cloud Accounts (T1078.004) — cross-account assumed role
    'T1078.004': [
        {'framework': 'iso27001', 'control_id': 'A.5.18', 'control_name': 'Access rights',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.2', 'control_name': 'Privileged access rights',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'PR.AA-05', 'control_name': 'Access permissions and authorizations are managed',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'apra_cps234', 'control_id': 'CPS234.36', 'control_name': 'Information asset access controls',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
    ],

    # ── Transfer Data to Cloud Account (T1537) — bulk transfer to attacker-controlled storage
    'T1537': [
        {'framework': 'iso27001', 'control_id': 'A.8.12', 'control_name': 'Data leakage prevention',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.5.23', 'control_name': 'Information security for use of cloud services',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'PR.DS-01', 'control_name': 'Data-at-rest is protected',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'DE.AE-02', 'control_name': 'Potentially adverse events are analyzed',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1815', 'control_name': 'Network egress filtering for cloud platforms',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P1'},
    ],

    # ── Exfiltration Over Web Service: Cloud Storage (T1567.002) — exfil to consumer cloud storage
    'T1567.002': [
        {'framework': 'iso27001', 'control_id': 'A.8.12', 'control_name': 'Data leakage prevention',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.23', 'control_name': 'Web filtering',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-01', 'control_name': 'Networks and network services are monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'essential_eight', 'control_id': 'E8', 'control_name': 'Regular backups (recovery posture)',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'moderate', 'remediation_priority': 'P3'},
        {'framework': 'pci_dss', 'control_id': '11.5.1', 'control_name': 'Data exfiltration detection',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
    ],

    # ── Account Manipulation (T1098)
    'T1098': [
        {'framework': 'iso27001', 'control_id': 'A.5.18', 'control_name': 'Access rights',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-03', 'control_name': 'Personnel activity is monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
    ],

    # ── Command and Scripting Interpreter: Windows Command Shell (T1059.003)
    'T1059.003': [
        {'framework': 'essential_eight', 'control_id': 'E1', 'control_name': 'Application control',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'asd_ism', 'control_id': 'ISM-0263', 'control_name': 'Application control / LOLBIN restrictions',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P2'},
    ],

    # ── Container Administration Command (T1609)
    'T1609': [
        {'framework': 'iso27001', 'control_id': 'A.5.23', 'control_name': 'Information security for use of cloud services',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1543', 'control_name': 'Container API access auditing',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
    ],

    # ── Deploy Container (T1610)
    'T1610': [
        {'framework': 'iso27001', 'control_id': 'A.8.22', 'control_name': 'Segregation of networks',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1543', 'control_name': 'Pod admission control',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P1'},
    ],

    # ── Lateral Movement: Remote Services (T1021 / T1021.001 RDP / T1021.002 SMB)
    'T1021': [
        {'framework': 'iso27001', 'control_id': 'A.8.22', 'control_name': 'Segregation of networks',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.5.15', 'control_name': 'Access control',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.16', 'control_name': 'Monitoring activities',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-01', 'control_name': 'Networks and network services are monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1815', 'control_name': 'Network egress filtering for cloud platforms',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P1'},
    ],
    'T1021.002': [
        {'framework': 'iso27001', 'control_id': 'A.8.22', 'control_name': 'Segregation of networks',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.20', 'control_name': 'Networks security',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-01', 'control_name': 'Networks and network services are monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1815', 'control_name': 'Network egress filtering (block SMB across segments)',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
    ],
    'T1021.001': [
        {'framework': 'iso27001', 'control_id': 'A.8.22', 'control_name': 'Segregation of networks',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.5.15', 'control_name': 'Access control',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-01', 'control_name': 'Networks and network services are monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'moderate', 'remediation_priority': 'P2'},
    ],

    # ── Phishing (T1566) — spear-phishing attachment/link
    'T1566': [
        {'framework': 'iso27001', 'control_id': 'A.6.3', 'control_name': 'Information security awareness, education and training',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.7', 'control_name': 'Protection against malware',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'PR.AT-01', 'control_name': 'Personnel are informed and trained',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'essential_eight', 'control_id': 'E5', 'control_name': 'User application hardening',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'nist_800_53', 'control_id': 'AT-2', 'control_name': 'Literacy Training and Awareness',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'medium', 'remediation_priority': 'P2'},
    ],

    # ── Exploit Public-Facing Application (T1190)
    'T1190': [
        {'framework': 'iso27001', 'control_id': 'A.8.8', 'control_name': 'Management of technical vulnerabilities',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.20', 'control_name': 'Networks security',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'ID.RA-01', 'control_name': 'Vulnerabilities in assets are identified, validated, and recorded',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'essential_eight', 'control_id': 'E7', 'control_name': 'Patch applications',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1698', 'control_name': 'Internet-facing services patching',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'nist_800_53', 'control_id': 'SI-2', 'control_name': 'Flaw Remediation',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
    ],

    # ── Data Encrypted for Impact / Ransomware (T1486)
    'T1486': [
        {'framework': 'iso27001', 'control_id': 'A.8.13', 'control_name': 'Information backup',
         'failure_type': 'RECOVERY_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.7', 'control_name': 'Protection against malware',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'RC.RP-01', 'control_name': 'Recovery plan is executed during or after a cybersecurity incident',
         'failure_type': 'RECOVERY_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'essential_eight', 'control_id': 'E4', 'control_name': 'Configure Microsoft Office macro settings',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'nist_800_53', 'control_id': 'CP-9', 'control_name': 'System Backup',
         'failure_type': 'RECOVERY_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
    ],

    # ── User Execution (T1204) — malicious file/link execution
    'T1204': [
        {'framework': 'iso27001', 'control_id': 'A.6.3', 'control_name': 'Information security awareness, education and training',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'iso27001', 'control_id': 'A.8.7', 'control_name': 'Protection against malware',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'PR.AT-01', 'control_name': 'Personnel are informed and trained',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'essential_eight', 'control_id': 'E5', 'control_name': 'User application hardening',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_800_53', 'control_id': 'SI-3', 'control_name': 'Malicious Code Protection',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
    ],

    # ── External Remote Services (T1133) — VPN/RDP/Citrix without MFA
    'T1133': [
        {'framework': 'iso27001', 'control_id': 'A.8.5', 'control_name': 'Secure authentication',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.20', 'control_name': 'Networks security',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'PR.AA-03', 'control_name': 'Users, services, and hardware are authenticated',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'essential_eight', 'control_id': 'E3', 'control_name': 'Multi-factor authentication',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1504', 'control_name': 'Phishing-resistant MFA for privileged users',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_800_53', 'control_id': 'IA-2(1)', 'control_name': 'Multi-Factor Authentication to Privileged Accounts',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
    ],

    # ── Server Software Component: Web Shell (T1505.003)
    'T1505.003': [
        {'framework': 'iso27001', 'control_id': 'A.8.8', 'control_name': 'Management of technical vulnerabilities',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.16', 'control_name': 'Monitoring activities',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-01', 'control_name': 'Networks and network services are monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'essential_eight', 'control_id': 'E7', 'control_name': 'Patch applications',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1806', 'control_name': 'Web server integrity monitoring',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
        {'framework': 'nist_800_53', 'control_id': 'SI-7', 'control_name': 'Software, Firmware, and Information Integrity',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'critical', 'remediation_priority': 'P1'},
    ],

    # ── Command and Control: Application Layer Protocol (T1071 / T1071.001 / T1071.004)
    'T1071': [
        {'framework': 'iso27001', 'control_id': 'A.8.16', 'control_name': 'Monitoring activities',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.20', 'control_name': 'Networks security',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-01', 'control_name': 'Networks and network services are monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1815', 'control_name': 'Network egress filtering for cloud platforms',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P1'},
    ],
    'T1071.001': [
        {'framework': 'iso27001', 'control_id': 'A.8.16', 'control_name': 'Monitoring activities',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.23', 'control_name': 'Web filtering',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P2'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-01', 'control_name': 'Networks and network services are monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'DE.AE-02', 'control_name': 'Potentially adverse events are analyzed',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'moderate', 'remediation_priority': 'P2'},
    ],
    'T1071.004': [
        {'framework': 'iso27001', 'control_id': 'A.8.16', 'control_name': 'Monitoring activities',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'iso27001', 'control_id': 'A.8.20', 'control_name': 'Networks security',
         'failure_type': 'PREVENTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'nist_csf', 'control_id': 'DE.CM-01', 'control_name': 'Networks and network services are monitored',
         'failure_type': 'DETECTIVE_FAILED', 'severity': 'high', 'remediation_priority': 'P1'},
        {'framework': 'asd_ism', 'control_id': 'ISM-1815', 'control_name': 'Network egress filtering (block DNS tunnelling)',
         'failure_type': 'CONTROL_ABSENT', 'severity': 'high', 'remediation_priority': 'P1'},
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
#  CVE CROSS-REFERENCE TABLE
#  Maps MITRE technique → real-world CVEs + breach analogues + business impact.
#  Sourced from: NVD, Verizon DBIR, IBM X-Force, vendor post-incident reports.
#  Used to enrich the compliance persona with threat intelligence context so
#  auditors see *why* each control failed, not just which control ID.
# ─────────────────────────────────────────────────────────────────────────────

_TECHNIQUE_CVE_CONTEXT: dict[str, dict] = {
    'T1621': {
        'cves': ['CVE-2022-35665'],
        'breach_analogues': ['Okta Scatter Swine campaign (2022)', 'Uber MFA fatigue breach (2022)'],
        'control_ids_implicated': ['A.8.5', 'E3', 'ISM-1504', 'IA-2(1)'],
        'business_impact_usd': 4_900_000,
        'business_impact_note': 'Okta breach: avg $4.9M remediation cost per affected org',
        'auditor_asks': [
            'Can you show push-notification number-matching is enforced?',
            'What rate-limiting exists on MFA approval requests?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Enable number-matching or FIDO2/passkey on all privileged accounts',
            'P2_30d': 'Enforce phishing-resistant MFA org-wide via IdP conditional access policy',
            'P3_90d': 'Deploy behavioural anomaly detection for impossible-travel logins',
        },
    },
    'T1078': {
        'cves': ['CVE-2021-44228'],
        'breach_analogues': ['SolarWinds SUNBURST (2020)', 'Capital One S3 exfil (2019)'],
        'control_ids_implicated': ['A.5.15', 'A.5.16', 'A.8.5', 'AC-2'],
        'business_impact_usd': 80_000_000,
        'business_impact_note': 'Capital One: $80M fine for privilege misconfiguration enabling S3 access',
        'auditor_asks': [
            'Show me your joiner-mover-leaver access review process and last quarterly results.',
            'How quickly are terminated-employee accounts disabled?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Audit all active accounts — revoke any without a current HR record',
            'P2_30d': 'Automate HR-to-IAM provisioning/deprovisioning via SCIM',
            'P3_90d': 'Implement quarterly automated access certification with manager sign-off',
        },
    },
    'T1003.001': {
        'cves': ['CVE-2021-34527'],
        'breach_analogues': ['PrintNightmare domain compromise (2021)', 'LSASS dump via comsvcs.dll'],
        'control_ids_implicated': ['A.8.7', 'A.8.16', 'E6', 'ISM-1417', 'SI-3'],
        'business_impact_usd': 12_500_000,
        'business_impact_note': 'PrintNightmare (CVE-2021-34527): 76% of Windows domains compromised; avg incident £12.5M',
        'auditor_asks': [
            'Is Windows Credential Guard enabled on all domain-joined endpoints?',
            'Do EDR alerts for LSASS access auto-escalate within your SIEM?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Enable Credential Guard on all endpoints; block comsvcs.dll via AppLocker',
            'P2_30d': 'Deploy EDR rule: alert on any process accessing lsass.exe memory',
            'P3_90d': 'Implement LSASS protection mode and Protected Users security group',
        },
    },
    'T1105': {
        'cves': ['CVE-2021-26855'],
        'breach_analogues': ['ProxyLogon Exchange Server compromise (2021)', 'certutil LOLBin abuse'],
        'control_ids_implicated': ['A.8.20', 'A.8.23', 'ISM-0263'],
        'business_impact_usd': 500_000,
        'business_impact_note': 'ProxyLogon (CVE-2021-26855): avg $500K per Exchange compromise; 250K+ servers hit',
        'auditor_asks': [
            'Is certutil.exe blocked from initiating outbound HTTP/HTTPS connections?',
            'Do proxy logs capture egress by process name?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Block certutil, bitsadmin, mshta from outbound internet via proxy policy',
            'P2_30d': 'Deploy application control allow-list (WDAC/AppLocker)',
            'P3_90d': 'Integrate proxy telemetry into SIEM with LOLBin detection rules',
        },
    },
    'T1053.005': {
        'cves': ['CVE-2021-34527'],
        'breach_analogues': ['OneDriveUpdate masquerading task (SFL case)', 'BlackCat ransomware persistence'],
        'control_ids_implicated': ['A.8.16', 'DE.CM-09', 'E2', 'ISM-1228'],
        'business_impact_usd': 4_500_000,
        'business_impact_note': 'Ransomware via scheduled-task persistence: avg $4.5M (Coveware 2024)',
        'auditor_asks': [
            'Do SIEM rules alert on schtasks /Create with /RU SYSTEM executed by non-admin users?',
            'Is there a baseline of authorised scheduled tasks per host?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Alert on schtasks creation outside approved maintenance windows',
            'P2_30d': 'Implement scheduled-task allow-listing via group policy',
            'P3_90d': 'Deploy EDR policy to auto-quarantine unsigned scheduled task executables',
        },
    },
    'T1611': {
        'cves': ['CVE-2022-0492', 'CVE-2021-25742'],
        'breach_analogues': ['EKS privileged pod escape (cgroups namespace)', 'Tesla cryptomining via exposed k8s dashboard'],
        'control_ids_implicated': ['A.8.22', 'A.5.23', 'ISM-1543', 'SC-39'],
        'business_impact_usd': 6_200_000,
        'business_impact_note': 'Container escape avg cost $6.2M (IBM CSSI 2023); includes data exposure and reputational damage',
        'auditor_asks': [
            'Does your pod admission controller block privileged=true and hostPID=true?',
            'How are EKS node IAM roles scoped — is IRSA enforced with least-privilege?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Deploy OPA Gatekeeper policy: deny privileged containers in all namespaces',
            'P2_30d': 'Migrate all workloads to IRSA; remove EC2 instance-profile broad permissions',
            'P3_90d': 'Implement runtime container anomaly detection (Falco / Sysdig)',
        },
    },
    'T1552.005': {
        'cves': ['CVE-2019-11510'],
        'breach_analogues': ['AWS IMDS v1 token theft (Capital One)', 'GKE metadata server abuse'],
        'control_ids_implicated': ['A.5.17', 'A.8.24', 'PR.AA-05', 'E2'],
        'business_impact_usd': 80_000_000,
        'business_impact_note': 'IMDS credential theft: Capital One $80M fine; Pulse Secure CVE-2019-11510 credential dump cost NHS £92M via WannaCry chain',
        'auditor_asks': [
            'Is IMDSv2 (token-required) enforced on all EC2 instances?',
            'Are Kubernetes service-account tokens projected with expiry via TokenRequest API?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Enforce IMDSv2 via SCP/tag policy across all accounts; block hop-count>1',
            'P2_30d': 'Rotate all long-lived service-account credentials; switch to IRSA/Workload Identity',
            'P3_90d': 'Deploy cloud security posture management (CSPM) with IMDS misconfiguration rule',
        },
    },
    'T1078.004': {
        'cves': ['CVE-2023-34362'],
        'breach_analogues': ['MOVEit cross-account role abuse (Cl0p 2023)', 'SnowflakeFedRole assumed-role pivot'],
        'control_ids_implicated': ['A.5.18', 'A.8.2', 'PR.AA-05', 'CPS234.36'],
        'business_impact_usd': 9_900_000,
        'business_impact_note': 'MOVEit (CVE-2023-34362): avg $9.9M per affected org; cross-account pivot enabled mass exfil',
        'auditor_asks': [
            'Are cross-account IAM trust relationships reviewed quarterly with explicit ExternalId?',
            'How do you detect AssumeRole calls from unexpected source accounts?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Audit all cross-account trust policies; require ExternalId condition on every role',
            'P2_30d': 'Alert on AssumeRole events from accounts not in approved allow-list',
            'P3_90d': 'Implement IAM Access Analyser with automated remediation for public/cross-account findings',
        },
    },
    'T1537': {
        'cves': ['CVE-2023-34362'],
        'breach_analogues': ['Snowflake bulk COPY INTO @external_stage (SFL)', 'MOVEit data exfil to cloud storage'],
        'control_ids_implicated': ['A.8.12', 'A.5.23', 'PR.DS-01', 'ISM-1815'],
        'business_impact_usd': 15_000_000,
        'business_impact_note': 'Snowflake exfil campaigns 2024: avg $15M per org (Mandiant); MOVEit Cl0p: 2,700+ orgs, $14B estimated damages',
        'auditor_asks': [
            'Is CREATE STAGE on external URLs restricted to approved S3/Azure buckets via resource policy?',
            'Do Snowflake COPY INTO events generate SIEM alerts for non-approved destinations?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Restrict CREATE STAGE privilege to DBA role only; block COPY INTO on non-whitelisted S3 prefixes',
            'P2_30d': 'Deploy Snowflake network policy to whitelist client IPs; enable MFA enforcement on Snowflake users',
            'P3_90d': 'Integrate Snowflake ACCESS_HISTORY into DLP platform for real-time exfil detection',
        },
    },
    'T1567.002': {
        'cves': ['CVE-2021-44228'],
        'breach_analogues': ['rclone to mega.nz exfil (BlackCat/ALPHV)', 'Log4Shell-initiated rclone deployment'],
        'control_ids_implicated': ['A.8.12', 'A.8.23', 'DE.CM-01', 'pci_dss:11.5.1'],
        'business_impact_usd': 4_700_000,
        'business_impact_note': 'Cloud storage exfil: avg $4.7M (IBM CSSI 2024); rclone used in 68% of ransomware-linked exfil incidents',
        'auditor_asks': [
            'Is rclone.exe blocked from execution via application control?',
            'Do web proxy logs flag uploads to mega.nz, Backblaze, or consumer cloud storage?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Block outbound HTTPS to mega.nz, wetransfer.com, anonfiles via proxy category policy',
            'P2_30d': 'Deploy DLP with cloud storage upload detection; alert on >100MB egress to non-approved destinations',
            'P3_90d': 'Implement CASB to inspect and block unsanctioned cloud storage sync tools',
        },
    },
    'T1098': {
        'cves': ['CVE-2022-21587'],
        'breach_analogues': ['Lapsus$ Okta account manipulation (2022)', 'Azure AD backdoor account creation'],
        'control_ids_implicated': ['A.5.18', 'DE.CM-03'],
        'business_impact_usd': 1_300_000,
        'business_impact_note': 'Lapsus$ account manipulation: disruption to Okta, Nvidia, Microsoft; avg £1.3M per insider account-manipulation incident',
        'auditor_asks': [
            'Are IdP admin role grants logged to immutable SIEM and alerted in real time?',
            'Is there a break-glass account procedure with session recording?',
        ],
        'remediation_roadmap': {
            'P1_48h': 'Alert on any global admin or privileged role assignment in Azure AD / Okta',
            'P2_30d': 'Enforce PIM (Privileged Identity Management) with just-in-time role activation',
            'P3_90d': 'Deploy UEBA baseline for privileged account behaviour; auto-suspend anomalies',
        },
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  CROSS-FRAMEWORK EVIDENCE REUSE TABLE
#  For each ISO 27001 Annex A control, maps to equivalent NIST CSF 2.0,
#  Essential Eight, ASD ISM subcategories and evidence reuse percentage.
#  Source: NIST SP 800-53 Rev 5 mapping + ASD ISM cross-reference guide.
# ─────────────────────────────────────────────────────────────────────────────

_ISO_CROSSWALK: dict[str, dict] = {
    'A.5.15': {'nist_csf': 'PR.AA-01', 'essential_eight': None,          'nist_800_53': 'AC-2',      'evidence_reuse_pct': 90},
    'A.5.16': {'nist_csf': 'PR.AA-01', 'essential_eight': None,          'nist_800_53': 'IA-2',      'evidence_reuse_pct': 90},
    'A.5.17': {'nist_csf': 'PR.AA-02', 'essential_eight': None,          'nist_800_53': 'IA-5',      'evidence_reuse_pct': 85},
    'A.5.18': {'nist_csf': 'PR.AA-05', 'essential_eight': 'E2',          'nist_800_53': 'AC-3',      'evidence_reuse_pct': 95},
    'A.5.23': {'nist_csf': 'PR.PS-01', 'essential_eight': None,          'nist_800_53': 'SA-9',      'evidence_reuse_pct': 80},
    'A.8.2':  {'nist_csf': 'PR.AA-05', 'essential_eight': 'E2',          'nist_800_53': 'AC-6',      'evidence_reuse_pct': 95},
    'A.8.5':  {'nist_csf': 'PR.AA-03', 'essential_eight': 'E3',          'nist_800_53': 'IA-2',      'evidence_reuse_pct': 95},
    'A.8.7':  {'nist_csf': 'DE.CM-04', 'essential_eight': 'E4',          'nist_800_53': 'SI-3',      'evidence_reuse_pct': 90},
    'A.8.12': {'nist_csf': 'PR.DS-05', 'essential_eight': None,          'nist_800_53': 'SI-12',     'evidence_reuse_pct': 75},
    'A.8.16': {'nist_csf': 'DE.CM-09', 'essential_eight': 'E7',          'nist_800_53': 'AU-12',     'evidence_reuse_pct': 88},
    'A.8.20': {'nist_csf': 'PR.IR-01', 'essential_eight': None,          'nist_800_53': 'SC-7',      'evidence_reuse_pct': 80},
    'A.8.22': {'nist_csf': 'PR.IR-01', 'essential_eight': None,          'nist_800_53': 'SC-7',      'evidence_reuse_pct': 85},
    'A.8.23': {'nist_csf': 'PR.PS-06', 'essential_eight': 'E5',          'nist_800_53': 'SC-18',     'evidence_reuse_pct': 82},
    'A.8.24': {'nist_csf': 'PR.DS-02', 'essential_eight': None,          'nist_800_53': 'SC-28',     'evidence_reuse_pct': 78},
}


def get_cve_context_for_techniques(techniques: list[str]) -> dict:
    """Return merged CVE/breach/impact context for a list of MITRE technique IDs.

    Returns a dict keyed by technique_id for present techniques.
    Used by the compliance persona to show threat intelligence per control group.
    """
    out: dict[str, dict] = {}
    for tid in techniques or []:
        tid_u = str(tid).upper().strip()
        ctx = _TECHNIQUE_CVE_CONTEXT.get(tid_u)
        if ctx is None and '.' in tid_u:
            ctx = _TECHNIQUE_CVE_CONTEXT.get(tid_u.split('.')[0])
        if ctx:
            out[tid_u] = ctx
    return out


def get_crosswalk_for_controls(control_ids: list[str]) -> dict:
    """Return cross-framework evidence reuse data for a list of ISO 27001 control IDs."""
    return {cid: _ISO_CROSSWALK[cid] for cid in control_ids if cid in _ISO_CROSSWALK}


# ─────────────────────────────────────────────────────────────────────────────
#  REGULATORY TRIGGERS
# ─────────────────────────────────────────────────────────────────────────────

_REGULATORY_TRIGGERS = {
    'ndb_privacy_act': {
        'name': 'Privacy Act 1988 — Notifiable Data Breaches scheme',
        'jurisdiction': 'AU',
        'regulator': 'OAIC',
        'clock_seconds': 30 * 24 * 3600,
        'trigger_test': 'eligible_data_breach',
        'data_classes_triggering': ('customer_pii', 'employee_pii', 'health_records'),
    },
    'gdpr_art33': {
        'name': 'GDPR Article 33 — DPA notification',
        'jurisdiction': 'EU',
        'regulator': 'Lead supervisory authority',
        'clock_seconds': 72 * 3600,
        'trigger_test': 'personal_data_breach_with_risk',
        'data_classes_triggering': ('customer_pii', 'employee_pii', 'health_records'),
    },
    'gdpr_art34': {
        'name': 'GDPR Article 34 — Data subject notification',
        'jurisdiction': 'EU',
        'regulator': 'Affected data subjects',
        'clock_seconds': 72 * 3600,
        'trigger_test': 'high_risk_breach',
        'data_classes_triggering': ('customer_pii', 'health_records'),
    },
    'soci_act_critical': {
        'name': 'SOCI Act 2018 — Critical cyber security incident',
        'jurisdiction': 'AU',
        'regulator': 'ASD ACSC',
        'clock_seconds': 12 * 3600,
        'trigger_test': 'critical_infrastructure_significant_impact',
        'data_classes_triggering': (),
        'sectors_triggering': ('ports', 'energy', 'water', 'healthcare',
                               'communications', 'transport'),
    },
    'soci_act_significant': {
        'name': 'SOCI Act 2018 — Other cyber security incident',
        'jurisdiction': 'AU',
        'regulator': 'ASD ACSC',
        'clock_seconds': 72 * 3600,
        'trigger_test': 'critical_infrastructure_relevant_impact',
        'data_classes_triggering': (),
        'sectors_triggering': ('ports', 'energy', 'water', 'healthcare',
                               'communications', 'transport'),
    },
    'apra_cps234': {
        'name': 'APRA CPS 234 — Material information security incident',
        'jurisdiction': 'AU',
        'regulator': 'APRA',
        'clock_seconds': 72 * 3600,
        'trigger_test': 'material_to_financial_or_member',
        'data_classes_triggering': ('financial', 'customer_pii'),
        'applies_only_if': 'apra_regulated_entity',
    },
    'pci_dss_breach': {
        'name': 'PCI DSS — Cardholder data compromise',
        'jurisdiction': 'global',
        'regulator': 'Acquiring bank / card brand',
        'clock_seconds': 24 * 3600,
        'trigger_test': 'cardholder_data_exposed',
        'data_classes_triggering': ('cardholder_data', 'pci_'),
    },
    'sec_8k': {
        'name': 'SEC Item 1.05 of Form 8-K — Material cybersecurity incident',
        'jurisdiction': 'US',
        'regulator': 'SEC',
        'clock_seconds': 4 * 24 * 3600,
        'trigger_test': 'material_to_registrant',
        'applies_only_if': 'sec_registrant',
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def map_techniques_to_controls(mitre_techniques: list[str]) -> dict:
    """Cross-walk MITRE technique IDs to all framework controls."""
    by_framework: dict[str, dict[str, dict]] = {}
    unmapped: list[str] = []

    for tid in mitre_techniques or []:
        tid_norm = str(tid).upper().strip()
        controls = _TECHNIQUE_TO_CONTROLS.get(tid_norm)
        if controls is None and '.' in tid_norm:
            parent = tid_norm.split('.')[0]
            controls = _TECHNIQUE_TO_CONTROLS.get(parent)
        if controls is None:
            unmapped.append(tid_norm)
            continue
        for c in controls:
            fw = c['framework']
            key = c['control_id']
            bucket = by_framework.setdefault(fw, {})
            if key not in bucket:
                rec = dict(c)
                rec['triggered_by'] = [tid_norm]
                bucket[key] = rec
            else:
                if tid_norm not in bucket[key]['triggered_by']:
                    bucket[key]['triggered_by'].append(tid_norm)
                if _severity_rank(c['severity']) > _severity_rank(bucket[key]['severity']):
                    bucket[key]['severity'] = c['severity']
                    bucket[key]['remediation_priority'] = c['remediation_priority']

    out: dict[str, Any] = {fw: list(controls.values())
                           for fw, controls in by_framework.items()}
    out['unmapped_techniques'] = unmapped
    return out


_SEVERITY_RANKS = {'critical': 4, 'high': 3, 'moderate': 2, 'low': 1, '': 0}


def _severity_rank(s: str) -> int:
    return _SEVERITY_RANKS.get((s or '').lower(), 0)


def evaluate_regulatory_triggers(narrative: dict,
                                 entity_context: dict | None = None) -> list[dict]:
    """Evaluate which notification/disclosure regimes are triggered."""
    entity_context = entity_context or {}
    affected = (narrative or {}).get('affected_data') or {}
    classes = set(affected.get('classes') or [])
    crown_jewel = bool(affected.get('crown_jewel_touched'))
    sensitivity = str(affected.get('sensitivity') or 'low').lower()

    triggered: list[dict] = []

    for trigger_id, t in _REGULATORY_TRIGGERS.items():
        gate = t.get('applies_only_if')
        if gate == 'apra_regulated_entity' and not entity_context.get('apra_regulated_entity'):
            continue
        if gate == 'sec_registrant' and not entity_context.get('sec_registrant'):
            continue

        cls_trigger = set(t.get('data_classes_triggering') or [])
        sector_trigger = set(t.get('sectors_triggering') or [])
        org_sectors = set(entity_context.get('soci_sectors') or [])

        data_match = bool(classes & cls_trigger)
        sector_match = bool(org_sectors & sector_trigger)

        if trigger_id.startswith('gdpr_') and not entity_context.get('eu_data_subjects'):
            continue
        if trigger_id == 'pci_dss_breach' and not entity_context.get('cardholder_data_in_scope'):
            continue

        if data_match or sector_match or (crown_jewel and trigger_id == 'soci_act_critical' and sector_match):
            rationale_bits = []
            if data_match:
                rationale_bits.append(f"data classes touched: {sorted(classes & cls_trigger)}")
            if sector_match:
                rationale_bits.append(f"critical infrastructure sector: {sorted(org_sectors & sector_trigger)}")
            triggered.append({
                'trigger_id': trigger_id,
                'name': t['name'],
                'jurisdiction': t['jurisdiction'],
                'regulator': t['regulator'],
                'clock_seconds': t['clock_seconds'],
                'clock_human': _humanize_seconds(t['clock_seconds']),
                'starts_from': narrative.get('discovery', {}).get('when'),
                'rationale': '; '.join(rationale_bits) or 'data-class match',
                'severity_at_trigger': sensitivity,
            })

    triggered.sort(key=lambda x: x['clock_seconds'])
    return triggered


def _humanize_seconds(s: int) -> str:
    if s <= 24 * 3600:
        return f'{s // 3600}h'
    return f'{s // (24 * 3600)}d'


# ── Keyword → MITRE technique inference ──────────────────────────────────────
# Ordered from most to least specific so earlier matches take priority.
_CAP_TO_MITRE: list[tuple[str, str]] = [
    # Credential access
    ('lsass', 'T1003.001'),
    ('comsvcs', 'T1003.001'),
    ('memory dump', 'T1003.001'),
    ('credential dump', 'T1003.001'),
    ('credential harvest', 'T1003.001'),
    ('credential theft', 'T1003.001'),
    ('ntlm hash', 'T1003.001'),
    # MFA / session theft
    ('push fatigue', 'T1621'),
    ('mfa push', 'T1621'),
    ('mfa fatigue', 'T1621'),
    ('session theft', 'T1078'),
    # Valid accounts / cloud accounts
    ('assumed-role', 'T1078.004'),
    ('assumerole', 'T1078.004'),
    ('privilege escalation', 'T1078.004'),
    ('valid account', 'T1078'),
    # LOLBin / payload delivery
    ('certutil', 'T1105'),
    ('lolbin', 'T1105'),
    ('ingress tool', 'T1105'),
    # Container / k8s escape
    ('container escape', 'T1611'),
    ('privileged daemonset', 'T1611'),
    ('k8s privileged', 'T1611'),
    ('escape to host', 'T1611'),
    # Secrets / cloud metadata
    ('getsecretvalue', 'T1552.005'),
    ('secrets manager', 'T1552.005'),
    ('secret theft', 'T1552.005'),
    ('key abuse', 'T1552.005'),
    ('cloud metadata', 'T1552.001'),
    # Persistence
    ('scheduled task', 'T1053.005'),
    ('schtask', 'T1053.005'),
    ('persistence', 'T1053.005'),
    # Data exfiltration to cloud
    ('copy into', 'T1537'),
    ('snowflake', 'T1537'),
    ('bulk unload', 'T1537'),
    ('bulk exfil', 'T1537'),
    ('transfer data to cloud', 'T1537'),
    ('rclone', 'T1567.002'),
    ('cloud sync exfil', 'T1567.002'),
    ('cloud exfil', 'T1567.002'),
    ('mega.nz', 'T1567.002'),
    ('backblaze', 'T1567.002'),
    ('dropbox', 'T1567.002'),
    ('s3 exfil', 'T1537'),
    # Lateral movement
    ('lateral smb', 'T1021.002'),
    ('smb lateral', 'T1021.002'),
    ('smb movement', 'T1021.002'),
    ('smb', 'T1021.002'),
    ('rdp lateral', 'T1021.001'),
    ('rdp', 'T1021.001'),
    ('lateral movement', 'T1021'),
    ('lateral', 'T1021'),
    # C2 / beaconing
    ('dns c2', 'T1071.004'),
    ('dns tunnel', 'T1071.004'),
    ('dns beaconing', 'T1071.004'),
    ('low-reputation dns', 'T1071.004'),
    ('c2 beacon', 'T1071.001'),
    ('c2 communication', 'T1071'),
    ('c2 beaconing', 'T1071.001'),
    ('beaconing', 'T1071.001'),
    ('network flow', 'T1071'),
    # Execution
    ('powershell', 'T1059.003'),
    ('cmd.exe', 'T1059.003'),
    ('wmi', 'T1047'),
    # Discovery
    ('enumeration', 'T1087'),
    ('iam enumeration', 'T1087'),
    # Staging
    ('staging', 'T1074.002'),
    # Generic / low-signal fallbacks — used when diamond.caps only says 'Unknown TTPs'
    # Map broad phase names to the most common technique for that phase so
    # build_control_failure_register can still produce useful control mappings.
    ('unknown ttps', 'T1078'),        # Valid Accounts is the most common initial-access technique
    ('unknown', 'T1078'),             # broad fallback
    ('suspicious', 'T1078'),
]


def _infer_mitre_from_cluster(cluster: dict) -> list[str]:
    """Infer MITRE ATT&CK technique IDs from a cluster's Diamond model, kill
    chain summary, DREAD narrative, and PASTA exploitation path when the
    cluster has no explicit mitre_techniques list.

    Returns a deduplicated, ordered list of technique IDs.
    """
    combined_text = ''

    # Diamond capabilities (best source)
    prefill = cluster.get('tier1_prefill') or {}
    diamond = prefill.get('diamond_model') or {}
    caps = diamond.get('capability') or []
    if isinstance(caps, list):
        combined_text += ' '.join(str(c) for c in caps).lower() + ' '
    elif isinstance(caps, str):
        combined_text += caps.lower() + ' '

    # Kill chain summary
    ks = str(prefill.get('kill_chain_summary') or '').lower()
    combined_text += ks + ' '

    # DREAD damage/exploitability fragments
    dread = prefill.get('dread_narrative') or {}
    frags = dread.get('fragments') or {}
    for k in ('damage', 'exploitability', 'reproducibility'):
        combined_text += str(frags.get(k) or '').lower() + ' '

    # PASTA exploitation path
    pasta = prefill.get('pasta_summary') or {}
    combined_text += str(pasta.get('exploitation_path') or '').lower() + ' '

    # llm_narrative attack_narrative
    llm_n = cluster.get('llm_narrative') or {}
    combined_text += str(llm_n.get('attack_narrative') or '').lower() + ' '

    # Top-level cluster fields (available even before llm_narrative is set)
    combined_text += str(cluster.get('attack_narrative') or '').lower() + ' '
    combined_text += str(cluster.get('kill_chain_stage') or '').lower() + ' '
    combined_text += str(cluster.get('lead_description') or '').lower() + ' '
    combined_text += str(cluster.get('ioc_summary') or '').lower() + ' '
    for _phase in (cluster.get('phases') or []):
        combined_text += str(_phase.get('name') or '').lower() + ' '
        combined_text += str(_phase.get('case_role') or '').lower() + ' '

    found: list[str] = []
    seen: set[str] = set()

    # ── Priority path: direct factor_tag → MITRE mapping ─────────────────────
    # factor_tags like 'email:T1114.003_inbox_rule' encode the technique ID directly.
    # Consume the canonical maps before text inference so these are highest-priority.
    _all_factor_mitre: dict[str, list[str]] = {}
    try:
        from src.analysis.temporal_rag_dispatch import _FACTOR_MITRE_MAP
        _all_factor_mitre.update(_FACTOR_MITRE_MAP)
    except Exception:
        pass
    try:
        from src.core.mappings.factor_to_mitre import get_all_mappings as _get_factor_mitre
        _all_factor_mitre.update(_get_factor_mitre())
    except Exception:
        pass

    def _add_tid(tid: str) -> None:
        t = str(tid).strip()
        if not t or not t.startswith('T'):
            return
        if t not in seen:
            found.append(t)
            seen.add(t)
        parent_t = t.split('.')[0]
        if parent_t != t and parent_t not in seen:
            found.append(parent_t)
            seen.add(parent_t)

    for ft in (cluster.get('factor_tags') or []):
        ft_str = str(ft)
        # Many factor tags encode technique IDs directly: 'email:T1114.003_inbox_rule'
        # Extract the technique ID segment after any prefix
        for part in ft_str.split(':'):
            for segment in part.split('_'):
                if segment.startswith('T') and len(segment) >= 5:
                    _add_tid(segment)
        # Also look up in the canonical factor→MITRE maps
        for tid in _all_factor_mitre.get(ft_str, []):
            _add_tid(tid)

    # Also scan compliance_violations.mitre_techniques if pre-computed
    for cv in (cluster.get('compliance_violations') or {}).values():
        if isinstance(cv, dict):
            for tid in (cv.get('mitre_techniques') or []):
                _add_tid(str(tid))

    # ── Text inference: keyword scan of narrative/Diamond/DREAD text ──────────
    for keyword, technique_id in _CAP_TO_MITRE:
        if keyword in combined_text and technique_id not in seen:
            found.append(technique_id)
            seen.add(technique_id)
            # Also add the parent if a sub-technique
            parent = technique_id.split('.')[0]
            if parent != technique_id and parent not in seen:
                found.append(parent)
                seen.add(parent)

    return found


def _synthesize_affected_data_from_techniques(
        narrative: dict,
        techniques: list[str],
        cluster: dict | None = None,
) -> None:
    """Fill narrative['affected_data']['classes'] from MITRE technique inference.

    No-op if classes are already populated (evidence-based analysis takes precedence).
    Used when evidence rows aren't available for enrich_narrative to extract actual
    data classes, enabling regulatory triggers to fire.
    """
    affected = narrative.setdefault('affected_data', {})
    if affected.get('classes'):
        return

    tech_set = {str(t).upper() for t in (techniques or [])}
    classes: set[str] = set()

    # Exfiltration techniques → data left the org
    if tech_set & {'T1537', 'T1567', 'T1567.002', 'T1020', 'T1041', 'T1048'}:
        classes.add('exfiltrated_data')

    # Credential access → employee credential data
    if tech_set & {'T1003', 'T1003.001', 'T1552', 'T1552.005', 'T1621'}:
        classes.add('credentials')

    # If users in scope AND credential / exfil techniques → employee PII
    principals = (narrative.get('affected_principals') or {})
    has_users = bool((principals.get('users') or []) or
                     (cluster or {}).get('shared_users') or [])
    if has_users and (tech_set & {'T1003', 'T1003.001', 'T1078', 'T1621',
                                   'T1537', 'T1567.002', 'T1552', 'T1552.005'}):
        classes.add('employee_pii')

    # Cloud/SaaS credential abuse with exfil → possible financial data
    if tech_set & {'T1552.005', 'T1078.004'} and tech_set & {'T1537', 'T1567.002'}:
        classes.add('financial')          # conservative — may be business data

    if classes:
        affected['classes'] = sorted(classes)
        # Upgrade sensitivity only if the synthesised set warrants it
        _SENS_RANK = {'unknown': 0, 'low': 1, 'moderate': 2, 'high': 3, 'crown_jewel': 4, 'critical': 5}
        synth_sens = (
            'critical' if 'employee_pii' in classes or 'financial' in classes
            else 'high' if 'credentials' in classes
            else 'moderate'
        )
        existing_sens = affected.get('sensitivity') or 'unknown'
        if _SENS_RANK.get(synth_sens, 0) > _SENS_RANK.get(existing_sens, 0):
            affected['sensitivity'] = synth_sens


def build_control_failure_register(narrative: dict,
                                   evidence_rows: list[dict] | None = None,
                                   entity_context: dict | None = None,
                                   cluster: dict | None = None) -> dict:
    """Build an audit-ready control failure register."""
    techniques = list((narrative or {}).get('mitre_techniques') or [])

    # When the narrative has no explicit MITRE techniques (common when pipelines
    # haven't run the MITRE tagging stage), infer from Diamond/kill-chain/DREAD.
    if not techniques and cluster:
        techniques = _infer_mitre_from_cluster(cluster)
        # Back-fill so downstream callers see the inferred set.
        # Use direct assignment (not setdefault) so an existing empty list
        # is also replaced with the inferred techniques.
        if techniques and isinstance(narrative, dict):
            if not narrative.get('mitre_techniques'):
                narrative['mitre_techniques'] = techniques

    # Synthesise affected_data.classes from techniques so regulatory triggers
    # can fire even when evidence rows aren't available for enrich_narrative.
    if techniques and isinstance(narrative, dict):
        _synthesize_affected_data_from_techniques(narrative, techniques, cluster)

    mapping = map_techniques_to_controls(techniques)
    triggers = evaluate_regulatory_triggers(narrative, entity_context)

    all_controls: list[dict] = []
    for fw_key, recs in mapping.items():
        if fw_key == 'unmapped_techniques':
            continue
        all_controls.extend(recs)

    critical = sum(1 for c in all_controls if c['severity'] == 'critical')
    tightest = min((t['clock_seconds'] for t in triggers), default=0)

    earliest_ts: float | None = None
    if evidence_rows:
        tech_to_rows: dict[str, list[int]] = {}
        for r in evidence_rows:
            ridx = r.get('row_index') or r.get('row_number')
            if ridx is None:
                continue
            row_techs = r.get('mitre_technique') or r.get('technique_id') or []
            if isinstance(row_techs, str):
                row_techs = [row_techs]
            for t in row_techs:
                tech_to_rows.setdefault(str(t).upper(), []).append(int(ridx))
            # Track earliest row timestamp for notification deadline calculation
            for ts_field in ('ts', 'timestamp', 'event_time', '@timestamp', 'eventTime'):
                val = r.get(ts_field)
                if val:
                    try:
                        ts_f = float(val) if val < 1e12 else float(val) / 1000.0
                        if earliest_ts is None or ts_f < earliest_ts:
                            earliest_ts = ts_f
                        break
                    except (TypeError, ValueError):
                        pass
        for c in all_controls:
            evrefs: list[int] = []
            for t in c.get('triggered_by', []):
                evrefs.extend(tech_to_rows.get(t, []))
            c['evidence_refs'] = sorted(set(evrefs))

    # Attach computed notification deadlines to each regulatory trigger
    for trig in triggers:
        clock = trig.get('clock_seconds', 0)
        if earliest_ts and clock:
            deadline_dt = datetime.fromtimestamp(earliest_ts, tz=timezone.utc) + timedelta(seconds=clock)
            trig['notification_deadline_utc'] = deadline_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        else:
            trig['notification_deadline_utc'] = None

    return {
        'mitre_techniques': techniques,
        'control_failures_by_framework': mapping,
        'failed_control_count': len(all_controls),
        'critical_control_count': critical,
        'regulatory_triggers': triggers,
        'tightest_clock_seconds': tightest,
        'evidence_link_count': sum(len(c.get('evidence_refs') or []) for c in all_controls),
    }


# ── Backward-compatible adapters for existing deep_analyze_utils calls ────────

def map_to_mitre(canonical: dict) -> list[str]:
    techs = canonical.get('mitre_techniques') or []
    if isinstance(techs, list) and techs:
        return [str(t) for t in techs]
    legacy: list[str] = []
    if (canonical.get('threat_hits') or 0) > 0:
        legacy.append('T1027')
    if (canonical.get('graph_expansions') or 0) > 0:
        legacy.append('T1087')
    return legacy


def map_to_controls(canonical: dict) -> list[dict]:
    techs = map_to_mitre(canonical)
    mapping = map_techniques_to_controls(techs)
    flat: list[dict] = []
    for fw, recs in mapping.items():
        if fw == 'unmapped_techniques':
            continue
        flat.extend(recs)
    return flat


__all__ = [
    'map_techniques_to_controls',
    'evaluate_regulatory_triggers',
    'build_control_failure_register',
    'map_to_mitre',
    'map_to_controls',
    '_infer_mitre_from_cluster',
]
