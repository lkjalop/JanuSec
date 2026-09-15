"""Single consolidated phase-knowledge registry (de-brittling the core).

Per-phase attributes (compliance controls, remediation, DREAD components, driven
actions, asset class, kill-chain label) previously lived in SIX dicts across FOUR
files - only 13 of 38 detectors were mapped in all six, and adding a detector meant
editing up to six places or silently degrading to generic output.

This is the ONE place to describe a phase. Consumers read it through the accessors
below (each with a graceful default); coverage() surfaces which detected phases are
unmapped so a gap is visible, not silent.

To add a detector: add one entry to PHASE_KNOWLEDGE (or _EXTRA for local overrides).
"""
from __future__ import annotations

from typing import Optional

PHASE_KNOWLEDGE = {'ad_recon_discovery': {'asset_class': 'Active Directory',
                        'controls': {'iso27001': ['A.8.16'], 'soc2': ['CC7.2']},
                        'dread': {'D': 4,
                                  'Disc': 6,
                                  'E': 8,
                                  'R': 9,
                                  'why': 'Enumeration maps the estate for follow-on attacks; low direct damage.'},
                        'kc': (2, 'Active Directory reconnaissance'),
                        'remediation': ('Restrict AD enumeration; monitor the actor for follow-on privilege '
                                        'escalation.',
                                        'Identity')},
 'aitm_session': {'controls': {'iso27001': ['A.5.17', 'A.8.5'], 'soc2': ['CC6.1']},
                  'dread': {'D': 7,
                            'Disc': 5,
                            'E': 6,
                            'R': 7,
                            'why': 'Adversary-in-the-middle steals live sessions, defeating MFA.'},
                  'drivers': {'improvements': ['Session-revocation runbook'],
                              'infrastructure': ['Token-binding / continuous access evaluation; block legacy auth'],
                              'investments': ['Phishing-resistant MFA (FIDO2)']},
                  'kc': (1, 'an adversary-in-the-middle session theft'),
                  'remediation': ('Revoke the session tokens; reset credentials; enforce phishing-resistant MFA.',
                                  'Identity')},
 'bastion_rdp_lateral': {'asset_class': 'Endpoint / Windows',
                         'controls': {'iso27001': ['A.8.20', 'A.8.22'], 'soc2': ['CC6.6']},
                         'dread': {'D': 6,
                                   'Disc': 5,
                                   'E': 6,
                                   'R': 7,
                                   'why': 'Jump-host abuse pivots into segmented networks.'},
                         'drivers': {'improvements': ['Just-in-time, time-boxed admin sessions'],
                                     'infrastructure': ['Enforce all admin access via a hardened bastion with MFA; '
                                                        'segment management network'],
                                     'investments': ['Privileged Access Workstation / PAM session brokering']},
                         'kc': (6, 'bastion/RDP lateral movement'),
                         'remediation': ('Review the jump-host session; enforce segmentation and MFA on the bastion.',
                                         'SOC')},
 'c2_dns_beacon': {'asset_class': 'Network',
                   'controls': {'iso27001': ['A.8.20', 'A.8.16'], 'soc2': ['CC7.2']},
                   'dread': {'D': 6, 'Disc': 4, 'E': 6, 'R': 7, 'why': 'Covert C2 sustains attacker control.'},
                   'drivers': {'improvements': ['Beaconing-detection tuning'],
                               'infrastructure': ['Protective DNS; egress allow-listing; TLS inspection where '
                                                  'lawful'],
                               'investments': ['Network Detection & Response (NDR)', 'Threat-intel feed']},
                   'kc': (7, 'covert C2 beaconing'),
                   'remediation': ('Block the C2 domain/IP; isolate the beaconing host; hunt for the implant.',
                                   'SOC')},
 'cloud_iam_privesc': {'asset_class': 'Cloud IAM',
                       'controls': {'iso27001': ['A.5.15', 'A.8.2'], 'soc2': ['CC6.1', 'CC6.3']},
                       'dread': {'D': 8,
                                 'Disc': 5,
                                 'E': 6,
                                 'R': 6,
                                 'why': 'IAM escalation can grant control of the whole cloud account.'},
                       'kc': (4, 'cloud IAM escalation'),
                       'remediation': ('Revoke the escalated IAM permissions; review the policy that permitted '
                                       'escalation.',
                                       'Cloud/Identity')},
 'cloud_imds_theft': {'asset_class': 'Cloud IAM',
                      'controls': {'iso27001': ['A.5.17', 'A.8.2'], 'soc2': ['CC6.1']},
                      'dread': {'D': 8,
                                'Disc': 5,
                                'E': 6,
                                'R': 7,
                                'why': 'Stolen instance-role credentials access cloud APIs.'},
                      'drivers': {'improvements': ['Instance-role review; SSRF testing in CI'],
                                  'infrastructure': ['Enforce IMDSv2 / hop-limit; patch SSRF; scope instance roles '
                                                     'to least privilege'],
                                  'investments': ['Cloud Workload Protection (CWPP)', 'CSPM']},
                      'kc': (3, 'cloud instance-credential theft'),
                      'remediation': ('Revoke the instance role credentials; patch the SSRF/exposure path.',
                                      'Cloud/Identity')},
 'credential_theft': {'asset_class': 'Endpoint / Windows',
                      'controls': {'iso27001': ['A.5.17', 'A.8.7'], 'soc2': ['CC6.1']},
                      'dread': {'D': 8,
                                'Disc': 5,
                                'E': 6,
                                'R': 7,
                                'why': 'LSASS/credential theft yields reusable secrets.'},
                      'kc': (3, 'credential theft'),
                      'remediation': ('Reset the exposed credentials; isolate the host; enable credential-guard.',
                                      'Identity')},
 'data_exfiltration_rclone': {'controls': {'iso27001': ['A.8.12', 'A.5.14'], 'soc2': ['CC6.7']},
                              'dread': {'D': 9,
                                        'Disc': 4,
                                        'E': 6,
                                        'R': 6,
                                        'why': 'rclone bulk sync to cloud storage.'},
                              'kc': (9, 'rclone bulk exfiltration'),
                              'remediation': ('Block the destination; isolate the host; quantify data exposure.',
                                              'SOC/DLP')},
 'data_exfiltration_snowflake': {'controls': {'iso27001': ['A.8.12', 'A.5.14'], 'soc2': ['CC6.7']},
                                 'dread': {'D': 9,
                                           'Disc': 4,
                                           'E': 6,
                                           'R': 6,
                                           'why': 'Bulk database export - large records exposure.'},
                                 'kc': (9, 'bulk database export'),
                                 'remediation': ('Revoke the database credentials; block egress; quantify records '
                                                 'exposed.',
                                                 'SOC/DLP')},
 'dcsync_replication': {'asset_class': 'Active Directory',
                        'controls': {'iso27001': ['A.5.17', 'A.8.2', 'A.8.3'], 'soc2': ['CC6.1', 'CC6.3']},
                        'dread': {'D': 10,
                                  'Disc': 4,
                                  'E': 6,
                                  'R': 8,
                                  'why': 'DCSync extracts all domain hashes - full domain compromise.'},
                        'drivers': {'improvements': ['Documented krbtgt dual-reset runbook'],
                                    'infrastructure': ['Restrict directory replication rights; audit DCSync ACLs; '
                                                       'Tier-0 isolation'],
                                    'investments': ['ITDR / AD monitoring (e.g. Defender for Identity-class)']},
                        'kc': (3, 'a DCSync credential-replication attack'),
                        'remediation': ('Assume domain compromise: reset krbtgt twice and all privileged creds; '
                                        'audit replication rights.',
                                        'Identity')},
 'dns_tunnel_exfil': {'asset_class': 'Network',
                      'controls': {'iso27001': ['A.8.12', 'A.8.20'], 'soc2': ['CC6.7', 'CC7.2']},
                      'dread': {'D': 8,
                                'Disc': 3,
                                'E': 6,
                                'R': 6,
                                'why': 'DNS tunnelling exfiltrates data below most controls.'},
                      'drivers': {'improvements': ['DNS-tunnelling detection tuning'],
                                  'infrastructure': ['Protective DNS; block/inspect anomalous DNS volume and record '
                                                     'types'],
                                  'investments': ['Protective DNS / DNS security service', 'DLP']},
                      'kc': (9, 'DNS-tunnel exfiltration'),
                      'remediation': ('Block the tunnelling domain; quantify data exposure; isolate the host.',
                                      'SOC/DLP')},
 'email_external_exfil': {'asset_class': 'Email / M365',
                          'controls': {'iso27001': ['A.8.12', 'A.5.14'], 'soc2': ['CC6.7']},
                          'dread': {'D': 7,
                                    'Disc': 5,
                                    'E': 6,
                                    'R': 6,
                                    'why': 'External auto-forwarding leaks correspondence.'},
                          'kc': (9, 'external mail exfiltration'),
                          'remediation': ('Block the external forwarding; quantify data exposure; reset credentials.',
                                          'SOC/DLP')},
 'email_inbox_rule_abuse': {'asset_class': 'Email / M365',
                            'controls': {'iso27001': ['A.5.14', 'A.8.23'], 'soc2': ['CC6.7']},
                            'dread': {'D': 6,
                                      'Disc': 6,
                                      'E': 7,
                                      'R': 7,
                                      'why': 'Hidden inbox rules enable BEC and data theft.'},
                            'drivers': {'improvements': ['Inbox-rule monitoring and BEC playbook'],
                                        'infrastructure': ['Block/alert on external-forwarding and hidden inbox '
                                                           'rules; disable auto-forwarding'],
                                        'investments': ['Email security gateway / ICES (integrated cloud email '
                                                        'security)']},
                            'kc': (2, 'malicious inbox-rule abuse'),
                            'remediation': ('Delete the malicious inbox rule; reset the mailbox credentials; hunt '
                                            'for BEC.',
                                            'Identity')},
 'entra_privesc': {'asset_class': 'Cloud IdP',
                   'controls': {'iso27001': ['A.5.15', 'A.8.2'], 'soc2': ['CC6.1', 'CC6.3']},
                   'dread': {'D': 8,
                             'Disc': 5,
                             'E': 6,
                             'R': 6,
                             'why': 'Directory role escalation grants tenant-wide control.'},
                   'kc': (4, 'directory privilege escalation'),
                   'remediation': ('Remove the anomalous role assignment; review privileged-role activation policy.',
                                   'Identity')},
 'esxi_ransomware': {'controls': {'iso27001': ['A.8.7', 'A.8.13'], 'soc2': ['CC7.2']},
                     'dread': {'D': 10,
                               'Disc': 5,
                               'E': 6,
                               'R': 6,
                               'why': 'Hypervisor encryption takes out many VMs at once.'},
                     'drivers': {'improvements': ['Hypervisor patch and lockdown baseline'],
                                 'infrastructure': ['Isolate hypervisor management network; MFA on vCenter; '
                                                    'immutable VM backups'],
                                 'investments': ['Immutable backup for virtualization', 'EDR for hypervisor hosts']},
                     'kc': (8, 'ESXi ransomware'),
                     'remediation': ('Isolate the hypervisor management network; verify VM backups; begin IR '
                                     'playbook.',
                                     'SOC')},
 'exfil:cumulative_bytes_anomaly': {'asset_class': 'Data / Network',
                                    'controls': {'iso27001': ['A.8.12', 'A.5.14'], 'soc2': ['CC6.7']},
                                    'dread': {'D': 9,
                                              'Disc': 3,
                                              'E': 6,
                                              'R': 6,
                                              'why': 'Sustained low-and-slow exfiltration below per-event '
                                                     'thresholds.'},
                                    'drivers': {'improvements': ['Data classification; egress-anomaly monitoring'],
                                                'infrastructure': ['Egress filtering with allow-listed destinations; '
                                                                   'DNS security; data-egress baselining'],
                                                'investments': ['Data Loss Prevention (DLP)',
                                                                'Cloud Access Security Broker (CASB)']},
                                    'kc': (9, 'sustained data exfiltration'),
                                    'remediation': ('Block egress to the destination; quantify data exposure; '
                                                    'trigger breach-notification assessment.',
                                                    'SOC/DLP')},
 'exfil:cumulative_cloud_bytes_anomaly': {'asset_class': 'Cloud Data',
                                          'controls': {'iso27001': ['A.8.12', 'A.5.14'], 'soc2': ['CC6.7']},
                                          'dread': {'D': 9,
                                                    'Disc': 3,
                                                    'E': 6,
                                                    'R': 6,
                                                    'why': 'Cloud data egress to attacker-controlled destination.'},
                                          'drivers': {'improvements': ['Cloud data classification and egress '
                                                                       'baselining'],
                                                      'infrastructure': ['Cloud egress controls; restrict data-plane '
                                                                         'access to known destinations; private '
                                                                         'endpoints'],
                                                      'investments': ['DLP + CASB',
                                                                      'Cloud DSPM (data security posture)']},
                                          'kc': (9, 'cloud data exfiltration'),
                                          'remediation': ('Revoke the token/keys used; block the destination; assess '
                                                          'data exposure.',
                                                          'SOC/DLP')},
 'helpdesk_anomalous_reset': {'controls': {'iso27001': ['A.5.16', 'A.5.17'], 'soc2': ['CC6.2']},
                              'dread': {'D': 6,
                                        'Disc': 6,
                                        'E': 7,
                                        'R': 6,
                                        'why': 'Social-engineered resets hand over an account.'},
                              'kc': (1, 'a social-engineered credential reset'),
                              'remediation': ('Reverse the unauthorized reset; verify helpdesk identity-proofing '
                                              'controls.',
                                              'Identity')},
 'iam:oauth_consent_excessive_scope': {'asset_class': 'SaaS / M365',
                                       'controls': {'iso27001': ['A.5.15', 'A.5.18', 'A.8.2'],
                                                    'soc2': ['CC6.1', 'CC6.3']},
                                       'dread': {'D': 7,
                                                 'Disc': 5,
                                                 'E': 6,
                                                 'R': 8,
                                                 'why': 'Excessive OAuth scopes give an attacker standing access to '
                                                        'sensitive data.'},
                                       'drivers': {'improvements': ['Scope-review gate in the app-onboarding '
                                                                    'process'],
                                                   'infrastructure': ['Restrict delegated/app permissions to least '
                                                                      'privilege; block high-risk scopes'],
                                                   'investments': ['SSPM / OAuth governance']},
                                       'kc': (1, 'an over-scoped OAuth consent'),
                                       'remediation': ('Revoke the OAuth grant; require admin-consent for high-risk '
                                                       'scopes.',
                                                       'Identity')},
 'kerberoasting': {'asset_class': 'Active Directory',
                   'controls': {'iso27001': ['A.5.17', 'A.8.5'], 'soc2': ['CC6.1']},
                   'dread': {'D': 7,
                             'Disc': 6,
                             'E': 7,
                             'R': 9,
                             'why': 'Offline crackable service tickets yield credentials for lateral movement.'},
                   'drivers': {'improvements': ['gMSA migration; quarterly service-account audit'],
                               'infrastructure': ['Enforce AES-only Kerberos; 25+ char gMSA passwords; remove SPNs '
                                                  'from user accounts; Tier-0/1/2 admin model'],
                               'investments': ['Privileged Access Management (PAM)',
                                               'Identity Threat Detection & Response (ITDR)']},
                   'kc': (3, 'Kerberoasting of AD service accounts'),
                   'remediation': ('Reset the targeted service-account password and rotate krbtgt; enforce AES + '
                                   'long SPN passwords.',
                                   'Identity')},
 'lolbin_execution': {'asset_class': 'Endpoint / Windows',
                      'controls': {'iso27001': ['A.8.7'], 'soc2': ['CC7.2']},
                      'dread': {'D': 5,
                                'Disc': 7,
                                'E': 7,
                                'R': 8,
                                'why': 'Living-off-the-land evades signature controls.'},
                      'drivers': {'improvements': ['LOLBin hunting playbook'],
                                  'infrastructure': ['Application allow-listing; block/monitor known LOLBins'],
                                  'investments': ['EDR/XDR with behavioural detection']},
                      'kc': (5, 'living-off-the-land execution'),
                      'remediation': ('Isolate the host; review application-control policy for the abused binary.',
                                      'SOC')},
 'mcp_tool_abuse': {'asset_class': 'AI / Agent',
                    'controls': {'iso27001': ['A.8.16'], 'iso42001': ['A.6.2.4', 'A.9.2'], 'soc2': ['CC7.2']},
                    'dread': {'D': 7,
                              'Disc': 5,
                              'E': 6,
                              'R': 7,
                              'why': 'Agent tool-call abuse executes attacker intent via the AI layer.'},
                    'drivers': {'improvements': ['MCP tool-authorization policy and audit (ISO 42001)'],
                                'infrastructure': ['Scope agent/tool credentials; enforce tool-call authorization '
                                                   'and human-in-the-loop for high-risk tools'],
                                'investments': ['AI runtime security / agent guardrails']},
                    'kc': (5, 'AI agent tool-call abuse'),
                    'remediation': ('Revoke the agent/tool credentials; review MCP tool-call authorization policy.',
                                    'AppSec/AI')},
 'mfa_fatigue': {'controls': {'iso27001': ['A.5.17', 'A.8.5'], 'soc2': ['CC6.1']},
                 'dread': {'D': 6,
                           'Disc': 6,
                           'E': 8,
                           'R': 7,
                           'why': 'Low-skill MFA bombing yields an authenticated session.'},
                 'drivers': {'improvements': ['Sign-in-risk policy tuning; user MFA-bombing awareness'],
                             'infrastructure': ['Number-matching MFA; block legacy auth; sign-in risk conditional '
                                                'access'],
                             'investments': ['Phishing-resistant MFA (FIDO2 hardware keys)']},
                 'kc': (1, 'MFA fatigue'),
                 'remediation': ("Reset the account's credentials; enforce number-matching MFA; tighten sign-in risk "
                                 'policy.',
                                 'Identity')},
 'ntlm_relay_pth': {'asset_class': 'Active Directory',
                    'controls': {'iso27001': ['A.5.17', 'A.8.5', 'A.8.20'], 'soc2': ['CC6.1']},
                    'dread': {'D': 7,
                              'Disc': 5,
                              'E': 6,
                              'R': 7,
                              'why': 'Relayed/reused hashes authenticate as the victim.'},
                    'kc': (6, 'NTLM relay / pass-the-hash'),
                    'remediation': ('Reset the affected credentials; enforce SMB signing and disable NTLM where '
                                    'possible.',
                                    'Identity')},
 'oauth_device_code': {'asset_class': 'SaaS / M365',
                       'controls': {'iso27001': ['A.5.15', 'A.5.16', 'A.8.5'], 'soc2': ['CC6.1', 'CC6.7']},
                       'dread': {'D': 7,
                                 'Disc': 5,
                                 'E': 6,
                                 'R': 8,
                                 'why': 'OAuth consent grants durable app access to mail/files, bypassing MFA.'},
                       'drivers': {'improvements': ['Quarterly app-registration and consent-grant review'],
                                   'infrastructure': ['Disable end-user OAuth consent; require admin-consent '
                                                      'workflow for high-risk scopes'],
                                   'investments': ['SaaS Security Posture Management (SSPM) / OAuth app governance',
                                                   'IdP risk-based conditional access']},
                       'kc': (1, 'a malicious OAuth consent grant'),
                       'remediation': ('Revoke the malicious OAuth consent grant and audit app registrations for '
                                       'excessive scopes.',
                                       'Identity')},
 'powershell_staged_payload': {'asset_class': 'Endpoint / Windows',
                               'controls': {'iso27001': ['A.8.7', 'A.8.16'], 'soc2': ['CC7.2']},
                               'dread': {'D': 6,
                                         'Disc': 6,
                                         'E': 7,
                                         'R': 7,
                                         'why': 'Staged payloads execute attacker code on the host.'},
                               'drivers': {'improvements': ['PowerShell logging baseline and alerting'],
                                           'infrastructure': ['Application control (WDAC/AppLocker); PowerShell '
                                                              'constrained language mode; script-block + module '
                                                              'logging'],
                                           'investments': ['EDR/XDR']},
                               'kc': (5, 'staged PowerShell execution'),
                               'remediation': ('Isolate the host; capture PowerShell script-block logs; hunt for '
                                               'persistence.',
                                               'SOC')},
 'privilege_escalation_k8s': {'controls': {'iso27001': ['A.8.2', 'A.8.9'], 'soc2': ['CC6.3']},
                              'kc': (4, 'Kubernetes privilege escalation'),
                              'remediation': ('Revoke the escalated RBAC; review admission and RBAC policy.',
                                              'Cloud')},
 'ransomware_staging': {'controls': {'iso27001': ['A.8.7', 'A.8.13'], 'soc2': ['CC7.2']},
                        'dread': {'D': 10,
                                  'Disc': 5,
                                  'E': 6,
                                  'R': 6,
                                  'why': 'Staging precedes encryption - imminent business outage.'},
                        'drivers': {'improvements': ['Tested ransomware IR + recovery runbook'],
                                    'infrastructure': ['Immutable/offline backups; segmentation; application '
                                                       'control'],
                                    'investments': ['EDR/XDR with ransomware rollback', 'Immutable backup solution']},
                        'kc': (8, 'ransomware staging'),
                        'remediation': ('Isolate immediately; verify backups are offline and intact; begin IR '
                                        'playbook.',
                                        'SOC')},
 'secret_access': {'asset_class': 'Secrets / Cloud',
                   'controls': {'iso27001': ['A.5.17', 'A.8.24'], 'soc2': ['CC6.1']},
                   'dread': {'D': 8,
                             'Disc': 5,
                             'E': 6,
                             'R': 7,
                             'why': 'Secret-store access yields keys to further systems.'},
                   'drivers': {'improvements': ['Secret-rotation automation'],
                               'infrastructure': ['Centralised secret store with short-lived leases; rotate on '
                                                  'access; least-privilege policies'],
                               'investments': ['Secrets management platform', 'CSPM']},
                   'kc': (3, 'secret-store access'),
                   'remediation': ('Rotate the accessed secrets; audit secret-store access policy.',
                                   'Cloud/Identity')},
 'ses_leaked_key': {'controls': {'iso27001': ['A.5.17', 'A.8.12'], 'soc2': ['CC6.1', 'CC6.7']},
                    'dread': {'D': 7,
                              'Disc': 5,
                              'E': 7,
                              'R': 7,
                              'why': 'Leaked keys enable data access and mail abuse.'},
                    'remediation': ('Deactivate the leaked key; block the sending identity; assess data/abuse '
                                    'exposure.',
                                    'Cloud/Identity')},
 'shadow_copy_deletion': {'controls': {'iso27001': ['A.8.13', 'A.8.7'], 'soc2': ['CC7.2']},
                          'dread': {'D': 9,
                                    'Disc': 6,
                                    'E': 6,
                                    'R': 6,
                                    'why': 'Backup destruction removes recovery options before impact.'},
                          'kc': (8, 'backup destruction'),
                          'remediation': ('Isolate immediately; assume ransomware; verify offline backups.', 'SOC')},
 'sharepoint_bulk_download': {'controls': {'iso27001': ['A.8.12', 'A.5.14'], 'soc2': ['CC6.7']},
                              'dread': {'D': 8,
                                        'Disc': 4,
                                        'E': 6,
                                        'R': 6,
                                        'why': 'Mass document download from collaboration store.'},
                              'kc': (9, 'mass document download'),
                              'remediation': ('Revoke the session; restrict the affected library; quantify data '
                                              'exposure.',
                                              'SOC/DLP')},
 'sim_swap': {'controls': {'iso27001': ['A.5.17', 'A.8.5'], 'soc2': ['CC6.1']},
              'dread': {'D': 6, 'Disc': 6, 'E': 6, 'R': 5, 'why': 'Number porting defeats SMS MFA.'},
              'kc': (1, 'a SIM swap'),
              'remediation': ('Move the account off SMS MFA to a phishing-resistant factor; verify with the carrier.',
                              'Identity')},
 'wmi_dcom_lateral': {'asset_class': 'Endpoint / Windows',
                      'controls': {'iso27001': ['A.8.20', 'A.8.22'], 'soc2': ['CC6.6', 'CC7.2']},
                      'dread': {'D': 6,
                                'Disc': 5,
                                'E': 7,
                                'R': 8,
                                'why': 'Remote WMI/DCOM execution spreads the intrusion host-to-host.'},
                      'drivers': {'improvements': ['Just-in-time admin access'],
                                  'infrastructure': ['East-west microsegmentation; restrict WMI/DCOM to admin jump '
                                                     'hosts; host firewall deny-by-default'],
                                  'investments': ['Microsegmentation platform', 'EDR/XDR']},
                      'kc': (6, 'WMI lateral movement'),
                      'remediation': ('Isolate the source and destination hosts; audit WMI/DCOM remote-exec '
                                      'permissions.',
                                      'SOC')}}

# Local override / extension point - merged over PHASE_KNOWLEDGE.
_EXTRA: dict = {
    # ── Detectors that were entirely unmapped ────────────────────────────────
    "firewall_threat": {
        "controls": {"iso27001": ["A.8.20", "A.8.16"], "soc2": ["CC6.6", "CC7.2"]},
        "remediation": ("Review the firewall/IPS block; confirm the source is contained and hunt for other ingress.", "SOC"),
        "dread": {"D": 5, "R": 6, "E": 6, "Disc": 6, "why": "A perimeter block indicates an attempted intrusion."},
        "drivers": {"infrastructure": ["Tune IPS/firewall rules; deny-by-default ingress"], "investments": ["NGFW/IPS", "Network Detection & Response (NDR)"], "improvements": ["Perimeter rule review"]},
        "asset_class": "Network", "kc": (1, "a perimeter intrusion attempt"),
    },
    "identity_ip_anomaly": {
        "controls": {"iso27001": ["A.5.17", "A.8.16"], "soc2": ["CC6.1", "CC7.2"]},
        "remediation": ("Verify the sign-in location/device; challenge or reset the account if unrecognised.", "Identity"),
        "dread": {"D": 5, "R": 6, "E": 6, "Disc": 6, "why": "Sign-in from an anomalous location may indicate account takeover."},
        "drivers": {"infrastructure": ["Risk-based conditional access; impossible-travel policy"], "investments": ["ITDR", "IdP risk-based policies"], "improvements": ["Sign-in-risk tuning"]},
        "asset_class": "Cloud IdP", "kc": (1, "an anomalous-location sign-in"),
    },
    "ike_vpn_exploit": {
        "controls": {"iso27001": ["A.8.20", "A.8.9"], "soc2": ["CC6.6"]},
        "remediation": ("Patch the VPN/IKE appliance; rotate pre-shared keys and credentials; hunt for ingress.", "SOC"),
        "dread": {"D": 8, "R": 6, "E": 6, "Disc": 5, "why": "VPN/IKE exploitation grants network ingress."},
        "drivers": {"infrastructure": ["Patch VPN appliances; enforce MFA on VPN; restrict IKE"], "investments": ["Remote-access hardening", "NDR"], "improvements": ["Appliance patch cadence"]},
        "asset_class": "Network", "kc": (1, "a VPN/IKE exploit"),
    },
    "insider_after_hours": {
        "controls": {"iso27001": ["A.5.15", "A.8.16"], "soc2": ["CC6.1", "CC7.2"]},
        "remediation": ("Verify the access was authorised; review with the user/manager; check DLP for exfiltration.", "Identity"),
        "dread": {"D": 6, "R": 6, "E": 5, "Disc": 6, "why": "Off-hours sensitive access may indicate insider risk or account misuse."},
        "drivers": {"infrastructure": ["UEBA baselining; sensitive-data access logging"], "investments": ["Insider-risk / UEBA platform", "DLP"], "improvements": ["Access-review cadence"]},
        "asset_class": "Data", "kc": (2, "after-hours sensitive-data access"),
    },
    "pentest_escalation": {
        "remediation": ("Confirm the activity is within the sanctioned pentest scope; otherwise treat as a real escalation.", "SOC"),
        "dread": {"D": 3, "R": 5, "E": 5, "Disc": 5, "why": "Sanctioned pentest escalation (benign if in scope)."},
        "drivers": {"infrastructure": ["Track sanctioned-pentest scope and windows"], "investments": [], "improvements": ["Pentest deconfliction process"]},
        "asset_class": "Endpoint / Windows", "kc": (4, "privilege escalation (pentest context)"),
    },
    "dlp_exfil": {
        "controls": {"iso27001": ["A.8.12", "A.5.14"], "soc2": ["CC6.7"]},
        "remediation": ("Block the egress path; quantify data exposure; trigger breach-notification assessment.", "SOC/DLP"),
        "dread": {"D": 8, "R": 6, "E": 6, "Disc": 4, "why": "DLP-detected exfiltration of sensitive data."},
        "drivers": {"infrastructure": ["Egress filtering; enforce DLP policy"], "investments": ["DLP", "CASB"], "improvements": ["Data classification"]},
        "asset_class": "Data", "kc": (9, "DLP-flagged data exfiltration"),
    },
    "session_theft": {
        "controls": {"iso27001": ["A.5.17", "A.8.5"], "soc2": ["CC6.1"]},
        "remediation": ("Revoke the stolen session tokens; reset credentials; enforce token-binding / continuous access evaluation.", "Identity"),
        "dread": {"D": 7, "R": 7, "E": 6, "Disc": 5, "why": "Session/token theft authenticates as the victim, bypassing MFA."},
        "drivers": {"infrastructure": ["Continuous access evaluation; token binding; short token TTLs"], "investments": ["Phishing-resistant MFA (FIDO2)"], "improvements": ["Session-revocation runbook"]},
        "asset_class": "Cloud IdP", "kc": (3, "session/token theft"),
    },
    # ── Fill missing dimensions on partially-mapped detectors ─────────────────
    "ad_recon_discovery": {"drivers": {"infrastructure": ["Restrict AD enumeration; deploy honeytokens"], "investments": ["ITDR"], "improvements": ["Recon-detection tuning"]}},
    "aitm_session": {"asset_class": "Cloud IdP"},
    "cloud_iam_privesc": {"drivers": {"infrastructure": ["Least-privilege IAM; permission boundaries; SCPs"], "investments": ["CIEM", "CSPM"], "improvements": ["IAM policy review"]}},
    "credential_theft": {"drivers": {"infrastructure": ["Credential Guard; LSASS protection; tiered admin"], "investments": ["EDR/XDR"], "improvements": ["Credential-hygiene review"]}},
    "data_exfiltration_rclone": {"drivers": {"infrastructure": ["Egress allow-listing; block cloud-sync tools"], "investments": ["DLP", "CASB"], "improvements": ["Egress baselining"]}, "asset_class": "Cloud Data"},
    "data_exfiltration_snowflake": {"drivers": {"infrastructure": ["DB egress controls; network policies; query monitoring"], "investments": ["DLP", "Cloud DSPM"], "improvements": ["Database access review"]}, "asset_class": "Cloud Data"},
    "email_external_exfil": {"drivers": {"infrastructure": ["Block external auto-forwarding; DLP on mail"], "investments": ["Email security gateway / ICES", "DLP"], "improvements": ["Mail-flow rule review"]}},
    "entra_privesc": {"drivers": {"infrastructure": ["PIM / just-in-time roles; restrict role assignment"], "investments": ["ITDR", "PAM"], "improvements": ["Privileged-role review"]}},
    "esxi_ransomware": {"asset_class": "Virtualization"},
    "helpdesk_anomalous_reset": {"drivers": {"infrastructure": ["Strong identity-proofing for resets; callback verification"], "investments": ["ITDR"], "improvements": ["Helpdesk verification procedure"]}, "asset_class": "Cloud IdP"},
    "mfa_fatigue": {"asset_class": "Cloud IdP"},
    "ntlm_relay_pth": {"drivers": {"infrastructure": ["Enforce SMB signing; disable NTLM; LDAP channel binding"], "investments": ["ITDR"], "improvements": ["NTLM-usage audit"]}},
    "privilege_escalation_k8s": {"dread": {"D": 8, "R": 6, "E": 6, "Disc": 5, "why": "Kubernetes RBAC escalation can grant cluster control."}, "drivers": {"infrastructure": ["Restrict RBAC; admission control (OPA/Kyverno); pod security"], "investments": ["CWPP", "Kubernetes security platform"], "improvements": ["RBAC review"]}, "asset_class": "Kubernetes"},
    "ransomware_staging": {"asset_class": "Endpoint / Windows"},
    "ses_leaked_key": {"drivers": {"infrastructure": ["Rotate/scope keys; restrict SES sending identities"], "investments": ["CSPM", "Secrets management"], "improvements": ["Key-rotation automation"]}, "asset_class": "Cloud / Email", "kc": (3, "leaked cloud-key abuse")},
    "shadow_copy_deletion": {"drivers": {"infrastructure": ["Protect VSS; immutable/offline backups; block vssadmin"], "investments": ["EDR with ransomware rollback", "Immutable backup"], "improvements": ["Backup-integrity testing"]}, "asset_class": "Endpoint / Windows"},
    "sharepoint_bulk_download": {"drivers": {"infrastructure": ["Throttle/alert bulk downloads; sensitivity labels"], "investments": ["DLP", "SSPM"], "improvements": ["Collaboration data governance"]}, "asset_class": "SaaS / M365"},
    "sim_swap": {"drivers": {"infrastructure": ["Move off SMS MFA; carrier port-freeze"], "investments": ["Phishing-resistant MFA (FIDO2)"], "improvements": ["MFA-factor policy"]}, "asset_class": "Identity"},
}
for _k, _v in _EXTRA.items():
    PHASE_KNOWLEDGE.setdefault(_k, {}).update(_v)

# Canonical provider-neutral milestone.  Keep the M365-specific key above as a
# read alias for historical assessments and exported packs.
PHASE_KNOWLEDGE["cloud_object_collection"] = {
    **PHASE_KNOWLEDGE["sharepoint_bulk_download"],
    "asset_class": "Cloud object / SaaS data",
    "drivers": {
        "infrastructure": ["Throttle and alert bulk object reads; classify sensitive objects"],
        "investments": ["DLP", "CSPM/SSPM"],
        "improvements": ["Provider-neutral cloud data governance"],
    },
}

# Outbound writes/uploads are not collection.  This milestone is produced by a
# long-horizon aggregate only when its contributing evidence rows are retained.
PHASE_KNOWLEDGE["cloud_object_exfiltration"] = {
    **PHASE_KNOWLEDGE["sharepoint_bulk_download"],
    "asset_class": "Cloud object / SaaS data",
    "drivers": {
        "infrastructure": ["Restrict outbound object destinations and verify tenant ownership"],
        "investments": ["DLP", "CASB/SSE"],
        "improvements": ["Destination-aware egress baselines and cumulative transfer monitoring"],
    },
}

PHASE_KNOWLEDGE["kerberos_ticket_forgery"] = {
    **PHASE_KNOWLEDGE["kerberoasting"],
    "asset_class": "Active Directory / Identity",
    "dread": {
        "D": 9, "R": 9, "E": 8, "Disc": 4,
        "why": "Forged long-lived Kerberos tickets can preserve privileged domain access after ordinary credential rotation.",
    },
    "kc": (5, "forged Kerberos ticket persistence"),
    "remediation": (
        "Preserve domain-controller evidence, reset KRBTGT twice using the approved recovery sequence, and invalidate active tickets.",
        "Identity / Incident Response",
    ),
    "drivers": {
        "infrastructure": ["Reset KRBTGT twice using the approved domain recovery sequence; invalidate forged tickets"],
        "investments": ["ITDR", "Privileged access management"],
        "improvements": ["Kerberos encryption hardening and anomalous ticket-option monitoring"],
    },
}

DEFAULT_DREAD = {"D": 5, "R": 5, "E": 5, "Disc": 5, "why": "Confirmed malicious activity of undetermined technique."}
DEFAULT_DRIVERS = {
    "infrastructure": ["Contain the affected entities; apply least privilege and segmentation to the blast radius"],
    "investments": ["EDR/XDR", "ITDR"],
    "improvements": ["Post-incident control review"],
}
DEFAULT_REMEDIATION = ("Investigate and contain the affected entities; preserve forensic evidence.", "SOC")

_DIMENSIONS = ("controls", "remediation", "dread", "drivers", "asset_class", "kc")


def _get(phase, key):
    return (PHASE_KNOWLEDGE.get(str(phase)) or {}).get(key)


def controls(phase) -> dict:
    return _get(phase, "controls") or {}


def remediation(phase) -> Optional[tuple]:
    return _get(phase, "remediation")


def dread(phase) -> dict:
    return _get(phase, "dread") or DEFAULT_DREAD


def drivers(phase) -> Optional[dict]:
    return _get(phase, "drivers")


def asset_class(phase) -> Optional[str]:
    return _get(phase, "asset_class")


def kc(phase) -> Optional[tuple]:
    return _get(phase, "kc")


def known_phases() -> set:
    return set(PHASE_KNOWLEDGE)


def coverage(phases) -> dict:
    gaps: dict = {}
    for p in {str(x) for x in (phases or [])}:
        entry = PHASE_KNOWLEDGE.get(p) or {}
        for dim in _DIMENSIONS:
            if not entry.get(dim):
                gaps.setdefault(dim, []).append(p)
    unmapped = sorted({p for ps in gaps.values() for p in ps})
    return {"unmapped_by_dimension": {k: sorted(v) for k, v in gaps.items()}, "unmapped_phases": unmapped}
