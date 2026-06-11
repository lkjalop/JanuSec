"""Factor → Compliance Framework Control Matrix.

Maps Janusec internal factor strings to control violations across:
    - CIS Controls v8
    - NIST CSF 2.0 (Identify / Protect / Detect / Respond / Recover)
    - ISO/IEC 27001:2022 (Annex A controls)
    - SOC 2 Type II (Trust Service Criteria)
    - PCI-DSS v4.0 (requirements)
    - HIPAA Security Rule (45 CFR Part 164)
    - GDPR (Articles and Recitals)
    - FedRAMP / NIST 800-53 (control families)

Each factor maps to a dict with keys per framework containing list of control IDs.
Absence of a framework key means no relevant control mapping.

Usage:
    from src.core.mappings.factor_to_compliance import get_compliance_hits
    hits = get_compliance_hits(['endpoint:persistence_reg_run', 'email:bec_replyto_mismatch'])
    # hits = {
    #     'cis': ['CIS-10.1', 'CIS-13.1'],
    #     'nist_csf': ['DE.CM-1', 'PR.MA-2'],
    #     'iso27001': ['A.8.8', 'A.8.15'],
    #     'soc2': ['CC6.1', 'CC7.2'],
    #     'pci_dss': ['Req 5.3', 'Req 10.2'],
    #     'hipaa': ['164.312(b)'],
    #     'gdpr': ['Art.32'],
    #     'nist_800_53': ['SI-3', 'AU-2'],
    # }
"""
from __future__ import annotations

from typing import Dict, List, Any

# ---------------------------------------------------------------------------
# Core compliance mapping table
# ---------------------------------------------------------------------------
# Format: factor_name → {framework: [control_ids]}
# Partial matches: if an entry starts with 'email:' or 'endpoint:', it will
# match any factor with that prefix (done in get_compliance_hits).

FACTOR_TO_COMPLIANCE: Dict[str, Dict[str, List[str]]] = {

    # =========================================================================
    # EMAIL THREAT FACTORS
    # =========================================================================

    'email:T1114.003_inbox_rule': {
        'cis':          ['CIS-8.5', 'CIS-8.11'],
        'nist_csf':     ['DE.CM-3', 'PR.AA-1'],
        'iso27001':     ['A.5.15', 'A.8.15', 'A.8.16'],
        'soc2':         ['CC6.1', 'CC7.2', 'CC7.3'],
        'nist_800_53':  ['AC-2', 'AU-6', 'SI-4'],
    },

    'email:inbox_rule_external_forward': {
        'cis':          ['CIS-8.5', 'CIS-13.1'],
        'nist_csf':     ['DE.CM-3', 'PR.DS-5'],
        'iso27001':     ['A.5.15', 'A.8.12', 'A.8.15', 'A.8.16'],
        'soc2':         ['CC6.1', 'CC7.2', 'CC7.3'],
        'nist_800_53':  ['AC-2', 'AU-6', 'SI-4'],
    },

    'data:sensitive_file_access': {
        'cis':          ['CIS-3.3', 'CIS-3.7', 'CIS-13.1'],
        'nist_csf':     ['PR.DS-1', 'PR.DS-5', 'DE.CM-1'],
        'iso27001':     ['A.5.12', 'A.5.13', 'A.8.12', 'A.8.15'],
        'soc2':         ['CC6.1', 'CC6.7', 'CC7.2'],
        'nist_800_53':  ['AC-4', 'AU-6', 'SI-4'],
    },

    'identity:ml_risk_spike': {
        'cis':          ['CIS-5.2', 'CIS-6.5', 'CIS-8.11'],
        'nist_csf':     ['DE.CM-1', 'DE.CM-3', 'PR.AA-1'],
        'iso27001':     ['A.5.15', 'A.5.16', 'A.8.15', 'A.8.16'],
        'soc2':         ['CC6.1', 'CC7.2', 'CC7.3'],
        'nist_800_53':  ['AC-2', 'AU-6', 'SI-4'],
    },

    'email:url_entropy_high': {
        'cis':          ['CIS-9.6', 'CIS-13.4'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.23', 'A.8.16'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.4', 'Req 10.7'],
        'nist_800_53':  ['SI-3', 'AU-12'],
    },

    'email:url_homoglyph': {
        'cis':          ['CIS-9.5', 'CIS-9.6'],
        'nist_csf':     ['DE.CM-1', 'PR.AT-1'],
        'iso27001':     ['A.8.23', 'A.6.3'],
        'soc2':         ['CC6.1', 'CC6.2'],
        'pci_dss':      ['Req 5.4.1', 'Req 12.6'],
        'hipaa':        ['164.308(a)(5)'],
        'nist_800_53':  ['SI-3', 'AT-2'],
    },

    'email:url_redirect_chain': {
        'cis':          ['CIS-9.6', 'CIS-13.4'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.23'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.4'],
        'nist_800_53':  ['SI-3', 'SC-18'],
    },

    'email:url_fresh_domain': {
        'cis':          ['CIS-9.6'],
        'nist_csf':     ['DE.CM-1'],
        'iso27001':     ['A.8.23'],
        'soc2':         ['CC6.1'],
        'pci_dss':      ['Req 5.4.1'],
        'nist_800_53':  ['SI-3'],
    },

    'email:url_dga_candidate': {
        'cis':          ['CIS-9.6', 'CIS-13.4'],
        'nist_csf':     ['DE.CM-1', 'DE.CM-7'],
        'iso27001':     ['A.8.23', 'A.8.16'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 10.7.2'],
        'nist_800_53':  ['SI-3', 'SC-44'],
    },

    'email:attachment_double_ext': {
        'cis':          ['CIS-9.4', 'CIS-10.1'],
        'nist_csf':     ['DE.CM-1', 'PR.DS-2'],
        'iso27001':     ['A.8.7', 'A.8.23'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.2', 'Req 5.4.1'],
        'hipaa':        ['164.312(b)'],
        'nist_800_53':  ['SI-3', 'SI-16'],
    },

    'email:attachment_zip_bomb': {
        'cis':          ['CIS-9.4', 'CIS-13.1'],
        'nist_csf':     ['DE.CM-1', 'PR.DS-2'],
        'iso27001':     ['A.8.7'],
        'soc2':         ['CC6.1', 'A1.1'],
        'pci_dss':      ['Req 5.3.4', 'Req 6.4.3'],
        'nist_800_53':  ['SI-3', 'SC-5'],
    },

    'email:attachment_ole_macro': {
        'cis':          ['CIS-9.4', 'CIS-10.1', 'CIS-2.7'],
        'nist_csf':     ['DE.CM-1', 'PR.DS-2', 'PR.PT-3'],
        'iso27001':     ['A.8.7', 'A.8.9'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.2', 'Req 5.4.1', 'Req 6.3.3'],
        'hipaa':        ['164.312(b)', '164.308(a)(1)'],
        'gdpr':         ['Art.32'],
        'nist_800_53':  ['SI-3', 'SI-7', 'CM-7'],
    },

    'email:attachment_rtf_exploit': {
        'cis':          ['CIS-9.4', 'CIS-7.4'],
        'nist_csf':     ['DE.CM-1', 'RS.MI-1'],
        'iso27001':     ['A.8.7', 'A.8.8'],
        'soc2':         ['CC6.1', 'CC7.3'],
        'pci_dss':      ['Req 5.3.2', 'Req 6.3.2'],
        'nist_800_53':  ['SI-3', 'SI-2'],
    },

    'email:attachment_html_smuggling': {
        'cis':          ['CIS-9.4', 'CIS-9.6'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.7', 'A.8.23'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.4', 'Req 5.4.1'],
        'nist_800_53':  ['SI-3', 'SC-18'],
    },

    'email:attachment_lnk_target': {
        'cis':          ['CIS-9.4', 'CIS-10.1'],
        'nist_csf':     ['DE.CM-1'],
        'iso27001':     ['A.8.7'],
        'soc2':         ['CC6.1'],
        'pci_dss':      ['Req 5.3.2'],
        'nist_800_53':  ['SI-3'],
    },

    'email:bec_sender_anomaly': {
        'cis':          ['CIS-9.5', 'CIS-6.5'],
        'nist_csf':     ['DE.CM-3', 'PR.AT-1'],
        'iso27001':     ['A.8.16', 'A.6.3'],
        'soc2':         ['CC6.1', 'CC6.2'],
        'pci_dss':      ['Req 12.6.3', 'Req 10.7'],
        'hipaa':        ['164.308(a)(5)'],
        'nist_800_53':  ['AU-6', 'AT-2'],
    },

    'email:bec_replyto_mismatch': {
        'cis':          ['CIS-9.5'],
        'nist_csf':     ['DE.CM-1', 'PR.AT-1'],
        'iso27001':     ['A.8.23', 'A.6.3'],
        'soc2':         ['CC6.1'],
        'pci_dss':      ['Req 12.6.3'],
        'hipaa':        ['164.308(a)(5)'],
        'nist_800_53':  ['SI-3', 'AT-2'],
    },

    'email:bec_first_contact': {
        'cis':          ['CIS-9.5', 'CIS-6.5'],
        'nist_csf':     ['DE.CM-3'],
        'iso27001':     ['A.8.16'],
        'soc2':         ['CC6.2', 'CC7.2'],
        'pci_dss':      ['Req 10.7'],
        'nist_800_53':  ['AU-6'],
    },

    'email:bec_display_name_spoof': {
        'cis':          ['CIS-9.5', 'CIS-6.5'],
        'nist_csf':     ['DE.CM-1', 'PR.AT-1'],
        'iso27001':     ['A.8.23', 'A.6.3'],
        'soc2':         ['CC6.1', 'CC6.2'],
        'pci_dss':      ['Req 12.6.3'],
        'hipaa':        ['164.308(a)(5)'],
        'nist_800_53':  ['SI-3', 'AT-2'],
    },

    'email:bec_urgency_pressure': {
        'cis':          ['CIS-9.5', 'CIS-14.1'],
        'nist_csf':     ['PR.AT-1'],
        'iso27001':     ['A.6.3'],
        'soc2':         ['CC1.4'],
        'pci_dss':      ['Req 12.6.3'],
        'hipaa':        ['164.308(a)(5)'],
        'nist_800_53':  ['AT-2'],
    },

    'email:bec_lookalike_advanced': {
        'cis':          ['CIS-9.5', 'CIS-9.6'],
        'nist_csf':     ['DE.CM-1', 'PR.AT-1'],
        'iso27001':     ['A.8.23', 'A.6.3'],
        'soc2':         ['CC6.1'],
        'pci_dss':      ['Req 12.6.3', 'Req 5.4.1'],
        'nist_800_53':  ['SI-3', 'AT-2'],
    },

    # =========================================================================
    # ENDPOINT — PROCESS TREE
    # =========================================================================

    'endpoint:process_tree_anomaly': {
        'cis':          ['CIS-10.1', 'CIS-13.1', 'CIS-8.2'],
        'nist_csf':     ['DE.CM-1', 'DE.AE-2', 'PR.PT-3'],
        'iso27001':     ['A.8.15', 'A.8.16', 'A.8.9'],
        'soc2':         ['CC7.2', 'CC7.3'],
        'pci_dss':      ['Req 5.3.4', 'Req 10.7.1', 'Req 11.5'],
        'hipaa':        ['164.312(b)', '164.308(a)(1)'],
        'gdpr':         ['Art.32'],
        'nist_800_53':  ['SI-3', 'AU-2', 'CM-7'],
    },

    'endpoint:cmdline_rarity_high': {
        'cis':          ['CIS-10.1', 'CIS-8.2'],
        'nist_csf':     ['DE.CM-1', 'DE.AE-3'],
        'iso27001':     ['A.8.15', 'A.8.16'],
        'soc2':         ['CC7.2'],
        'pci_dss':      ['Req 10.7.1'],
        'nist_800_53':  ['AU-2', 'SI-4'],
    },

    'endpoint:orphan_process': {
        'cis':          ['CIS-10.1', 'CIS-13.1'],
        'nist_csf':     ['DE.CM-1', 'DE.AE-2'],
        'iso27001':     ['A.8.15', 'A.8.16'],
        'soc2':         ['CC7.2', 'CC7.3'],
        'pci_dss':      ['Req 10.7.1'],
        'nist_800_53':  ['SI-3', 'AU-2'],
    },

    'endpoint:process_depth_spike': {
        'cis':          ['CIS-10.1'],
        'nist_csf':     ['DE.CM-1'],
        'iso27001':     ['A.8.15'],
        'soc2':         ['CC7.2'],
        'pci_dss':      ['Req 10.7.1'],
        'nist_800_53':  ['SI-3'],
    },

    'endpoint:lolbin_child_unusual': {
        'cis':          ['CIS-10.1', 'CIS-2.7', 'CIS-16.1'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.9', 'A.8.15'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.4', 'Req 6.3.3'],
        'hipaa':        ['164.312(b)'],
        'nist_800_53':  ['SI-3', 'CM-7'],
    },

    'endpoint:process_masquerade': {
        'cis':          ['CIS-10.1', 'CIS-4.1'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.9', 'A.8.15'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.4', 'Req 11.5'],
        'nist_800_53':  ['SI-3', 'CM-7', 'SI-7'],
    },

    # =========================================================================
    # ENDPOINT — PERSISTENCE
    # =========================================================================

    'endpoint:persistence_reg_run': {
        'cis':          ['CIS-10.1', 'CIS-4.1'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.9', 'A.8.15'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.4', 'Req 6.3.3', 'Req 11.5'],
        'hipaa':        ['164.312(b)'],
        'nist_800_53':  ['SI-3', 'CM-7'],
    },

    'endpoint:persistence_service_new': {
        'cis':          ['CIS-10.1', 'CIS-4.1', 'CIS-5.4'],
        'nist_csf':     ['DE.CM-1', 'PR.IP-1'],
        'iso27001':     ['A.8.9', 'A.8.32'],
        'soc2':         ['CC6.1', 'CC8.1'],
        'pci_dss':      ['Req 6.3.3', 'Req 11.5'],
        'nist_800_53':  ['CM-7', 'SI-3', 'CM-8'],
    },

    'endpoint:persistence_task_new': {
        'cis':          ['CIS-10.1', 'CIS-4.1'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.9', 'A.8.15'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.4', 'Req 6.3.3'],
        'nist_800_53':  ['SI-3', 'CM-7'],
    },

    'endpoint:persistence_wmi_sub': {
        'cis':          ['CIS-10.1', 'CIS-4.8'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.9'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.4'],
        'nist_800_53':  ['SI-3', 'CM-7'],
    },

    'endpoint:persistence_ifeo': {
        'cis':          ['CIS-10.1', 'CIS-4.1'],
        'nist_csf':     ['DE.CM-1'],
        'iso27001':     ['A.8.9'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.4'],
        'nist_800_53':  ['SI-3', 'CM-7'],
    },

    'endpoint:persistence_dll_search': {
        'cis':          ['CIS-10.1', 'CIS-2.7'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.9', 'A.8.7'],
        'soc2':         ['CC6.1'],
        'pci_dss':      ['Req 6.3.3'],
        'nist_800_53':  ['SI-3', 'CM-7'],
    },

    'endpoint:persistence_bootkit': {
        'cis':          ['CIS-10.1', 'CIS-3.6'],
        'nist_csf':     ['DE.CM-1', 'PR.IP-3'],
        'iso27001':     ['A.8.7', 'A.8.9'],
        'soc2':         ['CC7.2', 'CC7.3'],
        'pci_dss':      ['Req 11.5.1', 'Req 5.3.4'],
        'nist_800_53':  ['SI-3', 'SI-7', 'SC-34'],
    },

    'endpoint:persistence_burst': {
        'cis':          ['CIS-10.1', 'CIS-13.1'],
        'nist_csf':     ['DE.CM-1', 'DE.AE-2'],
        'iso27001':     ['A.8.15', 'A.8.16'],
        'soc2':         ['CC7.2', 'CC7.3'],
        'pci_dss':      ['Req 11.5.1', 'Req 10.7'],
        'hipaa':        ['164.312(b)'],
        'nist_800_53':  ['SI-3', 'AU-6'],
    },

    'endpoint:persistence_novel': {
        'cis':          ['CIS-10.1', 'CIS-4.1'],
        'nist_csf':     ['DE.CM-1', 'DE.AE-1'],
        'iso27001':     ['A.8.9', 'A.8.16'],
        'soc2':         ['CC7.2'],
        'pci_dss':      ['Req 11.5'],
        'nist_800_53':  ['CM-7', 'AU-6'],
    },

    'endpoint:persistence_ld_preload': {
        'cis':          ['CIS-10.1', 'CIS-2.7'],
        'nist_csf':     ['DE.CM-1'],
        'iso27001':     ['A.8.9'],
        'soc2':         ['CC6.1'],
        'pci_dss':      ['Req 6.3.3'],
        'nist_800_53':  ['CM-7', 'SI-3'],
    },

    'endpoint:persistence_profile_mod': {
        'cis':          ['CIS-10.1', 'CIS-5.4'],
        'nist_csf':     ['DE.CM-1', 'PR.AC-4'],
        'iso27001':     ['A.8.9', 'A.5.15'],
        'soc2':         ['CC6.1', 'CC6.3'],
        'pci_dss':      ['Req 6.3.3', 'Req 7.2'],
        'nist_800_53':  ['CM-7', 'AC-3'],
    },

    # =========================================================================
    # ADVANCED THREATS — FILELESS
    # =========================================================================

    'endpoint:fileless_reflective_load': {
        'cis':          ['CIS-10.1', 'CIS-13.1', 'CIS-8.2'],
        'nist_csf':     ['DE.CM-1', 'DE.AE-2'],
        'iso27001':     ['A.8.7', 'A.8.15'],
        'soc2':         ['CC7.2', 'CC7.3'],
        'pci_dss':      ['Req 5.3.4', 'Req 11.5.1'],
        'hipaa':        ['164.312(b)'],
        'nist_800_53':  ['SI-3', 'SI-16', 'AU-2'],
    },

    'endpoint:fileless_process_hollow': {
        'cis':          ['CIS-10.1', 'CIS-8.2'],
        'nist_csf':     ['DE.CM-1', 'DE.AE-2'],
        'iso27001':     ['A.8.7', 'A.8.15'],
        'soc2':         ['CC7.2', 'CC7.3'],
        'pci_dss':      ['Req 5.3.4'],
        'nist_800_53':  ['SI-3', 'SI-16'],
    },

    'endpoint:fileless_shellcode_alloc': {
        'cis':          ['CIS-10.1'],
        'nist_csf':     ['DE.CM-1'],
        'iso27001':     ['A.8.7'],
        'soc2':         ['CC7.2'],
        'pci_dss':      ['Req 5.3.4'],
        'nist_800_53':  ['SI-3'],
    },

    # =========================================================================
    # ADVANCED THREATS — eBPF / KERNEL
    # =========================================================================

    'endpoint:ebpf_prog_load_unusual': {
        'cis':          ['CIS-10.1', 'CIS-4.8'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.9', 'A.8.15'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.4', 'Req 6.3.3'],
        'nist_800_53':  ['CM-7', 'SI-3'],
    },

    'endpoint:kernel_module_novel': {
        'cis':          ['CIS-10.1', 'CIS-2.7'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.9'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 6.3.3', 'Req 11.5'],
        'nist_800_53':  ['CM-7', 'SI-7'],
    },

    'endpoint:kernel_symbol_hook': {
        'cis':          ['CIS-10.1', 'CIS-4.1'],
        'nist_csf':     ['DE.CM-1'],
        'iso27001':     ['A.8.9'],
        'soc2':         ['CC7.2', 'CC7.3'],
        'pci_dss':      ['Req 11.5.1'],
        'nist_800_53':  ['SI-7', 'SI-3'],
    },

    # =========================================================================
    # ADVANCED THREATS — STEGANOGRAPHY
    # =========================================================================

    'endpoint:steg_tool_execution': {
        'cis':          ['CIS-13.1', 'CIS-9.4'],
        'nist_csf':     ['DE.CM-1', 'PR.DS-5'],
        'iso27001':     ['A.8.12', 'A.8.16'],
        'soc2':         ['CC7.2', 'CC6.7'],
        'pci_dss':      ['Req 12.5', 'Req 10.7'],
        'hipaa':        ['164.312(e)(2)'],
        'gdpr':         ['Art.32'],
        'nist_800_53':  ['SI-4', 'AU-2'],
    },

    'endpoint:steg_image_entropy_flat': {
        'cis':          ['CIS-13.1'],
        'nist_csf':     ['DE.CM-1'],
        'iso27001':     ['A.8.12'],
        'soc2':         ['CC7.2'],
        'pci_dss':      ['Req 12.5'],
        'nist_800_53':  ['SI-4'],
    },

    # =========================================================================
    # ADVANCED THREATS — SUPPLY CHAIN
    # =========================================================================

    'endpoint:npm_postinstall_exec': {
        'cis':          ['CIS-2.3', 'CIS-16.1', 'CIS-16.6'],
        'nist_csf':     ['DE.CM-1', 'ID.SC-4', 'PR.IP-2'],
        'iso27001':     ['A.8.30', 'A.5.19', 'A.8.8'],
        'soc2':         ['CC9.2', 'CC6.1'],
        'pci_dss':      ['Req 6.3.2', 'Req 12.8'],
        'nist_800_53':  ['SA-12', 'SI-7', 'CM-7'],
    },

    'endpoint:pip_setup_exec': {
        'cis':          ['CIS-2.3', 'CIS-16.1'],
        'nist_csf':     ['DE.CM-1', 'ID.SC-4'],
        'iso27001':     ['A.8.30', 'A.5.19'],
        'soc2':         ['CC9.2'],
        'pci_dss':      ['Req 6.3.2', 'Req 12.8'],
        'nist_800_53':  ['SA-12', 'SI-7'],
    },

    'endpoint:build_tool_network': {
        'cis':          ['CIS-16.1', 'CIS-13.4'],
        'nist_csf':     ['DE.CM-1', 'ID.SC-4'],
        'iso27001':     ['A.8.30', 'A.5.19', 'A.8.16'],
        'soc2':         ['CC9.2', 'CC7.2'],
        'pci_dss':      ['Req 12.8', 'Req 10.7'],
        'nist_800_53':  ['SA-12', 'AU-2'],
    },

    'endpoint:ci_runner_escalation': {
        'cis':          ['CIS-5.4', 'CIS-16.6'],
        'nist_csf':     ['PR.AC-4', 'ID.SC-4'],
        'iso27001':     ['A.5.15', 'A.8.30', 'A.8.18'],
        'soc2':         ['CC6.3', 'CC9.2'],
        'pci_dss':      ['Req 7.2', 'Req 12.8'],
        'nist_800_53':  ['AC-6', 'SA-12'],
    },

    'endpoint:dev_tool_modified': {
        'cis':          ['CIS-16.1', 'CIS-2.3'],
        'nist_csf':     ['ID.SC-4', 'DE.CM-1'],
        'iso27001':     ['A.8.30', 'A.8.8'],
        'soc2':         ['CC9.2'],
        'pci_dss':      ['Req 6.3.2', 'Req 12.8'],
        'nist_800_53':  ['SA-12', 'SI-7'],
    },

    # =========================================================================
    # ADVANCED THREATS — MACROS
    # =========================================================================

    'endpoint:xlm_macro_execution': {
        'cis':          ['CIS-9.4', 'CIS-10.1'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-3'],
        'iso27001':     ['A.8.7', 'A.8.9'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.2', 'Req 5.4.1'],
        'hipaa':        ['164.312(b)'],
        'nist_800_53':  ['SI-3', 'CM-7'],
    },

    'endpoint:dde_command_injection': {
        'cis':          ['CIS-9.4', 'CIS-10.1'],
        'nist_csf':     ['DE.CM-1'],
        'iso27001':     ['A.8.7'],
        'soc2':         ['CC6.1', 'CC7.2'],
        'pci_dss':      ['Req 5.3.2'],
        'nist_800_53':  ['SI-3'],
    },

    # =========================================================================
    # RANSOMWARE INDICATORS
    # =========================================================================

    'endpoint:ransom_network_share_enum': {
        'cis':          ['CIS-13.1', 'CIS-12.6'],
        'nist_csf':     ['DE.CM-1', 'DE.AE-2'],
        'iso27001':     ['A.8.15', 'A.8.16'],
        'soc2':         ['CC7.2', 'CC7.3'],
        'pci_dss':      ['Req 10.7', 'Req 11.5'],
        'nist_800_53':  ['AU-6', 'SI-4'],
    },

    'endpoint:ransom_backup_catalog_del': {
        'cis':          ['CIS-10.1', 'CIS-11.3'],
        'nist_csf':     ['PR.IP-4', 'RC.RP-1'],
        'iso27001':     ['A.8.13', 'A.8.7'],
        'soc2':         ['A1.2', 'CC7.3'],
        'pci_dss':      ['Req 12.3.4', 'Req 11.5.1'],
        'hipaa':        ['164.308(a)(7)'],
        'nist_800_53':  ['CP-9', 'SI-3'],
    },

    'endpoint:ransom_inhibit_recovery': {
        'cis':          ['CIS-10.1', 'CIS-11.3'],
        'nist_csf':     ['PR.IP-4', 'RC.RP-1'],
        'iso27001':     ['A.8.13'],
        'soc2':         ['A1.2'],
        'pci_dss':      ['Req 12.3.4'],
        'hipaa':        ['164.308(a)(7)'],
        'nist_800_53':  ['CP-9', 'SI-7'],
    },

    # =========================================================================
    # AI / ML THREAT FACTORS — ISO 42001, OWASP LLM 2025, NIST AI RMF
    # =========================================================================

    'prompt_injection': {
        'iso27001':     ['A.8.25', 'A.8.26'],
        'nist_800_53':  ['SI-10', 'SI-3'],
        'iso42001':     ['6.1.2', '8.4', '9.1'],
        'owasp_llm':    ['LLM01:2025'],
        'nist_ai_rmf':  ['GOVERN-1.2', 'MAP-5.1', 'MEASURE-2.5'],
        'maestro':      ['L3-AgentFramework-InputValidation'],
    },

    'tool_abuse': {
        'iso27001':     ['A.8.26', 'A.5.10'],
        'nist_800_53':  ['AC-3', 'CM-7'],
        'iso42001':     ['8.4', '8.6'],
        'owasp_llm':    ['LLM06:2025', 'LLM07:2025'],
        'nist_ai_rmf':  ['GOVERN-1.4', 'MAP-5.2'],
        'maestro':      ['L4-AgentOrchestrator-ToolPermissions'],
    },

    'sensitive_output_leak': {
        'iso27001':     ['A.5.34', 'A.8.11'],
        'nist_800_53':  ['AC-3', 'AC-4', 'SI-12'],
        'gdpr':         ['Art.5', 'Art.32'],
        'iso42001':     ['8.4', '9.1'],
        'owasp_llm':    ['LLM02:2025'],
        'nist_ai_rmf':  ['MEASURE-2.6', 'MANAGE-2.2'],
    },

    'training_data_poisoning': {
        'iso27001':     ['A.8.8', 'A.5.23'],
        'nist_800_53':  ['SI-7', 'RA-5'],
        'iso42001':     ['8.3', '8.4', '6.1.1'],
        'owasp_llm':    ['LLM04:2025'],
        'nist_ai_rmf':  ['MAP-1.6', 'MEASURE-2.7'],
    },

    'model_evasion_adversarial': {
        'iso27001':     ['A.8.25', 'A.8.29'],
        'nist_800_53':  ['SI-10', 'RA-5'],
        'iso42001':     ['8.4', '8.5', '9.1'],
        'owasp_llm':    ['LLM05:2025'],
        'nist_ai_rmf':  ['MEASURE-2.5', 'MANAGE-4.1'],
    },

    'vector_db_poisoning': {
        'iso27001':     ['A.8.8', 'A.8.25'],
        'nist_800_53':  ['SI-7', 'SI-10'],
        'iso42001':     ['8.3', '8.4'],
        'owasp_llm':    ['LLM08:2025'],
        'nist_ai_rmf':  ['MAP-1.6', 'MEASURE-2.7'],
    },

    'rag_context_injection': {
        'iso27001':     ['A.8.25', 'A.8.26'],
        'nist_800_53':  ['SI-10'],
        'iso42001':     ['8.4'],
        'owasp_llm':    ['LLM08:2025', 'LLM01:2025'],
        'nist_ai_rmf':  ['MAP-5.1'],
        'maestro':      ['L2-DataOrchestration-RAGPipeline'],
    },

    'system_prompt_exfil': {
        'iso27001':     ['A.8.12', 'A.5.34'],
        'nist_800_53':  ['AC-4', 'SI-12'],
        'iso42001':     ['8.4', '9.1'],
        'owasp_llm':    ['LLM07:2025'],
        'nist_ai_rmf':  ['GOVERN-1.2', 'MEASURE-2.6'],
    },

    'mcp_tool_injection': {
        'iso27001':     ['A.8.26', 'A.5.10'],
        'nist_800_53':  ['CM-7', 'AC-3'],
        'iso42001':     ['8.4', '8.6'],
        'owasp_llm':    ['LLM01:2025', 'LLM06:2025'],
        'nist_ai_rmf':  ['MAP-5.2'],
        'maestro':      ['L5-MCPLayer-ToolCallValidation'],
    },

    'model_dos_token_flood': {
        'iso27001':     ['A.8.6'],
        'nist_800_53':  ['SC-5', 'AU-11'],
        'iso42001':     ['8.4', '9.1'],
        'owasp_llm':    ['LLM10:2025'],
        'nist_ai_rmf':  ['MANAGE-2.4'],
    },

    'model_supply_chain_tamper': {
        'iso27001':     ['A.5.19', 'A.5.20', 'A.8.8'],
        'nist_800_53':  ['SR-4', 'SR-6', 'SI-7'],
        'iso42001':     ['8.3', '6.1.1'],
        'owasp_llm':    ['LLM03:2025'],
        'nist_ai_rmf':  ['MAP-1.6', 'GOVERN-1.7'],
    },

    # =========================================================================
    # OWASP API TOP 10:2023 FACTORS
    # =========================================================================

    'api:broken_object_level_auth': {
        'iso27001':     ['A.5.15', 'A.8.3'],
        'nist_800_53':  ['AC-3', 'AC-6'],
        'owasp_api':    ['API1:2023 - BOLA'],
        'nist_csf':     ['PR.AC-3'],
    },

    'api:broken_authentication': {
        'iso27001':     ['A.5.17', 'A.8.5'],
        'nist_800_53':  ['IA-2', 'IA-5'],
        'owasp_api':    ['API2:2023 - Broken Authentication'],
        'nist_csf':     ['PR.AC-1'],
    },

    'api:broken_object_property_auth': {
        'iso27001':     ['A.5.15', 'A.8.3'],
        'nist_800_53':  ['AC-3', 'AC-6'],
        'owasp_api':    ['API3:2023 - BOPLA'],
    },

    'api:unrestricted_resource_consumption': {
        'iso27001':     ['A.8.6'],
        'nist_800_53':  ['SC-5'],
        'owasp_api':    ['API4:2023 - Unrestricted Resource Consumption'],
    },

    'api:function_level_auth_broken': {
        'iso27001':     ['A.5.15', 'A.5.18'],
        'nist_800_53':  ['AC-3', 'AC-6'],
        'owasp_api':    ['API5:2023 - BFLA'],
    },

    'api:unrestricted_access_sensitive_flows': {
        'iso27001':     ['A.5.15', 'A.8.3'],
        'nist_800_53':  ['AC-3', 'AC-21'],
        'owasp_api':    ['API6:2023 - Unrestricted Access to Sensitive Business Flows'],
        'nist_csf':     ['PR.AC-4'],
    },

    'api:ssrf_detected': {
        'iso27001':     ['A.8.22', 'A.8.26'],
        'nist_800_53':  ['SC-7', 'SI-10'],
        'owasp_api':    ['API7:2023 - SSRF'],
        'nist_csf':     ['DE.CM-1'],
    },

    'api:security_misconfiguration': {
        'iso27001':     ['A.8.8', 'A.8.9'],
        'nist_800_53':  ['CM-6', 'CM-7'],
        'owasp_api':    ['API8:2023 - Security Misconfiguration'],
        'nist_csf':     ['PR.IP-1'],
    },

    'api:improper_inventory_management': {
        'iso27001':     ['A.5.9', 'A.8.8'],
        'nist_800_53':  ['CM-8'],
        'owasp_api':    ['API9:2023 - Improper Inventory Management'],
    },

    'api:unsafe_consumption_third_party': {
        'iso27001':     ['A.5.19', 'A.5.20'],
        'nist_800_53':  ['SR-4', 'SI-7'],
        'owasp_api':    ['API10:2023 - Unsafe Consumption of APIs'],
    },

    # MITRE v14/v15 new technique compliance mappings
    'iam:adcs_cert_request_abuse': {
        'iso27001':     ['A.5.15', 'A.8.3', 'A.8.5'],
        'nist_800_53':  ['IA-5', 'SC-17', 'AC-6'],
        'nist_csf':     ['PR.AC-1', 'PR.AC-6'],
        'soc2':         ['CC6.1', 'CC6.3'],
    },

    'cloud:ssm_run_command_unusual': {
        'iso27001':     ['A.8.9', 'A.8.15'],
        'nist_800_53':  ['AU-2', 'CM-6', 'SI-4'],
        'nist_csf':     ['DE.CM-1', 'DE.AE-3'],
    },

    'cloud:cloudtrail_enumeration': {
        'iso27001':     ['A.8.15', 'A.8.16'],
        'nist_800_53':  ['AU-6', 'SI-4'],
        'nist_csf':     ['DE.AE-3'],
    },

    'email:bec_wire_transfer_redirect': {
        'iso27001':     ['A.5.25', 'A.8.15'],
        'nist_800_53':  ['IR-4', 'SI-4'],
        'nist_csf':     ['RS.RP-1', 'DE.AE-2'],
        'soc2':         ['CC7.3', 'CC7.4'],
    },

    'endpoint:ebpf_rootkit_persist': {
        'iso27001':     ['A.8.7', 'A.8.15', 'A.8.16'],
        'nist_800_53':  ['SI-3', 'SI-7', 'AU-6'],
        'nist_csf':     ['DE.CM-4', 'DE.AE-5'],
        'cis':          ['CIS-10.1', 'CIS-10.5'],
    },

    'net:jarm_c2_match': {
        'iso27001':     ['A.8.22', 'A.8.15'],
        'nist_800_53':  ['SC-7', 'SI-4'],
        'nist_csf':     ['DE.CM-1', 'PR.PT-4'],
    },
}

# ---------------------------------------------------------------------------
# Framework metadata (for UI display)
# ---------------------------------------------------------------------------
FRAMEWORK_LABELS: Dict[str, str] = {
    'cis':         'CIS Controls v8',
    'nist_csf':    'NIST CSF 2.0',
    'iso27001':    'ISO/IEC 27001:2022',
    'soc2':        'SOC 2 Type II',
    'pci_dss':     'PCI-DSS v4.0',
    'hipaa':       'HIPAA Security Rule',
    'gdpr':        'GDPR',
    'nist_800_53': 'NIST SP 800-53 Rev 5',
    # AI / emerging frameworks
    'iso42001':    'ISO/IEC 42001:2023 AI Management',
    'owasp_llm':   'OWASP LLM Top 10:2025',
    'owasp_api':   'OWASP API Top 10:2023',
    'nist_ai_rmf': 'NIST AI RMF 1.0',
    'maestro':     'MAESTRO AI Agent Threat Model',
}

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def get_compliance_hits(factors: List[str]) -> Dict[str, List[str]]:
    """Return deduplicated compliance control IDs violated by the given factors.

    Args:
        factors: List of factor strings (e.g. ['email:bec_replyto_mismatch', ...])

    Returns:
        Dict keyed by framework abbreviation → sorted list of control IDs.

    Example:
        {'cis': ['CIS-9.5', 'CIS-10.1'], 'nist_csf': ['DE.CM-1'], ...}
    """
    hits: Dict[str, set] = {fw: set() for fw in FRAMEWORK_LABELS}  # auto-expands with FRAMEWORK_LABELS

    for factor in factors:
        mapping = FACTOR_TO_COMPLIANCE.get(factor)
        if not mapping:
            # Try prefix match for unknown sub-variants
            prefix = factor.rsplit(':', 1)[0] + ':' if ':' in factor else ''
            for key, val in FACTOR_TO_COMPLIANCE.items():
                if key.startswith(prefix) and prefix:
                    mapping = val
                    break
        if not mapping:
            continue
        for fw, controls in mapping.items():
            if fw in hits:
                hits[fw].update(controls)

    return {fw: sorted(controls) for fw, controls in hits.items() if controls}


def get_compliance_report(factors: List[str]) -> Dict[str, Any]:
    """Return a structured compliance report with control counts and framework labels.

    Suitable for inclusion in CISO / Audit persona reports.
    """
    hits = get_compliance_hits(factors)
    report: Dict[str, Any] = {
        'frameworks_violated': [],
        'total_controls_flagged': 0,
        'details': {},
    }
    total = 0
    for fw, controls in hits.items():
        count = len(controls)
        total += count
        report['frameworks_violated'].append(fw)
        report['details'][fw] = {
            'label': FRAMEWORK_LABELS.get(fw, fw),
            'controls': controls,
            'count': count,
        }
    report['total_controls_flagged'] = total
    return report


__all__ = ['FACTOR_TO_COMPLIANCE', 'FRAMEWORK_LABELS', 'get_compliance_hits', 'get_compliance_report']
