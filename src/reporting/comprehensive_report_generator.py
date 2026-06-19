import json
from html import escape

# ── factor → short display label ────────────────────────────────────────────
_FACTOR_LABELS = {
    'suspicious_process':         'Suspicious Process',
    'lolbin':                     'LOLBin Abuse',
    'powershell_execution':       'PowerShell Execution',
    'encoded_command':            'Encoded Command (-enc)',
    'powershell_bypass':          'Policy Bypass (-nop/-bypass)',
    'powershell_download_cradle': 'Download Cradle (IEX/DownloadString)',
    'office_child_process':       'Office-spawned Child Process',
    'temp_execution':             'Execution from Temp/Writable Path',
    'user_writable_exec':         'Executable in User-Writable Directory',
    'known_bad_hash':             'Known-Bad File Hash',
    'c2_beacon':                  'C2 Beacon / Command-and-Control',
    'network_beacon':             'Outbound Network Beacon',
    'macro_lure':                 'Macro Lure (Enable Content)',
    'phishing_link':              'Phishing URL in Message Body',
    'phishing_lure':              'Phishing Lure Subject',
    'email_malicious_url':        'Malicious URL in Email',
    'credential_access':          'Credential Access Attempt',
    'account_discovery':          'Account Discovery (net user / net localgroup)',
    'rdp_lateral_movement':       'RDP Lateral Movement (port 3389)',
    'smb_lateral_movement':       'SMB Lateral Movement (port 445)',
    'wmi_lateral_movement':       'WMI Lateral Movement',
    'windows_update':             'Windows Update Artefact (benign)',
    # Assessment / pipeline factors
    'external_connection':        'External Network Connection',
    'c2_port':                    'Known C2 Port (443/8080/etc.)',
    'malicious_process':          'Malicious Process Execution',
    'process_execution':          'Process Execution Event',
    'phishing_subject':           'Phishing Subject Line Detected',
    'email_received':             'Email Received',
    'unclassified_event':         'Unclassified Event',
    # New enrichment factors
    'lateral_movement':           'Active Lateral Movement (internal pivot)',
    'lateral_movement_tool':      'Offensive Lateral Movement Tool (wmiexec/psexec)',
    'interactive_wmi_session':    'Interactive WMI Session (-i flag)',
    'credential_harvest':         'Credential Harvesting Link in Email Body',
    'smb_external':               'SMB to External IP (T1021.002)',
    'dropper_file_write':         'Dropper: Malicious Process Wrote Secondary Payload',
    'masquerading_extension':     'Masquerading: File with Benign Extension (T1036.005)',
    'c2_data_staging':            'C2 Payload Size Elevated — Data Staging Suspected',
    'c2_communication':           'Active C2 Communication Confirmed',
    'dns_beacon':                 'DNS Beacon Channel',
    'suspicious_url_in_body':     'Suspicious URL in Email Body',
    'edr_observation':            'EDR Observation (non-blocking)',
}

# ── MITRE technique display helpers ─────────────────────────────────────────
_MITRE_NAMES = {
    'T1059':     'Command and Scripting Interpreter',
    'T1059.001': 'PowerShell',
    'T1059.003': 'Windows Command Shell',
    'T1036':     'Masquerading',
    'T1036.005': 'Match Legitimate Name or Location',
    'T1027':     'Obfuscated Files or Information',
    'T1047':     'Windows Management Instrumentation',
    'T1021':     'Remote Services',
    'T1021.001': 'Remote Desktop Protocol',
    'T1021.002': 'SMB/Windows Admin Shares',
    'T1021.006': 'Windows Remote Management',
    'T1071.001': 'Application Layer Protocol: Web',
    'T1095':     'Non-Application Layer Protocol',
    'T1571':     'Non-Standard Port',
    'T1105':     'Ingress Tool Transfer',
    'T1218':     'Signed Binary Proxy Execution',
    'T1566.001': 'Phishing: Spearphishing Attachment',
    'T1204.001': 'User Execution: Malicious Link',
    'T1204.002': 'User Execution: Malicious File',
    'T1003':     'OS Credential Dumping',
    'T1056':     'Input Capture',
    'T1087':     'Account Discovery',
    'T1069':     'Permission Groups Discovery',
    'T1553':     'Subvert Trust Controls',
    'T1562':     'Impair Defenses',
    'T1486':     'Data Encrypted for Impact',
    'T1190':     'Exploit Public-Facing Application',
    'T1566':     'Phishing',
    'T1041':     'Exfiltration Over C2 Channel',
    'T1055':     'Process Injection',
    'T1547':     'Boot or Logon Autostart Execution',
    'T1543':     'Create or Modify System Process',
    'T1053':     'Scheduled Task/Job',
    'T1133':     'External Remote Services',
    'T1048':     'Exfiltration Over Alternative Protocol',
    'T1102':     'Web Service (C2)',
    'T1566.002': 'Phishing: Spearphishing Link',
    'T1071.004': 'Application Layer Protocol: DNS',
    'T1046':     'Network Service Discovery',
    'T1021.003': 'DCOM Remote Services',
    'T1021.004': 'SSH Remote Services',
    'T1095':     'Non-Application Layer Protocol',
}

# ── persona "what to do next" playbook ───────────────────────────────────────
_NEXT_STEPS = {
    'executive': [
        ('Immediate', 'Authorise containment of affected hosts — suspend network access for flagged endpoints while investigation proceeds.'),
        ('24 hours',  'Request a Tier-2 LLM incident summary from your SOC team for board-level briefing language.'),
        ('This week', 'Review whether cyber-insurance policy covers the identified kill-chain stage. Notify legal if PII may be in scope.'),
        ('30 days',   'Commission a tabletop exercise covering C2-beacon and lateral-movement scenarios identified in this assessment.'),
    ],
    'soc_analyst': [
        ('Now',         'Isolate flagged hosts — block outbound to known-bad IPs (203.0.113.45, 198.51.100.22) at the perimeter firewall.'),
        ('15 min',      'Pull process tree for flagged executable names from EDR; confirm parent–child ancestry and timeline.'),
        ('1 hour',      'Pivot on sha256 hashes in VirusTotal / MalwareBazaar; if no result, submit to sandboxing.'),
        ('4 hours',     'Correlate C2 beacon timestamps across network logs — check for periodic outbound matching T1071.001 pattern.'),
        ('Next shift',  'Open JIRA/ServiceNow incident, attach this report, and escalate to Tier-2 for LLM-assisted correlation.'),
    ],
    'threat_hunter': [
        ('Hunt query 1', 'Process creation audit: WHERE process_name IN (evil_procs) AND parent NOT IN (known_safe_parents)'),
        ('Hunt query 2', 'Network: WHERE dst_ip IN (known_bad_ips) AND bytes_out > 0 ORDER BY ts — look for beaconing interval'),
        ('Hunt query 3', 'File events: WHERE path LIKE %\\temp\\%.exe% OR path LIKE %\\downloads\\%.exe%'),
        ('Hypothesis',   'C2 dwell time — if first_seen < incident_ts−72h, adversary likely has persistent foothold; check scheduled tasks & service installs.'),
        ('Sigma rule',   'title: Suspicious Process from Temp Path detection=process_name in list and path contains temp'),
    ],
    'forensics': [
        ('Step 1 — Volatile',     'Snapshot running processes, open network connections, and loaded modules before touching disk.'),
        ('Step 2 — Memory',       'Acquire full RAM image (Magnet/WinPMEM) from each flagged host prior to shutdown.'),
        ('Step 3 — Disk',         'Image with write-blocker; collect MFT, prefetch, Amcache, event logs, and scheduled task XML.'),
        ('Step 4 — Network',      'Export PCAP for the beacon window; extract TLS SNI and JA3/JA3S fingerprints.'),
        ('Step 5 — Chain of Custody', "Hash all artefacts (SHA-256), log analyst names, and store originals in read-only evidence container."),
    ],
    'compliance': [
        ('Immediate',    'Log incident in your GRC tool; assign incident reference number for audit trail.'),
        ('24 hours',     'Assess if personal data was accessible to the flagged process — triggers GDPR 72-hour notification clock.'),
        ('72 hours',     'GDPR breach notification deadline to DPA if personal data exfiltration cannot be ruled out.'),
        ('This week',    'Document control failures linked to identified MITRE techniques; map to CIS Controls / ISO 27001 Annex A.'),
        ('Post-incident', 'Update risk register; commission penetration test to validate remediation effectiveness.'),
    ],
}

# ── compliance framework mapping ─────────────────────────────────────────────
_MITRE_TO_FRAMEWORK = {
    'T1059.001': {'CIS': 'CIS-8.2', 'ISO27001': 'A.12.6.1', 'SOC2': 'CC6.8', 'GDPR': ''},
    'T1566.001': {'CIS': 'CIS-9.4', 'ISO27001': 'A.13.2.3', 'SOC2': 'CC6.1', 'GDPR': 'Art.32'},
    'T1071.001': {'CIS': 'CIS-12.4', 'ISO27001': 'A.13.1.3', 'SOC2': 'CC7.2', 'GDPR': ''},
    'T1021.002': {'CIS': 'CIS-4.7', 'ISO27001': 'A.9.4.2', 'SOC2': 'CC6.2', 'GDPR': ''},
    'T1021.001': {'CIS': 'CIS-4.7', 'ISO27001': 'A.9.4.2', 'SOC2': 'CC6.2', 'GDPR': ''},
    'T1218':     {'CIS': 'CIS-8.9', 'ISO27001': 'A.12.6.1', 'SOC2': 'CC6.8', 'GDPR': ''},
    'T1003':     {'CIS': 'CIS-5.2', 'ISO27001': 'A.9.2.4', 'SOC2': 'CC6.3', 'GDPR': 'Art.32'},
}

# ── severity from risk_score ─────────────────────────────────────────────────
def _sev_from_risk(risk_score: float) -> str:
    if risk_score >= 0.70: return 'critical'
    if risk_score >= 0.45: return 'high'
    if risk_score >= 0.20: return 'medium'
    if risk_score > 0.0:   return 'low'
    return 'info'

_SEV_COLORS = {
    'critical': '#c0392b',
    'high':     '#e67e22',
    'medium':   '#f1c40f',
    'low':      '#2980b9',
    'info':     '#555',
}


def _render_row_preview(r):
    try:
        return '<pre style="background:#111; color:#e6eef8; padding:8px; border-radius:6px; overflow:auto; max-height:160px">' + escape(json.dumps(r, indent=2)) + '</pre>'
    except Exception:
        return '<pre>(failed to render)</pre>'


def _derive_severity_dist(rows: list) -> dict:
    """Derive severity distribution from risk_score / confidence / severity on each row."""
    dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for r in rows:
        # Prefer explicit severity label from assessment rows
        explicit_sev = str(r.get('severity') or '').lower()
        if explicit_sev in dist:
            dist[explicit_sev] += 1
            continue
        risk = 0.0
        try:
            risk = float(r.get('risk_score') or r.get('confidence') or r.get('dread_score') or 0)
        except Exception:
            pass
        dist[_sev_from_risk(risk)] += 1
    return {k: v for k, v in dist.items() if v > 0}


def _collect_mitre(rows: list) -> list:
    """Collect MITRE techniques from row factors and mitre_techniques field."""
    counts: dict = {}
    try:
        from src.core.mappings.factor_to_mitre import get_all_mappings
    except Exception:
        try:
            from ..core.mappings.factor_to_mitre import get_all_mappings  # type: ignore
        except Exception:
            get_all_mappings = None  # type: ignore
    for row in rows:
        # Direct mitre_techniques from assessment rows
        # Supports formats: "T1041", "T1041:Exfiltration", ("T1041","name"), ["T1041","name"]
        for m in (row.get('mitre_techniques') or []):
            if isinstance(m, (list, tuple)) and m:
                tid = str(m[0]).strip()
            else:
                tid = str(m).split(':')[0].strip()
            # Strip leading parens from stringified tuples e.g. "('T1021.001'"
            tid = tid.lstrip("('\"").rstrip(")'\"")
            if tid and tid.startswith('T'):
                counts[tid] = counts.get(tid, 0) + 1
        # Factor-derived MITRE via mappings
        factors = row.get('factors') or []
        if isinstance(factors, list):
            factor_names = [f.get('name') if isinstance(f, dict) else str(f) for f in factors]
        else:
            factor_names = []
        if get_all_mappings and factor_names:
            mapping = get_all_mappings(factor_names)
            for t in mapping.get('mitre', []):
                counts[t] = counts.get(t, 0) + 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)


def _collect_all_factors(rows: list) -> dict:
    """Count factor occurrences across all rows."""
    counts: dict = {}
    for row in rows:
        factors = row.get('factors') or []
        for f in factors:
            name = (
                f.get('name') or f.get('factor') or f.get('id') or f.get('label')
                if isinstance(f, dict) else str(f)
            )
            if name:
                counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


def _render_persona_section(payload: dict, persona: str, report_options: dict | None = None) -> str:
    """Render a styled persona-specific HTML block."""
    secs: list = []
    rows = payload.get('rows') or []
    meta = payload.get('meta') or {}
    _ropts_local = report_options or {}
    _defaults_local = {
        'include_blind_spots': True, 'include_hunt_queries': True,
        'include_raw_events': True, 'include_mitre_table': True,
        'include_dread_breakdown': True, 'include_beacon_analysis': True,
    }
    def _opt(key: str, default: bool = True) -> bool:  # noqa: E306
        return bool(_ropts_local.get(key, _defaults_local.get(key, default)))
    all_factors = _collect_all_factors(rows)
    mitre_hits = _collect_mitre(rows)
    n_rows = len(rows)
    try:
        n_total_events = int(meta.get('total_rows') or n_rows)
    except Exception:
        n_total_events = n_rows
    n_flagged = sum(1 for r in rows
                    if float(r.get('risk_score') or r.get('confidence') or r.get('dread_score') or 0) > 0.05
                    or str(r.get('verdict') or '').lower() in ('malicious', 'suspicious', 'review', 'escalate')
                    or str(r.get('severity') or '').lower() in ('critical', 'high', 'medium'))

    # Threat models (STRIDE, Diamond, MAESTRO, PASTA) from enrichment
    threat_models = payload.get('threat_models') or {}
    stride_summary = threat_models.get('stride_summary') or {}
    diamond_model = threat_models.get('diamond_model') or {}
    maestro_stages = threat_models.get('maestro_stages') or []
    pasta_risks = threat_models.get('pasta_risk_matrix') or []

    BLOCK = 'margin-top:18px;padding:14px;background:#0c1520;border-left:4px solid {clr};border-radius:6px'
    HEAD  = 'color:{clr};font-size:15px;font-weight:600;margin-bottom:8px'
    SUB   = 'color:#9bb;font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px'
    PILL  = 'display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;margin:2px;background:{bg};color:{fg}'

    if persona == 'executive':
        clr = '#5b9bd5'
        secs.append(f'<div style="{BLOCK.format(clr=clr)}">')
        secs.append(f'<div style="{HEAD.format(clr=clr)}">Executive Summary</div>')
        if n_flagged:
            secs.append(f'<p><strong>{n_flagged} of {n_rows} events</strong> require your attention. '
                        f'{"High-confidence threats including C2 command-and-control beacons and malicious process execution were found." if any(f in all_factors for f in ("c2_beacon","suspicious_process","c2_communication")) else "Suspicious activity was detected across multiple data sources."}'
                        f' Immediate containment is recommended for impacted endpoints.</p>')
        else:
            secs.append(f'<p>No high-risk events detected in this batch of {n_rows} records. Routine security monitoring can continue.</p>')
        # MAESTRO Mission Assessment (adversary intent)
        if maestro_stages:
            m_stage = next((s for s in maestro_stages if s.get('stage','').startswith('M')), None)
            o_stage = next((s for s in maestro_stages if s.get('stage','').startswith('O')), None)
            if m_stage and m_stage.get('detected'):
                secs.append(f'<div style="padding:10px 14px;background:#0a1018;border:1px solid {clr};border-radius:4px;margin:8px 0">')
                secs.append(f'<strong style="color:{clr}">Adversary Mission Assessment (MAESTRO):</strong> '
                            f'{escape(m_stage.get("description",""))}')
                if o_stage and o_stage.get('detected'):
                    secs.append(f'<br><strong style="color:#e74c3c">Attack Status:</strong> '
                                f'The attacker has NOT completed their objective. The observed window captures the beginning of an attack chain — containment window is narrowing.')
                secs.append('</div>')
        # Diamond Model — Blast Radius
        if diamond_model.get('victims'):
            secs.append(f'<div style="{SUB}">Blast Radius (Diamond Model)</div>')
            secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:10px">')
            secs.append('<thead><tr><th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Target</th>'
                        '<th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Status</th>'
                        '<th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Source</th></tr></thead><tbody>')
            for v in diamond_model['victims'][:8]:
                st_clr = '#e74c3c' if 'COMPROMISED' in v.get('status','') else '#f1c40f'
                secs.append(f'<tr><td style="padding:3px 8px;border-bottom:1px solid #0e1722;font-family:monospace">{escape(str(v.get("identity","")))}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;color:{st_clr}">{escape(v.get("status",""))}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;color:#9bb">{escape(v.get("sheet",""))}</td></tr>')
            secs.append('</tbody></table>')
        # PASTA Business Risk Table
        if pasta_risks:
            secs.append(f'<div style="{SUB}">Business Risk (PASTA Stage 7)</div>')
            secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:10px">')
            secs.append('<thead><tr><th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Risk</th>'
                        '<th style="text-align:center;padding:3px 8px;border-bottom:1px solid #243144">Likelihood</th>'
                        '<th style="text-align:center;padding:3px 8px;border-bottom:1px solid #243144">Impact</th>'
                        '<th style="text-align:right;padding:3px 8px;border-bottom:1px solid #243144">Score</th></tr></thead><tbody>')
            for risk in pasta_risks[:6]:
                score_clr = '#e74c3c' if risk.get('score',0) >= 8.0 else '#f1c40f'
                secs.append(f'<tr><td style="padding:3px 8px;border-bottom:1px solid #0e1722">{escape(risk.get("risk",""))}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;text-align:center">{escape(risk.get("likelihood",""))}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;text-align:center">{escape(risk.get("impact",""))}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;text-align:right;color:{score_clr};font-weight:600">{risk.get("score",0)}/10</td></tr>')
            secs.append('</tbody></table>')
        # Business impact
        top_factors = list(all_factors.keys())[:3]
        if top_factors:
            secs.append(f'<div style="{SUB}">Business Risk Indicators</div>')
            secs.append('<ul style="margin:4px 0 8px 18px">')
            risk_map = {
                'c2_beacon':          'Active command-and-control channel — attacker may have persistent access to your network.',
                'c2_port':            'Traffic on known C2 port (443/8080) to external IP — potential data exfiltration or implant callback.',
                'c2_communication':   'Active C2 communication confirmed — attacker has established persistent remote access.',
                'external_connection':'External network connections detected to suspicious IPs — outbound traffic requires investigation.',
                'suspicious_process': 'Malicious processes executed — potential malware infection on one or more endpoints.',
                'malicious_process':  'Confirmed malicious process execution — immediate endpoint containment required.',
                'process_execution':  'Process execution events detected — verify parent/child process ancestry for anomalies.',
                'macro_lure':         'Phishing campaign via macro-enabled documents — credential theft or malware delivery likely attempted.',
                'phishing_subject':   'Phishing email detected by subject line analysis — social engineering attack targeting staff.',
                'credential_harvest': 'Credential harvesting link detected — employee passwords may be compromised.',
                'lateral_movement':   'Active lateral movement to internal hosts — attacker spreading through your network.',
                'smb_lateral_movement': 'Lateral movement across file shares — attacker traversing the internal network.',
                'rdp_lateral_movement': 'Remote desktop lateral movement — attacker moving to higher-value systems.',
                'lateral_movement_tool': 'Offensive lateral movement tool detected (e.g. wmiexec) — hands-on-keyboard attacker activity.',
                'smb_external':       'SMB connection to external IP — possible credential relay or file share exploitation.',
                'dropper_file_write': 'Malicious file dropped secondary payload — multi-stage attack in progress.',
                'c2_data_staging':    'C2 payload size increasing — possible data exfiltration in progress.',
                'phishing_lure':      'Phishing email targeting staff — social engineering risk to credentials or data.',
                'credential_access':  'Credential theft attempted — passwords or tokens may have been compromised.',
            }
            for f in top_factors:
                label = risk_map.get(f, _FACTOR_LABELS.get(f, f))
                secs.append(f'  <li>{escape(label)}</li>')
            secs.append('</ul>')
        # Next steps
        secs.append(f'<div style="{SUB}">What You Need to Do</div>')
        secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px">')
        secs.append('<thead><tr><th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144;width:90px">Timeframe</th>'
                    '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Action</th></tr></thead><tbody>')
        for timeframe, action in _NEXT_STEPS['executive']:
            secs.append(f'<tr><td style="padding:4px 8px;border-bottom:1px solid #151e2b;white-space:nowrap;color:#8ab">{escape(timeframe)}</td>'
                        f'<td style="padding:4px 8px;border-bottom:1px solid #151e2b">{escape(action)}</td></tr>')
        secs.append('</tbody></table>')
        secs.append('</div>')

    elif persona == 'soc_analyst':
        clr = '#2ecc71'
        secs.append(f'<div style="{BLOCK.format(clr=clr)}">')
        secs.append(f'<div style="{HEAD.format(clr=clr)}">SOC Analyst — Triage & Response</div>')
        # STRIDE Quick-Hits for SOC
        if stride_summary:
            _stride_soc_items = []
            e_stride = stride_summary.get('E', {})
            r_stride = stride_summary.get('R', {})
            t_stride = stride_summary.get('T', {})
            s_stride = stride_summary.get('S', {})
            if e_stride.get('count', 0) > 0:
                _stride_soc_items.append(('E — Privilege', 'Investigate all lateral movement tool sessions for admin credential usage'))
            if r_stride.get('count', 0) > 0:
                _stride_soc_items.append(('R — Repudiation', 'Enable auth logging NOW before any remediation — evidence will be lost'))
            if t_stride.get('count', 0) > 0:
                _stride_soc_items.append(('T — Tampering', 'Check if dropped files were subsequently executed — secondary payloads may be live'))
            if s_stride.get('count', 0) > 0:
                _stride_soc_items.append(('S — Spoofing', 'Verify sender identity via DKIM/SPF for all flagged emails'))
            if _stride_soc_items:
                secs.append(f'<div style="{SUB}">STRIDE Priority Actions</div>')
                secs.append('<div style="padding:8px;background:#0a1a10;border:1px solid #2ecc71;border-radius:4px;margin-bottom:10px">')
                for label, action in _stride_soc_items:
                    secs.append(f'<div style="margin:4px 0"><strong style="color:#2ecc71">{escape(label)}:</strong> {escape(action)}</div>')
                secs.append('</div>')
        # Factor frequency table
        if all_factors:
            secs.append(f'<div style="{SUB}">Key factors</div>')
            secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:10px">')
            secs.append('<thead><tr>'
                        '<th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Factor</th>'
                        '<th style="text-align:right;padding:3px 8px;border-bottom:1px solid #243144">Count</th>'
                        '<th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Description</th>'
                        '</tr></thead><tbody>')
            for fname, cnt in list(all_factors.items())[:15]:
                label = _FACTOR_LABELS.get(fname, fname)
                secs.append(f'<tr><td style="padding:3px 8px;border-bottom:1px solid #0e1722;font-family:monospace;font-size:11px">{escape(fname)}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;text-align:right">{cnt}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;color:#9bb">{escape(label)}</td></tr>')
            secs.append('</tbody></table>')
        # MITRE coverage
        if mitre_hits:
            secs.append(f'<div style="{SUB}">MITRE ATT&CK Coverage</div>')
            secs.append('<div style="margin-bottom:8px">')
            for tid, cnt in mitre_hits[:12]:
                name = _MITRE_NAMES.get(tid, '')
                label_text = f'{tid}' + (f' — {name}' if name else '')
                secs.append(f'<span style="{PILL.format(bg="#1c2d1e", fg="#2ecc71")}">{escape(label_text)} ({cnt})</span>')
            secs.append('</div>')
        # Triage steps
        secs.append(f'<div style="{SUB}">Triage Checklist</div>')
        secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px">')
        secs.append('<thead><tr><th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144;width:110px">Priority</th>'
                    '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Action</th></tr></thead><tbody>')
        for priority, action in _NEXT_STEPS['soc_analyst']:
            secs.append(f'<tr><td style="padding:4px 8px;border-bottom:1px solid #151e2b;white-space:nowrap;color:#8ab">{escape(priority)}</td>'
                        f'<td style="padding:4px 8px;border-bottom:1px solid #151e2b">{escape(action)}</td></tr>')
        secs.append('</tbody></table>')
        secs.append('</div>')

    elif persona == 'threat_hunter':
        clr = '#e74c3c'
        secs.append(f'<div style="{BLOCK.format(clr=clr)}">')
        secs.append(f'<div style="{HEAD.format(clr=clr)}">Threat Hunter — Kill Chain & Hypotheses</div>')
        # Diamond Model — Campaign Overview
        if diamond_model.get('infrastructure') or diamond_model.get('capabilities'):
            secs.append(f'<div style="{SUB}">Diamond Model — Campaign Overview</div>')
            secs.append('<div style="padding:10px;background:#1a0a0a;border:1px solid #e74c3c;border-radius:4px;margin-bottom:10px">')
            adv = diamond_model.get('adversary', {})
            secs.append(f'<div style="margin-bottom:6px"><strong style="color:#e74c3c">Adversary:</strong> {escape(adv.get("profile","Unknown"))}</div>')
            if diamond_model.get('infrastructure'):
                secs.append('<div style="margin-bottom:4px"><strong style="color:#e74c3c">Infrastructure:</strong></div>')
                secs.append('<div style="margin-left:14px;font-family:monospace;font-size:11px">')
                for inf in diamond_model['infrastructure'][:6]:
                    secs.append(f'{escape(str(inf.get("ip","")))}:{escape(str(inf.get("port","")))} — {escape(inf.get("role",""))} &nbsp; ')
                secs.append('</div>')
            if diamond_model.get('victims'):
                secs.append(f'<div style="margin-top:4px"><strong style="color:#e74c3c">Victims:</strong> ')
                secs.append(', '.join(f'{escape(str(v.get("identity","")))} ({escape(v.get("status",""))})' for v in diamond_model['victims'][:6]))
                secs.append('</div>')
            secs.append('</div>')
        # MAESTRO Kill Chain Stage Coverage
        if maestro_stages:
            secs.append(f'<div style="{SUB}">MAESTRO Kill Chain Coverage</div>')
            secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:10px">')
            secs.append('<thead><tr><th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Stage</th>'
                        '<th style="text-align:center;padding:3px 8px;border-bottom:1px solid #243144">Detected?</th>'
                        '<th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Evidence</th>'
                        '<th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Assessment</th></tr></thead><tbody>')
            for ms in maestro_stages:
                det_clr = '#2ecc71' if ms.get('detected') else '#555'
                det_txt = 'YES' if ms.get('detected') else 'NOT SEEN'
                ev_txt = ', '.join(ms.get('evidence_factors',[])[:3]) or '—'
                secs.append(f'<tr><td style="padding:3px 8px;border-bottom:1px solid #0e1722;font-weight:600;color:{clr}">{escape(ms.get("stage",""))}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;text-align:center;color:{det_clr}">{det_txt}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;font-family:monospace;font-size:10px">{escape(ev_txt)}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;color:#9bb">{escape(ms.get("description",""))}</td></tr>')
            secs.append('</tbody></table>')
        # Kill chain stage inference
        stages = []
        if any(f in all_factors for f in ('macro_lure','phishing_link','phishing_lure','email_malicious_url','phishing_subject')):
            stages.append(('Initial Access', 'Phishing / malicious email with macro lure', 'T1566.001'))
        if any(f in all_factors for f in ('powershell_execution','encoded_command','office_child_process','malicious_process','process_execution')):
            stages.append(('Execution', 'Scripted execution via PowerShell or malicious process', 'T1059.001'))
        if any(f in all_factors for f in ('suspicious_process','lolbin','temp_execution')):
            stages.append(('Defense Evasion', 'LOLBin or temp-path execution bypassing AV', 'T1218/T1036.005'))
        if any(f in all_factors for f in ('wmi_lateral_movement','rdp_lateral_movement','smb_lateral_movement')):
            stages.append(('Lateral Movement', 'Remote execution or admin-share access', 'T1021'))
        if any(f in all_factors for f in ('c2_beacon','network_beacon','c2_port','external_connection')):
            stages.append(('Command & Control', 'Outbound beacon to known-bad IP — likely implant callback', 'T1071.001'))
        if any(f in all_factors for f in ('credential_access','account_discovery')):
            stages.append(('Credential Access', 'OS credential dump or account enumeration', 'T1003/T1087'))
        if stages:
            secs.append(f'<div style="{SUB}">Inferred Kill Chain Stages</div>')
            secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:10px">')
            secs.append('<thead><tr><th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Stage</th>'
                        '<th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Evidence</th>'
                        '<th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">MITRE</th>'
                        '</tr></thead><tbody>')
            for stage, evidence, mitre in stages:
                secs.append(f'<tr><td style="padding:3px 8px;border-bottom:1px solid #0e1722;font-weight:600;color:{clr}">{escape(stage)}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722">{escape(evidence)}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;font-family:monospace;font-size:11px;color:#f4a">{escape(mitre)}</td></tr>')
            secs.append('</tbody></table>')
        # Hunt queries
        secs.append(f'<div style="{SUB}">Suggested Hunt Queries</div>')
        secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px">')
        secs.append('<thead><tr><th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144;width:120px">Query</th>'
                    '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Expression</th></tr></thead><tbody>')
        for qname, qtext in _NEXT_STEPS['threat_hunter']:
            secs.append(f'<tr><td style="padding:4px 8px;border-bottom:1px solid #151e2b;white-space:nowrap;color:#e74">{escape(qname)}</td>'
                        f'<td style="padding:4px 8px;border-bottom:1px solid #151e2b;font-family:monospace;font-size:11px">{escape(qtext)}</td></tr>')
        secs.append('</tbody></table>')
        # Blind Spots (P2: surface coverage gaps for analysts)
        if _opt('include_blind_spots', default=True):
            _blind_spots = [
                ('No EDR agent coverage on DCs', 'Domain controller process telemetry unavailable — lateral movement may be partially blind'),
                ('No network-level PCAP', 'Full packet capture not integrated — C2 payload content unverified'),
                ('WMI event subscription log state unknown', 'WMI persistence (T1546.003) cannot be confirmed absent — check WMI-Activity/Operational log retention'),
                ('AD/DC auth logs not in scope', 'Pass-the-hash / Kerberoasting stages inferred, not confirmed from DC Security log'),
                ('Email gateway lacks DKIM verification', 'Phishing attribution limited to SMTP headers — sender spoofing possible until DKIM check enabled (install dkimpy)'),
            ]
            secs.append(f'<details style="margin-top:12px;border:1px solid #e74c3c44;border-radius:4px;padding:0">')
            secs.append(f'<summary style="padding:8px 12px;cursor:pointer;color:#e74c3c;font-weight:600;font-size:12px">⚠ Blind Spots & Coverage Gaps ({len(_blind_spots)} identified)</summary>')
            secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px;margin:0">')
            secs.append('<thead><tr><th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144;width:220px">Gap</th>'
                        '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Impact</th></tr></thead><tbody>')
            for gap_title, gap_impact in _blind_spots:
                secs.append(f'<tr><td style="padding:4px 8px;border-bottom:1px solid #0e1722;color:#e74c3c;font-weight:600">{escape(gap_title)}</td>'
                            f'<td style="padding:4px 8px;border-bottom:1px solid #0e1722;color:#9bb">{escape(gap_impact)}</td></tr>')
            secs.append('</tbody></table></details>')
        secs.append('</div>')

    elif persona == 'compliance':
        clr = '#9b59b6'
        secs.append(f'<div style="{BLOCK.format(clr=clr)}">')
        secs.append(f'<div style="{HEAD.format(clr=clr)}">Compliance — Controls & Regulatory Obligations</div>')
        # STRIDE → Control Domain Mapping
        if stride_summary:
            _stride_ctrl_map = [
                ('S', 'Spoofing', 'Identity & Auth', 'ISO A.8.5 / NIST IA-2'),
                ('T', 'Tampering', 'Integrity Controls', 'ISO A.8.15 / NIST SI-7'),
                ('R', 'Repudiation', 'Audit & Logging', 'ISO A.8.15 / NIST AU-2'),
                ('I', 'Info Disclosure', 'Data Protection', 'GDPR Art.5(1)(f) / NIST SC-28'),
                ('D', 'Denial of Service', 'Availability', 'ISO A.8.6 / NIST CP-10'),
                ('E', 'Elevation of Priv', 'Access Control', 'ISO A.8.3 / NIST AC-6'),
            ]
            secs.append(f'<div style="{SUB}">STRIDE → Control Domain Mapping</div>')
            secs.append('<table style="width:100%;border-collapse:collapse;font-size:11px;margin-bottom:10px">')
            secs.append('<thead><tr>'
                        '<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #243144">STRIDE</th>'
                        '<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #243144">Control Domain</th>'
                        '<th style="text-align:center;padding:3px 6px;border-bottom:1px solid #243144">Status</th>'
                        '<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #243144">Framework</th>'
                        '</tr></thead><tbody>')
            for code, label, domain, fw in _stride_ctrl_map:
                s = stride_summary.get(code, {})
                status = s.get('status', 'NOT DETECTED')
                st_clr = '#e74c3c' if status == 'CONFIRMED' else ('#f1c40f' if status == 'SUSPECTED' else '#555')
                secs.append(f'<tr><td style="padding:3px 6px;border-bottom:1px solid #0e1722;font-weight:600;color:#c4b">{escape(code)} — {escape(label)}</td>'
                            f'<td style="padding:3px 6px;border-bottom:1px solid #0e1722">{escape(domain)}</td>'
                            f'<td style="padding:3px 6px;border-bottom:1px solid #0e1722;text-align:center;color:{st_clr}">{escape(status)}</td>'
                            f'<td style="padding:3px 6px;border-bottom:1px solid #0e1722;font-family:monospace;font-size:10px">{escape(fw)}</td></tr>')
            secs.append('</tbody></table>')
        # GDPR warning — clock based on DISCOVERY time, not incident time
        import datetime as _dt
        _discovery_ts = _dt.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        _gdpr_triggered = any(f in all_factors for f in (
            'credential_access', 'credential_harvest', 'phishing_lure', 'phishing_subject',
            'macro_lure', 'c2_beacon', 'c2_communication', 'c2_data_staging',
            'malicious_process', 'external_connection',
        ))
        if _gdpr_triggered:
            secs.append('<div style="padding:10px 14px;background:#1a0a20;border:1px solid #9b59b6;border-radius:4px;margin-bottom:10px">')
            secs.append(f'<strong style="color:#c4b">GDPR Art.33 — Breach Notification:</strong><br>')
            secs.append(f'72-hour clock starts at <strong>discovery</strong> ({escape(_discovery_ts)}), NOT at the incident timestamp.<br>')
            secs.append(f'PII in scope: employee email addresses confirmed in phishing/C2 data path.<br>')
            secs.append(f'<strong>Notification: LIKELY REQUIRED</strong> — unless controller can demonstrate unlikely risk to individuals.')
            secs.append('</div>')
        # PASTA Risk Register (for board/audit committee)
        if pasta_risks:
            secs.append(f'<div style="{SUB}">PASTA Risk Register (Stage 7)</div>')
            secs.append('<table style="width:100%;border-collapse:collapse;font-size:11px;margin-bottom:10px">')
            secs.append('<thead><tr><th style="text-align:left;padding:3px 6px;border-bottom:1px solid #243144">Risk</th>'
                        '<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #243144">Control Gap</th>'
                        '<th style="text-align:right;padding:3px 6px;border-bottom:1px solid #243144">Score</th></tr></thead><tbody>')
            _pasta_gap_map = {
                'Ransomware': 'EDR prevention mode OFF', 'domain compromise': 'Network segmentation absent',
                'PII': 'No DLP / egress filtering', 'Credential': 'MFA not enforced',
                'Regulatory': 'Notification pending', 'disruption': 'IR plan not tested',
            }
            for risk in pasta_risks[:6]:
                gap = next((v for k, v in _pasta_gap_map.items() if k.lower() in risk.get('risk','').lower()), 'Review required')
                score_clr = '#e74c3c' if risk.get('score',0) >= 8.0 else '#f1c40f'
                secs.append(f'<tr><td style="padding:3px 6px;border-bottom:1px solid #0e1722">{escape(risk.get("risk",""))}</td>'
                            f'<td style="padding:3px 6px;border-bottom:1px solid #0e1722;color:#9bb">{escape(gap)}</td>'
                            f'<td style="padding:3px 6px;border-bottom:1px solid #0e1722;text-align:right;color:{score_clr};font-weight:600">{risk.get("score",0)}/10</td></tr>')
            secs.append('</tbody></table>')
        # Framework mapping table
        if mitre_hits:
            fw_rows = []
            for tid, cnt in mitre_hits[:10]:
                fw = _MITRE_TO_FRAMEWORK.get(tid)
                if fw:
                    fw_rows.append((tid, cnt, fw))
            if fw_rows:
                secs.append(f'<div style="{SUB}">MITRE → Control Framework Mapping</div>')
                secs.append('<table style="width:100%;border-collapse:collapse;font-size:11px;margin-bottom:10px">')
                secs.append('<thead><tr>'
                            '<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #243144">Technique</th>'
                            '<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #243144">CIS</th>'
                            '<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #243144">ISO 27001</th>'
                            '<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #243144">SOC 2</th>'
                            '<th style="text-align:left;padding:3px 6px;border-bottom:1px solid #243144">GDPR</th>'
                            '</tr></thead><tbody>')
                for tid, cnt, fw in fw_rows:
                    secs.append(f'<tr><td style="padding:3px 6px;border-bottom:1px solid #0e1722;font-family:monospace">{escape(tid)}</td>'
                                f'<td style="padding:3px 6px;border-bottom:1px solid #0e1722">{escape(fw.get("CIS",""))}</td>'
                                f'<td style="padding:3px 6px;border-bottom:1px solid #0e1722">{escape(fw.get("ISO27001",""))}</td>'
                                f'<td style="padding:3px 6px;border-bottom:1px solid #0e1722">{escape(fw.get("SOC2",""))}</td>'
                                f'<td style="padding:3px 6px;border-bottom:1px solid #0e1722;color:#c4b">{escape(fw.get("GDPR",""))}</td>'
                                '</tr>')
                secs.append('</tbody></table>')
        # Compliance next steps
        secs.append(f'<div style="{SUB}">Compliance Action Plan</div>')
        secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px">')
        secs.append('<thead><tr><th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144;width:110px">Deadline</th>'
                    '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Action</th></tr></thead><tbody>')
        for deadline, action in _NEXT_STEPS['compliance']:
            secs.append(f'<tr><td style="padding:4px 8px;border-bottom:1px solid #151e2b;white-space:nowrap;color:#c4b">{escape(deadline)}</td>'
                        f'<td style="padding:4px 8px;border-bottom:1px solid #151e2b">{escape(action)}</td></tr>')
        secs.append('</tbody></table>')
        secs.append('</div>')

    elif persona == 'forensics':
        clr = '#e67e22'
        secs.append(f'<div style="{BLOCK.format(clr=clr)}">')
        secs.append(f'<div style="{HEAD.format(clr=clr)}">Forensics — Artefact Collection & Investigation</div>')
        # STRIDE Tamper/Repudiation flags for evidence integrity
        _t_stride = stride_summary.get('T', {})
        _r_stride = stride_summary.get('R', {})
        if _t_stride.get('count', 0) > 0 or _r_stride.get('count', 0) > 0:
            secs.append(f'<div style="padding:8px 12px;background:#1a120a;border:1px solid #e67e22;border-radius:4px;margin-bottom:10px">')
            secs.append(f'<strong style="color:#e67e22">STRIDE Evidence Integrity Flags:</strong><br>')
            if _t_stride.get('count', 0) > 0:
                secs.append(f'<strong>T — Tampering ({_t_stride["count"]} events):</strong> File writes and payload modifications detected. '
                            f'Preserve all dropped files BEFORE remediation — hash doc.doc and secondary payloads on disk.<br>')
            if _r_stride.get('count', 0) > 0:
                secs.append(f'<strong>R — Repudiation ({_r_stride["count"]} events):</strong> WMI interactive sessions suppress audit logging. '
                            f'Check for Event 4688 gaps; enable command-line process auditing before system restart.')
            secs.append('</div>')
        # IOC table — including SHA256 anomaly flagging
        hosts_seen, ips_seen, hashes_seen, processes_seen = set(), set(), set(), set()
        sha256_anomalies = []
        for r in rows:
            if r.get('host'): hosts_seen.add(r['host'])
            if r.get('dst_ip'): ips_seen.add(r['dst_ip'])
            if r.get('src_ip'): ips_seen.add(r['src_ip'])
            _sha = r.get('sha256') or ''
            if _sha: hashes_seen.add(_sha)
            # Flag anomalous hash values
            if _sha and (len(_sha) == 32 or _sha in ('d41d8cd98f00b204e9800998ecf8427e',)):
                _proc = r.get('process') or r.get('process_name') or r.get('host') or 'unknown'
                sha256_anomalies.append((_proc, _sha))
            if r.get('process') or r.get('process_name'):
                processes_seen.add(r.get('process') or r.get('process_name'))
        # Display SHA256 anomalies as a distinct warning block
        if sha256_anomalies:
            secs.append(f'<div style="padding:8px 12px;background:#0a0e1a;border:1px solid #e74c3c;border-radius:4px;margin-bottom:10px">')
            secs.append(f'<strong style="color:#e74c3c">⚠ SHA256 Integrity Anomaly Detected:</strong><br>')
            for _ap, _av in sha256_anomalies[:5]:
                _tag = 'MD5 collision (wrong hash algorithm)' if len(_av) == 32 else 'empty-file sentinel'
                secs.append(f'<code style="font-size:11px">{escape(_ap)}</code>: hash <code>{escape(_av[:20])}…</code> '
                            f'— <strong style="color:#e74c3c">ANOMALOUS ({_tag})</strong>. '
                            f'Collect file sample and recompute SHA256 from disk. Do not trust this hash for attribution.<br>')
            secs.append('</div>')
        ioc_rows = []
        for h in list(hosts_seen)[:5]:
            ioc_rows.append(('Host', h, 'Image memory + MFT'))
        for ip in list(ips_seen)[:5]:
            if ip not in ('', 'None'):
                ioc_rows.append(('IP', ip, 'PCAP + firewall logs'))
        for sha in list(hashes_seen)[:3]:
            if sha not in ('', 'None'):
                ioc_rows.append(('SHA-256', sha[:20]+'…', 'File sample + VT lookup'))
        for proc in list(processes_seen)[:5]:
            if proc not in ('', 'None'):
                ioc_rows.append(('Process', proc, 'Prefetch + Amcache + EDR telemetry'))
        if ioc_rows:
            secs.append(f'<div style="{SUB}">Artefacts to Collect (IOC List)</div>')
            secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:10px">')
            secs.append('<thead><tr><th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144;width:80px">Type</th>'
                        '<th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Value</th>'
                        '<th style="text-align:left;padding:3px 8px;border-bottom:1px solid #243144">Collection Source</th>'
                        '</tr></thead><tbody>')
            for ioc_type, value, source in ioc_rows:
                secs.append(f'<tr><td style="padding:3px 8px;border-bottom:1px solid #0e1722;color:#e67">{escape(ioc_type)}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;font-family:monospace;font-size:11px">{escape(str(value))}</td>'
                            f'<td style="padding:3px 8px;border-bottom:1px solid #0e1722;color:#9bb">{escape(source)}</td></tr>')
            secs.append('</tbody></table>')
        # Investigation checklist
        secs.append(f'<div style="{SUB}">Investigation Checklist</div>')
        secs.append('<table style="width:100%;border-collapse:collapse;font-size:12px">')
        secs.append('<thead><tr><th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144;width:140px">Step</th>'
                    '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Action</th></tr></thead><tbody>')
        for step, action in _NEXT_STEPS['forensics']:
            secs.append(f'<tr><td style="padding:4px 8px;border-bottom:1px solid #151e2b;white-space:nowrap;color:#e67">{escape(step)}</td>'
                        f'<td style="padding:4px 8px;border-bottom:1px solid #151e2b">{escape(action)}</td></tr>')
        secs.append('</tbody></table>')
        secs.append('</div>')

    return '\n'.join(secs)


# ── shared HTML scaffold ─────────────────────────────────────────────────────
def _wrap_page(title_esc: str, body: str, accent: str) -> str:
    css = (
        'body{background:#0c1520;color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;'
        'padding:24px;max-width:1200px;margin:0 auto}'
        'h2,h3,h4{color:#e6eef8}table{width:100%;border-collapse:collapse;table-layout:fixed}'
        'th{text-align:left;padding:5px 8px;border-bottom:1px solid #243144;color:#9bb;font-size:11px;text-transform:uppercase}'
        'td{padding:5px 8px;border-bottom:1px solid #0e1722;overflow-wrap:break-word}'
        'a{color:#5b9bd5}pre{overflow-x:auto;background:#0a1018;padding:10px;border-radius:6px}'
        'details>summary{cursor:pointer;padding:8px 12px;font-size:12px;font-weight:600}'
        f'details{{border:1px solid {accent}44;border-radius:6px;margin-top:14px}}'
        '.pill{display:inline-block;padding:2px 9px;border-radius:12px;font-size:11px;margin:2px}'
        '.section{margin-top:18px;padding:16px;background:#0e1828;border-left:4px solid '
        + accent + ';border-radius:6px}'
        '.warn{padding:12px 16px;border-radius:6px;margin-bottom:14px}'
        '.stat-bar{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}'
        '.stat{padding:10px 16px;border-radius:6px;background:#0d1620;flex:1;min-width:90px;text-align:center}'
        '.stat .n{font-size:24px;font-weight:700}'
        '.stat .l{font-size:11px;color:#9bb}'
    )
    return (
        f'<!doctype html><html><head><meta charset="utf-8"><title>{title_esc}</title>'
        f'<style>{css}</style></head><body>{body}</body></html>'
    )


def _page_header(label: str, verdict: str, confidence: str, company: str,
                 session: str, generated_at: str, accent: str) -> str:
    conf_part = f' — {escape(confidence)}%' if confidence else ''
    co_part = f'<strong style="color:#e6eef8">{escape(company)}</strong> &nbsp;·&nbsp; ' if company else ''
    return (
        f'<div style="border-bottom:3px solid {accent};padding-bottom:12px;margin-bottom:18px">'
        f'<h2 style="margin:0;color:{accent};letter-spacing:.03em">{escape(label)}{conf_part}</h2>'
        f'<div style="font-size:13px;font-weight:700;color:#e74c3c;margin-top:6px">'
        f'{escape(verdict)}</div>'
        f'<div style="color:#9bb;font-size:11px;margin-top:4px">'
        f'{co_part}Session: <code>{escape(str(session))}</code>'
        f' &nbsp;·&nbsp; Generated: {generated_at}</div>'
        f'</div>'
    )


def _stat_bar(items: list) -> str:
    """items = list of (number, label, color)"""
    parts = ['<div class="stat-bar">']
    for n, lbl, clr in items:
        parts.append(f'<div class="stat"><div class="n" style="color:{clr}">{escape(str(n))}</div>'
                     f'<div class="l">{escape(lbl)}</div></div>')
    parts.append('</div>')
    return '\n'.join(parts)


def _collapsible(summary_label: str, body_html: str, accent: str) -> str:
    return (f'<details style="border:1px solid {accent}44;border-radius:6px;margin-top:14px">'
            f'<summary style="padding:8px 12px;color:{accent};font-weight:600;font-size:12px">'
            f'{escape(summary_label)}</summary>'
            f'<div style="padding:12px">{body_html}</div></details>')


def _table(headers: list, rows_html: list, style: str = '') -> str:
    ths = ''.join(f'<th>{escape(h)}</th>' for h in headers)
    return (f'<table style="{style}"><thead><tr>{ths}</tr></thead>'
            f'<tbody>{"".join(rows_html)}</tbody></table>')


def _td(val, mono: bool = False, clr: str = '', align: str = 'left') -> str:
    s = f'text-align:{align};'
    if clr:
        s += f'color:{clr};'
    if mono:
        s += 'font-family:monospace;font-size:11px;'
    return f'<td style="{s}">{escape(str(val))}</td>'


# ── per-persona full-page builders ───────────────────────────────────────────

from src.reporting.html.scaffold import (  # noqa: E402,F811
    collapsible as _collapsible,
    page_header as _page_header,
    stat_bar as _stat_bar,
    table as _table,
    td as _td,
    wrap_page as _wrap_page,
)


def _build_soc_page(payload: dict, meta: dict, assessment_view: dict,
                    session: str, company: str, generated_at: str) -> str:
    accent = '#e05252'
    rows = payload.get('rows') or []
    all_factors = _collect_all_factors(rows)
    mitre_hits = _collect_mitre(rows)

    verdict = str(assessment_view.get('verdict') or meta.get('verdict') or 'UNDER INVESTIGATION').upper()
    conf_raw = assessment_view.get('confidence') or meta.get('confidence') or ''
    try:
        confidence = str(int(float(conf_raw) * 100)) if conf_raw and float(conf_raw) <= 1 else str(int(float(conf_raw))) if conf_raw else ''
    except Exception:
        confidence = str(conf_raw)

    n_flagged = sum(1 for r in rows if
                    float(r.get('risk_score') or r.get('confidence') or r.get('dread_score') or 0) > 0.05
                    or str(r.get('verdict') or '').lower() in ('malicious', 'suspicious', 'review', 'escalate')
                    or str(r.get('severity') or '').lower() in ('critical', 'high', 'medium'))
    cluster_count = int(assessment_view.get('cluster_count') or 0)
    source_count = int(assessment_view.get('source_count') or 0)

    parts = [_page_header('SOC ANALYST REPORT', verdict, confidence, company, session, generated_at, accent)]

    # stat bar
    parts.append(_stat_bar([
        (n_flagged, 'Flagged Events', '#e05252'),
        (cluster_count, 'Clusters', '#f59e0b'),
        (source_count, 'Sources', '#60a5fa'),
        (len(mitre_hits), 'MITRE Techniques', '#a78bfa'),
    ]))

    # Severity Distribution + Top MITRE Techniques — always rendered so the report has a
    # consistent structure (and a CEO/analyst can see "nothing observed" vs a missing
    # section). Data flows from aggregate_decisions via the report payload.
    _sev_dist = payload.get('severity_distribution') or payload.get('severity_counts') or {}
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:8px">Severity Distribution</strong>')
    if _sev_dist:
        parts.append('<table><thead><tr><th>Severity</th><th style="width:100px">Count</th></tr></thead><tbody>')
        for _sev in ('critical', 'high', 'medium', 'low'):
            parts.append(f'<tr><td>{escape(_sev.title())}</td>'
                         f'<td style="text-align:right">{int(_sev_dist.get(_sev, 0) or 0)}</td></tr>')
        parts.append('</tbody></table>')
    else:
        parts.append('<div style="color:#9bb">No severity data.</div>')
    parts.append('</div>')

    _top_mitre = payload.get('top_mitre') or []
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:8px">Top MITRE Techniques</strong>')
    if _top_mitre:
        parts.append('<div>')
        for _m in _top_mitre[:12]:
            _tid = (_m.get('technique') if isinstance(_m, dict) else str(_m)) or ''
            _cnt = (_m.get('count', 1) if isinstance(_m, dict) else 1)
            _name = _MITRE_NAMES.get(_tid, '')
            _lbl = _tid + (f' · {_name}' if _name else '')
            parts.append(f'<span class="pill" style="background:#1c1020;color:#c084fc">'
                         f'{escape(str(_lbl))} ({int(_cnt)})</span>')
        parts.append('</div>')
    else:
        parts.append('<div style="color:#9bb">No MITRE techniques observed.</div>')
    parts.append('</div>')

    # START HERE box
    parts.append('<div class="warn" style="background:#1a0a0a;border:2px solid #e05252">')
    parts.append(f'<div style="color:{accent};font-weight:700;font-size:14px;margin-bottom:10px">START HERE — CONTAINMENT TIMELINE</div>')
    parts.append('<table><thead><tr><th style="width:110px">Window</th><th>Action</th></tr></thead><tbody>')
    for timeframe, action in _NEXT_STEPS['soc_analyst']:
        parts.append(f'<tr><td style="color:#f87171;font-weight:600;white-space:nowrap">{escape(timeframe)}</td>'
                     f'<td>{escape(action)}</td></tr>')
    parts.append('</tbody></table></div>')

    # CORRELATION DETAILS — cross-domain verdict + campaign progression + temporal anomalies.
    # Surfaces the behavioral _campaign_links and ChronoGraph factors that were previously
    # computed but never rendered, so the report tells one campaign story.
    corr = payload.get('correlation') or {}
    campaign_links = (payload.get('campaign_links') or assessment_view.get('campaign_links')
                      or [l for r in rows for l in (r.get('campaign_links') or [])])
    chrono_factors = sorted(
        {f for r in rows for f in (r.get('_chrono_factors') or [])}
        | set(assessment_view.get('chrono_factors') or [])
    )
    if corr or campaign_links or chrono_factors:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">Correlation details</strong>')
        if corr:
            cv = escape(str(corr.get('verdict') or '').upper())
            _cc = corr.get('confidence')
            cc_s = f" · {int(float(_cc) * 100)}% confidence" if _cc not in (None, '') else ''
            doms = ', '.join(escape(str(d)) for d in (corr.get('top_domains') or []))
            rec = escape(str(corr.get('recommended_action') or ''))
            parts.append('<table><tbody>')
            parts.append(f'<tr><td style="width:170px;color:#9bb">Cross-domain verdict</td>'
                         f'<td style="font-weight:600;color:#f87171">{cv}{cc_s}</td></tr>')
            if doms:
                parts.append(f'<tr><td style="color:#9bb">Domains involved</td><td>{doms}</td></tr>')
            if rec:
                parts.append(f'<tr><td style="color:#9bb">Recommended action</td>'
                             f'<td style="font-weight:600;color:#fbbf24">{rec}</td></tr>')
            parts.append('</tbody></table>')
        if campaign_links:
            parts.append('<div style="margin-top:8px;color:#fbbf24">Campaign progression (linked clusters):</div>'
                         '<ul style="margin:4px 0 0 18px;color:#cbd5e1">')
            for l in campaign_links[:6]:
                rel = escape(str(l.get('relationship') or 'linked'))
                cid = escape(str(l.get('cluster_id') or ''))
                parts.append(f'<li>{rel} cluster {cid}</li>')
            parts.append('</ul>')
        if chrono_factors:
            parts.append('<div style="margin-top:8px;color:#c7d2fe">Temporal anomalies (ChronoGraph): '
                         + ' '.join(f'<span class="pill" style="background:#1a2030;color:#c7d2fe">{escape(f)}</span>'
                                    for f in chrono_factors[:8]) + '</div>')
        parts.append('</div>')

    # KEY FACTORS — the deterministic signals that drove the verdict.
    if all_factors:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:8px">Key factors</strong>')
        parts.append('<div>')
        for fac, cnt in sorted(all_factors.items(), key=lambda x: -x[1])[:18]:
            lbl = _FACTOR_LABELS.get(fac, fac)
            parts.append(f'<span class="pill" style="background:#2a1520;color:#fca5a5">'
                         f'{escape(str(lbl))} ({cnt})</span>')
        parts.append('</div></div>')

    # IOC TRIAGE table
    hosts_seen, ips_seen, hashes_seen, domains_seen = set(), set(), set(), set()
    for r in rows:
        if r.get('host'): hosts_seen.add(r['host'])
        if r.get('dst_ip'): ips_seen.add(r['dst_ip'])
        if r.get('src_ip'): ips_seen.add(r['src_ip'])
        if r.get('sha256'): hashes_seen.add(r['sha256'])
        if r.get('domain'): domains_seen.add(r['domain'])
        if r.get('dst_domain'): domains_seen.add(r['dst_domain'])

    ioc_rows_html = []
    for ip in list(ips_seen)[:8]:
        if ip and ip not in ('None',):
            ioc_rows_html.append(f'<tr><td style="color:#f87171">IP</td>'
                                 f'<td style="font-family:monospace;font-size:11px">{escape(str(ip))}</td>'
                                 f'<td>Block at perimeter firewall</td></tr>')
    for d in list(domains_seen)[:5]:
        if d and d not in ('None',):
            ioc_rows_html.append(f'<tr><td style="color:#fbbf24">Domain</td>'
                                 f'<td style="font-family:monospace;font-size:11px">{escape(str(d))}</td>'
                                 f'<td>DNS sinkhole / proxy block</td></tr>')
    for h in list(hashes_seen)[:5]:
        if h and h not in ('None',):
            ioc_rows_html.append(f'<tr><td style="color:#a78bfa">Hash</td>'
                                 f'<td style="font-family:monospace;font-size:11px">{escape(str(h)[:40])}…</td>'
                                 f'<td>Submit VT / sandbox; block in EDR</td></tr>')
    if ioc_rows_html:
        parts.append('<div class="section">')
        parts.append(f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'
                     f'<strong style="color:{accent}">IOC TRIAGE</strong>'
                     f'<button onclick="(function(){{var t=document.getElementById(\'ioc-list\').innerText;navigator.clipboard.writeText(t)}})()" '
                     f'style="background:{accent};color:#fff;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:11px">'
                     f'Copy All IOCs</button></div>')
        parts.append(f'<div id="ioc-list"><table><thead><tr><th style="width:80px">Type</th><th>Value</th><th>Action</th></tr></thead>'
                     f'<tbody>{"".join(ioc_rows_html)}</tbody></table></div>')
        parts.append('</div>')

    # HOST CONTAINMENT
    if hosts_seen:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">HOST CONTAINMENT</strong>')
        parts.append('<table><thead><tr><th>Host</th><th style="width:100px">Priority</th><th>Action</th></tr></thead><tbody>')
        for i, h in enumerate(list(hosts_seen)[:10]):
            prio = 'CRITICAL' if i == 0 else ('HIGH' if i < 3 else 'MEDIUM')
            prio_clr = '#e74c3c' if prio == 'CRITICAL' else ('#f59e0b' if prio == 'HIGH' else '#fbbf24')
            parts.append(f'<tr><td style="font-family:monospace;font-size:11px">{escape(str(h))}</td>'
                         f'<td style="color:{prio_clr};font-weight:700">{prio}</td>'
                         f'<td>Isolate NIC / quarantine in EDR console</td></tr>')
        parts.append('</tbody></table></div>')

    # SIEM DETECTION GAPS
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:8px">SIEM DETECTION GAPS</strong>')
    parts.append('<ul style="margin:0 0 0 18px;color:#fde68a">')
    gap_list = [
        'No alert fired on encoded PowerShell (-enc) execution — add Sysmon Event 1 rule',
        'C2 beacon interval not baselined — configure UEBA for periodic outbound anomaly',
        'Lateral movement via WMI not correlated across hosts — enable WMI-Activity/Operational log ingestion',
        'No alert on process write to temp path followed by execution — add file-event + process-start correlation rule',
        'Email gateway IOC not cross-referenced against network firewall logs',
    ]
    # surface factor-specific gaps
    if 'lolbin' in all_factors:
        gap_list.insert(0, 'LOLBin execution (e.g. rundll32/certutil) not alerted — add LOLBAS-based detection rule')
    if 'rdp_lateral_movement' in all_factors:
        gap_list.insert(1, 'RDP lateral movement not alerted — correlate Event 4624 (Type 10) across hosts')
    for g in gap_list[:6]:
        parts.append(f'<li style="margin:4px 0">{escape(g)}</li>')
    parts.append('</ul></div>')

    # CONTROL FAILURES → SOC ACTIONS
    top_factors = assessment_view.get('top_factors') or []
    if top_factors:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">CONTROL FAILURES → SOC ACTIONS</strong>')
        parts.append('<table><thead><tr><th style="width:140px">Factor / Control</th><th style="width:120px">Gap Type</th><th>SOC Action Now</th></tr></thead><tbody>')
        soc_action_map = {
            'c2_beacon': ('Detection Gap', 'Block outbound C2 IPs at firewall; alert Tier-2'),
            'c2_communication': ('Detection Gap', 'Isolate implanted host; pull memory image before restart'),
            'lateral_movement': ('Prevention Gap', 'Revoke impersonated credentials; audit admin shares'),
            'credential_access': ('Detection Gap', 'Force password reset for affected accounts; check for token reuse'),
            'powershell_execution': ('Policy Gap', 'Enable PowerShell script-block logging; constrained language mode'),
            'encoded_command': ('Detection Gap', 'Alert on -enc flag in process args; detonate sample in sandbox'),
            'lolbin': ('Allowlist Gap', 'Review application allowlist; block unsigned LOLBin variants'),
            'phishing_lure': ('Prevention Gap', 'Quarantine phishing emails; reset credentials of recipients'),
            'macro_lure': ('Policy Gap', 'Disable macros via GPO for all non-approved users immediately'),
            'rdp_lateral_movement': ('Network Gap', 'Block RDP (3389) between workstations at switch ACL'),
            'smb_lateral_movement': ('Network Gap', 'Block SMB (445) lateral; check for admin share mounts'),
        }
        shown = 0
        for item in top_factors[:12]:
            fname = str(item.get('factor') or '')
            if fname in soc_action_map:
                gap_type, action = soc_action_map[fname]
                label = _FACTOR_LABELS.get(fname, fname)
                parts.append(f'<tr><td style="font-family:monospace;font-size:11px;color:#fbbf24">{escape(fname)}</td>'
                             f'<td style="color:#f87171">{escape(gap_type)}</td>'
                             f'<td>{escape(action)}</td></tr>')
                shown += 1
        if shown == 0:
            parts.append('<tr><td colspan="3" style="color:#9bb">No specific control failures mapped — review factors manually</td></tr>')
        parts.append('</tbody></table></div>')

    # MITRE coverage chips
    if mitre_hits:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:8px">MITRE ATT&CK COVERAGE</strong>')
        parts.append('<div>')
        for tid, cnt in mitre_hits[:16]:
            name = _MITRE_NAMES.get(tid, '')
            lbl = f'{tid}' + (f' · {name}' if name else '')
            parts.append(f'<span class="pill" style="background:#1c1020;color:#c084fc">{escape(lbl)} ({cnt})</span>')
        parts.append('</div></div>')

    # Collapsible: cluster table + raw event appendix
    clusters = assessment_view.get('cluster_rollups') or payload.get('clusters') or []
    coll_parts = []
    if clusters:
        coll_parts.append('<strong style="color:#9bb">Correlated Clusters</strong>')
        coll_parts.append('<table style="margin-top:6px"><thead><tr><th>Cluster</th><th>Verdict</th><th>Rows</th><th>Key Factors</th></tr></thead><tbody>')
        for c in clusters[:15]:
            verdict_c = c.get('final_verdict') or c.get('verdict') or 'UNKNOWN'
            ctitle = c.get('title') or c.get('incident_name') or c.get('cluster_id') or 'cluster'
            cfactors = [str(f) for f in (c.get('key_factors') or c.get('factor_tags') or [])[:6]]
            fchtml = ' '.join(f'<span class="pill" style="background:#1a2030;color:#c7d2fe">{escape(f)}</span>' for f in cfactors)
            coll_parts.append(f'<tr><td>{escape(str(ctitle)[:120])}</td>'
                              f'<td style="color:#f87171;font-weight:600">{escape(str(verdict_c))}</td>'
                              f'<td style="text-align:right">{int(c.get("row_count") or 0):,}</td>'
                              f'<td>{fchtml}</td></tr>')
        coll_parts.append('</tbody></table>')

    flagged_rows = [r for r in rows if
                    float(r.get('risk_score') or r.get('confidence') or r.get('dread_score') or 0) > 0.05
                    or str(r.get('verdict') or '').lower() in ('malicious', 'suspicious', 'review', 'escalate')]
    if flagged_rows:
        coll_parts.append(f'<strong style="color:#9bb;display:block;margin-top:14px">Raw Event Appendix ({len(flagged_rows)} flagged rows)</strong>')
        # Structured one-line summary per row (no raw-JSON <pre> dump — that was unreadable
        # and the reason persona reports looked like a data dump).
        _preview_fields = ('timestamp', 'host', 'user', 'process_name', 'command_line',
                           'verdict', 'src_ip', 'dst_ip', 'domain', 'dst_domain', 'sha256')
        for i, r in enumerate(flagged_rows[:30]):
            _kv = []
            for k in _preview_fields:
                v = r.get(k)
                if v not in (None, '', 'None'):
                    _kv.append(f'<span style="color:#7f93a8">{escape(k)}</span>=' + escape(str(v)[:80]))
            coll_parts.append(
                f'<div style="margin:4px 0;font-size:11px;line-height:1.5">'
                f'<strong style="color:#9bb">Row {i+1}</strong> · '
                + ' · '.join(_kv) + '</div>')

    if coll_parts:
        parts.append(_collapsible('Cluster Table & Raw Event Appendix', '\n'.join(coll_parts), accent))

    body = '\n'.join(parts)
    title_esc = f'SOC Analyst Report — {escape(verdict)}'
    return _wrap_page(title_esc, body, accent)


def _build_ciso_page(payload: dict, meta: dict, assessment_view: dict,
                     session: str, company: str, generated_at: str) -> str:
    import datetime as _dt
    accent = '#7c3aed'
    rows = payload.get('rows') or []
    all_factors = _collect_all_factors(rows)
    mitre_hits = _collect_mitre(rows)

    verdict = str(assessment_view.get('verdict') or meta.get('verdict') or 'UNDER INVESTIGATION').upper()
    conf_raw = assessment_view.get('confidence') or meta.get('confidence') or ''
    try:
        confidence = str(int(float(conf_raw) * 100)) if conf_raw and float(conf_raw) <= 1 else str(int(float(conf_raw))) if conf_raw else ''
    except Exception:
        confidence = str(conf_raw)

    discovery_ts = _dt.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    cluster_count = int(assessment_view.get('cluster_count') or 0)
    validated_count = int(assessment_view.get('validated_breach_count') or 0)

    parts = [_page_header('CISO / LEGAL REPORT', verdict, confidence, company, session, generated_at, accent)]

    parts.append(_stat_bar([
        (validated_count, 'Validated Breaches', '#f87171'),
        (cluster_count, 'Correlated Clusters', '#a78bfa'),
        (len(mitre_hits), 'MITRE Techniques', '#60a5fa'),
    ]))

    # REGULATORY CLOCK STATUS
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">REGULATORY CLOCK STATUS</strong>')
    parts.append(f'<div style="font-size:11px;color:#9bb;margin-bottom:8px">Discovery time: <strong style="color:#e6eef8">{escape(discovery_ts)}</strong></div>')

    gdpr_triggered = any(f in all_factors for f in (
        'credential_access', 'credential_harvest', 'phishing_lure', 'phishing_subject',
        'macro_lure', 'c2_beacon', 'c2_communication', 'c2_data_staging',
        'malicious_process', 'external_connection',
    ))
    regimes = [
        ('GDPR Art.33', '72h', 'red' if gdpr_triggered else 'grey',
         'Notify DPA if personal data affected' if gdpr_triggered else 'Likely not triggered — verify PII scope'),
        ('NIS2 / CER', '24h early warning + 72h', '#f59e0b',
         'Early warning to CSIRT; full notification at 72h'),
        ('SEC Cyber Rule', '4 business days', '#f59e0b',
         'Material incident disclosure to SEC Form 8-K if publicly listed'),
        ('HIPAA Breach', '60 days', '#60a5fa',
         'Notify HHS and affected individuals if PHI in scope'),
        ('PCI DSS 4.0', 'Immediate', '#f87171' if any(f in all_factors for f in ('c2_beacon','credential_access')) else '#555',
         'Notify acquiring bank and card brands if CHD in scope'),
    ]
    parts.append('<table><thead><tr><th>Regime</th><th style="width:130px">Clock / Deadline</th><th style="width:80px">Status</th><th>Obligation</th></tr></thead><tbody>')
    for regime, clock, clr_key, obligation in regimes:
        status_clr = '#e74c3c' if clr_key == 'red' else ('#f59e0b' if clr_key not in ('#60a5fa', '#555') else clr_key)
        status_txt = 'LIKELY TRIGGERED' if clr_key == 'red' else ('POSSIBLE' if clr_key == '#f59e0b' else ('IN SCOPE' if clr_key == '#60a5fa' else 'NOT TRIGGERED'))
        parts.append(f'<tr><td style="font-weight:600">{escape(regime)}</td>'
                     f'<td style="color:#fbbf24;font-family:monospace">{escape(clock)}</td>'
                     f'<td style="color:{status_clr};font-weight:700">{status_txt}</td>'
                     f'<td style="color:#9bb">{escape(obligation)}</td></tr>')
    parts.append('</tbody></table></div>')

    # Legal boundary warning
    parts.append('<div class="warn" style="background:#150d20;border:1px solid #7c3aed">')
    parts.append(f'<strong style="color:#c4b5fd">JanuSec validates the technical evidence path only.</strong> '
                 f'Whether a breach triggers a legal notification obligation requires your attestation as the data controller. '
                 f'This report cannot substitute for legal counsel.')
    parts.append('</div>')

    # MATERIALITY ASSESSMENT
    executive_story = assessment_view.get('executive_story') or {}
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:8px">MATERIALITY ASSESSMENT</strong>')
    parts.append('<table><thead><tr><th style="width:120px">Dimension</th><th>Assessment</th></tr></thead><tbody>')
    parts.append(f'<tr><td style="color:#9bb">Technical Verdict</td><td style="font-weight:700;color:#f87171">{escape(verdict)}</td></tr>')
    parts.append(f'<tr><td style="color:#9bb">Confidence</td><td>{escape(confidence + "%" if confidence else "—")}</td></tr>')
    biz_decision = str(executive_story.get('business_decision') or 'Incident under investigation — materiality pending full scope assessment.')
    parts.append(f'<tr><td style="color:#9bb">Rationale</td><td style="color:#e6eef8">{escape(biz_decision[:300])}</td></tr>')
    parts.append(f'<tr><td style="color:#9bb">PII Exposure</td><td style="color:{"#f87171" if gdpr_triggered else "#4ade80"}">'
                 f'{"POSSIBLE — GDPR scope review required" if gdpr_triggered else "Not indicated — verify with data-owner attestation"}'
                 f'</td></tr>')
    parts.append('</tbody></table></div>')

    # SIGN-OFF CHECKLIST
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">YOUR SIGN-OFF CHECKLIST</strong>')
    checklist = [
        ('Confirm data-owner attestation on PII scope', 'Before any notification decision'),
        ('Brief General Counsel on technical findings', 'Before 24h mark'),
        ('Decide: notify DPA Y/N — document rationale', 'Before 72h GDPR deadline'),
        ('Authorise forensics scope and evidence preservation', 'Immediately'),
        ('Approve board/exec communications language', 'Within 4 business hours'),
        ('Assign control owners for each identified gap', 'Within 48h'),
    ]
    parts.append('<div style="font-size:13px">')
    for item, deadline in checklist:
        parts.append(f'<div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid #1e2535">'
                     f'<input type="checkbox" style="margin-top:3px;accent-color:{accent}">'
                     f'<div><span style="color:#e6eef8">{escape(item)}</span>'
                     f'<span style="color:#9bb;font-size:11px;display:block">{escape(deadline)}</span></div></div>')
    parts.append('</div></div>')

    # CONTROL FAILURES table
    top_factors = assessment_view.get('top_factors') or []
    if top_factors:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">CONTROL FAILURES — ISMS ACCOUNTABILITY</strong>')
        parts.append('<table><thead><tr><th>Factor / Control</th><th>Gap Type</th><th>Your ISMS Accountability</th></tr></thead><tbody>')
        isms_map = {
            'c2_beacon': ('Detection', 'Ensure MDR/SIEM contract covers C2 detection SLA; review SOC-2 CC7.2'),
            'credential_access': ('Access Control', 'ISO A.9.2.4 — enforce MFA; commission PAM review'),
            'lateral_movement': ('Network Segmentation', 'ISO A.13.1.3 — commission network segmentation audit'),
            'powershell_execution': ('Endpoint Hardening', 'ISO A.12.6.1 — enforce application control policy via GPO'),
            'phishing_lure': ('Security Awareness', 'ISO A.6.3 — commission staff phishing training programme'),
            'macro_lure': ('Email Security', 'ISO A.8.23 — disable macros org-wide via policy'),
            'rdp_lateral_movement': ('Network Access', 'ISO A.9.4.2 — restrict RDP to jump-server only'),
            'lolbin': ('Endpoint Control', 'CIS-8.9 — deploy application allowlisting'),
            'c2_data_staging': ('DLP', 'ISO A.8.12 — deploy egress DLP for data exfil detection'),
        }
        shown = 0
        for item in top_factors[:12]:
            fname = str(item.get('factor') or '')
            if fname in isms_map:
                gap_type, action = isms_map[fname]
                parts.append(f'<tr><td style="font-family:monospace;font-size:11px;color:#c4b5fd">{escape(fname)}</td>'
                             f'<td style="color:#f87171">{escape(gap_type)}</td>'
                             f'<td>{escape(action)}</td></tr>')
                shown += 1
        if shown == 0:
            parts.append('<tr><td colspan="3" style="color:#9bb">No specific control failures mapped — review with your ISMS lead</td></tr>')
        parts.append('</tbody></table></div>')

    # Collapsible: board memo draft, ISO 27035 audit trail, SOA impact
    coll_parts = []
    # Board memo draft
    coll_parts.append(f'<strong style="color:{accent};display:block;margin-bottom:8px">BOARD MEMO DRAFT</strong>')
    coll_parts.append(f'<div style="background:#0a0d14;padding:12px;border-radius:6px;font-size:12px;color:#e6eef8;white-space:pre-wrap">'
                      f'BOARD CONFIDENTIAL — CYBER INCIDENT BRIEFING\n\n'
                      f'Date: {generated_at}\n'
                      f'Prepared by: CISO / Security Operations\n\n'
                      f'INCIDENT STATUS: {verdict}\n\n'
                      f'We have identified a security incident affecting our environment. '
                      f'JanuSec has correlated {cluster_count} incident clusters across {int(assessment_view.get("source_count") or 0)} data sources. '
                      f'Containment actions are {"underway" if validated_count > 0 else "being assessed"}.\n\n'
                      f'Next briefing: [DATE / TIME]\nContact: [CISO NAME]\n</div>')

    # ISO 27035 phases
    executive_story2 = assessment_view.get('executive_story') or {}
    lifecycle = (executive_story2.get('iso27035_lifecycle') or {}) if isinstance(executive_story2, dict) else {}
    phases = lifecycle.get('phases') or [] if isinstance(lifecycle, dict) else []
    if phases:
        coll_parts.append('<strong style="color:#9bb;display:block;margin-top:14px;margin-bottom:6px">ISO 27035 AUDIT TRAIL</strong>')
        coll_parts.append('<table><thead><tr><th>Phase</th><th>Status</th><th>Evidence</th></tr></thead><tbody>')
        for phase in phases[:6]:
            coll_parts.append(f'<tr><td style="color:#93c5fd;font-weight:600">{escape(str(phase.get("phase") or ""))}</td>'
                              f'<td>{escape(str(phase.get("status") or ""))}</td>'
                              f'<td style="color:#9bb">{escape(str(phase.get("evidence") or ""))}</td></tr>')
        coll_parts.append('</tbody></table>')

    # Framework mapping
    fw_rows = [(tid, cnt, _MITRE_TO_FRAMEWORK[tid]) for tid, cnt in mitre_hits[:10] if tid in _MITRE_TO_FRAMEWORK]
    if fw_rows:
        coll_parts.append('<strong style="color:#9bb;display:block;margin-top:14px;margin-bottom:6px">SOA IMPACT (ISO 27001 ANNEX A)</strong>')
        coll_parts.append('<table><thead><tr><th>Technique</th><th>CIS</th><th>ISO 27001</th><th>SOC 2</th><th>GDPR</th></tr></thead><tbody>')
        for tid, cnt, fw in fw_rows:
            coll_parts.append(f'<tr><td style="font-family:monospace;color:#c4b5fd">{escape(tid)}</td>'
                              f'<td>{escape(fw.get("CIS",""))}</td><td>{escape(fw.get("ISO27001",""))}</td>'
                              f'<td>{escape(fw.get("SOC2",""))}</td><td style="color:#c4b5fd">{escape(fw.get("GDPR",""))}</td></tr>')
        coll_parts.append('</tbody></table>')

    parts.append(_collapsible('Board Memo Draft · ISO 27035 Audit Trail · SOA Impact', '\n'.join(coll_parts), accent))

    body = '\n'.join(parts)
    return _wrap_page(f'CISO Report — {escape(verdict)}', body, accent)


def _build_executive_page(payload: dict, meta: dict, assessment_view: dict,
                          session: str, company: str, generated_at: str) -> str:
    accent = '#3b82f6'
    rows = payload.get('rows') or []
    all_factors = _collect_all_factors(rows)

    verdict = str(assessment_view.get('verdict') or meta.get('verdict') or 'UNDER INVESTIGATION').upper()
    conf_raw = assessment_view.get('confidence') or meta.get('confidence') or ''
    try:
        confidence = str(int(float(conf_raw) * 100)) if conf_raw and float(conf_raw) <= 1 else str(int(float(conf_raw))) if conf_raw else ''
    except Exception:
        confidence = str(conf_raw)

    validated_count = int(assessment_view.get('validated_breach_count') or 0)
    cluster_count = int(assessment_view.get('cluster_count') or 0)
    source_count = int(assessment_view.get('source_count') or 0)
    executive_story = assessment_view.get('executive_story') or {}

    parts = [_page_header('EXECUTIVE BRIEFING — CONFIDENTIAL', verdict, confidence, company, session, generated_at, accent)]

    # CONFIRMED BREACH hero block
    breach_clr = '#ef4444' if 'BREACH' in verdict or 'MALICIOUS' in verdict else '#f59e0b'
    parts.append(f'<div style="text-align:center;padding:24px;background:#0f0a0a;border:2px solid {breach_clr};border-radius:8px;margin-bottom:20px">')
    parts.append(f'<div style="font-size:36px;font-weight:900;color:{breach_clr};letter-spacing:.05em">{escape(verdict)}</div>')
    if confidence:
        parts.append(f'<div style="font-size:16px;color:#9bb;margin-top:6px">{escape(confidence)}% confidence · {validated_count} validated breach cluster{"s" if validated_count != 1 else ""}</div>')
    parts.append('</div>')

    # WHAT HAPPENED — plain English
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">WHAT HAPPENED</strong>')
    what_happened = str(executive_story.get('what_happened') or '')
    if not what_happened:
        # synthesise from factors
        factor_keys = list(all_factors.keys())
        if any(f in factor_keys for f in ('phishing_lure','macro_lure','phishing_subject')):
            what_happened = 'An attacker sent a deceptive email to staff. '
        if any(f in factor_keys for f in ('powershell_execution','malicious_process','lolbin')):
            what_happened += 'When the email was opened, malicious software began running on the device. '
        if any(f in factor_keys for f in ('c2_beacon','c2_communication','external_connection')):
            what_happened += 'The software then contacted the attacker\'s server over the internet, giving them remote access. '
        if any(f in factor_keys for f in ('lateral_movement','rdp_lateral_movement','smb_lateral_movement')):
            what_happened += 'The attacker used that access to move to other systems inside the organisation. '
        if any(f in factor_keys for f in ('credential_access','credential_harvest')):
            what_happened += 'Passwords or login credentials were likely accessed or stolen. '
        if not what_happened:
            what_happened = 'Suspicious activity was detected across multiple security data sources. The system has correlated these events into a confirmed security incident requiring your attention.'
    parts.append(f'<p style="color:#e6eef8;font-size:15px;line-height:1.7;margin:0">{escape(what_happened.strip())}</p>')
    parts.append('</div>')

    # WHO WAS AFFECTED
    hosts_seen = list({r.get('host') for r in rows if r.get('host')})[:8]
    accounts_seen = list({r.get('user') or r.get('username') or r.get('account') for r in rows
                         if r.get('user') or r.get('username') or r.get('account')})[:5]
    if hosts_seen or accounts_seen:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:8px">WHO WAS AFFECTED</strong>')
        parts.append('<ul style="margin:0 0 0 18px;color:#e6eef8;font-size:14px;line-height:1.8">')
        for h in hosts_seen[:5]:
            parts.append(f'<li>Device: <strong>{escape(str(h))}</strong></li>')
        for a in accounts_seen[:4]:
            if a and str(a) not in ('None',):
                parts.append(f'<li>Account: <strong>{escape(str(a))}</strong></li>')
        if source_count:
            parts.append(f'<li>Activity seen across <strong>{source_count}</strong> different security data sources</li>')
        parts.append('</ul></div>')

    # 3 DECISIONS THAT NEED YOU
    parts.append('<div class="warn" style="background:#0a1018;border:2px solid #3b82f6">')
    parts.append(f'<strong style="color:{accent};font-size:15px;display:block;margin-bottom:12px">3 DECISIONS THAT NEED YOU</strong>')
    decisions_data = [
        ('1. CONTAIN', 'Authorise isolating the affected devices from the network now. Your SOC team is waiting for approval.',
         'Authorise Containment', '#ef4444'),
        ('2. NOTIFY', 'Decide whether to notify regulators (GDPR 72h clock). Your legal team needs your call.',
         'Brief Legal Now', '#f59e0b'),
        ('3. BOARD', 'Approve a board-level communications statement. Prepare for media/investor inquiries.',
         'Approve Comms', '#3b82f6'),
    ]
    for title_d, desc, btn_label, btn_clr in decisions_data:
        parts.append(f'<div style="display:flex;align-items:flex-start;gap:14px;padding:10px 0;border-bottom:1px solid #1e2535">'
                     f'<div style="flex:1"><strong style="color:#e6eef8">{escape(title_d)}</strong>'
                     f'<p style="margin:4px 0 0;color:#9bb;font-size:13px">{escape(desc)}</p></div>'
                     f'<button style="background:{btn_clr};color:#fff;border:none;padding:6px 14px;'
                     f'border-radius:4px;cursor:pointer;font-size:12px;white-space:nowrap;flex-shrink:0">'
                     f'{escape(btn_label)}</button></div>')
    parts.append('</div>')

    # WHAT JANUSEC DID
    total_events = int(assessment_view.get('total_rows') or meta.get('total_rows') or len(rows))
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:6px">WHAT JANUSEC DID</strong>')
    parts.append(f'<p style="color:#9bb;font-size:13px;margin:0">'
                 f'Automatically correlated <strong style="color:#e6eef8">{total_events:,} events</strong> across '
                 f'<strong style="color:#e6eef8">{source_count or "multiple"} data sources</strong> into '
                 f'<strong style="color:#e6eef8">{cluster_count} incident clusters</strong>. '
                 f'A manual analyst would take 2–3 days for equivalent correlation.</p>')
    parts.append('</div>')

    # Collapsible: business impact detail, what was missed
    coll_parts = []
    sequence = executive_story.get('temporal_sequence') or []
    if sequence:
        coll_parts.append('<strong style="color:#9bb;display:block;margin-bottom:8px">BUSINESS IMPACT DETAIL — TIMELINE</strong>')
        coll_parts.append('<table><thead><tr><th>When</th><th>What Happened</th><th>Why It Matters</th></tr></thead><tbody>')
        for item in sequence:
            when = f'{item.get("day") or ""} {item.get("date") or ""}'.strip()
            coll_parts.append(f'<tr><td style="color:#93c5fd;font-weight:600;white-space:nowrap">{escape(when)}</td>'
                              f'<td><strong>{escape(str(item.get("title") or ""))}</strong><br>'
                              f'<span style="color:#9bb;font-size:11px">{escape(str(item.get("what") or ""))}</span></td>'
                              f'<td style="color:#9bb">{escape(str(item.get("significance") or ""))}</td></tr>')
        coll_parts.append('</tbody></table>')
        missed = [str(item.get('why_missed') or '') for item in sequence if item.get('why_missed')]
        if missed:
            coll_parts.append('<strong style="color:#fbbf24;display:block;margin-top:14px;margin-bottom:6px">WHAT WAS MISSED AND WHY</strong>')
            coll_parts.append('<ul style="margin:0 0 0 18px;color:#fde68a">')
            for m in missed[:6]:
                coll_parts.append(f'<li style="margin:4px 0">{escape(m)}</li>')
            coll_parts.append('</ul>')

    if coll_parts:
        parts.append(_collapsible('Business Impact Detail & What Was Missed', '\n'.join(coll_parts), accent))

    body = '\n'.join(parts)
    return _wrap_page(f'Executive Briefing — {escape(verdict)}', body, accent)


def _build_threat_hunter_page(payload: dict, meta: dict, assessment_view: dict,
                               session: str, company: str, generated_at: str) -> str:
    accent = '#8b5cf6'
    rows = payload.get('rows') or []
    all_factors = _collect_all_factors(rows)
    mitre_hits = _collect_mitre(rows)
    threat_models = payload.get('threat_models') or {}
    diamond_model = threat_models.get('diamond_model') or {}
    maestro_stages = threat_models.get('maestro_stages') or []

    verdict = str(assessment_view.get('verdict') or meta.get('verdict') or 'UNDER INVESTIGATION').upper()
    conf_raw = assessment_view.get('confidence') or meta.get('confidence') or ''
    try:
        confidence = str(int(float(conf_raw) * 100)) if conf_raw and float(conf_raw) <= 1 else str(int(float(conf_raw))) if conf_raw else ''
    except Exception:
        confidence = str(conf_raw)

    source_count = int(assessment_view.get('source_count') or 0)

    # Collect IPs already checked
    ips_seen = {r.get('dst_ip') for r in rows if r.get('dst_ip')} | {r.get('src_ip') for r in rows if r.get('src_ip')}
    ips_seen.discard(None); ips_seen.discard('None'); ips_seen.discard('')

    # ── Ground the templated hunt queries in THIS incident's real IOCs ──────────
    # A query with the actual attacker IP/domain is runnable; one with `known_bad_ips`
    # is a demo. Substitute the observed EXTERNAL IPs + domains into the templates.
    import ipaddress as _ipaddr

    def _is_external(_ip: str) -> bool:
        try:
            return not _ipaddr.ip_address(str(_ip)).is_private
        except Exception:
            return False
    _ext_ips = [str(i) for i in sorted(ips_seen) if _is_external(i)][:6]
    _domains = sorted({str(r.get('dst_domain') or r.get('domain')) for r in rows
                       if (r.get('dst_domain') or r.get('domain'))} - {'None', ''})[:6]
    _ip_sql = ("'" + "', '".join(_ext_ips) + "'") if _ext_ips else 'known_bad_ips'
    _dom_sql = ("'" + "', '".join(_domains) + "'") if _domains else 'suspicious_domains'

    def _ground_query(_q: str) -> str:
        return (_q or '').replace('known_bad_ips', _ip_sql).replace('suspicious_domains', _dom_sql)

    parts = [_page_header('THREAT HUNTER REPORT', verdict, confidence, company, session, generated_at, accent)]

    parts.append(_stat_bar([
        (len(mitre_hits), 'MITRE Techniques', '#a78bfa'),
        (len(ips_seen), 'IPs Checked', '#60a5fa'),
        (source_count, 'Sources', '#34d399'),
        (len(maestro_stages), 'Kill Chain Stages', '#f87171'),
    ]))

    # MISSION box
    parts.append('<div class="warn" style="background:#0d0a1a;border:2px solid #8b5cf6">')
    parts.append(f'<strong style="color:{accent};font-size:14px">MISSION: Find adjacent activity not yet proven.</strong>')
    parts.append(f'<div style="color:#9bb;margin-top:6px">'
                 f'Already checked <strong style="color:#e6eef8">{len(ips_seen)}</strong> IPs across '
                 f'<strong style="color:#e6eef8">{source_count or "multiple"}</strong> sources. '
                 f'Hunt scope: expand laterally from known pivot points and identify pre-compromise activity not captured in assessed window.</div>')
    parts.append('</div>')

    # HUNT HYPOTHESES
    hypotheses = [
        ('H1 — Persistent Foothold',
         'Adversary may have installed persistence (scheduled task / service / WMI subscription) before the detected window.',
         'SELECT * FROM process_creation WHERE parent_image LIKE "%svchost%" AND command_line LIKE "%cmd%"',
         'Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\\Microsoft\\*"} | Select TaskName,Actions'),
        ('H2 — Credential Reuse',
         'Stolen credentials may have been used from external IP to authenticate to VPN / OWA / cloud services.',
         'SELECT user, src_ip, count(*) FROM auth_logs WHERE result="success" AND src_ip NOT IN (known_corporate_ips) GROUP BY user, src_ip',
         'Search-UnifiedAuditLog -Operations UserLoggedIn -SessionCommand ReturnLargeSet | Where {$_.ClientIP -notmatch "10\\.|192\\.168\\."}'),
        ('H3 — C2 Dwell Time',
         'If first C2 beacon predates assessed window by >72h, adversary likely has persistent implant — check scheduled tasks and service installs.',
         'SELECT src_ip, dst_ip, min(ts) as first_seen FROM netflow WHERE dst_ip IN (known_bad_ips) GROUP BY src_ip, dst_ip',
         'Get-WinEvent -LogName System | Where {$_.Id -eq 7045} | Select TimeCreated,Message | Format-List'),
        ('H4 — Lateral Movement Pre-Image',
         'Check for RDP or SMB connections to high-value targets (DCs, file servers) that precede the assessed event window.',
         'SELECT src_host, dst_host, port, min(ts) FROM netflow WHERE port IN (3389,445) AND dst_host IN (dc_list) GROUP BY src_host, dst_host, port',
         'Get-WinEvent -ComputerName (Get-ADDomainController -Filter *).Name -FilterHashtable @{LogName="Security";Id=4624;} | Where {$_.Properties[8].Value -eq 10}'),
    ]
    # Add factor-specific hypotheses
    if 'dns_beacon' in all_factors:
        hypotheses.insert(0, ('H0 — DNS Beacon Channel',
                               'DNS-based C2 detected — hunt for long TTL, high-frequency, or algorithmically generated domain queries.',
                               'SELECT query_name, count(*) as freq FROM dns_logs GROUP BY query_name HAVING freq > 100 ORDER BY freq DESC',
                               'Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" | Where {$_.Message -match "\\.(tk|ga|cf|gq)$"}'))

    for i, (title_h, desc_h, spl, kql) in enumerate(hypotheses[:5]):
        parts.append(f'<details style="border:1px solid {accent}44;border-radius:6px;margin-top:10px">')
        parts.append(f'<summary style="padding:10px 14px;color:{accent};font-weight:700">{escape(title_h)}</summary>')
        parts.append(f'<div style="padding:12px">')
        parts.append(f'<p style="color:#9bb;margin:0 0 10px">{escape(desc_h)}</p>')
        parts.append(f'<div style="margin-bottom:6px"><span style="color:#60a5fa;font-size:11px;font-weight:600">SPL (Splunk)</span>'
                     f'<pre style="margin-top:4px;font-size:11px">{escape(_ground_query(spl))}</pre></div>')
        parts.append(f'<div><span style="color:#34d399;font-size:11px;font-weight:600">KQL (Sentinel / Defender)</span>'
                     f'<pre style="margin-top:4px;font-size:11px">{escape(_ground_query(kql))}</pre></div>')
        parts.append('</div></details>')

    # PIVOT GRAPH — text-based attacker infrastructure tree
    infra = diamond_model.get('infrastructure') or []
    if infra or ips_seen:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">PIVOT GRAPH — ATTACKER INFRASTRUCTURE</strong>')
        parts.append('<pre style="font-size:12px;line-height:1.7">')
        parts.append('ATTACKER\n')
        infra_shown = set()
        for inf in infra[:6]:
            ip = str(inf.get('ip', ''))
            role = inf.get('role', 'unknown')
            if ip:
                infra_shown.add(ip)
                parts.append(f'  └─ {escape(ip)} [{escape(role)}]\n')
        for ip in list(ips_seen)[:8]:
            if str(ip) not in infra_shown:
                parts.append(f'  └─ {escape(str(ip))} [observed]\n')
        parts.append('</pre></div>')

    # MITRE COVERAGE MAP — technique chips in grid
    if mitre_hits:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">MITRE ATT&CK COVERAGE MAP</strong>')
        parts.append('<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:6px">')
        for tid, cnt in mitre_hits[:20]:
            name = _MITRE_NAMES.get(tid, '')
            parts.append(f'<div style="background:#110d20;border:1px solid {accent}66;border-radius:6px;padding:6px 10px">'
                         f'<div style="color:{accent};font-family:monospace;font-size:11px;font-weight:700">{escape(tid)}</div>'
                         f'<div style="color:#e6eef8;font-size:11px">{escape(name)}</div>'
                         f'<div style="color:#9bb;font-size:10px">{cnt} events</div></div>')
        parts.append('</div></div>')

    # MAESTRO Kill Chain stages
    if maestro_stages:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">MAESTRO KILL CHAIN COVERAGE</strong>')
        parts.append('<table><thead><tr><th>Stage</th><th style="width:90px">Detected?</th><th>Evidence Factors</th><th>Assessment</th></tr></thead><tbody>')
        for ms in maestro_stages:
            det_clr = '#4ade80' if ms.get('detected') else '#555'
            det_txt = 'YES' if ms.get('detected') else 'NOT SEEN'
            ev_txt = ', '.join(ms.get('evidence_factors', [])[:3]) or '—'
            parts.append(f'<tr><td style="color:{accent};font-weight:600">{escape(ms.get("stage",""))}</td>'
                         f'<td style="color:{det_clr};font-weight:700">{det_txt}</td>'
                         f'<td style="font-family:monospace;font-size:10px">{escape(ev_txt)}</td>'
                         f'<td style="color:#9bb">{escape(ms.get("description",""))}</td></tr>')
        parts.append('</tbody></table></div>')

    # Collapsible: full infra + Sigma rules
    coll_parts = []
    if infra:
        coll_parts.append('<strong style="color:#9bb;display:block;margin-bottom:6px">FULL ATTACKER INFRASTRUCTURE</strong>')
        coll_parts.append('<table><thead><tr><th>IP</th><th>Port</th><th>Role</th><th>Protocol</th></tr></thead><tbody>')
        for inf in infra:
            coll_parts.append(f'<tr><td style="font-family:monospace">{escape(str(inf.get("ip","")))}</td>'
                              f'<td style="font-family:monospace">{escape(str(inf.get("port","")))}</td>'
                              f'<td style="color:#a78bfa">{escape(inf.get("role",""))}</td>'
                              f'<td style="color:#9bb">{escape(inf.get("protocol",""))}</td></tr>')
        coll_parts.append('</tbody></table>')

    sigma_rules = [
        ('Suspicious Encoded PowerShell',
         'title: Encoded PowerShell Execution\nstatus: stable\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: "-enc"\n  condition: selection'),
        ('Temp Path Execution',
         'title: Process Execution from Temp Path\nstatus: stable\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|contains:\n      - "\\Temp\\"\n      - "\\AppData\\"\n  condition: selection'),
        ('C2 Beacon Interval',
         'title: Periodic C2 Beacon Pattern\nstatus: experimental\nlogsource:\n  category: network_connection\ndetection:\n  selection:\n    Initiated: "true"\n    DestinationPort:\n      - 443\n      - 8080\n      - 8443\n  condition: selection'),
    ]
    if sigma_rules:
        coll_parts.append('<strong style="color:#9bb;display:block;margin-top:14px;margin-bottom:6px">SIGMA RULES</strong>')
        for rule_name, rule_body in sigma_rules:
            coll_parts.append(f'<div style="margin-bottom:10px"><strong style="color:#a78bfa">{escape(rule_name)}</strong>'
                              f'<pre style="font-size:10px;margin-top:4px">{escape(rule_body)}</pre></div>')

    if coll_parts:
        parts.append(_collapsible('Full Attacker Infrastructure & Sigma Rules', '\n'.join(coll_parts), accent))

    body = '\n'.join(parts)
    return _wrap_page(f'Threat Hunter Report — {escape(verdict)}', body, accent)


def _build_forensics_page(payload: dict, meta: dict, assessment_view: dict,
                           session: str, company: str, generated_at: str) -> str:
    accent = '#f59e0b'
    rows = payload.get('rows') or []
    all_factors = _collect_all_factors(rows)
    threat_models = payload.get('threat_models') or {}
    stride_summary = threat_models.get('stride_summary') or {}

    verdict = str(assessment_view.get('verdict') or meta.get('verdict') or 'UNDER INVESTIGATION').upper()
    conf_raw = assessment_view.get('confidence') or meta.get('confidence') or ''
    try:
        confidence = str(int(float(conf_raw) * 100)) if conf_raw and float(conf_raw) <= 1 else str(int(float(conf_raw))) if conf_raw else ''
    except Exception:
        confidence = str(conf_raw)

    hosts_seen, ips_seen, hashes_seen, processes_seen = set(), set(), set(), set()
    sha256_anomalies = []
    for r in rows:
        if r.get('host'): hosts_seen.add(r['host'])
        if r.get('dst_ip'): ips_seen.add(r['dst_ip'])
        if r.get('src_ip'): ips_seen.add(r['src_ip'])
        _sha = r.get('sha256') or ''
        if _sha: hashes_seen.add(_sha)
        if _sha and (len(_sha) == 32 or _sha == 'd41d8cd98f00b204e9800998ecf8427e'):
            _proc = r.get('process') or r.get('process_name') or r.get('host') or 'unknown'
            sha256_anomalies.append((_proc, _sha))
        if r.get('process') or r.get('process_name'):
            processes_seen.add(r.get('process') or r.get('process_name'))

    parts = [_page_header('FORENSICS REPORT', verdict, confidence, company, session, generated_at, accent)]

    parts.append(_stat_bar([
        (len(hosts_seen), 'Hosts to Image', '#f59e0b'),
        (len(ips_seen), 'Network IOCs', '#60a5fa'),
        (len(hashes_seen), 'File Hashes', '#a78bfa'),
        (len(processes_seen), 'Processes', '#34d399'),
    ]))

    # BIG WARNING
    parts.append('<div class="warn" style="background:#1a0e00;border:3px solid #f59e0b;text-align:center">')
    parts.append(f'<div style="font-size:20px;font-weight:900;color:#f59e0b;letter-spacing:.05em">'
                 f'PRESERVE BEFORE CONTAINMENT</div>')
    parts.append(f'<div style="color:#fde68a;margin-top:8px;font-size:14px">'
                 f'Volatile evidence (RAM, network connections, running processes) is destroyed by host isolation or reboot. '
                 f'Complete acquisition steps 1-2 before any containment action.</div>')
    parts.append('</div>')

    # SHA256 anomaly warning
    if sha256_anomalies:
        parts.append('<div class="warn" style="background:#0a0e1a;border:1px solid #ef4444">')
        parts.append(f'<strong style="color:#ef4444">SHA256 INTEGRITY ANOMALY DETECTED:</strong><br>')
        for _ap, _av in sha256_anomalies[:5]:
            _tag = 'MD5 collision (wrong hash algorithm)' if len(_av) == 32 else 'empty-file sentinel'
            parts.append(f'<code style="font-size:11px">{escape(str(_ap))}</code>: '
                         f'hash <code>{escape(_av[:20])}…</code> — '
                         f'<strong style="color:#ef4444">ANOMALOUS ({escape(_tag)})</strong>. '
                         f'Collect file sample and recompute SHA256 from disk.<br>')
        parts.append('</div>')

    # EVIDENCE ACQUISITION ORDER
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">EVIDENCE ACQUISITION ORDER</strong>')
    parts.append('<table><thead><tr><th style="width:40px">#</th><th>Host</th><th style="width:90px">Priority</th>'
                 '<th>Artifact</th><th style="width:80px">ETA</th><th>Tool / Command</th></tr></thead><tbody>')

    acq_rows = []
    for i, h in enumerate(list(hosts_seen)[:5]):
        prio = 'CRITICAL' if i == 0 else ('HIGH' if i < 3 else 'MEDIUM')
        acq_rows.append((i+1, h, prio, 'Volatile: RAM + netstat + process list', '15 min', 'WinPMEM / Magnet RAM Capture'))
    for i, h in enumerate(list(hosts_seen)[:5]):
        acq_rows.append((len(hosts_seen)+i+1, h, 'HIGH', 'Disk image (write-blocked)', '45-90 min', 'FTK Imager / dc3dd'))
    if not acq_rows:
        acq_rows = [
            (1, 'All flagged hosts', 'CRITICAL', 'RAM image', '15 min', 'WinPMEM'),
            (2, 'All flagged hosts', 'HIGH', 'Disk image', '60 min', 'FTK Imager'),
            (3, 'All flagged hosts', 'HIGH', 'MFT + Prefetch + Amcache', '20 min', 'Kape / Velociraptor'),
            (4, 'Perimeter firewall', 'HIGH', 'PCAP for beacon window', '30 min', 'tcpdump / Wireshark'),
            (5, 'All flagged hosts', 'MEDIUM', 'Windows Event Logs (Security, System, PowerShell)', '10 min', 'wevtutil / evtx-dump'),
        ]

    prio_clr_map = {'CRITICAL': '#ef4444', 'HIGH': '#f59e0b', 'MEDIUM': '#fbbf24'}
    for seq, host, prio, artifact, eta, tool in acq_rows[:10]:
        clr = prio_clr_map.get(prio, '#9bb')
        parts.append(f'<tr><td style="font-weight:700;color:{accent}">{seq}</td>'
                     f'<td style="font-family:monospace;font-size:11px">{escape(str(host)[:40])}</td>'
                     f'<td style="color:{clr};font-weight:700">{escape(prio)}</td>'
                     f'<td>{escape(artifact)}</td>'
                     f'<td style="color:#9bb">{escape(eta)}</td>'
                     f'<td style="font-family:monospace;font-size:11px">{escape(tool)}</td></tr>')
    parts.append('</tbody></table></div>')

    # CHAIN OF CUSTODY TRACKER
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">CHAIN OF CUSTODY TRACKER</strong>')
    parts.append('<table><thead><tr><th>Item</th><th style="width:80px">Acquired</th><th style="width:100px">Hash Verified</th>'
                 '<th>Custodian</th><th>Location</th></tr></thead><tbody>')
    cos_items = [f'RAM image — {h}' for h in list(hosts_seen)[:3]] + \
                [f'Disk image — {h}' for h in list(hosts_seen)[:3]] + \
                ['PCAP — perimeter firewall', 'Windows Event Logs', 'Prefetch / Amcache artifacts']
    if not hosts_seen:
        cos_items = ['RAM image', 'Disk image', 'PCAP', 'Windows Event Logs', 'Prefetch / Amcache', 'MFT dump']
    for item in cos_items[:8]:
        parts.append(f'<tr><td style="font-size:12px">{escape(item)}</td>'
                     f'<td style="text-align:center"><input type="checkbox" style="accent-color:{accent}"></td>'
                     f'<td style="text-align:center"><input type="checkbox" style="accent-color:{accent}"></td>'
                     f'<td><input type="text" placeholder="analyst name" style="background:#0a1018;color:#e6eef8;border:1px solid #243144;border-radius:3px;padding:2px 6px;width:100%;font-size:11px"></td>'
                     f'<td><input type="text" placeholder="evidence store path" style="background:#0a1018;color:#e6eef8;border:1px solid #243144;border-radius:3px;padding:2px 6px;width:100%;font-size:11px"></td></tr>')
    parts.append('</tbody></table></div>')

    # PROOF OF EXECUTION — key timestamped events
    clusters = assessment_view.get('cluster_rollups') or payload.get('clusters') or []
    executive_story = assessment_view.get('executive_story') or {}
    sequence = executive_story.get('temporal_sequence') or []
    if sequence or clusters:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">PROOF OF EXECUTION — KEY EVENTS</strong>')
        parts.append('<table><thead><tr><th>Timestamp</th><th>Event</th><th>Evidence Basis</th></tr></thead><tbody>')
        for item in sequence[:10]:
            when = f'{item.get("day") or ""} {item.get("date") or ""}'.strip()
            parts.append(f'<tr><td style="font-family:monospace;font-size:11px;color:#fbbf24;white-space:nowrap">{escape(when)}</td>'
                         f'<td><strong>{escape(str(item.get("title") or ""))}</strong><br>'
                         f'<span style="color:#9bb;font-size:11px">{escape(str(item.get("what") or ""))}</span></td>'
                         f'<td style="color:#9bb;font-size:11px">{escape(str(item.get("significance") or ""))}</td></tr>')
        for c in clusters[:5]:
            ctitle = c.get('title') or c.get('incident_name') or c.get('cluster_id') or 'cluster'
            cfactors = ', '.join(str(f) for f in (c.get('key_factors') or c.get('factor_tags') or [])[:4])
            parts.append(f'<tr><td style="font-family:monospace;font-size:11px;color:#fbbf24">Cluster</td>'
                         f'<td><strong>{escape(str(ctitle)[:80])}</strong></td>'
                         f'<td style="color:#9bb;font-size:11px">{escape(cfactors)}</td></tr>')
        parts.append('</tbody></table></div>')

    # ANTI-FORENSICS CHECKS
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">ANTI-FORENSICS CHECKS</strong>')
    af_checks = [
        ('Timestomping', 'Verify MFT $STANDARD_INFORMATION vs $FILE_NAME timestamps — discrepancy indicates tampering'),
        ('Log clearing', 'Check Windows Security Event 1102 / System Event 104 for log-clearing events'),
        ('VSS deletion', 'Check Event 524 / vssadmin list shadows — attacker may have deleted shadow copies'),
        ('Prefetch deletion', 'Verify prefetch files exist for all flagged executables — absence is suspicious'),
        ('Event log gaps', 'Look for gaps > 1h in Security event log sequence numbers — indicates log manipulation'),
        ('Alternate data streams', 'Run "dir /r" on dropped file directories — ADS may hide secondary payload'),
        ('Timestamped processes outside business hours', 'Cross-reference process timestamps with shift schedules'),
    ]
    # add STRIDE-based checks
    _t_stride = stride_summary.get('T', {})
    if _t_stride.get('count', 0) > 0:
        af_checks.insert(0, ('STRIDE-T Tampering Detected', f'{_t_stride["count"]} tampering events in this dataset — prioritise file-integrity checks'))
    parts.append('<div style="font-size:13px">')
    for check_name, check_desc in af_checks[:8]:
        parts.append(f'<div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid #1e2535">'
                     f'<input type="checkbox" style="margin-top:3px;accent-color:{accent}">'
                     f'<div><span style="color:#e6eef8;font-weight:600">{escape(check_name)}</span>'
                     f'<span style="color:#9bb;font-size:11px;display:block">{escape(check_desc)}</span></div></div>')
    parts.append('</div></div>')

    # Collapsible: full forensic timeline, evidence manifest
    coll_parts = []
    all_rows_ts = sorted(
        [r for r in rows if r.get('timestamp') or r.get('ts') or r.get('time')],
        key=lambda r: str(r.get('timestamp') or r.get('ts') or r.get('time') or ''),
    )
    if all_rows_ts:
        coll_parts.append('<strong style="color:#9bb;display:block;margin-bottom:6px">FULL FORENSIC TIMELINE</strong>')
        coll_parts.append('<table><thead><tr><th>Timestamp</th><th>Host</th><th>Event</th><th>Risk</th></tr></thead><tbody>')
        for r in all_rows_ts[:50]:
            ts = str(r.get('timestamp') or r.get('ts') or r.get('time') or '')
            host = str(r.get('host') or '')
            identifier = (r.get('process') or r.get('process_name') or r.get('src_ip') or r.get('subject') or 'event')
            risk = float(r.get('risk_score') or r.get('confidence') or 0)
            risk_clr = '#ef4444' if risk > 0.7 else ('#f59e0b' if risk > 0.4 else '#9bb')
            coll_parts.append(f'<tr><td style="font-family:monospace;font-size:10px;white-space:nowrap">{escape(ts[:25])}</td>'
                              f'<td style="font-family:monospace;font-size:10px">{escape(host[:20])}</td>'
                              f'<td style="font-size:11px">{escape(str(identifier)[:60])}</td>'
                              f'<td style="color:{risk_clr};font-family:monospace;font-size:10px">{risk:.3f}</td></tr>')
        coll_parts.append('</tbody></table>')

    ioc_manifest = []
    for h in list(hosts_seen)[:5]:
        ioc_manifest.append(f'Host: {h} — RAM + Disk image required')
    for ip in list(ips_seen)[:5]:
        if ip and ip not in ('None',):
            ioc_manifest.append(f'IP: {ip} — PCAP + firewall log required')
    for sha in list(hashes_seen)[:5]:
        if sha and sha not in ('None',):
            ioc_manifest.append(f'Hash: {sha[:32]}… — VT lookup + disk sample required')
    if ioc_manifest:
        coll_parts.append('<strong style="color:#9bb;display:block;margin-top:14px;margin-bottom:6px">EVIDENCE MANIFEST</strong>')
        coll_parts.append('<ul style="margin:0 0 0 18px;color:#9bb;font-size:12px">')
        for item in ioc_manifest:
            coll_parts.append(f'<li style="margin:3px 0">{escape(item)}</li>')
        coll_parts.append('</ul>')

    if coll_parts:
        parts.append(_collapsible('Full Forensic Timeline & Evidence Manifest', '\n'.join(coll_parts), accent))

    body = '\n'.join(parts)
    return _wrap_page(f'Forensics Report — {escape(verdict)}', body, accent)


def _build_compliance_page(payload: dict, meta: dict, assessment_view: dict,
                            session: str, company: str, generated_at: str) -> str:
    import datetime as _dt
    accent = '#9b59b6'
    rows = payload.get('rows') or []
    all_factors = _collect_all_factors(rows)
    mitre_hits = _collect_mitre(rows)
    threat_models = payload.get('threat_models') or {}
    stride_summary = threat_models.get('stride_summary') or {}
    pasta_risks = (threat_models.get('pasta_risk_matrix') or [])

    verdict = str(assessment_view.get('verdict') or meta.get('verdict') or 'UNDER INVESTIGATION').upper()
    conf_raw = assessment_view.get('confidence') or meta.get('confidence') or ''
    try:
        confidence = str(int(float(conf_raw) * 100)) if conf_raw and float(conf_raw) <= 1 else str(int(float(conf_raw))) if conf_raw else ''
    except Exception:
        confidence = str(conf_raw)

    discovery_ts = _dt.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    gdpr_triggered = any(f in all_factors for f in (
        'credential_access', 'credential_harvest', 'phishing_lure', 'phishing_subject',
        'macro_lure', 'c2_beacon', 'c2_communication', 'c2_data_staging',
        'malicious_process', 'external_connection',
    ))
    cluster_count = int(assessment_view.get('cluster_count') or 0)

    parts = [_page_header('COMPLIANCE & REGULATORY REPORT', verdict, confidence, company, session, generated_at, accent)]

    parts.append(_stat_bar([
        (len(mitre_hits), 'MITRE Techniques', '#a78bfa'),
        (cluster_count, 'Clusters', '#60a5fa'),
        (len([f for f in all_factors if f in ('credential_access','c2_beacon','lateral_movement','phishing_lure')]),
         'Reportable Factors', '#f87171'),
    ]))

    # FRAMEWORK SUMMARY
    fw_gap_map = {}
    for tid, cnt in mitre_hits[:15]:
        fw = _MITRE_TO_FRAMEWORK.get(tid, {})
        for fw_name, ctrl in fw.items():
            if ctrl:
                if fw_name not in fw_gap_map:
                    fw_gap_map[fw_name] = {'gaps': 0, 'severity': 'medium', 'controls': []}
                fw_gap_map[fw_name]['gaps'] += 1
                fw_gap_map[fw_name]['controls'].append(f'{tid}→{ctrl}')
                if cnt > 5:
                    fw_gap_map[fw_name]['severity'] = 'high'

    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">FRAMEWORK SUMMARY</strong>')
    parts.append('<table><thead><tr><th>Framework</th><th style="width:80px"># Gaps</th>'
                 '<th style="width:80px">Severity</th><th>Action Required</th></tr></thead><tbody>')
    if fw_gap_map:
        sev_map_fw = {'high': ('#ef4444', 'HIGH'), 'medium': ('#f59e0b', 'MEDIUM')}
        for fw_name, info in list(fw_gap_map.items())[:8]:
            sev_clr, sev_lbl = sev_map_fw.get(info['severity'], ('#9bb', 'LOW'))
            action = f'Review {len(info["controls"])} control(s): {", ".join(info["controls"][:3])}'
            parts.append(f'<tr><td style="font-weight:600">{escape(fw_name)}</td>'
                         f'<td style="text-align:center;color:#fbbf24">{info["gaps"]}</td>'
                         f'<td style="color:{sev_clr};font-weight:700">{sev_lbl}</td>'
                         f'<td style="font-size:11px;color:#9bb">{escape(action)}</td></tr>')
    else:
        parts.append('<tr><td colspan="4" style="color:#9bb">No MITRE-to-framework mapping found — review manually</td></tr>')
    parts.append('</tbody></table></div>')

    # PER-CONTROL ACTION TABLE
    top_factors = assessment_view.get('top_factors') or []
    ctrl_action_map = {
        'c2_beacon': ('CC7.2 / A.12.4.1', 'Detection', 'Deploy network-level C2 detection; engage MDR provider'),
        'credential_access': ('A.9.2.4 / IA-2', 'Access Control', 'Enforce MFA org-wide; rotate affected credentials; commission PAM review'),
        'lateral_movement': ('A.13.1.3 / SC-7', 'Network Segmentation', 'Commission network segmentation audit; implement micro-segmentation'),
        'powershell_execution': ('A.12.6.1 / SI-3', 'Endpoint Hardening', 'Enforce application control; enable PS script-block logging'),
        'phishing_lure': ('A.6.3 / AT-2', 'User Awareness', 'Commission phishing simulation and training programme'),
        'macro_lure': ('A.8.23 / SC-18', 'Email Security', 'Disable macros org-wide via policy; deploy sandboxed email gateway'),
        'rdp_lateral_movement': ('A.9.4.2 / AC-17', 'Remote Access', 'Restrict RDP to jump-server; enforce session recording'),
        'lolbin': ('CIS-8.9 / CM-7', 'Application Control', 'Deploy application allowlisting; block unsigned LOLBAS variants'),
        'c2_data_staging': ('A.8.12 / SI-12', 'DLP', 'Deploy egress DLP with exfil detection; alert on large outbound transfers'),
        'smb_lateral_movement': ('A.13.1.2 / SC-7', 'Network', 'Block SMB (445) laterally at switch ACL; audit admin shares'),
    }
    if top_factors:
        parts.append('<div class="section">')
        parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">PER-CONTROL ACTION TABLE</strong>')
        parts.append('<table><thead><tr><th>Factor</th><th style="width:130px">Control ID</th>'
                     '<th style="width:100px">Gap Type</th><th>Action Required</th><th style="width:100px">Remediation Owner</th></tr></thead><tbody>')
        shown = 0
        for item in top_factors[:12]:
            fname = str(item.get('factor') or '')
            if fname in ctrl_action_map:
                ctrl_id, gap_type, action = ctrl_action_map[fname]
                owner = 'CISO' if 'Access' in gap_type or 'DLP' in gap_type else ('IT Ops' if 'Network' in gap_type or 'Endpoint' in gap_type else 'Security Team')
                parts.append(f'<tr><td style="font-family:monospace;font-size:11px;color:#c4b5fd">{escape(fname)}</td>'
                             f'<td style="font-family:monospace;font-size:10px">{escape(ctrl_id)}</td>'
                             f'<td style="color:#f87171">{escape(gap_type)}</td>'
                             f'<td style="font-size:12px">{escape(action)}</td>'
                             f'<td style="color:#9bb">{escape(owner)}</td></tr>')
                shown += 1
        if shown == 0:
            parts.append('<tr><td colspan="5" style="color:#9bb">No specific control failures mapped — review with GRC lead</td></tr>')
        parts.append('</tbody></table></div>')

    # NOTIFICATION TIMELINE
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">NOTIFICATION TIMELINE</strong>')
    parts.append(f'<div style="font-size:11px;color:#9bb;margin-bottom:8px">T+0 = discovery time: <strong style="color:#e6eef8">{escape(discovery_ts)}</strong></div>')
    timeline = [
        ('T+0h', 'Incident detected / discovery', '#e6eef8', 'Log incident reference number in GRC tool'),
        ('T+2h', 'Internal escalation complete', '#fbbf24', 'CISO briefed; legal counsel engaged; data-owner attestation requested'),
        ('T+24h', 'Early regulatory warning (NIS2)', '#f59e0b' if gdpr_triggered else '#555',
         'Submit early warning to CSIRT if NIS2 applies' if gdpr_triggered else 'NIS2 early warning — assess applicability'),
        ('T+72h', 'GDPR Art.33 DPA notification deadline', '#ef4444' if gdpr_triggered else '#555',
         'Notify DPA if personal data affected — document decision and rationale' if gdpr_triggered else 'Likely not triggered — document justification for non-notification'),
        ('T+4 days', 'SEC Form 8-K deadline (if listed)', '#9bb', 'Material cybersecurity incident disclosure if publicly listed company'),
        ('T+1 week', 'Internal post-incident review', '#4ade80', 'Document control failures; update risk register; assign remediation owners'),
    ]
    parts.append('<table><thead><tr><th style="width:100px">Milestone</th><th>Event</th><th style="width:80px">Status</th><th>Required Action</th></tr></thead><tbody>')
    for milestone, event, clr, action in timeline:
        parts.append(f'<tr><td style="font-family:monospace;font-weight:700;color:{clr}">{escape(milestone)}</td>'
                     f'<td style="font-weight:600">{escape(event)}</td>'
                     f'<td><input type="checkbox" style="accent-color:{accent}"> Done</td>'
                     f'<td style="color:#9bb;font-size:12px">{escape(action)}</td></tr>')
    parts.append('</tbody></table></div>')

    # AUDIT EVIDENCE PACKAGE
    parts.append('<div class="section">')
    parts.append(f'<strong style="color:{accent};display:block;margin-bottom:10px">AUDIT EVIDENCE PACKAGE</strong>')
    evidence_items = [
        ('JanuSec assessment report (this document)', 'READY', '#4ade80'),
        ('Cluster correlation evidence (JSON export)', 'READY' if cluster_count > 0 else 'PENDING', '#4ade80' if cluster_count > 0 else '#f59e0b'),
        ('Data-owner attestation on PII scope', 'PENDING', '#f59e0b'),
        ('Chain-of-custody log from forensics', 'PENDING', '#f59e0b'),
        ('Legal counsel sign-off on notification decision', 'PENDING', '#f59e0b'),
        ('GRC tool incident record with reference number', 'PENDING', '#f59e0b'),
        ('Post-incident risk register update', 'PENDING', '#f59e0b'),
        ('Control remediation plan with owners and dates', 'PENDING', '#f59e0b'),
    ]
    parts.append('<table><thead><tr><th>Evidence Item</th><th style="width:80px">Status</th></tr></thead><tbody>')
    for item_name, status, status_clr in evidence_items:
        parts.append(f'<tr><td>{escape(item_name)}</td>'
                     f'<td style="color:{status_clr};font-weight:700">{escape(status)}</td></tr>')
    parts.append('</tbody></table></div>')

    # Collapsible: MITRE → framework mapping table, PASTA risk register, GRC export note
    coll_parts = []
    fw_rows = [(tid, cnt, _MITRE_TO_FRAMEWORK[tid]) for tid, cnt in mitre_hits[:10] if tid in _MITRE_TO_FRAMEWORK]
    if fw_rows:
        coll_parts.append('<strong style="color:#9bb;display:block;margin-bottom:6px">CONTROL REMEDIATION ROADMAP — MITRE MAPPING</strong>')
        coll_parts.append('<table><thead><tr><th>Technique</th><th>CIS</th><th>ISO 27001</th><th>SOC 2</th><th>GDPR</th></tr></thead><tbody>')
        for tid, cnt, fw in fw_rows:
            coll_parts.append(f'<tr><td style="font-family:monospace;color:#c4b5fd">{escape(tid)}</td>'
                              f'<td>{escape(fw.get("CIS",""))}</td><td>{escape(fw.get("ISO27001",""))}</td>'
                              f'<td>{escape(fw.get("SOC2",""))}</td><td style="color:#c4b5fd">{escape(fw.get("GDPR",""))}</td></tr>')
        coll_parts.append('</tbody></table>')

    if pasta_risks:
        coll_parts.append('<strong style="color:#9bb;display:block;margin-top:14px;margin-bottom:6px">PASTA RISK REGISTER</strong>')
        coll_parts.append('<table><thead><tr><th>Risk</th><th>Control Gap</th><th style="width:60px">Score</th></tr></thead><tbody>')
        _pasta_gap_map = {
            'Ransomware': 'EDR prevention mode OFF', 'domain compromise': 'Network segmentation absent',
            'PII': 'No DLP / egress filtering', 'Credential': 'MFA not enforced',
            'Regulatory': 'Notification pending', 'disruption': 'IR plan not tested',
        }
        for risk in pasta_risks[:8]:
            gap = next((v for k, v in _pasta_gap_map.items() if k.lower() in risk.get('risk', '').lower()), 'Review required')
            score_clr = '#ef4444' if risk.get('score', 0) >= 8.0 else '#f59e0b'
            coll_parts.append(f'<tr><td>{escape(risk.get("risk",""))}</td>'
                              f'<td style="color:#9bb">{escape(gap)}</td>'
                              f'<td style="color:{score_clr};font-weight:700">{risk.get("score",0)}/10</td></tr>')
        coll_parts.append('</tbody></table>')

    coll_parts.append('<div style="margin-top:14px;padding:12px;background:#0a0d14;border-radius:6px;font-size:12px;color:#9bb">'
                      '<strong style="color:#e6eef8">GRC EVIDENCE EXPORT NOTE:</strong> '
                      'To export this report as evidence, use File > Save As in your browser (HTML format preserves all data). '
                      'For structured GRC tool import, request JSON export from /api/v1/report/ingestion?format=json from your JanuSec administrator.'
                      '</div>')

    parts.append(_collapsible('Control Remediation Roadmap · PASTA Risk Register · GRC Evidence Export', '\n'.join(coll_parts), accent))

    body = '\n'.join(parts)
    return _wrap_page(f'Compliance Report — {escape(verdict)}', body, accent)


# ── main entry point ─────────────────────────────────────────────────────────
def _build_assessment_page(payload: dict, meta: dict, assessment_view: dict,
                           session: str, company: str, generated_at: str) -> str:
    """Evidence-backed default report for persisted assessment exports."""
    accent = '#5b9bd5'
    rows = payload.get('rows') or []
    title = escape(str(assessment_view.get('title') or payload.get('title') or 'JanuSec Breach Assessment'))
    story = assessment_view.get('executive_story') or {}
    parts = [
        f'<h2 style="color:{accent};margin-bottom:4px">{title}</h2>',
        f'<div style="color:#9bb;font-size:12px;margin-bottom:16px">Generated: {generated_at}</div>',
        _stat_bar([
            (f"{int(assessment_view.get('total_rows') or meta.get('total_rows') or len(rows)):,}", 'Total Events', '#60a5fa'),
            (f"{int(assessment_view.get('source_count') or 0):,}", 'Sources', '#a78bfa'),
            (f"{int(assessment_view.get('cluster_count') or 0):,}", 'Correlated Breach Clusters', '#f59e0b'),
            (f"{int(assessment_view.get('validated_breach_count') or 0):,}", 'Validated Breaches', '#e05252'),
        ]),
    ]

    def section(label: str, content: object) -> None:
        text = str(content or '').strip()
        if text:
            parts.append(f'<div class="section"><h3>{escape(label)}</h3><p>{escape(text)}</p></div>')

    sequence = story.get('temporal_sequence') or []
    section('Why This Is Confirmed', story.get('why_confident'))
    missed = story.get('why_missed') or story.get('missed_reason')
    if not missed and sequence:
        missed = '; '.join(str(item.get('why_missed') or '').strip() for item in sequence[:4] if item.get('why_missed'))
    section('Why It Was Missed Earlier', missed)
    section('Business Decision Needed', story.get('business_decision'))
    section('Technical Validation vs Legal Notification', story.get('legal_boundary'))

    if sequence:
        parts.append('<div class="section"><h3>What Happened Over Time</h3><table><thead><tr><th>When</th><th>Event</th><th>Business Impact</th></tr></thead><tbody>')
        for item in sequence[:12]:
            when = ' '.join(str(x) for x in (item.get('day'), item.get('date')) if x)
            parts.append('<tr>' + _td(when) + _td(item.get('title') or item.get('what') or '') + _td(item.get('business_impact') or item.get('significance') or '') + '</tr>')
        parts.append('</tbody></table></div>')

    lifecycle = story.get('iso27035_lifecycle') or {}
    phases = lifecycle.get('phases') or []
    if phases:
        parts.append('<div class="section"><h3>ISO 27035 Incident Lifecycle</h3><table><thead><tr><th>Phase</th><th>Status</th><th>Evidence</th></tr></thead><tbody>')
        for phase in phases:
            parts.append('<tr>' + _td(phase.get('phase') or phase.get('name') or '') + _td(phase.get('status') or '') + _td(phase.get('evidence') or phase.get('note') or '') + '</tr>')
        parts.append('</tbody></table></div>')

    control = story.get('control_impact') or {}
    frameworks = control.get('frameworks') or []
    if frameworks:
        parts.append('<div class="section"><h3>ISO 27001 ISMS controls</h3><p>' + escape(', '.join(str(x) for x in frameworks[:12])) + '</p></div>')

    reasons = assessment_view.get('confirmed_reasons') or []
    if reasons:
        parts.append('<div class="section"><h3>Confirmed Reasons</h3><ul>')
        for reason in reasons:
            parts.append(f'<li><strong>{escape(str(reason.get("title") or ""))}</strong>: {escape(str(reason.get("narrative") or ""))}</li>')
        parts.append('</ul></div>')

    factors = assessment_view.get('top_factors') or []
    if factors:
        parts.append('<div class="section"><h3>Top Validated-Breach Factors</h3><table><thead><tr><th>Factor</th><th>Count</th><th>Origins</th></tr></thead><tbody>')
        for item in factors[:16]:
            origins = item.get('origins') or {}
            parts.append('<tr>' + _td(item.get('factor') or '', mono=True) + _td(item.get('count') or 0, align='right') + _td(', '.join(str(k) for k in origins.keys())) + '</tr>')
        parts.append('</tbody></table></div>')

    source_counts = assessment_view.get('source_counts') or meta.get('source_counts') or {}
    if source_counts:
        parts.append('<div class="section"><h3>Source Coverage</h3><table><thead><tr><th>Source</th><th>Rows</th></tr></thead><tbody>')
        for source, count in source_counts.items():
            parts.append('<tr>' + _td(source) + _td(f'{int(count):,}', align='right') + '</tr>')
        parts.append('</tbody></table></div>')

    clusters = assessment_view.get('cluster_rollups') or payload.get('clusters') or []
    if clusters:
        parts.append('<div class="section"><h3>Correlated Breach Clusters</h3><table><thead><tr><th>Cluster</th><th>Verdict</th><th>Rows</th><th>Key Factors</th></tr></thead><tbody>')
        for cluster in clusters[:20]:
            factors_text = ', '.join(str(x) for x in (cluster.get('key_factors') or cluster.get('factor_tags') or [])[:6])
            parts.append('<tr>' + _td(cluster.get('title') or cluster.get('incident_name') or cluster.get('cluster_id') or '') + _td(cluster.get('verdict') or cluster.get('final_verdict') or '') + _td(f'{int(cluster.get("row_count") or 0):,}', align='right') + _td(factors_text) + '</tr>')
        parts.append('</tbody></table></div>')

    parts.append('<div class="section"><h3>Benchmark Comparison</h3><p>Benchmark labels are derived from persisted assessment metadata and evidence coverage, not from raw event table fields.</p></div>')

    if rows:
        preview = ['<table><thead><tr><th>Time</th><th>User</th><th>Host</th><th>Event</th><th>Severity</th></tr></thead><tbody>']
        for row in rows[:50]:
            preview.append('<tr>' + _td(row.get('timestamp') or row.get('createdDateTime') or '') + _td(row.get('user') or row.get('user_canonical') or '') + _td(row.get('host') or row.get('hostname') or row.get('src_host') or '') + _td(row.get('event_type') or row.get('event_name') or row.get('action') or '') + _td(row.get('severity') or row.get('verdict') or '') + '</tr>')
        preview.append('</tbody></table>')
        parts.append(_collapsible('Appendix - Flagged Event Preview', ''.join(preview), accent))

    return _wrap_page(title, '\n'.join(parts), accent)


def build_report_html(payload):
    import datetime
    assessment_view = payload.get('assessment_view') if isinstance(payload.get('assessment_view'), dict) else {}
    report_title = assessment_view.get('title') or payload.get('title') or 'Comprehensive Findings Report'
    title = escape(str(report_title))
    rows = payload.get('rows') or []
    session = payload.get('session_id') or ''
    meta = payload.get('meta') or {}
    persona = str(meta.get('persona') or ('assessment' if assessment_view else 'soc_analyst')).lower()
    company = meta.get('company_name') or ''
    generated_at = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    # Dispatch to per-persona full-page builders
    _builders = {
        'soc_analyst':   _build_soc_page,
        'ciso':          _build_ciso_page,
        'executive':     _build_executive_page,
        'threat_hunter': _build_threat_hunter_page,
        'forensics':     _build_forensics_page,
        'compliance':    _build_compliance_page,
        'assessment':    _build_assessment_page,
    }
    builder = _builders.get(persona)
    if builder:
        return builder(payload, meta, assessment_view, session, company, generated_at)

    # ── Fallback: generic page for unknown personas ───────────────────────────
    _ropts = meta.get('report_options') or {}
    def _opt(key: str, default: bool = True) -> bool:
        return bool(_ropts.get(key, default))

    rows = payload.get('rows') or []
    n_rows = len(rows)
    accent = '#5b9bd5'
    mitre_from_rows = _collect_mitre(rows)
    top_mitre_payload = payload.get('top_mitre') or []
    if not mitre_from_rows and top_mitre_payload:
        mitre_from_rows = [(item.get('technique', ''), item.get('count', 1)) for item in top_mitre_payload[:10]]

    persona_html = _render_persona_section(payload, persona, _ropts)
    footer = (f'<div style="margin-top:24px;padding-top:10px;border-top:1px solid #1e2535;'
              f'font-size:11px;color:#555">Generated by Janusec · {generated_at} · Persona: {escape(persona)}</div>')
    css = ('body{background:#0c1520;color:#e0e0e0;font-family:Segoe UI,Arial,sans-serif;padding:20px;max-width:1200px;margin:0 auto}'
           'h2,h3{color:#e6eef8}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{overflow-wrap:break-word;padding:5px 8px}'
           'a{color:#5b9bd5}pre{overflow-x:auto}')
    body = f'<h2 style="color:{accent}">{title}</h2>\n{persona_html}\n{footer}'
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>'
            f'<style>{css}</style></head><body>{body}</body></html>')
