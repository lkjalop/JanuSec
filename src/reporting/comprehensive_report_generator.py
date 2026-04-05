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
    """Derive severity distribution from risk_score / confidence on each row."""
    dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for r in rows:
        risk = 0.0
        try:
            risk = float(r.get('risk_score') or r.get('confidence') or 0)
        except Exception:
            pass
        dist[_sev_from_risk(risk)] += 1
    return {k: v for k, v in dist.items() if v > 0}


def _collect_mitre(rows: list) -> list:
    """Collect MITRE techniques from row factors."""
    counts: dict = {}
    try:
        from src.core.mappings.factor_to_mitre import get_all_mappings
    except Exception:
        try:
            from ..core.mappings.factor_to_mitre import get_all_mappings  # type: ignore
        except Exception:
            return []
    for row in rows:
        factors = row.get('factors') or []
        if isinstance(factors, list):
            factor_names = [f.get('name') if isinstance(f, dict) else str(f) for f in factors]
        else:
            factor_names = []
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
            name = f.get('name') if isinstance(f, dict) else str(f)
            if name:
                counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


def _render_persona_section(payload: dict, persona: str) -> str:
    """Render a styled persona-specific HTML block."""
    secs: list = []
    rows = payload.get('rows') or []
    meta = payload.get('meta') or {}
    all_factors = _collect_all_factors(rows)
    mitre_hits = _collect_mitre(rows)
    n_rows = len(rows)
    n_flagged = sum(1 for r in rows if float(r.get('risk_score') or r.get('confidence') or 0) > 0.05)

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
                        f'{"High-confidence threats including C2 command-and-control beacons and malicious process execution were found." if any(f in all_factors for f in ("c2_beacon","suspicious_process")) else "Suspicious activity was detected across multiple data sources."}'
                        f' Immediate containment is recommended for impacted endpoints.</p>')
        else:
            secs.append(f'<p>No high-risk events detected in this batch of {n_rows} records. Routine security monitoring can continue.</p>')
        # Business impact
        top_factors = list(all_factors.keys())[:3]
        if top_factors:
            secs.append(f'<div style="{SUB}">Business Risk Indicators</div>')
            secs.append('<ul style="margin:4px 0 8px 18px">')
            risk_map = {
                'c2_beacon':          'Active command-and-control channel — attacker may have persistent access to your network.',
                'suspicious_process': 'Malicious processes executed — potential malware infection on one or more endpoints.',
                'macro_lure':         'Phishing campaign via macro-enabled documents — credential theft or malware delivery likely attempted.',
                'smb_lateral_movement': 'Lateral movement across file shares — attacker may be traversing the internal network.',
                'rdp_lateral_movement': 'Remote desktop lateral movement — attacker may be moving to higher-value systems.',
                'wmi_lateral_movement': 'Remote execution via WMI — could indicate hands-on-keyboard attacker behaviour.',
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
        # Factor frequency table
        if all_factors:
            secs.append(f'<div style="{SUB}">Detected Factors (frequency)</div>')
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
        # Kill chain stage inference
        stages = []
        if any(f in all_factors for f in ('macro_lure','phishing_link','phishing_lure','email_malicious_url')):
            stages.append(('Initial Access', 'Phishing / malicious email with macro lure', 'T1566.001'))
        if any(f in all_factors for f in ('powershell_execution','encoded_command','office_child_process')):
            stages.append(('Execution', 'Scripted execution via PowerShell or Office macro', 'T1059.001'))
        if any(f in all_factors for f in ('suspicious_process','lolbin','temp_execution')):
            stages.append(('Defense Evasion', 'LOLBin or temp-path execution bypassing AV', 'T1218/T1036.005'))
        if any(f in all_factors for f in ('wmi_lateral_movement','rdp_lateral_movement','smb_lateral_movement')):
            stages.append(('Lateral Movement', 'Remote execution or admin-share access', 'T1021'))
        if any(f in all_factors for f in ('c2_beacon','network_beacon')):
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
        secs.append('</div>')

    elif persona == 'compliance':
        clr = '#9b59b6'
        secs.append(f'<div style="{BLOCK.format(clr=clr)}">')
        secs.append(f'<div style="{HEAD.format(clr=clr)}">Compliance — Controls & Regulatory Obligations</div>')
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
        # GDPR warning
        if any(f in all_factors for f in ('credential_access','phishing_lure','macro_lure','c2_beacon')):
            secs.append('<div style="padding:8px 12px;background:#1a0a20;border:1px solid #9b59b6;border-radius:4px;margin-bottom:10px">'
                        '<strong style="color:#c4b">⚠ GDPR Notification Risk:</strong> Credential access or phishing targeting of users '
                        'may constitute a personal data breach. Assess within 72 hours of confirming incident scope. '
                        'Article 33 requires notification to the supervisory authority if risk to individuals cannot be ruled out.</div>')
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
        # IOC table
        hosts_seen, ips_seen, hashes_seen, processes_seen = set(), set(), set(), set()
        for r in rows:
            if r.get('host'): hosts_seen.add(r['host'])
            if r.get('dst_ip'): ips_seen.add(r['dst_ip'])
            if r.get('src_ip'): ips_seen.add(r['src_ip'])
            if r.get('sha256'): hashes_seen.add(r['sha256'])
            if r.get('process') or r.get('process_name'):
                processes_seen.add(r.get('process') or r.get('process_name'))
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


def build_report_html(payload):
    import datetime
    title = escape(str(payload.get('title', 'Comprehensive Findings Report')))
    rows = payload.get('rows') or []
    session = payload.get('session_id') or ''
    meta = payload.get('meta') or {}
    persona = str(meta.get('persona') or 'soc_analyst').lower()
    company = meta.get('company_name') or ''
    generated_at = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    # Derive real stats from rows (these override any hardcoded values)
    n_rows = len(rows)
    sev_dist = _derive_severity_dist(rows)
    # Use passed severity_distribution if rows lack risk_score (aggregation path)
    summary = payload.get('summary') or {}
    passed_sev = (summary.get('severity_distribution') if isinstance(summary, dict) else None) or {}
    if not any(sev_dist.values()):
        sev_dist = passed_sev
    mitre_from_rows = _collect_mitre(rows)
    # Also pick up pre-computed top_mitre from the payload (aggregation path)
    top_mitre_payload = payload.get('top_mitre') or []
    if not mitre_from_rows and top_mitre_payload:
        mitre_from_rows = [(item.get('technique', ''), item.get('count', 1)) for item in top_mitre_payload[:10]]
    all_factors = _collect_all_factors(rows)

    PERSONA_COLORS = {
        'executive':    '#5b9bd5',
        'soc_analyst':  '#2ecc71',
        'threat_hunter':'#e74c3c',
        'compliance':   '#9b59b6',
        'forensics':    '#e67e22',
    }
    accent = PERSONA_COLORS.get(persona, '#5b9bd5')

    sections = []
    # ── Header ──────────────────────────────────────────────────────────────
    sections.append(
        f'<div style="border-bottom:2px solid {accent};padding-bottom:10px;margin-bottom:14px">'
        f'<h2 style="margin:0;color:{accent}">{title}</h2>'
        f'<div style="color:#9bb;font-size:12px;margin-top:4px">'
        + (f'<strong style="color:#e6eef8">{escape(company)}</strong> &nbsp;·&nbsp; ' if company else '')
        + f'Session: <code>{escape(str(session))}</code> &nbsp;·&nbsp; '
        f'Persona: <span style="color:{accent};font-weight:600">{escape(persona.replace("_"," ").title())}</span> '
        f'&nbsp;·&nbsp; Generated: {generated_at}</div></div>'
    )

    # ── Key Stats bar ────────────────────────────────────────────────────────
    n_flagged = sum(1 for r in rows if float(r.get('risk_score') or r.get('confidence') or 0) > 0.05)
    sev_labels = {'critical': ('#c0392b', '⛔'), 'high': ('#e67e22', '🔴'),
                  'medium': ('#f1c40f', '🟡'), 'low': ('#2980b9', '🟢'), 'info': ('#555', 'ℹ')}
    sections.append('<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">')
    stat_style = 'padding:8px 14px;border-radius:6px;background:#0d1620;flex:1;min-width:100px;text-align:center'
    sections.append(f'<div style="{stat_style}"><div style="font-size:22px;font-weight:700;color:{accent}">{n_rows}</div>'
                    f'<div style="font-size:11px;color:#9bb">Total Events</div></div>')
    sections.append(f'<div style="{stat_style}"><div style="font-size:22px;font-weight:700;color:#e67e22">{n_flagged}</div>'
                    f'<div style="font-size:11px;color:#9bb">Flagged</div></div>')
    for sev in ('critical', 'high', 'medium', 'low'):
        cnt = sev_dist.get(sev, 0)
        if cnt:
            clr, ico = sev_labels[sev]
            sections.append(f'<div style="{stat_style}"><div style="font-size:22px;font-weight:700;color:{clr}">{cnt}</div>'
                            f'<div style="font-size:11px;color:#9bb">{ico} {sev.title()}</div></div>')
    sections.append('</div>')

    # ── Persona section ──────────────────────────────────────────────────────
    persona_html = _render_persona_section(payload, persona)
    if persona_html:
        sections.append(persona_html)

    # ── MITRE ATT&CK ────────────────────────────────────────────────────────
    if mitre_from_rows:
        sections.append('<h3 style="margin-top:20px">MITRE ATT&CK Techniques Observed</h3>')
        sections.append('<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:14px">')
        sections.append('<thead><tr>'
                        '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Technique ID</th>'
                        '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Name</th>'
                        '<th style="text-align:right;padding:4px 8px;border-bottom:1px solid #243144">Events</th>'
                        '</tr></thead><tbody>')
        for tid, cnt in mitre_from_rows[:15]:
            name = _MITRE_NAMES.get(str(tid), '')
            sections.append(f'<tr>'
                            f'<td style="padding:4px 8px;border-bottom:1px solid #0e1722;font-family:monospace;color:#f4a">{escape(str(tid))}</td>'
                            f'<td style="padding:4px 8px;border-bottom:1px solid #0e1722">{escape(name)}</td>'
                            f'<td style="padding:4px 8px;border-bottom:1px solid #0e1722;text-align:right">{cnt}</td>'
                            '</tr>')
        sections.append('</tbody></table>')

    # ── Flagged Events table ─────────────────────────────────────────────────
    flagged_rows = [r for r in rows if float(r.get('risk_score') or r.get('confidence') or 0) > 0.05]
    if flagged_rows:
        sections.append('<h3 style="margin-top:16px">Flagged Events</h3>')
        sections.append('<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:14px">')
        sections.append('<thead><tr>'
                        '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Event / Identifier</th>'
                        '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Severity</th>'
                        '<th style="text-align:right;padding:4px 8px;border-bottom:1px solid #243144">Risk</th>'
                        '<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #243144">Factors</th>'
                        '</tr></thead><tbody>')
        for r in flagged_rows[:50]:
            risk = float(r.get('risk_score') or r.get('confidence') or 0)
            sev = _sev_from_risk(risk)
            sev_color = _SEV_COLORS.get(sev, '#555')
            identifier = (r.get('process') or r.get('process_name') or r.get('path') or
                          r.get('file_path') or r.get('src_ip') or r.get('host') or
                          r.get('from') or r.get('event_id') or 'unknown')
            factors_list = r.get('factors') or []
            factor_names = [f.get('name') if isinstance(f, dict) else str(f) for f in factors_list[:5]]
            factor_html = ' '.join(f'<span style="display:inline-block;padding:1px 6px;border-radius:10px;font-size:10px;background:#1a2030;color:#9bb;margin:1px">{escape(fn)}</span>'
                                   for fn in factor_names)
            sections.append(f'<tr>'
                            f'<td style="padding:4px 8px;border-bottom:1px solid #0e1722;font-family:monospace;font-size:11px">{escape(str(identifier)[:80])}</td>'
                            f'<td style="padding:4px 8px;border-bottom:1px solid #0e1722"><span style="color:{sev_color};font-weight:600">{sev.upper()}</span></td>'
                            f'<td style="padding:4px 8px;border-bottom:1px solid #0e1722;text-align:right">{risk:.3f}</td>'
                            f'<td style="padding:4px 8px;border-bottom:1px solid #0e1722">{factor_html}</td>'
                            '</tr>')
        sections.append('</tbody></table>')

    # ── Network Highlights ───────────────────────────────────────────────────
    highlights = payload.get('network_highlights') or {}
    if highlights and any(highlights.get(k) for k in ('top_talkers','beacon_findings','narrative')):
        sections.append('<h3 style="margin-top:16px">Network Highlights</h3>')
        sections.append('<div style="border:1px solid #1f2a38;padding:12px;border-radius:6px;background:#0e141d;margin-bottom:12px">')
        if highlights.get('narrative'):
            sections.append('<ul style="margin:4px 0 10px 16px">' + ''.join(
                f'<li>{escape(str(n))}</li>' for n in highlights['narrative']) + '</ul>')
        if highlights.get('top_talkers'):
            sections.append('<strong>Top Talkers</strong>')
            sections.append('<table style="width:100%;border-collapse:collapse;font-size:12px;margin:6px 0 8px">')
            sections.append('<thead><tr><th style="text-align:left;padding:3px;border-bottom:1px solid #243144">IP</th>'
                            '<th style="text-align:right;padding:3px;border-bottom:1px solid #243144">Flows</th>'
                            '<th style="text-align:left;padding:3px;border-bottom:1px solid #243144">Stage</th></tr></thead><tbody>')
            for t in highlights['top_talkers'][:5]:
                sections.append(f'<tr><td style="padding:3px;border-bottom:1px solid #0e1722;font-family:monospace">{escape(str(t.get("ip")))}</td>'
                                f'<td style="padding:3px;border-bottom:1px solid #0e1722;text-align:right">{escape(str(t.get("count")))}</td>'
                                f'<td style="padding:3px;border-bottom:1px solid #0e1722">{escape(str(t.get("stage")))}</td></tr>')
            sections.append('</tbody></table>')
        sections.append('</div>')

    # ── Raw Rows (collapsible, last) ──────────────────────────────────────────
    if rows and persona in ('soc_analyst', 'forensics', 'threat_hunter'):
        sections.append('<details style="margin-top:16px"><summary style="cursor:pointer;color:#9bb;font-size:13px">'
                        f'Raw Event Data ({len(rows)} rows — click to expand)</summary>')
        for i, r in enumerate(rows[:50]):
            sections.append(f'<div style="border:1px solid #1e2535;padding:6px;margin:4px 0;border-radius:4px">'
                            f'<strong style="font-size:11px;color:#9bb">Row {i+1}</strong>'
                            + _render_row_preview(r) + '</div>')
        sections.append('</details>')

    # ── HopGraph (if present) ────────────────────────────────────────────────
    corr = payload.get('correlation')
    if corr and isinstance(corr, dict) and any(corr.values()):
        sections.append('<h3 style="margin-top:16px">Correlation / HopGraph</h3>')
        try:
            sections.append('<div><pre style="background:#0a1018;padding:10px;border-radius:6px;font-size:11px;overflow:auto;max-height:200px">'
                            + escape(json.dumps(corr, indent=2)) + '</pre></div>')
        except Exception:
            pass

    footer = (f'<div style="margin-top:24px;padding-top:10px;border-top:1px solid #1e2535;'
              f'font-size:11px;color:#555">Generated by Janusec · {generated_at} · Persona: {escape(persona)}</div>')
    css = ('body{background:#0b0f14;color:#e6eef8;font-family:Segoe UI,Arial,sans-serif;padding:20px;max-width:1200px;margin:0 auto}'
           'h2,h3{color:#e6eef8}table{table-layout:fixed}th,td{overflow-wrap:break-word}'
           'a{color:#5b9bd5}pre{overflow-x:auto}')
    html = (f'<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>'
            f'<style>{css}</style></head><body>' + '\n'.join(sections) + footer + '</body></html>')
    return html
