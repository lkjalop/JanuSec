"""Tier-1 prefill prompt templates for cluster headline + structured incident assessment.

Model: qwen2.5:14b (default) — fast, entity-pinned, JSON output only.
Budget: ~12s per cluster, 1500 tokens max (raised from 512 to support structured output).

Output schema v2 — six structured sections analysts use to answer:
  What happened | Root cause | Affected identity/assets | Evidence chain |
  Observed impact | Confidence + validation | Evidence gaps | Immediate actions
"""
from __future__ import annotations

from typing import Any


def _build_enrichment_context(all_rows: list[dict[str, Any]]) -> str:
    """Extract vendor/HR/change-window context from XLSX enrichment rows (_sheet field set)."""
    vendors: list[str] = []
    hr: list[str] = []
    changes: list[str] = []
    iocs: list[str] = []
    sow: list[str] = []

    for r in all_rows:
        sheet = str(r.get('_sheet') or '').strip()
        if not sheet:
            continue
        try:
            from src.core.ingest.input_classifier import is_non_evidence_sheet
            if is_non_evidence_sheet(sheet):
                continue
        except Exception:
            pass
        sl = sheet.lower()
        if 'vendor' in sl or 'customer' in sl:
            name = r.get('name') or r.get('vendor_name') or r.get('company') or ''
            status = r.get('status') or r.get('vendor_status') or ''
            note = r.get('notes') or r.get('description') or ''
            if name:
                vendors.append(f"  {name}: {status} — {str(note)[:80]}")
        elif 'hr' in sl or 'directory' in sl or 'employee' in sl:
            uname = r.get('user_name') or r.get('username') or r.get('email') or ''
            role = r.get('role') or r.get('job_title') or ''
            dept = r.get('department') or ''
            if uname:
                hr.append(f"  {uname}: {role}, {dept}")
        elif 'change' in sl or 'outage' in sl or 'calendar' in sl:
            cid = r.get('change_id') or r.get('id') or ''
            start = r.get('start') or r.get('start_time') or ''
            impact = r.get('impact') or r.get('description') or ''
            if cid or impact:
                changes.append(f"  {cid} {start}: {str(impact)[:80]}")
        elif 'ioc' in sl or 'threat_intel' in sl or 'intel' in sl:
            indicator = r.get('indicator') or r.get('value') or r.get('ip') or r.get('domain') or ''
            itype = r.get('type') or r.get('indicator_type') or ''
            if indicator:
                iocs.append(f"  [{itype}] {indicator}")
        elif 'sow' in sl or 'pentest' in sl or 'red_herring' in sl:
            item = r.get('description') or r.get('notes') or r.get('scope') or ''
            if item:
                sow.append(f"  {str(item)[:80]}")

    parts: list[str] = []
    if vendors:
        parts.append('KNOWN VENDORS/CUSTOMERS:\n' + '\n'.join(vendors[:15]))
    if hr:
        parts.append('HR DIRECTORY (known users):\n' + '\n'.join(hr[:20]))
    if changes:
        parts.append('CHANGE WINDOWS (telemetry gaps):\n' + '\n'.join(changes[:8]))
    if iocs:
        parts.append('THREAT INTEL IOCs:\n' + '\n'.join(iocs[:20]))
    if sow:
        parts.append('AUTHORIZED PENTEST SCOPE:\n' + '\n'.join(sow[:5]))
    return '\n\n'.join(parts)


def build_cluster_prefill_prompt(
    cluster: dict[str, Any],
    rows: list[dict[str, Any]],
    all_assessment_rows: list[dict[str, Any]] | None = None,
    attack_sequence: str = '',
) -> str:
    cid = cluster.get('cluster_id', 'unknown')
    severity = cluster.get('severity') or cluster.get('risk_level') or 'unknown'
    verdict = cluster.get('verdict') or cluster.get('final_verdict') or 'UNCERTAIN'
    row_count = len(rows)
    sources = sorted({str(r.get('_source') or r.get('source') or '') for r in rows
                      if r.get('_source') or r.get('source')})

    enrichment_block = _build_enrichment_context(all_assessment_rows or [])

    # Entity extraction — bounded set for hallucination prevention
    # Sort rows by severity before sampling so the LLM sees the most important events
    _SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    sorted_rows = sorted(
        rows,
        key=lambda r: _SEV_ORDER.get(str(r.get('severity') or r.get('risk_level') or 'low').lower(), 5)
    )
    users, ips, hosts, mitre_ids = set(), set(), set(), set()
    row_summaries: list[str] = []

    for r in sorted_rows[:30]:
        for f in ('user', 'user_principal_name', 'username', 'account', 'entity'):
            v = str(r.get(f) or '').strip()
            if v and v not in ('-', 'N/A', ''):
                users.add(v)
        for f in ('src_ip', 'source_ip', 'dst_ip', 'destination_ip'):
            v = str(r.get(f) or '').strip()
            if v and v not in ('-', 'N/A', ''):
                ips.add(v)
        for f in ('hostname', 'host', 'src_host', 'device_name'):
            v = str(r.get(f) or '').strip()
            if v and v not in ('-', 'N/A', ''):
                hosts.add(v)
        for f in ('mitre_technique', 'mitre', 'technique_id'):
            v = r.get(f)
            if isinstance(v, list):
                mitre_ids.update(str(x) for x in v if x)
            elif v:
                mitre_ids.add(str(v))
        desc = (r.get('description') or r.get('analyst_notes') or
                r.get('activityDisplayName') or r.get('eventName') or
                r.get('operationName') or '')
        ridx = r.get('row_index') or r.get('row_number') or '?'
        sev = r.get('severity') or r.get('risk_level') or 'low'
        if desc:
            row_summaries.append(f"  row_{ridx} [{sev}]: {str(desc)[:120]}")

    entities_block = '\n'.join([
        '  Users/accounts: ' + (', '.join(sorted(users)[:8]) or 'none identified'),
        '  External IPs:   ' + (', '.join(sorted(ips)[:6]) or 'none identified'),
        '  Hosts:          ' + (', '.join(sorted(hosts)[:6]) or 'none identified'),
        '  MITRE:          ' + (', '.join(sorted(mitre_ids)[:8]) or 'none identified'),
    ])

    rows_block = '\n'.join(row_summaries[:20]) or '  (no descriptions available)'

    # Correlation pivot context so the LLM understands WHY rows were clustered
    reason_summary = cluster.get('reason_summary') or ''
    top_links = cluster.get('top_links') or []
    pivot_lines: list[str] = []
    seen_pivots: set[str] = set()
    for lk in top_links:
        line = (f"  row_{lk.get('src')}\u2194row_{lk.get('dst')}"
                f" [{lk.get('pivot','?')}] conf={lk.get('conf',0):.2f}: {lk.get('summary','')}")
        key = f"{lk.get('pivot')}:{lk.get('summary','')[:40]}"
        if key not in seen_pivots:
            pivot_lines.append(line)
            seen_pivots.add(key)
    pivot_block = ('\n'.join(pivot_lines[:4])
                   or (f'  {reason_summary}' if reason_summary
                       else '  (no pivot details available)'))

    enrichment_section = (
        f'\nENRICHMENT CONTEXT (use this to identify known entities before drawing conclusions):\n{enrichment_block}\n'
        if enrichment_block else ''
    )

    attack_sequence_section = (
        f'\nATTACK SEQUENCE (kill-chain phases derived from row timestamps — use this to reason about multi-stage activity):\n  {attack_sequence.replace(chr(10), chr(10) + "  ")}\n'
        if attack_sequence else ''
    )

    return f"""You are a senior security analyst producing a structured incident assessment.
Your output will be read by both technical analysts (evidence chain, MITRE, actions)
and non-technical executives (what_happened, root_cause, short_narrative).

CLUSTER: {cid}
SEVERITY: {severity}
VERDICT: {verdict}
ROW COUNT: {row_count}
SOURCES: {', '.join(sources) or 'unknown'}
{enrichment_section}{attack_sequence_section}
CORRELATION PIVOT REASONS (why these rows were clustered together):
{pivot_block}

ENTITIES ALLOWED — only reference entities listed below. Do NOT invent any name, IP, or host not in this list:
{entities_block}

EVIDENCE ROWS (ordered by row_index, highest severity first):
{rows_block}

━━━ REASONING STEPS (write in "reasoning" field — will NOT be shown to users) ━━━

STEP 1 — EVIDENCE INVENTORY
  List every unique data point you have: accounts, IPs, hosts, timestamps, actions.
  Can you build a coherent timeline? If not, what is missing?

STEP 2 — ADVERSARIAL CHECK
  a) Write the strongest BENIGN explanation (pentest, misconfiguration, user error, approved IT change).
  b) List every row that contradicts the benign explanation.
  c) Final verdict: if >60% of rows cannot be explained benignly, verdict is REAL.

STEP 3 — MULTI-HOP INTERROGATION (critical — do not skip)
  If your hypothesis is correct, what additional evidence WOULD you expect to find?
  For each expected evidence item: is it present in the rows above?
  For each ABSENT expected item: does its absence weaken or strengthen your hypothesis?
  Ask yourself: "Am I missing any evidence that would change my assessment?"

STEP 4 — ROOT CAUSE vs OBSERVED ACTIVITY
  Root cause: what vulnerability, misconfiguration, or gap ENABLED this attack?
    (examples: no MFA, weak password policy, unpatched CVE, over-privileged account)
  Observed activity: what did the attacker actually DO, step by step?

STEP 5 — IMPACT CHAIN
  Identity: which accounts are compromised or at risk?
  Data: what data was accessed, exfiltrated, or at risk?
  Operational: what systems or services are disrupted or at risk?

━━━ OUTPUT RULES ━━━
1. Return ONLY valid JSON. No markdown, no text outside the JSON object.
2. All string fields: plain English, no technical jargon (no T-codes, no raw IPs in narrative fields,
   no KQL, no SPL). Jargon belongs ONLY in tool_command fields.
3. incident_name: 2-4 words, uppercase (e.g. "HARBOURSIDE BEC", "NPM WORM DEV").
4. headline_subtitle: ≤10 words, entity→action→target pattern.
5. what_happened: 2-3 sentences for a non-technical executive. Explain the attack story
   using plain language. No acronyms without explanation. No IP addresses.
6. root_cause: 1 sentence — what vulnerability or gap made this attack possible.
7. evidence_chain: ordered list of attack steps, each with the row indices that prove it.
   Maximum 5 steps. Each step: what happened and why it matters.
8. observed_impact.identity: list of affected account names (from ENTITIES ALLOWED only).
9. observed_impact.data: 1 sentence on data at risk.
10. observed_impact.operational: 1 sentence on service/system disruption.
11. evidence_gaps: list of 2-3 gaps — sources not present, expected events not seen.
    For each gap: what it would confirm if it were present.
12. confidence_rationale: list of 3-4 strings — WHY this confidence level.
13. immediate_actions: list of 3-5 actions, priority-ordered (P1 first).
    Each action MUST have subtasks (2-3 specific steps with tool_command strings).
14. short_narrative: same as what_happened but 1 sentence — for card headline.
15. verdict_reasoning: 1-2 sentences WHY this verdict, citing specific row indices.
16. mitre_evidence_map: map technique_id → [row_index integers] — ONLY if row evidence supports it.

Return this exact JSON schema (all fields required):
{{
  "reasoning": "<STEP 1-5 scratchpad — adversarial check + multi-hop interrogation>",
  "incident_name": "EXAMPLE INCIDENT",
  "headline_subtitle": "attacker did X to target Y",
  "what_happened": "Plain English 2-3 sentence story for executives.",
  "root_cause": "One sentence on what enabled this attack.",
  "evidence_chain": [
    {{
      "step": 1,
      "row_refs": [<row_index integers>],
      "what": "What happened at this step.",
      "why_significant": "Why this step matters in the attack chain."
    }}
  ],
  "observed_impact": {{
    "identity": ["affected.account@corp.com"],
    "data": "What data was accessed or at risk.",
    "operational": "What system or service is disrupted."
  }},
  "evidence_gaps": [
    {{
      "gap": "What evidence is absent.",
      "would_confirm": "What this evidence would prove if present.",
      "significance": "high | medium | low"
    }}
  ],
  "confidence_rationale": ["Bullet 1", "Bullet 2", "Bullet 3"],
  "immediate_actions": [
    {{
      "priority": "P1",
      "title": "Short action title",
      "persona": "soc",
      "rationale": "Why this is the first priority.",
      "subtasks": [
        {{
          "label": "Step description",
          "tool_command": "exact command string",
          "expected_finding": "What you expect to find"
        }}
      ]
    }}
  ],
  "short_narrative": "One-sentence plain English summary.",
  "verdict_reasoning": "WHY this verdict, citing row_X.",
  "mitre_techniques": ["T1234"],
  "mitre_evidence_map": {{"T1234": [0, 3]}}
}}"""


def build_exec_summary_prompt(
    cluster_headlines: list[dict[str, Any]],
    verdict_counts: dict[str, int],
    total_rows: int,
    total_sources: int,
) -> str:
    headlines_block = '\n'.join(
        f"  {i+1}. [{h.get('verdict','?')}] {h.get('incident_name','?')} — {h.get('headline_subtitle','')}"
        for i, h in enumerate(cluster_headlines[:3])
    )
    counts_line = ', '.join(
        f"{v} {k}" for k, v in verdict_counts.items() if v > 0
    )

    return f"""You are a security analyst writing a one-sentence executive summary of a threat assessment.

ASSESSMENT FACTS (do not alter these numbers):
  Total rows: {total_rows}
  Total sources: {total_sources}
  Verdict breakdown: {counts_line}

TOP CLUSTER HEADLINES:
{headlines_block}

TASK: Write exactly 1-2 sentences describing the dominant attack pattern and any secondary indicators.
Rules:
- Only reference entities, technique names, or threat types visible in the headlines above
- Do not invent actors, tools, or techniques not mentioned
- Do not repeat the verdict counts (those come from the deterministic backbone)
- Tone: factual, concise, professional
- No technical jargon (no T-codes, no raw IPs, no tool names)

Return ONLY valid JSON:
{{"llm_color": "..."}}"""


# Tool commands available per source type — surfaced in further-task subtasks
TOOL_COMMANDS_BY_SOURCE: dict[str, dict[str, list[str]]] = {
    'okta': {
        'soc':      ['Okta System Log API: GET /api/v1/logs?filter=...', 'Okta Admin Console → Reports → System Log'],
        'hunter':   ['KQL: OktaSSO | where eventType startswith "user.authentication"', 'Sigma rule: okta_credential_spray.yml'],
        'forensics':['Okta API token audit: GET /api/v1/api-tokens', 'Export raw SCIM events for user lifecycle review'],
    },
    'azure_entra': {
        'soc':      ['KQL: SigninLogs | where UserPrincipalName == "..."', 'AzureCLI: az ad user show --id ...'],
        'hunter':   ['KQL: AADNonInteractiveUserSignInLogs | where RiskLevelDuringSignIn == "high"', 'Defender: DeviceLogonEvents | where LogonType == 3'],
        'forensics':['KQL: AuditLogs | where OperationName == "Reset user password"', 'az ad auditlogs list --filter <expr>'],
    },
    'endpoint': {
        'soc':      ['Defender: DeviceProcessEvents | where FileName == "..."', 'MDE isolate device: POST /api/machines/{id}/isolate'],
        'hunter':   ['YARA scan: yara rules/persistence.yar /proc/', 'Sigma: proc_creation_susp_*.yml', 'KQL: DeviceEvents | where ActionType == "ProcessInjection"'],
        'forensics':['Volatility: vol.py -f mem.raw windows.malfind', 'KAPE target: KapeTriage', 'FTK: mount image → run IOC sweep'],
    },
    'azure_net': {
        'soc':      ['KQL: AzureNetworkAnalytics_CL | where SubType_s == "FlowLog"', 'AzureCLI: az network watcher flow-log show'],
        'hunter':   ['KQL: CommonSecurityLog | where DeviceAction == "deny" | summarize by DestinationIP', 'SPL: index=azure sourcetype=azure:nsg'],
        'forensics':['Packet capture: az network watcher packet-capture create', 'NSG flow log export → pcap analysis'],
    },
    'email': {
        'soc':      ['Exchange: Get-MessageTrace -SenderAddress ...', 'M365 Defender: EmailEvents | where SenderFromAddress == "..."'],
        'hunter':   ['KQL: EmailEvents | where EmailDirection == "Inbound" and AttachmentCount > 0', 'Sigma: exchange_email_phishing.yml'],
        'forensics':['eDiscovery: New-ComplianceSearch -ContentMatchQuery "..."', 'MFMT analysis of email headers'],
    },
    'npm_log': {
        'soc':      ['npm audit --json', 'Review package.json diff against last known-good commit'],
        'hunter':   ['KQL: DeviceNetworkEvents | where InitiatingProcessFileName == "node.exe"', 'YARA: npm_malicious_postinstall.yar'],
        'forensics':['strings node_modules/<pkg>/<script>.js | grep -i "http\\|curl\\|wget"', 'npm pack --dry-run > inspect tarball contents'],
    },
}

_DEFAULT_TOOL_COMMANDS = {
    'soc':      ['Check source-specific admin console for account activity', 'Review authentication logs for affected entities'],
    'hunter':   ['Build Sigma rule from observed IOCs', 'Search SIEM for lateral movement from affected hosts'],
    'forensics':['Acquire memory image if endpoint involved', 'Hash known-bad files and cross-reference VirusTotal'],
}


def _get_tool_commands_for_sources(sources: list[str]) -> dict[str, list[str]]:
    """Merge tool commands across all sources present in this cluster."""
    merged: dict[str, set[str]] = {'soc': set(), 'hunter': set(), 'forensics': set()}
    for src in sources:
        cmds = TOOL_COMMANDS_BY_SOURCE.get(src, _DEFAULT_TOOL_COMMANDS)
        for persona, items in cmds.items():
            merged[persona].update(items)
    return {p: sorted(v)[:4] for p, v in merged.items()}


def build_further_tasks_prompt(
    cluster: dict[str, Any],
    uncovered_rows: list[dict[str, Any]],
    missing_sources: list[str],
    completed_task_titles: list[str],
    entities_allowed: dict[str, list[str]],
    cluster_sources: list[str] | None = None,
) -> str:
    uncovered_block = '\n'.join(
        f"  row_{r.get('row_index') if 'row_index' in r else r.get('row_number','?')} [{r.get('severity','low')}] "
        f"{r.get('mitre_technique') or r.get('technique_id','')}: "
        f"{str(r.get('description') or r.get('analyst_notes') or r.get('activityDisplayName') or '')[:120]}"
        for r in uncovered_rows[:12]
    ) or '  (none)'

    missing_block = '\n'.join(f'  \u00b7 {s}' for s in missing_sources) or '  (none)'
    completed_block = '\n'.join(f'  \u00b7 {t}' for t in completed_task_titles) or '  (none)'

    entities_block = '\n'.join([
        '  Users: ' + ', '.join(entities_allowed.get('users', [])[:8]),
        '  IPs: '   + ', '.join(entities_allowed.get('ips', [])[:6]),
        '  Hosts: ' + ', '.join(entities_allowed.get('hosts', [])[:6]),
    ])

    tool_cmds = _get_tool_commands_for_sources(cluster_sources or [])
    tool_block = '\n'.join([
        '  SOC Analyst commands: '   + '; '.join(tool_cmds['soc'][:2]      or ['(general console review)']),
        '  Threat Hunter commands: ' + '; '.join(tool_cmds['hunter'][:2]   or ['(build Sigma rule)']),
        '  Forensics commands: '     + '; '.join(tool_cmds['forensics'][:2] or ['(acquire artifacts)']),
    ])

    return f"""You are a security analyst suggesting additional investigation tasks after initial triage.

ENTITIES ALLOWED — only reference entities listed below:
{entities_block}

COMPLETED TASKS (do not repeat these):
{completed_block}

UNCOVERED EVIDENCE (rows not yet referenced by any completed task):
{uncovered_block}

MISSING LOG SOURCES (pre-computed — only suggest pulling these specific sources):
{missing_block}

TOOL COMMANDS AVAILABLE (use exactly these strings in subtask tool_command fields):
{tool_block}

TASK: Suggest up to 3 further investigation tasks.
Each task MUST satisfy ONE of:
  A. Cite at least one row_index from UNCOVERED EVIDENCE above, OR
  B. Cite a specific source from MISSING LOG SOURCES above

Rules:
- Do NOT invent row numbers not listed in UNCOVERED EVIDENCE
- Do NOT reference entities not in ENTITIES ALLOWED
- Do NOT repeat completed tasks
- priority: P1 (urgent), P2 (important), P3 (nice to have)
- Each subtask MUST include a tool_command chosen from TOOL COMMANDS AVAILABLE above
- persona: "soc", "hunter", or "forensics" — match to the relevant tool_command

Return ONLY valid JSON:
{{
  "further_tasks": [
    {{
      "title": "...",
      "rationale": "Based on row_X showing ...",
      "evidence_refs": [<row_index integers from UNCOVERED list>],
      "missing_source": null,
      "priority": "P2",
      "subtasks": [
        {{
          "label": "...",
          "persona": "soc",
          "tool_command": "<exact string from TOOL COMMANDS AVAILABLE>",
          "expected_finding": "What you expect to find if hypothesis is correct"
        }}
      ]
    }}
  ]
}}"""
