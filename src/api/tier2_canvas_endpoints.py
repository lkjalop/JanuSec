"""
Tier 2 Investigation Canvas — Guided Workflow API
==================================================
Endpoints for the split-pane analyst canvas at /static/tier2_investigation.html

Routes (all under /api/v1/assessments/{assessment_id}/clusters/{cluster_id}/tier2):
  GET    …/tier2           — generate or load cached investigation steps
  POST   …/tier2/decisions — persist one analyst decision
  POST   …/tier2/phase     — record phase completion
  POST   …/tier2/finalise  — mark closed; amend reports for CISO/Executive/Audit/Compliance
  GET    …/tier2/log       — full decision log
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/api/v1/assessments', tags=['tier2-canvas'])
_LLM = None

# ── File-backed store ───────────────────────────────────────────────────────
_BASE = Path(__file__).resolve().parents[2] / 'src' / 'data' / 'tier2'


def _safe(s: str) -> str:
    return str(s).replace('/', '_').replace('\\', '_').replace(':', '_')


def _t2_path(tenant_id: str, assessment_id: str, cluster_id: str) -> Path:
    p = _BASE / _safe(tenant_id) / _safe(assessment_id)
    p.mkdir(parents=True, exist_ok=True)
    return p / (_safe(cluster_id) + '.json')


def _load_t2(tenant_id: str, assessment_id: str, cluster_id: str) -> dict:
    try:
        path = _t2_path(tenant_id, assessment_id, cluster_id)
        if path.exists():
            return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        pass
    return {}


def _save_t2(tenant_id: str, assessment_id: str, cluster_id: str, data: dict) -> None:
    try:
        _t2_path(tenant_id, assessment_id, cluster_id).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8'
        )
    except Exception as exc:
        logger.warning('tier2_canvas save failed: %s', exc)


# ── Pydantic models ──────────────────────────────────────────────────────────

class DecisionIn(BaseModel):
    step_id: str
    phase: str
    decision: str
    notes: str = ''
    logged_at: Optional[int] = None


class PhaseIn(BaseModel):
    phase: str
    decision_log: List[dict] = Field(default_factory=list)


class FinaliseIn(BaseModel):
    decision_log: List[dict] = Field(default_factory=list)


# ── Step generation ──────────────────────────────────────────────────────────

def _safe_text(v: Any) -> str:
    return '' if v is None else str(v)


def _extract_evidence_pins(cluster: dict, rows: List[dict]) -> dict:
    """Extract concrete, citable IOCs and evidence from cluster rows.

    Returns a dict with typed evidence buckets that step instructions reference.
    """
    sev_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    sorted_rows = sorted(
        rows,
        key=lambda r: sev_rank.get(_safe_text(r.get('severity') or r.get('risk_level') or '').lower(), 0),
        reverse=True,
    )[:12]

    ips: list[str] = []
    accounts: list[str] = []
    hosts: list[str] = []
    timestamps: list[str] = []
    mitre_ids: list[str] = []
    event_types: list[str] = []
    descriptions: list[str] = []
    row_ids: list[str] = []

    for r in sorted_rows:
        # IPs
        for f in ('src_ip', 'source_ip', 'dst_ip', 'destination_ip'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in ips and not v.startswith('10.') and not v.startswith('192.168') and not v.startswith('172.'):
                ips.append(v)
        # Accounts / users
        for f in ('user', 'user_principal_name', 'username', 'account', 'entity'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in accounts and v not in ('-', 'N/A', ''):
                accounts.append(v)
        # Hostnames
        for f in ('hostname', 'host', 'src_host', 'dst_host', 'device_name'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in hosts and v not in ('-', 'N/A', ''):
                hosts.append(v)
        # Timestamps
        for f in ('timestamp', 'timestamp_utc', 'event_time', 'time'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in timestamps:
                timestamps.append(v[:19])  # truncate to YYYY-MM-DDTHH:MM:SS
        # MITRE
        for f in ('mitre_technique', 'mitre', 'technique_id'):
            v = r.get(f)
            if isinstance(v, list):
                mitre_ids.extend([_safe_text(x) for x in v if _safe_text(x)])
            elif v:
                mitre_ids.append(_safe_text(v))
        # Event type / description
        ev = _safe_text(r.get('event_type') or '').strip()
        if ev and ev not in event_types:
            event_types.append(ev)
        d = _safe_text(r.get('description') or r.get('analyst_notes') or '').strip()
        if d and d not in descriptions:
            descriptions.append(d[:100])
        # Row refs
        for f in ('row_index', 'row_number', 'event_id', 'id'):
            v = _safe_text(r.get(f)).strip()
            if v and v not in row_ids:
                row_ids.append(v)
                break

    # Deduplicate
    mitre_ids = list(dict.fromkeys(mitre_ids))

    # Also pull from cluster-level fields
    c_accounts = list(dict.fromkeys(
        accounts + (cluster.get('shared_accounts') or []) + (cluster.get('affected_accounts') or [])
    ))[:6]
    c_hosts = list(dict.fromkeys(
        hosts + (cluster.get('shared_hosts') or []) + (cluster.get('affected_assets') or [])
    ))[:6]
    c_ips = list(dict.fromkeys(
        ips + (cluster.get('shared_external_ips') or [])
    ))[:6]
    c_mitre = list(dict.fromkeys(
        mitre_ids + (cluster.get('top_mitre') or [])
    ))[:8]

    return {
        'accounts':    c_accounts,
        'hosts':       c_hosts,
        'ips':         c_ips,
        'timestamps':  timestamps[:6],
        'mitre':       c_mitre,
        'event_types': event_types[:6],
        'descriptions': descriptions[:4],
        'row_ids':     row_ids[:8],
        'top_row_id':  row_ids[0] if row_ids else '',
    }


def _fmt_evidence(pins: dict, *, accounts: bool = False, hosts: bool = False,
                  ips: bool = False, mitre: bool = False, timestamps: bool = False) -> str:
    """Build a compact evidence line for inclusion in step instructions."""
    parts: list[str] = []
    if accounts and pins.get('accounts'):
        parts.append('account(s): ' + ', '.join(pins['accounts'][:3]))
    if hosts and pins.get('hosts'):
        parts.append('host(s): ' + ', '.join(pins['hosts'][:3]))
    if ips and pins.get('ips'):
        parts.append('external IP(s): ' + ', '.join(pins['ips'][:3]))
    if mitre and pins.get('mitre'):
        parts.append('ATT&CK: ' + ', '.join(pins['mitre'][:4]))
    if timestamps and pins.get('timestamps'):
        parts.append('first seen: ' + pins['timestamps'][0] +
                     ((' — last: ' + pins['timestamps'][-1]) if len(pins['timestamps']) > 1 else ''))
    return ('Evidence: ' + '; '.join(parts) + '.') if parts else ''


def _generate_steps(cluster: dict, rows: List[dict]) -> List[dict]:
    sev = cluster.get('severity') or 'high'
    pivots: List[str] = (
        cluster.get('shared_accounts') or cluster.get('shared_hosts') or
        cluster.get('shared_external_ips') or []
    )[:3]
    pivot_text = ', '.join(pivots) if pivots else 'affected entities'
    row_refs: List = cluster.get('row_refs') or []
    top_refs = [int(r) for r in row_refs[:6] if str(r).isdigit()]
    mitre_str = ', '.join((cluster.get('top_mitre') or [])[:4]) or 'undetermined'

    # ── Extract concrete IOCs / evidence pins ─────────────────────────────
    pins = _extract_evidence_pins(cluster, rows)
    ev_accounts  = _fmt_evidence(pins, accounts=True, timestamps=True)
    ev_hosts     = _fmt_evidence(pins, hosts=True, ips=True)
    ev_ips       = _fmt_evidence(pins, ips=True, mitre=True)
    ev_full      = _fmt_evidence(pins, accounts=True, hosts=True, ips=True, mitre=True, timestamps=True)

    # Row-level description corpus for has_* detection
    all_text = ' '.join([
        _safe_text(r.get('description') or r.get('analyst_notes') or r.get('event_type') or '')
        for r in rows
    ] + pins.get('descriptions', [])).lower()

    has_exfil   = any(k in all_text for k in ('exfil', 'upload', 'tar.gz', 'customer', 'pii', 'sftp', 'curl', 'data_pkg', 'ld.db'))
    has_priv    = any(k in all_text for k in ('admin', 'privilege', 'escalat', 'sudo', 'pim', 'jit', 'assumerole', 'svc_', 'policy', 'weakened'))
    has_persist = any(k in all_text for k in ('persist', 'cron', 'startup', 'scheduled', 'backdoor', 'implant', 'schtask', 'beacon'))
    has_cloud   = any(k in all_text for k in ('s3', 'blob', 'azure', 'aws', 'gcp', 'iam', 'role', 'assume', 'cloudtrail'))
    has_cred    = any(k in all_text for k in ('credential', 'password', 'hash', 'ntlm', 'lsass', 'mimikatz', 'spray', 'ld.db', 'imap', 'legacy auth'))
    has_bec     = any(k in all_text for k in ('bec', 'wire transfer', 'forward', 'mailbox', 'forwarding rule', 'imap4', 'finance'))
    has_c2      = any(k in all_text for k in ('c2', 'beacon', 'dns tunnel', 'update-cdn', 'cobalt', 'implant'))
    has_lateral = any(k in all_text for k in ('lateral', 'smb', 'wmi', 'pass-the-hash', 'kerberos', 'rdp'))

    def rr(refs: list) -> list:
        return [int(r) for r in refs if str(r).isdigit()]

    def _ep(step_pins: dict) -> dict:
        """Return a per-step evidence_pins sub-dict for the UI drill-down."""
        return {
            'accounts':    step_pins.get('accounts', []),
            'hosts':       step_pins.get('hosts', []),
            'ips':         step_pins.get('ips', []),
            'timestamps':  step_pins.get('timestamps', []),
            'mitre':       step_pins.get('mitre', []),
            'event_types': step_pins.get('event_types', []),
            'descriptions': step_pins.get('descriptions', []),
            'row_ids':     step_pins.get('row_ids', []),
        }

    # ── Containment actions (evidence-specific) ───────────────────────────
    if has_cloud:
        contain_action = (
            'Revoke active cloud sessions for ' + pivot_text + '. '
            'Apply deny-all SCPs / IAM boundary policies. '
            'Rotate service account credentials before investigation begins. '
            + ev_accounts
        )
    elif has_priv:
        contain_action = (
            'Disable privileged account(s): ' + (', '.join(pins['accounts'][:3]) or pivot_text) + '. '
            'Force-terminate all active sessions (check Okta, Entra, and VPN). '
            'Reset credentials before any investigation step to prevent re-entry. '
            + ev_accounts
        )
    elif has_bec:
        contain_action = (
            'Suspend compromised mailbox: ' + (', '.join(pins['accounts'][:2]) or pivot_text) + '. '
            'Block all mail forwarding rules — check for hidden BCC/forward rules. '
            'Alert finance/AP team immediately; freeze any pending wire transfers. '
            + ev_accounts
        )
    else:
        contain_action = (
            'Isolate: ' + (', '.join(pins['hosts'][:2]) or pivot_text) + ' from the network. '
            'EDR quarantine for hosts; disable identity for accounts. '
            + ev_hosts
        )

    if has_c2:
        network_block = (
            'Block C2 infrastructure at DNS and firewall layers:\n'
            + ('  • Domains: ' + ', '.join([e for e in pins.get('event_types', []) if '.' in e][:2]) + '\n' if any('.' in e for e in pins.get('event_types', [])) else '')
            + ('  • IPs: ' + ', '.join(pins['ips'][:4]) + '\n' if pins['ips'] else '')
            + 'Create SIEM/EDR detection rule for subsequent beacons from these destinations. '
            'Verify block does not catch CDN/legitimate traffic sharing the ASN.'
        )
    else:
        network_block = (
            'Block external IPs and domains identified in evidence rows:\n'
            + ('  • IPs to block: ' + ', '.join(pins['ips'][:4]) + '\n' if pins['ips'] else '  • No external IPs extracted — review rows manually.\n')
            + 'Confirm block at proxy, firewall, and DNS layers. '
            'Cross-check against known-good CDN/SaaS IPs before applying.'
        )

    if has_priv:
        timeline_note = (
            'Confirm whether ' + (', '.join(pins['accounts'][:2]) or pivot_text) +
            ' achieved privileged access (domain admin, JIT, or IAM role assumption) before lateral movement. '
            'Check: Okta policy changes, Azure PIM activations, sudo/su events in syslog.'
        )
    elif has_exfil:
        timeline_note = (
            'Map the exfiltration path: what was staged (' +
            (', '.join(pins['descriptions'][:2]) or 'unknown') +
            '), destination (' + (', '.join(pins['ips'][:2]) or 'unknown') +
            '), volume, and data classification (PII/regulated/IP?). '
            'Pull DLP, proxy, and cloud storage access logs.'
        )
    elif has_bec:
        timeline_note = (
            'Reconstruct BEC chain: compromised mailbox → email style harvest → target. '
            'Confirm: (1) forwarding rule creation time, (2) BEC send time, '
            '(3) target read time, (4) approval sent. '
            'Cross-check with finance AP records for any wire transfers processed.'
        )
    elif has_persist:
        timeline_note = (
            'Confirm persistence mechanism: check Schtasks, Cron, WMI subscriptions, '
            'startup folder, and registry Run keys on ' + (', '.join(pins['hosts'][:2]) or pivot_text) + '.'
        )
    else:
        timeline_note = 'Confirm whether the activity extended beyond ' + pivot_text + '.'

    # ── Build steps ────────────────────────────────────────────────────────
    steps: List[dict] = [
        # ── CONTAIN ───────────────────────────────────────────────────────
        {
            'id': 'c1', 'phase': 'contain', 'persona': 'SOC Analyst',
            'title': 'Isolate and disable ' + (pins['accounts'][0] if pins['accounts'] else pivots[0] if pivots else 'affected entity'),
            'why_flagged': (
                '[' + sev.upper() + '] This cluster contains ' + str(len(row_refs)) + ' correlated events '
                'spanning ' + str(len(set(cluster.get('source_sheets') or []))) + ' source(s). '
                + (_fmt_evidence(pins, accounts=True, hosts=True, timestamps=True) or 'No shared entities extracted.')
                + (' ATT&CK: ' + mitre_str + '.' if mitre_str != 'undetermined' else '')
            ),
            'instructions': contain_action + ' Document every action with timestamp and ticket reference.',
            'evidence_pins': _ep(pins),
            'row_refs': rr(top_refs),
        },
        {
            'id': 'c2', 'phase': 'contain', 'persona': 'SOC Analyst',
            'title': 'Block malicious network destinations',
            'why_flagged': (
                'External infrastructure was identified in ' + str(len(pins['ips'])) + ' evidence row(s). '
                + ev_ips
            ),
            'instructions': network_block,
            'evidence_pins': _ep(pins),
            'row_refs': rr(top_refs),
        },
        {
            'id': 'c3', 'phase': 'contain', 'persona': 'SOC Analyst / CISO',
            'title': 'Confirm containment scope and get CISO sign-off',
            'why_flagged': 'All ' + str(len(row_refs)) + ' rows in this cluster must be covered before investigation. '
                'Blast radius: ' + (cluster.get('blast_radius_summary') or 'unknown') + '.',
            'instructions': (
                'List every identity, host, and network path contained. '
                'Verify: ' + (', '.join(pins['accounts'][:3] + pins['hosts'][:3])) + '. '
                'Confirm all ' + str(len(row_refs)) + ' cluster events are covered. '
                'Get written CISO acknowledgement (ticket, Slack screenshot, or email) before investigation begins.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': [],
        },

        # ── INVESTIGATE ───────────────────────────────────────────────────
        {
            'id': 'i1', 'phase': 'investigate', 'persona': 'SOC Analyst / Threat Hunter',
            'title': 'Reconstruct the full attack timeline',
            'why_flagged': (
                'ATT&CK techniques identified: ' + mitre_str + '. '
                'Campaign window: ' + (pins['timestamps'][0] if pins['timestamps'] else 'unknown') +
                (' to ' + pins['timestamps'][-1] if len(pins['timestamps']) > 1 else '') + '.'
            ),
            'instructions': (
                'Order all ' + str(len(row_refs)) + ' events chronologically. '
                + timeline_note + '\n'
                'Pull adjacent log sources ±48h of first event. '
                'Key pivots: ' + (', '.join(pins['accounts'][:2] + pins['hosts'][:2] + pins['ips'][:2])) + '. '
                'ATT&CK chain to verify: ' + mitre_str + '.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': rr(top_refs),
        },
        {
            'id': 'i2', 'phase': 'investigate', 'persona': 'Threat Hunter',
            'title': 'Confirm blast radius — expand pivot beyond known scope',
            'why_flagged': (
                'Shared entities across cluster: ' + ev_full
            ),
            'instructions': (
                'Pivot on each of the following across EDR, DNS, email, and cloud audit logs:\n'
                + ('  Accounts: ' + ', '.join(pins['accounts'][:4]) + '\n' if pins['accounts'] else '')
                + ('  Hosts:    ' + ', '.join(pins['hosts'][:4]) + '\n' if pins['hosts'] else '')
                + ('  IPs:      ' + ', '.join(pins['ips'][:4]) + '\n' if pins['ips'] else '')
                + 'Did the attacker reach data-bearing, privileged, or production assets outside this cluster? '
                'Document every additional asset found as a new row reference.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': rr(top_refs),
        },
        {
            'id': 'i3', 'phase': 'investigate', 'persona': 'Forensics',
            'title': 'Preserve volatile evidence before any remediation',
            'why_flagged': (
                'Hosts with malicious activity confirmed: ' + (', '.join(pins['hosts'][:3]) or 'see row refs') + '. '
                'Volatile evidence (memory, process tree) will be lost on reboot or EDR remediation.'
            ),
            'instructions': (
                ('Collect from ' + ', '.join(pins['hosts'][:2]) + ':\n' if pins['hosts'] else 'Collect:\n')
                + ('  • Memory dump and PCAP of upload path (exfil detected)\n' if has_exfil else '')
                + ('  • Beacon process tree and DNS query history\n' if has_c2 else '')
                + '  • Filesystem diff (new/modified files since ' + (pins['timestamps'][0][:10] if pins['timestamps'] else 'incident start') + ')\n'
                + '  • Browser credential store (ld.db / Login Data)\n' if has_cred else ''
                + '  • Mailbox export for compromised accounts\n' if has_bec else ''
                + 'Chain of custody required. Do NOT remediate until collection is confirmed complete.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': rr(top_refs),
        },
    ]

    if has_cred:
        steps.append({
            'id': 'i4', 'phase': 'investigate', 'persona': 'Threat Hunter',
            'title': 'Hunt credential exposure — pass-the-hash / token reuse',
            'why_flagged': (
                'Credential access or theft is indicated by: ' +
                '; '.join(pins['descriptions'][:2]) + '. '
                + ev_accounts
            ),
            'instructions': (
                'Hunt for NTLM relay, Kerberoasting, and token replay originating from:\n'
                + ('  IPs: ' + ', '.join(pins['ips'][:3]) + '\n' if pins['ips'] else '')
                + ('  Accounts: ' + ', '.join(pins['accounts'][:3]) + '\n' if pins['accounts'] else '')
                + 'Check: multi-IP use of same credential hash, Okta/Entra impossible-travel logins, '
                'IMAP/legacy auth bypassing MFA. '
                'ATT&CK: ' + mitre_str + '.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': rr(top_refs),
        })

    if has_bec:
        steps.append({
            'id': 'i5', 'phase': 'investigate', 'persona': 'SOC Analyst / Finance',
            'title': 'Trace and freeze BEC-linked financial transactions',
            'why_flagged': (
                'BEC indicators detected: mailbox compromise, forwarding rule, and/or fraudulent email chain. '
                + ev_accounts
            ),
            'instructions': (
                'Immediately contact finance/AP and bank to freeze any pending wire transfers. '
                'Recover evidence: (1) original BEC email + headers, '
                '(2) forwarding rule creation event with timestamp, '
                '(3) CFO/approver response email, '
                '(4) wire transfer processing confirmation. '
                'Preserve all mail items — do NOT delete compromised mailbox before forensic export. '
                'Report to ACSC/FinCERT if wire transfer was processed.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': rr(top_refs),
        })

    if has_c2:
        steps.append({
            'id': 'i6', 'phase': 'investigate', 'persona': 'Threat Hunter / Network',
            'title': 'Characterise full C2 channel and dwell time',
            'why_flagged': (
                'Active C2 beacon detected to: ' + (', '.join(pins['ips'][:2]) or 'unknown C2 IP') + '. '
                + ev_ips
            ),
            'instructions': (
                'Pull all DNS queries to update-cdn-svc.net or matching C2 domain from affected hosts. '
                'Calculate: total beacon count, dwell duration, and first-seen timestamp. '
                'Decode any subdomain exfil data (base64/hex in label entropy > 3.5). '
                'Identify every host with a beacon — lateral movement confirmed if beacons appear on multiple subnets. '
                'Check JA3/JA3S fingerprints against known C2 profiles (Cobalt Strike, Sliver, Metasploit).'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': rr(top_refs),
        })

    if has_lateral:
        steps.append({
            'id': 'i7', 'phase': 'investigate', 'persona': 'Threat Hunter',
            'title': 'Map lateral movement path and second-stage foothold',
            'why_flagged': (
                'Lateral movement indicators in cluster: ' + '; '.join(pins['descriptions'][:2]) + '.'
            ),
            'instructions': (
                'Trace lateral path from initial compromise host to secondary host(s). '
                'Check: SMB named-pipe connections, WMI remote execution, RDP auth events, '
                'and Kerberos service-ticket requests from ' + (', '.join(pins['hosts'][:2]) or pivot_text) + '. '
                'Confirm whether attacker achieved persistence on the second-stage host before containment.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': rr(top_refs),
        })

    # Notification note
    if has_exfil:
        reg_note = (
            'Potential PII / regulated data exfiltration detected: ' +
            '; '.join(pins['descriptions'][:2]) + '. '
            'Confirm data classification and volume. '
            'GDPR Art.33: 72h notification deadline from confirmed discovery. '
            'HIPAA/PCI DSS thresholds: assess per data type. '
            'Document: when exfil was first confirmed, data subject count estimate, and notification decision.'
        )
    elif has_bec:
        reg_note = (
            'BEC with possible financial loss — notify: (1) bank within 24h for wire recall, '
            '(2) ACSC/FinCERT if transfer was processed, '
            '(3) insurers per cyber insurance policy. '
            'Document: wire amount, recipient account, date processed, recall status.'
        )
    else:
        reg_note = (
            'Assess notification obligations: check cluster against regulated data scope '
            '(' + (cluster.get('regulated_data_likelihood') or 'unknown') + ' likelihood). '
            'Frameworks: ' + (', '.join((cluster.get('affected_frameworks') or [])[:3]) or 'none identified') + '. '
            'Document decision with rationale even if notification not required.'
        )

    steps += [
        # ── NOTIFY ────────────────────────────────────────────────────────
        {
            'id': 'n1', 'phase': 'notify', 'persona': 'CISO / Compliance',
            'title': 'Assess and action regulatory notification obligations',
            'why_flagged': (
                'Regulated data likelihood: ' + (cluster.get('regulated_data_likelihood') or 'unknown') +
                '. Legal review recommended: ' + str(cluster.get('legal_review_recommended', False)) + '.'
            ),
            'instructions': reg_note,
            'evidence_pins': _ep(pins),
            'row_refs': [],
        },
        {
            'id': 'n2', 'phase': 'notify', 'persona': 'Executive / CISO',
            'title': 'Internal and external stakeholder notification',
            'why_flagged': 'Severity: ' + sev.upper() + '. Communications owner: ' + (cluster.get('communications_owner') or 'Security leadership') + '.',
            'instructions': (
                'Notify: executive leadership, legal, and HR. '
                'If PR statement recommended: ' + str(cluster.get('pr_statement_recommended', False)) + '. '
                'Log every notification: recipient, timestamp, channel, acknowledgement. '
                'Do not issue external statements until scope is confirmed and legal has reviewed.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': [],
        },

        # ── REMEDIATE ─────────────────────────────────────────────────────
        {
            'id': 'r1', 'phase': 'remediate', 'persona': 'SOC Analyst / IT Ops',
            'title': 'Eradicate malicious presence from affected hosts',
            'why_flagged': (
                'Persistence or active implant detected on: ' + (', '.join(pins['hosts'][:3]) or pivot_text) + '.'
            ),
            'instructions': (
                ('Remove scheduled tasks, startup scripts, and beacon binary from affected hosts:\n' if has_persist or has_c2 else
                 'Remove all malicious files, processes, and shells:\n')
                + ('  Hosts: ' + ', '.join(pins['hosts'][:3]) + '\n' if pins['hosts'] else '')
                + '  Verify removal via EDR process/filesystem scan.\n'
                '  Check for secondary persistence (WMI subscriptions, service installs, GPO).\n'
                'Do NOT restore to production until eradication is confirmed by Forensics.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': rr(top_refs),
        },
        {
            'id': 'r2', 'phase': 'remediate', 'persona': 'Security Engineering / IT Ops',
            'title': 'Patch, harden, and close the initial access vector',
            'why_flagged': (
                'Initial access vector: ' + (pins['event_types'][0] if pins['event_types'] else 'unknown') +
                '. ' + ev_ips
            ),
            'instructions': (
                'Rotate credentials for ALL accounts in blast radius:\n'
                + ('  ' + ', '.join(pins['accounts'][:4]) + '\n' if pins['accounts'] else '')
                + 'Enforce MFA on all affected accounts — no exceptions for service accounts.\n'
                + ('Re-enable MFA for legacy auth protocols (IMAP4, SMTP AUTH, EWS).\n' if has_cred or has_bec else '')
                + ('Tighten IAM roles: remove unused policies, enforce least-privilege.\n' if has_cloud else
                   'Restrict RDP/SMB/WMI via firewall or GPO.\n')
                + 'Remove any added trusted network zones or CA policy exemptions.\n'
                + 'Document each change: before-state, after-state, responsible engineer, ticket.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': [],
        },

        # ── REPORT ────────────────────────────────────────────────────────
        {
            'id': 'rep1', 'phase': 'report', 'persona': 'SOC Analyst / Compliance',
            'title': 'Write the final incident report',
            'why_flagged': 'Decision log from this canvas is the authoritative timeline source.',
            'instructions': (
                'Produce the final report covering:\n'
                '  1. Initial access vector and first-seen timestamp (' + (pins['timestamps'][0] if pins['timestamps'] else 'confirm') + ')\n'
                '  2. Full attack timeline with ATT&CK mapping (' + mitre_str + ')\n'
                '  3. Lateral movement path and affected assets\n'
                '  4. Data impact: ' + ('exfiltration confirmed — classify volume and data type' if has_exfil else 'no exfil confirmed' if not has_exfil else 'assess') + '\n'
                '  5. Containment and eradication actions\n'
                '  6. Hardening steps applied\n'
                '  7. Open action items with owners and deadlines\n'
                'Use the decision log timestamps from this canvas as the authoritative incident timeline.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': [],
        },
        {
            'id': 'rep2', 'phase': 'report', 'persona': 'CISO',
            'title': 'CISO sign-off, lessons learned, and control gap remediation',
            'why_flagged': 'Required before incident closure. Controls affected: ' + (', '.join((cluster.get('affected_controls') or [])[:3]) or 'see rearchitect section') + '.',
            'instructions': (
                'Review and approve the incident report.\n'
                'Document 3+ lessons learned with control gap owners:\n'
                '  • Which detection rule should have caught this earlier?\n'
                '  • Which control failed — and what is the remediation deadline?\n'
                '  • What hunting query should be added to the SOC runbook?\n'
                'Close the incident ticket only after this sign-off is recorded in writing.'
            ),
            'evidence_pins': _ep(pins),
            'row_refs': [],
        },
    ]

    return steps


# ── Route helpers ─────────────────────────────────────────────────────────────

def _get_tenant(request: Request) -> str:
    return (request.headers.get('X-Tenant-ID') or
            request.headers.get('x-tenant-id') or 'default')


def _get_assessment(assessment_id: str) -> Optional[dict]:
    """Look up an assessment using the disk-backed helper (same as cluster_enrich_endpoints).

    Falls back to _ASSESSMENT_STORE for callers that still hold the object in memory.
    """
    try:
        from src.api.deep_analyze_endpoints import _get_assessment_cached  # type: ignore
        result = _get_assessment_cached(assessment_id)
        if result:
            return result
    except Exception:
        pass
    # Last-resort: in-memory REPORT_STORE (works when session is still live)
    try:
        from src.api.deep_analyze_endpoints import REPORT_STORE  # type: ignore
        return REPORT_STORE.get(assessment_id)
    except Exception:
        return None


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get('/{assessment_id}/clusters/{cluster_id}/tier2')
async def get_tier2_steps(assessment_id: str, cluster_id: str, request: Request) -> dict:
    tenant_id = _get_tenant(request)
    store = _load_t2(tenant_id, assessment_id, cluster_id)

    if store.get('steps'):
        return {
            'assessment_id': assessment_id,
            'cluster_id': cluster_id,
            'steps': store['steps'],
            'current_phase': store.get('current_phase', 'contain'),
            'decision_log': store.get('decision_log', []),
            'status': store.get('status', 'in_progress'),
        }

    assessment = _get_assessment(assessment_id)
    cluster: dict = {}
    rows: List[dict] = []
    if assessment:
        for c in (assessment.get('correlation_clusters') or []):
            if c.get('cluster_id') == cluster_id:
                cluster = c
                rr_set = set(c.get('row_refs') or [])
                rows = [r for r in (assessment.get('normalized_rows') or assessment.get('rows') or [])
                        if r.get('row_number') in rr_set or r.get('row_index') in rr_set]
                break

    steps = _generate_steps(cluster, rows)
    store = {
        'assessment_id': assessment_id, 'cluster_id': cluster_id, 'tenant_id': tenant_id,
        'steps': steps, 'current_phase': 'contain', 'decision_log': [], 'status': 'in_progress',
        'created_at': int(time.time()),
    }
    _save_t2(tenant_id, assessment_id, cluster_id, store)
    return {
        'assessment_id': assessment_id, 'cluster_id': cluster_id,
        'steps': steps, 'cluster': cluster or None,
        'current_phase': 'contain', 'decision_log': [], 'status': 'in_progress',
    }


@router.post('/{assessment_id}/clusters/{cluster_id}/tier2/decisions')
async def post_decision(
    assessment_id: str, cluster_id: str, body: DecisionIn, request: Request
) -> dict:
    tenant_id = _get_tenant(request)
    store = _load_t2(tenant_id, assessment_id, cluster_id)
    if not store:
        store = {
            'steps': [], 'decision_log': [], 'current_phase': 'contain', 'status': 'in_progress',
            'assessment_id': assessment_id, 'cluster_id': cluster_id, 'tenant_id': tenant_id,
            'created_at': int(time.time()),
        }

    for step in (store.get('steps') or []):
        if step.get('id') == body.step_id:
            step['decision'] = body.decision
            step['notes'] = body.notes
            step['logged_at'] = body.logged_at or int(time.time() * 1000)
            break

    log: List[dict] = [d for d in (store.get('decision_log') or []) if d.get('step_id') != body.step_id]
    log.append({
        'step_id': body.step_id, 'phase': body.phase, 'decision': body.decision,
        'notes': body.notes, 'logged_at': body.logged_at or int(time.time() * 1000),
    })
    store['decision_log'] = log
    _save_t2(tenant_id, assessment_id, cluster_id, store)
    return {'ok': True, 'step_id': body.step_id, 'decision': body.decision}


@router.post('/{assessment_id}/clusters/{cluster_id}/tier2/phase')
async def advance_phase(
    assessment_id: str, cluster_id: str, body: PhaseIn, request: Request
) -> dict:
    tenant_id = _get_tenant(request)
    store = _load_t2(tenant_id, assessment_id, cluster_id)
    if not store:
        raise HTTPException(status_code=404, detail='tier2_session_not_found')
    store['current_phase'] = body.phase
    if body.decision_log:
        store['decision_log'] = body.decision_log
    store['phase_advanced_at'] = int(time.time())
    _save_t2(tenant_id, assessment_id, cluster_id, store)
    return {'ok': True, 'current_phase': body.phase}


@router.post('/{assessment_id}/clusters/{cluster_id}/tier2/finalise')
async def finalise_investigation(
    assessment_id: str, cluster_id: str, body: FinaliseIn, request: Request
) -> dict:
    tenant_id = _get_tenant(request)
    store = _load_t2(tenant_id, assessment_id, cluster_id)
    if not store:
        raise HTTPException(status_code=404, detail='tier2_session_not_found')

    store['status'] = 'closed'
    store['finalised_at'] = int(time.time())
    if body.decision_log:
        store['decision_log'] = body.decision_log

    amended = _build_amended_report(store)
    store['amended_report'] = amended
    _save_t2(tenant_id, assessment_id, cluster_id, store)

    try:
        assessment = _get_assessment(assessment_id)
        if assessment:
            assessment.setdefault('tier2_investigations', {})[cluster_id] = {
                'status': 'closed',
                'finalised_at': store['finalised_at'],
                'amended_report': amended,
            }
    except Exception as exc:
        logger.warning('tier2 finalise attach: %s', exc)

    return {'ok': True, 'status': 'closed', 'amended_report': amended}


@router.get('/{assessment_id}/clusters/{cluster_id}/tier2/log')
async def get_decision_log(assessment_id: str, cluster_id: str, request: Request) -> dict:
    tenant_id = _get_tenant(request)
    store = _load_t2(tenant_id, assessment_id, cluster_id)
    return {
        'assessment_id': assessment_id,
        'cluster_id': cluster_id,
        'decision_log': store.get('decision_log') or [],
        'current_phase': store.get('current_phase', 'contain'),
        'status': store.get('status', 'not_started'),
    }


# ── Amended report builder ────────────────────────────────────────────────────

def _build_amended_report(store: dict) -> dict:
    log = store.get('decision_log') or []
    by_phase: Dict[str, List[dict]] = {}
    for d in log:
        by_phase.setdefault(d.get('phase', 'unknown'), []).append(d)

    summary_lines = []
    for phase, decisions in by_phase.items():
        yes = sum(1 for d in decisions if d.get('decision') == 'yes')
        no  = sum(1 for d in decisions if d.get('decision') == 'no')
        esc = sum(1 for d in decisions if d.get('decision') == 'escalate')
        summary_lines.append(
            phase.title() + ': ' + str(yes) + ' confirmed, ' + str(no) + ' denied'
            + (', ' + str(esc) + ' escalated' if esc else '') + '.'
        )

    notes_text = ' '.join(d.get('notes', '') for d in log if d.get('notes'))[:800]
    summary = ' '.join(summary_lines) or 'Investigation complete.'
    cid = store.get('cluster_id', '')

    return {
        'summary': summary,
        'analyst_notes': notes_text,
        'ciso_brief': (
            'Tier 2 investigation complete for cluster ' + cid + '. '
            + summary
            + (' Analyst notes: ' + notes_text[:200] if notes_text else '')
        ),
        'compliance_note': (
            'Tier 2 investigation completed with full decision log. '
            'All phases (Contain → Investigate → Notify → Remediate → Report) completed '
            'with documented analyst decisions. Available for audit export.'
        ),
        'generated_at': int(time.time()),
    }


# ── LLM cluster summary (Tier 1 drawer widget) ────────────────────────────────

def _get_llm():
    """Lazy getter so we always use the current DEFAULT_CLIENT, not a stale import."""
    override = globals().get('_LLM')
    if override is not None:
        return override
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT  # type: ignore
        return DEFAULT_CLIENT
    except Exception:
        return None


def _generate_with_optional_model(client, *, prompt: str, max_tokens: int, tenant_id: Optional[str], overrides: dict, model: Optional[str] = None) -> dict:
    """Call LLM clients that may not support the newer model keyword."""
    try:
        return client.generate(
            prompt=prompt,
            max_tokens=max_tokens,
            tenant_id=tenant_id,
            overrides=overrides,
            model=model,
        )
    except TypeError as exc:
        if "unexpected keyword argument 'model'" not in str(exc):
            raise
        return client.generate(
            prompt=prompt,
            max_tokens=max_tokens,
            tenant_id=tenant_id,
            overrides=overrides,
        )


def _build_prior_context_block(cluster: dict, rows: List[dict], tenant_id: str = 'default') -> str:
    """Pull two live sources of prior context and format them for prompt injection.

    Source 1 — Decision Lifecycle Trace
        Shows what actions have ALREADY been taken on the entities in this cluster
        so the model doesn't repeat completed steps or re-disable already-disabled accounts.

    Source 2 — Temporal RAG
        Semantically similar events from the last 7 days give the model historical
        signal: did this entity appear in a prior incident? Were there precursor events?

    Both sources are queried defensively — any import or runtime failure silently
    returns an empty string so the prompt is never broken by unavailability.
    """
    import datetime

    pins        = _extract_evidence_pins(cluster, rows)
    accounts    = set(pins['accounts'][:5])
    hosts       = set(pins['hosts'][:5])
    ips         = set(pins['ips'][:5])
    all_entities: set[str] = accounts | hosts | ips

    # Row-level event IDs in this cluster — used for exact lifecycle lookup
    row_event_ids: set[str] = set()
    for r in rows:
        eid = r.get('event_id') or r.get('row_id') or r.get('id') or ''
        if eid:
            row_event_ids.add(str(eid))

    lines: list[str] = []

    # ── 1. Decision Lifecycle Trace ────────────────────────────────────────────
    try:
        from src.api.decision_lifecycle import DECISION_LIFECYCLE  # type: ignore
        recent = DECISION_LIFECYCLE.list_recent(limit=500)
        matched: list[dict] = []
        for rec in recent:
            # Exact match: this row's event_id is in the lifecycle store
            if rec.get('event_id', '') in row_event_ids:
                matched.append(rec)
                continue
            # Entity text match: entity name appears in reason or metadata
            meta   = rec.get('metadata') or {}
            reason = rec.get('reason', '') or ''
            meta_entities: set[str] = set(
                (meta.get('accounts') or []) +
                (meta.get('hosts') or []) +
                (meta.get('ips') or [])
            )
            if any(e and (e in meta_entities or e in reason) for e in all_entities):
                matched.append(rec)

        if matched:
            lines.append('PRIOR DECISIONS — already actioned on these entities (DO NOT repeat):')
            for rec in matched[:8]:
                ts_val = rec.get('timestamp', 0)
                ts_str = datetime.datetime.utcfromtimestamp(ts_val).strftime('%Y-%m-%dT%H:%MZ') if ts_val else '?'
                state  = (rec.get('state') or '?').upper()
                actor  = rec.get('actor') or 'system'
                reason = (rec.get('reason') or '')[:140].replace('\n', ' ')
                event  = rec.get('event_id', '?')[:40]
                disp   = rec.get('disposition', '')
                disp_str = f'  disposition={disp}' if disp else ''
                lines.append(f'  {ts_str}  [{state}]  event={event}  by={actor}{disp_str}')
                if reason:
                    lines.append(f'    reason: {reason}')
            lines.append('')
    except Exception:
        pass

    # ── 2. Temporal RAG — similar prior events ─────────────────────────────────
    try:
        from src.ai.temporal_rag import get_engine  # type: ignore
        query_parts = list(all_entities)[:6]
        if cluster.get('top_mitre'):
            query_parts += (cluster['top_mitre'] or [])[:3]
        query_text = ' '.join(query_parts)
        ctx = get_engine().build_context_block(
            query_text,
            tenant=tenant_id,
            top_k=5,
            window_seconds=604800,   # 7-day lookback
        )
        if ctx.get('rag_available') and ctx.get('neighbours'):
            lines.append('TEMPORAL RAG — similar events in the prior 7 days (corroborating signal):')
            lines.append(f'  {ctx["summary_hint"]}')
            for n in (ctx.get('neighbours') or [])[:5]:
                ent  = n.get('entity') or n.get('user') or n.get('ip') or '?'
                sev  = n.get('severity') or '?'
                desc = (n.get('description') or '')[:110]
                ts   = (str(n.get('ts') or n.get('timestamp') or '?'))[:19]
                src  = n.get('source') or '?'
                lines.append(f'  [{ts}] {ent} ({sev}) — {desc}  [src:{src}]')
            lines.append('')
    except Exception:
        pass

    return '\n'.join(lines) if lines else ''


def _build_evidence_rows_block(rows: List[dict], max_rows: int = 8) -> str:
    """Build a structured evidence table for the LLM prompt.

    Passes source, timestamp, entity names, MITRE technique, and the analyst_notes
    field (which contains the richest detail) for each top row.
    """
    sorted_rows = sorted(rows, key=lambda r: float(r.get('triage_score') or 0), reverse=True)
    lines: list[str] = []
    for i, r in enumerate(sorted_rows[:max_rows]):
        ts     = (r.get('date_utc') or r.get('timestamp') or r.get('event_time') or 'unknown time')[:19]
        source = r.get('_source') or r.get('source') or r.get('_sheet') or 'unknown'
        acct   = r.get('username') or r.get('account') or r.get('user') or ''
        host   = r.get('hostname') or r.get('host') or r.get('asset') or ''
        src_ip = r.get('src_ip') or r.get('internal_ip') or r.get('source_ip') or ''
        tech   = r.get('mitre_technique') or ''
        tactic = r.get('mitre_tactic') or ''
        note   = (r.get('analyst_notes') or r.get('description') or '').replace('\n', ' ').strip()[:220]

        entity_parts: list[str] = []
        if acct:   entity_parts.append(f'user={acct}')
        if host:   entity_parts.append(f'host={host}')
        if src_ip: entity_parts.append(f'ip={src_ip}')
        entity_str = ', '.join(entity_parts) or 'no entity'

        tech_str   = f' | {tech}' if tech else ''
        tactic_str = f' ({tactic})' if tactic else ''
        note_str   = f'\n     → {note}' if note else ''

        lines.append(f'  [{i+1}] {ts} | {source} | {entity_str}{tech_str}{tactic_str}{note_str}')

    return '\n'.join(lines) if lines else '  (no evidence rows available)'


def _build_mitre_attribution_block(cluster: dict, rows: List[dict]) -> str:
    """Map each MITRE technique to the specific evidence rows that triggered it.

    This is the core of non-theatrical threat modeling: every T-code must be
    grounded in real log data, not inferred from the cluster label alone.
    """
    # Build row-level technique map: technique → [(row_num, source, note)]
    tech_to_rows: dict[str, list[str]] = {}
    for r in rows:
        tech = r.get('mitre_technique') or r.get('technique_id') or ''
        if not tech:
            continue
        techs = [tech] if isinstance(tech, str) else list(tech)
        row_num = r.get('row_number') or r.get('row_index') or '?'
        source  = r.get('_source') or r.get('source') or r.get('_sheet') or 'unknown'
        ts      = (r.get('date_utc') or r.get('timestamp') or '')[:16]
        note    = (r.get('analyst_notes') or r.get('description') or '')[:80].replace('\n', ' ')
        for t in techs:
            t = str(t).strip()
            if t:
                tech_to_rows.setdefault(t, []).append(
                    f'row[{row_num}] {ts} {source}' + (f' — {note}' if note else '')
                )

    # Also pull from cluster-level top_mitre that may not be in individual rows
    cluster_mitre = cluster.get('top_mitre') or []
    for t in cluster_mitre:
        tech_to_rows.setdefault(str(t).strip(), [])

    if not tech_to_rows:
        return ''

    lines = ['MITRE ATTRIBUTION — evidence basis for each technique (cite these in your analysis):']
    for tech, evidence_list in sorted(tech_to_rows.items()):
        if evidence_list:
            lines.append(f'  {tech}: triggered by {len(evidence_list)} row(s)')
            for ev in evidence_list[:3]:
                lines.append(f'    • {ev}')
        else:
            lines.append(f'  {tech}: inferred from cluster pattern (no direct row match — treat as lower confidence)')
    lines.append('')
    return '\n'.join(lines)


def _build_dread_evidence_block(cluster: dict) -> str:
    """One-line DREAD summary: composite score + top damage drivers only.

    Keeps the token cost low while still giving the model the key signal:
    what drives the damage score (the dimension most relevant to triage priority).
    """
    try:
        from src.core.scoring.dread_engine import compute_dread  # type: ignore
        factors  = cluster.get('factors') or []
        artifact = {
            'factors':           factors,
            'destination_ports': cluster.get('destination_ports') or [],
            'business_tier':     cluster.get('business_tier') or '',
            'destination_ips':   (cluster.get('external_ips') or [])[:5],
        }
        result    = compute_dread(artifact, factors=[])
        composite = result.get('composite', 0.0)
        evidence  = result.get('evidence') or {}
        dmg_evs   = ', '.join((evidence.get('damage') or [])[:3]) or 'no specific factors'
        return f'DREAD score: {composite:.1f}/10 — damage driven by: {dmg_evs}\n'
    except Exception:
        dread_data = (cluster.get('threat_models') or {}).get('dread') or {}
        if dread_data:
            comp = dread_data.get('composite') or dread_data.get('risk_score') or '?'
            return f'DREAD score: {comp}/10\n'
        return ''


def _build_threat_model_block(threat_models: dict, fp_flag: bool, fp_guid: str) -> str:
    """Compact threat model context — only emit populated fields, 1 line each.

    Skips entirely when fields are empty/template-only so the prompt doesn't
    waste tokens on structural placeholders with no real content.
    """
    lines: list[str] = []

    # PASTA — only attack scenarios + business impact if present
    pasta = threat_models.get('pasta') or {}
    scenarios  = pasta.get('attack_scenarios') or []
    biz_impact = pasta.get('business_impact') or pasta.get('impact') or ''
    if scenarios:
        lines.append(f'PASTA: {"; ".join(str(s)[:100] for s in scenarios[:2])}')
    if biz_impact:
        lines.append(f'PASTA business impact: {str(biz_impact)[:150]}')

    # Diamond — only populated quadrants, inline
    diamond = threat_models.get('diamond') or {}
    diamond_parts: list[str] = []
    for key, label in [('adversary','adv'),('infrastructure','infra'),('capability','cap'),('victim','victim')]:
        val = diamond.get(key) or diamond.get(key + 's') or ''
        if val and str(val).lower() not in ('unknown', 'none', ''):
            val_str = ', '.join(val) if isinstance(val, list) else str(val)
            diamond_parts.append(f'{label}={val_str[:80]}')
    if diamond_parts:
        lines.append(f'DIAMOND: {" | ".join(diamond_parts)}')

    # MAESTRO — phases + maturity in one line
    maestro = threat_models.get('maestro') or {}
    mphases  = maestro.get('phases') or maestro.get('campaign_stages') or []
    maturity = maestro.get('maturity_level')
    if mphases:
        mat_str = f' (maturity {maturity}/5)' if maturity else ''
        lines.append(f'MAESTRO phases: {", ".join(str(p) for p in mphases[:6])}{mat_str}')

    # FP guidance
    if fp_flag and fp_guid:
        lines.append(f'FP GUIDANCE: {fp_guid[:150]}')

    return '\n'.join(lines) + '\n' if lines else ''


def _build_cluster_summary_prompt(
    cluster: dict,
    rows: List[dict],
    persona: str = 'soc_analyst',
    tenant_id: str = 'default',
) -> str:
    """Build an entity-anchored, CoT-primed Tier-1 investigation prompt.

    Forces the model to reference each specific account/host/IP and produce
    concrete HOW-TO steps with substeps, blast radius, and evidence-gap analysis.

    Augmented with two live sources to prevent stale output:
      - Decision lifecycle trace  (already-completed actions on these entities)
      - Temporal RAG              (semantically similar events from the last 7 days)
    """
    from datetime import date, timedelta
    today_iso          = date.today().isoformat()                       # e.g. 2026-04-15
    two_weeks_ago_iso  = (date.today() - timedelta(days=14)).isoformat()  # e.g. 2026-04-01

    pins = _extract_evidence_pins(cluster, rows)
    sev     = (cluster.get('severity') or 'unknown').upper()
    cid     = cluster.get('cluster_id', '?')
    phases  = ', '.join(cluster.get('phase_sequence') or []) or 'none'
    ac      = cluster.get('attack_chain') or {}
    chain   = ac.get('chain_text') or 'not available'
    blast   = cluster.get('blast_radius_summary') or 'unknown'
    conf    = cluster.get('confidence', 0.0)
    fp_flag = cluster.get('fp_flag', False)
    fp_guid = cluster.get('fp_guidance', '')
    gaps    = (cluster.get('telemetry_gaps') or {}).get('missing_logs') or []
    threat_models = cluster.get('threat_models') or {}

    accounts  = pins['accounts'][:5]
    hosts     = pins['hosts'][:5]
    ext_ips   = pins['ips'][:5]
    timestamps_str = (pins['timestamps'][0] if pins['timestamps'] else 'unknown') + \
                     (' -> ' + pins['timestamps'][-1] if len(pins['timestamps']) > 1 else '')

    # Rich evidence block — structured rows with timestamps, sources, notes
    evidence_rows_block = _build_evidence_rows_block(rows, max_rows=8)

    # Prior context: decision lifecycle trace + temporal RAG (anti-staleness)
    prior_context_block = _build_prior_context_block(cluster, rows, tenant_id=tenant_id)

    # ── MITRE attribution block: technique → which evidence rows triggered it ──
    mitre_attribution = _build_mitre_attribution_block(cluster, rows)

    # ── Full DREAD evidence block (per-dimension rationale, not just score) ────
    dread_block = _build_dread_evidence_block(cluster)

    # ── Full threat model context (PASTA stages, Diamond quadrants, MAESTRO) ───
    threat_model_block = _build_threat_model_block(threat_models, fp_flag, fp_guid)

    # Per-persona instruction shaping what the analyst cares about
    persona_focus = {
        'soc_analyst':   'containment steps with exact commands, who to call, ticket priority, escalation triggers',
        'threat_hunter': 'pivot paths, IoC expansion, hunting queries, lateral movement validation',
        'forensics':     'artefact collection order, evidence preservation, forensic tools per host',
        'ciso':          'business impact, regulatory exposure, exec communications, incident classification',
        'compliance':    'which controls failed, breach notification window, frameworks implicated',
        'executive':     'business risk in plain language, response status, financial/reputational exposure',
        'mssp':          'SLA impact, customer notification, runbook references, escalation path',
        'audit':         'evidence trail completeness, logging gaps, policy violations, audit log steps',
    }.get(persona, 'actionable next steps grounded in the specific evidence')

    # Entity-type command guide so the model uses the RIGHT action per entity type
    entity_command_guide = """ENTITY-TYPE COMMAND REFERENCE (use the appropriate block per entity type):

[ACCOUNT — Azure/Entra ID]
  Disable:  az ad user update --id <upn_or_object_id> --account-enabled false
  Sessions: az ad user revoke-sign-in-sessions --id <upn_or_object_id>
  Audit:    az ad audit-logs list --filter "initiatedBy/user/userPrincipalName eq '<upn>'" --top 20
  Date range for audit queries: {two_weeks_ago} to {today}

[ACCOUNT — Active Directory on-prem]
  Disable:  Disable-ADAccount -Identity <samAccountName>
  Sessions: Invoke-Command -ComputerName <DC> -ScriptBlock {{ Get-PSSession | Where-Object {{$_.UserName -like '*<samAccountName>*'}} | Remove-PSSession }}
  Audit:    Get-ADUser <samAccountName> -Properties * | Select LastLogonDate, LockedOut, Enabled

[ACCOUNT — Linux local]
  Disable:  usermod -L <username>   (locks password — does NOT kill active SSH sessions)
  Kill SSH: pkill -u <username> sshd
  Audit:    last <username> | head -20

[HOST — Cloud VM (Azure)]
  Isolate (NSG deny-all): az network nsg rule create --nsg-name <nsg> -g <rg> -n ISOLATE --priority 100 --access Deny --direction Inbound --protocol '*' --source-address-prefixes '*' --destination-port-ranges '*'
  Snapshot: az snapshot create --name <hostname>-forensic-{today} --source <disk_id> -g <rg>
  Audit:    az monitor activity-log list --resource-id <vm_id> --start-time {two_weeks_ago}
  SSH key rotation: az vm user update --name <hostname> -g <rg> --username <user> --ssh-key-value "$(cat ~/.ssh/id_rsa.pub)"

[HOST — Linux on-prem / bare metal]
  Firewall isolate: iptables -I INPUT 1 -j DROP && iptables -I OUTPUT 1 -j DROP  (run AFTER taking memory dump)
  Memory dump: avml /mnt/usb/memory.lime
  Auth log: cp /var/log/auth.log /mnt/evidence/ && sha256sum /var/log/auth.log
  Disable SSH: systemctl stop sshd && systemctl disable sshd

[EXTERNAL IP]
  Block (Linux iptables): iptables -A INPUT -s <ip> -j DROP && iptables -A OUTPUT -d <ip> -j DROP && iptables-save > /etc/iptables/rules.v4
  Block (Azure NSG):      az network nsg rule create --nsg-name <nsg> -g <rg> -n BLOCK-<ip_safe> --priority 110 --access Deny --direction Inbound --source-address-prefixes <ip> --destination-port-ranges '*'
  Verify:                 iptables -L -n | grep <ip>  OR  az network nsg rule show --nsg-name <nsg> -g <rg> -n BLOCK-<ip_safe>
  Threat intel:           curl -s https://ipinfo.io/<ip>/json | jq '.org,.country,.hostname'
  Active connections:     ss -antp | grep <ip>

CRITICAL RULES — violations produce incorrect, dangerous output:
1. NEVER include `az login` or any authentication command as a containment step.
   Containment = DISABLING access. Authenticating as the suspect account is evidence contamination.
   Wrong: az login -u suspect@domain.com
   Correct: az ad user update --id suspect@domain.com --account-enabled false
2. Use ONLY the account/host/IP names listed in the ACCOUNTS / HOSTS / EXTERNAL IPs fields.
3. ALL date ranges in audit queries MUST use these values: from={two_weeks_ago} to={today}
   Never invent or hardcode dates.""".format(today=today_iso, two_weeks_ago=two_weeks_ago_iso)

    # ── Cluster header (shared across all personas) ──────────────────────────
    cluster_header = f"""CLUSTER {cid} | {sev} | {conf:.0%} confidence
Kill-chain phases: {phases}
Attack chain: {chain}
Blast radius summary: {blast}
Time range: {timestamps_str}

ACCOUNTS: {', '.join(accounts) if accounts else 'none'}
HOSTS: {', '.join(hosts) if hosts else 'none'}
EXTERNAL IPs: {', '.join(ext_ips) if ext_ips else 'none'}
{'Known log gaps: ' + ', '.join(gaps[:4]) if gaps else ''}

{prior_context_block}{mitre_attribution}{dread_block}{threat_model_block}EVIDENCE ROWS (most significant first — source | entities | technique | analyst note):
{evidence_rows_block}"""

    common_rules = """THREE RULES — violating any of these produces output that will be rejected:
1. CITATION RULE: Every factual claim must cite a row number (e.g. "row[3]"). If you cannot cite a row, write "no direct evidence".
2. ENTITY RULE: Only name accounts, hosts, and IPs that appear verbatim in the ACCOUNTS / HOSTS / EXTERNAL IPs lists above.
3. VERDICT RULE: Use INSUFFICIENT EVIDENCE when fewer than 2 rows clearly show attack behaviour. Reserve LIKELY REAL only when 2+ independent rows corroborate the same entity."""

    # ── Technical personas: SOC, MSSP — full CLI containment template ────────
    if persona in ('soc_analyst', 'mssp'):
        sections = f"""Write exactly these 5 numbered sections. Do NOT use markdown headers. Inside section 3 use lettered substeps a/b/c/d.

1. WHAT IS HAPPENING
2-3 sentences. Every claim must cite a row number.
- Cite the specific account, IP, and timestamp (e.g. "at 03:14 UTC, azureuser authenticated from 45.153.160.200 — row[3]")
- Name the MITRE technique AND the row that triggered it (from the MITRE ATTRIBUTION block above)
- If a technique is marked "inferred / lower confidence" in the attribution block, say so

2. WHY IT MATTERS
2 sentences max.
- Name the specific asset at risk and worst-case outcome
- Reference the DREAD score and its damage drivers

3. IMMEDIATE ACTIONS
One numbered item per entity (accounts first, then hosts, then external IPs).
Only include entities supported by at least one cited evidence row — skip entities with no row citations.
Choose commands from the ENTITY-TYPE COMMAND REFERENCE below — match entity type exactly.
Each item must have lettered substeps:
  a. Exact CLI command (use the real entity name, real date range)
  b. How to verify the action took effect (one command)
  c. Who to notify and on what channel/ticket, referencing the evidence row and timestamp
  d. Blast-radius check: one command to find other accounts or hosts sharing this access path

Example (ACCOUNT — Azure):
1. [ACCOUNT azureuser] Disable and revoke sessions: [evidence: T1110.003 row[3] — 47 failed then success]
   a. az ad user update --id azureuser@contoso.com --account-enabled false && az ad user revoke-sign-in-sessions --id azureuser@contoso.com
   b. Verify: az ad user show --id azureuser@contoso.com --query accountEnabled
   c. Notify SOC lead in #incidents-soc, open P1 ticket, reference row [3] ({today_iso})
   d. Blast check: az ad user get-member-objects --id azureuser@contoso.com to find shared privileged groups

4. BLAST RADIUS & INVESTIGATE NEXT
Part A — BLAST RADIUS: 2-3 accounts, hosts, or subnets not yet confirmed. For each, cite the row that implies lateral reach.
Part B — EVIDENCE GAPS: 2-3 missing log sources that would confirm or rule out the attack. For each: name the source, write the exact query using date range {two_weeks_ago_iso} to {today_iso}, state whether finding it raises or lowers confidence.

5. VERDICT
Choose exactly one: LIKELY REAL / LIKELY BENIGN / UNCERTAIN
Rule: UNCERTAIN only if you genuinely cannot tell attacker from admin.
One sentence: cite the strongest evidence item AND the strongest counter-argument.
"""
        return f"""You are a senior SOC analyst.
Focus on: {persona_focus}.
Today's date: {today_iso}. Use this for all date ranges.

A correlation engine flagged this cluster. Use ONLY the real entity names below.

{cluster_header}

{entity_command_guide}

{common_rules}

{sections}"""

    # ── Threat Hunter — pivot paths, IoC expansion, hunting queries ──────────
    elif persona == 'threat_hunter':
        return f"""You are a senior threat hunter.
Focus on: {persona_focus}.
Today's date: {today_iso}.

A correlation engine flagged this cluster. Use ONLY the real entity names below.

{cluster_header}

{common_rules}

Write exactly these 5 numbered sections. Do NOT use markdown headers.

1. WHAT IS HAPPENING
2-3 sentences grounded in evidence rows. Name the kill-chain phase, technique, and entity involved in each sentence.

2. PIVOT OPPORTUNITIES
For each account, host, and external IP: list 2 concrete pivot queries to expand the hunt.
Format: [ENTITY name] → <query or log source> → what you expect to find if this is attacker activity.
Use date range {two_weeks_ago_iso} to {today_iso}.

3. IOC EXPANSION & HUNTING QUERIES
- List 3-5 derived IoCs (new IPs, hashes, domains, or usernames implied by the evidence rows).
- For each IoC write one hunting query (KQL, Splunk SPL, or grep depending on source).
- Tag each IoC as HIGH / MEDIUM confidence based on row evidence.

4. LATERAL MOVEMENT VALIDATION
Which entities have NOT been confirmed compromised but share an access path with confirmed entities (cite the row)?
For each: write the query to confirm or deny lateral reach using date range {two_weeks_ago_iso} to {today_iso}.

5. VERDICT
Choose exactly one: LIKELY REAL / LIKELY BENIGN / UNCERTAIN
Justify with: strongest corroborating evidence, strongest benign explanation, and what single data point would shift you from UNCERTAIN to LIKELY REAL.
"""

    # ── Forensics — evidence preservation, artifact collection order ─────────
    elif persona == 'forensics':
        return f"""You are a senior digital forensics investigator.
Focus on: {persona_focus}.
Today's date: {today_iso}.

A correlation engine flagged this cluster. Use ONLY the real entity names below.

{cluster_header}

{common_rules}

Write exactly these 5 numbered sections. Do NOT use markdown headers.

1. WHAT IS HAPPENING
2-3 sentences. Identify which hosts and accounts are involved, citing evidence rows.

2. EVIDENCE PRESERVATION ORDER
Order of volatility — most volatile first. For each entity type:
- Memory: exact command to acquire (avml / winpmem / LiME)
- Running processes / network connections: exact command
- Log files to copy: path + sha256sum command
- Disk image: tool and command (only after volatile evidence collected)
Use entity names from the ACCOUNTS / HOSTS lists above.

3. FORENSIC ARTIFACT TARGETS
For each host: list 3-5 specific artifacts to collect (registry hives, prefetch, SRUM, event logs, browser history, scheduled tasks).
For each account: list authentication artifacts (Security.evtx, Azure sign-in logs, SSH authorized_keys).
Tag each artifact as CRITICAL / SUPPORTING.

4. CHAIN OF CUSTODY NOTES
- Which evidence rows are already preserved in the log source vs. at risk of overwrite?
- What is the retention window for each source? Cite row numbers for at-risk items.
- Write the hash verification command for each collected artifact.

5. VERDICT
Choose exactly one: LIKELY REAL / LIKELY BENIGN / UNCERTAIN
State which evidence items, if acquired now, would confirm or rule out malicious activity within 2 hours.
"""

    # ── CISO / Executive — business impact, no CLI commands ──────────────────
    elif persona in ('ciso', 'executive'):
        exec_focus = (
            'executive communications, board-level risk framing, response status'
            if persona == 'executive'
            else 'business impact, regulatory exposure, incident classification, exec communications'
        )
        return f"""You are a {persona.replace('_', ' ')} preparing a security briefing.
Focus on: {exec_focus}.
Today's date: {today_iso}.
DO NOT write CLI commands or technical queries. Write in plain business language.

A correlation engine flagged a security incident cluster. Key facts:

{cluster_header}

{common_rules}

Write exactly these 5 numbered sections. Do NOT use markdown headers. No CLI commands.

1. WHAT IS HAPPENING (Plain Language)
2-3 sentences a non-technical executive can understand.
- What was accessed or attempted? By whom or from where (cite row numbers)?
- What is the business function at risk?

2. BUSINESS IMPACT
- Worst-case outcome if this is confirmed malicious (data exposure, service disruption, financial loss).
- Current containment status: what has been done, what is still at risk.
- Cite the DREAD score context: which damage/reach dimension is highest?

3. DECISIONS REQUIRED NOW
List 2-3 decisions that need executive or CISO sign-off within the next 4 hours.
Format: [DECISION] <what> — <why it can't wait> — <who owns it>

4. REGULATORY & REPUTATIONAL EXPOSURE
- Which data types or regulated assets are potentially affected (cite evidence rows)?
- Applicable frameworks or breach notification windows (GDPR 72h, HIPAA 60d, etc.) if relevant.
- Reputational risk: public-facing systems involved? Customer data at risk?

5. RESPONSE STATUS & VERDICT
Choose exactly one: LIKELY REAL / LIKELY BENIGN / UNCERTAIN
One executive-level sentence: what happened, confidence level, and current response action.
"""

    # ── Compliance / Audit ────────────────────────────────────────────────────
    elif persona in ('compliance', 'audit'):
        return f"""You are a {persona} officer reviewing a security incident for control failures and evidence trail.
Focus on: {persona_focus}.
Today's date: {today_iso}.

A correlation engine flagged this cluster. Use ONLY the real entity names below.

{cluster_header}

{common_rules}

Write exactly these 5 numbered sections. Do NOT use markdown headers.

1. WHAT IS HAPPENING
2-3 sentences. Identify which accounts, systems, and data types are involved, citing evidence rows.

2. CONTROL FAILURES
For each evidence row, identify which preventive or detective control should have caught this:
Format: row[N] — <expected control> — <why it failed or was absent>
Rate each failure: DESIGN GAP / IMPLEMENTATION GAP / MONITORING GAP.

3. BREACH NOTIFICATION ASSESSMENT
- Data types potentially exposed (PII, PHI, financial, IP — cite evidence rows).
- Applicable notification windows: GDPR (72h from discovery), HIPAA (60d), state laws, contractual SLAs.
- Clock start: when was this first detectable? (cite earliest evidence row timestamp)
- Decision: notification required NOW / requires further investigation / not applicable.

4. AUDIT TRAIL COMPLETENESS
- Which evidence rows have sufficient logging for evidentiary purposes?
- Which log sources are missing or have gaps (from telemetry_gaps block)?
- Logging policy violations: any entities that should have been logged but weren't?

5. VERDICT & REGULATORY RISK RATING
Choose exactly one: LIKELY REAL / LIKELY BENIGN / UNCERTAIN
Rate regulatory risk: CRITICAL / HIGH / MEDIUM / LOW.
One sentence on the single most important control remediation to prevent recurrence.
"""

    # ── Default fallback (analyst / any unknown persona) ─────────────────────
    else:
        return f"""You are a senior security analyst ({persona.replace('_', ' ')}).
Focus on: {persona_focus}.
Today's date: {today_iso}. Use this for all date ranges.

A correlation engine flagged this cluster. Use ONLY the real entity names below.

{cluster_header}

{entity_command_guide}

{common_rules}

Write exactly these 5 numbered sections. Do NOT use markdown headers.

1. WHAT IS HAPPENING
2-3 sentences. Every claim must cite a row number.

2. WHY IT MATTERS
2 sentences max. Name the specific asset at risk and worst-case outcome.

3. IMMEDIATE ACTIONS
One numbered item per entity with exact steps and verification commands.

4. BLAST RADIUS & INVESTIGATE NEXT
Part A — 2-3 unconfirmed accounts/hosts that may be affected (cite rows).
Part B — 2-3 missing log sources with exact queries using date range {two_weeks_ago_iso} to {today_iso}.

5. VERDICT
Choose exactly one: LIKELY REAL / LIKELY BENIGN / UNCERTAIN
One sentence citing strongest evidence and strongest counter-argument.
"""


_PERSONA_META: dict[str, dict[str, str]] = {
    'soc_analyst': {
        'label': 'SOC briefing',
        'focus': 'containment, validation, escalation, and blast-radius checks',
    },
    'threat_hunter': {
        'label': 'Threat Hunter briefing',
        'focus': 'pivot paths, IoC expansion, hunt queries, and alternate hypotheses',
    },
    'forensics': {
        'label': 'Forensics briefing',
        'focus': 'evidence preservation, artifact collection, and chain of custody',
    },
    'ciso': {
        'label': 'CISO briefing',
        'focus': 'business impact, incident classification, and executive decisions',
    },
    'executive': {
        'label': 'Executive briefing',
        'focus': 'plain-language impact, response status, and business decisions',
    },
    'compliance': {
        'label': 'Compliance briefing',
        'focus': 'control gaps, notification windows, and evidence retention',
    },
    'audit': {
        'label': 'Audit briefing',
        'focus': 'audit trail completeness, policy evidence, and remediation records',
    },
    'mssp': {
        'label': 'MSSP briefing',
        'focus': 'SLA handling, customer handoff, and escalation package quality',
    },
}


def _persona_meta(persona: str | None) -> dict[str, str]:
    key = str(persona or 'soc_analyst').strip().lower() or 'soc_analyst'
    return _PERSONA_META.get(key, {
        'label': key.replace('_', ' ').title() + ' briefing',
        'focus': 'role-specific next steps grounded in the selected evidence',
    })


def _row_ref(row: dict) -> int | str:
    for key in ('row_index', 'row_number', 'index'):
        if row.get(key) is not None:
            try:
                return int(row.get(key))
            except Exception:
                return str(row.get(key))
    return '?'


def _first_nonempty(row: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        val = row.get(key)
        if val not in (None, ''):
            return str(val)
        raw = row.get('raw') if isinstance(row.get('raw'), dict) else {}
        val = raw.get(key)
        if val not in (None, ''):
            return str(val)
    return ''


def _fallback_entities(cluster: dict, rows: list[dict]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {
        'accounts': [],
        'hosts': [],
        'ips': [],
        'domains': [],
    }

    def add(kind: str, vals: Any) -> None:
        if not isinstance(vals, list):
            vals = [vals]
        for val in vals:
            text = str(val or '').strip()
            if text and text not in out[kind]:
                out[kind].append(text)

    add('accounts', cluster.get('shared_accounts') or cluster.get('accounts') or cluster.get('users') or [])
    add('hosts', cluster.get('shared_hosts') or cluster.get('hosts') or [])
    add('ips', cluster.get('shared_external_ips') or cluster.get('external_ips') or cluster.get('ips') or [])
    add('domains', cluster.get('shared_domains') or cluster.get('domains') or [])

    for row in rows:
        add('accounts', _first_nonempty(row, ('user', 'username', 'account', 'principal', 'userPrincipalName')))
        add('hosts', _first_nonempty(row, ('host', 'hostname', 'device', 'device_name', 'computer')))
        add('ips', _first_nonempty(row, ('src_ip', 'source_ip', 'ip_src', 'dst_ip', 'destination_ip', 'ip_dst', 'external_ip', 'ip')))
        add('domains', _first_nonempty(row, ('domain', 'dns_query', 'qname', 'sni', 'url')))

    return {key: vals[:5] for key, vals in out.items()}


def _fallback_evidence_refs(rows: list[dict], limit: int = 4) -> list[int | str]:
    refs: list[int | str] = []
    for row in rows:
        ref = _row_ref(row)
        if ref != '?' and ref not in refs:
            refs.append(ref)
        if len(refs) >= limit:
            break
    return refs or ['?']


def _refs_text(refs: list[int | str]) -> str:
    return ', '.join('row[%s]' % ref for ref in refs)


_SEV_RANK = {'critical': 4, 'crit': 4, 'high': 3, 'medium': 2, 'med': 2, 'low': 1}


def _row_risk_score(row: dict) -> float:
    """Return a numeric risk score for sorting rows highest-risk-first."""
    for key in ('risk_score', 'triage_score', 'threat_confidence'):
        val = _first_nonempty(row, (key,))
        try:
            return float(val)
        except (ValueError, TypeError):
            pass
    sev = _first_nonempty(row, ('severity', 'risk_level', 'riskLevel')).lower()
    return float(_SEV_RANK.get(sev, 0))


def _step(title: str, owner: str, priority: str, subtasks: list[str], refs: list[int | str]) -> dict:
    return {
        'title': title,
        'owner': owner,
        'priority': priority,
        'subtasks': [{'label': item, 'evidence_refs': refs[:4]} for item in subtasks],
    }


def _render_persona_steps(steps: list[dict]) -> str:
    lines: list[str] = []
    for idx, step in enumerate(steps, 1):
        lines.append(f"{idx}. {step.get('title')} [{step.get('priority')}]")
        for letter, sub in zip('abcd', step.get('subtasks') or []):
            refs = _refs_text(sub.get('evidence_refs') or [])
            lines.append(f"   {letter}. {sub.get('label')} ({refs})")
    return '\n'.join(lines)


def _build_persona_fallback_summary(persona: str, cluster: dict, rows: list[dict]) -> tuple[dict, list[dict]]:
    """Build grounded, role-specific sections when model output is unparseable."""
    key = str(persona or 'soc_analyst').strip().lower() or 'soc_analyst'
    meta = _persona_meta(key)
    refs = _fallback_evidence_refs(rows)
    entities = _fallback_entities(cluster, rows)
    pivot = (
        (entities['accounts'] or entities['hosts'] or entities['ips'] or entities['domains'] or [cluster.get('cluster_id') or 'selected cluster'])[0]
    )
    severity = str(cluster.get('severity') or 'unknown').upper()
    confidence = cluster.get('confidence')
    try:
        confidence_text = f"{float(confidence) * 100:.0f}%"
    except Exception:
        confidence_text = 'unknown'
    reason = cluster.get('reason_summary') or cluster.get('business_significance') or 'shared evidence across uploaded sources'
    owner = meta['label'].replace(' briefing', '')

    if key in ('soc_analyst', 'mssp'):
        steps = [
            _step('Contain affected access paths', owner, 'P1', [
                f"Disable or restrict {pivot} while validating the correlated evidence.",
                'Verify containment through identity/session logs and firewall or EDR state.',
                'Notify SOC lead and open an incident ticket with the cited evidence rows.',
                'Check adjacent accounts, hosts, and IPs that share this cluster pivot.',
            ], refs),
            _step('Validate true-positive evidence', owner, 'P1', [
                'Confirm the suspicious sequence appears in at least two independent sources.',
                'Pull missing identity, endpoint, and network telemetry for the same time window.',
                'Document the strongest benign explanation before escalation.',
            ], refs),
        ]
        why = f"{severity} cluster at {confidence_text} confidence could represent active compromise if {pivot} is unauthorized."
        investigate = 'Collect identity sign-in logs, endpoint process/network events, and network flow evidence for the same entities and time range.'
    elif key == 'threat_hunter':
        steps = [
            _step('Expand pivots from the selected cluster', owner, 'High', [
                f"Hunt for other events involving {pivot} across identity, endpoint, and network telemetry.",
                'Generate KQL/SPL searches for shared accounts, hosts, IPs, domains, and ASNs.',
                'Look for lateral movement, token replay, or repeated infrastructure reuse.',
            ], refs),
            _step('Build alternate hypotheses', owner, 'High', [
                'Compare attacker hypothesis against admin activity, scanner noise, and known maintenance.',
                'Flag each new IoC as high or medium confidence based on row-level support.',
                'Push confirmed pivots back into HopGraph for additional path expansion.',
            ], refs),
        ]
        why = f"The cluster gives hunters concrete pivots around {pivot}, not just an isolated alert."
        investigate = 'Prioritize KQL/SPL pivoting, IoC expansion, lateral movement validation, and benign-hypothesis testing.'
    elif key == 'forensics':
        steps = [
            _step('Preserve volatile evidence first', owner, 'P1', [
                'Capture memory, running processes, active network connections, and authentication sessions before isolation.',
                'Hash copied logs and artifacts immediately after collection.',
                'Record collection timestamps and custodian for each evidence item.',
            ], refs),
            _step('Collect host and account artifacts', owner, 'High', [
                'Acquire endpoint logs, scheduled tasks, persistence locations, shell history, and EDR telemetry.',
                'Collect account sign-in/audit logs and privilege-change records.',
                'Map collected artifacts back to the cited cluster rows.',
            ], refs),
        ]
        why = f"{severity} evidence around {pivot} may be overwritten unless volatile artifacts are preserved quickly."
        investigate = 'Start with volatile artifacts, then disk/log acquisition, then chain-of-custody documentation.'
    elif key in ('ciso', 'executive'):
        steps = [
            _step('Classify incident and business risk', owner, 'Executive', [
                f"Decide whether this {severity} cluster should be treated as an active incident.",
                'Assign a business owner for the affected identity, host, service, or data path.',
                'Approve containment if customer, regulated, or production systems may be affected.',
            ], refs),
            _step('Prepare communication and escalation', owner, 'Executive', [
                'Brief executives on impact, confidence, current containment, and unresolved evidence gaps.',
                'Decide whether legal, privacy, customer success, or external IR support must be notified.',
                'Set a four-hour checkpoint for updated blast radius and containment status.',
            ], refs),
        ]
        why = f"This is a decision point: {reason}. The business risk is unresolved until ownership, containment, and notification posture are confirmed."
        investigate = 'Request a concise status update: impacted assets, data exposure risk, containment decision, and next executive checkpoint.'
    elif key in ('compliance', 'audit'):
        steps = [
            _step('Assess controls and notification clock', owner, 'High', [
                'Identify which preventive or detective controls should have produced earlier signal.',
                'Determine whether regulated data, customer data, or contractual SLAs are implicated.',
                'Establish first-detectable time from the cited evidence rows.',
            ], refs),
            _step('Preserve audit-ready evidence', owner, 'High', [
                'Record source system, timestamp, row references, analyst action, and decision rationale.',
                'List missing logs that prevent final compliance determination.',
                'Create remediation evidence requirements for control owners.',
            ], refs),
        ]
        why = f"The cluster may expose control or logging gaps around {pivot}; auditability depends on preserving row-level evidence."
        investigate = 'Map evidence to controls, notification obligations, retention gaps, and remediation proof.'
    else:
        steps = [
            _step('Triage selected cluster', owner, 'High', [
                f"Validate whether {pivot} is expected activity or unauthorized behavior.",
                'Collect missing telemetry and confirm the shared pivot across sources.',
                'Escalate if two independent evidence sources corroborate malicious behavior.',
            ], refs),
        ]
        why = f"{severity} cluster at {confidence_text} confidence requires role-specific validation."
        investigate = 'Confirm ownership, collect missing telemetry, and document the evidence that would change the verdict.'

    what_to_do = _render_persona_steps(steps)
    sections = {
        'what_is_happening': (
            f"Cluster {cluster.get('cluster_id') or '?'} groups evidence around {pivot}. "
            f"The current reason is {reason}; strongest cited evidence: {_refs_text(refs)}."
        ),
        'why_it_matters': why,
        'what_to_do': what_to_do,
        'investigate_next': investigate,
        'verdict_line': f"UNCERTAIN - strongest evidence is {_refs_text(refs)}; benign authorization still requires owner confirmation.",
        'is_this_real': f"UNCERTAIN - strongest evidence is {_refs_text(refs)}; benign authorization still requires owner confirmation.",
        'reality_verdict': 'UNCERTAIN',
        'entities': [],
        'persona_notes': {key: what_to_do},
        'persona_questions': {
            key: 'Who owns this activity, and what telemetry would confirm or deny malicious use within the next four hours?'
        },
    }
    return sections, steps


def _summary_sections_useful(sections: dict) -> bool:
    useful_keys = ('what_is_happening', 'why_it_matters', 'what_to_do', 'investigate_next', 'verdict_line')
    return any(str(sections.get(key) or '').strip() for key in useful_keys)


_ACTION_VERBS = re.compile(
    r'\b(block|isolate|alert|query|run|check|review|confirm|investigate|revoke|reset|'
    r'escalate|contain|hunt|pivot|correlate|verify|remediate|disable|monitor|collect)\b',
    re.IGNORECASE,
)
_ROW_REF_PAT = re.compile(r'\brow\[?\d+\]?|\bR\d{2,}|\b#\d{2,}|\[\d{2,}\]')
_ENTITY_PAT  = re.compile(
    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'       # IPv4
    r'|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'        # email
    r'|[a-zA-Z0-9-]{2,}\.[a-zA-Z]{2,6}\b'            # domain/host
    r'|[A-Z][A-Z0-9_-]{3,}',                          # uppercase identifier (hostname/account)
)


def _output_grounding_score(sections: dict) -> int:
    """Score LLM output on three axes; returns 0-3.

    1 point for ≥1 cited row ref (row[N], R12, #34, [56])
    1 point for ≥1 entity (IP, email, domain, host-like token)
    1 point for ≥1 concrete action verb
    Threshold of <2 triggers fallback for elevated clusters.
    """
    combined = ' '.join(str(sections.get(k) or '') for k in (
        'what_is_happening', 'why_it_matters', 'what_to_do', 'investigate_next', 'verdict_line'
    ))
    score = 0
    if _ROW_REF_PAT.search(combined):
        score += 1
    if _ENTITY_PAT.search(combined):
        score += 1
    if _ACTION_VERBS.search(combined):
        score += 1
    return score


def _build_compact_cluster_summary_prompt(cluster: dict, rows: list[dict], persona: str, tenant_id: str = 'default') -> str:
    """Short prompt for local models with strict token caps."""
    del tenant_id  # Reserved for future tenant-specific compact context.
    meta = _persona_meta(persona)
    top_rows = sorted(rows, key=_row_risk_score, reverse=True)[:8]
    refs = _fallback_evidence_refs(top_rows, limit=8)
    entities = _fallback_entities(cluster, top_rows)
    evidence_lines = []
    for row in top_rows:
        ref = _row_ref(row)
        desc = _first_nonempty(row, (
            'analyst_notes', 'description', 'event_description', 'message',
            'summary', 'activityDisplayName', 'event_type', 'operation',
        ))
        user = _first_nonempty(row, ('user', 'username', 'account', 'principal', 'userPrincipalName'))
        host = _first_nonempty(row, ('host', 'hostname', 'device', 'device_name', 'computer'))
        ip = _first_nonempty(row, ('src_ip', 'source_ip', 'dst_ip', 'destination_ip', 'external_ip', 'ip'))
        event_type = _first_nonempty(row, ('event_type', 'activityDisplayName', 'operation', 'action'))
        mitre = _first_nonempty(row, ('mitre_technique', 'technique_id', 'mitre'))
        severity = _first_nonempty(row, ('severity', 'risk_level', 'riskLevel'))
        risk = _first_nonempty(row, ('risk_score', 'triage_score', 'threat_confidence'))
        evidence_lines.append(
            f"row[{ref}]: sev={severity or '-'} risk={risk or '-'} event={event_type or '-'} "
            f"user={user or '-'} host={host or '-'} ip={ip or '-'} mitre={mitre or '-'} "
            f"detail={desc[:220] or '-'}"
        )
    entity_line = (
        f"accounts={', '.join(entities['accounts']) or 'none'}; "
        f"hosts={', '.join(entities['hosts']) or 'none'}; "
        f"ips={', '.join(entities['ips']) or 'none'}; "
        f"domains={', '.join(entities['domains']) or 'none'}"
    )
    return f"""You are generating a {meta['label']} for a security cluster.
Persona focus: {meta['focus']}.
Cluster: {cluster.get('cluster_id')} severity={cluster.get('severity')} confidence={cluster.get('confidence')}.
Why grouped: {cluster.get('reason_summary') or cluster.get('business_significance') or 'shared telemetry'}.
Entities: {entity_line}.
Evidence refs available: {_refs_text(refs)}.
Evidence:
{chr(10).join(evidence_lines)}

Return exactly five numbered sections:
1. WHAT IS HAPPENING
2. WHY IT MATTERS
3. IMMEDIATE ACTIONS
4. INVESTIGATE NEXT
5. VERDICT

Make section 3 role-specific for {persona}: SOC must include containment; threat_hunter must include hunt pivots/queries; CISO/executive must include business decisions; compliance/audit must include controls/evidence; forensics must include collection steps.
Every claim must cite row refs from the evidence list. If severity is high or critical, do not dismiss the cluster as "no direct evidence" when rows are listed; instead state the strongest cited evidence and the strongest uncertainty. Keep under 700 words."""



@router.get('/{assessment_id}/clusters/{cluster_id}/tier2/llm-summary')
async def get_llm_cluster_summary(
    assessment_id: str,
    cluster_id: str,
    request: Request,
    model: str = 'qwen2.5:14b',
    force_refresh: bool = False,
) -> dict:
    """Generate or return a cached LLM Tier-1 briefing for a cluster.

    Uses the model specified via ?model= (default: qwen2.5:14b).
    Supports extended thinking via the 'thinking' override when the model supports it.
    """
    tenant_id = _get_tenant(request)
    persona = request.headers.get('x-persona', 'soc_analyst')

    # Check disk cache first (keyed by cluster + model + persona so each role gets its own summary)
    cache_key = _safe(cluster_id) + '_llm_summary_' + _safe(model) + '_' + _safe(persona)
    cache_path = _BASE / _safe(tenant_id) / _safe(assessment_id) / (cache_key + '.json')
    if not force_refresh and cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text(encoding='utf-8'))
            return {**cached, 'from_cache': True}
        except Exception:
            pass

    assessment = _get_assessment(assessment_id)
    cluster: dict = {}
    rows: List[dict] = []
    if assessment:
        for c in (assessment.get('correlation_clusters') or []):
            if c.get('cluster_id') == cluster_id:
                cluster = c
                rr_set = set(c.get('row_refs') or [])
                rows = [r for r in (assessment.get('normalized_rows') or assessment.get('rows') or [])
                        if r.get('row_number') in rr_set or r.get('row_index') in rr_set]
                break

    if not cluster:
        raise HTTPException(
            status_code=404,
            detail=f'Cluster {cluster_id} not found in assessment {assessment_id}.',
        )

    _LLM = _get_llm()
    if _LLM is None:
        return {
            'cluster_id': cluster_id, 'assessment_id': assessment_id,
            'llm_available': False,
            'error': 'LLM client not available. Start Ollama and set OLLAMA_HOST in .env.',
            'from_cache': False,
        }

    prompt = _build_cluster_summary_prompt(
        cluster, rows,
        persona=persona,
        tenant_id=tenant_id,
    )

    # Route to the right provider based on the model name:
    #   claude-*        → Anthropic Messages API
    #   gpt-* / o[1-9]  → OpenAI Chat API
    #   anything else   → Ollama (local)
    _is_claude  = model.startswith('claude')
    _is_openai  = model.startswith('gpt') or (len(model) >= 2 and model[0] == 'o' and model[1].isdigit())

    missing_cloud_key = (
        (_is_claude and not os.getenv('ANTHROPIC_API_KEY'))
        or (_is_openai and not os.getenv('OPENAI_API_KEY'))
    )
    if missing_cloud_key:
        parsed, persona_steps = _build_persona_fallback_summary(persona, cluster, rows)
        result = {
            'cluster_id':    cluster_id,
            'assessment_id': assessment_id,
            'model':         model,
            'persona':       persona,
            'persona_label': _persona_meta(persona)['label'],
            'persona_focus': _persona_meta(persona)['focus'],
            'sections':      parsed,
            'persona_steps': persona_steps,
            'raw_text':      '',
            'generated_at':  time.time(),
            'from_cache':    False,
            'llm_available': True,
            'fallback_generated': True,
            'fallback_reason': 'cloud_model_unconfigured',
            'llm_skipped_reason': 'Requested cloud model is not configured; rendered grounded persona fallback.',
        }
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        except Exception:
            pass
        return result

    if _is_claude or _is_openai:
        # Frontier-model path: do NOT warm up Ollama
        overrides: dict = {
            'thinking': {'type': 'enabled', 'budget_tokens': 2048} if _is_claude else {},
        }
    else:
        # Warm-up Ollama before the main call
        try:
            _LLM.generate(prompt='hi', max_tokens=1, tenant_id=None,
                          overrides={'ollama_model': model})
        except Exception:
            pass
        overrides = {
            'ollama_model': model,
            # Turn-level thinking for Ollama models that support it (qwen3+)
            'thinking': {'type': 'enabled', 'budget_tokens': 2048},
        }

    try:
        _max_tokens = max(256, min(8192, int(os.getenv('CLUSTER_LLM_MAX_TOKENS', '3000'))))
    except Exception:
        _max_tokens = 3000

    try:
        prompt_for_model = prompt
        if not (_is_claude or _is_openai) and len(prompt_for_model.split()) > 900:
            prompt_for_model = _build_compact_cluster_summary_prompt(cluster, rows, persona, tenant_id=tenant_id)

        raw = _generate_with_optional_model(
            _LLM,
            prompt=prompt_for_model,
            max_tokens=_max_tokens,
            tenant_id=tenant_id,
            overrides=overrides,
            model=model,
        )
        text = raw.get('text') or ''
        parsed = _parse_llm_summary(text)
        persona_steps: list[dict] = []
        fallback_generated = False
        fallback_reason = None
        elevated_cluster = str(cluster.get('severity') or '').lower() in {'critical', 'crit', 'high'}
        sections_useful = _summary_sections_useful(parsed)
        if not sections_useful or (rows and elevated_cluster and _output_grounding_score(parsed) < 2):
            parsed, persona_steps = _build_persona_fallback_summary(persona, cluster, rows)
            fallback_generated = True
            fallback_reason = 'llm_output_unparseable' if not sections_useful else 'llm_output_under_grounded'
        else:
            persona_steps = []
        result = {
            'cluster_id':    cluster_id,
            'assessment_id': assessment_id,
            'model':         raw.get('meta', {}).get('model', model),
            'persona':       persona,
            'persona_label': _persona_meta(persona)['label'],
            'persona_focus': _persona_meta(persona)['focus'],
            'sections':      parsed,
            'persona_steps': persona_steps,
            'raw_text':      text,
            'generated_at':  time.time(),
            'from_cache':    False,
            'llm_available': True,
            'fallback_generated': fallback_generated,
            'fallback_reason': fallback_reason,
        }
        # Cache to disk
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        except Exception:
            pass
        return result
    except Exception as exc:
        logger.exception('LLM summary failed: %s', exc)
        err = str(exc)
        cold_start = any(k in err.lower() for k in ('connect', 'refused', 'timeout', 'ollama_session', 'ollama_override', 'remotedisconnected'))
        return {
            'cluster_id': cluster_id, 'assessment_id': assessment_id,
            'llm_available': False, 'error': err,
            'cold_start_hint': (
                'Ollama appears offline or still loading. Start Ollama, wait ~30s, then retry.'
                if cold_start else None
            ),
            'from_cache': False,
        }


def _parse_llm_summary(text: str) -> dict:
    """Parse numbered-section LLM response into structured fields.

    Handles the new format:
      1. WHAT IS HAPPENING
      2. WHY IT MATTERS
      3. IMMEDIATE ACTIONS
      4. INVESTIGATE NEXT
      5. VERDICT
    and falls back gracefully to the legacy 4-section format for cached responses.

    IMPORTANT: only transitions to a new section when the text after "N." matches
    the expected header keywords.  This prevents numbered sub-items inside section 3
    (e.g. "1. [ACCOUNT azureuser] Disable ...") from being misidentified as section 1.
    """
    import re

    sections: dict = {}

    # ── Section anchor keywords: only lines "N. <ANCHOR>..." trigger a transition ─
    SECTION_ANCHORS: dict[str, tuple[str, ...]] = {
        '1': ('WHAT IS HAPPENING', 'WHAT IS', 'SITUATION', 'SUMMARY'),
        '2': ('WHY IT MATTERS', 'BUSINESS RISK', 'WHY IT', 'IMPACT'),
        '3': ('IMMEDIATE ACTIONS', 'WHAT TO DO', 'REMEDIATION', 'ACTIONS', 'CONTAINMENT'),
        '4': ('BLAST RADIUS', 'INVESTIGATE NEXT', 'INVESTIGATE', 'NEXT STEPS', 'FOLLOW'),
        '5': ('VERDICT', 'IS THIS REAL', 'ASSESSMENT', 'CONCLUSION'),
        '6': ('PERSONA NOTES', 'PERSONA', 'ROLE-SPECIFIC', 'ROLE NOTES'),
    }
    numbered_map: dict[str, str] = {
        '1': 'what_is_happening',
        '2': 'why_it_matters',
        '3': 'what_to_do',
        '4': 'investigate_next',
        '5': 'verdict_line',
        '6': 'persona_notes_raw',
    }
    # Legacy keyword-only headers (no number prefix)
    keyword_map: dict[str, str] = {
        'WHAT IS HAPPENING':    'what_is_happening',
        'WHY IT MATTERS':       'why_it_matters',
        'WHAT TO DO RIGHT NOW': 'what_to_do',
        'IMMEDIATE ACTIONS':    'what_to_do',
        'INVESTIGATE NEXT':     'investigate_next',
        'IS THIS REAL?':        'verdict_line',
        'IS THIS REAL':         'verdict_line',
        'VERDICT':              'verdict_line',
    }

    current_key: str | None = None
    buf: list[str] = []

    def flush() -> None:
        if current_key and buf:
            sections[current_key] = '\n'.join(buf).strip()

    for line in text.splitlines():
        stripped = line.strip()
        # Strip markdown bold/italic/heading markers for header detection
        clean = re.sub(r'[*#]+', '', stripped).strip()
        upper = clean.upper()

        # ── Numbered section header: "N. ANCHOR TEXT ..."  ───────────────────
        # Only match digits 1-6 and only when the text after "N. " starts with
        # a known anchor keyword.  This stops sub-items ("1. [ACCOUNT ...]")
        # inside section 3 from being mis-classified as section-1 headers.
        num_match = re.match(r'^([1-6])\.\s+(.+)$', clean)
        if num_match:
            n, header_text = num_match.group(1), num_match.group(2).upper()
            anchors = SECTION_ANCHORS.get(n, ())
            if any(header_text.startswith(a) for a in anchors):
                flush()
                buf = []
                current_key = numbered_map[n]
                continue  # header line itself is not content

        # ── Keyword-only headers (legacy / no-number format) ─────────────────
        matched_kw: str | None = None
        for header, key in keyword_map.items():
            if upper.startswith(header):
                matched_kw = key
                break
        if matched_kw:
            flush()
            buf = []
            current_key = matched_kw
            rest = stripped[len(matched_kw.rstrip('?')):].lstrip(':').strip()
            if rest:
                buf.append(rest)
            continue

        if current_key:
            buf.append(line)

    flush()

    # ── Parse section 6 persona sub-sections ─────────────────────────────────
    # Model writes "SOC ANALYST: <bullets>" or "THREAT HUNTER: ..." etc.
    # Extract into a dict keyed by persona slug so the frontend can tab-switch.
    persona_notes: dict[str, str] = {}
    if 'persona_notes_raw' in sections:
        raw6 = sections.pop('persona_notes_raw')
        PERSONA_PREFIXES = [
            ('SOC ANALYST',   'soc_analyst'),
            ('SOC_ANALYST',   'soc_analyst'),
            ('THREAT HUNTER', 'threat_hunter'),
            ('THREAT_HUNTER', 'threat_hunter'),
            ('CISO',          'ciso'),
            ('FORENSICS',     'forensics'),
            ('FORENSIC',      'forensics'),
        ]
        current_pkey: str | None = None
        pbuf: list[str] = []

        def flush_persona() -> None:
            if current_pkey and pbuf:
                persona_notes[current_pkey] = '\n'.join(pbuf).strip()

        for pline in raw6.splitlines():
            pstrip = pline.strip()
            pupper = re.sub(r'\*+', '', pstrip).upper()
            matched_prefix: str | None = None
            remainder = ''
            for pfx, pslug in PERSONA_PREFIXES:
                if pupper.startswith(pfx + ':') or pupper.startswith(pfx + ' -'):
                    matched_prefix = pslug
                    remainder = pstrip[len(pfx):].lstrip(':- ').strip()
                    break
            if matched_prefix:
                flush_persona()
                pbuf = [remainder] if remainder else []
                current_pkey = matched_prefix
            elif current_pkey and pstrip:
                pbuf.append(pstrip)

        flush_persona()
    # Post-process: split OPEN_QUESTION out of each persona's text
    persona_questions: dict[str, str] = {}
    for pslug, ptext in persona_notes.items():
        lines = ptext.splitlines()
        q_lines = [l for l in lines if l.strip().upper().startswith('OPEN_QUESTION:')]
        body_lines = [l for l in lines if not l.strip().upper().startswith('OPEN_QUESTION:')]
        persona_notes[pslug] = '\n'.join(body_lines).strip()
        if q_lines:
            # Take the last OPEN_QUESTION line, strip the prefix
            q_text = re.sub(r'^OPEN_QUESTION:\s*', '', q_lines[-1].strip(), flags=re.IGNORECASE)
            persona_questions[pslug] = q_text
    sections['persona_notes'] = persona_notes
    sections['persona_questions'] = persona_questions

    # ── Derive reality_verdict from verdict_line ──────────────────────────────
    verdict_text = sections.get('verdict_line', '') or sections.get('is_this_real', '')
    reality = 'UNCERTAIN'
    for kw in ('LIKELY REAL', 'LIKELY BENIGN', 'UNCERTAIN'):
        if kw in verdict_text.upper():
            reality = kw
            break
    sections['reality_verdict'] = reality

    # Keep is_this_real alias for legacy renderer paths
    if 'verdict_line' in sections and 'is_this_real' not in sections:
        sections['is_this_real'] = sections['verdict_line']

    # Keep entities empty list so frontend renderer gracefully falls back to text sections
    sections.setdefault('entities', [])

    return sections


# ── Persona follow-up refine endpoint ────────────────────────────────────────

# ── MITRE playbook: deterministic sub-steps per technique ────────────────────
# Keyed by T-code. Each entry has:
#   steps  — ordered list of concrete sub-steps (shown instantly, no LLM)
#   unknowns — questions the playbook cannot answer without additional context
#   ioc_checks — what to cross-reference in evidence for this technique
_MITRE_PLAYBOOK: dict[str, dict] = {
    'T1078': {  # Valid Accounts
        'label': 'Valid Account Abuse',
        'steps': [
            'Check when {account} last authenticated vs. normal business hours — anomalous time = higher confidence',
            'Pull all role assignments for {account}: az role assignment list --assignee {account} (Azure) or Get-ADUser -Identity {account} | Get-ADGroupMember',
            'Check if {account} was recently added to a privileged group: search AD/AAD audit log for "Add member to role" events in past 14 days',
            'Revoke all active sessions: az ad user revoke-sign-in-sessions --id {account}',
            'Disable login: az ad user update --id {account} --account-enabled false',
            'Reset MFA: Remove all registered authenticator methods, require re-enroll on next access',
            'Check if {account} has service principal or app registration attached — those tokens survive account disable',
        ],
        'unknowns': [
            'What role/privilege level does {account} hold? (Owner/Contributor/standard user changes severity)',
            'Were elevated privileges added to {account} recently? (AD/AAD audit log — "Add member to role" past 14 days)',
            'Does {account} have a service principal or API key that also needs rotation?',
            'Is {account} a shared/service account or a human account? (changes revocation approach)',
        ],
        'ioc_checks': [
            'Off-hours authentication timestamp',
            'Source IP geolocation inconsistent with user home country',
            'Agent string / user-agent anomaly',
            'MFA bypass or legacy protocol use',
        ],
    },
    'T1021': {  # Remote Services (generic)
        'label': 'Remote Service Lateral Movement',
        'steps': [
            'Identify all hosts {account} accessed via SSH/RDP/WinRM in the cluster time window',
            'Check {host} for new authorized_keys entries: diff /home/{account}/.ssh/authorized_keys vs last-known-good backup',
            'Review process tree on {host} from session start: who initiated the connection, what was run after login',
            'Check for persistence: crontab -l -u {account}; ls /etc/cron.d; systemctl list-units --state=enabled',
            'Isolate {host} at switch/NSG level — preserve state before shutdown for memory forensics',
        ],
        'unknowns': [
            'What ran on {host} after {account} logged in? (need process execution log — Sysmon/EDR/auditd)',
            'Did {account} create any new files or modify existing ones on {host}?',
            'Was the SSH connection via key or password? (key suggests prior preparation)',
            'Are there other hosts in the same subnet {account} could reach next?',
        ],
        'ioc_checks': [
            'Lateral movement within <5 minute window of initial access',
            'Multiple host targets from same source account',
            'New SSH key or RDP certificate observed',
        ],
    },
    'T1021.004': {  # SSH
        'label': 'SSH Lateral Movement',
        'steps': [
            'Check /var/log/auth.log on {host} for accepted key vs. password auth',
            'Find all SSH keys trusted by {account} on {host}: cat /home/{account}/.ssh/authorized_keys',
            'Check SSH config for forwarding abuse: cat /etc/ssh/sshd_config | grep -E "AllowTcpForwarding|GatewayPorts"',
            'Identify pivot targets: netstat -ant on {host} for established connections out to internal subnet',
            'Preserve auth log: cp /var/log/auth.log /evidence/auth_$(date +%Y%m%d_%H%M%S).log',
        ],
        'unknowns': [
            'Was this SSH session from an interactive terminal or an automated script?',
            'Did the session use key-based auth? If yes, where was the private key sourced from?',
        ],
        'ioc_checks': ['First-time SSH from this source IP', 'Connection duration vs. typical session length'],
    },
    'T1041': {  # Exfiltration Over C2
        'label': 'Exfiltration/C2 Communication',
        'steps': [
            'Check volume of data transferred to {ip}: bytes_out field in netflow or firewall logs',
            'Run reverse DNS and ASN lookup on {ip}: dig -x {ip}; curl "https://ipinfo.io/{ip}"',
            'Check if {ip} appears in any threat intel feed: AbuseIPDB, VirusTotal, Shodan',
            'Block {ip} at NGFW: add rule DROP src/dst = {ip}, log all future hits',
            'Check for scheduled tasks or cron invoking outbound transfer to {ip}',
            'Correlate {ip} with other clusters — if hit on multiple clusters, escalate to "campaign"',
        ],
        'unknowns': [
            'How much data went to {ip}? (netflow bytes_out — determines breach notification threshold)',
            'Is {ip} a known C2 infrastructure? (check TIP)',
            'Did the connection persist or was it a single-burst transfer?',
            'Are other hosts contacting the same {ip}?',
        ],
        'ioc_checks': ['Beaconing interval regularity', 'Unusually large bytes_out', 'DNS tunnelling patterns'],
    },
    'T1071': {  # Application Layer Protocol
        'label': 'C2 via Application Protocol (HTTP/DNS/SMTP)',
        'steps': [
            'Decode payload sample: if HTTP, inspect URI patterns and user-agent; if DNS, look for long subdomain labels',
            'Check {ip} for domain fronting or CDN abuse: whois {ip}; check if ASN is a major CDN',
            'Capture 10 packets from {host} to {ip}: tcpdump -w /evidence/c2_sample.pcap -c 200 host {ip}',
            'Block based on domain/SNI not just IP if TLS is in use',
        ],
        'unknowns': [
            'Is the traffic HTTP/HTTPS, DNS, or another protocol?',
            'Is this a known CDN or legitimate service being abused (domain fronting)?',
        ],
        'ioc_checks': ['Regular beaconing interval (±5% jitter = tool, >30% jitter = human)', 'URI path randomness'],
    },
    'T1110': {  # Brute Force
        'label': 'Brute Force / Password Spray',
        'steps': [
            'Count failed auth attempts for {account} in past 24h: grep "Failed password" /var/log/auth.log | grep {account} | wc -l',
            'Check if multiple accounts were targeted from same {ip}: look for fan-out pattern in auth logs',
            'Enable lockout policy if not already: net accounts /lockoutthreshold:10 (Windows) or pam_tally2 (Linux)',
            'Force password reset for {account} and all accounts that showed failed attempts',
        ],
        'unknowns': [
            'Was there a successful authentication immediately after failed attempts? (indicates correct password found)',
            'Were multiple accounts targeted from the same IP? (spray vs targeted)',
        ],
        'ioc_checks': ['Failed auth count > threshold in <5 min window', 'Multiple accounts same source IP'],
    },
    'T1190': {  # Exploit Public-Facing Application
        'label': 'Public Application Exploitation',
        'steps': [
            'Capture web server access log around event timestamp on {host}: grep "{ip}" /var/log/nginx/access.log',
            'Check for file writes to web root after the request: find /var/www -newer /tmp/baseline -type f',
            'Verify application version and check CVE database for known exploits matching the request pattern',
            'Isolate {host} if webshell suspected: scan with: find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|system" {} \\;',
        ],
        'unknowns': [
            'Which application and version is on {host}?',
            'Was a webshell dropped? (check for new .php/.aspx/.jsp files written after event time)',
            'Did the request return an unusual HTTP response code (200 on a path that should 404)?',
        ],
        'ioc_checks': ['Unusual URI with shell metacharacters', 'Large POST to unusual path', 'Outbound connection from web process'],
    },
}
# Fallback for unmapped techniques
_MITRE_FALLBACK = {
    'steps': [
        'Review all evidence rows for {entity_type} {entity_name} in the cluster time window',
        'Cross-reference {entity_name} activity against baseline behaviour (last 30 days)',
        'Determine if action was initiated by a human, service account, or automated process',
        'Document findings in the investigation log before taking any containment action',
    ],
    'unknowns': [
        'Is this {entity_type} {entity_name} behaviour consistent with its normal role?',
        'What other systems does {entity_name} interact with that are not yet in scope?',
    ],
    'ioc_checks': ['Baseline deviation', 'Timing anomaly', 'Cross-entity correlation'],
}


def _get_playbook_for_techniques(techniques: list[str]) -> dict:
    """Return merged playbook entry for the best-matching techniques."""
    for t in techniques:
        base = t.split('.')[0]  # T1021 from T1021.004
        if t in _MITRE_PLAYBOOK:
            return _MITRE_PLAYBOOK[t]
        if base in _MITRE_PLAYBOOK:
            return _MITRE_PLAYBOOK[base]
    return _MITRE_FALLBACK


def _render_playbook_steps(playbook: dict, entity_name: str, entity_type: str, ip: str = '') -> dict:
    """Fill entity name/type/ip into playbook template strings."""
    def fill(s: str) -> str:
        return s.replace('{account}', entity_name
                   ).replace('{host}', entity_name
                   ).replace('{ip}', ip or entity_name
                   ).replace('{entity_name}', entity_name
                   ).replace('{entity_type}', entity_type)
    return {
        'label': playbook.get('label', ''),
        'steps': [fill(s) for s in playbook.get('steps', [])],
        'unknowns': [fill(u) for u in playbook.get('unknowns', [])],
        'ioc_checks': playbook.get('ioc_checks', []),
    }


def _parse_action_entities(what_to_do: str) -> list[dict]:
    """Parse the what_to_do section into structured entity-action records.

    Each action line like '[ACCOUNT azureuser] Disable immediately: ...'
    becomes: {entity_type, entity_name, action_summary, full_line}
    """
    import re
    result = []
    for line in what_to_do.splitlines():
        line = line.strip()
        if not line:
            continue
        # Strip leading list number: "1. [ACCOUNT ...]" → "[ACCOUNT ...]"
        line = re.sub(r'^\d+\.\s+', '', line)
        m = re.match(r'\[(ACCOUNT|HOST|IP)\s+(.+?)\]\s*(.*)', line, re.IGNORECASE)
        if m:
            result.append({
                'entity_type': m.group(1).lower(),
                'entity_name': m.group(2).strip(),
                'action_summary': m.group(3).strip()[:120],
                'full_line': line,
            })
        else:
            # fallback — unstructured line
            result.append({
                'entity_type': 'unknown',
                'entity_name': '',
                'action_summary': line[:120],
                'full_line': line,
            })
    return result


# ── Entity deepen endpoint ────────────────────────────────────────────────────

class _DeepenRequest(BaseModel):
    entity_type: str                   # 'account' | 'host' | 'ip'
    entity_name: str                   # e.g. 'azureuser'
    action_summary: str = ''           # The original action line from section 3
    analyst_answers: dict = Field(default_factory=dict)   # {'question': 'answer', ...}
    model: str = 'qwen2.5:14b'


def _build_deepen_prompt(
    cluster: dict,
    rows: List[dict],
    entity_type: str,
    entity_name: str,
    action_summary: str,
    analyst_answers: dict,
    playbook: dict,
) -> str:
    """Build a focused 400-token-max prompt for ONE entity.

    Context window discipline:
    - System instruction: ~80 tokens
    - Entity evidence rows (this entity only): ~200 tokens max
    - Playbook unknowns answered by analyst: ~100 tokens
    - Output instruction: ~60 tokens
    Total input: ~440 tokens → output cap 400 tokens → well within 14B coherence range
    """
    # Filter rows to only those mentioning this entity
    entity_lower = entity_name.lower()
    entity_rows = [
        r for r in rows
        if any(
            entity_lower in str(r.get(f, '')).lower()
            for f in ('user', 'username', 'account', 'hostname', 'host', 'src_ip', 'dst_ip', 'description')
        )
    ][:6]  # hard cap to keep tokens tight

    # Build compact evidence string
    ev_lines = []
    for r in entity_rows:
        ts = str(r.get('timestamp', r.get('event_time', '')))[:16]
        desc = str(r.get('description', r.get('event_type', '')))[:80]
        sev = str(r.get('severity', r.get('risk_level', '')))
        ev_lines.append(f'  [{ts}] {desc} sev={sev}')
    ev_str = '\n'.join(ev_lines) or '  (no rows specifically match this entity — use cluster-level context)'

    mitre = ', '.join((cluster.get('top_mitre') or [])[:4]) or 'unknown'
    sev = (cluster.get('severity') or 'unknown').upper()
    phase = ', '.join(cluster.get('phase_sequence') or []) or 'unknown'
    blast = cluster.get('blast_radius_summary') or 'unknown'

    # Analyst answers block
    answers_block = ''
    if analyst_answers:
        answers_block = '\nANALYST PROVIDED:\n' + '\n'.join(f'  {k}: {v}' for k, v in analyst_answers.items())

    # Unanswered unknowns (questions the analyst has NOT yet answered)
    answered_keys = set(k.lower() for k in analyst_answers.keys())
    open_unknowns = [u for u in playbook.get('unknowns', []) if not any(a in u.lower() for a in answered_keys)][:3]
    open_str = '\n'.join(f'  - {u}' for u in open_unknowns) if open_unknowns else '  (none outstanding)'

    type_label = {'account': 'User Account', 'host': 'Host/Server', 'ip': 'External IP'}.get(entity_type, entity_type)

    return f"""Defense analyst. ONE entity deep-dive. Be specific. Max 400 words. No padding.

{type_label.upper()}: {entity_name}
Cluster severity: {sev} | Techniques: {mitre} | Phase: {phase}
Blast radius: {blast}
Original action: {action_summary}
{answers_block}

Evidence rows for {entity_name}:
{ev_str}

Still unanswered (address if evidence allows):
{open_str}

Write exactly 4 sections (no headings preamble, start section immediately):

SUB-STEPS:
3-5 numbered concrete steps for {entity_name} specifically. Each step must either give an exact command OR name a specific log source to check. Reference evidence timestamps where available.

ESCALATE_OR_RESOLVE:
One line: SELF-RESOLVE if a standard analyst can do this alone, ESCALATE if it requires security team lead or legal, or PARTIAL (explain who does what).

OPEN_QUESTIONS:
1-2 questions still unanswered whose answers would materially change the response. If none, write NONE.

CAPTURE_AS_EVIDENCE:
Exactly what to log/preserve about {entity_name} before taking containment action. Include specific file paths or log queries.
"""


@router.post('/{assessment_id}/clusters/{cluster_id}/tier2/llm-entity-deepen')
async def entity_deepen(
    assessment_id: str,
    cluster_id: str,
    body: _DeepenRequest,
    request: Request,
) -> dict:
    """Focused 400-token LLM deep-dive for a single entity.

    Called when analyst clicks ▼ on an action card and optionally fills answers.
    Returns sub-steps, escalation verdict, open questions, and evidence capture list.
    """
    _LLM = _get_llm()
    if _LLM is None:
        return {'llm_available': False, 'error': 'LLM not available.'}

    assessment = _get_assessment(assessment_id)
    cluster: dict = {}
    rows: List[dict] = []
    if assessment:
        for c in (assessment.get('correlation_clusters') or []):
            if c.get('cluster_id') == cluster_id:
                cluster = c
                rr_set = set(c.get('row_refs') or [])
                rows = [r for r in (assessment.get('normalized_rows') or assessment.get('rows') or [])
                        if r.get('row_number') in rr_set or r.get('row_index') in rr_set]
                break

    if not cluster:
        raise HTTPException(status_code=404, detail=f'Cluster {cluster_id} not found.')

    # Get playbook for this entity based on cluster techniques
    techniques = cluster.get('top_mitre') or []
    playbook_raw = _get_playbook_for_techniques(techniques)
    playbook = _render_playbook_steps(
        playbook_raw,
        entity_name=body.entity_name,
        entity_type=body.entity_type,
        ip=body.entity_name if body.entity_type == 'ip' else '',
    )

    prompt = _build_deepen_prompt(
        cluster=cluster,
        rows=rows,
        entity_type=body.entity_type,
        entity_name=body.entity_name,
        action_summary=body.action_summary,
        analyst_answers=body.analyst_answers,
        playbook=playbook,
    )

    try:
        raw = _LLM.generate(
            prompt=prompt,
            max_tokens=500,
            tenant_id=_get_tenant(request),
            overrides={'ollama_model': body.model},
        )
        text = raw.get('text') or ''

        # Parse the 4 sections
        sections: dict[str, str] = {}
        current = None
        buf: list[str] = []
        HEADERS = {
            'SUB-STEPS:': 'sub_steps',
            'SUB_STEPS:': 'sub_steps',
            'ESCALATE_OR_RESOLVE:': 'escalate_or_resolve',
            'OPEN_QUESTIONS:': 'open_questions',
            'CAPTURE_AS_EVIDENCE:': 'capture_as_evidence',
        }
        for line in text.splitlines():
            upper = line.strip().upper()
            matched = next((v for k, v in HEADERS.items() if upper.startswith(k)), None)
            if matched:
                if current and buf:
                    sections[current] = '\n'.join(buf).strip()
                current = matched
                buf = []
                remainder = line.strip()[len([k for k in HEADERS if upper.startswith(k)][0]):]
                if remainder.strip():
                    buf.append(remainder.strip())
            elif current:
                buf.append(line)
        if current and buf:
            sections[current] = '\n'.join(buf).strip()

        return {
            'llm_available': True,
            'entity_type': body.entity_type,
            'entity_name': body.entity_name,
            'playbook': playbook,
            'llm_sections': sections,
            'raw_text': text,
            'model': raw.get('meta', {}).get('model', body.model),
        }
    except Exception as exc:
        logger.exception('entity-deepen failed: %s', exc)
        return {'llm_available': False, 'error': str(exc)}


class _RefineRequest(BaseModel):
    persona: str = 'soc_analyst'
    answer_key: str              # What was answered: 'siem', 'host_live', 'regulatory_scope', 'sessions_active', etc.
    answer_value: str            # Analyst's answer: e.g. 'Splunk', 'yes', 'PCI', etc.
    current_notes: str = ''      # Existing persona notes to refine (passed by the browser)
    model: str = 'qwen2.5:14b'


def _build_refine_prompt(
    cluster: dict,
    rows: List[dict],
    persona: str,
    answer_key: str,
    answer_value: str,
    current_notes: str,
) -> str:
    """Build a focused follow-up prompt that refines persona notes given one analyst answer."""
    pins = _extract_evidence_pins(cluster, rows)
    accounts = pins['accounts'][:4]
    hosts = pins['hosts'][:4]
    ext_ips = pins['ips'][:3]
    mitre = ', '.join((cluster.get('top_mitre') or [])[:5]) or 'unknown'
    sev = (cluster.get('severity') or 'unknown').upper()

    persona_labels = {
        'soc_analyst': 'SOC Analyst',
        'threat_hunter': 'Threat Hunter',
        'ciso': 'CISO',
        'forensics': 'Forensics Investigator',
    }
    persona_label = persona_labels.get(persona, persona.replace('_', ' ').title())

    # Map answer_key to a human-readable context note
    context_note_map: dict[str, str] = {
        'siem':             f'The tenant uses {answer_value} as their SIEM.',
        'host_live':        f'The affected host {"is still live and reachable" if answer_value.lower() in ("yes","live","y") else "is offline or unreachable"}.',
        'regulatory_scope': f'Regulatory scope confirmed: {answer_value}.',
        'sessions_active':  f'Active sessions for the account are {"confirmed present" if answer_value.lower() in ("yes","y","active") else "not confirmed"}.',
        'correlated':       f'This cluster is {"correlated with other active clusters" if answer_value.lower() in ("yes","correlated","campaign") else "isolated — no other clusters show related activity"}.',
        'can_isolate':      f'The analyst {"has permission to isolate hosts directly" if answer_value.lower() in ("yes","y") else "does NOT have direct isolation permission — escalation required"}.',
    }
    context_note = context_note_map.get(answer_key, f'Additional context: {answer_key} = {answer_value}')

    return f"""You are a senior security analyst. You have just learned one critical new fact about this incident.
Rewrite the {persona_label} next-steps block to be significantly more specific given this new information.
Do NOT repeat the original notes verbatim. Replace generic steps with concrete ones based on the new fact.

CLUSTER: {cluster.get('cluster_id','?')} | {sev} | Techniques: {mitre}
Accounts: {', '.join(accounts) or 'none'}
Hosts: {', '.join(hosts) or 'none'}
External IPs: {', '.join(ext_ips) or 'none'}

NEW FACT JUST CONFIRMED: {context_note}

Previous {persona_label} notes (IMPROVE these, do not just copy):
{current_notes or '(none yet)'}

Write 3-5 updated bullets for {persona_label}. Each bullet must:
- Name a specific entity (account, host, or IP from the list above)
- Give an exact command, query, or action step reflecting the new fact
- State whether the analyst can do it themselves or must escalate

For THREAT HUNTER with a known SIEM: write the actual query, not a description of the query.
For FORENSICS with host liveness known: put preservation steps in the exact right order.
For CISO with regulatory scope known: state the specific notification obligation and deadline.
For SOC ANALYST with session info: state exact revocation command for that session state.

End with: VERDICT: can this persona resolve it themselves (YES/ESCALATE/PARTIAL) and one sentence why.
"""


@router.post('/{assessment_id}/clusters/{cluster_id}/tier2/llm-refine')
async def refine_persona_notes(
    assessment_id: str,
    cluster_id: str,
    body: _RefineRequest,
    request: Request,
) -> dict:
    """One follow-up LLM call to refine a single persona's notes after an analyst answers a question.

    Lighter than a full re-summary — only generates updated bullets for the requested persona.
    """
    _LLM = _get_llm()
    if _LLM is None:
        return {'llm_available': False, 'error': 'LLM not available.'}

    assessment = _get_assessment(assessment_id)
    cluster: dict = {}
    rows: List[dict] = []
    if assessment:
        for c in (assessment.get('correlation_clusters') or []):
            if c.get('cluster_id') == cluster_id:
                cluster = c
                rr_set = set(c.get('row_refs') or [])
                rows = [r for r in (assessment.get('normalized_rows') or assessment.get('rows') or [])
                        if r.get('row_number') in rr_set or r.get('row_index') in rr_set]
                break

    if not cluster:
        raise HTTPException(status_code=404, detail=f'Cluster {cluster_id} not found.')

    prompt = _build_refine_prompt(
        cluster, rows,
        persona=body.persona,
        answer_key=body.answer_key,
        answer_value=body.answer_value,
        current_notes=body.current_notes,
    )

    try:
        raw = _LLM.generate(
            prompt=prompt,
            max_tokens=600,
            tenant_id=_get_tenant(request),
            overrides={'ollama_model': body.model},
        )
        text = raw.get('text') or ''

        # Extract VERDICT line if present
        verdict_line = ''
        body_lines = []
        for line in text.splitlines():
            if line.strip().upper().startswith('VERDICT:'):
                verdict_line = line.strip()[8:].strip()
            else:
                body_lines.append(line)
        refined_text = '\n'.join(body_lines).strip()

        return {
            'llm_available': True,
            'persona': body.persona,
            'refined_notes': refined_text,
            'self_resolvable': verdict_line,
            'answer_key': body.answer_key,
            'answer_value': body.answer_value,
            'model': raw.get('meta', {}).get('model', body.model),
        }
    except Exception as exc:
        logger.exception('llm-refine failed: %s', exc)
        return {'llm_available': False, 'error': str(exc)}


__all__ = ['router']
