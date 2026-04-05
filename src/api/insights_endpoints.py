"""AI-powered insights generation endpoints."""
from __future__ import annotations

import logging
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
import time
import asyncio

from fastapi import APIRouter, HTTPException
from fastapi import Request
from src.api.tenant_helpers import resolve_tenant_id
from src.security.roles import require_roles
from pydantic import BaseModel, Field

from src.analysis.auto_llm import (
    LLMAssessmentClient,
    detect_domain_with_confidence,
    _build_tier1_fallback,
    _build_threat_intel_context,
)
from src.services.network_highlights import get_network_highlights_snapshot
from src.services.network_highlights import get_network_highlights_snapshot
from src.analysis.persona_format import render_persona_prompt
from src.analysis.triage import compute_triage_score
try:
    from src.reporting.persona_parser import parse_persona_text, validate_parsed_persona
except Exception:  # pragma: no cover - best-effort import for tests
    def parse_persona_text(text):
        return {'summary': '', 'actions': [], 'evidence_refs': [], 'confidence': 0.0, 'parsed_from_json': False}
    def validate_parsed_persona(parsed):
        return (False, ['parser_unavailable'])

try:  # pragma: no cover - optional dependency in tests
    from src.integrations.llm_client import DEFAULT_CLIENT
except Exception:  # pragma: no cover
    DEFAULT_CLIENT = None


logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/insights', tags=['insights'])
try:
    _TIER1_CLIENT = LLMAssessmentClient()
except Exception:
    _TIER1_CLIENT = None


class InsightRequest(BaseModel):
    row: Dict[str, Any] = Field(..., description='Artifact row data')
    insight_type: Literal['tier1', 'tier2', 'dread', 'playbook', 'hunt', 'executive']
    pipeline_context: Optional[Dict[str, Any]] = Field(default=None, description='Optional enrichment context')


class InsightResponse(BaseModel):
    text: str
    insight_type: str
    estimated_cost: float
    model: str
    payload: Optional[Dict[str, Any]] = None


FACTOR_EXPLANATIONS: Dict[str, str] = {
    'novel_global': 'Hash not seen across enterprise baseline; indicates potential targeted malware.',
    'novel_local': 'New artifact on this endpoint; validate install source.',
    'temp_execution': 'Executed from a temporary directory, common for staging malware.',
    'naming_mimicry': 'Filename mimics trusted tooling (CrowdStrike, etc.).',
    'orphan_process': 'Process lacks a parent in telemetry; possible injection.',
    'unsigned_executable': 'Binary lacks a digital signature despite vendor naming.',
    'lolbin': 'Executed using living-off-the-land binaries abused by attackers.',
    'network_beacon': 'Exhibits periodic outbound connections resembling C2.',
    'credential_access': 'Touched credential stores or LSASS memory.',
}

_PLAYBOOK_TEMPLATE_DIR = Path(os.getenv('PLAYBOOK_TEMPLATES_DIR', Path.cwd() / 'playbook_templates'))


def _load_playbook_templates() -> Dict[str, Dict[str, Any]]:
    templates: Dict[str, Dict[str, Any]] = {}
    if _PLAYBOOK_TEMPLATE_DIR.exists():
        for path in sorted(_PLAYBOOK_TEMPLATE_DIR.glob('*.json')):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
            except Exception:
                continue
            alert_type = data.get('alert_type') or path.stem
            steps = data.get('steps')
            if not isinstance(steps, list) or not steps:
                continue
            templates[alert_type] = {
                'alert_type': alert_type,
                'summary': data.get('summary'),
                'severity': data.get('severity'),
                'mitre': data.get('mitre') or [],
                'cisa_kev': data.get('cisa_kev') or [],
                'cvss_reference': data.get('cvss_reference'),
                'epss': data.get('epss'),
                'references': data.get('references') or [],
                'steps': steps,
            }
    if 'generic_anomaly' not in templates:
        templates['generic_anomaly'] = {
            'alert_type': 'generic_anomaly',
            'summary': 'Catch-all response for pipeline anomalies lacking classification.',
            'severity': 'medium',
            'mitre': ['T1036', 'T1057'],
            'cisa_kev': [],
            'cvss_reference': 6.5,
            'epss': 0.2,
            'references': ['https://attack.mitre.org/'],
            'steps': [
                {'order': 1, 'action': 'Validate host ownership and role', 'rationale': 'Quantify business impact.', 'automated': False},
                {'order': 2, 'action': 'Pivot to related alerts for host/user', 'rationale': 'Identify multi-stage campaigns.', 'automated': True},
                {'order': 3, 'action': 'Request missing telemetry', 'rationale': 'Gather evidence before escalation.', 'automated': False},
            ],
        }
    return templates


PLAYBOOK_LIBRARY: Dict[str, Dict[str, Any]] = _load_playbook_templates()

DEFAULT_ANALYST_ACTIONS: List[Dict[str, Any]] = [
    {'action': 'escalate_tier2', 'label': 'Escalate to Tier 2', 'shortcut': 'E', 'recommended': True, 'reason': 'High-risk indicators present.'},
    {'action': 'mark_true_positive', 'label': 'Confirm Malicious', 'shortcut': 'T'},
    {'action': 'mark_false_positive', 'label': 'Mark False Positive', 'shortcut': 'F'},
    {'action': 'request_logs', 'label': 'Request Additional Logs', 'shortcut': 'L'},
]


def _resolve_tenant(request: Request | None, hint: str | None = None) -> str | None:
    if request is None:
        return hint
    return resolve_tenant_id(request, hint)


def _enforce_row_tenant(request: Request | None, row: Dict[str, Any] | None, context: Dict[str, Any] | None = None) -> str | None:
    row = row or {}
    context = context or {}
    hint = (
        context.get('tenant')
        or context.get('tenant_id')
        or context.get('org')
        or row.get('tenant')
        or row.get('tenant_id')
        or row.get('org')
    )
    tenant_id = _resolve_tenant(request, hint)
    row_tenant = row.get('tenant_id') or row.get('tenant') or row.get('org')
    if tenant_id and row_tenant and str(row_tenant) != str(tenant_id):
        raise HTTPException(status_code=403, detail='tenant_mismatch')
    return tenant_id


def _infer_alert_type(row: Dict[str, Any]) -> str:
    path = str(row.get('file_path') or row.get('path') or '').lower()
    proc = str(row.get('process_name') or row.get('image') or '').lower()
    cmd = str(row.get('command_line') or row.get('cmdline') or '').lower()
    event_type = str(row.get('event_type') or '').lower()
    category = str(row.get('category') or '').lower()
    factors = [str(f).lower() for f in (row.get('factors') or [])]
    if 'temp' in path or 'appdata\\local\\temp' in path:
        return 'suspicious_temp_execution'
    if any(token in proc for token in ('powershell', 'wscript', 'cscript', 'cmd.exe', 'wmic', 'mshta', 'certutil')) or any(token in cmd for token in ('powershell', 'mshta', 'regsvr32', 'rundll32')):
        return 'lolbin_execution'
    iam_factor_tokens = ('privilege_escalation', 'iam', 'cloudtrail')
    if (
        'iam' in event_type
        or 'signin' in event_type
        or 'iam' in category
        or any(any(token in factor for token in iam_factor_tokens) for factor in factors)
        or 'assumerole' in cmd
    ):
        return 'cloud_iam_anomaly'
    if any('beacon' in f or 'c2' in f or 'callback' in f for f in factors) or row.get('beacon_score') or row.get('beacon_period'):
        return 'network_beaconing'
    if any('dns' in f and ('exfil' in f or 'tunnel' in f or 'txt_record' in f) for f in factors) or 'dns' in event_type and 'txt' in cmd:
        return 'dns_exfiltration'
    if any('rdp' in f and ('brute' in f or 'password' in f) for f in factors) or 'rdp' in event_type or 'rdp' in row.get('protocol', '').lower():
        return 'rdp_bruteforce'
    if any('credential' in f or 'lsass' in f or 'sam' in f or 'dpapi' in f for f in factors) or 'lsass' in cmd or 'procdump' in cmd:
        return 'credential_access'
    return 'generic_anomaly'


def _extract_dread_dims(row: Dict[str, Any]) -> Dict[str, Any]:
    """Return the 5 DREAD dimension scores (1-10) from whichever engine populated _dread.

    Priority:
    1. dread_engine path  — keys: damage, reproducibility, exploitability, affected, discoverability
    2. factor_taxonomy path — uses max_components dict from aggregate_threat_model
    3. Synthesise from composite score and factors (rough proportional split)
    """
    dread = row.get('_dread') or row.get('dread') or {}
    if isinstance(dread, (int, float)):
        dread = {'score': dread}

    dims: Dict[str, Any] = {}
    # --- Path 1: dread_engine explicitly populated all 5 ---
    for key in ('damage', 'reproducibility', 'exploitability', 'affected', 'discoverability'):
        v = dread.get(key) or dread.get(f'affected_users' if key == 'affected' else key)
        if v is not None:
            try:
                dims[key] = int(round(float(v)))
            except Exception:
                pass

    # --- Path 2: factor_taxonomy components dict ---
    comps = dread.get('components') or dread.get('max_components') or {}
    if isinstance(comps, dict) and not dims:
        _map = {
            'damage': comps.get('damage'),
            'reproducibility': comps.get('reproducibility'),
            'exploitability': comps.get('exploitability'),
            'affected': comps.get('affected'),
            'discoverability': comps.get('discoverability'),
        }
        for k, v in _map.items():
            if v is not None:
                try:
                    # taxonomy values are 0..1, scale to 1-10
                    scaled = max(1, min(10, int(round(float(v) * 10))))
                    dims[k] = scaled
                except Exception:
                    pass

    # --- Path 3: synthesise from composite ---
    if not dims:
        composite = (
            dread.get('composite')
            or dread.get('score')
            or dread.get('risk_score', 0) * 10
        )
        try:
            c = float(composite or 0)
        except Exception:
            c = 0.0
        factors = [str(f).lower() for f in (row.get('factors') or [])]
        # rough evidence-based splits
        damage = min(10, max(1, int(c + (1 if any(x in ' '.join(factors) for x in ('lsass', 'credential', 'critical', 'tier1')) else 0))))
        exploitability = min(10, max(1, int(c + (1 if any('exploit' in f or 'cve' in f or 'public_poc' in f for f in factors) else -1))))
        reproducibility = min(10, max(1, int(c - (1 if any('rare' in f or 'unique' in f for f in factors) else 0))))
        affected = min(10, max(1, int(c + (1 if any('domain' in f or 'all_user' in f for f in factors) else -1))))
        discoverability = min(10, max(1, int(c - (1 if any('hidden' in f or 'obfuscat' in f for f in factors) else 0))))
        dims = {
            'damage': damage,
            'reproducibility': reproducibility,
            'exploitability': exploitability,
            'affected': affected,
            'discoverability': discoverability,
        }

    return dims


# Evidence labels used to explain why each dimension scored as it did
_DREAD_EVIDENCE_LABELS: Dict[str, Dict[str, str]] = {
    'damage': {
        'critical_ports': 'target exposes critical service ports (22/445/3389)',
        'business_tier': 'asset is classified as {val} business tier',
        'cmdb_criticality': 'CMDB criticality score {val}/10',
        'vuln_high': '{val} high-CVSS vulnerabilities matched',
    },
    'exploitability': {
        'exploit_available': 'public exploit or PoC available',
        'avg_cvss': 'average CVSS {val} across matched CVEs',
        'prior_exploits': 'prior exploitation activity detected',
    },
    'reproducibility': {
        'asn_residential': 'source ASN is residential/static (persistent attacker infra)',
        'tool_masscan': 'masscan fingerprint detected (automated tooling)',
    },
    'affected': {
        'host_count': '{val} destination hosts in scope',
        'domain_wide': 'asset serves domain-wide Identity/Auth role',
    },
    'discoverability': {
        'public_dns': 'target has public DNS record',
        'public_facing': 'asset is externally reachable',
        'sequential_scan': 'sequential/automated scan pattern indicates pre-mapping',
    },
}


def _build_dread_rationale(row: Dict[str, Any]) -> str:
    """Return a compact evidence-anchored rationale string for each DREAD dimension.

    Used to ground LLM prompts in concrete evidence instead of bare factor strings.
    Returns an empty string when no DREAD data is available (safe to skip).
    """
    dims = _extract_dread_dims(row)
    if not dims:
        return ''

    dread = row.get('_dread') or row.get('dread') or {}
    if isinstance(dread, (int, float)):
        dread = {}
    factors = [str(f).lower() for f in (row.get('factors') or [])]
    factor_str = ' '.join(factors)

    def _hint(dim: str) -> str:
        hints = []
        if dim == 'damage':
            ports = dread.get('destination_ports') or row.get('destination_ports') or []
            critical = {22, 23, 445, 3389, 1433, 3306}
            if set(ports) & critical:
                hints.append('critical service ports exposed')
            biz = (row.get('business_tier') or dread.get('business_tier') or '').lower()
            if biz in ('high', 'critical'):
                hints.append(f'asset tier: {biz}')
            vuln = dread.get('vuln_matches') or []
            high_cves = [v for v in (vuln if isinstance(vuln, list) else []) if (v.get('cvss') or 0) >= 7]
            if high_cves:
                hints.append(f'{len(high_cves)} high-CVSS CVE(s) matched (e.g. {high_cves[0].get("cve_id","CVE-??")} CVSS {high_cves[0].get("cvss","?")})')
            if any(x in factor_str for x in ('lsass', 'credential', 'sam_hive', 'dpapi')):
                hints.append('credential store targeted')
        elif dim == 'exploitability':
            if any('exploit' in f or 'public_poc' in f for f in factors):
                hints.append('public exploit/PoC available')
            avg_cvss = dread.get('avg_cvss')
            if avg_cvss:
                hints.append(f'avg CVSS {avg_cvss}')
            if any('prior_exploit' in f for f in factors):
                hints.append('prior exploitation observed')
        elif dim == 'reproducibility':
            asn = (dread.get('asn_category') or '').lower()
            if asn in ('residential', 'static'):
                hints.append(f'source ASN: {asn} (persistent infra)')
            if any('masscan' in f or 'automated_tool' in f for f in factors):
                hints.append('automated tooling fingerprint')
            if not hints:
                score = dims.get('reproducibility', 5)
                hints.append('ease of repetition' + (' high' if score >= 7 else ' moderate' if score >= 4 else ' low'))
        elif dim == 'affected':
            hosts = row.get('destination_ips') or []
            if isinstance(hosts, list) and hosts:
                hints.append(f'{len(hosts)} destination host(s) in scope')
            if any('domain' in f or 'all_user' in f or 'dc_' in f for f in factors):
                hints.append('domain-wide identity asset')
            user = row.get('user') or row.get('username')
            if user:
                hints.append(f'user: {user}')
        elif dim == 'discoverability':
            if any('public_dns' in f or 'public_facing' in f for f in factors):
                hints.append('publicly reachable target')
            if any('sequential' in f or 'horizontal_scan' in f for f in factors):
                hints.append('sequential scan pattern (pre-mapped)')
            if not hints:
                score = dims.get('discoverability', 5)
                hints.append('findability' + (' high — asset exposed' if score >= 7 else ' moderate' if score >= 4 else ' low — requires insider knowledge'))
        return '; '.join(hints) if hints else 'based on pipeline telemetry'

    labels = {
        'damage': 'Damage',
        'reproducibility': 'Reproducibility',
        'exploitability': 'Exploitability',
        'affected': 'Affected Users',
        'discoverability': 'Discoverability',
    }
    lines = ['DREAD evidence:']
    for dim in ('damage', 'exploitability', 'reproducibility', 'affected', 'discoverability'):
        score = dims.get(dim)
        if score is None:
            continue
        lines.append(f'  {labels[dim]} {score}/10 — {_hint(dim)}')
    return '\n'.join(lines)


def _build_signal_entries(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    factors = row.get('factors')
    if not isinstance(factors, list):
        factors = []
    entries: List[Dict[str, Any]] = []
    weight = 0.42
    for idx, factor in enumerate(factors[:5]):
        if not factor:
            continue
        key = str(factor).lower()
        explanation = FACTOR_EXPLANATIONS.get(key, f'Flagged due to pipeline signal: {factor}')
        entries.append({'signal_name': factor, 'explanation': explanation, 'weight': round(max(0.1, weight), 2)})
        weight -= 0.08
    return entries


def _derive_confidence_score(row: Dict[str, Any]) -> float:
    for key in ('confidence', 'confidence_score', 'score'):
        if key in row:
            try:
                value = float(row[key])
                if value > 1:
                    value = value / 100.0 if value > 10 else value / 10.0
                return max(0.05, min(value, 0.99))
            except Exception:
                continue
    factors = row.get('factors') or []
    inferred = 0.45 + 0.1 * min(len(factors), 4)
    return round(min(inferred, 0.92), 2)


def _normalize_mitre(row: Dict[str, Any]) -> List[str]:
    mitre: List[str] = []
    raw = row.get('_mitre') or row.get('mitre') or row.get('mitre_tags') or []
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                val = entry.get('id') or entry.get('name')
            else:
                val = str(entry)
            if val:
                mitre.append(val)
    return mitre[:6]


def _resolve_playbook_template(alert_type: str) -> Dict[str, Any]:
    return PLAYBOOK_LIBRARY.get(alert_type) or PLAYBOOK_LIBRARY.get('generic_anomaly', {})


def _compose_tier1_payload(row: Dict[str, Any], domain: str, ctx: Dict[str, Any], model: str, summary_text: str) -> Dict[str, Any]:
    dread = row.get('_dread') or row.get('dread') or {}
    if isinstance(dread, (int, float)):
        dread = {'score': dread}
    signal_entries = _build_signal_entries(row)
    alert_type = _infer_alert_type(row)
    template = _resolve_playbook_template(alert_type)
    template_steps = template.get('steps') or PLAYBOOK_LIBRARY.get('generic_anomaly', {}).get('steps') or []
    timestamp = row.get('timestamp') or row.get('ts') or row.get('event_ts') or row.get('time') or row.get('created_at')
    primary_artifact = {
        'type': 'executable',
        'path': row.get('file_path') or row.get('path') or '',
        'hash_sha256': row.get('sha256') or row.get('SHA256') or '',
        'signature_status': row.get('signature_status') or row.get('signature') or ('unsigned' if any(str(f).lower() == 'unsigned_executable' for f in row.get('factors') or []) else 'unknown'),
        'file_size_bytes': row.get('file_size') or row.get('size') or row.get('image_size'),
    }
    related_artifacts = []
    for field in ('sha1', 'md5'):
        if row.get(field):
            related_artifacts.append({'type': field, 'value': row[field]})
    metadata = {
        'row_id': row.get('row_index') or row.get('row_id') or ctx.get('row_index'),
        'timestamp': timestamp,
        'processing_cost': ctx.get('estimated_cost') or 0.0006,
        'model_version': ctx.get('model_version') or 'tier1-schema-v1',
        'confidence_score': _derive_confidence_score(row),
        'weighted_confidence': _derive_confidence_score(row),
        'domain': domain,
    }
    verdict_mitre = _normalize_mitre(row)
    if not verdict_mitre and template.get('mitre'):
        verdict_mitre = template.get('mitre', [])
    _dread_dims = _extract_dread_dims(row)
    verdict = {
        'classification': row.get('verdict') or row.get('classification') or 'UNKNOWN',
        'dread_score': (dread or {}).get('score') or (dread or {}).get('composite'),
        'dread_breakdown': {
            'damage': _dread_dims.get('damage'),
            'reproducibility': _dread_dims.get('reproducibility'),
            'exploitability': _dread_dims.get('exploitability'),
            'affected_users': _dread_dims.get('affected'),
            'discoverability': _dread_dims.get('discoverability'),
        },
        'dread_rationale': _build_dread_rationale(row) or None,
        'mitre_techniques': verdict_mitre,
        'kill_chain_phase': row.get('kill_chain') or row.get('stage'),
    }
    next_actions = [
        step.get('action')
        for step in template_steps
        if isinstance(step, dict) and step.get('action')
    ]
    if not next_actions:
        next_actions = [action.get('label') for action in DEFAULT_ANALYST_ACTIONS if isinstance(action, dict) and action.get('label')]
    top_factors = [entry.get('name') for entry in signal_entries if isinstance(entry, dict) and entry.get('name')]
    if not top_factors:
        top_factors = [str(f) for f in (row.get('factors') or []) if f]
    payload = {
        'metadata': metadata,
        'verdict': verdict,
        'confidence': metadata['confidence_score'],
        'top_factors': top_factors[:5],
        'evidence_summary': {
            'primary_reason': signal_entries[0]['explanation'] if signal_entries else 'Pipeline heuristics flagged this artifact for review.',
            'hostname': row.get('host') or row.get('hostname') or 'unknown host',
            'username': row.get('user') or row.get('username') or row.get('account') or 'unknown user',
            'ip_address': row.get('ip') or row.get('src_ip') or row.get('destination_ip'),
        },
        'attck_tags': verdict_mitre,
        'next_actions': next_actions[:4],
        'approval_state': row.get('approval_state') or 'NOT_REQUIRED',
        'why_flagged': {
            'primary_reason': signal_entries[0]['explanation'] if signal_entries else 'Pipeline heuristics flagged this artifact for review.',
            'contributing_signals': signal_entries,
        },
        'key_evidence': {
            'primary_artifact': primary_artifact,
            'context': {
                'hostname': row.get('host') or row.get('hostname') or 'unknown host',
                'username': row.get('user') or row.get('username') or row.get('account') or 'unknown user',
                'ip_address': row.get('ip') or row.get('src_ip') or row.get('destination_ip'),
            },
            'related_artifacts': related_artifacts,
        },
        'playbook': {
            'alert_type': alert_type,
            'summary': template.get('summary'),
            'severity': template.get('severity'),
            'mitre': template.get('mitre'),
            'cisa_kev': template.get('cisa_kev'),
            'epss': template.get('epss'),
            'cvss_reference': template.get('cvss_reference'),
            'references': template.get('references'),
            'steps': template_steps,
        },
        'analyst_actions': DEFAULT_ANALYST_ACTIONS,
        'model': model,
        'raw_summary': summary_text,
    }
    # surface skip reason if previously applied on row
    if row.get('llm_skipped_reason'):
        payload['llm_skipped_reason'] = row.get('llm_skipped_reason')
    try:
        highlights = get_network_highlights_snapshot(ctx.get('tenant') or os.getenv('DEFAULT_TENANT', 'default'))
    except Exception:
        highlights = None
    if highlights:
        payload.setdefault('network_highlights', highlights)
    return payload


def _build_tier2_fallback(row: Dict[str, Any]) -> Dict[str, Any]:
    host = row.get('host') or row.get('hostname') or 'unknown host'
    user = row.get('user') or row.get('username') or 'unknown user'
    process = row.get('process_name') or row.get('file_path') or 'artifact'
    verdict = (row.get('verdict') or 'suspicious').upper()
    timestamp = row.get('timestamp') or row.get('ts') or row.get('time')
    mitre = row.get('mitre_tags') or row.get('mitre') or []
    primary_entity = {
        'type': 'process',
        'identifier': process,
        'properties': {
            'host': host,
            'user': user,
            'verdict': verdict,
            'path': row.get('file_path') or row.get('path'),
            'sha256': row.get('sha256') or row.get('SHA256'),
        }
    }
    related_entities: List[Dict[str, Any]] = []
    if host:
        related_entities.append({'type': 'host', 'identifier': host, 'relationship': 'executed_on'})
    if user and user.lower() != 'unknown user':
        related_entities.append({'type': 'user', 'identifier': user, 'relationship': 'initiated_by'})

    timeline_events: List[Dict[str, Any]] = []
    if timestamp:
        timeline_events.append({'timestamp': timestamp, 'event_type': 'process_start', 'description': f'{process} executed on {host}', 'severity': 'high'})

    return {
        'executive_summary': {
            'one_liner': f'{process} on {host} flagged as {verdict}',
            'threat_level': 'HIGH' if verdict in {'CRITICAL', 'HIGH'} else 'MEDIUM',
            'recommended_action': 'Isolate host and acquire memory image.',
        },
        'ai_reasoning': {
            'primary_hypothesis': 'Potential malware dropper executing from suspicious path.',
            'supporting_evidence': [
                {'observation': f'Process {process} launched on {host}', 'significance': 'Unexpected execution requires containment.', 'confidence': 0.65},
            ],
            'alternative_hypotheses': [
                {'hypothesis': 'Legitimate IT tool misconfigured', 'probability': 0.2, 'evidence_needed': 'Verify deployment records for host.'},
            ],
            'knowledge_gaps': ['Missing parent process lineage', 'Network telemetry unavailable'],
            'confidence_level': 'MEDIUM',
            'reasoning_caveats': 'Baseline host activity unknown; verify with asset owner.',
        },
        'investigation_tasks': [
            {'task': 'Capture volatile memory', 'tool': 'Velociraptor / WinPMEM', 'priority': 'critical'},
            {'task': 'Collect Sysmon process tree', 'tool': 'Sysmon / SIEM query', 'priority': 'high'},
        ],
        'siem_queries': [
            {'name': 'Hash prevalence', 'query': f'process.hash.sha256:{row.get("sha256") or "*"}', 'platform': 'elastic', 'time_range': 'last 24h'}
        ],
        'mitre_mapping': {
            'techniques': mitre[:5],
            'tactics': [],
            'kill_chain_phase': row.get('kill_chain') or 'Execution',
        },
        'evidence_timeline': {'events': timeline_events},
        'entity_graph': {'primary_entity': primary_entity, 'related_entities': related_entities},
        'analyst_notes': {'notes': [], 'tags': []},
    }


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        elif value is not None:
            result[key] = value
    return result


def _compose_tier2_payload(row: Dict[str, Any], ctx: Dict[str, Any], raw_text: Any) -> Dict[str, Any]:
    payload = _build_tier2_fallback(row)
    parsed: Optional[Dict[str, Any]] = None
    if isinstance(raw_text, dict):
        parsed = raw_text
    elif isinstance(raw_text, str):
        try:
            candidate = json.loads(raw_text)
            if isinstance(candidate, dict):
                parsed = candidate
        except Exception:
            parsed = None
    if parsed:
        payload = _deep_merge(payload, parsed)
    pipeline_ctx = {}
    try:
        pipeline_ctx = ctx.get('pipeline_context') or ctx
    except Exception:
        pipeline_ctx = {}
    try:
        ti_ctx = _build_threat_intel_context(row, pipeline_ctx if isinstance(pipeline_ctx, dict) else {})
        payload['threat_intel'] = ti_ctx
    except Exception:
        payload.setdefault('threat_intel', {'note': 'Threat intel context unavailable.'})
    try:
        highlights = get_network_highlights_snapshot(ctx.get('tenant') or os.getenv('DEFAULT_TENANT', 'default'))
    except Exception:
        highlights = None
    if highlights:
        payload.setdefault('network_highlights', highlights)
    # Attach per-dimension DREAD breakdown and rationale to Tier-2 payload
    try:
        _dims = _extract_dread_dims(row)
        if _dims:
            payload.setdefault('dread_breakdown', _dims)
            rationale = _build_dread_rationale(row)
            if rationale:
                payload.setdefault('dread_rationale', rationale)
    except Exception:
        pass
    return payload


def _llm_generate(prompt: str, model: str = 'gpt-4o-mini', max_tokens: int = 800, context: Optional[Dict[str, Any]] = None) -> Optional[str]:
    if not DEFAULT_CLIENT:
        return None
    try:
        _overrides = None
        try:
            if isinstance(context, dict):
                _overrides = context.get('pipeline_context', {}) or context.get('overrides') or context.get('options', {}).get('overrides')
        except Exception:
            _overrides = None
        if _overrides:
            try:
                result = DEFAULT_CLIENT.generate(prompt, model=model, max_tokens=max_tokens, overrides=_overrides)
            except Exception as exc:
                # If an override was provided but the override path failed, surface an HTTP error
                logger.exception('LLM override generation failed: %s', exc)
                raise HTTPException(status_code=503, detail=f"LLM override failed: {str(exc)}")
        else:
            result = DEFAULT_CLIENT.generate(prompt, model=model, max_tokens=max_tokens)
        if isinstance(result, dict):
            return result.get('text') or result.get('content')
        return str(result)
    except HTTPException:
        # re-raise HTTP exceptions generated above
        raise
    except Exception as exc:  # pragma: no cover - just log
        logger.warning('LLM generation failed: %s', exc)
        return None


def _get_tenant_business_context(tenant_id: str | None, context: Dict[str, Any] | None = None) -> str:
    """Return a single formatted line of business context for LLM prompts.

    Reads from (in priority order):
      1. context dict keys: industry, regulatory_scope, revenue_tier
      2. Tenant-scoped env vars: TENANT_<ID>_INDUSTRY / REGULATORY_SCOPE / REVENUE_TIER
      3. Global defaults:       TENANT_DEFAULT_INDUSTRY / REGULATORY_SCOPE / REVENUE_TIER

    Returns an empty string when no context is available so callers can skip it.
    """
    ctx = context or {}
    tid = (tenant_id or '').upper().replace('-', '_')

    def _get(key: str) -> str:
        # 1. inline context
        val = ctx.get(key.lower()) or ctx.get(key)
        if val:
            return str(val)
        # 2. tenant-scoped env
        if tid:
            val = os.getenv(f'TENANT_{tid}_{key.upper()}')
            if val:
                return val
        # 3. global default
        return os.getenv(f'TENANT_DEFAULT_{key.upper()}', '')

    industry = _get('industry')
    regulatory = _get('regulatory_scope')
    revenue = _get('revenue_tier')

    parts = []
    if industry:
        parts.append(f'Industry: {industry}')
    if regulatory:
        parts.append(f'Regulatory: {regulatory}')
    if revenue:
        parts.append(f'Revenue Tier: {revenue}')
    return ' | '.join(parts)


def _generate_dread(row: Dict[str, Any], context: Dict[str, Any]) -> tuple[str, str]:
    proc = row.get('process_name') or row.get('name') or 'unknown process'
    host = row.get('host') or 'unknown host'
    score = context.get('dread_score') or (context.get('dread') or {}).get('score') or 7.0
    mitre = context.get('mitre_tags') or row.get('mitre_tags') or []
    tenant_id = context.get('tenant_id') or context.get('org') or row.get('tenant_id')
    biz_ctx = _get_tenant_business_context(tenant_id, context)
    biz_line = f'BUSINESS CONTEXT: {biz_ctx}\n' if biz_ctx else ''
    prompt = (
        "You are a SOC risk analyst. Produce exactly three DREAD scenarios.\n"
        f"{biz_line}"
        f"Process: {proc}\nHost: {host}\nDREAD Score: {score}/10\n"
        f"MITRE Techniques: {', '.join(mitre[:3]) or 'unknown'}\n"
        "Format each scenario as:\n"
        "SCENARIO X: <Title>\n"
        "Damage: <1-10> - ...\n"
        "Reproducibility: <1-10> - ...\n"
        "Exploitability: <1-10> - ...\n"
        "Affected Users: <1-10> - ...\n"
        "Discoverability: <1-10> - ...\n"
        "Total DREAD: <value>\n"
    )
    llm_text = _llm_generate(prompt, model='gpt-4o-mini', max_tokens=800, context=context)
    if llm_text:
        return llm_text, 'gpt-4o-mini'
    fallback = (
        f"SCENARIO 1: Credential Theft via {proc}\n"
        "Damage: 8 - Compromised admin credentials enable lateral movement.\n"
        "Reproducibility: 7 - Technique documented in multiple playbooks.\n"
        "Exploitability: 6 - Requires user context but no privilege escalation.\n"
        "Affected Users: 8 - Domain-wide blast radius.\n"
        "Discoverability: 5 - Requires memory artefact review.\n"
        "Total DREAD: 6.8\n\n"
        "SCENARIO 2: Living-off-the-Land Persistence\n"
        "Damage: 7 - Establishes scheduled tasks for beaconing.\n"
        "Reproducibility: 6 - LOLBAS techniques widely available.\n"
        "Exploitability: 5 - Needs initial foothold but no exploits.\n"
        "Affected Users: 6 - Impacts shared workstation pools.\n"
        "Discoverability: 4 - Blends with legitimate admin activity.\n"
        "Total DREAD: 5.6\n\n"
        "SCENARIO 3: Data Exfiltration via HTTPS Tunnel\n"
        "Damage: 9 - Sensitive archives pulled from the host.\n"
        "Reproducibility: 5 - Requires staging and C2 infrastructure.\n"
        "Exploitability: 6 - TLS hides payload.\n"
        "Affected Users: 7 - Impacts business unit owning the host.\n"
        "Discoverability: 5 - Needs packet capture or proxy logs.\n"
        "Total DREAD: 6.4"
    )
    return fallback, 'rule-based'


def _generate_tier1_summary(row: Dict[str, Any], domain: str, context: Dict[str, Any]) -> tuple[str, str, Dict[str, Any]]:
    ctx = context or {}
    text = ''
    model = 'fallback-tier1'
    # gating: check triage score and budget before calling LLM to avoid unnecessary spend
    try:
        min_triage = float(os.getenv('LLM_T1_MIN_TRIAGE', '0.15'))
    except Exception:
        min_triage = 0.15
    try:
        triage = float(row.get('triage_score') or 0.0)
    except Exception:
        triage = 0.0
    # simple budget check (optional): if set, we treat it as max total cost per assessment
    try:
        budget = float(os.getenv('LLM_BUDGET_PER_ASSESSMENT', '0'))
    except Exception:
        budget = 0.0
    if budget > 0.0 and ctx.get('assessment_id'):
        try:
            # best-effort check: if cost already > budget, skip
            existing_cost = float(ctx.get('existing_llm_cost') or 0.0)
            if existing_cost >= budget:
                payload = _compose_tier1_payload(row, domain, ctx, model, '')
                payload['llm_skipped_reason'] = 'budget_exhausted'
                # include weighted confidence hint
                payload['weighted_confidence'] = _derive_confidence_score(row)
                return '', model, payload
        except Exception:
            pass
    if triage < min_triage:
        payload = _compose_tier1_payload(row, domain, ctx, model, '')
        payload['llm_skipped_reason'] = 'below_severity_threshold'
        payload['weighted_confidence'] = _derive_confidence_score(row)
        return '', model, payload
    # DREAD gate — skip LLM when both DREAD and confidence are below thresholds
    # Set LLM_T1_MIN_DREAD (default 0 = disabled) and LLM_T1_DREAD_CONF_OVERRIDE to tune
    try:
        _min_dread = float(os.getenv('LLM_T1_MIN_DREAD', '0'))
    except Exception:
        _min_dread = 0.0
    if _min_dread > 0:
        _dread_val = float(
            (row.get('_dread') or {}).get('score')
            or (row.get('_dread') or {}).get('composite')
            or row.get('dread')
            or 0
        )
        _conf = _derive_confidence_score(row)
        try:
            _conf_override = float(os.getenv('LLM_T1_DREAD_CONF_OVERRIDE', '0.85'))
        except Exception:
            _conf_override = 0.85
        # OR gate: skip only when BOTH dread and confidence are below their respective floors
        if _dread_val < _min_dread and _conf < _conf_override:
            payload = _compose_tier1_payload(row, domain, ctx, model, '')
            payload['llm_skipped_reason'] = f'below_dread_threshold(dread={round(_dread_val,1)}<{_min_dread},conf={round(_conf,2)}<{_conf_override})'
            payload['weighted_confidence'] = _conf
            return '', model, payload
    # compute triage score early so gating and payloads can use it
    try:
        tri_inputs = {'dread': (row.get('_dread') or {}).get('score') or row.get('dread'),
                      'correlation': row.get('_pipeline_confidence') or row.get('correlation') or 0.0,
                      'density': row.get('factor_density') or 0.0,
                      'confidence': _derive_confidence_score(row),
                      'rarity': row.get('_rarity') or 0.0}
        tri = compute_triage_score(tri_inputs)
        row['triage_score'] = tri.get('triage_score')
        row['_triage_breakdown'] = tri.get('breakdown')
        row['_triage_weights'] = tri.get('weights')
    except Exception:
        pass

    if _TIER1_CLIENT:
        tier1_ctx = {
            'tier': 'tier1',
            'org': ctx.get('org') or 'insights-service',
            'pipeline_context': ctx,
        }
        # Inject business context so the LLM can frame risk in business terms
        _biz_ctx = _get_tenant_business_context(ctx.get('tenant_id') or ctx.get('org') or row.get('tenant_id'), ctx)
        if _biz_ctx:
            tier1_ctx['business_context'] = _biz_ctx
        if ctx.get('overrides'):
            tier1_ctx['overrides'] = ctx.get('overrides')
        try:
            # Prepend persona-specific instruction fragment when provided
            persona = None
            try:
                persona = (ctx.get('pipeline_context') or {}).get('persona') or ctx.get('persona')
            except Exception:
                persona = None
            if persona:
                persona_prompt = render_persona_prompt(persona, { 'verdict': row.get('verdict'), 'triage_score': row.get('triage_score'), 'factors': row.get('factors') })
                tier1_ctx['persona_prompt'] = persona_prompt
            result = _TIER1_CLIENT.summarize_row(row, tier1_ctx)
            if isinstance(result, dict):
                text = (result.get('text') or '').strip()
                model = result.get('model') or (result.get('meta') or {}).get('model') or model
        except Exception as exc:
            logger.warning('Tier 1 summarize_row failed: %s', exc)
    if not text:
        proc = row.get('process_name') or row.get('image') or 'unknown process'
        host = row.get('host') or row.get('device') or 'unknown host'
        verdict = (row.get('verdict') or 'suspicious').upper()
        dread_score = (row.get('_dread') or {}).get('score') or (row.get('_dread') or {}).get('composite') or row.get('dread') or 0
        signals = ', '.join(row.get('factors') or row.get('signals') or [])
        tenant_id = context.get('tenant_id') or context.get('org') or row.get('tenant_id')
        biz_ctx = _get_tenant_business_context(tenant_id, context)
        biz_line = f'\nBUSINESS CONTEXT: {biz_ctx}' if biz_ctx else ''
        dread_rationale = _build_dread_rationale(row)
        rationale_block = f'\n{dread_rationale}' if dread_rationale else f'\nDREAD composite: {dread_score}'
        mitre_tags = ', '.join(_normalize_mitre(row)[:3]) or 'unknown'
        prompt = (
            "You are a SOC analyst performing FAST TRIAGE. Follow this schema exactly:\n"
            "1. WHAT IS IT (1 sentence, non-technical — what happened in plain English)\n"
            "2. WHY IT MATTERS (1 sentence — business/user impact based on evidence below)\n"
            "3. WHAT TO DO NEXT (2-3 bullet points — specific, actionable, prioritised)\n"
            "Ground every statement in the evidence provided. Avoid filler phrases.\n"
            f"\nProcess: {proc}\nHost: {host}\nVerdict: {verdict}\nDomain: {domain}\n"
            f"MITRE: {mitre_tags}\nSignals: {signals or 'none'}{rationale_block}{biz_line}"
        )
        llm_text = _llm_generate(prompt, model='gpt-4o-mini', max_tokens=400, context=context)
        if llm_text:
            text = llm_text.strip()
            model = 'gpt-4o-mini'
    if not text:
        text = _build_tier1_fallback(row)
        model = 'fallback-tier1'
    payload = _compose_tier1_payload(row, domain, ctx, model, text)
    # Attach persona validation checks when persona-like text present in raw_summary or model output
    try:
        checks = []
        # prefer payload.raw_summary then text
        candidate_text = payload.get('raw_summary') or text or ''
        if isinstance(candidate_text, str) and candidate_text.strip():
            parsed = parse_persona_text(candidate_text)
            valid, errors = validate_parsed_persona(parsed)
            checks.append({'ok': bool(valid), 'errors': errors, 'confidence': parsed.get('confidence', 0.0), 'parsed_from_json': parsed.get('parsed_from_json', False)})
        # also scan any persona fragments in payload.playbook.summary
        try:
            pb = payload.get('playbook', {}) or {}
            ps = pb.get('summary')
            if isinstance(ps, str) and ps.strip():
                p2 = parse_persona_text(ps)
                v2, e2 = validate_parsed_persona(p2)
                checks.append({'ok': bool(v2), 'errors': e2, 'confidence': p2.get('confidence', 0.0), 'source': 'playbook_summary'})
        except Exception:
            pass
        if checks:
            payload.setdefault('validation', {})
            payload['validation']['persona_text_checks'] = checks
    except Exception:
        pass
    return text, model, payload


def _generate_tier2_summary(row: Dict[str, Any], context: Dict[str, Any]) -> tuple[str, str, Dict[str, Any]]:
    ctx = context or {}
    # ensure triage exists for tier2 enrichment
    try:
        tri_inputs = {'dread': (row.get('_dread') or {}).get('score') or row.get('dread'),
                      'correlation': row.get('_pipeline_confidence') or row.get('correlation') or 0.0,
                      'density': row.get('factor_density') or 0.0,
                      'confidence': _derive_confidence_score(row),
                      'rarity': row.get('_rarity') or 0.0}
        tri = compute_triage_score(tri_inputs)
        row['triage_score'] = tri.get('triage_score')
        row['_triage_breakdown'] = tri.get('breakdown')
    except Exception:
        pass
    tier2_ctx = {
        'tier': 'tier2',
        'org': ctx.get('org') or 'insights-service',
        'pipeline_context': ctx.get('pipeline_context') or ctx,
        'gated_domain': ctx.get('gated_domain'),
        'domain_confidence': ctx.get('domain_confidence'),
    }
    # Inject business context so the LLM can tailor risk framing to the tenant's industry/regulatory scope
    _biz_ctx = _get_tenant_business_context(ctx.get('tenant_id') or ctx.get('org') or row.get('tenant_id'), ctx)
    if _biz_ctx:
        tier2_ctx['business_context'] = _biz_ctx
    if ctx.get('overrides'):
        tier2_ctx['overrides'] = ctx.get('overrides')
    text = ''
    model = 'unknown'
    payload: Dict[str, Any] | None = None
    if _TIER1_CLIENT:
        try:
            persona = None
            try:
                persona = (ctx.get('pipeline_context') or {}).get('persona') or ctx.get('persona')
            except Exception:
                persona = None
            if persona:
                persona_prompt = render_persona_prompt(persona, { 'verdict': row.get('verdict'), 'triage_score': row.get('triage_score'), 'factors': row.get('factors') })
                tier2_ctx['persona_prompt'] = persona_prompt
            result = _TIER1_CLIENT.summarize_row(row, tier2_ctx)
        except Exception as exc:
            logger.warning('Tier 2 summarize_row failed: %s', exc)
            result = None
        if isinstance(result, dict):
            text = (result.get('text') or result.get('tier2_summary') or '').strip()
            model = result.get('model') or (result.get('meta') or {}).get('model') or model
            payload = result.get('payload')
    if not payload:
        payload = _compose_tier2_payload(row, tier2_ctx, text)
    # Attach persona validation metadata when available
    try:
        checks = []
        cand = None
        # priority: payload entries that look like persona text
        if isinstance(text, str) and text.strip():
            cand = text
        elif isinstance(payload, dict):
            # check for executive_summary.one_liner or ai_reasoning.primary_hypothesis
            cand = payload.get('executive_summary', {}).get('one_liner') or payload.get('ai_reasoning', {}).get('primary_hypothesis')
        if isinstance(cand, str) and cand.strip():
            p = parse_persona_text(cand)
            ok, errs = validate_parsed_persona(p)
            checks.append({'ok': bool(ok), 'errors': errs, 'confidence': p.get('confidence', 0.0), 'parsed_from_json': p.get('parsed_from_json', False)})
        if checks:
            payload.setdefault('validation', {})
            payload['validation']['persona_text_checks'] = checks
    except Exception:
        pass
    if not text:
        try:
            text = json.dumps(payload, indent=2)
        except Exception:
            text = 'Tier 2 summary unavailable.'
    return text, model, payload


# Instrumentation for Tier2 batch jobs
try:
    from src.api.metrics_init import ensure_metrics, _safe_counter, _safe_hist
    ensure_metrics()
    TIER2_REQUESTS = _safe_counter('tier2_requests_total', 'Tier2 batch requests', ['outcome'])
    TIER2_COMPLETED = _safe_counter('tier2_completed_total', 'Tier2 completed rows', None)
    TIER2_LATENCY = _safe_hist('tier2_latency_seconds', 'Latency of tier2 batch (seconds)')
except Exception:
    TIER2_REQUESTS = TIER2_COMPLETED = TIER2_LATENCY = None


@router.post('/tier2/enrich_batch')
async def tier2_enrich_batch(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Accept a batch of rows and return tier2 payloads for each row.

    Payload: { assessment_id?: str, rows: [{row_index, raw}], pipeline_context?: {} }
    """
    try:
        rows = payload.get('rows') or []
        ctx = payload.get('pipeline_context') or {}
        tenant_id = _resolve_tenant(request, payload.get('tenant_id') or ctx.get('tenant') or ctx.get('tenant_id'))
        start = time.time()
        out = []
        for r in rows:
            row = r.get('raw') if isinstance(r, dict) else r
            _enforce_row_tenant(request, row if isinstance(row, dict) else {}, {'tenant_id': tenant_id, **(ctx if isinstance(ctx, dict) else {})})
            try:
                text, model, pl = _generate_tier2_summary(row, {**ctx, 'assessment_id': payload.get('assessment_id')})
                out.append({'row_index': r.get('row_index'), 'text': text, 'model': model, 'payload': pl})
                try:
                    if TIER2_COMPLETED: TIER2_COMPLETED.labels().inc(1)
                except Exception:
                    pass
            except Exception as ex:
                out.append({'row_index': r.get('row_index'), 'error': str(ex)})
        duration = time.time() - start
        try:
            if TIER2_LATENCY: TIER2_LATENCY.labels().observe(duration)
            if TIER2_REQUESTS: TIER2_REQUESTS.labels(outcome='ok').inc(1)
        except Exception:
            pass
        return {'assessment_id': payload.get('assessment_id'), 'rows': out, 'duration': duration}
    except Exception as exc:
        try:
            if TIER2_REQUESTS: TIER2_REQUESTS.labels(outcome='error').inc(1)
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f'tier2_error:{exc}') from exc


# Simple in-memory Tier2 job queue and worker (with optional Redis-backed queue)
TIER2_JOBS: Dict[str, Dict[str, Any]] = {}

# Try to import optional Redis queue helper
_REDIS_QUEUE_AVAILABLE = False
try:
    from src.queue import redis_tier2 as redis_tier2
    _REDIS_QUEUE_AVAILABLE = True
except Exception:
    redis_tier2 = None
    _REDIS_QUEUE_AVAILABLE = False


def _tier2_jobs_dir() -> str:
    base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data', 'sessions')
    out = os.path.join(base, 'tier2_jobs')
    try:
        os.makedirs(out, exist_ok=True)
    except Exception:
        pass
    return out


def _persist_tier2_job(job_id: str) -> None:
    try:
        out = _tier2_jobs_dir()
        path = os.path.join(out, f"{job_id}.json")
        with open(path + '.tmp', 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(TIER2_JOBS.get(job_id) or {}))
        os.replace(path + '.tmp', path)
    except Exception:
        pass


def _load_persisted_tier2_jobs():
    try:
        out = _tier2_jobs_dir()
        for fn in os.listdir(out):
            if not fn.endswith('.json'):
                continue
            path = os.path.join(out, fn)
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                jid = data.get('job_id') or os.path.splitext(fn)[0]
                TIER2_JOBS[jid] = data
            except Exception:
                continue
    except Exception:
        pass


# cleanup loop to prune old jobs
async def _tier2_cleanup_loop(interval_seconds: int = 300, ttl_seconds: int = 3600):
    try:
        while True:
            try:
                now = int(time.time())
                for jid, job in list(TIER2_JOBS.items()):
                    created = job.get('created_at') or now
                    if job.get('status') in ('completed', 'cancelled', 'failed') and (now - created) > ttl_seconds:
                        try:
                            # remove persisted file
                            path = os.path.join(_tier2_jobs_dir(), f"{jid}.json")
                            if os.path.exists(path):
                                os.remove(path)
                        except Exception:
                            pass
                        try:
                            del TIER2_JOBS[jid]
                        except Exception:
                            pass
            except Exception:
                pass
            try:
                await asyncio.sleep(interval_seconds)
            except Exception:
                # if sleep is interrupted, continue loop
                continue
    except Exception:
        pass


# Load persisted jobs on import
try:
    _load_persisted_tier2_jobs()
except Exception:
    pass

# Start cleanup loop if event loop available (best-effort non-blocking)
try:
    interval = int(os.getenv('TIER2_CLEAN_INTERVAL', '300'))
except Exception:
    interval = 300
if interval and interval > 0:
    try:
        # Avoid starting long-running cleanup loops during pytest or lite tests
        _is_test = ('PYTEST_CURRENT_TEST' in os.environ) or (os.getenv('TEST_HELPERS_ENABLED','0').lower() in {'1','true','yes'}) or os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'}
    except Exception:
        _is_test = False
    if not _is_test:
        try:
            loop = asyncio.get_event_loop()
            try:
                t = loop.create_task(_tier2_cleanup_loop(interval, int(os.getenv('TIER2_JOB_TTL', '3600'))))
                # register task into global BACKGROUND_TASKS so lifespan shutdown can cancel/await it
                try:
                    from src.api.server import BACKGROUND_TASKS
                    BACKGROUND_TASKS.add(t)
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass


async def _run_tier2_job(job_id: str):
    job = TIER2_JOBS.get(job_id) or {}
    if not job:
        return
    job['status'] = 'running'
    TIER2_JOBS[job_id] = job
    _persist_tier2_job(job_id)
    try:
        rows = job.get('rows') or []
        results = []
        for r in rows:
            if TIER2_JOBS.get(job_id, {}).get('cancel_requested'):
                job['status'] = 'cancelled'
                TIER2_JOBS[job_id] = job
                _persist_tier2_job(job_id)
                return
            try:
                text, model, pl = _generate_tier2_summary(r.get('raw') if isinstance(r, dict) else r, job.get('pipeline_context') or {})
                results.append({'row_index': r.get('row_index'), 'model': model, 'payload': pl})
            except Exception as ex:
                results.append({'row_index': r.get('row_index'), 'error': str(ex)})
        job['results'] = results
        job['status'] = 'completed'
        TIER2_JOBS[job_id] = job
        _persist_tier2_job(job_id)
    except Exception:
        job['status'] = 'failed'
        TIER2_JOBS[job_id] = job
        _persist_tier2_job(job_id)


@router.post('/tier2/enqueue')
async def tier2_enqueue(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    try:
        import uuid
        job_id = payload.get('job_id') or str(uuid.uuid4())
        tenant_id = _resolve_tenant(request, payload.get('tenant_id') or payload.get('tenant') or (payload.get('pipeline_context') or {}).get('tenant') or (payload.get('pipeline_context') or {}).get('tenant_id'))
        for r in (payload.get('rows') or []):
            row = r.get('raw') if isinstance(r, dict) else r
            _enforce_row_tenant(request, row if isinstance(row, dict) else {}, {'tenant_id': tenant_id})
        job = {
            'job_id': job_id,
            'status': 'queued',
            'rows': payload.get('rows') or [],
            'pipeline_context': payload.get('pipeline_context') or {},
            'created_at': int(time.time()),
            'tenant_id': tenant_id,
        }
        # If Redis queue available, enqueue there for multi-worker handling
        if _REDIS_QUEUE_AVAILABLE:
            try:
                redis_tier2.enqueue(job_id, job)
                # persist local view for status tracking as well
                TIER2_JOBS[job_id] = job
                _persist_tier2_job(job_id)
                return {'job_id': job_id, 'status': 'queued', 'via': 'redis'}
            except Exception:
                # fallback to filesystem/in-memory
                pass

        # Default fallback: persist and schedule in-process worker
        TIER2_JOBS[job_id] = job
        _persist_tier2_job(job_id)
        # schedule background worker
        loop = asyncio.get_event_loop()
        loop.create_task(_run_tier2_job(job_id))
        return {'job_id': job_id, 'status': 'queued', 'via': 'inprocess'}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'enqueue_failed:{exc}') from exc


@router.get('/tier2/{job_id}/status')
async def tier2_job_status(job_id: str, request: Request) -> Dict[str, Any]:
    job = TIER2_JOBS.get(job_id)
    if not job:
        return {'job_id': job_id, 'status': 'not_found'}
    _resolve_tenant(request, job.get('tenant_id'))
    return job


@router.post('/tier2/{job_id}/stop')
async def tier2_job_stop(job_id: str, request: Request) -> Dict[str, Any]:
    job = TIER2_JOBS.get(job_id)
    if not job:
        return {'job_id': job_id, 'status': 'not_found'}
    _resolve_tenant(request, job.get('tenant_id'))
    job['cancel_requested'] = True
    job['status'] = 'stopping'
    TIER2_JOBS[job_id] = job
    # If Redis queue available, update Redis-backed job state key as well
    try:
        if _REDIS_QUEUE_AVAILABLE and redis_tier2:
            try:
                # load persisted job from redis and set cancel flag
                raw_key = redis_tier2._JOB_KEY_PREFIX + job_id  # type: ignore[attr-defined]
                try:
                    # using the underlying client to set cancel flag
                    client = redis_tier2._redis_client  # type: ignore[attr-defined]
                    if client:
                        rv = client.get(raw_key)
                        if rv:
                            try:
                                obj = json.loads(rv)
                                obj['cancel_requested'] = True
                                obj['status'] = 'stopping'
                                client.set(raw_key, json.dumps(obj))
                            except Exception:
                                pass
                except Exception:
                    pass
            except Exception:
                pass
    except Exception:
        pass
    return {'job_id': job_id, 'status': 'stopping'}


def _generate_playbook(row: Dict[str, Any], domain: str) -> str:
    host = row.get('host') or 'unknown host'
    sha256 = row.get('sha256') or 'unknown hash'
    base = [
        f"1. Isolate {host} from the network or containment VLAN.",
        "2. Capture a memory image (FTK Imager or Velociraptor) prior to reboot.",
        f"3. Collect process tree + command line for {row.get('process_name') or 'the suspicious binary'}",
        f"4. Hash verification: compare {sha256} against VirusTotal / internal IOC store."
    ]
    if domain == 'network':
        base.extend(
            [
                "5. Pull DNS, proxy, and firewall logs for the source IP covering the last 24h.",
                "6. Run Zeek intel::seen analysis for destinations contacted by the host.",
                "7. Push indicators to perimeter block-lists once confirmed.",
            ]
        )
    elif domain == 'endpoint':
        base.extend(
            [
                "5. Export Sysmon Event IDs 1, 10, 13, 22 from the past hour.",
                "6. Run KAPE triage package (RegistryHives, Amcache, Shimcache).",
                "7. Use Velociraptor's Windows.Timeline artifact to pivot through execution ancestry.",
            ]
        )
    else:
        base.extend(
            [
                "5. Confirm whether alert originated from SaaS, identity, or workload telemetry.",
                "6. Collect raw JSON payload from upstream detector for attachment to the incident.",
            ]
        )
    base.append("8. Document containment outcome and analyst notes in the incident tracker.")
    return "\n".join(base)


def _generate_hunt_queries(row: Dict[str, Any], domain: str) -> str:
    indicator = row.get('sha256') or row.get('process_name') or row.get('domain') or 'indicator'
    user = row.get('user') or '<user>'
    host = row.get('host') or '<host>'
    kql = (
        f"// KQL\n"
        f"DeviceProcessEvents\n"
        f"| where InitiatingProcessSHA256 == '{indicator}' or InitiatingProcessFileName =~ '{row.get('process_name','')}'\n"
        f"| where AccountName =~ '{user}' or DeviceName =~ '{host}'\n"
        f"| summarize count(), min(Timestamp), max(Timestamp) by DeviceName, AccountName\n"
    )
    spl = (
        f"// Splunk\n"
        f"index=edr sourcetype=sysmon EventCode=1\n"
        + (f"| eval suspect=if(sha256=='{indicator}' OR process=='{row.get('process_name','')}',1,0)\n"
           if indicator or row.get('process_name') else "| eval suspect=0\n")
        + "| search suspect=1\n"
        + "| stats values(command_line) as cmd by host, user"
    )
    sigma = (
        f"// Sigma snippet\n"
        "title: Suspicious LOLBAS execution\n"
        "logsource:\n  product: windows\n  service: sysmon\n"
        f"detection:\n  selection:\n    Image|endswith: '\\\\{row.get('process_name','')}'\n"
        "    CommandLine|contains: 'EncodedCommand'\n  condition: selection"
    )
    if domain == 'network':
        kql += "\n// Add network focus\nDeviceNetworkEvents | where RemoteUrl has '185.220.' or RemoteIP in watchlist('c2_ips')"
    return "\n\n".join([kql, spl, sigma])


def _generate_executive_summary(row: Dict[str, Any], domain: str, context: Optional[Dict[str, Any]] = None) -> tuple[str, str]:
    verdict = (row.get('verdict') or 'suspicious').upper()
    host = row.get('host') or 'unknown host'
    summary_prompt = (
        "You are briefing a CISO in two short paragraphs. "
        f"The alert is classified as {verdict} on {host}. "
        f"Domain context: {domain}. Highlight business impact, recommended action, and risk if ignored."
    )
    llm_text = _llm_generate(summary_prompt, model='gpt-4o-mini', max_tokens=300, context=context)
    if llm_text:
        # attach persona validation metadata by returning as payload in a tuple-like shape
        # Executive path returns text, model — validation will be attached at callsite
        return llm_text, 'gpt-4o-mini'
    fallback = (
        f"{verdict} activity observed on {host}. "
        "Telemetry indicates possible credential abuse and outbound command-and-control beacons. "
        "Immediate isolation and full disk triage recommended.\n\n"
        "If ignored, attacker maintains persistence, moves laterally, and may exfiltrate privileged data. "
        "Containment within 30 minutes preserves forensic artefacts and limits blast radius."
    )
    return fallback, 'rule-based'


def _auto_commit_tier1_incident(
    row: Dict[str, Any],
    text: str,
    model: str,
    payload: Dict[str, Any],
    context: Dict[str, Any],
) -> None:
    """Persist a Tier-1 result as an incident when confidence or DREAD is high enough.

    Gate: confidence >= LLM_T1_INCIDENT_MIN_CONFIDENCE (default 0.7)
          OR dread_score >= LLM_T1_INCIDENT_MIN_DREAD   (default 7.0)
    Controlled by env:
      LLM_T1_INCIDENT_MIN_CONFIDENCE  — float 0-1 (default 0.7)
      LLM_T1_INCIDENT_MIN_DREAD       — float 0-10 (default 7.0)
      LLM_T1_INCIDENT_AUTO_COMMIT=1   — master switch (default: enabled)
    """
    try:
        auto_commit = os.getenv('LLM_T1_INCIDENT_AUTO_COMMIT', '1').lower() not in ('0', 'false', 'no')
        if not auto_commit:
            return

        min_conf = float(os.getenv('LLM_T1_INCIDENT_MIN_CONFIDENCE', '0.7'))
        min_dread = float(os.getenv('LLM_T1_INCIDENT_MIN_DREAD', '7.0'))

        confidence = float(payload.get('confidence') or payload.get('metadata', {}).get('confidence_score') or 0.0)
        dread_score = float(
            (payload.get('verdict') or {}).get('dread_score')
            or (row.get('_dread') or {}).get('score')
            or row.get('dread')
            or 0.0
        )
        skipped = payload.get('llm_skipped_reason')
        if skipped or (confidence < min_conf and dread_score < min_dread):
            return  # below threshold — skip

        import time as _time
        import uuid as _uuid

        from src.api.incidents_store import INCIDENT_STORE

        tenant_id = (
            context.get('tenant_id')
            or context.get('org')
            or row.get('tenant_id')
            or 'default'
        )
        verdict_payload = payload.get('verdict') or {}
        incident: Dict[str, Any] = {
            'incident_id': f'tier1-{_uuid.uuid4().hex[:12]}',
            'source': 'tier1_auto',
            'tenant_id': tenant_id,
            'created_at': _time.time(),
            'title': (
                f"{row.get('process_name') or row.get('name') or 'Alert'} "
                f"on {row.get('host') or 'unknown host'} "
                f"[{(verdict_payload.get('classification') or 'UNKNOWN').upper()}]"
            ),
            'severity': (
                'critical' if dread_score >= 9.0
                else 'high' if dread_score >= 7.0 or confidence >= 0.85
                else 'medium'
            ),
            'confidence': confidence,
            'dread_score': dread_score,
            'tier1_summary': text,
            'model': model,
            'factors': row.get('factors') or [],
            'mitre_techniques': verdict_payload.get('mitre_techniques') or [],
            'host': row.get('host'),
            'user': row.get('user'),
            'process': row.get('process_name'),
            'payload_snapshot': {
                k: v for k, v in (payload or {}).items()
                if k in ('metadata', 'verdict', 'top_factors', 'why_flagged', 'playbook', 'evidence_summary')
            },
            'recommendation_actions': [
                {
                    'id': f'tier1|review|{row.get("host","unknown")}',
                    'domain': 'endpoint',
                    'action': 'review_tier1_alert',
                    'priority': 'high' if dread_score >= 7.0 else 'medium',
                    'status': 'pending',
                    'updated_ts': _time.time(),
                }
            ],
        }

        # Cap incidents store at 1000 entries to avoid unbounded growth
        INCIDENT_STORE.append(incident)
        if len(INCIDENT_STORE) > 1000:
            del INCIDENT_STORE[:-1000]

        logger.debug(
            'Tier-1 auto-committed incident %s (confidence=%.2f dread=%.1f)',
            incident['incident_id'], confidence, dread_score,
        )
    except Exception as exc:
        logger.debug('Tier-1 auto-commit failed (non-fatal): %s', exc)


@router.post('/generate', response_model=InsightResponse, operation_id='insights_generate')
@require_roles('analyst','admin')
async def generate_insight(request: Request = None) -> InsightResponse:
    # Support both Pydantic-backed InsightRequest and raw Starlette `Request` passed
    # through the `require_roles` wrapper (which sometimes forwards `Request`).
    row = {}
    context = {}
    insight_type = None
    try:
        # If this is a real Starlette Request, it has an async json() method
        if request is not None and hasattr(request, 'json') and callable(getattr(request, 'json')):
            try:
                body = await request.json()
            except Exception:
                body = {}
            row = body.get('row') or {}
            context = body.get('pipeline_context') or row.get('pipeline_context') or {}
            insight_type = body.get('insight_type')
        else:
            # Likely a Pydantic InsightRequest instance
            row = (request.row if request is not None and hasattr(request, 'row') else {}) or {}
            context = (request.pipeline_context if request is not None and hasattr(request, 'pipeline_context') else None) or row.get('pipeline_context') or {}
            insight_type = getattr(request, 'insight_type', None) if request is not None else None
    except Exception:
        row = {}
        context = {}
        insight_type = None
    domain, _confidence = detect_domain_with_confidence(row)
    try:
        _enforce_row_tenant(request, row if isinstance(row, dict) else {}, context if isinstance(context, dict) else {})
    except HTTPException:
        raise
    except Exception:
        pass

    if insight_type == 'tier1':
        text, model, payload = _generate_tier1_summary(row, domain, context)
        # Auto-persist high-confidence Tier-1 results to the incidents store
        _auto_commit_tier1_incident(row, text, model, payload, context)
        return InsightResponse(text=text, insight_type='tier1', estimated_cost=0.0006, model=model, payload=payload)
    if insight_type == 'tier2':
        text, model, payload = _generate_tier2_summary(row, context)
        return InsightResponse(text=text, insight_type='tier2', estimated_cost=0.015, model=model, payload=payload)
    if insight_type == 'dread':
        text, model = _generate_dread(row, context)
        return InsightResponse(text=text, insight_type='dread', estimated_cost=0.001, model=model)
    if insight_type == 'playbook':
        text = _generate_playbook(row, domain)
        return InsightResponse(text=text, insight_type='playbook', estimated_cost=0.0, model='rules')
    if insight_type == 'hunt':
        text = _generate_hunt_queries(row, domain)
        return InsightResponse(text=text, insight_type='hunt', estimated_cost=0.0008, model='rules')
    if insight_type == 'executive':
        text, model = _generate_executive_summary(row, domain, context)
        # Attach persona validation metadata into payload
        payload = {}
        try:
            checks = []
            if isinstance(text, str) and text.strip():
                p = parse_persona_text(text)
                ok, errs = validate_parsed_persona(p)
                checks.append({'ok': bool(ok), 'errors': errs, 'confidence': p.get('confidence', 0.0), 'parsed_from_json': p.get('parsed_from_json', False)})
            if checks:
                payload['validation'] = {'persona_text_checks': checks}
        except Exception:
            pass
        return InsightResponse(text=text, insight_type='executive', estimated_cost=0.0005, model=model, payload=payload or None)

    raise HTTPException(status_code=400, detail='unsupported_insight')
