from __future__ import annotations

import io
import time
import tempfile
import os
from fastapi import APIRouter, Request, Query, HTTPException
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse
from src.reporting.comprehensive_report_generator import build_report_html
from .tenant_helpers import resolve_tenant_id

from fastapi import APIRouter, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, PlainTextResponse
from fastapi.encoders import jsonable_encoder
from html import escape
from typing import Any
import json
import time
import hashlib
try:
    from src.reporting.email_summaries import tier1_summary, tier2_summary
except Exception:
    from ..reporting.email_summaries import tier1_summary, tier2_summary
try:
    from src.correlation.chain_builder import ChainBuilder
except Exception:
    ChainBuilder = None  # type: ignore
try:
    from src.connectors.email.click_persistence import fetch_recent_clicks
except Exception:
    fetch_recent_clicks = None  # type: ignore
try:
    # Prefer absolute import when running under normal package layout
    from src.reporting.comprehensive_report_generator import build_report_html
except Exception:
    # Fallback to relative import when package context is different (tests may import `api` as top-level)
    from ..reporting.comprehensive_report_generator import build_report_html
try:
    from src.api.report_aggregation import build_ingestion_report
    from src.api.dependencies import get_platform_state
except Exception:
    from .report_aggregation import build_ingestion_report  # type: ignore
    from .dependencies import get_platform_state  # type: ignore

try:
    from src.integrations.llm_client import generate_summary
except Exception:
    from ..integrations.llm_client import generate_summary
try:
    from src.reporting.llm_prompts import build_summary_prompt, parse_structured_summary
except Exception:
    from ..reporting.llm_prompts import build_summary_prompt, parse_structured_summary
try:
    from src.reporting.assessment_view_model import build_assessment_report_view
except Exception:
    from ..reporting.assessment_view_model import build_assessment_report_view  # type: ignore
try:
    from src.reporting.prompt_templates import build_incident_prompt as _build_incident_prompt
except Exception:
    try:
        from ..reporting.prompt_templates import build_incident_prompt as _build_incident_prompt  # type: ignore
    except Exception:
        _build_incident_prompt = None  # type: ignore
try:
    import bleach
    _HAS_BLEACH = True
except Exception:
    bleach = None
    _HAS_BLEACH = False
import io
import re

def _simple_sanitize(html: str) -> str:
    # Very small fallback sanitizer: remove script/style tags and on* attributes
    html = re.sub(r'(?is)<script.*?>.*?</script>', '', html)
    html = re.sub(r'(?is)<style.*?>.*?</style>', '', html)
    # remove on* attributes like onclick
    html = re.sub(r'\son\w+="[^"]*"', '', html)
    html = re.sub(r"\son\w+='[^']*'", '', html)
    return html

_STREAM_THRESHOLD = int(__import__('os').environ.get('REPORT_STREAM_THRESHOLD_BYTES', '16384'))

router = APIRouter()

# ── GRC compliance pre-fill: maps MITRE techniques → control frameworks ──────

_MITRE_CONTROL_MAP: dict[str, list[dict]] = {
    'T1110': [
        {'framework': 'ISO 27001', 'control': 'A.9.4.3', 'title': 'Password management system'},
        {'framework': 'NIST CSF',  'control': 'PR.AC-7', 'title': 'Users/devices authenticated commensurate with risk'},
        {'framework': 'SOC 2',     'control': 'CC6.1',   'title': 'Logical access security measures'},
        {'framework': 'Privacy Act 1988', 'control': 'Part IIIC NDB Scheme', 'title': '72h mandatory notification if credentials exfiltrated'},
    ],
    'T1621': [
        {'framework': 'ISO 27001', 'control': 'A.9.4.2', 'title': 'Secure log-on procedures — MFA required'},
        {'framework': 'NIST CSF',  'control': 'PR.AC-7', 'title': 'Adaptive MFA policy absent'},
        {'framework': 'SOC 2',     'control': 'CC6.1',   'title': 'MFA bypass not blocked by policy'},
    ],
    'T1114': [
        {'framework': 'ISO 27001', 'control': 'A.13.2.1', 'title': 'Information transfer policies'},
        {'framework': 'SOC 2',     'control': 'CC6.7',    'title': 'Transmission/disposal controls'},
        {'framework': 'GDPR',      'control': 'Art. 33',  'title': '72h supervisory authority notification'},
        {'framework': 'Privacy Act 1988', 'control': 'Part IIIC NDB Scheme', 'title': 'Notification if PI exfiltrated'},
    ],
    'T1567': [
        {'framework': 'ISO 27001', 'control': 'A.13.2.3', 'title': 'Electronic messaging controls'},
        {'framework': 'NIST CSF',  'control': 'DE.CM-1',  'title': 'Network communications monitored'},
        {'framework': 'SOC 2',     'control': 'CC7.2',    'title': 'System monitoring — data exfil detection'},
    ],
    'T1071': [
        {'framework': 'NIST CSF',  'control': 'DE.CM-1',  'title': 'Network monitored for C2'},
        {'framework': 'ISO 27001', 'control': 'A.13.1.1', 'title': 'Network controls — anomalous traffic'},
    ],
    'T1078': [
        {'framework': 'ISO 27001', 'control': 'A.9.2.3', 'title': 'Privileged access management'},
        {'framework': 'NIST CSF',  'control': 'PR.AC-4', 'title': 'Access permissions managed'},
        {'framework': 'SOC 2',     'control': 'CC6.3',   'title': 'Role-based access controls'},
    ],
    'T1059': [
        {'framework': 'CIS',       'control': 'CIS 4',   'title': 'Secure configuration of assets'},
        {'framework': 'NIST CSF',  'control': 'PR.PT-3', 'title': 'Principle of least functionality'},
    ],
}

_SABSA_LAYERS = [
    ('Contextual (Why)', 'Business drivers and risk appetite — what are the fiduciary duties and breach notification obligations?'),
    ('Conceptual (What)', 'Security policy intent — risk appetite for credential exposure and data exfiltration'),
    ('Logical (How)', 'Security services design — MFA policy, DLP rules, mail flow controls, alert thresholds'),
    ('Physical (With What)', 'Specific technology controls — Okta MFA, Exchange transport rules, SIEM correlation rules, NSG flow logs'),
    ('Component (Implementation)', 'Artefacts to evidence — BCC rule JSON, MFA event logs, DNS query logs, Defender telemetry'),
]


def _build_grc_prefill(assessment: dict) -> dict:
    """Build a GRC compliance pre-fill block from assessment data.

    First tries to pull the rich persona_dispatch.compliance payload from the
    lead breach cluster (populated by Stage 5d). Falls back to a simpler
    MITRE→controls mapping if dispatch data is unavailable.
    """
    # ── Prefer persona_dispatch.compliance from the lead cluster ─────────────
    for key in ('analysis_clusters', 'clusters', 'correlation_clusters'):
        for cluster in (assessment.get(key) or []):
            verdict = str(cluster.get('verdict') or cluster.get('final_verdict') or '').upper()
            if verdict not in ('VALIDATED_BREACH', 'CONFIRMED_BREACH', 'CONFIRMED_INTRUSION',
                               'LIKELY_BREACH', 'LIKELY_COMPROMISE'):
                continue
            pd = cluster.get('persona_dispatch') or {}
            comp = pd.get('compliance') or {}
            if comp.get('control_failures'):
                control_gaps = [
                    {
                        'technique': ', '.join(cf.get('triggered_by') or []),
                        'framework': cf.get('framework', ''),
                        'control': cf.get('control_id', ''),
                        'title': cf.get('control_name', ''),
                        'severity': cf.get('severity', ''),
                        'priority': cf.get('remediation_priority', ''),
                    }
                    for cf in comp['control_failures']
                ]
                reg_triggers = comp.get('regulatory_triggers') or []
                notification_triggers = [
                    (f"{t.get('name','')}: {t.get('rationale','')}"
                     + (f" (deadline: {t.get('clock_seconds', 0) // 3600}h)" if t.get('clock_seconds') else ''))
                    for t in reg_triggers
                ]
                isms = comp.get('isms_summary') or {}
                return {
                    'techniques': list({t for cf in comp['control_failures'] for t in (cf.get('triggered_by') or [])}),
                    'control_gaps': control_gaps,
                    'notification_triggers': notification_triggers,
                    'sabsa_layers': _SABSA_LAYERS,
                    'frameworks_triggered': list({cf.get('framework', '') for cf in comp['control_failures']}),
                    'total_business_impact_usd': comp.get('total_business_impact_usd', 0),
                    'impact_notes': comp.get('impact_notes') or [],
                    'cve_context': comp.get('cve_context') or {},
                    'cross_framework_evidence': comp.get('cross_framework_evidence') or {},
                    'auditor_insights': comp.get('auditor_insights') or [],
                    'remediation_roadmap': comp.get('remediation_roadmap') or {},
                    'isms_summary': isms,
                    'headline': comp.get('headline', ''),
                    'risk_register_entries': comp.get('risk_register_entries') or [],
                }

    # ── Fallback: infer MITRE from cluster data ────────────────────────────
    techniques: set[str] = set()
    for key in ('analysis_clusters', 'clusters', 'correlation_clusters'):
        for cluster in (assessment.get(key) or []):
            p = cluster.get('tier1_prefill') or {}
            for t in (p.get('mitre_techniques') or []):
                tid = str(t).upper()[:7].replace(' ', '').split('-')[0]
                if tid.startswith('T'):
                    techniques.add(tid)
            for t in (cluster.get('top_mitre') or []):
                tid = str(t).upper()[:7].replace(' ', '').split('-')[0]
                if tid.startswith('T'):
                    techniques.add(tid)
            if not techniques:
                try:
                    from src.analysis.framework_mapper import _infer_mitre_from_cluster
                    techniques.update(_infer_mitre_from_cluster(cluster))
                except Exception:
                    pass

    control_gaps = []
    seen_ctrl: set[str] = set()
    for tid in sorted(techniques):
        for t_prefix, controls in _MITRE_CONTROL_MAP.items():
            if tid.startswith(t_prefix):
                for ctrl in controls:
                    k2 = ctrl['framework'] + '|' + ctrl['control']
                    if k2 not in seen_ctrl:
                        seen_ctrl.add(k2)
                        control_gaps.append({'technique': tid, **ctrl})

    notification_triggers: list[str] = []
    verdict = str(assessment.get('verdict') or '').upper()
    if 'BREACH' in verdict or 'INTRUSION' in verdict or 'COMPROMISE' in verdict:
        notification_triggers.append('Privacy Act 1988 (Cth) Part IIIC — NDB Scheme: notify OAIC + affected individuals within 72 hours')
        notification_triggers.append('GDPR Art. 33 — Notify supervisory authority within 72 hours if EU personal data affected')
        notification_triggers.append('ASX Listing Rules 3.1 — Continuous disclosure if financially material')
        notification_triggers.append('SEC Rule 10b-5 / Form 8-K — Disclose if material to investors')

    return {
        'techniques': sorted(techniques),
        'control_gaps': control_gaps,
        'notification_triggers': notification_triggers,
        'sabsa_layers': _SABSA_LAYERS,
        'frameworks_triggered': sorted({c['framework'] for c in control_gaps}),
    }


def _parse_sessions_param(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [token.strip() for token in raw.split(',') if token.strip()]


def _parse_recipients(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [addr.strip() for addr in raw.split(',') if addr.strip()]


def _persona_from_variant(variant: str | None, override: str | None) -> str:
    if override:
        derived = override.strip().lower()
        if derived:
            return derived
    mapping = {
        'executive': 'executive',
        'exec': 'executive',
        'soc': 'soc_analyst',
        'soc_analyst': 'soc_analyst',
        'technical': 'soc_analyst',
        'hunter': 'threat_hunter',
        'threat_hunter': 'threat_hunter',
        'compliance': 'compliance',
        'mssp': 'soc_analyst',
    }
    key = (variant or '').strip().lower()
    return mapping.get(key, 'soc_analyst')


def _report_to_csv(report: dict[str, Any]) -> str:
    lines: list[str] = []
    meta = report.get('meta') or {}
    if meta.get('persona'):
        lines.append(f"persona,selected,{meta.get('persona')}")
    if meta.get('variant'):
        lines.append(f"persona,variant,{meta.get('variant')}")
    verdict_stats = report.get('verdict_stats') or {}
    for key, value in verdict_stats.items():
        lines.append(f"verdict_stats,{key},{value}")
    severity = report.get('severity_distribution') or {}
    for key, value in severity.items():
        lines.append(f"severity_distribution,{key},{value}")
    for item in report.get('top_mitre', []) or []:
        lines.append(f"top_mitre,{item.get('technique')},{item.get('count')}")
    alerts = report.get('alerts') or []
    lines.append(f"alerts,total,{len(alerts)}")
    lines.append(f"network_artifacts,total,{len(report.get('network_artifacts') or [])}")
    network_highlights = report.get('network_highlights') or {}
    for talker in (network_highlights.get('top_talkers') or []):
        lines.append(
            "network_top_talker,"
            + ",".join(
                [
                    str(talker.get('ip') or ''),
                    str(talker.get('count') or 0),
                    str(talker.get('stage') or ''),
                ]
            )
        )
    for beacon in (network_highlights.get('beacon_findings') or []):
        lines.append(
            "network_beacon,"
            + ",".join(
                [
                    str(beacon.get('src_ip') or ''),
                    str(beacon.get('dst_ip') or ''),
                    str(beacon.get('score') or ''),
                ]
            )
        )
    for artifact in report.get('network_artifacts') or []:
        try:
            payload = artifact.get('data')
            serialized = json.dumps(payload, separators=(',', ':')) if payload is not None else ''
        except Exception:
            serialized = ''
        lines.append(
            "network_artifact,"
            + ",".join(
                [
                    str(artifact.get('type') or ''),
                    serialized.replace('\n', ' '),
                ]
            )
        )
    finops = report.get('finops') or {}
    if finops:
        lines.append(f"finops,ingest_cost_estimate,{finops.get('ingest_cost_estimate')}")
        lines.append(f"finops,storage_cost_estimate,{finops.get('storage_cost_estimate')}")
        lines.append(f"finops,net_savings_estimate,{finops.get('net_savings_estimate')}")
    return '\n'.join(lines)


def _build_html_payload(report: dict[str, Any], session_ids: list[str], recipients: list[str]) -> dict[str, Any]:
    meta = dict(report.get('meta') or {})
    if recipients:
        meta['recipients'] = recipients
    assessment_view = report.get('assessment_view') or {}
    title = assessment_view.get('title') or report.get('title') or 'Investigation Report'
    payload = {
        'title': title,
        'session_id': ', '.join(session_ids) if session_ids else '',
        'rows': report.get('flagged_events', []),
        'summary': {
            'verdict_stats': report.get('verdict_stats'),
            'severity_distribution': report.get('severity_distribution'),
            'finops': report.get('finops'),
        },
        'correlation': report.get('network_highlights'),
        'clusters': report.get('clusters') or [],
        'assessment_view': assessment_view,
        'executive_summary': report.get('executive_summary') or report.get('summary_text') or '',
        'meta': meta,
        'network_highlights': report.get('network_highlights'),
        'top_mitre': report.get('top_mitre_techniques') or report.get('top_mitre'),
        'threat_models': report.get('threat_models'),
    }
    # Compose email sections using Tier1/Tier2 summaries when available
    try:
        rows = report.get('flagged_events') or []
        # Collect recent click context mapped by message_id
        click_map = {}
        if fetch_recent_clicks:
            try:
                for c in fetch_recent_clicks(limit=200) or []:
                    mid = c.get('message_id')
                    if not mid:
                        continue
                    lst = click_map.setdefault(mid, [])
                    lst.append({
                        'user': c.get('user'),
                        'ip': (c.get('meta') or {}).get('ip') if isinstance(c.get('meta'), dict) else None,
                        'ua': (c.get('meta') or {}).get('ua') if isinstance(c.get('meta'), dict) else None,
                        'url': c.get('url'),
                        'verdict': c.get('verdict'),
                        'mapping_confidence': 1.0,  # exact message_id match
                    })
            except Exception:
                click_map = {}
        cb = ChainBuilder() if ChainBuilder else None
        email_t1: list[dict[str, Any]] = []
        email_t2: list[dict[str, Any]] = []
        email_chains: list[dict[str, Any]] = []
        for r in rows:
            src = (r.get('source_platform') or '').lower()
            is_email = src in {'proofpoint', 'mimecast', 'report_phish_mailbox'} or bool(r.get('sender') or r.get('sender_domain'))
            if not is_email:
                continue
            # Attach click context into raw_event
            re = r.setdefault('raw_event', {})
            mid = r.get('message_id')
            if mid and click_map.get(mid):
                re['click_events'] = click_map[mid]
            chain = None
            if cb:
                try:
                    chain = cb.build_or_update(email_event=None, identity_events=[], devops_events=[], endpoint_events=[], window_seconds=24*3600)
                except Exception:
                    chain = None
            email_t1.append(tier1_summary(r, chain))
            email_t2.append(tier2_summary(r, chain))
            if chain:
                email_chains.append({
                    'chain_id': getattr(chain, 'chain_id', None),
                    'confidence': getattr(chain, 'confidence', 0.0),
                    'stages': [
                        {
                            'domain': getattr(s, 'domain', ''),
                            'event_id': getattr(s, 'event_id', ''),
                            'timestamp': getattr(s, 'timestamp', 0.0),
                            'confidence': getattr(s, 'confidence', 0.0),
                        } for s in getattr(chain, 'stages', []) or []
                    ],
                })
        if email_t1:
            payload['email_summaries'] = email_t1
            payload['email_details'] = email_t2
            payload['email_chains'] = email_chains
    except Exception:
        # Non-fatal: continue without email sections
        pass
    return payload


def _load_persisted_assessment_report_data(assessment_id: str | None, tenant_id: str | None = None) -> tuple[str | None, dict]:
    """Load an assessment snapshot by id, or the latest snapshot when id is omitted."""
    bases = []
    if os.getenv("SESSION_PERSIST_DIR"):
        bases.append(os.getenv("SESSION_PERSIST_DIR") or "")
    bases.append(os.path.abspath(os.path.join(os.getcwd(), "data", "assessments")))
    bases = [b for b in dict.fromkeys(bases) if b and os.path.isdir(b)]
    if not bases:
        return assessment_id, {}
    candidates: list[str] = []
    for base in bases:
        for dirpath, _dirnames, filenames in os.walk(base):
            if tenant_id and tenant_id not in dirpath:
                continue
            for name in filenames:
                if not name.endswith(".json"):
                    continue
                if assessment_id and name != f"{assessment_id}.json":
                    continue
                candidates.append(os.path.join(dirpath, name))
    if assessment_id and tenant_id and not candidates:
        for base in bases:
            for dirpath, _dirnames, filenames in os.walk(base):
                for name in filenames:
                    if name == f"{assessment_id}.json":
                        candidates.append(os.path.join(dirpath, name))
    loaded: list[tuple[str, float, str, dict]] = []
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                continue
            aid = str(data.get("assessment_id") or os.path.splitext(os.path.basename(path))[0])
            if assessment_id and aid != assessment_id:
                continue
            created = str(data.get("created_at") or "")
            # Assessment ids include an epoch-like component; use it as a
            # deterministic fallback when filesystem mtimes collide.
            aid_epoch = 0.0
            try:
                parts = aid.split("-")
                if len(parts) >= 2:
                    aid_epoch = float(parts[1])
            except Exception:
                aid_epoch = 0.0
            sort_token = created or aid
            loaded.append((sort_token, aid_epoch, aid, data))
        except Exception:
            continue
    if loaded:
        loaded.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return loaded[0][2], loaded[0][3]
    return assessment_id, {}


@router.get('/api/v1/report/ingestion')
async def report_ingestion(
    request: Request,
    format: str = Query('html'),
    include_alerts: bool = Query(True),
    limit_alerts: int = Query(150, ge=0, le=1000),
    alerts_offset: int = Query(0, ge=0),
    include_model: bool = Query(False),
    include_scenarios: bool = Query(False),
    include_suppressed_vex: bool = Query(False),
    sessions: str | None = Query(None),
    variant: str | None = Query(None),
    persona: str | None = Query(None),
    recipients: str | None = Query(None),
    tenant: str | None = Query(None),
    persist: bool = Query(True),
    assessment_id: str | None = Query(None),
    deep: bool = Query(False),
) -> Any:
    fmt = (format or 'html').strip().lower()
    session_ids = _parse_sessions_param(sessions)
    persona_selected = _persona_from_variant(variant, persona)
    tenant_id = resolve_tenant_id(request, tenant or request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id'))
    state = get_platform_state()

    # When assessment_id is omitted, default to the latest persisted assessment
    # so LIVE console exports are assessment-backed instead of generic zero-event reports.
    assessment_data: dict = {}
    if assessment_id:
        try:
            from src.api.breach_endpoints import REPORT_STORE  # type: ignore
            assessment_data = REPORT_STORE.get(assessment_id) or {}
        except Exception:
            pass
        if not assessment_data:
            try:
                from src.core.ingest import assessment_store  # type: ignore
                assessment_data = assessment_store.get(assessment_id) or {}
            except Exception:
                pass
    if not assessment_data:
        assessment_id, assessment_data = _load_persisted_assessment_report_data(assessment_id, tenant_id)

    report = build_ingestion_report(
        session_ids,
        include_alerts,
        limit_alerts,
        state,
        tenant_id=tenant_id,
        alerts_offset=alerts_offset,
        include_scenarios=include_scenarios,
        include_model=include_model,
        include_suppressed_vex=include_suppressed_vex,
        persona=persona_selected,
        variant=variant,
    )

    # Merge assessment-specific evidence when available (fixes "0 events" from dispatch preview)
    if assessment_data:
        rows = (assessment_data.get('normalized_rows')
                or assessment_data.get('evidence_rows')
                or assessment_data.get('rows') or [])
        clusters = (
            assessment_data.get('clusters')
            or assessment_data.get('raw_correlation_clusters')
            or assessment_data.get('correlation_clusters')
            or []
        )
        if not rows and clusters:
            rows = []
            for cluster in clusters:
                for row in cluster.get('evidence_preview') or []:
                    if isinstance(row, dict):
                        rows.append(row)
                    if len(rows) >= 500:
                        break
                if len(rows) >= 500:
                    break
        if rows:
            report['flagged_events'] = rows[:500]
        # Carry verdict and cluster metadata
        if assessment_data.get('verdict'):
            report['verdict'] = assessment_data['verdict']
        if clusters:
            report['clusters'] = clusters
        if assessment_data.get('executive_summary'):
            report['executive_summary'] = assessment_data.get('executive_summary')
        meta_a = report.setdefault('meta', {})
        meta_a['assessment_id'] = assessment_id
        total_rows_for_report = (
            assessment_data.get('total_rows')
            or assessment_data.get('rows_processed')
            or assessment_data.get('uploaded_row_count')
            or len(rows)
        )
        source_counts_for_report = assessment_data.get('source_counts') or {}
        try:
            if (
                assessment_id
                and source_counts_for_report
                and total_rows_for_report
                and sum(int(v or 0) for v in source_counts_for_report.values()) != int(total_rows_for_report)
            ):
                from src.core.ingest import store as _ingest_store  # type: ignore
                corrected = _ingest_store.source_counts(assessment_id)
                if corrected and sum(corrected.values()) == int(total_rows_for_report):
                    source_counts_for_report = corrected
        except Exception:
            pass
        meta_a['source_count'] = len(source_counts_for_report) or assessment_data.get('source_count', 1)
        meta_a['source_counts'] = source_counts_for_report
        meta_a['total_rows'] = total_rows_for_report
        try:
            assessment_view = build_assessment_report_view(
                assessment_data,
                assessment_id=assessment_id,
                corrected_source_counts=source_counts_for_report,
            )
            report['assessment_view'] = assessment_view
            report['title'] = assessment_view.get('title') or report.get('title')
            # Use view-model as canonical source for key aggregate fields so all
            # report endpoints (ingestion, exec-summary, dispatch) agree on counts.
            if assessment_view.get('verdict'):
                report['verdict'] = assessment_view['verdict']
            if assessment_view.get('top_mitre_techniques'):
                report['top_mitre_techniques'] = assessment_view['top_mitre_techniques']
            if assessment_view.get('validated_breach_count') is not None:
                report.setdefault('meta', {})['validated_breach_count'] = (
                    assessment_view['validated_breach_count']
                )
            if assessment_view.get('evidence_rows'):
                report['flagged_events'] = assessment_view['evidence_rows'][:500]
            if assessment_view.get('severity_distribution'):
                report['severity_distribution'] = assessment_view['severity_distribution']
        except Exception:
            pass
        # Build GRC compliance pre-fill for compliance persona
        if persona_selected in ('compliance', 'ciso') and clusters:
            report['_grc_prefill'] = _build_grc_prefill(assessment_data)

    recipients_list = _parse_recipients(recipients)
    meta = report.setdefault('meta', {})
    if tenant_id:
        meta.setdefault('tenant_id', tenant_id)
    if session_ids:
        meta['sessions'] = session_ids
    if recipients_list:
        meta['recipients'] = recipients_list
    meta['persona'] = persona_selected
    meta['variant'] = (variant or '').strip().lower() or meta.get('variant')
    meta['format'] = fmt
    if _should_persist_reports(persist):
        report = _persist_report_snapshot(
            report,
            tenant_id,
            title='Ingestion Report',
            source_type='ingestion',
            source_id=','.join(session_ids) if session_ids else None,
        )

    if fmt == 'json':
        return JSONResponse(report)
    if fmt == 'csv':
        csv_text = _report_to_csv(report)
        return PlainTextResponse(content=csv_text, media_type='text/csv')
    if fmt == 'html':
        payload = _build_html_payload(report, session_ids, recipients_list)
        # Ensure persona propagates into payload.meta so build_report_html can dispatch
        if persona_selected:
            payload.setdefault('meta', {})['persona'] = persona_selected
        # Inject GRC pre-fill into payload for compliance/ciso personas
        if report.get('_grc_prefill'):
            payload['_grc_prefill'] = report['_grc_prefill']
        html = build_report_html(payload)
        # Optionally include model summary into HTML (sanitized)
        # Assessment-backed exports already render validated metrics, factors,
        # clusters, and persona sections. The generic model prompt is based on
        # platform aggregate counters and can produce a misleading "zero events"
        # preface for persisted assessment reports, so only use it for generic
        # ingestion/status reports.
        if include_model and not payload.get('assessment_view'):
            try:
                try:
                    if _build_incident_prompt is not None:
                        _pd = _build_incident_prompt(persona_selected, payload.get('summary') or {})
                        _msgs = _pd.get('messages') or []
                        prompt = '\n'.join(m.get('content', '') for m in _msgs if isinstance(m, dict) and m.get('content'))
                    else:
                        raise ValueError('unavailable')
                except Exception:
                    prompt = build_summary_prompt(payload.get('summary') or {}, len(payload.get('rows') or []))
                llm_resp = generate_summary(prompt, max_tokens=512)
                if hasattr(llm_resp, '__await__'):
                    llm_resp = await llm_resp
                # Extract clean text from LLM response — avoid showing raw dict/JSON to users
                if isinstance(llm_resp, dict):
                    model_text = (llm_resp.get('text') or llm_resp.get('content')
                                  or llm_resp.get('summary') or llm_resp.get('response') or '')
                    # If we still have a dict-like string, try to extract just the text
                    if isinstance(model_text, dict):
                        model_text = str(model_text.get('text') or model_text.get('content') or '')
                else:
                    model_text = str(llm_resp or '')
                # Strip any remaining JSON artifacts at start of string
                model_text = re.sub(r'^\s*\{.*?\}\s*', '', str(model_text or ''), flags=re.DOTALL).strip()
                try:
                    prompt_hash = hashlib.sha256(prompt.encode('utf-8')).hexdigest()
                except Exception:
                    prompt_hash = None
                _persona_label = persona_selected.replace('_', ' ').title()
                # Build styled HTML with GRC pre-fill block if available
                grc_html = ''
                grc = report.get('_grc_prefill')
                if grc and persona_selected in ('compliance', 'ciso'):
                    # ── Impact banner ──────────────────────────────────────
                    impact_usd = grc.get('total_business_impact_usd') or 0
                    headline = grc.get('headline') or ''
                    impact_html = ''
                    if impact_usd or headline:
                        impact_html = (
                            '<div style="margin-bottom:12px;padding:10px 14px;background:rgba(239,68,68,.08);'
                            'border-left:3px solid #ef4444;border-radius:4px">'
                            + (f'<div style="color:#f87171;font-weight:700;font-size:13px">{escape(headline)}</div>' if headline else '')
                            + (f'<div style="color:#fca5a5;font-size:12px;margin-top:4px">Estimated business impact: '
                               f'<strong>${impact_usd:,.0f}</strong></div>' if impact_usd else '')
                            + ''.join(f'<div style="color:#94a3b8;font-size:12px">{escape(n.get("label","") + ": $" + str(n.get("amount_usd","")) if isinstance(n,dict) else str(n))}</div>'
                                      for n in (grc.get('impact_notes') or [])[:4])
                            + '</div>'
                        )

                    # ── Control failures table ──────────────────────────────
                    gaps_rows = ''.join(
                        f'<tr><td style="padding:4px 8px;color:#94a3b8;font-size:11px">{escape(g.get("technique",""))}</td>'
                        f'<td style="padding:4px 8px;color:#e2e8f0;font-size:11px">{escape(str(g.get("framework","")).upper())}</td>'
                        f'<td style="padding:4px 8px;color:#94a3b8;font-size:11px">{escape(g.get("control",""))}</td>'
                        f'<td style="padding:4px 8px;font-size:11px">{escape(g.get("title") or g.get("control_name",""))}</td>'
                        f'<td style="padding:4px 8px;text-align:center"><span style="background:{"rgba(239,68,68,.15)" if g.get("severity") in ("critical","high") else "rgba(251,191,36,.1)"};'
                        f'color:{"#f87171" if g.get("severity") in ("critical","high") else "#fbbf24"};padding:1px 6px;border-radius:3px;font-size:10px">{escape(str(g.get("severity","")).upper())}</span></td>'
                        f'<td style="padding:4px 8px;color:#818cf8;font-size:11px">{escape(g.get("priority",""))}</td></tr>'
                        for g in (grc.get('control_gaps') or [])[:30]
                    )
                    notifs = ''.join(f'<li style="margin:4px 0;font-size:12px">{escape(n)}</li>' for n in (grc.get('notification_triggers') or []))

                    # ── CVE cross-walk / framework evidence ─────────────────
                    xfw_html = ''
                    xfw = grc.get('cross_framework_evidence') or {}
                    if xfw:
                        xfw_rows = ''.join(
                            f'<tr><td style="padding:4px 8px;color:#a78bfa;font-size:11px">{escape(k)}</td>'
                            f'<td style="padding:4px 8px;color:#94a3b8;font-size:11px">{escape(", ".join(v) if isinstance(v,list) else str(v))}</td></tr>'
                            for k, v in list(xfw.items())[:10]
                        )
                        xfw_html = (
                            '<h4 style="color:#a78bfa;margin:14px 0 8px;font-size:12px">Framework Crosswalk Evidence</h4>'
                            f'<table style="width:100%;border-collapse:collapse;font-size:11px"><tbody>{xfw_rows}</tbody></table>'
                        )

                    # ── Auditor questions ───────────────────────────────────
                    auditor_html = ''
                    asks = grc.get('auditor_insights') or []
                    if asks:
                        asks_items = ''.join(f'<li style="margin:4px 0;font-size:12px;color:#cbd5e1">{escape(str(a))}</li>' for a in asks[:8])
                        auditor_html = (
                            '<h4 style="color:#60a5fa;margin:14px 0 8px;font-size:12px">Auditor Questions</h4>'
                            f'<ul style="margin:0;padding-left:16px">{asks_items}</ul>'
                        )

                    # ── Remediation roadmap ─────────────────────────────────
                    roadmap_html = ''
                    roadmap = grc.get('remediation_roadmap') or {}
                    if roadmap:
                        rmap_rows = ''.join(
                            f'<tr style="border-top:1px solid rgba(99,102,241,.1)">'
                            f'<td style="padding:6px 8px;color:#818cf8;font-weight:700;font-size:11px">{escape(k.upper())}</td>'
                            f'<td style="padding:6px 8px"><ul style="margin:0;padding-left:14px">'
                            + ''.join(f'<li style="font-size:11px;color:#cbd5e1;margin:2px 0">{escape(str(item))}</li>'
                                      for item in (v if isinstance(v, list) else [v])[:5])
                            + '</ul></td></tr>'
                            for k, v in roadmap.items()
                        )
                        roadmap_html = (
                            '<h4 style="color:#34d399;margin:14px 0 8px;font-size:12px">Remediation Roadmap</h4>'
                            f'<table style="width:100%;border-collapse:collapse">{rmap_rows}</table>'
                        )

                    # ── SABSA ───────────────────────────────────────────────
                    sabsa_rows = ''.join(
                        f'<tr><td style="padding:4px 8px;font-weight:600;color:#a78bfa;font-size:11px">{escape(l[0])}</td>'
                        f'<td style="padding:4px 8px;color:#94a3b8;font-size:11px">{escape(l[1])}</td></tr>'
                        for l in (grc.get('sabsa_layers') or [])
                    )
                    grc_html = (
                        '<div style="margin-top:16px;padding:16px;background:#0a0f1e;border:1px solid rgba(167,139,250,.3);border-radius:6px">'
                        '<h4 style="color:#a78bfa;margin:0 0 12px;font-size:13px">Compliance Control Analysis</h4>'
                        + impact_html
                        + (f'<table style="width:100%;border-collapse:collapse;font-size:12px"><thead><tr>'
                           '<th style="text-align:left;padding:4px 8px;color:#64748b;font-size:10px">TECHNIQUE</th>'
                           '<th style="text-align:left;padding:4px 8px;color:#64748b;font-size:10px">FRAMEWORK</th>'
                           '<th style="text-align:left;padding:4px 8px;color:#64748b;font-size:10px">CONTROL</th>'
                           '<th style="text-align:left;padding:4px 8px;color:#64748b;font-size:10px">GAP</th>'
                           '<th style="text-align:left;padding:4px 8px;color:#64748b;font-size:10px">SEV</th>'
                           '<th style="text-align:left;padding:4px 8px;color:#64748b;font-size:10px">PRI</th></tr></thead>'
                           f'<tbody>{gaps_rows}</tbody></table>' if gaps_rows else '')
                        + xfw_html
                        + auditor_html
                        + roadmap_html
                        + (f'<h4 style="color:#f87171;margin:12px 0 8px;font-size:12px">Notification Obligations</h4>'
                           f'<ul style="margin:0;padding-left:16px;color:#fca5a5">{notifs}</ul>' if notifs else '')
                        + (f'<h4 style="color:#60a5fa;margin:12px 0 8px;font-size:12px">SABSA Architectural Evidence</h4>'
                           f'<table style="width:100%;border-collapse:collapse;font-size:11px"><tbody>{sabsa_rows}</tbody></table>' if sabsa_rows else '')
                        + '</div>'
                    )
                model_html = (
                    '<div style="padding:16px;background:#071021;color:#e6eef8;border-radius:6px;'
                    'border:1px solid rgba(99,102,241,.2);margin-bottom:16px">'
                    f'<h3 style="color:#818cf8;margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.05em">'
                    f'{escape(_persona_label)} Analysis</h3>'
                    f'<div style="font-size:13px;line-height:1.7;white-space:pre-wrap">{escape(model_text)}</div>'
                    + grc_html
                    + '</div>'
                )
                try:
                    if _HAS_BLEACH:
                        model_html = bleach.clean(model_html, tags=bleach.sanitizer.ALLOWED_TAGS + ['div','h3','h4','pre','code','span','table','thead','tbody','tr','th','td','ul','li'], attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES, strip=True)
                    else:
                        model_html = _simple_sanitize(model_html)
                except Exception:
                    pass
                # prepend model HTML and persist model meta into a small injected comment for provenance
                meta_comment = f"<!-- model_prompt_hash:{prompt_hash} generated_at:{int(time.time())} -->\n"
                html = meta_comment + model_html + '\n' + html
            except Exception:
                # non-fatal; return HTML without model summary
                pass
        headers = {'X-Report-Id': str(report.get('report_id') or '')} if report.get('report_id') else None
        return HTMLResponse(content=html, headers=headers)
    if fmt == 'pdf':
        payload = _build_html_payload(report, session_ids, recipients_list)
        if persona_selected:
            payload.setdefault('meta', {})['persona'] = persona_selected
        html = build_report_html(payload)
        try:
            from src.reporting.export import export_pdf_bytes_from_html as _epdf
            pdf_bytes = _epdf(html)
            if pdf_bytes:
                report_id = str(report.get('report_id') or '')
                fname = f'report_{report_id or int(time.time())}.pdf'
                return StreamingResponse(
                    io.BytesIO(pdf_bytes),
                    media_type='application/pdf',
                    headers={'Content-Disposition': f'attachment; filename="{fname}"'},
                )
        except Exception:
            pass
        # Fallback: serve as HTML download
        return StreamingResponse(
            io.BytesIO(html.encode('utf-8')),
            media_type='text/html',
            headers={'Content-Disposition': f'attachment; filename="report_{int(time.time())}.html"'},
        )
    raise HTTPException(status_code=400, detail='unsupported_format')


@router.get('/api/v1/report/pasta')
async def report_pasta(request: Request) -> Any:
    """PASTA scenario rollup: map recorded decision factors to attack scenarios
    (SCN-* ids) via the scenario engine, aggregated by occurrence/risk. Thin
    wrapper over the same machinery the ingestion report's scenario section uses."""
    try:
        from .report_aggregation import aggregate_decisions, _scenario_summary, SCEN_ENGINE  # type: ignore
    except Exception:
        from src.api.report_aggregation import aggregate_decisions, _scenario_summary, SCEN_ENGINE  # type: ignore
    decisions = aggregate_decisions()
    for rec in (decisions.get('flagged_events', []) + decisions.get('autoblocked_samples', [])):
        try:
            rec['scenarios'] = SCEN_ENGINE.evaluate(rec.get('factors', []) or [])
        except Exception:
            rec['scenarios'] = []
    return _scenario_summary(decisions)


@router.get('/api/v1/report/threat_model')
async def report_threat_model(request: Request) -> Any:
    """STRIDE / threat-model rollup across recorded decisions: derive a unified
    threat model per decision and aggregate STRIDE categories + framework counts."""
    try:
        from .report_aggregation import aggregate_decisions, _build_framework_summary, _unified_threat_model  # type: ignore
    except Exception:
        from src.api.report_aggregation import aggregate_decisions, _build_framework_summary, _unified_threat_model  # type: ignore
    decisions = aggregate_decisions()
    records = decisions.get('flagged_events', []) + decisions.get('autoblocked_samples', [])
    for rec in records:
        try:
            model = _unified_threat_model(rec.get('factors', []) or [])
            if model:
                rec['threat_model'] = model
        except Exception:
            continue
    return _build_framework_summary(records) or {'stride_categories': [], 'stride_counts': []}


@router.post('/api/v1/report/generate_pdf')
async def generate_pdf_report(req: Request, include_model: bool = Query(False)):
    """Generate a PDF from the standard HTML report. Uses WeasyPrint when available.

    Fallback: if WeasyPrint isn't installed or fails, return the HTML as a StreamingResponse
    with `text/html` so the frontend can fall back to downloading HTML.
    """
    payload = await req.json()
    try:
        resolve_tenant_id(req, payload.get('tenant_id') or payload.get('tenant'))
    except Exception:
        raise
    html = build_report_html(payload)
    # Optionally include model summary into HTML
    if include_model:
        try:
            _pdf_persona = payload.get('persona') or 'soc_analyst'
            try:
                if _build_incident_prompt is not None:
                    _pd = _build_incident_prompt(_pdf_persona, payload.get('summary') or {})
                    _msgs = _pd.get('messages') or []
                    prompt = '\n'.join(m.get('content', '') for m in _msgs if isinstance(m, dict) and m.get('content'))
                else:
                    raise ValueError('unavailable')
            except Exception:
                prompt = build_summary_prompt(payload.get('summary') or {}, len(payload.get('rows') or []))
            llm_resp = generate_summary(prompt, max_tokens=512)
            if hasattr(llm_resp, '__await__'):
                llm_resp = await llm_resp
            model_text = llm_resp.get('text') if isinstance(llm_resp, dict) else str(llm_resp)
            # simple injection
            _pdf_label = _pdf_persona.replace('_', ' ').title()
            model_html = '<div style="padding:12px;background:#071021;color:#e6eef8;border-radius:6px"><h3>' + escape(_pdf_label) + ' Model Summary</h3><div>' + escape(str(model_text or '')) + '</div></div>'
            html = model_html + '\n' + html
        except Exception:
            # continue without model
            pass

    try:
        from src.reporting.export import export_pdf_bytes_from_html
    except Exception:
        export_pdf_bytes_from_html = None

    if export_pdf_bytes_from_html is not None:
        try:
            pdf_bytes = export_pdf_bytes_from_html(html)
            if pdf_bytes:
                import io
                return StreamingResponse(io.BytesIO(pdf_bytes), media_type='application/pdf', headers={'Content-Disposition': 'attachment; filename="report.pdf"'})
        except Exception:
            pass

    # Fallback: return HTML content
    buf = html.encode('utf-8')
    return StreamingResponse(io.BytesIO(buf), media_type='text/html')


@router.post('/api/v1/report/generate_pdf_from_html')
async def generate_pdf_from_html_endpoint(req: Request):
    """Accept raw HTML body and return a PDF (or HTML fallback). No session/DB lookups.
    Request body: { "html": "<html>..." }
    """
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    html = body.get('html', '')
    if not html:
        raise HTTPException(status_code=400, detail='html_required')
    try:
        from src.reporting.export import export_pdf_bytes_from_html as _export  # type: ignore
        pdf_bytes = _export(html)
        if pdf_bytes:
            return StreamingResponse(io.BytesIO(pdf_bytes), media_type='application/pdf',
                                     headers={'Content-Disposition': f'attachment; filename="report_{int(time.time())}.pdf"'})
    except Exception:
        pass
    try:
        from weasyprint import HTML as _WP  # type: ignore
        pdf_bytes = _WP(string=html).write_pdf()
        return StreamingResponse(io.BytesIO(pdf_bytes), media_type='application/pdf',
                                 headers={'Content-Disposition': f'attachment; filename="report_{int(time.time())}.pdf"'})
    except ImportError:
        pass
    except Exception:
        pass
    return StreamingResponse(io.BytesIO(html.encode('utf-8')), media_type='text/html',
                             headers={'Content-Disposition': f'attachment; filename="report_{int(time.time())}.html"'})


@router.post('/api/v1/report/generate')
async def generate_report(req: Request, format: str = Query('html'), include_model: bool = Query(False), include_scenarios: bool = Query(False), persist: bool = Query(True)):
    payload = await req.json()
    try:
        resolve_tenant_id(req, payload.get('tenant_id') or payload.get('tenant'))
    except Exception:
        raise

    # If assessment_id is supplied but rows/summary are absent, hydrate from the store.
    # This lets the frontend call /report/generate with just {"assessment_id": "..."} and
    # get a real data-backed report rather than a static template.
    _gen_aid = payload.get('assessment_id') or payload.get('session_id')
    if _gen_aid and not (payload.get('rows') or payload.get('summary')):
        _gen_data: dict = {}
        try:
            from src.api.breach_endpoints import REPORT_STORE  # type: ignore
            _gen_data = REPORT_STORE.get(_gen_aid) or {}
        except Exception:
            pass
        if not _gen_data:
            try:
                from src.core.ingest import assessment_store  # type: ignore
                _gen_data = assessment_store.get(_gen_aid) or {}
            except Exception:
                pass
        if not _gen_data:
            _, _gen_data = _load_persisted_assessment_report_data(
                _gen_aid, payload.get('tenant_id') or payload.get('tenant')
            )
        if _gen_data:
            payload.setdefault('rows', (
                _gen_data.get('normalized_rows') or
                _gen_data.get('evidence_rows') or
                _gen_data.get('flagged_events') or []
            ))
            payload.setdefault('summary', {
                'verdict': _gen_data.get('verdict'),
                'cluster_count': len(_gen_data.get('correlation_clusters') or []),
                'top_mitre': _gen_data.get('top_mitre_techniques') or [],
                'severity_distribution': _gen_data.get('severity_distribution') or {},
                'clusters': _gen_data.get('correlation_clusters') or [],
            })
            payload.setdefault('clusters', _gen_data.get('correlation_clusters') or [])
            payload.setdefault('assessment_id', _gen_aid)

    # payload may include: session_id, rows (list), summary
    # Build the HTML or JSON output
    html = build_report_html(payload)
    result = {'html': html}
    tenant_id = payload.get('tenant_id') or payload.get('tenant')

    # Optionally request an LLM summary and attach provenance
    if include_model:
        _gen_persona = payload.get('persona') or 'soc_analyst'
        try:
            if _build_incident_prompt is not None:
                _pd = _build_incident_prompt(_gen_persona, payload.get('summary') or {})
                _msgs = _pd.get('messages') or []
                prompt = '\n'.join(m.get('content', '') for m in _msgs if isinstance(m, dict) and m.get('content'))
            else:
                raise ValueError('unavailable')
        except Exception:
            prompt = build_summary_prompt(payload.get('summary') or {}, len(payload.get('rows') or []))
        try:
            # prompt already built above; generate via LLM client
            # generate_summary may be sync; allow both sync and async returns
            llm_resp = generate_summary(prompt, max_tokens=512)
            if hasattr(llm_resp, '__await__'):
                llm_resp = await llm_resp
            # Attach provenance metadata into result
            model_text = llm_resp.get('text') if isinstance(llm_resp, dict) else str(llm_resp)
            try:
                prompt_hash = hashlib.sha256(prompt.encode('utf-8')).hexdigest()
            except Exception:
                prompt_hash = None
            result['model_summary'] = {
                'text': model_text,
                'model': llm_resp.get('model') if isinstance(llm_resp, dict) else None,
                'meta': llm_resp.get('meta') if isinstance(llm_resp, dict) else None,
                'provenance': {'prompt_hash': prompt_hash, 'generated_at': int(time.time())}
            }
            # Attempt to parse structured JSON summary from model text
            try:
                parsed = parse_structured_summary(model_text or '')
                result['model_summary']['provenance']['structured'] = parsed
            except Exception:
                pass
            # Create a compact model_html snippet (sanitized below)
            model_html = '<div style="padding:12px;background:#071021;color:#e6eef8;border-radius:6px"><h3>Model Executive Summary</h3><div>' + escape(str(model_text or '')) + '</div></div>'
            result['model_html'] = model_html
        except Exception as e:
            result['model_summary'] = {'error': str(e)}

    # Sanitize HTML output to avoid XSS
    try:
        if _HAS_BLEACH:
            safe_html = bleach.clean(html, tags=bleach.sanitizer.ALLOWED_TAGS + ['table', 'tr', 'td', 'th'], attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES, strip=True)
        else:
            safe_html = _simple_sanitize(html)
    except Exception:
        safe_html = html

    # Sanitize model_html if present
    try:
        if result.get('model_html'):
            if _HAS_BLEACH:
                result['model_html'] = bleach.clean(result['model_html'], tags=bleach.sanitizer.ALLOWED_TAGS + ['div','h3','pre','code','span'], attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES, strip=True)
            else:
                result['model_html'] = _simple_sanitize(result['model_html'])
    except Exception:
        pass

    persisted_payload = dict(payload or {})
    if _should_persist_reports(persist):
        summary = payload.get('summary')
        summary_title = summary.get('title') if isinstance(summary, dict) else None
        persisted_payload = _persist_report_snapshot(
            persisted_payload,
            tenant_id,
            title=str(summary_title or payload.get('title') or 'Generated Report'),
            source_type='generate',
            source_id=payload.get('session_id'),
        )
        result['report_id'] = persisted_payload.get('report_id')
        result['artifact'] = {
            'report_id': persisted_payload.get('report_id'),
            'available_formats': ['json', 'html'],
        }

    if format == 'html':
        # If include_model requested, return JSON (avoid embedding raw model text into HTML)
        if include_model:
            return JSONResponse(result)
        # Stream large HTML responses to avoid memory pressure
        buf = safe_html.encode('utf-8')
        headers = {'X-Report-Id': str(persisted_payload.get('report_id') or '')} if persisted_payload.get('report_id') else None
        if len(buf) > _STREAM_THRESHOLD:
            return StreamingResponse(io.BytesIO(buf), media_type='text/html', headers=headers)
        return HTMLResponse(content=safe_html, status_code=200, headers=headers)
    else:
        return JSONResponse(result)


# ---------------- Persona View Endpoints -----------------
try:
    # Snapshot loader for stored ingestion/executive reports
    from src.repositories.report_snapshots_repo import load_snapshot, load_snapshot_meta, list_snapshots, save_snapshot
except Exception:
    try:
        from ..repositories.report_snapshots_repo import load_snapshot, load_snapshot_meta, list_snapshots, save_snapshot
    except Exception:
        load_snapshot = None  # type: ignore
        load_snapshot_meta = None  # type: ignore
        list_snapshots = None  # type: ignore
        save_snapshot = None  # type: ignore
try:
    from src.reporting.persona_views import generate_persona_view
except Exception:
    from ..reporting.persona_views import generate_persona_view

try:
    from src.repositories.feedback_repo import insert_report_feedback, get_feedback_for_report, insert_feedback
except Exception:
    insert_report_feedback = None  # type: ignore
    get_feedback_for_report = None  # type: ignore
    insert_feedback = None  # type: ignore

from pathlib import Path
import os
import math
from statistics import mean
try:
    from src.repositories.audit_repo import insert_audit, list_audits
except Exception:
    try:
        from ..repositories.audit_repo import insert_audit, list_audits
    except Exception:
        insert_audit = None  # type: ignore
        list_audits = None  # type: ignore

_SNAP_BASE = Path('reports') / 'snapshots'

try:
    from src.core.storage.report_store import report_store
except Exception:
    try:
        from ..core.storage.report_store import report_store
    except Exception:
        report_store = None  # type: ignore


def _should_persist_reports(explicit: bool | None = None) -> bool:
    if explicit is not None:
        return bool(explicit)
    return os.getenv('REPORT_PERSIST_DEFAULT', '1').lower() not in {'0', 'false', 'no'}


def _persist_report_snapshot(
    payload: dict[str, Any],
    tenant_id: str | None,
    *,
    title: str | None = None,
    notes: str | None = None,
    source_type: str | None = None,
    source_id: str | None = None,
) -> dict[str, Any]:
    report_payload = dict(payload or {})
    report_payload.setdefault('generated_at', time.time())
    report_payload.setdefault('tenant_id', tenant_id)
    report_id = report_payload.get('report_id')
    if not report_id:
        digest = hashlib.sha256(json.dumps(report_payload, sort_keys=True, default=str).encode('utf-8')).hexdigest()[:8]
        report_id = f"rep-{int(report_payload['generated_at'])}-{digest}"
        report_payload['report_id'] = report_id
    report_payload.setdefault('meta', {})
    report_payload['meta'].setdefault('tenant_id', tenant_id)
    if save_snapshot is not None:
        meta = save_snapshot(
            report_payload,
            tenant_id=tenant_id,
            title=title,
            notes=notes,
            report_id=report_id,
            artifact_type='report_snapshot',
            source_type=source_type,
            source_id=source_id,
            available_formats=['json', 'html', 'csv'],
        )
        report_payload['meta']['snapshot_meta'] = {
            'report_id': meta.report_id,
            'generated_at': meta.generated_at,
            'sha256': meta.sha256,
            'artifact_type': meta.artifact_type,
            'source_type': meta.source_type,
            'source_id': meta.source_id,
            'available_formats': meta.available_formats or ['json', 'html', 'csv'],
        }
    if report_store is not None:
        try:
            report_store.save(str(report_id), report_payload)
        except Exception:
            pass
    return report_payload


def _render_persisted_report_html(report: dict[str, Any]) -> str:
    meta = report.get('meta') or {}
    if 'flagged_events' in report or 'alerts' in report:
        payload = _build_html_payload(
            report,
            meta.get('sessions') or [],
            meta.get('recipients') or [],
        )
        return build_report_html(payload)
    return build_report_html(report)


def _load_snapshot_payload(
    report_id: str,
    request: Request | None,
    tenant_hint: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    tenant_id: str | None = None
    if request is not None:
        tenant_id = resolve_tenant_id(request, tenant_hint)
    elif tenant_hint:
        tenant_id = tenant_hint

    meta = None
    payload = None
    if load_snapshot_meta is not None:
        meta = load_snapshot_meta(report_id)
    if load_snapshot is not None:
        payload = load_snapshot(report_id)

    if not payload:
        p = _SNAP_BASE / f"{report_id}.json"
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding='utf-8'))
                meta = meta or (data.get('meta') if isinstance(data.get('meta'), dict) else None)
                payload = data.get('payload')
            except Exception:
                payload = None

    if not payload:
        raise HTTPException(status_code=404, detail='report_not_found')

    if tenant_id and meta and meta.get('tenant_id') and meta.get('tenant_id') != tenant_id:
        raise HTTPException(status_code=403, detail='tenant_mismatch')

    return payload, tenant_id

from src.reporting.attention_queue import categorize_reports
try:
    # Reuse centralized persona parser/validator when persona-like text is present
    from src.reporting.persona_parser import parse_persona_text, validate_parsed_persona
except Exception:
    parse_persona_text = None  # type: ignore
    validate_parsed_persona = None  # type: ignore

try:
    from src.core.enrichment.email_combiners import combine_email_signals
except Exception:
    combine_email_signals = None

try:
    from src.core.scoring.dread_engine import compute_dread, severity_from_dread
except Exception:
    compute_dread = None
    severity_from_dread = None
    try:
        from src.core.scoring.dread_engine import compute_dread, severity_from_dread
    except Exception:
        compute_dread = None
        severity_from_dread = None


def _compute_attention_score(rpt: dict) -> float:
    """Compute an attention score blending severity, confidence, dependency health, and age."""
    try:
        sev_map = {'CRITICAL': 1.0, 'HIGH': 0.8, 'MEDIUM': 0.5, 'LOW': 0.2}
        sev = (rpt.get('risk_quantification', {}).get('severity') or 'LOW').upper()
        s = sev_map.get(sev, 0.2)
        conf = float(rpt.get('verdict', {}).get('final_confidence', 0.0))
        dep = rpt.get('dependency_status', {})
        seconds_since_ok = float(dep.get('seconds_since_ok', 0) or 0)
        dep_penalty = 0.0 if seconds_since_ok <= 300 else min(0.3, (seconds_since_ok / 3600.0) * 0.05)
        ts = float(rpt.get('generated_at') or rpt.get('ts') or time.time())
        age_hours = max(0.0, (time.time() - ts) / 3600.0)
        age_score = 0.0 if age_hours < 1 else min(0.3, age_hours / 24.0)
        # attention score: severity*0.5 + (1-confidence)*0.3 + dep_penalty + age_score
        score = (s * 0.5) + ((1.0 - conf) * 0.3) + dep_penalty + age_score
        return float(score)
    except Exception:
        return 0.0


@router.get('/api/v1/reports/attention')
async def reports_attention(request: Request, limit: int = Query(50)):
    """Return attention buckets and a triage scoreboard (top-N by attention score).

    For demo mode this scans snapshots in `reports/snapshots` and computes buckets.
    """
    # Load snapshots from disk (best-effort); prefer snapshot loader when available
    snaps = []
    tenant_id = resolve_tenant_id(request, request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id'))
    try:
        if load_snapshot and list_snapshots:
            try:
                meta = list_snapshots(tenant_id=tenant_id, limit=limit)
                for m in meta:
                    rid = m.get('report_id') if isinstance(m, dict) else None
                    if not rid:
                        continue
                    try:
                        p, _ = _load_snapshot_payload(rid, request, tenant_id)
                    except Exception:
                        p = None
                    if p:
                        snaps.append(p)
            except Exception:
                pass
        for p in _SNAP_BASE.glob('*.json'):
            try:
                import json
                data = json.loads(p.read_text(encoding='utf-8'))
                meta = data.get('meta') if isinstance(data.get('meta'), dict) else {}
                if tenant_id and meta.get('tenant_id') and meta.get('tenant_id') != tenant_id:
                    continue
                payload = data.get('payload')
                if payload:
                    snaps.append(payload)
            except Exception:
                continue
    except Exception:
        snaps = []

    buckets = categorize_reports(snaps)

    # Build triage scoreboard
    scored = []
    for s in snaps:
        try:
            rpt_id = s.get('report_id')
            score = _compute_attention_score(s)
            scored.append({'report_id': rpt_id, 'score': score, 'summary': s.get('summary') or {}, 'decision_gates': s.get('decision_gates', [])})
        except Exception:
            continue
    scored_sorted = sorted(scored, key=lambda x: x.get('score', 0.0), reverse=True)
    triage = scored_sorted[:5]
    return JSONResponse({'buckets': buckets, 'triage_scoreboard': triage})


@router.get('/api/v1/reports')
async def list_report_artifacts(request: Request, limit: int = Query(50, ge=1, le=200)):
    tenant_id = resolve_tenant_id(request, request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id'))
    items = list_snapshots(tenant_id=tenant_id, limit=limit) if list_snapshots is not None else []
    return JSONResponse({'reports': items, 'count': len(items)})


@router.get('/api/v1/reports/{report_id}')
async def get_report_artifact(report_id: str, request: Request):
    payload, tenant_id = _load_snapshot_payload(report_id, request, request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id'))
    meta = load_snapshot_meta(report_id) if load_snapshot_meta is not None else None
    return JSONResponse({'report_id': report_id, 'tenant_id': tenant_id, 'meta': meta or {}, 'payload': payload})


@router.get('/api/v1/reports/{report_id}/artifact')
async def get_report_artifact_render(
    report_id: str,
    request: Request,
    format: str = Query('json'),
):
    payload, _ = _load_snapshot_payload(report_id, request, request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id'))
    fmt = (format or 'json').strip().lower()
    if fmt == 'json':
        return JSONResponse(payload)
    if fmt == 'csv':
        return PlainTextResponse(content=_report_to_csv(payload), media_type='text/csv')
    if fmt == 'html':
        return HTMLResponse(_render_persisted_report_html(payload), headers={'X-Report-Id': report_id})
    raise HTTPException(status_code=400, detail='unsupported_format')


@router.post('/api/v1/reports/{report_id}/route')
async def route_report(report_id: str, payload: dict, request: Request, persona: str = Query('executive'), disclosure_level: int = Query(2)):
    """Route a stored report to one or more personas and persist an audit entry.

    Payload must include `recipients` list (optional) and `note`.
    """
    # Basic auth guard: require console API key or admin
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    # Best-effort: allow when running in lite/demo mode
    if not api_key and os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=401, detail='api_key_required')
    tenant_hint = payload.get('tenant_id') or payload.get('tenant')
    snap, _ = _load_snapshot_payload(report_id, request, tenant_hint)
    recipients = payload.get('recipients') or []
    note = payload.get('note')
    # Enforce risk appetite rules
    try:
        from src.repositories.risk_appetite_repo import load_profiles
        profiles = load_profiles()
        prof = profiles.get(persona) or profiles.get(persona.lower()) or {}
    except Exception:
        prof = {}
    # allow override via payload.force
    force = bool(payload.get('force'))
    current_conf = float(snap.get('verdict', {}).get('final_confidence', 0.0))
    expected_loss = int(snap.get('risk_quantification', {}).get('expected_loss_usd', 0) or 0)
    if prof and not force:
        min_conf = float(prof.get('min_confidence', 0.0) or 0.0)
        cap = prof.get('impact_cap_usd')
        require_cost = bool(prof.get('require_cost_summary'))
        if current_conf < min_conf:
            raise HTTPException(status_code=403, detail='risk_appetite_confidence_too_low')
        if cap and expected_loss and expected_loss > cap:
            raise HTTPException(status_code=403, detail='risk_appetite_cost_exceeds_cap')
        if require_cost and not snap.get('risk_quantification'):
            raise HTTPException(status_code=403, detail='risk_appetite_requires_cost_summary')

    # Build audit record
    audit = {
        'report_id': report_id,
        'persona': persona,
        'recipients': recipients,
        'disclosure_level': int(disclosure_level),
        'note': note,
        'sent_by': api_key,
        'sent_at': int(time.time()),
    }
    # Persist via audit_repo if available
    audit_id = None
    try:
        if insert_audit:
            audit_id = insert_audit(audit)
        else:
            # fallback to file for backwards compatibility
            audit_dir = Path('reports') / 'audits'
            audit_dir.mkdir(parents=True, exist_ok=True)
            try:
                import json
                fname = audit_dir / f"audit_{report_id}_{int(time.time())}.json"
                fname.write_text(json.dumps(audit), encoding='utf-8')
            except Exception:
                pass
    except Exception:
        pass

    # Optionally trigger existing export/report endpoints to send the snapshot
    # For demo we return the persisted audit id and a hint URL to use /api/v1/report/generate
    hint = f"/api/v1/report/generate?format=json&report_id={report_id}"
    resp = {'routed': True, 'audit': audit}
    if audit_id:
        resp['audit_id'] = audit_id
    resp['send_hint'] = hint
    return JSONResponse(resp)


@router.post('/api/v1/reports/{report_id}/send', operation_id='reports_send_report')
async def send_report(report_id: str, payload: dict, request: Request):
    """Automated sender: generate report HTML/JSON and POST to recipient endpoints.

    Payload: {recipients: [{url, method, headers?}], format: 'html'|'json', include_model: bool}
    """
    # basic guard
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    if not api_key and os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=401, detail='api_key_required')
    tenant_hint = payload.get('tenant_id') or payload.get('tenant')
    snap, _ = _load_snapshot_payload(report_id, request, tenant_hint)

    # Build the report via the existing generate_report route function (call locally)
    try:
        # create a shallow payload for generator
        gen_payload = snap
        include_model = bool(payload.get('include_model'))
        fmt = payload.get('format','html')
        # call generator function (imported above)
        # generate_report expects a Request-like object; call build_report_html directly
        html = build_report_html(gen_payload)
        result = {'html': html}
        if include_model:
            try:
                prompt = build_summary_prompt(gen_payload.get('summary') or {}, len(gen_payload.get('rows') or []))
                llm_resp = generate_summary(prompt, max_tokens=512)
                if hasattr(llm_resp, '__await__'):
                    llm_resp = await llm_resp
                model_text = llm_resp.get('text') if isinstance(llm_resp, dict) else str(llm_resp)
                result['model_summary'] = {'text': model_text}
            except Exception:
                pass
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'generate_failed:{e}')

    recipients = payload.get('recipients') or []
    # enqueue background delivery and persist audit immediately
    try:
        from src.services.delivery_queue import enqueue_delivery
        audit_record = {'report_id': report_id, 'action': 'send', 'recipients': recipients, 'ts': int(time.time())}
        aid = enqueue_delivery(audit_record, recipients, result if fmt != 'html' else result['html'])
    except Exception:
        aid = None

    resp = {'enqueued': True, 'audit_id': aid}
    return JSONResponse(resp)


# Admin endpoints to manage risk appetite profiles
try:
    from src.repositories.risk_appetite_repo import load_profiles, save_profiles
except Exception:
    load_profiles = None
    save_profiles = None


def _require_admin(request: Request) -> None:
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    admin_key = os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')
    # Allow when running in lite/demo or fast test modes
    lite = os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'}
    testmode = os.getenv('FAST_TEST_MODE','0').lower() in {'1','true','yes'}
    if not admin_key:
        if lite or testmode:
            return
        raise HTTPException(status_code=403, detail='admin_key_not_configured')
    if api_key != admin_key:
        raise HTTPException(status_code=401, detail='unauthorized')


@router.get('/api/v1/admin/risk_profiles')
async def get_risk_profiles(request: Request):
    # Admin-only guard
    _require_admin(request)
    if not load_profiles:
        raise HTTPException(status_code=503, detail='risk_profiles_unavailable')
    try:
        profiles = load_profiles()
        return JSONResponse(profiles)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'load_failed:{e}')


@router.post('/api/v1/admin/risk_profiles')
async def post_risk_profiles(request: Request, payload: dict):
    _require_admin(request)
    if not save_profiles:
        raise HTTPException(status_code=503, detail='risk_profiles_unavailable')
    try:
        # payload expected to be a mapping of profile_name -> settings
        save_profiles(payload)
        return JSONResponse({'ok': True})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'save_failed:{e}')


# Playbook action endpoints (isolate, block, create_ticket, export_intel)
try:
    from src.repositories.playbook_repo import get_playbook_for_verdict
except Exception:
    get_playbook_for_verdict = None


@router.post('/api/v1/actions/isolate')
async def action_isolate(payload: dict, request: Request):
    # payload: {host, reason, report_id}
    # For demo, we record an audit and return an action_id
    try:
        report_id = payload.get('report_id')
        if report_id:
            _load_snapshot_payload(report_id, request, payload.get('tenant_id') or payload.get('tenant'))
        audit = {'report_id': report_id, 'action': 'isolate', 'target': payload.get('host'), 'ts': int(time.time())}
        aid = None
        if insert_audit:
            aid = insert_audit(audit)
        return {'ok': True, 'action_id': aid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/api/v1/actions/block')
async def action_block(payload: dict, request: Request):
    # payload: {ioc, type, report_id}
    try:
        report_id = payload.get('report_id')
        if report_id:
            _load_snapshot_payload(report_id, request, payload.get('tenant_id') or payload.get('tenant'))
        audit = {'report_id': report_id, 'action': 'block', 'target': payload.get('ioc'), 'ts': int(time.time())}
        aid = None
        if insert_audit:
            aid = insert_audit(audit)
        return {'ok': True, 'action_id': aid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/api/v1/actions/create_ticket')
async def action_create_ticket(payload: dict, request: Request):
    # payload: {title, description, report_id, priority}
    try:
        report_id = payload.get('report_id')
        if report_id:
            _load_snapshot_payload(report_id, request, payload.get('tenant_id') or payload.get('tenant'))
        # Demo: return a fake ticket id and persist audit
        ticket_id = f"TKT-{int(time.time())}"
        audit = {'report_id': report_id, 'action': 'create_ticket', 'ticket_id': ticket_id, 'ts': int(time.time())}
        aid = None
        if insert_audit:
            aid = insert_audit(audit)
        return {'ok': True, 'ticket_id': ticket_id, 'action_id': aid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/api/v1/actions/export_intel')
async def action_export_intel(payload: dict, request: Request):
    # payload: {report_id, recipients}
    try:
        # For demo, call send_report to export to recipients
        report_id = payload.get('report_id')
        recipients = payload.get('recipients') or []
        _load_snapshot_payload(report_id, request, payload.get('tenant_id') or payload.get('tenant'))
        resp = await send_report(report_id, {'recipients': recipients, 'format': 'json', 'include_model': False}, request)
        return resp
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@router.post('/api/v1/reports/{report_id}/feedback')
async def capture_report_feedback(report_id: str, payload: dict, request: Request):
    """Capture feedback for a report row or overall report.

    Expected payload: {row_id, accurate: bool, comment, reviewer}
    Also supports factor-level voting via {factor, vote, comment}
    """
    tenant_hint = payload.get('tenant_id') or payload.get('tenant')
    _load_snapshot_payload(report_id, request, tenant_hint)
    # allow anonymous in lite mode
    reviewer = payload.get('reviewer') or request.headers.get('x-user') or 'unknown'
    # row-level feedback
    row_id = payload.get('row_id')
    accurate = payload.get('accurate')
    comment = payload.get('comment')
    try:
        if row_id is not None:
            if insert_report_feedback:
                await insert_report_feedback(report_id, row_id, None, bool(accurate), comment, reviewer)
            else:
                # fallback file append
                fb_dir = Path('reports') / 'feedback'
                fb_dir.mkdir(parents=True, exist_ok=True)
                import json
                fp = fb_dir / f"feedback_{report_id}.jsonl"
                fp.write_text(json.dumps({'report_id': report_id, 'row_id': row_id, 'accurate': bool(accurate), 'comment': comment, 'reviewer': reviewer, 'ts': int(time.time())}) + '\n', encoding='utf-8', append=False)
    except Exception:
        raise HTTPException(status_code=500, detail='feedback_store_failed')
    # factor vote
    factor = payload.get('factor')
    vote = payload.get('vote')
    if factor and vote is not None:
        try:
            if insert_feedback:
                await insert_feedback(f"{report_id}:{row_id or '*'}", factor, int(vote), comment, None)
        except Exception:
            pass
    return {'ok': True}


@router.get('/api/v1/reports/{report_id}/persona_view')
async def get_persona_view(request: Request, report_id: str, persona: str = Query('executive'), disclosure_level: int = Query(2), top_n: int = Query(10, ge=1, le=100)):
    """Return a persona-specific view for a stored report snapshot.

    Loads the report payload via the snapshots repo and composes a concise
    persona view including summary signals and decision gates.
    """
    if load_snapshot is None:
        raise HTTPException(status_code=503, detail='snapshot_loader_unavailable')
    payload, _ = _load_snapshot_payload(report_id, request, request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id'))
    try:
        view = generate_persona_view(payload, persona=persona, disclosure_level=int(disclosure_level), top_n=int(top_n))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'persona_build_failed:{exc}')
    # Defensive: if view contains persona-like free text blocks, validate
    try:
        if parse_persona_text and validate_parsed_persona:
            # Common shapes to inspect: view['persona_reports'][key]['text'] or view['text']
            texts: list[str] = []
            try:
                pr = view.get('persona_reports') if isinstance(view, dict) else None
                if isinstance(pr, dict):
                    for _k, entry in pr.items():
                        t = (entry or {}).get('text') if isinstance(entry, dict) else None
                        if isinstance(t, str) and t.strip():
                            texts.append(t)
            except Exception:
                pass
            # Singular text key
            try:
                t0 = view.get('text') if isinstance(view, dict) else None
                if isinstance(t0, str) and t0.strip():
                    texts.append(t0)
            except Exception:
                pass
            # Attach aggregate validation summary if any persona-like texts present
            validations = []
            for t in texts[:3]:  # cap to small number defensively
                try:
                    parsed = parse_persona_text(t)
                except Exception:
                    parsed = None
                try:
                    if parsed is not None:
                        ok, errs = validate_parsed_persona(parsed)  # type: ignore
                        validations.append({'ok': bool(ok), 'errors': errs or [], 'confidence': parsed.get('confidence')})
                    else:
                        validations.append({'ok': False, 'errors': ['parse_failed']})
                except Exception:
                    validations.append({'ok': False, 'errors': ['validation_error']})
            if validations:
                view.setdefault('validation', {})
                view['validation'].setdefault('persona_text_checks', validations)
    except Exception:
        # Non-fatal; continue returning the persona view
        pass
    return JSONResponse(content=jsonable_encoder(view))


@router.post('/api/v1/reports/persona_view')
async def post_persona_view(req: Request, persona: str = Query('executive'), disclosure_level: int = Query(2), top_n: int = Query(10, ge=1, le=100)):
    """Build a persona view from an inline report payload.

    Accepts a JSON body containing the report structure and returns a
    persona-specific view. Useful for LIVE console previews without
    persisting a snapshot first.
    """
    try:
        payload = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    try:
        view = generate_persona_view(payload, persona=persona, disclosure_level=int(disclosure_level), top_n=int(top_n))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'persona_build_failed:{exc}')
    # Defensive persona text validation as above
    try:
        if parse_persona_text and validate_parsed_persona and isinstance(view, dict):
            texts: list[str] = []
            pr = view.get('persona_reports') if isinstance(view, dict) else None
            if isinstance(pr, dict):
                for _k, entry in pr.items():
                    t = (entry or {}).get('text') if isinstance(entry, dict) else None
                    if isinstance(t, str) and t.strip():
                        texts.append(t)
            t0 = view.get('text') if isinstance(view, dict) else None
            if isinstance(t0, str) and t0.strip():
                texts.append(t0)
            validations = []
            for t in texts[:3]:
                try:
                    parsed = parse_persona_text(t)
                except Exception:
                    parsed = None
                try:
                    if parsed is not None:
                        ok, errs = validate_parsed_persona(parsed)  # type: ignore
                        validations.append({'ok': bool(ok), 'errors': errs or [], 'confidence': parsed.get('confidence')})
                    else:
                        validations.append({'ok': False, 'errors': ['parse_failed']})
                except Exception:
                    validations.append({'ok': False, 'errors': ['validation_error']})
            if validations:
                view.setdefault('validation', {})
                view['validation'].setdefault('persona_text_checks', validations)
    except Exception:
        pass
    return JSONResponse(content=jsonable_encoder(view))


@router.post('/api/v1/enrichment/email/combine')
async def post_combine_email(req: Request):
    """Combine email auth signals, headers, envelope metadata and reputations.

    Accepts JSON: {auth: {...}, headers: {...}, envelope: {...}, reputations: {...}}
    Returns combined enrichment payload with multiplier, why and evidence.
    """
    try:
        payload = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    if combine_email_signals is None:
        raise HTTPException(status_code=503, detail='enricher_unavailable')
    auth = payload.get('auth') or {}
    headers = payload.get('headers') or {}
    envelope = payload.get('envelope') or {}
    reputations = payload.get('reputations') or {}
    try:
        out = combine_email_signals(auth=auth, headers=headers, envelope=envelope, reputations=reputations)
        return JSONResponse(content=jsonable_encoder(out))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'enrich_failed:{e}')


@router.post('/api/v1/enrichment/llm/prewarm')
async def post_prewarm_llm(req: Request):
    """Attempt to prewarm a local LLM (best-effort). Returns provenance info.

    Payload: {model: str}
    """
    try:
        payload = await req.json()
    except Exception:
        payload = {}
    model = (payload.get('model') or 'llama3:8b')
    # Best-effort ping to local Ollama or similar; non-fatal
    resp = {'model': model, 'ok': False, 'note': 'prewarm_attempted'}
    try:
        import requests
        # Local Ollama default
        url = os.getenv('LLM_PREWARM_URL', 'http://localhost:11434/api/generate')
        data = {'model': model, 'prompt': 'prewarm ping', 'max_tokens': 1}
        r = requests.post(url, json=data, timeout=2.0)
        if r.status_code == 200:
            resp['ok'] = True
            try:
                resp['meta'] = r.json()
            except Exception:
                resp['meta'] = {'status_code': r.status_code}
        else:
            resp['status_code'] = r.status_code
    except Exception as e:
        resp['error'] = str(e)
    return JSONResponse(content=jsonable_encoder(resp))


@router.post('/api/v1/enrichment/dread/score')
async def post_dread_score(req: Request):
    """Compute DREAD sub-scores for an artifact and return breakdown + severity."""
    try:
        payload = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    if compute_dread is None:
        raise HTTPException(status_code=503, detail='dread_unavailable')
    artifact = payload.get('artifact') or {}
    factors = payload.get('factors') or []
    try:
        res = compute_dread(artifact, factors)
        sev = severity_from_dread(res.get('composite')) if severity_from_dread else 'unknown'
        out = {'breakdown': res, 'severity': sev}
        return JSONResponse(content=jsonable_encoder(out))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'dread_failed:{e}')


@router.post('/api/v1/reports/bulk_triage')
async def post_bulk_triage(payload: dict, request: Request):
    """Apply triage actions to many reports in one request (rate-limited demo).

    Payload: {rows: [{report_id, action}]}
    Requires admin API key in demo mode.
    """
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    if not api_key and os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=401, detail='api_key_required')
    tenant_id = resolve_tenant_id(request, request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id'))
    rows = payload.get('rows') or []
    applied = []
    for r in rows:
        rid = r.get('report_id')
        action = r.get('action')
        if not rid:
            applied.append({'report_id': rid, 'action': action, 'ok': False, 'reason': 'missing_report_id'})
            continue
        try:
            _load_snapshot_payload(rid, request, tenant_id)
        except HTTPException as exc:
            applied.append({'report_id': rid, 'action': action, 'ok': False, 'reason': exc.detail})
            continue
        # For demo, persist a small audit entry per action
        audit = {'report_id': rid, 'action': action, 'ts': int(time.time())}
        try:
            if insert_audit:
                insert_audit(audit)
            applied.append({'report_id': rid, 'action': action, 'ok': True})
        except Exception:
            applied.append({'report_id': rid, 'action': action, 'ok': False})
    return JSONResponse(content=jsonable_encoder({'ok': True, 'applied': applied}))


@router.post('/api/v1/reports/{report_id}/ask_for_logs')
async def ask_for_logs(report_id: str, payload: dict, request: Request):
    """Trigger an 'ask for logs' workflow: create an audit entry and return a prefilled message.

    Payload may include `recipient` and `reason`. Returns {ok, audit_id, message}
    """
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    # allow when running in lite/demo for now
    if not api_key and os.getenv('PLATFORM_LITE_INIT','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=401, detail='api_key_required')
    tenant_hint = payload.get('tenant_id') or payload.get('tenant')
    # Best-effort snapshot lookup; do not fail if snapshot missing.
    # Only enforce tenant mismatch when a snapshot exists and indicates a different tenant.
    try:
        _load_snapshot_payload(report_id, request, tenant_hint)
    except HTTPException as exc:
        if exc.status_code == 403:
            raise  # enforce tenant mismatch
        # tolerate missing report snapshots (404) and continue
        # any other errors are treated as missing for demo/test flows
        pass
    recipient = payload.get('recipient') or payload.get('email') or 'security@example.com'
    reason = payload.get('reason') or 'Please provide forensic logs and timeline for further triage.'
    # Build prefilled message / playbook
    message = {
        'to': recipient,
        'subject': f"Request for additional logs: report {report_id}",
        'body': f"Hello,\n\nWe are investigating report {report_id}. Please provide the following logs and context:\n- Mail server logs (timestamps +/- 15m)\n- Web proxy logs for linked URLs\n- Endpoint telemetry for recipient hosts\n\nReason: {reason}\n\nThanks,\nSecurity Team",
    }
    audit = {'report_id': report_id, 'action': 'ask_for_logs', 'recipient': recipient, 'reason': reason, 'ts': int(time.time())}
    aid = None
    try:
        if insert_audit:
            aid = insert_audit(audit)
        else:
            # fallback file
            ad = Path('reports') / 'audits'
            ad.mkdir(parents=True, exist_ok=True)
            fname = ad / f"asklogs_{report_id}_{int(time.time())}.json"
            fname.write_text(json.dumps(audit), encoding='utf-8')
    except Exception:
        pass
    resp = {'ok': True, 'audit_id': aid, 'message': message}
    return JSONResponse(content=jsonable_encoder(resp))


# ── Regulatory Draft Endpoint ─────────────────────────────────────────────────

@router.post('/api/v1/dispatch/regulatory-draft/{action_type}')
async def regulatory_draft(
    request: Request,
    action_type: str,
    payload: dict = {},
    assessment_id: str | None = Query(None),
) -> Any:
    """Generate a regulatory notification draft document.

    Supported action_type values: ndb, gdpr, forensic, sec_8k, asx

    Query params:
        assessment_id — links to a stored breach assessment for context enrichment

    Body params (all optional):
        organisation, assessor, dpo, supervisory_authority
    """
    from src.reporting.regulatory_draft import build_regulatory_draft  # type: ignore

    # Look up assessment data
    assessment: dict = {}
    if assessment_id:
        try:
            from src.api.breach_endpoints import REPORT_STORE  # type: ignore
            assessment = REPORT_STORE.get(assessment_id) or {}
        except Exception:
            pass
        if not assessment:
            try:
                from src.core.ingest import assessment_store  # type: ignore
                assessment = assessment_store.get(assessment_id) or {}
            except Exception:
                pass
        if assessment:
            assessment['assessment_id'] = assessment_id

    meta = {k: v for k, v in (payload or {}).items()
            if k in ('organisation', 'assessor', 'dpo', 'supervisory_authority')}

    draft = build_regulatory_draft(action_type, assessment, meta)
    if draft.get('error'):
        raise HTTPException(status_code=400, detail=draft['error'])
    return JSONResponse(draft)
