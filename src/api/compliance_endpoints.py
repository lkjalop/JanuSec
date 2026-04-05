from __future__ import annotations

from typing import Any, Dict, List
import base64
import time
import json
import uuid
import hashlib

from fastapi import APIRouter, UploadFile, File, HTTPException, Body, Query, Header, Request
from pydantic import BaseModel
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
import io

from security.auth import require_scopes
from src.modules.compliance_mapper import ComplianceMapper
from src.modules.compliance.taxonomy_loader import ControlTaxonomyLoader
from .taxonomy_mapper import map_mitre_to_taxonomies
from .tenant_helpers import resolve_tenant_id
try:
    from src.core.ai_governance.eu_ai_act_compliance import EUAIActRiskManagement  # type: ignore
except Exception:  # pragma: no cover
    try:
        from core.ai_governance.eu_ai_act_compliance import EUAIActRiskManagement  # type: ignore
    except Exception:  # pragma: no cover
        EUAIActRiskManagement = None  # type: ignore
try:
    from src.core.ai_governance.dataset_governance import DatasetGovernance  # type: ignore
except Exception:  # pragma: no cover
    try:
        from core.ai_governance.dataset_governance import DatasetGovernance  # type: ignore
    except Exception:  # pragma: no cover
        DatasetGovernance = None  # type: ignore
from .integrations_endpoints import _STATE as _INTEGRATIONS_STATE  # reuse in-memory config
import httpx
import asyncio
import os
try:
    from prometheus_client import Counter as _PCounter, Gauge as _PGauge  # type: ignore
except Exception:  # pragma: no cover
    _PCounter = None  # type: ignore
    _PGauge = None  # type: ignore

class _NoopCounter:
    def labels(self,*a,**k): return self
    def inc(self,*a,**k): return None

def _safe_counter(name: str, desc: str, labelnames: list[str] | tuple[str, ...]):
    try:
        if _PCounter is None:
            return _NoopCounter()
        # Attempt to create; if already registered, return noop to avoid duplicate errors during tests
        return _PCounter(name, desc, list(labelnames))
    except Exception:
        # Duplicated timeseries or other registry errors -> noop
        return _NoopCounter()

class _NoopGauge:
    def labels(self,*a,**k): return self
    def set(self,*a,**k): return None

def _safe_gauge(name: str, desc: str, labelnames: list[str] | tuple[str, ...]):
    try:
        if _PGauge is None:
            return _NoopGauge()
        return _PGauge(name, desc, list(labelnames))
    except Exception:
        return _NoopGauge()


router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance"])

_ASSESSMENT_CACHE: dict[str, dict[str, dict[str, Any]]] = {}  # tenant -> {assessment_id: {result, graph}}
_CMP_JOBS: dict[str, dict[str, Any]] = {}  # job_id -> job meta (includes tenant)

_cmp_assess_total = _safe_counter('janusec_compliance_assess_total','Total compliance assessments',['mode'])
_cmp_report_total = _safe_counter('janusec_compliance_report_total','Total compliance reports',['format'])

# IAM/SG metrics (gauges/counters)
_iam_keys_no_mfa = _safe_gauge('iam_keys_no_mfa','Keys without MFA',['tenant'])
_iam_unused_keys = _safe_gauge('iam_unused_keys_over_90d','Unused keys over 90 days',['tenant'])
_iam_wildcard_policies = _safe_gauge('iam_wildcard_policies','Policies with wildcards',['tenant'])
_iam_admin_no_mfa = _safe_gauge('iam_admins_without_mfa','Admin users without MFA',['tenant'])
_sg_drift_events = _safe_counter('sg_drift_events_total','Total SG drift events',['tenant','change'])
_sg_open_world = _safe_counter('sg_open_to_world_total','Total SG rules open to world',['tenant'])

# Posture ingest metrics
_posture_ingest_total = _safe_counter('posture_ingest_total','Total posture findings ingested',['tenant'])
_posture_ingest_lag = _safe_gauge('posture_ingest_lag_seconds','Average ingest lag (source_ts->ingest) in seconds',['tenant'])


def _gen_assessment_id() -> str:
    return f"cmp-{int(time.time()*1000)}"


def _tenant_key(tenant_id: str | None) -> str:
    return tenant_id or 'default'


def _mk_dirs(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        pass


def _audit_log_path() -> str:
    path = os.getenv('COMPLIANCE_AUDIT_LOG', 'artifacts/compliance/audit_trail.jsonl')
    _mk_dirs(os.path.dirname(path))
    return path


def _append_audit(tenant: str, action: str, meta: dict[str, Any] | None = None, assessment_id: str | None = None, actor: str | None = None) -> None:
    rec = {
        'ts': time.time(),
        'tenant_id': tenant,
        'action': action,
        'actor': actor,
        'assessment_id': assessment_id,
        **(meta or {}),
    }
    # Persist to JSONL
    try:
        p = _audit_log_path()
        with open(p, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass
    # Attach to assessment cache trail if known
    if assessment_id:
        try:
            a = _ASSESSMENT_CACHE.get(tenant, {}).get(str(assessment_id))
            if a is not None:
                trail = a.setdefault('audit_trail', [])
                if isinstance(trail, list):
                    trail.append(rec)
        except Exception:
            pass


_STRIDE_TO_CONTROLS = {
    'spoofing': ['ISO27001 A.9', 'NIST AC-2'],
    'tampering': ['ISO27001 A.8', 'NIST SI-7'],
    'repudiation': ['ISO27001 A.5', 'NIST AU-3'],
    'information_disclosure': ['ISO27001 A.8', 'NIST SC-13'],
    'denial': ['ISO27001 A.7', 'NIST CP-10'],
    'elevation': ['ISO27001 A.8', 'NIST AC-6'],
    'discovery': ['ISO27001 A.8', 'NIST CA-7'],
    'execution': ['ISO27001 A.8', 'NIST SI-3'],
    'lateral_movement': ['ISO27001 A.8', 'NIST AC-4'],
    'persistence': ['ISO27001 A.8', 'NIST CM-7'],
    'defense_evasion': ['ISO27001 A.8', 'NIST SI-4'],
    'recon': ['ISO27001 A.5', 'NIST PM-16'],
    'exfiltration': ['ISO27001 A.8', 'NIST SC-7']
}

# Lightweight crosswalk of STRIDE categories to multiple frameworks (hints only)
_CROSSMAP_STRIDE = {
    'execution': {
        'iso27001': ['A.12.6.2','A.14.2.5'],
        'soc2': ['CC7.2'],
        'iso42001': ['AI.8.2'],      # placeholder/hint
        'iso19001': ['QMS.7.5'],     # placeholder/hint
        'isms': ['ISMS.AC','ISMS.OP']
    },
    'lateral_movement': {
        'iso27001': ['A.13.1.1','A.13.1.3'],
        'soc2': ['CC6.6','CC6.7'],
        'iso42001': ['AI.7.3'],
        'iso19001': ['QMS.8.1'],
        'isms': ['ISMS.NW']
    },
    'defense_evasion': {
        'iso27001': ['A.12.4.1','A.12.4.3'],
        'soc2': ['CC7.3'],
        'iso42001': ['AI.9.4'],
        'iso19001': ['QMS.9.1'],
        'isms': ['ISMS.MON']
    },
    'persistence': {
        'iso27001': ['A.12.1.2','A.12.5.1'],
        'soc2': ['CC7.4'],
        'iso42001': ['AI.8.4'],
        'iso19001': ['QMS.8.5'],
        'isms': ['ISMS.CH']
    },
    'exfiltration': {
        'iso27001': ['A.13.2.1','A.13.2.3'],
        'soc2': ['CC6.3'],
        'iso42001': ['AI.10.2'],
        'iso19001': ['QMS.8.2'],
        'isms': ['ISMS.DLP']
    },
    'spoofing': {
        'iso27001': ['A.9.2.3'],
        'soc2': ['CC6.1'],
        'iso42001': ['AI.6.1'],
        'iso19001': ['QMS.5.3'],
        'isms': ['ISMS.AU']
    },
    'tampering': {
        'iso27001': ['A.12.2.1','A.14.2.8'],
        'soc2': ['CC6.8'],
        'iso42001': ['AI.8.6'],
        'iso19001': ['QMS.8.7'],
        'isms': ['ISMS.INT']
    },
    'information_disclosure': {
        'iso27001': ['A.18.1.3','A.10.1.1'],
        'soc2': ['CC6.3','CC6.7'],
        'iso42001': ['AI.11.1'],
        'iso19001': ['QMS.7.1'],
        'isms': ['ISMS.CLS']
    },
}


@router.get('/map/stride')
async def stride_mapping() -> dict[str, Any]:
    """Return a lightweight mapping of STRIDE categories to ISO/NIST hints for UI/report references."""
    return {'stride_to_controls': _STRIDE_TO_CONTROLS}


class MitreMapRequest(BaseModel):
    mitre_ids: List[str]


@router.post('/map/mitre', summary='Map MITRE techniques to STRIDE/DREAD/CVSS/compliance controls')
async def mitre_mapping(payload: MitreMapRequest) -> dict[str, Any]:
    mitre_ids = [m for m in (payload.mitre_ids or []) if isinstance(m, str) and m.strip()]
    mapped = map_mitre_to_taxonomies(mitre_ids)
    return {'mitre_ids': mitre_ids, 'mapping': mapped}


@router.get('/summary')
async def compliance_summary(
    limit_events: int = Query(500, le=2000),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> dict[str, Any]:
    """Summarize recent decisions into prioritized STRIDE control gaps with ISO/NIST hints.

    Heuristic scoring:
      - Each observed event mapped to a STRIDE category contributes a weight by severity.
      - Verdict+confidence drive weight: critical=3, high=2, medium=1, low=0.5.
    """
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    # Import runtime caches lazily to avoid circulars
    try:
        from .runtime_state import DECISION_CACHE  # type: ignore
    except Exception:
        DECISION_CACHE = {}

    # Local STRIDE -> control hints (keep consistent with /map/stride)
    stride_to_controls = _STRIDE_TO_CONTROLS

    # Minimal severity weight mapping
    def _severity_weight(verdict: str | None, confidence: float | None) -> float:
        v = (verdict or '').lower()
        c = float(confidence or 0.0)
        if v in {'malicious', 'block', 'escalate'} and c >= 0.9:
            return 3.0
        if c >= 0.75:
            return 2.0
        if c >= 0.55:
            return 1.0
        return 0.5

    # Collect recent window
    items = list(DECISION_CACHE.values())[-limit_events:]
    # Aggregate STRIDE and scenarios
    try:
        from core.threat_modeling.factor_taxonomy import aggregate_threat_model  # type: ignore
    except Exception:
        aggregate_threat_model = None  # type: ignore
    try:
        from core.threat_modeling.scenario_engine import ENGINE as SCEN_ENGINE  # type: ignore
    except Exception:
        SCEN_ENGINE = None  # type: ignore

    stride_scores: dict[str, dict[str, float | int]] = {}
    scenario_counts: dict[str, dict[str, Any]] = {}
    sampled = 0
    for d in items:
        # Tenant filter (best-effort)
        try:
            if tenant_id and getattr(d, 'tenant_id', None) not in {tenant_id}:
                continue
        except Exception:
            pass
        try:
            verdict = getattr(d, 'verdict', None) or (d.get('verdict') if isinstance(d, dict) else None)
            confidence = getattr(d, 'confidence', None) or (d.get('confidence') if isinstance(d, dict) else None)
            factors = getattr(d, 'factors', None) or (d.get('factors') if isinstance(d, dict) else [])
        except Exception:
            verdict, confidence, factors = None, None, []
        weight = _severity_weight(str(verdict) if verdict is not None else None, float(confidence) if confidence is not None else None)
        cats: list[str] = []
        if aggregate_threat_model and isinstance(factors, list):
            try:
                model = aggregate_threat_model(list(factors))
                cats = (model.get('stride') or {}).get('categories', []) or []
            except Exception:
                cats = []
        for c in cats:
            entry = stride_scores.setdefault(c, {'score': 0.0, 'count': 0})
            entry['score'] = float(entry['score']) + float(weight)
            entry['count'] = int(entry['count']) + 1
        # scenarios
        if SCEN_ENGINE and isinstance(factors, list):
            try:
                scens = SCEN_ENGINE.evaluate(list(factors))
                for s in scens or []:
                    sid = s.get('id')
                    if not sid:
                        continue
                    ent = scenario_counts.setdefault(sid, {'id': sid, 'occurrences': 0, 'max_risk': 0.0, 'tags': s.get('tags') or []})
                    ent['occurrences'] = int(ent['occurrences'] or 0) + 1
                    cr = s.get('composite_risk') or 0.0
                    try:
                        crf = float(cr)
                        if crf > float(ent['max_risk']):
                            ent['max_risk'] = crf
                    except Exception:
                        pass
            except Exception:
                pass
        sampled += 1

    # Build priorities
    priorities = []
    for cat, vals in stride_scores.items():
        controls = stride_to_controls.get(cat, [])
        # Minimal remediation checklist by category
        rem: list[str] = []
        c = cat.lower()
        if c in {'execution'}:
            rem = ['Harden macro/script policies', 'Application control on endpoints', 'Disable unnecessary interpreters']
        elif c in {'lateral_movement'}:
            rem = ['Enforce network segmentation', 'Restrict admin shares/WinRM/SSH', 'Tiered admin model']
        elif c in {'defense_evasion'}:
            rem = ['EDR tamper protection', 'Script block logging', 'Audit disable-security tooling']
        elif c in {'persistence'}:
            rem = ['Monitor startup items/services', 'Block unsigned drivers', 'Harden scheduled tasks']
        elif c in {'exfiltration'}:
            rem = ['Egress filtering', 'DLP on sensitive routes', 'TLS inspection as permitted']
        elif c in {'spoofing'}:
            rem = ['MFA enforcement', 'Strong auth for privileged ops', 'Phishing-resistant tokens']
        elif c in {'tampering'}:
            rem = ['Code integrity', 'File integrity monitoring', 'Immutable backups']
        elif c in {'denial'}:
            rem = ['Rate limits & backpressure', 'Autoscaling guards', 'WAF/DoS protections']
        elif c in {'discovery','recon'}:
            rem = ['Network telemetry & baselines', 'Hardened banners', 'Limit unauthenticated enumeration']
        elif c in {'information_disclosure'}:
            rem = ['Classify/tag data', 'Encrypt in transit/at rest', 'Least-privilege access reviews']
        elif c in {'elevation'}:
            rem = ['Privilege separation', 'JIT/JEA for admin', 'Harden sudo/UAC policies']

        priorities.append({
            'category': cat,
            'score': round(float(vals['score']), 2),
            'occurrences': int(vals['count']),
            'controls': controls,
            'iso': [c for c in controls if c.startswith('ISO')],
            'nist': [c for c in controls if c.startswith('NIST')],
            'remediation': rem,
        })

    priorities.sort(key=lambda x: (-x['score'], -x['occurrences'], x['category']))

    top_scenarios = sorted(scenario_counts.values(), key=lambda x: (-float(x.get('max_risk') or 0.0), -int(x.get('occurrences') or 0), x.get('id') or ''))[:10]

    return {
        'generated_at': time.time(),
        'tenant_id': tenant_id,
        'window_sampled': sampled,
        'stride_priorities': priorities,
        'top_scenarios': top_scenarios,
        'notes': 'Heuristic priority based on recent decision severity and STRIDE mapping',
        'meta': {'limit_events': limit_events}
    }


@router.get('/crossmap', summary='Cross-map STRIDE categories to SOC2/ISO27001/ISO42001/ISO19001/ISMS (hints)')
async def crossmap() -> dict[str, Any]:
    # Provide the static crosswalk plus simple counts per framework
    fmwks = ['iso27001','soc2','iso42001','iso19001','isms']
    counts = {k: 0 for k in fmwks}
    for _cat, mp in _CROSSMAP_STRIDE.items():
        for f in fmwks:
            if mp.get(f):
                counts[f] += len(mp[f])
    return {
        'frameworks': fmwks,
        'counts': counts,
        'crossmap': _CROSSMAP_STRIDE,
        'notes': 'Indicative mapping only; use as decision-support, not formal GRC attestation.'
    }


@router.get('/kev/status', summary='KEV/EPSS enrichment cache status')
async def kev_status() -> dict[str, Any]:
    try:
        from src.integrations.vuln_enrichment import ENRICHER  # type: ignore
    except Exception:
        try:
            from integrations.vuln_enrichment import ENRICHER  # type: ignore
        except Exception:
            ENRICHER = None  # type: ignore
    if ENRICHER is None:
        raise HTTPException(status_code=503, detail='enricher_unavailable')
    now = time.time()
    kev_age = (now - float(getattr(ENRICHER, '_kev_last', 0.0))) if getattr(ENRICHER, '_kev_last', 0.0) else None
    epss_age = (now - float(getattr(ENRICHER, '_epss_last', 0.0))) if getattr(ENRICHER, '_epss_last', 0.0) else None
    kev_count = len(getattr(ENRICHER, '_kev_set', set()) or [])
    epss_count = len(getattr(ENRICHER, '_epss_map', {}) or {})
    return {
        'kev_cached': kev_count,
        'kev_age_seconds': int(kev_age) if kev_age is not None else None,
        'epss_cached': epss_count,
        'epss_age_seconds': int(epss_age) if epss_age is not None else None,
    }


@router.post('/kev/refresh', summary='Trigger KEV/EPSS refresh (best-effort)', operation_id='compliance_kev_refresh')
async def kev_refresh() -> dict[str, Any]:
    try:
        from src.integrations.vuln_enrichment import ENRICHER  # type: ignore
    except Exception:
        try:
            from integrations.vuln_enrichment import ENRICHER  # type: ignore
        except Exception:
            ENRICHER = None  # type: ignore
    if ENRICHER is None:
        raise HTTPException(status_code=503, detail='enricher_unavailable')
    # best-effort refresh; EPSS requires CVEs list; refresh_kev always ok
    try:
        await ENRICHER.refresh_kev()
        await ENRICHER.refresh_epss([])
        return {'ok': True}
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}

@router.get('/eu-ai-act/article-9', summary='EU AI Act Article 9 risk management report')
async def eu_ai_act_article9() -> dict[str, Any]:
    if EUAIActRiskManagement is None:  # type: ignore
        raise HTTPException(status_code=503, detail='module_unavailable')
    rm = EUAIActRiskManagement()  # type: ignore
    report = rm.generate_article_9_report()
    return {
        'report': report,
        'compliance_status': 'compliant' if int(report.get('overdue_reviews') or 0) == 0 else 'non_compliant',
    }


@router.get('/eu-ai-act/article-10', summary='EU AI Act Article 10 dataset governance report')
async def eu_ai_act_article10() -> dict[str, Any]:
    if DatasetGovernance is None:  # type: ignore
        raise HTTPException(status_code=503, detail='module_unavailable')
    dg = DatasetGovernance()  # type: ignore
    report = dg.generate_article_10_report()
    return {'report': report}


@router.get('/bias/report', summary='Bias testing report over recent decisions (heuristic)')
async def bias_report(
    attr: str = Query('tenant_id'),
    include_suspicious: bool = Query(False),
    limit_events: int = Query(1000, ge=10, le=10000),
    window_seconds: int | None = Query(None, ge=60, le=60*60*24*90, description='Optional time window to filter recent decisions'),
) -> dict[str, Any]:
    try:
        from .runtime_state import DECISION_CACHE  # type: ignore
    except Exception:
        DECISION_CACHE = {}
    # Collect recent decisions (optionally windowed by timestamp)
    items = list(DECISION_CACHE.values())
    now = time.time()
    decisions: list[Any] = []
    if window_seconds:
        cutoff = now - float(window_seconds)
        for d in items:
            ts = None
            try:
                # Pydantic model attr or plain dict field
                ts = getattr(d, 'timestamp', None)
                if ts is None and isinstance(d, dict):
                    ts = d.get('timestamp') or d.get('ts')
            except Exception:
                ts = None
            try:
                if ts is not None and float(ts) >= cutoff:
                    decisions.append(d)
            except Exception:
                # if timestamp invalid, skip in windowed mode
                pass
        # Respect limit after filtering
        if len(decisions) > limit_events:
            decisions = decisions[-limit_events:]
    else:
        decisions = items[-limit_events:]
    # Compute metrics
    try:
        from src.core.ai_governance.bias_testing import compute_bias  # type: ignore
    except Exception:
        from core.ai_governance.bias_testing import compute_bias  # type: ignore
    res = compute_bias(decisions, attr, include_suspicious)
    return res


@router.post('/ai-incident-plan', summary='Generate AI Incident Response Plan (structured)')
async def ai_incident_plan() -> dict[str, Any]:
    """Return a lightweight, structured AI incident response playbook.

    This is a reference template for demo purposes and not a formal attestation.
    """
    plan = {
        'version': '1.0',
        'generated_at': time.time(),
        'roles': [
            {'role': 'Incident Commander', 'owner': 'Security Manager', 'backup': 'Security Lead'},
            {'role': 'Comms Lead', 'owner': 'PR/Comms', 'backup': 'Legal Liaison'},
            {'role': 'Forensics Lead', 'owner': 'DFIR Analyst', 'backup': 'Senior Analyst'},
            {'role': 'Ops Lead', 'owner': 'Platform SRE', 'backup': 'On-call SRE'},
        ],
        'triggers': [
            'Confirmed malicious model output impacting users',
            'Prompt injection leading to data exfiltration attempt',
            'High-risk label flip rate indicating model compromise',
            'Third-party advisory (KEV/EPSS critical) impacting dependencies'
        ],
        'communications': {
            'internal': ['Slack #sec-incident', 'War room bridge', 'Executive brief every 4h'],
            'external': ['Customer status page if user-impacting', 'Regulatory notice per jurisdiction']
        },
        'evidence_retention': {
            'duration_days': 90,
            'artifacts': ['model inputs/outputs (redacted)', 'system logs', 'alert timeline', 'model version/weights hash']
        },
        'triage_slos': {
            'ack_minutes': 15,
            'containment_minutes': 60,
            'eradication_hours': 24
        },
        'playbook': [
            {'step': 'Ack + classify severity', 'owner': 'Incident Commander'},
            {'step': 'Contain via feature flags/killswitch', 'owner': 'Ops Lead'},
            {'step': 'Collect evidence and snapshots', 'owner': 'Forensics Lead'},
            {'step': 'Stakeholder comms and status cadence', 'owner': 'Comms Lead'},
            {'step': 'Root cause + corrective actions', 'owner': 'Forensics Lead'},
            {'step': 'Post-incident review + improvements', 'owner': 'Incident Commander'},
        ],
        'notes': 'Template plan; customize per organization. Not legal advice.'
    }
    return {'plan': plan}


@router.get('/metrics/validate', summary='Validate external metrics vs internal cache (heuristic)')
async def metrics_validate() -> dict[str, Any]:
    try:
        from .runtime_state import DECISION_CACHE  # type: ignore
    except Exception:
        DECISION_CACHE = {}
    cache_size = len(DECISION_CACHE)
    # Probe Prometheus registry if available
    registry_ok = False
    scrape_len = 0
    try:
        from prometheus_client import generate_latest  # type: ignore
        data = generate_latest()  # bytes
        scrape_len = len(data or b'')
        registry_ok = scrape_len > 0
    except Exception:
        registry_ok = False
        scrape_len = 0
    # Simple heuristic: if registry exists, ensure scrape non-empty
    return {
        'registry_ok': registry_ok,
        'decision_cache_size': cache_size,
        'metrics_scrape_bytes': scrape_len,
        'ok': bool(cache_size >= 0 and (not registry_ok or scrape_len > 0)),
        'notes': 'Heuristic consistency check; not a formal SLO.'
    }


@router.post('/assess')
async def assess_json(
    payload: Dict[str, Any] = Body(...),
    external: bool = Query(False),
    background: bool = Query(False),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
    auth=require_scopes('factors.search')
) -> JSONResponse:
    try:
        tenant_id = resolve_tenant_id(request, tenant_id or (payload.get('tenant_id') if isinstance(payload, dict) else None))
    except Exception:
        pass
    framework = str(payload.get('framework') or 'ISO27001')
    docs: List[dict] = []
    for d in payload.get('documents') or []:
        if not isinstance(d, dict):
            continue
        name = str(d.get('filename') or d.get('name') or 'document')
        if 'text' in d and isinstance(d['text'], str):
            docs.append({'filename': name, 'text': d['text']})
        elif 'content_base64' in d and isinstance(d['content_base64'], str):
            try:
                b = base64.b64decode(d['content_base64'])
            except Exception:
                b = b''
            docs.append({'filename': name, 'content': b})
    if not docs:
        raise HTTPException(status_code=400, detail='no_documents')
    # External processing path
    if external:
        entry = _INTEGRATIONS_STATE.get('compliance')
        url = entry and entry.get('webhook_url')
        if not (entry and entry.get('connected') and url):
            raise HTTPException(status_code=503, detail='compliance_external_unavailable')
        job_id = f"job-{int(time.time()*1000)}"
        _CMP_JOBS[job_id] = {
            'job_id': job_id,
            'tenant_id': tenant_id,
            'framework': framework,
            'status': 'queued',
            'created': time.time(),
            'assessment_id': None,
            'error': None,
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(str(url), json={'job_id': job_id, 'tenant_id': tenant_id, 'framework': framework, 'documents': docs})
        except Exception as e:
            _CMP_JOBS[job_id]['status'] = 'error'
            _CMP_JOBS[job_id]['error'] = str(e)
            raise HTTPException(status_code=502, detail='webhook_dispatch_failed')
        _cmp_assess_total.labels(mode='external').inc()
        return JSONResponse({'job_id': job_id, 'status': 'queued'}, status_code=202)
    # Local background job
    if background:
        job_id = f"job-{int(time.time()*1000)}"
        _CMP_JOBS[job_id] = {
            'job_id': job_id,
            'tenant_id': tenant_id,
            'framework': framework,
            'status': 'queued',
            'created': time.time(),
            'assessment_id': None,
            'error': None,
        }
        async def _run():
            try:
                mapper = ComplianceMapper({})
                res = await mapper.assess_documents(framework, docs)
                aid = _gen_assessment_id()
                g = res.pop('_graph', None)
                t = _tenant_key(tenant_id)
                _ASSESSMENT_CACHE.setdefault(t, {})[str(aid)] = {'result': res, 'graph': g}
                _CMP_JOBS[job_id]['status'] = 'completed'
                _CMP_JOBS[job_id]['assessment_id'] = aid
                _cmp_assess_total.labels(mode='local').inc()
                try:
                    filenames = [d.get('filename') for d in docs if isinstance(d, dict)]
                except Exception:
                    filenames = []
                _append_audit(_tenant_key(tenant_id), 'created_assessment', {'framework': framework, 'files': filenames}, assessment_id=str(aid))
            except Exception as e:
                _CMP_JOBS[job_id]['status'] = 'error'
                _CMP_JOBS[job_id]['error'] = str(e)
        try:
            asyncio.create_task(_run())
        except Exception:
            # fallback: run inline if loop missing
            await _run()
        return JSONResponse({'job_id': job_id, 'status': 'queued'}, status_code=202)

    # Local processing
    mapper = ComplianceMapper({})
    res = await mapper.assess_documents(framework, docs)
    aid = payload.get('assessment_id') or _gen_assessment_id()
    g = res.pop('_graph', None)
    t = _tenant_key(tenant_id)
    _ASSESSMENT_CACHE.setdefault(t, {})[str(aid)] = {'result': res, 'graph': g}
    _cmp_assess_total.labels(mode='local').inc()
    try:
        filenames = [d.get('filename') for d in docs if isinstance(d, dict)]
    except Exception:
        filenames = []
    _append_audit(t, 'created_assessment', {'framework': framework, 'files': filenames}, assessment_id=str(aid))
    return JSONResponse({'assessment_id': aid, **res})


@router.post('/assess/files')
async def assess_files(
    files: List[UploadFile] = File(...),
    framework: str = Query('ISO27001'),
    external: bool = Query(False),
    background: bool = Query(False),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> JSONResponse:
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    if not files:
        raise HTTPException(status_code=400, detail='no_files')
    docs: List[dict] = []
    MAX_SIZE = 10 * 1024 * 1024  # 10MB per file
    ALLOWED = ('.pdf', '.txt', '.md', '.log', '.json')
    for f in files:
        try:
            content = await f.read()
        except Exception:
            content = b''
        name = (f.filename or 'document')
        if not name.lower().endswith(ALLOWED):
            raise HTTPException(status_code=415, detail='unsupported_media_type')
        if len(content) > MAX_SIZE:
            raise HTTPException(status_code=413, detail='file_too_large')
        # Optional: extract text from PDFs for better control keyword matching
        if name.lower().endswith('.pdf') and content:
            text = None
            try:
                import io
                try:
                    import pdfplumber  # type: ignore
                    with pdfplumber.open(io.BytesIO(content)) as pdf:
                        pages = [p.extract_text() or '' for p in pdf.pages]
                        text = '\n'.join(pages)
                except Exception:
                    text = None
            except Exception:
                text = None
            if text and text.strip():
                docs.append({'filename': name, 'text': text})
            else:
                docs.append({'filename': name, 'content': content})
        else:
            docs.append({'filename': name, 'content': content})
    if external:
        entry = _INTEGRATIONS_STATE.get('compliance')
        url = entry and entry.get('webhook_url')
        if not (entry and entry.get('connected') and url):
            raise HTTPException(status_code=503, detail='compliance_external_unavailable')
        job_id = f"job-{int(time.time()*1000)}"
        _CMP_JOBS[job_id] = {
            'job_id': job_id,
            'tenant_id': tenant_id,
            'framework': framework,
            'status': 'queued',
            'created': time.time(),
            'assessment_id': None,
            'error': None,
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                # Convert to base64 for transport
                import base64
                docs64 = [{'filename': d['filename'], 'content_base64': base64.b64encode(d['content']).decode('ascii')} for d in docs]
                await client.post(str(url), json={'job_id': job_id, 'tenant_id': tenant_id, 'framework': framework, 'documents': docs64})
        except Exception as e:
            _CMP_JOBS[job_id]['status'] = 'error'
            _CMP_JOBS[job_id]['error'] = str(e)
            raise HTTPException(status_code=502, detail='webhook_dispatch_failed')
        _cmp_assess_total.labels(mode='external').inc()
        return JSONResponse({'job_id': job_id, 'status': 'queued'}, status_code=202)
    # Local background job
    if background and not external:
        job_id = f"job-{int(time.time()*1000)}"
        _CMP_JOBS[job_id] = {
            'job_id': job_id,
            'tenant_id': tenant_id,
            'framework': framework,
            'status': 'queued',
            'created': time.time(),
            'assessment_id': None,
            'error': None,
        }
        async def _run():
            try:
                mapper = ComplianceMapper({})
                res = await mapper.assess_documents(framework, docs)
                aid = _gen_assessment_id()
                g = res.pop('_graph', None)
                t = _tenant_key(tenant_id)
                _ASSESSMENT_CACHE.setdefault(t, {})[str(aid)] = {'result': res, 'graph': g}
                _CMP_JOBS[job_id]['status'] = 'completed'
                _CMP_JOBS[job_id]['assessment_id'] = aid
                _cmp_assess_total.labels(mode='local').inc()
                try:
                    filenames = [d.get('filename') for d in docs if isinstance(d, dict)]
                except Exception:
                    filenames = []
                _append_audit(_tenant_key(tenant_id), 'created_assessment', {'framework': framework, 'files': filenames}, assessment_id=str(aid))
            except Exception as e:
                _CMP_JOBS[job_id]['status'] = 'error'
                _CMP_JOBS[job_id]['error'] = str(e)
        try:
            asyncio.create_task(_run())
        except Exception:
            await _run()
        return JSONResponse({'job_id': job_id, 'status': 'queued'}, status_code=202)

    mapper = ComplianceMapper({})
    res = await mapper.assess_documents(framework, docs)
    aid = _gen_assessment_id()
    g = res.pop('_graph', None)
    t = _tenant_key(tenant_id)
    _ASSESSMENT_CACHE.setdefault(t, {})[aid] = {'result': res, 'graph': g}
    _cmp_assess_total.labels(mode='local').inc()
    try:
        filenames = [d.get('filename') for d in docs if isinstance(d, dict)]
    except Exception:
        filenames = []
    _append_audit(t, 'created_assessment', {'framework': framework, 'files': filenames}, assessment_id=str(aid))
    return JSONResponse({'assessment_id': aid, **res})


@router.get('/frameworks')
async def list_frameworks() -> dict[str, Any]:
    # Discover available frameworks from taxonomy files
    loader = ControlTaxonomyLoader()
    fws = loader.available_frameworks()
    return {'frameworks': fws}


@router.get('/controls')
async def list_controls(framework: str = Query('ISO27001')) -> dict[str, Any]:
    loader = ControlTaxonomyLoader()
    controls = loader.load_for(framework)
    return {'framework': framework, 'count': len(controls), 'controls': controls}


@router.get('/taxonomy/validate')
async def taxonomy_validate() -> dict[str, Any]:
    loader = ControlTaxonomyLoader()
    controls = loader.load()
    missing = [c for c in controls if not c.get('control_id') or not c.get('title')]
    return {
        'controls_loaded': len(controls),
        'missing_required': len(missing),
        'ok': len(missing) == 0
    }


@router.get('/report')
async def compliance_report(
    assessment_id: str,
    format: str = Query('html', pattern='^(html|pdf)$'),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
):
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    t = _tenant_key(tenant_id)
    item = (_ASSESSMENT_CACHE.get(t) or {}).get(assessment_id)
    if not item:
        raise HTTPException(status_code=404, detail='assessment_not_found')
    res = item['result']
    if format == 'html':
        # Simple HTML using a minimal dark style
        def esc(x):
            import html
            return html.escape(str(x))
        rows = ''.join(f"<tr><td>{esc(c['control_id'])}</td><td>{esc(c['title'])}</td><td>{esc(c['score'])}</td><td>{esc(c['risk_tier'])}</td><td>{esc(c['domain'])}</td></tr>" for c in res.get('control_results', [])[:200])
        html = f"""
<!DOCTYPE html><html><head><meta charset='utf-8'><title>Compliance Report</title>
<style>body{{background:#0b0e14;color:#e8ebf0;font-family:Arial,sans-serif}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #2a3142;padding:6px 8px;font-size:12px}}</style></head>
<body>
<h2>Compliance Assessment Report</h2>
<div>Framework: {esc(res.get('framework',''))}</div>
<div>Overall Score: {esc(res.get('overall_score',''))}</div>
<div>Risk Matrix: {esc(res.get('risk_matrix',''))}</div>
<h3>Controls</h3>
<table><tr><th>Control</th><th>Title</th><th>Score</th><th>Risk</th><th>Domain</th></tr>{rows}</table>
</body></html>"""
        _cmp_report_total.labels(format='html').inc()
        try:
            _append_audit(t, 'generated_report', {'format': 'html'}, assessment_id=str(assessment_id))
        except Exception:
            pass
        return HTMLResponse(html)
    # PDF
    try:
        from reportlab.lib.pagesizes import LETTER
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        import io
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=LETTER, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        story = [Paragraph('Compliance Assessment Report', styles['Title']), Spacer(1, 12)]
        story.append(Paragraph(f"Framework: {res.get('framework','')}", styles['Normal']))
        story.append(Paragraph(f"Overall Score: {res.get('overall_score','')}", styles['Normal']))
        story.append(Paragraph(f"Risk Matrix: {res.get('risk_matrix','')}", styles['Normal']))
        data = [['Control','Title','Score','Risk','Domain']]
        for c in res.get('control_results', [])[:200]:
            data.append([c.get('control_id'), c.get('title'), c.get('score'), c.get('risk_tier'), c.get('domain')])
        tbl = Table(data)
        tbl.setStyle(TableStyle([
            ('GRID',(0,0),(-1,-1),0.4,colors.grey),
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#253347')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ]))
        story.append(Spacer(1, 12))
        story.append(tbl)
        doc.build(story)
        buf.seek(0)
        from fastapi.responses import StreamingResponse
        _cmp_report_total.labels(format='pdf').inc()
        try:
            _append_audit(t, 'generated_report', {'format': 'pdf'}, assessment_id=str(assessment_id))
        except Exception:
            pass
        return StreamingResponse(buf, media_type='application/pdf', headers={'Content-Disposition': 'attachment; filename="compliance_report.pdf"'})
    except Exception:
        raise HTTPException(status_code=501, detail='pdf_generation_unavailable')


def _titanai_professional_pdf(res: dict[str, Any], org_name: str | None = None, auditor: str | None = None, executive_override: str | None = None, ai_insights: list[str] | None = None) -> bytes:
    """Generate an enhanced multi-section PDF (Pro) using reportlab.

    This mirrors a professional layout: title, executive summary, risk matrix,
    prioritized control list, and recommendations. It uses the cached
    assessment result and optional editor overrides.
    """
    try:
        from reportlab.lib.pagesizes import LETTER
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
    except Exception as e:
        raise HTTPException(status_code=501, detail=f'pdf_lib_missing:{e}')

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER, leftMargin=40, rightMargin=40, topMargin=48, bottomMargin=48)
    styles = getSampleStyleSheet()
    story = []

    org = org_name or 'Your Organization'
    assessor = auditor or 'JanuSec Compliance Professional'
    # Title
    story.append(Paragraph('JanuSec Professional Compliance Assessment', styles['Title']))
    story.append(Paragraph(f'Organization: {org}', styles['Normal']))
    story.append(Paragraph(f'Assessor: {assessor}', styles['Normal']))
    story.append(Paragraph(f'Framework: {res.get("framework","ISO27001")}', styles['Normal']))
    story.append(Spacer(1, 16))

    # Executive summary
    story.append(Paragraph('Executive Summary', styles['Heading2']))
    if executive_override:
        story.append(Paragraph(executive_override.replace('\n','<br/>'), styles['Normal']))
    else:
        matrix = res.get('risk_matrix', {}) or {}
        overall = res.get('overall_score')
        summ = f"Overall score: {overall if overall is not None else 'n/a'}. High: {matrix.get('High',0)}, Medium: {matrix.get('Medium',0)}, Low: {matrix.get('Low',0)}."
        story.append(Paragraph(summ, styles['Normal']))
    story.append(Spacer(1, 10))

    # Risk matrix table
    rm = res.get('risk_matrix', {}) or {}
    rm_rows = [['Risk Tier','Count'], ['High', rm.get('High',0)], ['Medium', rm.get('Medium',0)], ['Low', rm.get('Low',0)]]
    tbl_rm = Table(rm_rows, hAlign='LEFT')
    tbl_rm.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0), colors.HexColor('#253347')),
        ('TEXTCOLOR',(0,0),(-1,0), colors.whitesmoke),
        ('GRID',(0,0),(-1,-1),0.4, colors.grey),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
    ]))
    story.append(tbl_rm)
    story.append(PageBreak())

    # Control results (prioritized)
    story.append(Paragraph('Control Results (Prioritized)', styles['Heading2']))
    controls = list(res.get('control_results', []))
    priority = {'High': 0, 'Medium': 1, 'Low': 2}
    controls.sort(key=lambda c: (priority.get(c.get('risk_tier','Low'), 3), c.get('score', 0.0)))
    head = ['Control','Title','Score','Risk','Evidence Items']
    rows = [head]
    for c in controls[:100]:
        rows.append([c.get('control_id'), (c.get('title') or '')[:80], f"{c.get('score',0):.2f}", c.get('risk_tier'), c.get('supporting_count',0)])
    table = Table(rows, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0), colors.HexColor('#1f2a3a')),
        ('TEXTCOLOR',(0,0),(-1,0), colors.whitesmoke),
        ('GRID',(0,0),(-1,-1),0.3, colors.grey),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [colors.whitesmoke, colors.lightgrey]),
    ]))
    story.append(table)
    # Optional AI Insights section
    if ai_insights:
        story.append(Spacer(1, 10))
        story.append(Paragraph('AI Insights', styles['Heading2']))
        for ln in (ai_insights or [])[:10]:
            story.append(Paragraph(f'- {ln}', styles['Normal']))
    story.append(PageBreak())

    # Recommendations
    story.append(Paragraph('Recommendations', styles['Heading2']))
    high = [c for c in controls if c.get('risk_tier') == 'High'][:10]
    if not high:
        story.append(Paragraph('No high-risk gaps identified in this run. Review medium-risk items for incremental improvement.', styles['Normal']))
    else:
        for c in high:
            rec = f"{c.get('control_id')} - {(c.get('title') or '')[:120]}: Enhance evidence coverage, formalize procedures, and add records."
            story.append(Paragraph(rec, styles['Normal']))
            story.append(Spacer(1,6))

    doc.build(story)
    buf.seek(0)
    return buf.getvalue()


@router.post('/report/titanai', summary='Generate Pro PDF (TitanAI-style) from cached assessment')
async def titanai_report(
    payload: Dict[str, Any] = Body(...),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID')
) -> StreamingResponse:
    aid = str(payload.get('assessment_id') or '')
    if not aid:
        raise HTTPException(status_code=400, detail='assessment_id_required')
    t = _tenant_key(tenant_id)
    item = (_ASSESSMENT_CACHE.get(t) or {}).get(aid)
    if not item:
        raise HTTPException(status_code=404, detail='assessment_not_found')
    res = item['result']
    org = payload.get('organization')
    auditor = payload.get('auditor')
    exec_override = payload.get('executive_summary')
    # Optional AI insights list to include as an additional section
    ai_insights = payload.get('ai_insights') if isinstance(payload.get('ai_insights'), list) else None
    pdf_bytes = _titanai_professional_pdf(res, org_name=org, auditor=auditor, executive_override=exec_override, ai_insights=ai_insights)
    try:
        _append_audit(_tenant_key(tenant_id), 'generated_report', {'format': 'pro_pdf'}, assessment_id=str(aid))
    except Exception:
        pass
    return StreamingResponse(io.BytesIO(pdf_bytes), media_type='application/pdf', headers={'Content-Disposition': 'attachment; filename="janusec_pro_report.pdf"'})


@router.post('/report/titanai/advanced', summary='Generate Advanced Pro PDF using TitanAI generator (feature-flagged)')
async def titanai_report_advanced(
    payload: Dict[str, Any] = Body(...)
) -> StreamingResponse:
    """Attempt to use the TitanAI comprehensive report generator when available.

    Requirements:
      - Set env ENABLE_TITANAI_ADVANCED_PRO_REPORT=1
      - Ensure TitanAI code is present under dump/titan-ai/
      - Python deps for TitanAI installed (e.g., sentence-transformers)

    Payload:
      {
        framework: 'ISO27001'|..., organization?: str, assessor?: str,
        documents: [ {filename, text? | content_base64?} ],
        organization_context?: {}
      }
    """
    if os.getenv('ENABLE_TITANAI_ADVANCED_PRO_REPORT','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=501, detail='advanced_pro_report_disabled')
    try:
        from dump.titan_ai.comprehensive_report_generator import ComprehensiveReportGenerator, ReportConfiguration  # type: ignore
    except Exception as e:
        raise HTTPException(status_code=501, detail=f'advanced_generator_unavailable:{e}')

    framework = str(payload.get('framework') or 'ISO27001')
    org = payload.get('organization') or 'Your Organization'
    assessor = payload.get('assessor') or 'JanuSec + TitanAI'
    docs_raw = payload.get('documents') or []
    if not isinstance(docs_raw, list) or not docs_raw:
        raise HTTPException(status_code=400, detail='documents_required')
    # normalize docs
    docs: list[dict[str, Any]] = []
    for d in docs_raw:
        if not isinstance(d, dict):
            continue
        name = str(d.get('filename') or 'document')
        if isinstance(d.get('text'), str):
            docs.append({'filename': name, 'text': d['text']})
        elif isinstance(d.get('content_base64'), str):
            try:
                import base64
                b = base64.b64decode(d['content_base64'])
            except Exception:
                b = b''
            docs.append({'filename': name, 'content': b})
    if not docs:
        raise HTTPException(status_code=400, detail='no_valid_documents')
    org_ctx = payload.get('organization_context') or {}
    try:
        cfg = ReportConfiguration(organization_name=org, framework=framework, assessment_type='Comprehensive', assessor_name=assessor)  # type: ignore
        gen = ComprehensiveReportGenerator()  # type: ignore
        pdf = await gen.generate_comprehensive_report(cfg, docs, org_ctx)  # type: ignore
        return StreamingResponse(io.BytesIO(pdf), media_type='application/pdf', headers={'Content-Disposition': 'attachment; filename="janusec_advanced_pro_report.pdf"'})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'advanced_pdf_error:{e}')


@router.post('/summarize', summary='Summarize text using configured provider (ollama|hf|openai)', tags=['Compliance'], operation_id='compliance_summarize')
async def summarize(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    text = str(payload.get('text') or '')
    if not text.strip():
        raise HTTPException(status_code=400, detail='text_required')
    provider = os.getenv('COMPLIANCE_SUMMARIZER','disabled').lower()
    if provider in {'disabled','', 'none'}:
        return {'provider':'disabled', 'summary': text[:500]}
    if provider == 'ollama':
        host = os.getenv('OLLAMA_HOST','http://localhost:11434').rstrip('/')
        model = os.getenv('OLLAMA_MODEL','llama3')
        prompt = f"Summarize for executive compliance: {text}\nConcise, actionable bullets."
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(f"{host}/api/generate", json={"model": model, "prompt": prompt, "stream": False})
                if r.status_code >= 300:
                    raise HTTPException(status_code=502, detail=f'ollama_http_{r.status_code}')
                data = r.json()
                return {'provider':'ollama', 'summary': data.get('response') or ''}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=502, detail=f'ollama_error:{e}')
    if provider == 'hf':
        # Local Hugging Face pipeline (if available)
        model = os.getenv('COMPLIANCE_HF_MODEL','facebook/bart-large-cnn')
        try:
            from transformers import pipeline  # type: ignore
            summarizer = pipeline('summarization', model=model)
            res = summarizer(text, max_length=180, min_length=40, do_sample=False)
            summary = (res[0]['summary_text'] if res and isinstance(res, list) else '') or ''
        except Exception as e:
            raise HTTPException(status_code=501, detail=f'hf_error:{e}')
        # Optional security classifier for tags (e.g., SEC-BERT/CyBERT)
        labels: list[str] = []
        clf_name = os.getenv('COMPLIANCE_CLASSIFIER_MODEL')
        if clf_name:
            try:
                from transformers import pipeline  # type: ignore
                clf = pipeline('text-classification', model=clf_name, top_k=3)
                cres = clf(text)
                # normalize top labels
                if isinstance(cres, list) and cres:
                    top = cres[0] if isinstance(cres[0], list) else cres
                    labs: list[str] = []
                    for ent in top:  # type: ignore
                        lab = ent.get('label') if isinstance(ent, dict) else None  # type: ignore
                        if lab:
                            labs.append(str(lab))
                    labels = [l for l in labs if l][:5]
            except Exception:
                labels = []
        return {'provider':'hf', 'model': model, 'summary': summary, 'labels': labels}
    if provider == 'openai':
        # Placeholder to avoid network deps in restricted envs
        raise HTTPException(status_code=501, detail='openai_provider_not_configured')
    raise HTTPException(status_code=400, detail='unknown_provider')


# ---------------- Evidence Management ----------------
@router.post('/evidence/upload', summary='Upload evidence and associate to a control')
async def upload_evidence(
    control_id: str = Query(..., description='Control ID like A.9.2 or CC6.6'),
    description: str | None = Query(None),
    retention_days: int | None = Query(None, ge=1, le=3650),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    actor: str | None = Header(None, alias='X-Actor'),
    file: UploadFile = File(...),
    request: Request = None,
) -> dict[str, Any]:
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    tid = _tenant_key(tenant_id)
    now = time.time()
    # Save file
    base_dir = os.getenv('COMPLIANCE_EVIDENCE_DIR', 'artifacts/compliance/evidence')
    safe_cid = ''.join(ch for ch in control_id if ch.isalnum() or ch in '._-')
    target_dir = os.path.join(base_dir, tid, safe_cid)
    _mk_dirs(target_dir)
    content = await file.read()
    fname = file.filename or 'evidence.bin'
    stamp = int(now)
    path = os.path.join(target_dir, f"{stamp}_{fname}")
    with open(path, 'wb') as f:
        f.write(content)
    sha = hashlib.sha256(content).hexdigest()
    rec = {
        'id': str(uuid.uuid4()),
        'tenant_id': tid,
        'control_id': control_id,
        'filename': fname,
        'file_path': path,
        'size': len(content),
        'evidence_hash': sha,
        'uploaded_at': now,
        'uploaded_by': actor,
        'retention_until': (now + (retention_days or 0) * 86400) if retention_days else None,
        'description': description,
    }
    idx_path = os.getenv('COMPLIANCE_EVIDENCE_INDEX', 'artifacts/compliance/evidence.idx.jsonl')
    _mk_dirs(os.path.dirname(idx_path))
    try:
        with open(idx_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass
    _append_audit(tid, 'uploaded_evidence', {'control_id': control_id, 'filename': fname, 'hash': sha}, actor=actor)
    return {'ok': True, 'evidence': rec}


@router.get('/evidence/list', summary='List evidence records (optionally by control)', operation_id='compliance_list_evidence')
async def list_evidence(
    control_id: str | None = Query(None),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> dict[str, Any]:
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    tid = _tenant_key(tenant_id)
    idx_path = os.getenv('COMPLIANCE_EVIDENCE_INDEX', 'artifacts/compliance/evidence.idx.jsonl')
    items: list[dict[str, Any]] = []
    try:
        with open(idx_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if not isinstance(obj, dict):
                        continue
                    if obj.get('tenant_id') != tid:
                        continue
                    if control_id and str(obj.get('control_id')) != str(control_id):
                        continue
                    items.append(obj)
                except Exception:
                    continue
    except FileNotFoundError:
        items = []
    return {'tenant_id': tid, 'count': len(items), 'items': items}


@router.get('/audit/trail', summary='Fetch audit trail records (optionally by assessment)')
async def audit_trail(
    assessment_id: str | None = Query(None),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> dict[str, Any]:
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    tid = _tenant_key(tenant_id)
    p = _audit_log_path()
    out: list[dict[str, Any]] = []
    try:
        with open(p, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if not isinstance(obj, dict):
                        continue
                    if obj.get('tenant_id') != tid:
                        continue
                    if assessment_id and str(obj.get('assessment_id')) != str(assessment_id):
                        continue
                    out.append(obj)
                except Exception:
                    continue
    except FileNotFoundError:
        out = []
    return {'tenant_id': tid, 'count': len(out), 'items': out}


@router.post('/test/{control_id}', summary='Run automated control test')
async def run_control_test(
    control_id: str,
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> dict[str, Any]:
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    tid = _tenant_key(tenant_id)
    try:
        from src.modules.compliance.control_tests import ControlTestRunner  # type: ignore
    except Exception:
        from modules.compliance.control_tests import ControlTestRunner  # type: ignore
    runner = ControlTestRunner()
    result = await runner.run_test(control_id, tid)
    try:
        _append_audit(tid, 'control_test', {'control_id': control_id, 'status': result.get('status')})
    except Exception:
        pass
    return result


# ---------------- Remediation Tracker ----------------
def _rem_path() -> str:
    p = os.getenv('COMPLIANCE_REMEDIATIONS_PATH', 'artifacts/compliance/remediations.json')
    _mk_dirs(os.path.dirname(p))
    return p


def _load_rems() -> dict[str, list[dict[str, Any]]]:
    p = _rem_path()
    try:
        with open(p, 'r', encoding='utf-8') as f:
            obj = json.load(f)
            if isinstance(obj, dict):
                return obj
    except Exception:
        pass
    return {}


def _save_rems(data: dict[str, list[dict[str, Any]]]) -> None:
    p = _rem_path()
    try:
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(data, f)
    except Exception:
        pass


@router.post('/remediation/create', summary='Create remediation plan for a control')
async def remediation_create(payload: Dict[str, Any] = Body(...), tenant_id: str | None = Header(None, alias='X-Tenant-ID'), request: Request = None) -> dict[str, Any]:
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    tid = _tenant_key(tenant_id)
    control_id = str(payload.get('control_id') or '').strip()
    if not control_id:
        raise HTTPException(status_code=400, detail='control_id_required')
    item = {
        'id': str(uuid.uuid4()),
        'tenant_id': tid,
        'created_at': time.time(),
        'assessment_id': payload.get('assessment_id'),
        'control_id': control_id,
        'gap_description': payload.get('gap_description'),
        'remediation_plan': payload.get('remediation_plan'),
        'assigned_to': payload.get('assigned_to'),
        'due_date': payload.get('due_date'),
        'status': 'open',
        'jira_ticket': payload.get('jira_ticket'),
        'retest_date': None,
        'retest_result': None,
    }
    db = _load_rems()
    db.setdefault(tid, []).append(item)
    _save_rems(db)
    _append_audit(tid, 'remediation_created', {'control_id': control_id, 'id': item['id']})
    return {'ok': True, 'remediation': item}


@router.patch('/remediation/{rem_id}/status', summary='Update remediation status')
async def remediation_status(rem_id: str, payload: Dict[str, Any] = Body(...), tenant_id: str | None = Header(None, alias='X-Tenant-ID'), request: Request = None) -> dict[str, Any]:
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    tid = _tenant_key(tenant_id)
    db = _load_rems()
    items = db.get(tid, [])
    for it in items:
        if it.get('id') == rem_id:
            if 'status' in payload:
                it['status'] = payload['status']
            for k in ('jira_ticket','assigned_to','due_date','retest_date','retest_result'):
                if k in payload:
                    it[k] = payload[k]
            _save_rems(db)
            _append_audit(tid, 'remediation_updated', {'id': rem_id, 'status': it.get('status')})
            return {'ok': True, 'remediation': it}
    raise HTTPException(status_code=404, detail='remediation_not_found')


@router.get('/remediation/list', summary='List remediations')
async def remediation_list(status: str | None = Query(None), tenant_id: str | None = Header(None, alias='X-Tenant-ID'), request: Request = None) -> dict[str, Any]:
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    tid = _tenant_key(tenant_id)
    db = _load_rems()
    items = db.get(tid, [])
    if status:
        items = [i for i in items if i.get('status') == status]
    return {'tenant_id': tid, 'count': len(items), 'items': items}


@router.get('/graphml')
async def compliance_graphml(
    assessment_id: str,
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
):
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
    except Exception:
        pass
    t = _tenant_key(tenant_id)
    item = (_ASSESSMENT_CACHE.get(t) or {}).get(assessment_id)
    if not item:
        raise HTTPException(status_code=404, detail='assessment_not_found')
    g = item.get('graph')
    if not g:
        raise HTTPException(status_code=404, detail='graph_not_found')
    ml = g.to_graphml()
    return PlainTextResponse(ml, media_type='application/xml')


@router.get('/job/{job_id}')
async def job_status(job_id: str) -> dict[str, Any]:
    j = _CMP_JOBS.get(job_id)
    if not j:
        raise HTTPException(status_code=404, detail='job_not_found')
    return {'job_id': job_id, 'status': j.get('status'), 'assessment_id': j.get('assessment_id'), 'error': j.get('error')}


@router.post('/job/{job_id}/result')
async def job_result(job_id: str, request: Request) -> dict[str, Any]:
    j = _CMP_JOBS.get(job_id)
    if not j:
        raise HTTPException(status_code=404, detail='job_not_found')
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    res = body.get('result')
    if not isinstance(res, dict):
        raise HTTPException(status_code=400, detail='result_required')
    aid = res.get('assessment_id') or _gen_assessment_id()
    t = _tenant_key(j.get('tenant_id'))
    # External results are assumed to be already summarized; store as-is
    _ASSESSMENT_CACHE.setdefault(t, {})[str(aid)] = {'result': res, 'graph': None}
    j['status'] = 'completed'
    j['assessment_id'] = aid
    return {'accepted': True, 'assessment_id': aid}


# ---------------- Cloud/K8s Posture Ingestion ----------------
class PostureIngest(BaseModel):  # type: ignore[misc]
    findings: list[dict]
    tenant_id: str | None = None


@router.post('/posture', summary='Ingest cloud/K8s posture scan findings (CSPM-lite)')
async def ingest_posture(payload: PostureIngest, api_key: str | None = Header(None, alias='x-api-key'), request: Request = None) -> dict[str, Any]:
    """Accept a generic posture payload and persist a minimal slice for reporting.

    Expected finding fields (best-effort): { id, type, resource, severity }
    Recognized types map to factors: cloud:public_bucket, cloud:sg_open_0_0_0_0,
    iam:overpriv_wildcard, iam:key_no_mfa, k8s:anonymous_access, k8s:privileged_pod
    """
    try:
        import os, json, time
        tenant_id = resolve_tenant_id(request, payload.tenant_id)
        path = os.getenv('POSTURE_LOG_PATH', 'artifacts/compliance/posture.jsonl')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        now = time.time()
        count = 0
        lag_sum = 0.0
        lag_count = 0
        with open(path, 'a', encoding='utf-8') as f:
            for finding in (payload.findings or []):
                src_ts = finding.get('source_ts')
                rec = {
                    'ts': now,
                    'source_ts': src_ts,
                    'tenant_id': tenant_id,
                    'id': finding.get('id'),
                    'type': finding.get('type'),
                    'resource': finding.get('resource'),
                    'severity': finding.get('severity'),
                }
                f.write(json.dumps(rec) + "\n")
                count += 1
                try:
                    if src_ts is not None:
                        lag = now - float(src_ts)
                        if lag >= 0:
                            lag_sum += lag
                            lag_count += 1
                except Exception:
                    pass
        factor_map = {
            'cloud:sg_open_0_0_0_0': 0,
            'cloud:public_bucket': 0,
            'iam:overpriv_wildcard': 0,
            'iam:key_no_mfa': 0,
            'k8s:anonymous_access': 0,
            'k8s:privileged_pod': 0,
        }
        for finding in (payload.findings or []):
            t = str(finding.get('type') or '').lower()
            for k in list(factor_map.keys()):
                if k in t:
                    factor_map[k] += 1
        # Emit Prometheus metrics (best-effort)
        try:
            tlabel = _tenant_key(tenant_id)
            _posture_ingest_total.labels(tenant=tlabel).inc(count)
            if lag_count > 0:
                _posture_ingest_lag.labels(tenant=tlabel).set(lag_sum / float(lag_count))
        except Exception:
            pass
        return {'status': 'ok', 'ingested': count, 'factors': factor_map, 'tenant_id': tenant_id}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f'bad_posture_payload: {exc}')


@router.get('/posture', summary='Summarize cloud/K8s posture by tenant and severity')
async def summarize_posture(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    limit: int = Query(100000, ge=1, le=2_000_000),
    request: Request = None,
) -> dict[str, Any]:
    """Aggregate posture findings from the JSONL log with optional tenant filter.

    Returns a structure with totals, by_type counts, per-severity counts, and a simple
    risk score heuristic (critical=3, high=2, medium=1, low=0.5) to power a dashboard card.
    """
    import os
    from src.common.jsonl_cache import get_jsonl  # type: ignore
    path = os.getenv('POSTURE_LOG_PATH', 'artifacts/compliance/posture.jsonl')
    tenant_id = resolve_tenant_id(request, tenant_id)
    out: dict[str, Any] = {
        'total': 0,
        'by_type': {},
        'severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'tenants': {},
        'risk_score': 0.0,
        'tenant_id': tenant_id,
        'framework_completeness': {},
    }
    sev_weight = {'critical': 3.0, 'high': 2.0, 'medium': 1.0, 'low': 0.5}
    if not path or not os.path.exists(path):
        return out
    total_weight = 0.0
    seen = 0
    ttl = float(os.getenv('JSONL_CACHE_TTL','30') or 30)
    # Soft time budget (ms). If exceeded during summarization, return partial aggregation.
    try:
        budget_ms = float(os.getenv('POSTURE_SUMMARY_MS','100') or 100)
    except Exception:
        budget_ms = 100.0
    start_t = time.time()
    rows = get_jsonl(path, ttl)
    for j in rows:
        if seen >= limit:
            break
        # Respect time budget
        if ((time.time() - start_t) * 1000.0) > budget_ms:
            break
        seen += 1
        tnt = j.get('tenant_id')
        if tenant_id and tnt not in {tenant_id}:
            continue
        out['total'] += 1
        t = str(j.get('type') or '')
        sev = str(j.get('severity') or '').lower()
        out['by_type'][t] = out['by_type'].get(t, 0) + 1
        if sev in out['severity']:
            out['severity'][sev] += 1
            total_weight += sev_weight.get(sev, 0.0)
        # per-tenant fan-out (for multi-tenant overviews)
        key = tnt or 'default'
        ent = out['tenants'].setdefault(key, {'total': 0, 'severity': {'critical':0,'high':0,'medium':0,'low':0}})
        ent['total'] += 1
        if sev in ent['severity']:
            ent['severity'][sev] += 1
    out['risk_score'] = round(total_weight, 2)
    # Framework completeness (simple counts vs reference sets)
    reference_frameworks = {
        'ISO27001': ['A.12.4.1','A.12.6.2','A.8.7'],
        'PCI': ['10.2','10.3','11.5'],
        'SOC2': ['CC6.6','CC7.2','CC8.1'],
    }
    # For demo purposes, we map posture finding 'type' substrings to control IDs heuristically
    observed_controls = set()
    for t, count in out['by_type'].items():
        low_t = t.lower()
        if 'bucket' in low_t:
            observed_controls.add('A.12.4.1')
        if 'sg_open' in low_t:
            observed_controls.add('10.2')
        if 'privileged_pod' in low_t:
            observed_controls.add('CC7.2')
    completeness = {}
    for fw, controls in reference_frameworks.items():
        matched = len([c for c in controls if c in observed_controls])
        completeness[fw] = {
            'observed': matched,
            'total': len(controls),
            'percent': round((matched/len(controls))*100,1) if controls else 0.0
        }
    out['framework_completeness'] = completeness
    return out


# --------- CSPM Enhancements: history/top/remediation ---------
@router.get('/posture/history', summary='Time-bucketed posture findings history')
async def posture_history(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    since: float | None = Query(None, description='Epoch seconds cutoff; default last 7 days'),
    bucket: str = Query('1d', pattern='^(1d|1h)$'),
    limit: int = Query(500000, ge=1, le=5_000_000),
    request: Request = None,
) -> dict[str, Any]:
    import os, time
    from src.common.jsonl_cache import get_jsonl  # type: ignore
    path = os.getenv('POSTURE_LOG_PATH', 'artifacts/compliance/posture.jsonl')
    tenant_id = resolve_tenant_id(request, tenant_id)
    if not os.path.exists(path):
        return {'series': [], 'bucket': bucket, 'tenant_id': tenant_id}
    rows = get_jsonl(path, float(os.getenv('JSONL_CACHE_TTL','30') or 30))
    now = time.time()
    if since is None:
        since = now - (7*24*3600)
    size = 3600 if bucket == '1h' else 86400
    def _bucket_key(ts: float) -> int:
        return int((int(ts)//size)*size)
    buckets: dict[int, dict[str, int]] = {}
    seen = 0
    for j in rows:
        if seen >= limit:
            break
        try:
            ts = float(j.get('ts') or 0.0)
        except Exception:
            continue
        if ts < float(since):
            continue
        if tenant_id and (j.get('tenant_id') not in {tenant_id}):
            continue
        b = _bucket_key(ts)
        sev = str(j.get('severity') or '').lower()
        ent = buckets.setdefault(b, {'critical':0, 'high':0, 'medium':0, 'low':0})
        if sev in ent:
            ent[sev] += 1
        seen += 1
    series = [ {'ts': k, **v} for k, v in sorted(buckets.items(), key=lambda kv: kv[0]) ]
    return {'series': series, 'bucket': bucket, 'tenant_id': tenant_id, 'since': since}


@router.get('/posture/top', summary='Top misconfigurations by type or service')
async def posture_top(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    group_by: str = Query('type', pattern='^(type|service)$'),
    limit: int = Query(10, ge=1, le=100),
    scan_limit: int = Query(200000, ge=100, le=2_000_000),
    request: Request = None,
) -> dict[str, Any]:
    import os
    from src.common.jsonl_cache import get_jsonl  # type: ignore
    path = os.getenv('POSTURE_LOG_PATH', 'artifacts/compliance/posture.jsonl')
    tenant_id = resolve_tenant_id(request, tenant_id)
    if not os.path.exists(path):
        return {'group_by': group_by, 'items': []}
    rows = get_jsonl(path, float(os.getenv('JSONL_CACHE_TTL','30') or 30))
    counts: dict[str, int] = {}
    seen = 0
    for j in rows:
        if seen >= scan_limit:
            break
        if tenant_id and j.get('tenant_id') not in {tenant_id}:
            continue
        key = ''
        if group_by == 'type':
            key = str(j.get('type') or '')
        else:
            # Try to infer service from type like 'cloud:sg_open_0_0_0_0' -> 'sg'
            t = str(j.get('type') or '')
            key = t.split(':',1)[-1].split('_',1)[0] if ':' in t else (j.get('service') or '')
            key = str(key)
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
        seen += 1
    items = sorted([{'key': k, 'count': v} for k, v in counts.items()], key=lambda x: -x['count'])[:limit]
    return {'group_by': group_by, 'items': items, 'tenant_id': tenant_id}


@router.get('/posture/remediation', summary='Remediation guidance for known misconfigurations')
async def posture_remediation(t: str = Query(..., alias='type')) -> dict[str, Any]:
    guides = {
        'cloud:public_bucket': [
            'Enable S3 Block Public Access (account and bucket)',
            'Remove public ACLs and bucket policies',
            'Use VPC endpoints or PrivateLink for access'
        ],
        'cloud:s3_no_encryption': [
            'Enable default SSE (SSE-S3 or SSE-KMS) on bucket',
            'Audit lifecycle rules to ensure encrypted objects only'
        ],
        'cloud:s3_no_versioning': [
            'Enable bucket versioning to support rollback and object recovery'
        ],
        'cloud:sg_open_0_0_0_0': [
            'Restrict 0.0.0.0/0 rules; allow only necessary CIDR ranges',
            'Prefer security groups referencing other groups instead of IPs'
        ],
        'iam:overpriv_wildcard': [
            'Replace Action:* with least-privilege actions',
            'Scope resources to specific ARNs where possible'
        ],
    }
    return {'type': t, 'steps': guides.get(t, ['No remediation guidance available'])}


# --------- Assets API (lightweight index) ---------
class Asset(BaseModel):  # type: ignore[misc]
    id: str
    type: str | None = None
    service: str | None = None
    cloud: str | None = None
    account: str | None = None
    region: str | None = None
    tenant_id: str | None = None
    tags: dict[str, Any] | None = None


@router.post('/assets/sync', summary='Sync assets into a lightweight index')
async def assets_sync(payload: dict = Body(...), request: Request = None) -> dict[str, Any]:
    import os, json
    tenant_id = resolve_tenant_id(request, payload.get('tenant_id') if isinstance(payload, dict) else None)
    items = payload.get('assets') or []
    if not isinstance(items, list):
        raise HTTPException(status_code=400, detail='assets_list_required')
    path = os.getenv('ASSETS_INDEX_PATH', 'artifacts/compliance/assets.idx.json')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        existing = {}
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                existing = json.load(f)
    except Exception:
        existing = {}
    updated = 0
    for raw in items:
        try:
            if tenant_id and isinstance(raw, dict):
                raw_tenant = raw.get('tenant_id')
                if raw_tenant and raw_tenant != tenant_id:
                    raise HTTPException(status_code=403, detail='tenant_mismatch')
                if not raw_tenant:
                    raw['tenant_id'] = tenant_id
            a = Asset(**raw)
            existing[a.id] = a.model_dump()
            updated += 1
        except Exception:
            continue
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(existing, f)
    return {'synced': updated, 'total_indexed': len(existing)}


@router.get('/assets', summary='List assets with filters')
async def assets_list(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    type: str | None = Query(None),
    service: str | None = Query(None),
    cloud: str | None = Query(None),
    region: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=1000000),
    request: Request = None,
) -> dict[str, Any]:
    import os, json
    tenant_id = resolve_tenant_id(request, tenant_id)
    path = os.getenv('ASSETS_INDEX_PATH', 'artifacts/compliance/assets.idx.json')
    if not os.path.exists(path):
        return {'items': [], 'total': 0}
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    items = list(data.values())
    def _ok(a: dict) -> bool:
        if tenant_id and a.get('tenant_id') not in {tenant_id}: return False
        if type and str(a.get('type') or '') != type: return False
        if service and str(a.get('service') or '') != service: return False
        if cloud and str(a.get('cloud') or '') != cloud: return False
        if region and str(a.get('region') or '') != region: return False
        return True
    flt = [a for a in items if _ok(a)]
    total = len(flt)
    page = flt[offset:offset+limit]
    return {'items': page, 'total': total, 'limit': limit, 'offset': offset}


# --------- Cloud Telemetry & S3 Audit to posture ---------
@router.post('/cloud/events', summary='Ingest generic cloud audit events (JSONL append)')
async def cloud_events_ingest(payload: dict = Body(...), request: Request = None) -> dict[str, Any]:
    import os, json, time
    events = payload.get('events') or []
    tenant_id = resolve_tenant_id(request, payload.get('tenant_id') if isinstance(payload, dict) else None)
    path = os.getenv('CLOUD_EVENTS_LOG', 'artifacts/cloud/events.jsonl')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    written = 0
    with open(path, 'a', encoding='utf-8') as f:
        for e in events:
            try:
                rec = {'ts': time.time(), **(e if isinstance(e, dict) else {})}
                if tenant_id:
                    ev_tenant = rec.get('tenant_id')
                    if ev_tenant and ev_tenant != tenant_id:
                        raise HTTPException(status_code=403, detail='tenant_mismatch')
                    rec['tenant_id'] = tenant_id
                f.write(json.dumps(rec) + '\n')
                written += 1
            except Exception:
                pass
    return {'ingested': written}


@router.post('/cloud/s3/audit', summary='Ingest S3 bucket audit and derive posture findings')
async def s3_audit(payload: dict = Body(...), request: Request = None) -> dict[str, Any]:
    import os, json, time
    buckets = payload.get('buckets') or []
    tenant_id = resolve_tenant_id(request, payload.get('tenant_id') if isinstance(payload, dict) else None)
    if not isinstance(buckets, list):
        raise HTTPException(status_code=400, detail='buckets_list_required')
    path = os.getenv('POSTURE_LOG_PATH', 'artifacts/compliance/posture.jsonl')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    written = 0
    with open(path, 'a', encoding='utf-8') as f:
        for b in buckets:
            try:
                name = str(b.get('name') or '')
                public = bool(b.get('public') or False)
                enc = bool(b.get('encryption') or False)
                ver = bool(b.get('versioning') or False)
                common = {'ts': time.time(), 'tenant_id': tenant_id, 'resource': name, 'service': 's3', 'severity': 'medium'}
                if public:
                    f.write(json.dumps({**common, 'type': 'cloud:public_bucket', 'severity': 'high'})+'\n'); written += 1
                if not enc:
                    f.write(json.dumps({**common, 'type': 'cloud:s3_no_encryption', 'severity': 'medium'})+'\n'); written += 1
                if not ver:
                    f.write(json.dumps({**common, 'type': 'cloud:s3_no_versioning', 'severity': 'low'})+'\n'); written += 1
            except Exception:
                pass
    return {'findings_added': written}


# --------- IAM Risk ingest and summary ---------
@router.post('/iam/audit', summary='Ingest IAM audit entries (users/keys/policies)')
async def iam_audit(payload: dict = Body(...), request: Request = None) -> dict[str, Any]:
    """Accepts a generic IAM audit payload and appends to JSONL for later risk summarization.

    Expected entries example:
      { users:[{name,mfa_enabled,last_active}], keys:[{id,user,last_used_days,mfa_enabled}],
        policies:[{name,wildcard,attached_to}], tenant_id }
    """
    import os, json, time
    path = os.getenv('IAM_AUDIT_LOG', 'artifacts/compliance/iam.jsonl')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    now = time.time()
    tenant_id = resolve_tenant_id(request, payload.get('tenant_id') if isinstance(payload, dict) else None)
    rec = {'ts': now, **payload, 'tenant_id': tenant_id}
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(rec) + '\n')
    # Prometheus: increment at ingest to avoid inflation from repeated reads
    try:
        t = _tenant_key(tenant_id)
        for e in (payload.get('events') or []):
            ch = str(e.get('change') or '')
            cidr = str(e.get('cidr') or '')
            if ch:
                _sg_drift_events.labels(tenant=t, change=ch).inc()
            if cidr in {'0.0.0.0/0', '::/0'}:
                _sg_open_world.labels(tenant=t).inc()
    except Exception:
        pass
    return {'ingested': True}


@router.get('/iam/risks', summary='Summarize IAM risks (keys without MFA, wildcard policies, unused keys)')
async def iam_risks(tenant_id: str | None = Header(None, alias='X-Tenant-ID'), request: Request = None) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(request, tenant_id)
    import os
    from src.common.jsonl_cache import get_jsonl  # type: ignore
    path = os.getenv('IAM_AUDIT_LOG', 'artifacts/compliance/iam.jsonl')
    out: dict[str, Any] = {
        'tenant_id': tenant_id,
        'keys_without_mfa': 0,
        'unused_keys': 0,
        'wildcard_policies': 0,
        'admin_no_mfa': 0,
        'users_total': 0,
        'keys_total': 0,
        'policies_total': 0,
        'top_findings': [],
        # Enriched example lists for UX: small samples to avoid payload bloat
        'violating_keys_no_mfa': [],
        'violating_unused_keys': [],
        'violating_admin_no_mfa': [],
        'violating_wildcard_policies': [],
    }
    if not os.path.exists(path):
        return out
    rows = get_jsonl(path, float(os.getenv('JSONL_CACHE_TTL','30') or 30))
    # Use most recent record per tenant if multiple
    latest = None
    for j in rows[::-1]:
        if tenant_id and j.get('tenant_id') not in {tenant_id}:
            continue
        latest = j
        break
    if not latest:
        return out
    users = latest.get('users') or []
    keys = latest.get('keys') or []
    policies = latest.get('policies') or []
    out['users_total'] = len(users)
    out['keys_total'] = len(keys)
    out['policies_total'] = len(policies)
    # Collect example violators (cap at 20 to keep responses small)
    v_keys_no_mfa: list[dict[str, Any]] = []
    v_unused: list[dict[str, Any]] = []
    for k in keys:
        if not bool(k.get('mfa_enabled')):
            out['keys_without_mfa'] += 1
            if len(v_keys_no_mfa) < 20:
                v_keys_no_mfa.append({'id': k.get('id'), 'user': k.get('user')})
        try:
            if int(k.get('last_used_days') or 0) > 90:
                out['unused_keys'] += 1
                if len(v_unused) < 20:
                    v_unused.append({'id': k.get('id'), 'user': k.get('user'), 'last_used_days': k.get('last_used_days')})
        except Exception:
            pass
    v_policies: list[dict[str, Any]] = []
    for p in policies:
        if bool(p.get('wildcard')):
            out['wildcard_policies'] += 1
            if len(v_policies) < 20:
                v_policies.append({'name': p.get('name'), 'attached_to': p.get('attached_to')})
    v_admins: list[dict[str, Any]] = []
    for u in users:
        if (u.get('is_admin') or False) and not bool(u.get('mfa_enabled')):
            out['admin_no_mfa'] += 1
            if len(v_admins) < 20:
                v_admins.append({'name': u.get('name') or u.get('user')})
    # Assemble top findings list
    tf = []
    if out['admin_no_mfa']:
        tf.append({'type': 'iam:admin_no_mfa', 'count': out['admin_no_mfa']})
    if out['keys_without_mfa']:
        tf.append({'type': 'iam:keys_no_mfa', 'count': out['keys_without_mfa']})
    if out['unused_keys']:
        tf.append({'type': 'iam:unused_keys_>90d', 'count': out['unused_keys']})
    if out['wildcard_policies']:
        tf.append({'type': 'iam:wildcard_policies', 'count': out['wildcard_policies']})
    out['top_findings'] = sorted(tf, key=lambda x: -x['count'])
    out['violating_keys_no_mfa'] = v_keys_no_mfa
    out['violating_unused_keys'] = v_unused
    out['violating_admin_no_mfa'] = v_admins
    out['violating_wildcard_policies'] = v_policies

    # Update Prometheus gauges (best-effort; no-op if client missing)
    t = _tenant_key(tenant_id)
    try:
        _iam_keys_no_mfa.labels(tenant=t).set(float(out['keys_without_mfa']))
        _iam_unused_keys.labels(tenant=t).set(float(out['unused_keys']))
        _iam_wildcard_policies.labels(tenant=t).set(float(out['wildcard_policies']))
        _iam_admin_no_mfa.labels(tenant=t).set(float(out['admin_no_mfa']))
    except Exception:
        pass
    return out


# --------- Security Group drift ingest and summary ---------
@router.post('/net/sg/audit', summary='Ingest Security Group rule changes/drift')
async def sg_audit(payload: dict = Body(...), request: Request = None) -> dict[str, Any]:
    """Accepts SG drift events of the shape:
      { tenant_id, events:[{sg_id, change:'added'|'removed', cidr, port, proto, reason}] }
    """
    import os, json, time
    path = os.getenv('SG_DRIFT_LOG', 'artifacts/compliance/sg_drift.jsonl')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    now = time.time()
    tenant_id = resolve_tenant_id(request, payload.get('tenant_id') if isinstance(payload, dict) else None)
    rec = {'ts': now, **payload, 'tenant_id': tenant_id}
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(rec) + '\n')
    return {'ingested': True}


@router.get('/net/sg/drift', summary='Summarize Security Group drift events since cutoff')
async def sg_drift(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    since: float | None = Query(None),
    limit: int = Query(200000, ge=1, le=2_000_000),
    request: Request = None,
) -> dict[str, Any]:
    import os, time
    from src.common.jsonl_cache import get_jsonl  # type: ignore
    path = os.getenv('SG_DRIFT_LOG', 'artifacts/compliance/sg_drift.jsonl')
    tenant_id = resolve_tenant_id(request, tenant_id)
    out = {'tenant_id': tenant_id, 'events': 0, 'open_to_world': 0, 'by_sg': {}}
    if not os.path.exists(path):
        return out
    rows = get_jsonl(path, float(os.getenv('JSONL_CACHE_TTL','30') or 30))
    if since is None:
        since = time.time() - (7*24*3600)
    seen = 0
    for j in rows:
        if seen >= limit: break
        if tenant_id and j.get('tenant_id') not in {tenant_id}: continue
        ts = float(j.get('ts') or 0.0)
        if ts < float(since): continue
        for e in (j.get('events') or []):
            seen += 1
            sgid = str(e.get('sg_id') or 'unknown')
            ent = out['by_sg'].setdefault(sgid, {'added':0,'removed':0,'open_to_world':0})
            ch = str(e.get('change') or '')
            if ch in ent: ent[ch] += 1
            cidr = str(e.get('cidr') or '')
            if cidr == '0.0.0.0/0' or cidr == '::/0':
                ent['open_to_world'] += 1
                out['open_to_world'] += 1
            # Prometheus counters moved to ingest; optionally allow summary-based counting via env
            try:
                import os as _os
                if (_os.getenv('SG_METRICS_COUNT_AT','ingest') or 'ingest').lower() == 'summary':
                    t = _tenant_key(tenant_id)
                    if ch:
                        _sg_drift_events.labels(tenant=t, change=ch).inc()
                    if cidr in {'0.0.0.0/0', '::/0'}:
                        _sg_open_world.labels(tenant=t).inc()
            except Exception:
                pass
            out['events'] += 1
    # normalize for transport
    out['by_sg'] = [{'sg_id': k, **v} for k, v in out['by_sg'].items()]
    return out


# --------- Cloud crossmap to pipeline + explainability (static hints) ---------
@router.get('/cloud/crossmap', summary='Cross-map cloud posture/findings to pipeline/graph/metrics and explainability frameworks')
async def cloud_crossmap() -> dict[str, Any]:
    # Static, opinionated hints for demo/reference usage
    mappings: dict[str, dict[str, Any]] = {
        'cloud:public_bucket': {
            'pipeline_stages': ['ingest', 'normalize', 'enrich', 'correlate', 'risk', 'actions'],
            'graph': ['asset:s3_bucket', 'edge:exposure', 'risk:exfiltration'],
            'analytics': ['ewma', 'tfidf'],
            'explainability': {
                'cvss': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
                'kev': True,
                'mitre_stride': ['information_disclosure', 'exfiltration'],
                'pasta': ['TA-5', 'TA-6'],
                'dread': {'damage': 7, 'repro': 9, 'exploit': 8, 'affected': 8, 'discover': 6},
                'sbom': [],
            },
        },
        'cloud:sg_open_0_0_0_0': {
            'pipeline_stages': ['ingest', 'normalize', 'enrich', 'correlate', 'risk', 'actions'],
            'graph': ['asset:security_group', 'edge:ingress_open_world'],
            'analytics': ['ewma'],
            'explainability': {
                'cvss': 'AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:M/A:M',
                'kev': False,
                'mitre_stride': ['lateral_movement', 'exfiltration'],
                'pasta': ['TA-4'],
                'dread': {'damage': 6, 'repro': 10, 'exploit': 9, 'affected': 7, 'discover': 10},
            },
        },
        'iam:overpriv_wildcard': {
            'pipeline_stages': ['ingest', 'normalize', 'enrich', 'correlate', 'risk', 'actions'],
            'graph': ['principal', 'policy:*'],
            'analytics': ['tfidf'],
            'explainability': {
                'mitre_stride': ['elevation', 'execution'],
                'dread': {'damage': 6, 'repro': 8, 'exploit': 7, 'affected': 6, 'discover': 7},
            },
        },
        'iam:key_no_mfa': {
            'pipeline_stages': ['ingest', 'normalize', 'enrich', 'correlate', 'risk', 'actions'],
            'graph': ['principal', 'credential:access_key'],
            'analytics': ['ewma'],
            'explainability': {
                'mitre_stride': ['spoofing'],
                'dread': {'damage': 5, 'repro': 8, 'exploit': 8, 'affected': 6, 'discover': 8},
            },
        },
    }
    return {'mappings': mappings, 'notes': 'Crossmap is heuristic and for demo reference'}
