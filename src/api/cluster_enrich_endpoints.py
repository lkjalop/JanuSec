"""On-demand cluster enrichment with LLM + Corrective RAG (CRAG) grading.

Routes (all under /api/v1/assessments/{assessment_id}/clusters/{cluster_id}):
  POST  …/enrich          — trigger on-demand LLM enrichment + CRAG grading
  GET   …/enrich          — return cached enrichment result (or 404 if not run yet)
  POST  …/enrich/feedback — accept analyst feedback on the enrichment (accept/reject/refine)
  GET   …/enrich/routing  — preview which LLM tier/model would be selected (no LLM call)

Enrichment flow:
  1. Load the cluster from the in-flight assessment cache (or a persisted file).
  2. Run cluster_grader.grade_cluster() → rule-based CRAG verdict.
  3. REJECT  → return immediately, no LLM tokens consumed.
  4. ACCEPT/REFINE → call llm_router.route() to select tier + model based on:
       - CRAG composite score
       - Cluster severity
       - Per-tenant LLM config (BYOK keys / cloud-native endpoints)
       Tier matrix:
         composite < 0.72 or sev low/med  → small   (local fast model)
         composite ≥ 0.72 or sev high     → large   (larger local or cheap API)
         composite ≥ 0.85 or sev critical → critical (frontier API / Bedrock / Azure)
  5. Warm up Ollama if the selected provider is local.
  6. Build adversarial chain-of-thought prompt.
  7. Call DEFAULT_CLIENT.generate() with router-supplied overrides + thinking budget.
  8. Parse structured sections; persist + return result.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.analysis.cluster_grader import grade_cluster

try:
    from src.integrations.llm_client import DEFAULT_CLIENT
except Exception:
    DEFAULT_CLIENT = None  # type: ignore

try:
    from src.integrations.llm_router import route as _llm_route, describe_routing as _llm_describe_routing
    _ROUTER_AVAILABLE = True
except Exception:
    _ROUTER_AVAILABLE = False  # type: ignore

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/api/v1/assessments', tags=['cluster-enrich'])


def _try_warmup_ollama(overrides: dict | None = None) -> None:
    """Fire a tiny no-op prompt at Ollama to trigger model load before the real request.

    Uses the routing overrides so the warmup hits the same model/host as the real call.
    Errors are swallowed — the real call will surface a more useful message.
    """
    if DEFAULT_CLIENT is None:
        return
    try:
        DEFAULT_CLIENT.generate(
            prompt='hi',
            max_tokens=1,
            tenant_id=None,
            overrides=overrides or {},
        )
    except Exception:
        pass

# ── Persistent cache ─────────────────────────────────────────────────────────
_BASE = Path(__file__).resolve().parents[2] / 'src' / 'data' / 'cluster_enrich'


def _safe(s: str) -> str:
    return str(s).replace('/', '_').replace('\\', '_').replace(':', '_')


def _enrich_path(tenant_id: str, assessment_id: str, cluster_id: str) -> Path:
    p = _BASE / _safe(tenant_id) / _safe(assessment_id)
    p.mkdir(parents=True, exist_ok=True)
    return p / (_safe(cluster_id) + '.json')


def _load_cached(tenant_id: str, assessment_id: str, cluster_id: str) -> dict | None:
    try:
        path = _enrich_path(tenant_id, assessment_id, cluster_id)
        if path.exists():
            return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        pass
    return None


def _save_cached(
    tenant_id: str, assessment_id: str, cluster_id: str, data: dict
) -> None:
    try:
        _enrich_path(tenant_id, assessment_id, cluster_id).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8'
        )
    except Exception as exc:
        logger.warning('cluster_enrich save failed: %s', exc)


# ── Cluster store shim ───────────────────────────────────────────────────────
# The in-flight assessment cache lives in deep_analyze_endpoints.  We import
# it lazily to avoid a circular dependency.

def _fetch_cluster(assessment_id: str, cluster_id: str) -> dict | None:
    """Look up a cluster from the running assessment cache or persisted store."""
    try:
        from src.api.deep_analyze_endpoints import _get_assessment_cached  # type: ignore
        assessment = _get_assessment_cached(assessment_id)
    except Exception:
        assessment = None
    if not assessment:
        return None
    # Try multiple cluster list keys used by different code paths
    for key in ('correlation_clusters', 'clusters'):
        for c in (assessment.get(key) or []):
            if c.get('cluster_id') == cluster_id:
                return c
    return None


# ── Prompt builder ───────────────────────────────────────────────────────────

def _build_enrich_prompt(cluster: dict, grade: dict, mode: str) -> str:
    """Build an adversarial enrichment prompt grounded in specific named entities."""
    sev     = cluster.get('severity', 'unknown').upper()
    cid     = cluster.get('cluster_id', '?')
    phases  = ', '.join(cluster.get('phase_sequence') or []) or 'none identified'
    ac      = cluster.get('attack_chain') or {}
    chain   = ac.get('chain_text') or 'not available'
    blast   = cluster.get('blast_radius_summary') or 'unknown'
    reason  = cluster.get('reason_summary') or 'not available'
    conf    = cluster.get('confidence', 0.0)
    accs    = (cluster.get('shared_accounts') or [])[:5]
    hosts_list = (cluster.get('shared_hosts') or [])[:5]
    top_mitre = ', '.join((cluster.get('top_mitre') or [])[:6]) or 'none'
    gaps    = ', '.join((cluster.get('telemetry_gaps') or {}).get('missing_logs') or []) or 'none'
    caveats = (grade.get('caveats') or [])
    caveats_str = '\n'.join(f'  - {c}' for c in caveats) or '  (none)'
    scenarios_text = '\n'.join(
        f"  [{i+1}] {s.get('factor','?')}: {s.get('description','?')} ({s.get('urgency','?')})"
        for i, s in enumerate((ac.get('scenarios') or [])[:5])
    ) or '  (none mapped)'

    accs_str = ', '.join(accs) if accs else 'none identified'
    hosts_str = ', '.join(hosts_list) if hosts_list else 'none identified'
    ext_ips = (
        cluster.get('shared_external_ips') or
        cluster.get('external_ips') or
        cluster.get('top_ips') or
        []
    )[:3]
    ext_ips_str = ', '.join(ext_ips) if ext_ips else 'none identified'

    # Pre-build example lines for section 4 using real entity names
    _ex1 = f'1. [ACCOUNT {accs[0]}] Pull last 7 days of SSH auth events: grep \'{accs[0]}\' /var/log/auth.log | tail -200' if accs else '1. [ACCOUNT <name>] Pull auth log events for accounts listed above.'
    _ex2 = f'2. [HOST {hosts_list[0]}] Check for new cron jobs or ssh keys: find /home /root /etc/cron* -newer /tmp/baseline -type f' if hosts_list else '2. [HOST <name>] Check for new cron jobs or ssh keys on affected hosts.'
    _ex3 = f'3. [IP {ext_ips[0]}] Run AbuseIPDB lookup: curl \'https://api.abuseipdb.com/api/v2/check?ipAddress={ext_ips[0]}\'' if ext_ips else '3. [IP <address>] Run AbuseIPDB lookup for any external IPs in evidence.'

    refine_note = (
        '\nMODE: REFINE — The automated grader flagged evidence gaps. For each caveat below '
        'state explicitly: (a) does existing evidence resolve it, or (b) what specific log/telemetry would resolve it.'
        if mode == 'REFINE' else ''
    )

    return f"""You are a senior SOC analyst performing adversarial review of a correlation cluster.
Challenge the evidence. Look for alternative explanations. But also: if this looks real, say exactly what to do next.
Every recommendation MUST name a specific account, host, or IP — no generic advice.
{refine_note}

CLUSTER {cid} | {sev} | {conf:.2f} confidence
Techniques: {top_mitre}
Kill-chain: {phases}
Attack chain: {chain}
Blast radius: {blast}
Correlation reason: {reason}
Accounts: {accs_str}
Hosts: {hosts_str}
External IPs: {ext_ips_str}
Telemetry gaps: {gaps}

Attack scenarios:
{scenarios_text}

Grader caveats (MUST address each):
{caveats_str}

Write your analysis in exactly these numbered sections:

1. INVESTIGATION LEAD
List 2-3 specific alternative explanations. Each must reference the actual entities above.
Example: "{accs_str.split(',')[0].strip() or 'the account'} SSH access to {hosts_str.split(',')[0].strip() or 'the host'} during off-hours could be an automated backup job — check /etc/cron.d and scheduled tasks for that account."

2. EVIDENCE STRENGTH
For each caveat above, state in one sentence: resolved by existing evidence OR requires [specific log source].
Then state which 2 pieces of evidence are strongest and why.

3. ATTACK NARRATIVE (write this even if uncertain)
If likely malicious: 3 sentences naming the accounts/hosts/IPs and what the attacker has achieved so far and what they would do next.
If uncertain: state what single telemetry source would confirm or deny this in under 1 hour.

4. NEXT ACTIONS (max 5, each naming a specific entity from the list above)
Use only accounts, hosts, and IPs listed above — do not invent entity names or IPs not in the evidence.
{_ex1}
{_ex2}
{_ex3}
Continue this pattern for remaining entities.

5. ESCALATION RECOMMENDATION
EXACTLY one of: ESCALATE | HOLD_FOR_EVIDENCE | CLOSE_AS_BENIGN
One sentence justification citing specific evidence.
"""



# ── Pydantic models ──────────────────────────────────────────────────────────

class EnrichRequest(BaseModel):
    tenant_id: str = Field(default='default')
    force_refresh: bool = Field(default=False)
    thinking_budget: int = Field(default=4096, ge=256, le=16000)
    model: Optional[str] = Field(default=None, description='Override LLM model ID (e.g. qwen2.5:14b, gpt-4o)')
    provider: Optional[str] = Field(default=None, description='Override LLM provider (ollama | openai | anthropic)')


class FeedbackRequest(BaseModel):
    tenant_id: str = Field(default='default')
    analyst_verdict: str = Field(description='ACCEPT | REJECT | REFINE')
    analyst_note: str = Field(default='')


# ── Response parsing ─────────────────────────────────────────────────────────

def _parse_llm_response(text: str) -> dict:
    """Lightly parse numbered sections from the LLM response."""
    sections: dict[str, str] = {}
    current = None
    buf: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        for n, key in [
            ('1.', 'adversarial_challenge'),
            ('2.', 'evidence_assessment'),
            ('3.', 'attack_narrative'),
            ('4.', 'recommended_actions'),
            ('5.', 'escalation_recommendation'),
        ]:
            if stripped.startswith(n):
                if current and buf:
                    sections[current] = '\n'.join(buf).strip()
                current = key
                buf = [stripped[len(n):].strip()]
                break
        else:
            if current:
                buf.append(line)
    if current and buf:
        sections[current] = '\n'.join(buf).strip()

    # Extract escalation keyword
    esc_raw = sections.get('escalation_recommendation') or ''
    escalation = 'HOLD_FOR_EVIDENCE'
    for kw in ('ESCALATE', 'CLOSE_AS_BENIGN', 'HOLD_FOR_EVIDENCE'):
        if kw in esc_raw.upper():
            escalation = kw
            break

    return {
        'adversarial_challenge':    sections.get('adversarial_challenge', ''),
        'evidence_assessment':      sections.get('evidence_assessment', ''),
        'attack_narrative':         sections.get('attack_narrative', ''),
        'recommended_actions':      sections.get('recommended_actions', ''),
        'escalation_recommendation': escalation,
        'escalation_text':          esc_raw,
        'raw_response':             text,
    }


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post('/{assessment_id}/clusters/{cluster_id}/enrich', operation_id='enrich_cluster')
async def enrich_cluster(
    assessment_id: str,
    cluster_id: str,
    body: EnrichRequest,
    request: Request,
) -> dict:
    """Trigger on-demand LLM enrichment + CRAG grading for a cluster."""
    tenant_id = body.tenant_id

    # Check cache first (unless force_refresh)
    if not body.force_refresh:
        cached = _load_cached(tenant_id, assessment_id, cluster_id)
        if cached:
            return {**cached, 'from_cache': True}

    # Fetch live cluster
    cluster = _fetch_cluster(assessment_id, cluster_id)
    if not cluster:
        raise HTTPException(
            status_code=404,
            detail=f'Cluster {cluster_id} not found in assessment {assessment_id}. '
                   'Run analysis first or provide assessment_id from a completed run.',
        )

    # CRAG grading (rule-based, synchronous)
    grade = grade_cluster(cluster)

    result: dict = {
        'cluster_id':    cluster_id,
        'assessment_id': assessment_id,
        'tenant_id':     tenant_id,
        'grade':         grade,
        'enriched_at':   time.time(),
        'from_cache':    False,
        'llm_used':      False,
        'llm_response':  None,
        'analyst_feedback': None,
    }

    if grade['verdict'] == 'REJECT':
        result['llm_skipped_reason'] = (
            'CRAG grader returned REJECT — evidence is too thin or FP-dominated. '
            'Collect missing telemetry before requesting LLM enrichment.'
        )
        result['routing'] = {'verdict': 'REJECT', 'llm_blocked': True,
                             'reason': f'composite={grade.get("composite", 0):.3f}'}
        _save_cached(tenant_id, assessment_id, cluster_id, result)
        return result

    # ── LLM tier routing ──────────────────────────────────────────────────────
    # Selects provider/model based on CRAG composite + cluster severity + tenant config.
    call_spec = None
    routing_info: dict = {}
    if _ROUTER_AVAILABLE:
        try:
            call_spec = _llm_route(
                crag_grade=grade,
                cluster_severity=cluster.get('severity', 'medium'),
                tenant_id=tenant_id,
                thinking_budget=body.thinking_budget,
            )
            routing_info = {
                'tier':     call_spec.tier,
                'provider': call_spec.provider,
                'model':    call_spec.model,
                'reason':   call_spec.routing_reason,
            }
        except ValueError as ve:
            # Should not happen — we already checked REJECT above
            result['llm_skipped_reason'] = str(ve)
            _save_cached(tenant_id, assessment_id, cluster_id, result)
            return result
        except Exception as re:
            logger.warning('llm_router failed, falling back to DEFAULT_CLIENT: %s', re)

    result['routing'] = routing_info

    if DEFAULT_CLIENT is None:
        result['llm_skipped_reason'] = 'LLM client not available (no API key configured).'
        _save_cached(tenant_id, assessment_id, cluster_id, result)
        return result

    # Build prompt
    mode   = grade['verdict']  # ACCEPT or REFINE
    prompt = _build_enrich_prompt(cluster, grade, mode)

    # Build final overrides: router overrides + thinking budget
    if call_spec is not None:
        call_overrides: dict = dict(call_spec.overrides)
        effective_thinking = call_spec.thinking_budget
        effective_max_tokens = call_spec.max_tokens
    else:
        # Router unavailable — legacy behaviour
        call_overrides = {}
        effective_thinking = body.thinking_budget
        effective_max_tokens = min(body.thinking_budget + 1024, 8192)

    # Apply explicit UI model/provider overrides from the request body.
    # These take priority over router-selected values so analysts can
    # force a specific model from the cluster drawer picker.
    if body.model:
        call_overrides['ollama_model'] = body.model  # consumed by Ollama provider path
        call_overrides['model'] = body.model          # consumed by OpenAI / Anthropic path
    if body.provider:
        call_overrides['provider'] = body.provider

    if effective_thinking > 0 and call_overrides.get('provider', '') not in ('openai', 'azure_openai', 'vertex'):
        # Anthropic / Ollama support thinking; inject into overrides
        call_overrides['thinking'] = {
            'type':          'enabled',
            'budget_tokens': effective_thinking,
        }

    # Warm-up probe for Ollama (uses the routed host/model)
    if call_overrides.get('provider', call_spec.provider if call_spec else 'ollama') == 'ollama':
        _try_warmup_ollama(call_overrides)

    # ── LLM call ─────────────────────────────────────────────────────────────
    try:
        llm_raw = DEFAULT_CLIENT.generate(
            prompt=prompt,
            max_tokens=effective_max_tokens,
            tenant_id=tenant_id,
            overrides=call_overrides,
        )
        llm_text = llm_raw.get('text') or ''
        result['llm_response'] = _parse_llm_response(llm_text)
        result['llm_used'] = True
        result['llm_meta'] = {
            'provider':        llm_raw.get('meta', {}).get('provider', routing_info.get('provider', 'unknown')),
            'model':           llm_raw.get('model') or llm_raw.get('meta', {}).get('model') or routing_info.get('model', 'unknown'),
            'tier':            routing_info.get('tier', 'unknown'),
            'prompt_hash':     hashlib.sha256(prompt.encode()).hexdigest()[:16],
            'thinking_budget': effective_thinking,
            'input_tokens':    llm_raw.get('meta', {}).get('input_tokens', 0),
            'output_tokens':   llm_raw.get('meta', {}).get('output_tokens', 0),
            'est_cost_usd':    llm_raw.get('meta', {}).get('est_cost_usd', 0.0),
            'elapsed_s':       llm_raw.get('meta', {}).get('elapsed_s', 0.0),
        }
    except Exception as exc:
        logger.exception('LLM enrichment failed for cluster %s: %s', cluster_id, exc)
        result['llm_error'] = str(exc)
        err_lower = str(exc).lower()
        if 'connect' in err_lower or 'refused' in err_lower or 'timeout' in err_lower:
            provider_name = routing_info.get('provider', 'Ollama')
            result['llm_cold_start_hint'] = (
                f'{provider_name} appears to be offline or still loading the model. '
                'Start the model service and wait ~30s, then retry.'
            )

    _save_cached(tenant_id, assessment_id, cluster_id, result)
    return result


@router.get('/{assessment_id}/clusters/{cluster_id}/enrich', operation_id='get_cluster_enrich')
async def get_cluster_enrich(
    assessment_id: str,
    cluster_id: str,
    tenant_id: str = 'default',
) -> dict:
    """Return the cached enrichment result for a cluster (404 if not run yet)."""
    cached = _load_cached(tenant_id, assessment_id, cluster_id)
    if not cached:
        raise HTTPException(
            status_code=404,
            detail='No enrichment result found. POST to /enrich to run.',
        )
    return {**cached, 'from_cache': True}


@router.post('/{assessment_id}/clusters/{cluster_id}/enrich/feedback', operation_id='cluster_enrich_feedback')
async def cluster_enrich_feedback(
    assessment_id: str,
    cluster_id: str,
    body: FeedbackRequest,
) -> dict:
    """Record analyst feedback on an enrichment result (accept / reject / refine)."""
    tenant_id = body.tenant_id
    cached = _load_cached(tenant_id, assessment_id, cluster_id)
    if not cached:
        raise HTTPException(
            status_code=404,
            detail='No enrichment result to provide feedback on.',
        )
    valid_verdicts = {'ACCEPT', 'REJECT', 'REFINE'}
    verdict = body.analyst_verdict.upper()
    if verdict not in valid_verdicts:
        raise HTTPException(
            status_code=422,
            detail=f'analyst_verdict must be one of {sorted(valid_verdicts)}',
        )
    cached['analyst_feedback'] = {
        'verdict':   verdict,
        'note':      body.analyst_note,
        'recorded_at': time.time(),
    }
    _save_cached(tenant_id, assessment_id, cluster_id, cached)
    return {'ok': True, 'analyst_verdict': verdict, 'cluster_id': cluster_id}


@router.get('/{assessment_id}/clusters/{cluster_id}/enrich/routing', operation_id='preview_enrich_routing')
async def preview_enrich_routing(
    assessment_id: str,
    cluster_id: str,
    tenant_id: str = 'default',
) -> dict:
    """Preview which LLM tier/model/provider would be selected for this cluster.

    Does NOT call the LLM — useful for UI display and operator debugging.
    Returns the routing decision based on current CRAG grade + tenant config.
    """
    cluster = _fetch_cluster(assessment_id, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail=f'Cluster {cluster_id} not found.')

    grade = grade_cluster(cluster)

    if not _ROUTER_AVAILABLE:
        return {
            'cluster_id':  cluster_id,
            'grade':       grade,
            'routing':     {'error': 'llm_router not available'},
        }

    routing = _llm_describe_routing(
        crag_grade=grade,
        cluster_severity=cluster.get('severity', 'medium'),
        tenant_id=tenant_id,
    )
    return {
        'cluster_id':       cluster_id,
        'assessment_id':    assessment_id,
        'tenant_id':        tenant_id,
        'crag_verdict':     grade['verdict'],
        'crag_composite':   round(grade.get('composite', 0), 3),
        'cluster_severity': cluster.get('severity', 'medium'),
        'routing':          routing,
    }


__all__ = ['router']
