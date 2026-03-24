from typing import Dict, Any
from .summaries import (
    top5_risk_drivers,
    top5_factors,
    top5_iocs,
    top5_impacted_entities,
    top5_recommended_actions,
)
from .decision_support import DecisionSupportEngine
from .explainability_translator import enrich_report_explainability
from .schemas import DecisionGate
try:
    from src.repositories.playbook_repo import get_playbook_for_verdict
except Exception:
    try:
        from ..repositories.playbook_repo import get_playbook_for_verdict
    except Exception:
        get_playbook_for_verdict = None
try:
    from src.core.enrichment.email_combiners import combine_email_signals
except Exception:
    combine_email_signals = None
try:
    from src.core.scoring.dread_engine import compute_dread
except Exception:
    compute_dread = None


def generate_persona_view(report: Dict[str, Any], persona: str, disclosure_level: int = 2, top_n: int = 10) -> Dict[str, Any]:
    """Generate a persona-specific view with summary signals and decision gates.

    Persona: 'executive' | 'soc_analyst' | 'compliance' | 'threat_hunter' | 'mssp' | 'forensics'
    """
    base = {
        "report_id": report.get("report_id"),
        "persona": persona,
        "disclosure_level": disclosure_level,
        "summary_signals": {
            "risk_drivers": (top5_risk_drivers(report) or [])[:top_n],
            "factors": (top5_factors(report) or [])[:top_n],
            # top5_iocs returns a mapping of IOC-type -> list; apply top_n per-type
            "iocs": {k: (v or [])[:top_n] for k, v in (top5_iocs(report) or {}).items()},
            "impacted_entities": (top5_impacted_entities(report) or [])[:top_n],
            "recommended_actions": (top5_recommended_actions(report) or [])[:top_n],
        },
            # generate typed DecisionGate objects then convert to serializable dicts
            "decision_gates": [dg.model_dump() if isinstance(dg, DecisionGate) else dg for dg in DecisionSupportEngine().generate(report)],
    }

    # Attach enrichment and DREAD breakdown when available (evidence + provenance)
    try:
        # attach email auth/enrichment if present in report.raw_event or verdict
        raw = report.get('raw_event') or (report.get('rows') or [None])[0] or {}
        auth = (raw or {}).get('auth') or (report.get('verdict') or {}).get('auth') or {}
        headers = (raw or {}).get('headers') or {}
        envelope = (raw or {}).get('envelope') or {}
        reputations = (report.get('enrichment') or {}).get('reputations') or {}
        if combine_email_signals:
            enr = combine_email_signals(auth=auth, headers=headers, envelope=envelope, reputations=reputations)
            base['summary_signals']['enrichment'] = enr
        # Compute DREAD breakdown from artifact/factors if available
        artifact = report.get('artifact') or {}
        factors = (report.get('verdict') or {}).get('all_factors') or []
        if compute_dread:
            try:
                dread = compute_dread(artifact, factors)
                # include per-component evidence links/provenance placeholder
                base['summary_signals']['dread'] = {'breakdown': dread, 'provenance': {'factors': factors}}
            except Exception:
                pass
    except Exception:
        pass

    # Persona-specific additions
    p = persona.lower()
    if p == "executive":
        base["headline"] = _one_liner(report)
        base["business_impact"] = _business_impact(report)
        # Include tier metadata when available
        base['tier_metadata'] = report.get('tier_metadata', {})
    elif p == "soc_analyst":
        base["timeline"] = report.get("attack_timeline", [])
        base["iocs"] = base["summary_signals"]["iocs"]
    elif p == "compliance":
        base["audit_trail"] = _audit_trail(report)
        base["framework_mappings"] = report.get("framework_mappings", [])
    elif p == "threat_hunter":
        base["factor_analysis"] = report.get("verdict", {}).get("all_factors", [])
        base["statistical"] = _statistical(report)
    elif p == "mssp":
        base["client"] = {"tenant_id": report.get("tenant_id")}
        base["sla"] = {"target_minutes": 15}
    elif p == "forensics":
        raw = report.get('raw_event') or (report.get('rows') or [None])[0] or {}
        evidence = report.get('network_artifacts') or report.get('related_artifacts') or []
        base["timeline"] = report.get("attack_timeline", [])
        base["artifacts_to_collect"] = [
            value for value in [
                raw.get('host'),
                raw.get('process_name') or raw.get('process'),
                raw.get('file_hash') or raw.get('sha256') or raw.get('hash'),
                raw.get('domain'),
                raw.get('src_ip'),
                raw.get('dst_ip'),
            ] if value
        ][:top_n]
        base["evidence_sources"] = evidence[:top_n] if isinstance(evidence, list) else []
        base["investigation_checklist"] = [
            "Preserve volatile host evidence before containment.",
            "Validate execution ancestry and persistence mechanisms.",
            "Collect network pivots for external destinations and lateral movement.",
            "Capture relevant authentication and endpoint telemetry for the incident window.",
        ]
        base["chain_of_custody"] = {
            "report_id": report.get("report_id"),
            "tenant_id": report.get("tenant_id"),
            "artifact_count": len(base["evidence_sources"]),
        }

    # Progressive disclosure: level 1 = one-liner + top action, level 2 = timeline+IOCs+gates, level 3 = full
    try:
        lvl = int(disclosure_level or 2)
    except Exception:
        lvl = 2
    if lvl <= 1:
        # keep only headline / top recommended action
        small = {
            'report_id': base.get('report_id'),
            'persona': base.get('persona'),
            'headline': base.get('headline'),
            'top_action': (base.get('summary_signals', {}).get('recommended_actions') or [])[:1],
            'playbook_actions': get_playbook_for_verdict((report.get('verdict') or {}).get('final_verdict')) if get_playbook_for_verdict else {},
            'decision_gates': []
        }
        return small
    if lvl == 2:
        # include timeline, IOCs and gates but redact raw evidence
        mid = dict(base)
        # attach playbook actions for UI wiring
        try:
            mid['playbook_actions'] = get_playbook_for_verdict((report.get('verdict') or {}).get('final_verdict')) if get_playbook_for_verdict else {}
        except Exception:
            mid['playbook_actions'] = {}
        mid['summary_signals'] = dict(base.get('summary_signals', {}))
        # redact evidence links in timeline
        if 'timeline' in mid:
            try:
                mid['timeline'] = [{k: v for k, v in e.items() if k not in ('raw_evidence','raw_payload')} for e in mid.get('timeline', [])]
            except Exception:
                pass
        return mid
        # Enrich report explainability for persona-level human readable fields
        try:
            # map disclosure_level 1->MINIMAL,2->SUMMARY,3->DETAILED
            lvl_enum = int(disclosure_level or 2)
            # call enrichment to attach `all_factors_enriched`
            enrich_report_explainability(report, None)
        except Exception:
            pass

    return base



def _one_liner(report: Dict[str, Any]) -> str:
    verdict = report.get("verdict", {})
    rq = report.get("risk_quantification", {})
    return (
        f"{verdict.get('final_verdict', 'REVIEW')} at {verdict.get('final_confidence', 0.0):.0%} "
        f"(severity {rq.get('severity', 'LOW')})"
    )


def _business_impact(report: Dict[str, Any]) -> Dict[str, Any]:
    rq = report.get("risk_quantification", {})
    return {
        "estimated_loss_range": rq.get("impact_range_usd"),
        "likelihood": rq.get("likelihood_percent"),
        "expected_loss": rq.get("expected_loss_usd"),
    }


def _audit_trail(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "pipeline_version": report.get("pipeline_version"),
        "factor_weights_version": report.get("factor_weights_version"),
        "approval_status": report.get("approval_status"),
        "approved_by": report.get("approved_by"),
        "approved_at": report.get("approved_at"),
    }


def _statistical(report: Dict[str, Any]) -> Dict[str, Any]:
    v = report.get("verdict", {})
    return {
        "prior": v.get("bayesian_prior"),
        "posterior": v.get("bayesian_posterior"),
        "likelihood_ratio": v.get("likelihood_ratio"),
    }
