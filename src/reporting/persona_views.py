from typing import Dict, Any, List
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
try:
    from src.core.configuration.persona_windows import get_persona_window
except Exception:
    try:
        from core.configuration.persona_windows import get_persona_window  # type: ignore
    except Exception:
        get_persona_window = None  # type: ignore


def _normalise_mitre_tags(report: Dict[str, Any]) -> List[str]:
    """Return deduplicated list of base MITRE technique IDs (T1234) from all report locations.

    Handles both 'mitre_tags' (list of IDs) and 'mitre_techniques' (list of
    'T1234: Description' strings) found in rows and verdict.
    """
    import re as _re
    _T_RE = _re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
    tags: set[str] = set()

    def _extract(value: Any) -> None:
        for m in _T_RE.findall(str(value)):
            tags.add(m.split('.')[0].upper())

    verdict = report.get('verdict') or {}
    for t in (verdict.get('mitre_tags') or []):
        _extract(t)
    for t in (verdict.get('mitre_techniques') or []):
        _extract(t)
    for row in (report.get('rows') or report.get('llm_rows') or []):
        if not isinstance(row, dict):
            continue
        for field in ('mitre_tags', 'mitre_techniques', 'mitre'):
            for t in (row.get(field) or []):
                _extract(t)
    for finding in (report.get('findings') or []):
        if not isinstance(finding, dict):
            continue
        for field in ('mitre', 'mitre_tags', 'mitre_techniques'):
            for t in (finding.get(field) or []):
                _extract(t)
    # Also check mappings.mitre list
    for t in ((report.get('mappings') or {}).get('mitre') or []):
        _extract(t)
    return sorted(tags)


def _apply_persona_window(report: Dict[str, Any], persona: str) -> Dict[str, Any]:
    """Return a copy of report with rows filtered/capped to the persona's time window.

    Does NOT mutate the original report.  Falls back gracefully when
    get_persona_window is unavailable or rows have no timestamp.
    """
    if not get_persona_window:
        return report
    import time as _time
    win = get_persona_window(persona)
    lookback_secs = (win.get('lookback_hours') or 168) * 3600
    max_events = win.get('max_events') or 50
    recency_weight = win.get('recency_weight') or 0.5

    rows = list(report.get('rows') or [])
    if not rows:
        return report

    # Attempt to filter by timestamp when present
    now = _time.time()
    cutoff = now - lookback_secs
    ts_fields = ('ts', 'event_ts', 'valid_time_start', 'timestamp', 'createdDateTime', 'eventTimestamp', 'time')

    def _row_ts(r: dict) -> float | None:
        import datetime as _dt
        for f in ts_fields:
            v = r.get(f)
            if v is None:
                continue
            try:
                if isinstance(v, (int, float)):
                    return float(v)
                text = str(v).strip()
                if text.endswith('Z'):
                    text = text[:-1] + '+00:00'
                return _dt.datetime.fromisoformat(text).timestamp()
            except Exception:
                continue
        return None

    timestamped = [(r, _row_ts(r)) for r in rows]
    has_ts = any(ts is not None for _, ts in timestamped)

    if has_ts:
        # Keep rows within lookback window; fall back to all rows if nothing fits
        windowed = [r for r, ts in timestamped if ts is None or ts >= cutoff]
        if windowed:
            rows = windowed

    # Sort by recency when weight is high (SOC, MSSP)
    if recency_weight >= 0.7 and has_ts:
        try:
            rows = sorted(rows, key=lambda r: (_row_ts(r) or 0), reverse=True)
        except Exception:
            pass

    # Cap to max_events
    rows = rows[:max_events]

    return {**report, 'rows': rows}


def _extract_malicious_rows(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return rows with malicious/suspicious verdicts or high severity from report."""
    _HIGH_SEVERITY = {'critical', 'high'}
    _BAD_VERDICTS = {'malicious', 'suspicious', 'confirmed_malicious', 'needs_investigation'}
    result = []
    for row in (report.get('rows') or []):
        if not isinstance(row, dict):
            continue
        verdict = str(row.get('verdict') or '').lower()
        severity = str(row.get('severity') or '').lower()
        dread = float(row.get('dread_score') or 0)
        if verdict in _BAD_VERDICTS or severity in _HIGH_SEVERITY or dread >= 0.5:
            result.append(row)
    return result


def _extract_row_artifacts(rows: List[Dict[str, Any]]) -> List[str]:
    """Extract concrete artifact identifiers from scored rows for forensics/triage use."""
    import re as _re
    artifacts: list[str] = []
    seen: set[str] = set()

    _ARTIFACT_FACTORS = {
        'executable_file', 'malware_name_indicator', 'suspicious_temp_path',
        'c2_port', 'external_connection', 'lateral_movement', 'credential_access',
    }
    _EXE_RE = _re.compile(r'[\w\-\.]+\.(?:exe|dll|ps1|bat|vbs|js|sh|py)\b', _re.IGNORECASE)
    _IP_RE = _re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    _PATH_RE = _re.compile(r'(?:[a-zA-Z]:\\|/)[^\s:*?"<>|]{4,80}')

    for row in rows:
        if not isinstance(row, dict):
            continue
        factors = set(str(f).lower() for f in (row.get('factors') or []))
        if not factors.intersection(_ARTIFACT_FACTORS):
            continue

        summary = str(row.get('llm_summary') or '')
        # Executable names
        for m in _EXE_RE.findall(summary):
            key = m.lower()
            if key not in seen:
                seen.add(key)
                artifacts.append(m)
        # File paths
        for m in _PATH_RE.findall(summary):
            key = m.lower()
            if key not in seen:
                seen.add(key)
                artifacts.append(m[:120])
        # IPs from C2/external rows
        if factors.intersection({'c2_port', 'external_connection'}):
            for m in _IP_RE.findall(summary):
                key = m
                if key not in seen and not m.startswith('10.') and not m.startswith('192.168.'):
                    seen.add(key)
                    artifacts.append(f"C2:{m}")
        # Structured fields
        for field in ('file_hash', 'sha256', 'md5', 'process_name', 'src_ip', 'dst_ip'):
            v = row.get(field)
            if v:
                key = str(v).lower()
                if key not in seen:
                    seen.add(key)
                    artifacts.append(str(v))

    return artifacts[:20]


def _ensure_risk_quantification(report: Dict[str, Any]) -> None:
    """Guarantee report['risk_quantification'] is populated with at least floor values.

    This is a best-effort fallback for lite-pipeline paths where the full
    offline_workbook_assessment is not executed.  The report dict is modified
    in-place; existing populated values are never overwritten.
    """
    rq = report.get('risk_quantification') or {}
    # Already has meaningful data — nothing to do
    if rq.get('expected_loss_usd') or rq.get('severity'):
        if not report.get('risk_quantification'):
            report['risk_quantification'] = rq
        return

    rows = report.get('rows') or []
    factors: list = []
    for r in rows:
        factors.extend(r.get('factors') or [])
    n_rows = len(rows)

    # Derive counts from row-level scoring fields (dread_score, severity, verdict)
    n_malicious = sum(1 for r in rows if str(r.get('verdict') or '').lower() in ('malicious', 'confirmed_malicious'))
    n_suspicious = sum(1 for r in rows if str(r.get('verdict') or '').lower() in ('suspicious', 'needs_investigation'))
    n_high = sum(1 for r in rows if str(r.get('severity') or '').lower() in ('critical', 'high'))
    avg_dread = 0.0
    dread_vals = [float(r.get('dread_score') or 0) for r in rows if r.get('dread_score') is not None]
    if dread_vals:
        avg_dread = sum(dread_vals) / len(dread_vals)

    # Fall back to verdict confidence when rows don't carry per-row counts
    if not (n_malicious + n_suspicious):
        vc = float((report.get('verdict') or {}).get('final_confidence') or 0)
        n_suspicious = 1 if vc > 0.5 else 0

    # Use PASTA risk matrix (highest scored entry) when present
    pasta_entries = (
        (report.get('threat_models') or {}).get('pasta_risk_matrix')
        or (report.get('mappings') or {}).get('pasa', {}).get('risks')
        or []
    )
    pasta_max_score = 0.0
    pasta_severity_hint = ''
    for entry in pasta_entries:
        if not isinstance(entry, dict):
            continue
        s = float(entry.get('score') or 0)
        if s > pasta_max_score:
            pasta_max_score = s
            pasta_severity_hint = str(entry.get('impact') or entry.get('likelihood') or '').upper()

    # Determine severity: PASTA > explicit verdict > row-level counts > DREAD
    verdict_sev = ((report.get('verdict') or {}).get('final_verdict') or '').upper()
    if pasta_max_score >= 8.0 or n_malicious >= 3:
        severity = 'CRITICAL'
    elif pasta_max_score >= 6.0 or n_malicious >= 1 or n_high >= 5:
        severity = 'HIGH'
    elif pasta_max_score >= 4.0 or n_suspicious >= 5 or n_high >= 2 or avg_dread >= 0.5:
        severity = 'MEDIUM'
    elif verdict_sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        severity = verdict_sev
    elif n_suspicious > 0 or avg_dread >= 0.1:
        severity = 'LOW'
    else:
        severity = 'LOW'

    # Loss range driven by severity + PASTA top score
    _BASE_LOSS = {'LOW': 6000, 'MEDIUM': 45000, 'HIGH': 180000, 'CRITICAL': 650000}
    _MULTIPLIER = {'LOW': 3, 'MEDIUM': 4, 'HIGH': 5, 'CRITICAL': 8}
    base_loss = _BASE_LOSS.get(severity, 6000)
    # Scale up by PASTA score ratio when meaningful
    if pasta_max_score >= 4.0:
        scale = 1.0 + (pasta_max_score - 4.0) * 0.4
        base_loss = int(base_loss * scale)
    multiplier = _MULTIPLIER.get(severity, 3)

    try:
        from src.analysis.offline_workbook_assessment import _estimate_expected_loss
        expected = _estimate_expected_loss(severity, max(1, n_rows), n_malicious + n_suspicious, 0)
    except Exception:
        expected = base_loss

    likelihood = round(min(85, 15 + (n_malicious * 25) + (n_suspicious * 10) + (n_high * 5)), 1)

    report['risk_quantification'] = rq | {
        'severity': severity,
        'likelihood_percent': likelihood,
        'expected_loss_usd': expected,
        'impact_range_usd': [base_loss, base_loss * multiplier],
        'damage_potential': min(10, 2 + n_malicious * 3 + n_high),
        'evidence_based': bool(n_malicious + n_suspicious),
        'pasta_max_score': pasta_max_score,
        'row_counts': {
            'malicious': n_malicious,
            'suspicious': n_suspicious,
            'high_severity': n_high,
            'avg_dread': round(avg_dread, 3),
        },
        '_synthesized': True,
    }


def generate_persona_view(report: Dict[str, Any], persona: str, disclosure_level: int = 2, top_n: int = 10) -> Dict[str, Any]:
    """Generate a persona-specific view with summary signals and decision gates.

    Persona: 'executive' | 'ciso' | 'soc_analyst' | 'compliance' | 'threat_hunter' | 'mssp' | 'forensics'
    """
    # Apply persona-scoped evidence time window before any analysis
    report = _apply_persona_window(report, persona)

    # Ensure risk_quantification always has a value so downstream persona blocks can read dollar figures
    _ensure_risk_quantification(report)
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

    # Normalise MITRE tags once — used by compliance, threat_hunter, forensics
    mitre_tags = _normalise_mitre_tags(report)

    # Persona-specific additions
    p = persona.lower()
    if p == "executive":
        base["headline"] = _one_liner(report)
        base["business_impact"] = _business_impact(report)
        base["operational_next_step"] = _operational_next_step(report)
        base["control_posture"] = _control_posture(report)
        base['tier_metadata'] = report.get('tier_metadata', {})
        tier2 = report.get('tier2_analysis') or report.get('tier2') or {}
        if tier2:
            exec_summary = tier2.get('executive_summary') or {}
            ai_reasoning = tier2.get('ai_reasoning') or {}
            plain_narrative = (
                exec_summary.get('one_liner')
                or ai_reasoning.get('primary_hypothesis')
                or tier2.get('plain_english_narrative')
            )
            if plain_narrative:
                base['plain_english_narrative'] = plain_narrative
            threat_level = exec_summary.get('threat_level')
            if threat_level:
                base['tier2_threat_level'] = threat_level
            recommended_action = exec_summary.get('recommended_action')
            if recommended_action:
                base['tier2_recommended_action'] = recommended_action
            knowledge_gaps = ai_reasoning.get('knowledge_gaps')
            if knowledge_gaps:
                base['knowledge_gaps'] = knowledge_gaps

    elif p == "ciso":
        rq = report.get('risk_quantification') or {}
        severity = rq.get('severity', 'LOW')
        reg_ids = _map_to_regulatory_controls_from_tags(mitre_tags)
        gdpr_triggered = bool(reg_ids.get('GDPR'))
        base["headline"] = _ciso_headline(report, severity, gdpr_triggered)
        base["business_impact"] = _business_impact(report)
        base["regulatory_exposure"] = {
            "gdpr_notification_required": gdpr_triggered,
            "gdpr_article": "Art. 33 — 72h supervisory authority notification" if gdpr_triggered else None,
            "sec_8k_risk": severity in ('CRITICAL', 'HIGH'),
            "frameworks_triggered": [k for k in ('GDPR', 'SOC2', 'PCI_DSS', 'HIPAA', 'ISO27001') if reg_ids.get(k)],
        }
        base["isms_risk_treatment"] = _isms_risk_treatment(report, mitre_tags)
        base["control_posture"] = _control_posture(report)

    elif p == "soc_analyst":
        bad_rows = _extract_malicious_rows(report)
        base["timeline"] = report.get("attack_timeline", [])
        base["iocs"] = base["summary_signals"]["iocs"]
        base["triage_focus"] = _triage_focus(report) or _triage_focus_from_rows(bad_rows)
        base["corroboration_targets"] = _corroboration_targets(report)
        base["priority"] = _soc_priority(report)
        base["containment_options"] = _containment_options(bad_rows)

    elif p == "compliance":
        reg_ids = _map_to_regulatory_controls_from_tags(mitre_tags)
        base["audit_trail"] = _audit_trail(report)
        base["framework_mappings"] = _build_framework_mappings(report, mitre_tags)
        base["control_posture"] = _control_posture(report)
        base["regulatory_control_ids"] = reg_ids
        base["isms_findings"] = _isms_control_failures(report, mitre_tags)
        base["notification_obligations"] = _notification_obligations(report, reg_ids)

    elif p == "threat_hunter":
        base["factor_analysis"] = _factor_analysis_from_rows(report)
        base["statistical"] = _statistical(report)
        base["corroboration_targets"] = _corroboration_targets(report)
        base["kill_chain_stages"] = _derive_kill_chain_stages_from_tags(mitre_tags)
        base["sigma_rules"] = _generate_sigma_stubs(report)
        base["hunt_hypotheses"] = _hunt_hypotheses(report, mitre_tags)

    elif p == "mssp":
        rq = report.get('risk_quantification') or {}
        base["client"] = {"tenant_id": report.get("tenant_id")}
        base["sla"] = _sla_status(report)
        base["client_summary"] = _mssp_client_summary(report)

    elif p == "forensics":
        bad_rows = _extract_malicious_rows(report)
        all_rows = report.get('rows') or []
        evidence = report.get('network_artifacts') or report.get('related_artifacts') or []
        base["timeline"] = _build_forensic_timeline(report)
        base["artifacts_to_collect"] = _extract_row_artifacts(bad_rows or all_rows) or [
            value for value in [
                (report.get('raw_event') or {}).get('host'),
                (report.get('raw_event') or {}).get('process_name'),
            ] if value
        ]
        base["artifacts_to_collect"] = base["artifacts_to_collect"][:top_n]
        base["evidence_sources"] = evidence[:top_n] if isinstance(evidence, list) else []
        base["investigation_checklist"] = _forensic_checklist(bad_rows, mitre_tags)
        base["chain_of_custody"] = {
            "report_id": report.get("report_id"),
            "tenant_id": report.get("tenant_id"),
            "artifact_count": len(base["artifacts_to_collect"]),
            "valid_time_note": (
                "valid_time (event occurrence) and transaction_time (ingest) may differ for "
                "CloudTrail/VPN sources. Verify log ingestion lag before finalising timeline."
            ),
        }
        base["corroboration_targets"] = _corroboration_targets(report)

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
        # Enrich report explainability for persona-level human readable fields
        try:
            enrich_report_explainability(report, None)
        except Exception:
            pass
        return mid

    return base



def _one_liner(report: Dict[str, Any]) -> str:
    verdict = report.get("verdict") or {}
    rq = report.get("risk_quantification") or {}
    impact = report.get("impact_metadata") or {}
    identities = len(impact.get("affected_identities") or [])
    hosts = len(impact.get("affected_hosts") or [])
    scope = []
    if identities:
        scope.append(f"{identities} identity{'ies' if identities != 1 else ''}")
    if hosts:
        scope.append(f"{hosts} host{'s' if hosts != 1 else ''}")
    scope_text = f"; scope {', '.join(scope)}" if scope else ""

    severity = rq.get('severity') or 'LOW'
    counts = rq.get('row_counts') or {}
    n_malicious = counts.get('malicious', 0)
    n_suspicious = counts.get('suspicious', 0)
    confidence = verdict.get('final_confidence')

    # Use evidence-derived verdict when explicit verdict is absent
    final_verdict = verdict.get('final_verdict')
    if not final_verdict:
        if n_malicious:
            final_verdict = 'CONFIRMED MALICIOUS'
        elif n_suspicious:
            final_verdict = 'SUSPICIOUS — INVESTIGATE'
        else:
            final_verdict = 'NO CONFIRMED THREAT'

    confidence_text = f" at {confidence:.0%}" if confidence is not None else ""
    return f"{final_verdict}{confidence_text} (severity {severity}{scope_text})"


def _business_impact(report: Dict[str, Any]) -> Dict[str, Any]:
    rq = report.get("risk_quantification", {})
    raw_loss_range = rq.get("impact_range_usd")
    # Anti-pattern fix: never expose [0, 0] — replace with "Financial impact assessment pending"
    if raw_loss_range and (raw_loss_range == [0, 0] or (
            isinstance(raw_loss_range, (list, tuple)) and len(raw_loss_range) == 2
            and all(not v for v in raw_loss_range))):
        raw_loss_range = None
    loss_range_display = raw_loss_range if raw_loss_range else "Financial impact assessment pending"
    expected = rq.get("expected_loss_usd") or None
    impact: Dict[str, Any] = {
        "estimated_loss_range": loss_range_display,
        "likelihood": rq.get("likelihood_percent"),
        "expected_loss": expected,
    }

    # Enrich with AssetContext when available — enables "production payment processor" language
    raw_ctx = (
        report.get("asset_context")
        or (report.get("verdict") or {}).get("asset_context")
        or (report.get("artifact") or {}).get("asset_context")
    )
    if raw_ctx:
        try:
            from src.reporting.schemas import AssetContext
            ctx = AssetContext(**raw_ctx) if isinstance(raw_ctx, dict) else raw_ctx
            impact["asset_label"] = ctx.impact_label()
            impact["environment"] = ctx.environment
            impact["business_tier"] = ctx.business_tier
            impact["data_classification"] = ctx.data_classification
            impact["regulatory_scope"] = ctx.regulatory_scope
            impact["asset_criticality"] = ctx.asset_criticality
            if ctx.estimated_annual_revenue_impact_usd:
                impact["revenue_exposure_usd"] = ctx.estimated_annual_revenue_impact_usd
        except Exception:
            pass

    return impact


def _operational_next_step(report: Dict[str, Any]) -> str | None:
    actions = report.get("recommended_actions") or []
    if actions:
        top = actions[0]
        return top.get("primary_action") or top.get("action")
    return None


def _control_posture(report: Dict[str, Any]) -> Dict[str, Any]:
    impact = report.get("impact_metadata") or {}
    return {
        "control_objectives": impact.get("control_objectives") or [],
        "approval_required": ((report.get("decision_record") or {}).get("approval_state") or {}).get("required"),
        "approval_state": ((report.get("decision_record") or {}).get("approval_state") or {}).get("status"),
    }


def _audit_trail(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "pipeline_version": report.get("pipeline_version"),
        "factor_weights_version": report.get("factor_weights_version"),
        "approval_status": report.get("approval_status"),
        "approved_by": report.get("approved_by"),
        "approved_at": report.get("approved_at"),
    }


# ---------------------------------------------------------------------------
# Regulatory control ID mapping for the Compliance persona
# ---------------------------------------------------------------------------

# MITRE ATT&CK technique → {framework: [control_ids]} mapping
_TECHNIQUE_CONTROL_MAP: Dict[str, Dict[str, list[str]]] = {
    'T1078': {
        'SOC2': ['CC6.1', 'CC6.2', 'CC6.3'],
        'GDPR': ['Art. 32(1)(b)', 'Art. 32(1)(d)'],
        'PCI_DSS': ['8.2', '8.3', '10.2.4'],
        'HIPAA': ['§164.308(a)(3)', '§164.308(a)(4)', '§164.312(a)(1)'],
        'ISO27001': ['A.5.15', 'A.5.16', 'A.8.2'],
    },
    'T1110': {
        'SOC2': ['CC6.1', 'CC6.6'],
        'GDPR': ['Art. 32(1)(a)', 'Art. 32(1)(b)'],
        'PCI_DSS': ['8.3', '8.3.6', '10.2.4'],
        'HIPAA': ['§164.312(d)', '§164.308(a)(5)'],
        'ISO27001': ['A.5.16', 'A.8.5'],
    },
    'T1566': {
        'SOC2': ['CC6.7', 'CC6.8'],
        'GDPR': ['Art. 32(1)(b)'],
        'PCI_DSS': ['5.4', '12.6'],
        'HIPAA': ['§164.308(a)(5)', '§164.308(a)(1)'],
        'ISO27001': ['A.6.3', 'A.8.23'],
    },
    'T1003': {
        'SOC2': ['CC6.1', 'CC6.6'],
        'GDPR': ['Art. 32(1)(b)', 'Art. 33'],
        'PCI_DSS': ['8.2', '10.2.5'],
        'HIPAA': ['§164.312(a)(1)', '§164.308(a)(1)', '§164.312(c)(1)'],
        'ISO27001': ['A.5.17', 'A.8.2', 'A.5.28'],
    },
    'T1059': {
        'SOC2': ['CC6.8'],
        'GDPR': ['Art. 32(1)(b)'],
        'PCI_DSS': ['6.3', '10.2.2'],
        'HIPAA': ['§164.308(a)(1)', '§164.312(b)'],
        'ISO27001': ['A.8.9', 'A.8.20'],
    },
    'T1047': {
        'SOC2': ['CC6.8', 'CC7.2'],
        'GDPR': ['Art. 32(1)(d)'],
        'PCI_DSS': ['6.3', '10.2.2'],
        'HIPAA': ['§164.312(b)'],
        'ISO27001': ['A.8.9', 'A.8.15'],
    },
    'T1486': {
        'SOC2': ['A1.2', 'CC9.1'],
        'GDPR': ['Art. 32(1)(c)', 'Art. 33', 'Art. 34'],
        'PCI_DSS': ['12.10', '3.4'],
        'HIPAA': ['§164.308(a)(7)', '§164.310(d)(1)', '§164.412'],
        'ISO27001': ['A.5.29', 'A.5.30', 'A.8.13'],
    },
    'T1048': {
        'SOC2': ['CC6.7', 'CC7.3'],
        'GDPR': ['Art. 32(1)(b)', 'Art. 33'],
        'PCI_DSS': ['4.2', '10.3'],
        'HIPAA': ['§164.308(a)(1)', '§164.312(e)(2)'],
        'ISO27001': ['A.5.14', 'A.8.20'],
    },
    'T1071': {
        'SOC2': ['CC6.6', 'CC7.2'],
        'GDPR': ['Art. 32(1)(d)'],
        'PCI_DSS': ['1.3', '10.2.7'],
        'HIPAA': ['§164.312(e)(1)', '§164.312(b)'],
        'ISO27001': ['A.8.20', 'A.8.15'],
    },
    'T1190': {
        'SOC2': ['CC7.1', 'CC7.2'],
        'GDPR': ['Art. 32(1)(b)', 'Art. 33'],
        'PCI_DSS': ['6.3.3', '11.3'],
        'HIPAA': ['§164.308(a)(1)', '§164.312(b)'],
        'ISO27001': ['A.8.8', 'A.8.31'],
    },
    'T1021': {
        'SOC2': ['CC6.1', 'CC6.3'],
        'GDPR': ['Art. 32(1)(b)'],
        'PCI_DSS': ['7.2', '8.2', '10.2.3'],
        'HIPAA': ['§164.308(a)(4)', '§164.312(a)(2)'],
        'ISO27001': ['A.5.15', 'A.8.18'],
    },
    'T1552': {
        'SOC2': ['CC6.1', 'CC6.7'],
        'GDPR': ['Art. 32(1)(a)'],
        'PCI_DSS': ['8.3', '6.5'],
        'HIPAA': ['§164.312(a)(1)', '§164.308(a)(3)'],
        'ISO27001': ['A.5.17', 'A.8.12'],
    },
    'T1027': {
        'SOC2': ['CC7.1', 'CC7.2'],
        'GDPR': ['Art. 32(1)(d)'],
        'PCI_DSS': ['5.2', '10.2.7'],
        'HIPAA': ['§164.312(b)'],
        'ISO27001': ['A.8.16', 'A.8.15'],
    },
    # Data exfil / collection
    'T1530': {
        'SOC2': ['CC6.7', 'CC7.3'],
        'GDPR': ['Art. 32(1)(b)', 'Art. 33'],
        'PCI_DSS': ['3.5', '4.2'],
        'HIPAA': ['§164.312(a)(1)', '§164.312(e)(1)'],
        'ISO27001': ['A.5.12', 'A.5.14'],
    },
    # Privilege escalation
    'T1134': {
        'SOC2': ['CC6.3', 'CC6.8'],
        'GDPR': ['Art. 32(1)(b)'],
        'PCI_DSS': ['7.1', '8.2'],
        'HIPAA': ['§164.308(a)(4)', '§164.312(a)(1)'],
        'ISO27001': ['A.5.15', 'A.8.2'],
    },
    # Impact: account access removal
    'T1531': {
        'SOC2': ['CC6.2', 'CC7.2'],
        'GDPR': ['Art. 32(1)(d)'],
        'PCI_DSS': ['8.1', '12.10'],
        'HIPAA': ['§164.308(a)(3)', '§164.308(a)(7)'],
        'ISO27001': ['A.5.18', 'A.5.29'],
    },
}


def _map_to_regulatory_controls(report: Dict[str, Any]) -> Dict[str, Any]:
    """Return regulatory control mapping from report (derives tags internally)."""
    return _map_to_regulatory_controls_from_tags(_normalise_mitre_tags(report))


def _map_to_regulatory_controls_from_tags(mitre_tags: List[str]) -> Dict[str, Any]:
    """Return a mapping of regulatory control IDs relevant to the given MITRE technique IDs."""
    # Collect MITRE technique tags from pre-normalised list
    tag_set: set[str] = set(mitre_tags)

    soc2: set[str] = set()
    gdpr: set[str] = set()
    pci: set[str] = set()
    hipaa: set[str] = set()
    iso27001: set[str] = set()
    matched_techniques: list[str] = []

    for tag in tag_set:
        ctl = _TECHNIQUE_CONTROL_MAP.get(tag)
        if ctl:
            matched_techniques.append(tag)
            soc2.update(ctl.get('SOC2') or [])
            gdpr.update(ctl.get('GDPR') or [])
            pci.update(ctl.get('PCI_DSS') or [])
            hipaa.update(ctl.get('HIPAA') or [])
            iso27001.update(ctl.get('ISO27001') or [])

    # Always include baseline controls when any technique is matched
    if matched_techniques:
        soc2.update(['CC6.1'])
        pci.update(['10.1'])
        hipaa.update(['§164.308(a)(1)'])  # baseline: Security Management Process
        iso27001.update(['A.5.1'])         # baseline: Policies for information security

    result: Dict[str, Any] = {
        'SOC2': sorted(soc2),
        'GDPR': sorted(gdpr),
        'PCI_DSS': sorted(pci),
        'matched_techniques': sorted(matched_techniques),
        'rationale': {
            'SOC2': 'Logical access, change management, and monitoring controls relevant to detected TTPs.',
            'GDPR': 'Data protection obligations triggered by potential personal data access or breach indicators.',
            'PCI_DSS': 'Cardholder environment access logging and authentication requirements applicable to this activity.',
        } if matched_techniques else {},
    }
    if hipaa:
        result['HIPAA'] = sorted(hipaa)
        if matched_techniques:
            result['rationale']['HIPAA'] = (
                'HIPAA Security Rule safeguards applicable to ePHI access controls and '
                'breach notification obligations triggered by this activity.'
            )
    if iso27001:
        result['ISO27001'] = sorted(iso27001)
        if matched_techniques:
            result['rationale']['ISO27001'] = (
                'ISO/IEC 27001:2022 Annex A controls addressing access management, '
                'incident response and operations security relevant to detected TTPs.'
            )
    return result


def _ciso_headline(report: Dict[str, Any], severity: str, gdpr_triggered: bool) -> str:
    rq = report.get('risk_quantification') or {}
    counts = rq.get('row_counts') or {}
    n_malicious = counts.get('malicious', 0)
    n_suspicious = counts.get('suspicious', 0)
    # Fallback: derive directly from rows when row_counts absent (e.g. from offline scorer)
    if not (n_malicious + n_suspicious):
        for r in (report.get('rows') or []):
            if not isinstance(r, dict):
                continue
            v = str(r.get('verdict') or '').lower()
            if v in ('malicious', 'confirmed_malicious'):
                n_malicious += 1
            elif v in ('suspicious', 'needs_investigation'):
                n_suspicious += 1
    # Also use top-level verdict when rows are absent
    if not (n_malicious + n_suspicious):
        top_verdict = str(report.get('final_verdict') or '').upper()
        if top_verdict in ('THREAT', 'MALICIOUS', 'CONFIRMED_MALICIOUS'):
            n_malicious = 1
        elif top_verdict in ('SUSPICIOUS', 'REVIEW'):
            n_suspicious = 1

    gdpr_note = " — GDPR Art.33 disclosure assessment required" if gdpr_triggered else ""
    if n_malicious:
        return f"CONFIRMED {severity} INCIDENT: {n_malicious} malicious event{'s' if n_malicious != 1 else ''} detected{gdpr_note}"
    if n_suspicious:
        return f"SUSPICIOUS ACTIVITY — {severity}: {n_suspicious} event{'s' if n_suspicious != 1 else ''} require investigation{gdpr_note}"
    return f"ASSESSMENT COMPLETE — severity {severity}: monitor and review{gdpr_note}"


def _triage_focus_from_rows(bad_rows: List[Dict[str, Any]]) -> list[str]:
    focus = []
    seen: set = set()
    for row in bad_rows[:6]:
        summary = str(row.get('llm_summary') or '')[:200]
        sev = str(row.get('severity') or '').upper()
        if summary and summary not in seen:
            seen.add(summary)
            focus.append(f"[{sev}] {summary}")
    return focus


def _soc_priority(report: Dict[str, Any]) -> str:
    rq = report.get('risk_quantification') or {}
    sev = rq.get('severity', 'LOW')
    counts = rq.get('row_counts') or {}
    if sev == 'CRITICAL' or counts.get('malicious', 0) >= 3:
        return 'P1'
    if sev == 'HIGH' or counts.get('malicious', 0) >= 1 or counts.get('high_severity', 0) >= 3:
        return 'P2'
    if sev == 'MEDIUM' or counts.get('suspicious', 0) >= 3:
        return 'P3'
    return 'P4'


def _containment_options(bad_rows: List[Dict[str, Any]]) -> list[Dict[str, Any]]:
    options = []
    has_c2 = any('c2_port' in (r.get('factors') or []) or 'external_connection' in (r.get('factors') or []) for r in bad_rows)
    has_malware = any('executable_file' in (r.get('factors') or []) or 'malware_name_indicator' in (r.get('factors') or []) for r in bad_rows)
    has_lateral = any('lateral_movement' in (r.get('factors') or []) for r in bad_rows)
    has_cred = any('credential_access' in (r.get('factors') or []) or 'suspicious_temp_path' in (r.get('factors') or []) for r in bad_rows)
    if has_malware:
        options.append({'action': 'Isolate affected host(s) from network', 'speed': 'immediate', 'blast_radius': 'low'})
    if has_c2:
        options.append({'action': 'Block C2 IPs/domains at perimeter firewall', 'speed': 'immediate', 'blast_radius': 'low'})
    if has_cred:
        options.append({'action': 'Force password reset for all affected accounts', 'speed': 'urgent', 'blast_radius': 'medium'})
    if has_lateral:
        options.append({'action': 'Disable lateral movement protocols (WMI/RDP/SMB) in affected subnet', 'speed': 'urgent', 'blast_radius': 'medium'})
    if not options:
        options.append({'action': 'Escalate to Tier 2 for deeper investigation', 'speed': 'normal', 'blast_radius': 'none'})
    return options


def _build_framework_mappings(report: Dict[str, Any], mitre_tags: List[str]) -> list[Dict[str, Any]]:
    """Build framework_mappings list from MITRE tags, STRIDE, and existing mappings."""
    mappings_out: list[Dict[str, Any]] = []
    seen_tech: set[str] = set()

    # Pull existing framework_mappings if present
    for fm in (report.get('framework_mappings') or []):
        if isinstance(fm, dict):
            mappings_out.append(fm)
            tech = str(fm.get('technique') or fm.get('technique_id') or '').split('.')[0].upper()
            if tech:
                seen_tech.add(tech)

    # Build from normalised MITRE tags
    for tag in mitre_tags:
        if tag in seen_tech:
            continue
        ctl = _TECHNIQUE_CONTROL_MAP.get(tag)
        if not ctl:
            continue
        seen_tech.add(tag)
        entry: Dict[str, Any] = {'technique_id': tag, 'source': 'mitre_normalised'}
        for fw, ids in ctl.items():
            entry[fw] = ids
        mappings_out.append(entry)

    # Also pull from mappings.mitre (deep_analyze assessment field)
    for t in ((report.get('mappings') or {}).get('mitre') or []):
        if isinstance(t, str) and t not in seen_tech and not t.startswith('lite'):
            import re as _re
            m = _re.search(r'(T\d{4})', t)
            if m:
                tag = m.group(1)
                if tag not in seen_tech:
                    seen_tech.add(tag)
                    ctl = _TECHNIQUE_CONTROL_MAP.get(tag)
                    if ctl:
                        entry = {'technique_id': tag, 'source': 'mappings_mitre'}
                        entry.update(ctl)
                        mappings_out.append(entry)

    return mappings_out


def _isms_control_failures(report: Dict[str, Any], mitre_tags: List[str]) -> list[Dict[str, Any]]:
    """Return ISO 19011-style audit findings: nonconformity mapped to ISO 27001 Annex A controls."""
    _TECHNIQUE_ISMS: Dict[str, Dict[str, Any]] = {
        'T1003': {
            'annex_a': 'A.8.5 — Secure authentication',
            'nonconformity': 'LSASS credential dumping succeeded, indicating authentication controls did not prevent memory access to credential store.',
            'corrective_action': 'Enable Windows Credential Guard; configure LSASS Protected Mode (RunAsPPL).',
            'severity': 'Major',
        },
        'T1059': {
            'annex_a': 'A.8.9 — Configuration management / A.8.20 — Networks security',
            'nonconformity': 'Malicious script/command execution detected; application control policy did not block execution.',
            'corrective_action': 'Deploy application allowlisting (AppLocker/WDAC); restrict PowerShell execution policy.',
            'severity': 'Major',
        },
        'T1047': {
            'annex_a': 'A.8.9 — Configuration management',
            'nonconformity': 'WMI lateral movement detected; remote execution via WMI was not restricted.',
            'corrective_action': 'Disable WMI remote execution for non-administrative accounts; implement WBEM access controls.',
            'severity': 'Major',
        },
        'T1566': {
            'annex_a': 'A.6.3 — Information security awareness / A.8.23 — Web filtering',
            'nonconformity': 'Phishing/email-borne initial access occurred; user awareness and technical controls were insufficient.',
            'corrective_action': 'Enhance email security gateway filtering; conduct targeted phishing simulation for affected users.',
            'severity': 'Minor',
        },
        'T1078': {
            'annex_a': 'A.5.15 — Access control / A.5.16 — Identity management',
            'nonconformity': 'Valid account credentials were abused; identity lifecycle or MFA controls were insufficient.',
            'corrective_action': 'Enforce MFA on all privileged accounts; review and remove stale accounts.',
            'severity': 'Major',
        },
        'T1041': {
            'annex_a': 'A.5.14 — Information transfer / A.8.20 — Networks security',
            'nonconformity': 'Data exfiltration over C2 channel detected; outbound traffic was not sufficiently inspected.',
            'corrective_action': 'Implement TLS inspection at egress; enforce data loss prevention (DLP) policy.',
            'severity': 'Critical',
        },
        'T1021': {
            'annex_a': 'A.5.15 — Access control / A.8.18 — Use of privileged utility programs',
            'nonconformity': 'Lateral movement via remote services detected; access between hosts was not appropriately restricted.',
            'corrective_action': 'Implement network segmentation; restrict RDP/SMB to authorised jump hosts only.',
            'severity': 'Major',
        },
        'T1486': {
            'annex_a': 'A.5.29 — Information security during disruption / A.8.13 — Information backup',
            'nonconformity': 'Ransomware/data destruction capability detected; backup integrity and restoration controls are at risk.',
            'corrective_action': 'Validate offline backup integrity immediately; test restoration procedures.',
            'severity': 'Critical',
        },
    }
    findings: list[Dict[str, Any]] = []
    for tag in mitre_tags:
        entry = _TECHNIQUE_ISMS.get(tag)
        if entry:
            findings.append({
                'technique_id': tag,
                **entry,
                'evidence_source': 'mitre_technique_detection',
            })
    # Also check STRIDE confirmed status
    stride = (report.get('threat_models') or {}).get('stride_summary') or {}
    for cat, data in stride.items():
        if isinstance(data, dict) and data.get('status') == 'CONFIRMED' and data.get('count', 0) > 0:
            _STRIDE_ISMS = {
                'S': {'annex_a': 'A.5.16 — Identity management', 'nonconformity': 'Identity spoofing confirmed.', 'corrective_action': 'Review sender authentication (DMARC/SPF/DKIM); validate identity verification controls.', 'severity': 'Major'},
                'T': {'annex_a': 'A.8.9 — Configuration management', 'nonconformity': 'Tampering with system/data detected.', 'corrective_action': 'Enable file integrity monitoring; review change management controls.', 'severity': 'Major'},
                'I': {'annex_a': 'A.5.14 — Information transfer', 'nonconformity': 'Information disclosure / exfiltration pathway identified.', 'corrective_action': 'Implement DLP; review network egress filtering.', 'severity': 'Major'},
                'E': {'annex_a': 'A.5.15 — Access control', 'nonconformity': 'Privilege elevation detected.', 'corrective_action': 'Review privileged access management; enforce least-privilege principle.', 'severity': 'Critical'},
            }
            stride_finding = _STRIDE_ISMS.get(cat)
            if stride_finding:
                findings.append({
                    'stride_category': cat,
                    'stride_label': data.get('label', cat),
                    'evidence_count': data.get('count', 0),
                    **stride_finding,
                    'evidence_source': 'stride_confirmed',
                })
    return findings


def _isms_risk_treatment(report: Dict[str, Any], mitre_tags: List[str]) -> Dict[str, Any]:
    """CISO-oriented ISMS risk treatment assessment."""
    rq = report.get('risk_quantification') or {}
    severity = rq.get('severity', 'LOW')
    findings = _isms_control_failures(report, mitre_tags)
    critical_findings = [f for f in findings if f.get('severity') in ('Critical', 'Major')]
    return {
        'management_review_required': severity in ('CRITICAL', 'HIGH') or len(critical_findings) >= 2,
        'incident_classification': severity,
        'control_failures_count': len(findings),
        'critical_major_findings': len(critical_findings),
        'top_findings': findings[:3],
        'corrective_action_deadline': '72h' if severity == 'CRITICAL' else '7 days' if severity == 'HIGH' else '30 days',
    }


def _notification_obligations(report: Dict[str, Any], reg_ids: Dict[str, Any]) -> Dict[str, Any]:
    rq = report.get('risk_quantification') or {}
    severity = rq.get('severity', 'LOW')
    gdpr_triggered = bool(reg_ids.get('GDPR'))
    return {
        'gdpr_art33': {
            'triggered': gdpr_triggered,
            'deadline_hours': 72 if gdpr_triggered else None,
            'clock_status': 'RUNNING — verify PII involvement' if gdpr_triggered else 'NOT TRIGGERED',
            'note': 'Art.33 requires notification to supervisory authority within 72h of awareness.' if gdpr_triggered else None,
        },
        'sec_8k': {
            'triggered': severity in ('CRITICAL', 'HIGH'),
            'note': 'SEC Cybersecurity Disclosure Rule — material incidents require 8-K filing within 4 business days.' if severity in ('CRITICAL', 'HIGH') else None,
        },
        'nis2': {
            'triggered': severity == 'CRITICAL',
            'note': 'NIS2 Art.23 — early warning to CSIRT within 24h for significant incidents.' if severity == 'CRITICAL' else None,
        },
    }


def _hunt_hypotheses(report: Dict[str, Any], mitre_tags: List[str]) -> list[Dict[str, Any]]:
    hypotheses = []
    if 'T1041' in mitre_tags or 'T1071' in mitre_tags:
        hypotheses.append({
            'hypothesis': 'C2 beacon activity may indicate additional compromised hosts in the same subnet',
            'pivot': 'Search for matching JA3/JA3S fingerprints or beacon interval patterns across all hosts',
            'confidence': 'MEDIUM',
        })
    if 'T1003' in mitre_tags:
        hypotheses.append({
            'hypothesis': 'LSASS credential dump may have yielded credentials reused on other systems',
            'pivot': 'Check authentication logs for pass-the-hash or lateral authentication from affected host',
            'confidence': 'HIGH',
        })
    if 'T1047' in mitre_tags or 'T1021' in mitre_tags:
        hypotheses.append({
            'hypothesis': 'Lateral movement via WMI/remote services may indicate broader domain compromise',
            'pivot': 'Enumerate all WMI/SMB/RDP connections from compromised host in the 48h window',
            'confidence': 'HIGH',
        })
    if 'T1566' in mitre_tags:
        hypotheses.append({
            'hypothesis': 'Phishing campaign may have targeted multiple users in the same organisation',
            'pivot': 'Search email gateway logs for same sender/subject/attachment hash across all mailboxes',
            'confidence': 'MEDIUM',
        })
    return hypotheses


def _build_forensic_timeline(report: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Build a forensic timeline from rows with timestamps, noting valid_time vs transaction_time."""
    import datetime as _dt
    timeline = list(report.get('attack_timeline') or [])
    if not timeline:
        # Build from high-severity rows
        ts_fields = ('ts', 'event_ts', 'valid_time_start', 'timestamp', 'time', 'createdDateTime')
        for row in (report.get('rows') or []):
            if not isinstance(row, dict):
                continue
            sev = str(row.get('severity') or '').lower()
            if sev not in ('critical', 'high', 'medium'):
                continue
            ts = None
            for f in ts_fields:
                v = row.get(f)
                if v:
                    try:
                        ts = float(v) if isinstance(v, (int, float)) else None
                        if not ts:
                            text = str(v).strip().rstrip('Z') + '+00:00' if str(v).endswith('Z') else str(v)
                            ts = _dt.datetime.fromisoformat(text).timestamp()
                    except Exception:
                        pass
                if ts:
                    break
            entry: Dict[str, Any] = {
                'event': str(row.get('llm_summary') or '')[:120],
                'severity': sev,
                'verdict': row.get('verdict'),
                'factors': row.get('factors') or [],
                'mitre': row.get('mitre_techniques') or [],
            }
            if ts:
                entry['valid_time'] = _dt.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%dT%H:%M:%SZ')
            # transaction_time will be populated when bitemporal columns are added
            entry['transaction_time'] = row.get('transaction_time') or 'PENDING — bitemporal not yet enabled'
            timeline.append(entry)
    return timeline


def _forensic_checklist(bad_rows: List[Dict[str, Any]], mitre_tags: List[str]) -> list[str]:
    checklist = ["Preserve volatile host evidence (RAM, running processes) BEFORE any containment action."]
    if 'T1003' in mitre_tags or any('credential' in str(r.get('factors') or []).lower() for r in bad_rows):
        checklist.append("PRIORITY: Collect LSASS dump / credential store artefacts before they are overwritten.")
    if any('executable_file' in (r.get('factors') or []) for r in bad_rows):
        checklist.append("Collect all executables from temp/user paths; compute SHA256 hashes before quarantine.")
    if any('c2_port' in (r.get('factors') or []) or 'external_connection' in (r.get('factors') or []) for r in bad_rows):
        checklist.append("Capture live network connections (netstat -anob) and PCAP for all external destinations.")
    if 'T1047' in mitre_tags or any('lateral' in str(r.get('factors') or []).lower() for r in bad_rows):
        checklist.append("Collect WMI event subscriptions and scheduled task definitions before system reboot.")
    checklist.append("Validate execution ancestry (parent → child process chain) for all suspicious executables.")
    checklist.append("Capture relevant authentication and endpoint telemetry for the full incident window.")
    checklist.append("Hash all collected artefacts (SHA256) and record chain-of-custody before submission.")
    return checklist


def _mssp_client_summary(report: Dict[str, Any]) -> str:
    rq = report.get('risk_quantification') or {}
    severity = rq.get('severity', 'LOW')
    counts = rq.get('row_counts') or {}
    n_mal = counts.get('malicious', 0)
    n_sus = counts.get('suspicious', 0)
    if n_mal:
        return f"ALERT: {n_mal} confirmed malicious event{'s' if n_mal != 1 else ''} detected in tenant. Severity: {severity}. Immediate response required."
    if n_sus:
        return f"NOTICE: {n_sus} suspicious event{'s' if n_sus != 1 else ''} flagged for investigation. Severity: {severity}. Review within SLA window."
    return f"Assessment complete. No confirmed threats. Severity: {severity}. Standard monitoring continues."


def _sla_status(report: Dict[str, Any]) -> Dict[str, Any]:
    import time as _time
    rq = report.get('risk_quantification') or {}
    severity = rq.get('severity', 'LOW')
    target_minutes = {'CRITICAL': 15, 'HIGH': 30, 'MEDIUM': 60, 'LOW': 240}.get(severity, 15)
    created = report.get('created') or report.get('telemetry', {}).get('queued_at') or _time.time()
    elapsed_minutes = round((_time.time() - float(created)) / 60, 1)
    remaining = target_minutes - elapsed_minutes
    return {
        'target_minutes': target_minutes,
        'elapsed_minutes': elapsed_minutes,
        'remaining_minutes': max(0.0, round(remaining, 1)),
        'status': 'BREACHED' if remaining < 0 else ('AT_RISK' if remaining < target_minutes * 0.2 else 'WITHIN_TARGET'),
        'severity_tier': severity,
    }


def _factor_analysis_from_rows(report: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Build factor analysis from row-level factors for threat hunter."""
    from collections import Counter
    factor_counts: Counter = Counter()
    factor_max_dread: Dict[str, float] = {}
    for row in (report.get('rows') or []):
        if not isinstance(row, dict):
            continue
        dread = float(row.get('dread_score') or 0)
        for f in (row.get('factors') or []):
            fs = str(f)
            factor_counts[fs] += 1
            if dread > factor_max_dread.get(fs, 0):
                factor_max_dread[fs] = dread
    result = []
    for factor, count in factor_counts.most_common(10):
        result.append({
            'factor_name': factor,
            'occurrence_count': count,
            'max_dread_in_rows': round(factor_max_dread.get(factor, 0), 3),
        })
    # Also merge verdict-level factors
    verdict = report.get('verdict') or {}
    for entry in (verdict.get('all_factors') or verdict.get('top_contributing_factors') or []):
        if isinstance(entry, dict):
            n = entry.get('factor_name') or entry.get('factor') or entry.get('name')
            if n and not any(r['factor_name'] == str(n) for r in result):
                result.append({'factor_name': str(n), 'contribution_score': entry.get('contribution_score', 0), 'source': 'verdict'})
    return result[:15]


def _statistical(report: Dict[str, Any]) -> Dict[str, Any]:
    v = report.get("verdict", {})
    return {
        "prior": v.get("bayesian_prior"),
        "posterior": v.get("bayesian_posterior"),
        "likelihood_ratio": v.get("likelihood_ratio"),
    }


def _triage_focus(report: Dict[str, Any]) -> list[str]:
    findings = report.get("findings") or []
    focus: list[str] = []
    for finding in findings[:5]:
        title = finding.get("title")
        if title:
            focus.append(str(title))
    return focus


def _corroboration_targets(report: Dict[str, Any]) -> list[str]:
    verdict = report.get("verdict") or {}
    prioritized = (verdict.get("semantic_top_factors") or verdict.get("top_contributing_factors") or [])
    factors = [str(entry.get("factor_name") or entry) if isinstance(entry, dict) else str(entry) for entry in prioritized]
    targets: list[str] = []
    if any("email:" in factor for factor in factors):
        targets.append("Pull mailbox delivery traces, URL click telemetry, and attachment detonation evidence.")
    if any("endpoint:" in factor for factor in factors):
        targets.append("Collect process lineage, signed binary metadata, persistence artifacts, and memory snapshots.")
    if any("network:" in factor for factor in factors):
        targets.append("Review DNS, proxy, firewall, and east-west flow telemetry for corroborating pivots.")
    if any("identity:" in factor for factor in factors):
        targets.append("Pull Entra sign-in, Conditional Access, and Identity Protection events for the implicated principals.")
    if any("cloud:" in factor for factor in factors):
        targets.append("Corroborate with control-plane activity, Defender or GuardDuty findings, and target-resource access logs.")
    if any("corr:" in factor for factor in factors):
        targets.append("Pivot across identity, endpoint, and network timelines to validate the multi-stage chain.")
    return targets


# ---------------------------------------------------------------------------
# Kill-chain and Sigma helpers for the Threat Hunter persona
# ---------------------------------------------------------------------------

# MITRE ATT&CK technique → Lockheed Martin Kill Chain phase mapping (subset)
_TECHNIQUE_KILL_CHAIN: Dict[str, str] = {
    # Reconnaissance / Weaponization
    'T1595': 'Reconnaissance',
    'T1592': 'Reconnaissance',
    'T1589': 'Reconnaissance',
    'T1598': 'Reconnaissance',
    # Initial Access
    'T1078': 'Initial Access',
    'T1190': 'Initial Access',
    'T1566': 'Delivery',
    'T1133': 'Initial Access',
    'T1091': 'Delivery',
    # Execution
    'T1059': 'Execution',
    'T1204': 'Execution',
    'T1047': 'Execution',
    'T1053': 'Execution',
    # Persistence
    'T1547': 'Installation',
    'T1543': 'Installation',
    'T1136': 'Installation',
    # Privilege Escalation
    'T1548': 'Exploitation',
    'T1134': 'Exploitation',
    # Defense Evasion
    'T1027': 'Exploitation',
    'T1055': 'Exploitation',
    'T1218': 'Exploitation',
    # Credential Access
    'T1003': 'Exploitation',
    'T1110': 'Exploitation',
    'T1552': 'Exploitation',
    # Discovery
    'T1083': 'Actions on Objectives',
    'T1057': 'Actions on Objectives',
    'T1082': 'Actions on Objectives',
    # Lateral Movement
    'T1021': 'Lateral Movement',
    'T1550': 'Lateral Movement',
    # Collection
    'T1005': 'Actions on Objectives',
    'T1114': 'Actions on Objectives',
    # Command and Control
    'T1071': 'Command & Control',
    'T1095': 'Command & Control',
    'T1572': 'Command & Control',
    # Exfiltration
    'T1041': 'Actions on Objectives',
    'T1048': 'Actions on Objectives',
    # Impact
    'T1486': 'Actions on Objectives',
    'T1490': 'Actions on Objectives',
}

# Factor keyword → Sigma detection stubs
_FACTOR_SIGMA_TEMPLATES: Dict[str, Dict[str, Any]] = {
    'temp_execution': {
        'title': 'Suspicious Execution from Temp Directory',
        'status': 'experimental',
        'description': 'Detects process execution from user or system temp paths.',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection': {'Image|contains': ['\\AppData\\Local\\Temp\\', '\\Windows\\Temp\\']},
            'condition': 'selection',
        },
        'level': 'medium',
    },
    'lolbin': {
        'title': 'Living-off-the-Land Binary Abuse',
        'status': 'experimental',
        'description': 'Detects known LOLBAS programs used for proxy execution.',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection': {'Image|endswith': ['\\mshta.exe', '\\certutil.exe', '\\wscript.exe', '\\cscript.exe', '\\regsvr32.exe', '\\rundll32.exe']},
            'condition': 'selection',
        },
        'level': 'high',
    },
    'network_beacon': {
        'title': 'Periodic Outbound C2 Beacon Pattern',
        'status': 'experimental',
        'description': 'Detects anomalous periodic outbound connections that match C2 beacon timing.',
        'logsource': {'category': 'network_connection', 'product': 'zeek'},
        'detection': {
            'selection': {'resp_bytes': '0', 'duration|gt': 60},
            'condition': 'selection',
        },
        'level': 'high',
    },
    'credential_access': {
        'title': 'Credential Dumping via LSASS',
        'status': 'experimental',
        'description': 'Detects access to LSASS process memory consistent with credential harvesting.',
        'logsource': {'category': 'process_access', 'product': 'windows'},
        'detection': {
            'selection': {'TargetImage|endswith': '\\lsass.exe', 'GrantedAccess': ['0x1010', '0x1410', '0x1FFFFF']},
            'condition': 'selection',
        },
        'level': 'critical',
    },
    'identity:signin_anomaly': {
        'title': 'Anomalous Sign-in Pattern',
        'status': 'experimental',
        'description': 'Detects sign-ins from unusual geography, impossible travel, or after hours.',
        'logsource': {'service': 'azure_ad', 'product': 'azure'},
        'detection': {
            'selection': {'ResultType': '0', 'RiskLevelDuringSignIn': ['high', 'medium']},
            'condition': 'selection',
        },
        'level': 'high',
    },
    'cloud:privilege_escalation': {
        'title': 'Cloud IAM Privilege Escalation',
        'status': 'experimental',
        'description': 'Detects IAM role assumption or policy attachment in cloud environments.',
        'logsource': {'service': 'cloudtrail', 'product': 'aws'},
        'detection': {
            'selection': {'eventName': ['AssumeRole', 'AttachUserPolicy', 'AttachRolePolicy', 'CreateAccessKey']},
            'condition': 'selection',
        },
        'level': 'high',
    },
}


def _derive_kill_chain_stages(report: Dict[str, Any]) -> list[str]:
    """Map MITRE technique IDs from report to Lockheed Martin Kill Chain stages."""
    return _derive_kill_chain_stages_from_tags(_normalise_mitre_tags(report))


def _derive_kill_chain_stages_from_tags(mitre_tags: List[str]) -> list[str]:
    """Map pre-normalised MITRE technique IDs to Kill Chain stages."""
    stages: list[str] = []
    seen: set[str] = set()
    for tag in mitre_tags:
        stage = _TECHNIQUE_KILL_CHAIN.get(tag)
        if stage and stage not in seen:
            stages.append(stage)
            seen.add(stage)
    return stages


def _generate_sigma_stubs(report: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Return Sigma detection rule stubs matching the active factors and patterns."""
    factors: list[str] = []
    verdict = report.get('verdict') or {}
    for entry in (verdict.get('all_factors') or verdict.get('top_contributing_factors') or []):
        if isinstance(entry, dict):
            n = entry.get('factor_name') or entry.get('factor') or entry.get('name')
            if n:
                factors.append(str(n))
        elif isinstance(entry, str):
            factors.append(entry)
    for row in (report.get('rows') or []):
        row_factors = row.get('factors') or []
        factors.extend(str(f) for f in row_factors)
        # Derive factor hints from mitre_techniques strings
        for t in (row.get('mitre_techniques') or []):
            ts = str(t).lower()
            if 'lsass' in ts or 'credential' in ts or 'T1003' in t:
                factors.append('credential_access')
            if 'temp' in ts or 'T1059' in t or 'execution' in ts:
                factors.append('temp_execution')
            if 'c2' in ts or 'T1071' in t or 'command' in ts:
                factors.append('network_beacon')

    rules: list[Dict[str, Any]] = []
    seen_titles: set[str] = set()
    for factor in factors:
        fl = factor.lower()
        for key, stub in _FACTOR_SIGMA_TEMPLATES.items():
            if key in fl or fl in key:
                t = stub['title']
                if t not in seen_titles:
                    seen_titles.add(t)
                    rules.append({'sigma_stub': stub, 'matched_factor': factor})
        if len(rules) >= 4:
            break
    return rules
