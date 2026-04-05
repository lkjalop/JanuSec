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
    n_suspicious = sum(1 for r in rows if float(r.get('confidence', 0) or 0) > 0.5)
    if not n_suspicious:
        # Fall back to verdict confidence when rows don't carry per-row confidence
        vc = float((report.get('verdict') or {}).get('final_confidence') or 0)
        n_suspicious = 1 if vc > 0.5 else 0

    verdict_sev = ((report.get('verdict') or {}).get('final_verdict') or '').upper()
    if verdict_sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        severity = verdict_sev
    elif n_suspicious > 5:
        severity = 'CRITICAL'
    elif n_suspicious > 2:
        severity = 'HIGH'
    elif n_suspicious > 0:
        severity = 'MEDIUM'
    else:
        severity = 'LOW'

    try:
        from src.analysis.offline_workbook_assessment import _estimate_expected_loss
        expected = _estimate_expected_loss(severity, max(1, n_rows), n_suspicious, 0)
    except Exception:
        expected = {'LOW': 2500, 'MEDIUM': 12000, 'HIGH': 35000, 'CRITICAL': 90000}.get(severity, 2500)

    report['risk_quantification'] = rq | {
        'severity': severity,
        'likelihood_percent': round(min(85, 20 + n_suspicious * 15), 1),
        'expected_loss_usd': expected,
        'impact_range_usd': [expected, expected * 3],
        'damage_potential': min(10, 2 + len([f for f in factors if 'endpoint:' in str(f)])),
        'evidence_based': bool(n_suspicious),
        '_synthesized': True,
    }


def generate_persona_view(report: Dict[str, Any], persona: str, disclosure_level: int = 2, top_n: int = 10) -> Dict[str, Any]:
    """Generate a persona-specific view with summary signals and decision gates.

    Persona: 'executive' | 'soc_analyst' | 'compliance' | 'threat_hunter' | 'mssp' | 'forensics'
    """
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

    # Persona-specific additions
    p = persona.lower()
    if p == "executive":
        base["headline"] = _one_liner(report)
        base["business_impact"] = _business_impact(report)
        base["operational_next_step"] = _operational_next_step(report)
        base["control_posture"] = _control_posture(report)
        # Include tier metadata when available
        base['tier_metadata'] = report.get('tier_metadata', {})
    elif p == "soc_analyst":
        base["timeline"] = report.get("attack_timeline", [])
        base["iocs"] = base["summary_signals"]["iocs"]
        base["triage_focus"] = _triage_focus(report)
        base["corroboration_targets"] = _corroboration_targets(report)
    elif p == "compliance":
        base["audit_trail"] = _audit_trail(report)
        base["framework_mappings"] = report.get("framework_mappings", [])
        base["control_posture"] = _control_posture(report)
        base["regulatory_control_ids"] = _map_to_regulatory_controls(report)
    elif p == "threat_hunter":
        base["factor_analysis"] = report.get("verdict", {}).get("all_factors", [])
        base["statistical"] = _statistical(report)
        base["corroboration_targets"] = _corroboration_targets(report)
        base["kill_chain_stages"] = _derive_kill_chain_stages(report)
        base["sigma_rules"] = _generate_sigma_stubs(report)
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
    verdict = report.get("verdict", {})
    rq = report.get("risk_quantification", {})
    impact = report.get("impact_metadata", {})
    identities = len(impact.get("affected_identities") or [])
    hosts = len(impact.get("affected_hosts") or [])
    scope = []
    if identities:
        scope.append(f"{identities} identity{'ies' if identities != 1 else ''}")
    if hosts:
        scope.append(f"{hosts} host{'s' if hosts != 1 else ''}")
    scope_text = f"; scope {', '.join(scope)}" if scope else ""
    return (
        f"{verdict.get('final_verdict', 'REVIEW')} at {verdict.get('final_confidence', 0.0):.0%} "
        f"(severity {rq.get('severity', 'LOW')}{scope_text})"
    )


def _business_impact(report: Dict[str, Any]) -> Dict[str, Any]:
    rq = report.get("risk_quantification", {})
    impact: Dict[str, Any] = {
        "estimated_loss_range": rq.get("impact_range_usd"),
        "likelihood": rq.get("likelihood_percent"),
        "expected_loss": rq.get("expected_loss_usd"),
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
    },
    'T1110': {
        'SOC2': ['CC6.1', 'CC6.6'],
        'GDPR': ['Art. 32(1)(a)', 'Art. 32(1)(b)'],
        'PCI_DSS': ['8.3', '8.3.6', '10.2.4'],
    },
    'T1566': {
        'SOC2': ['CC6.7', 'CC6.8'],
        'GDPR': ['Art. 32(1)(b)'],
        'PCI_DSS': ['5.4', '12.6'],
    },
    'T1003': {
        'SOC2': ['CC6.1', 'CC6.6'],
        'GDPR': ['Art. 32(1)(b)', 'Art. 33'],
        'PCI_DSS': ['8.2', '10.2.5'],
    },
    'T1059': {
        'SOC2': ['CC6.8'],
        'GDPR': ['Art. 32(1)(b)'],
        'PCI_DSS': ['6.3', '10.2.2'],
    },
    'T1047': {
        'SOC2': ['CC6.8', 'CC7.2'],
        'GDPR': ['Art. 32(1)(d)'],
        'PCI_DSS': ['6.3', '10.2.2'],
    },
    'T1486': {
        'SOC2': ['A1.2', 'CC9.1'],
        'GDPR': ['Art. 32(1)(c)', 'Art. 33', 'Art. 34'],
        'PCI_DSS': ['12.10', '3.4'],
    },
    'T1048': {
        'SOC2': ['CC6.7', 'CC7.3'],
        'GDPR': ['Art. 32(1)(b)', 'Art. 33'],
        'PCI_DSS': ['4.2', '10.3'],
    },
    'T1071': {
        'SOC2': ['CC6.6', 'CC7.2'],
        'GDPR': ['Art. 32(1)(d)'],
        'PCI_DSS': ['1.3', '10.2.7'],
    },
    'T1190': {
        'SOC2': ['CC7.1', 'CC7.2'],
        'GDPR': ['Art. 32(1)(b)', 'Art. 33'],
        'PCI_DSS': ['6.3.3', '11.3'],
    },
    'T1021': {
        'SOC2': ['CC6.1', 'CC6.3'],
        'GDPR': ['Art. 32(1)(b)'],
        'PCI_DSS': ['7.2', '8.2', '10.2.3'],
    },
    'T1552': {
        'SOC2': ['CC6.1', 'CC6.7'],
        'GDPR': ['Art. 32(1)(a)'],
        'PCI_DSS': ['8.3', '6.5'],
    },
    'T1027': {
        'SOC2': ['CC7.1', 'CC7.2'],
        'GDPR': ['Art. 32(1)(d)'],
        'PCI_DSS': ['5.2', '10.2.7'],
    },
}


def _map_to_regulatory_controls(report: Dict[str, Any]) -> Dict[str, Any]:
    """Return a mapping of regulatory control IDs relevant to the detected techniques.

    Returns a dict keyed by framework ('SOC2', 'GDPR', 'PCI_DSS') with deduplicated
    control IDs.  Also includes a brief human-readable rationale per framework.
    """
    # Collect MITRE technique tags from multiple sources
    mitre_tags: set[str] = set()
    verdict = report.get('verdict') or {}
    for tag in (verdict.get('mitre_tags') or []):
        mitre_tags.add(str(tag).split('.')[0].upper())
    for row in (report.get('rows') or []):
        for tag in (row.get('mitre_tags') or row.get('mitre') or []):
            mitre_tags.add(str(tag).split('.')[0].upper())
    for finding in (report.get('findings') or []):
        for tag in (finding.get('mitre') or []):
            mitre_tags.add(str(tag).split('.')[0].upper())
    # Also look in framework_mappings if already present
    for fm in (report.get('framework_mappings') or []):
        if isinstance(fm, dict):
            tech = str(fm.get('technique') or fm.get('technique_id') or '').split('.')[0].upper()
            if tech:
                mitre_tags.add(tech)

    soc2: set[str] = set()
    gdpr: set[str] = set()
    pci: set[str] = set()
    matched_techniques: list[str] = []

    for tag in mitre_tags:
        ctl = _TECHNIQUE_CONTROL_MAP.get(tag)
        if ctl:
            matched_techniques.append(tag)
            soc2.update(ctl.get('SOC2') or [])
            gdpr.update(ctl.get('GDPR') or [])
            pci.update(ctl.get('PCI_DSS') or [])

    # Always include baseline controls when any technique is matched
    if matched_techniques:
        soc2.update(['CC6.1'])
        pci.update(['10.1'])

    return {
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
    """Map MITRE technique IDs from verdict/rows to Lockheed Martin Kill Chain stages."""
    mitre_tags: list[str] = []
    verdict = report.get('verdict') or {}
    # Collect from verdict
    mitre_tags.extend(verdict.get('mitre_tags') or [])
    # Collect from individual rows
    for row in (report.get('rows') or []):
        mitre_tags.extend(row.get('mitre_tags') or row.get('mitre') or [])
    # Also look in findings
    for f in (report.get('findings') or []):
        mitre_tags.extend(f.get('mitre') or [])

    stages: list[str] = []
    seen: set[str] = set()
    for tag in mitre_tags:
        # Normalize: strip subtechnique suffix (T1059.001 → T1059)
        base = str(tag).split('.')[0].upper()
        stage = _TECHNIQUE_KILL_CHAIN.get(base)
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
        factors.extend(str(f) for f in (row.get('factors') or []))

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
