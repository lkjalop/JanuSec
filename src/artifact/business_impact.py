from __future__ import annotations

import math
import time
from typing import Any, Dict, List

RISK_HIGH_THRESHOLD = 0.55  # align with SUSPICIOUS boundary
RISK_CRITICAL_THRESHOLD = 0.75

def generate_business_summary(report: dict[str,Any]) -> dict[str,Any]:
    """Produce an executive/business impact summary from a single artifact report.
    Logic:
      - If no suspicious/malicious artifacts -> low/no immediate risk message.
      - Else compute concentration (top10 risk share), emergent technique count (technique present in mitre_delta with delta>0),
        exposure surface (artifact_type distribution among risky ones), and rough blast radius (multi-host & propagation factors).
    Always ends with a disclaimer deferring to SOC.
    """
    if not report:
        return {'summary': 'Report unavailable', 'risk_level': 'unknown'}
    verdict_totals = report.get('verdict_totals',{})
    susp = int(verdict_totals.get('SUSPICIOUS',0))
    mal = int(verdict_totals.get('MALICIOUS',0))
    pua = int(verdict_totals.get('PUA',0))
    risky_total = susp + mal + pua
    if risky_total == 0:
        return {
            'risk_level': 'low',
            'summary': 'No suspicious or malicious artifacts detected in this batch; no immediate business impact indicated. Continue routine monitoring.',
            'details': {'risky_total': 0},
            'disclaimer': _disclaimer()
        }
    top_risky = report.get('top_risky', [])
    # High-risk concentration share
    top10 = top_risky[:10]
    total_risk_sum = sum(a.get('risk',0) for a in top_risky)
    top10_share = (sum(a.get('risk',0) for a in top10)/total_risk_sum) if total_risk_sum else 0.0
    emergent_techs = [d['technique'] for d in report.get('mitre_delta',[]) if d.get('delta',0)>0][:10]
    emergent_count = len(emergent_techs)
    # Exposure surfaces: count artifact types among risky list
    exposure = {}
    for a in top_risky:
        v = a.get('verdict'); a.get('risk',0)
        if v in ('SUSPICIOUS','MALICIOUS','PUA'):
            t = a.get('type','unknown')
            exposure[t] = exposure.get(t,0)+1
    # Blast radius heuristic: rapid multi-host or emerging flags
    propagation_cases = [a for a in top_risky if a.get('graph',{}).get('rapid_multi_host_appearance')]
    blast_radius_flag = bool(propagation_cases)
    max_risk = max((a.get('risk',0) for a in top_risky), default=0.0)
    risk_level = 'moderate'
    if max_risk >= RISK_CRITICAL_THRESHOLD or mal > 0:
        risk_level = 'elevated'
    if blast_radius_flag and mal > 0:
        risk_level = 'high'
    narrative_parts = []
    narrative_parts.append(f"Identified {risky_total} higher-risk artifacts (PUA/SUSPICIOUS/MALICIOUS) including {mal} malicious and {susp} suspicious.")
    if emergent_count:
        narrative_parts.append(f"Observed {emergent_count} emergent MITRE techniques: {', '.join(emergent_techs)}.")
    if blast_radius_flag:
        narrative_parts.append(f"Propagation indicators present in {len(propagation_cases)} artifacts across hosts (potential lateral or rapid deployment pattern).")
    if top10_share and top10_share > 0.65:
        narrative_parts.append("Risk concentration high: top 10 artifacts comprise over 65% of observed risk weighting -> prioritized triage can reduce majority exposure.")
    exposure_str = ", ".join(f"{k}:{v}" for k,v in sorted(exposure.items(), key=lambda x:-x[1])) or 'mixed'
    narrative_parts.append(f"Exposure surface (artifact types among risky set): {exposure_str}.")
    narrative_parts.append("No automatic containment performed; human SOC validation required before enforcement changes.")
    summary_text = " ".join(narrative_parts)
    return {
        'risk_level': risk_level,
        'summary': summary_text,
        'emergent_techniques': emergent_techs,
        'blast_radius_flag': blast_radius_flag,
        'exposure': exposure,
        'metrics': {
            'risky_total': risky_total,
            'malicious': mal,
            'suspicious': susp,
            'top10_risk_share': round(top10_share,3),
            'emergent_technique_count': emergent_count
        },
        'disclaimer': _disclaimer()
    }

def _disclaimer():
    return ("Automated analytical inference only. This platform surfaces potential impact; final adjudication, response, and enforcement decisions remain the responsibility of the human SOC team.")
