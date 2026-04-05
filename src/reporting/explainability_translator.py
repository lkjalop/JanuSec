from typing import Dict, Any, Optional
from .schemas import FactorContribution, ExplainabilityLevel


def translate_factor_for_persona(factor: FactorContribution, level: ExplainabilityLevel) -> Dict[str, Any]:
    """Produce persona-aware explanation fields for a factor."""
    try:
        if level == ExplainabilityLevel.MINIMAL:
            hr = factor.human_readable_explanation or (factor.reasoning.split('.')[0] if factor.reasoning else '')
            analogy = factor.analogy or None
        elif level == ExplainabilityLevel.SUMMARY:
            hr = factor.human_readable_explanation or f"{factor.reasoning}"
            analogy = factor.analogy or None
        else:
            hr = factor.reasoning
            analogy = factor.analogy or None
        return {"human_readable_explanation": hr, "analogy": analogy}
    except Exception:
        return {"human_readable_explanation": None, "analogy": None}


def enrich_report_explainability(report: Dict[str, Any], level: ExplainabilityLevel = ExplainabilityLevel.SUMMARY) -> Dict[str, Any]:
    """Walk factor contributions and attach translations."""
    try:
        factors = report.get('verdict', {}).get('all_factors', [])
        enriched = []
        for f in factors:
            if isinstance(f, FactorContribution):
                tf = translate_factor_for_persona(f, level)
                enriched.append({**f.dict(), **tf})
            elif isinstance(f, dict):
                # best-effort: map keys
                name = f.get('factor_name')
                reasoning = f.get('reasoning')
                human = f.get('human_readable_explanation') or (reasoning.split('.')[0] if reasoning else None)
                enriched.append({**f, 'human_readable_explanation': human, 'analogy': f.get('analogy')})
            else:
                enriched.append(f)
        report.setdefault('verdict', {})['all_factors_enriched'] = enriched
    except Exception:
        pass
    return report
from typing import Dict, Any, Optional
from .schemas import FactorContribution, ExplainabilityLevel


def translate_factor(fc: FactorContribution, level: ExplainabilityLevel) -> Dict[str, Any]:
    """Return a persona-appropriate translation for a FactorContribution."""
    if level == ExplainabilityLevel.MINIMAL:
        return {"short": fc.human_readable_explanation or (fc.reasoning.split('.')[0] if fc.reasoning else ''), "analogy": fc.analogy}
    if level == ExplainabilityLevel.SUMMARY:
        return {"summary": fc.human_readable_explanation or fc.reasoning, "confidence": fc.contribution_score}
    # detailed
    return {"detail": fc.get_explanation(level), "mitre": fc.mitre_techniques}


def generate_human_readable(factors: list[FactorContribution], level: ExplainabilityLevel) -> Dict[str, Any]:
    out = {}
    for fc in factors:
        out[fc.factor_name] = translate_factor(fc, level)
    return out
