from __future__ import annotations
from typing import List, Dict, Any
from ..canonical_event import CanonicalEvent


class FactorEmit(dict):
    pass


def _has_suspect_tokens(prompt: str | None) -> bool:
    if not isinstance(prompt, str):
        return False
    p = prompt.lower()
    for tok in ("ignore previous", "system prompt", "do anything", "jailbreak", "override policy", "bypass", "disable safety"):
        if tok in p:
            return True
    return False


def extract_ai_factors(events: List[CanonicalEvent]) -> List[FactorEmit]:
    out: List[FactorEmit] = []
    for e in events:
        if e.source_type != 'ai':
            continue
        # prompt_injection
        try:
            if _has_suspect_tokens(e.prompt) or str(e.guardrail or '').lower() in {"blocked", "deny", "rejected"}:
                out.append(FactorEmit(name='prompt_injection', nodes=['ai:prompt'], domain='ai', confidence=0.6, ts=e.timestamp))
        except Exception:
            pass
        # tool_abuse
        try:
            if e.tool:
                # simple policy presence check or suspicious args
                pol = e.raw.get('policy_id') if isinstance(e.raw, dict) else None
                if not pol:
                    out.append(FactorEmit(name='tool_abuse', nodes=[f"tool:{e.tool}"], domain='ai', confidence=0.55, ts=e.timestamp))
                else:
                    args_join = ''
                    ta = e.tool_args
                    if isinstance(ta, dict):
                        args_join = ' '.join([str(v) for v in ta.values()])
                    elif ta is not None:
                        args_join = str(ta)
                    if any(s in args_join.lower() for s in ('rm -rf', 'drop table', 'secrets', 'token=')):
                        out.append(FactorEmit(name='tool_abuse', nodes=[f"tool:{e.tool}"], domain='ai', confidence=0.6, ts=e.timestamp))
        except Exception:
            pass
        # sensitive_output_leak
        try:
            out_text = e.raw.get('output') or e.raw.get('model_output') if isinstance(e.raw, dict) else None
            if isinstance(out_text, str) and any(sig in out_text for sig in ('AKIA', 'BEGIN PRIVATE KEY', 'password=')):
                out.append(FactorEmit(name='sensitive_output_leak', nodes=['ai:output'], domain='ai', confidence=0.65, ts=e.timestamp))
        except Exception:
            pass
        # Optional placeholders derived from tags
        try:
            tags = e.raw.get('threat_tags') if isinstance(e.raw, dict) else None
            if isinstance(tags, list):
                low = [str(t).lower() for t in tags]
                if any('adversarial' in t or 'evasion' in t for t in low):
                    out.append(FactorEmit(name='model_evasion_adversarial', nodes=['ai:model'], domain='ai', confidence=0.5, ts=e.timestamp))
                if any('poison' in t for t in low):
                    out.append(FactorEmit(name='training_data_poisoning', nodes=['ai:dataset'], domain='ai', confidence=0.5, ts=e.timestamp))
        except Exception:
            pass
    return out

__all__ = ["extract_ai_factors"]

