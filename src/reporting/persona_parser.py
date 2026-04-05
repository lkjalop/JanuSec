from typing import Dict, Any, List, Tuple
import json
import re
import ast


def validate_parsed_persona(parsed: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate parsed persona output for minimal required fields.

    Returns (valid, errors)
    """
    errs: List[str] = []
    if not parsed.get('summary') or not isinstance(parsed.get('summary'), str) or not parsed.get('summary').strip():
        errs.append('missing_summary')
    acts = parsed.get('actions') or []
    if not isinstance(acts, list) or len(acts) == 0:
        errs.append('no_actions')
    else:
        for i, a in enumerate(acts):
            if not isinstance(a, dict) or not a.get('desc'):
                errs.append(f'action_{i}_invalid')
    return (len(errs) == 0, errs)

def _extract_json_from_text(text: str) -> Dict[str, Any] | None:
    try:
        # try direct JSON
        return json.loads(text)
    except Exception:
        # try to find a JSON object inside
        try:
            start = text.find('{')
            end = text.rfind('}')
            if start != -1 and end != -1 and end > start:
                substr = text[start:end+1]
                try:
                    return json.loads(substr)
                except Exception:
                    # Try Python literal eval for single-quoted dicts
                    try:
                        obj = ast.literal_eval(substr)
                        if isinstance(obj, dict):
                            return obj
                    except Exception:
                        return None
        except Exception:
            return None
    return None


def _repair_json_like(text: str) -> str | None:
    """Attempt basic repairs on common LLM JSON mistakes and return a repaired string or None."""
    try:
        s = text.strip()
        # extract likely JSON substring
        start = s.find('{')
        end = s.rfind('}')
        if start == -1 or end == -1 or end <= start:
            return None
        s = s[start:end+1]
        # remove trailing commas before closing braces/brackets
        s = s.replace(',}', '}').replace(',]', ']')
        # replace single quotes with double where safe (heuristic)
        s = re.sub(r"(?<=[:\[,\s])'([^']*)'(?=[,}\]])", r'"\1"', s)
        # ensure keys are double-quoted
        s = re.sub(r'([\{,\s])(\w+)\s*:', r'\1"\2":', s)
        return s
    except Exception:
        return None


def parse_persona_text(text: str) -> Dict[str, Any]:
    """Parse persona LLM output into a minimal structured schema.

    Returns: {summary: str, actions: [{desc, urgency}], evidence_refs: [str]}
    """
    out: Dict[str, Any] = {'summary': '', 'actions': [], 'evidence_refs': [], 'confidence': 0.0, 'parsed_from_json': False}
    if not text:
        return out
    # Attempt JSON extraction first
    j = _extract_json_from_text(text)
    # If initial extraction failed, try repair heuristics
    if j is None:
        repaired = _repair_json_like(text)
        if repaired:
            try:
                j = json.loads(repaired)
            except Exception:
                # aggressive fallback: replace single quotes with double quotes and try
                try:
                    j = json.loads(repaired.replace("'", '"'))
                except Exception:
                    j = None
    if isinstance(j, dict):
        # best-effort mapping
        out['parsed_from_json'] = True
        out['summary'] = j.get('summary') or j.get('one_line_recommendation') or j.get('text') or ''
        # actions may be under recommended_action(s)
        actions = []
        if j.get('actions') and isinstance(j.get('actions'), list):
            for a in j.get('actions'):
                if isinstance(a, dict):
                    actions.append({'desc': a.get('desc') or a.get('action') or str(a), 'urgency': a.get('urgency') or 'normal'})
                else:
                    actions.append({'desc': str(a), 'urgency': 'normal'})
        elif j.get('recommended_actions') and isinstance(j.get('recommended_actions'), list):
            for a in j.get('recommended_actions'):
                actions.append({'desc': a, 'urgency': 'normal'})
        out['actions'] = actions
        # collect evidence refs
        if j.get('evidence_refs') and isinstance(j.get('evidence_refs'), list):
            out['evidence_refs'] = [str(x) for x in j.get('evidence_refs')]
        # compute simple confidence heuristic
        conf = 0.0
        conf += 0.4  # JSON structured
        if out['summary']: conf += 0.2
        if out['actions']: conf += 0.2
        if out['evidence_refs']: conf += 0.2
        out['confidence'] = min(1.0, round(conf, 3))
        return out

    # Fallback heuristic parsing: split into lines and find bullets
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if lines:
        # first non-bullet line as summary
        for l in lines:
            if not l.startswith(('-', '*', '•')):
                out['summary'] = l
                break
        # actions: collect bullets
        actions = []
        for l in lines:
            if l.startswith(('-', '*', '•')):
                txt = l.lstrip('-*• ').strip()
                # simple urgency heuristics
                urgency = 'normal'
                if any(tok in txt.lower() for tok in ('immediate', 'now', 'isolate', 'block')):
                    urgency = 'immediate'
                elif any(tok in txt.lower() for tok in ('urgent', 'soon', 'quick')):
                    urgency = 'urgent'
                actions.append({'desc': txt, 'urgency': urgency})
            elif len(l) < 200 and l.endswith('.') and not out['summary']:
                out['summary'] = l
        out['actions'] = actions
        # evidence refs: simple match for evidence ids like evt_ or sha256
        refs: List[str] = []
        for token in text.split():
            t = token.strip(',.()[]"')
            if t.startswith('evt_') or len(t) == 64 and all(c in '0123456789abcdef' for c in t.lower()):
                refs.append(t)
        out['evidence_refs'] = refs
        # confidence heuristic for free-text parsing
        conf = 0.0
        if out['summary']: conf += 0.25
        if len(out['actions']) >= 1: conf += 0.35
        if len(out['evidence_refs']) >= 1: conf += 0.25
        # small boost if we detected SHA-like evidence
        if any(re.fullmatch(r'[0-9a-fA-F]{64}', r) for r in refs):
            conf += 0.15
        out['confidence'] = min(1.0, round(conf, 3))
    return out
