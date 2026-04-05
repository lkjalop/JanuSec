"""Simple playbook mapping: convert parsed persona actions into concrete steps.

This is intentionally minimal: it returns a list of actionable steps with types
so DecisionGate / UI wiring can attach automation later.
"""
from typing import List, Dict, Any
import re
try:
    from src.reporting.llm_helper import cached_generate
except Exception:
    cached_generate = None

PLAYBOOKS = {
    'isolate_host': {
        'title': 'Isolate Host from Network',
        'steps': [
            {'type': 'api', 'action': 'block_ip', 'args': ['host_ip'], 'desc': 'Apply network ACL to block host IP'},
            {'type': 'collect', 'action': 'gather_process_tree', 'args': ['event_id'], 'desc': 'Collect process tree snapshot from EDR'},
        ]
    },
    'collect_artifact': {
        'title': 'Collect Forensic Artifact',
        'steps': [
            {'type': 'collect', 'action': 'fetch_file', 'args': ['file_hash'], 'desc': 'Fetch file artifact by hash'},
            {'type': 'collect', 'action': 'fetch_windows_event', 'args': ['event_id'], 'desc': 'Fetch related Windows event logs'},
        ]
    },
    'block_ip': {
        'title': 'Block IP Address',
        'steps': [
            {'type': 'api', 'action': 'block_ip', 'args': ['ip'], 'desc': 'Add IP to blocklist'}
        ]
    }
}


def map_actions_to_playbook(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Map parsed persona actions into a list of playbook steps.

    Simple heuristics: look for keywords to select a playbook and fill args.
    """
    out: List[Dict[str, Any]] = []
    actions = parsed.get('actions') or []
    evidence = parsed.get('evidence_refs') or []
    for a in actions:
        desc = (a.get('desc') or '').lower()
        # quick heuristics for IOC types
        sha_re = re.compile(r"\b[0-9a-f]{64}\b")
        ip_re = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        domain_re = re.compile(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b")
        if sha_re.search(desc):
            pb = PLAYBOOKS['collect_artifact'].copy()
            out.append({'playbook': 'collect_artifact', 'title': pb['title'], 'steps': pb['steps'], 'urgency': a.get('urgency', 'normal')})
            continue
        if ip_re.search(desc):
            pb = PLAYBOOKS['block_ip'].copy()
            out.append({'playbook': 'block_ip', 'title': pb['title'], 'steps': pb['steps'], 'urgency': a.get('urgency', 'normal')})
            continue
        if domain_re.search(desc):
            pb = PLAYBOOKS['isolate_host'].copy()
            out.append({'playbook': 'isolate_host', 'title': pb['title'], 'steps': pb['steps'], 'urgency': a.get('urgency', 'normal')})
            continue
        if 'isolate' in desc or 'quarantine' in desc or 'disconnect' in desc:
            pb = PLAYBOOKS['isolate_host'].copy()
            # fill placeholders
            for step in pb['steps']:
                step = step
            out.append({'playbook': 'isolate_host', 'title': pb['title'], 'steps': pb['steps'], 'urgency': a.get('urgency', 'normal')})
        elif 'fetch' in desc or 'collect' in desc or 'artifact' in desc or 'sha256' in desc:
            pb = PLAYBOOKS['collect_artifact'].copy()
            out.append({'playbook': 'collect_artifact', 'title': pb['title'], 'steps': pb['steps'], 'urgency': a.get('urgency', 'normal')})
        elif 'block ip' in desc or 'block' in desc and any('.' in x for x in evidence):
            pb = PLAYBOOKS['block_ip'].copy()
            out.append({'playbook': 'block_ip', 'title': pb['title'], 'steps': pb['steps'], 'urgency': a.get('urgency', 'normal')})
        else:
            # fallback: convert desc into a single manual step
            out.append({'playbook': 'manual', 'title': 'Manual Action', 'steps': [{'type': 'manual', 'action': 'review', 'args': [], 'desc': a.get('desc')}], 'urgency': a.get('urgency', 'normal')})
    return out


def map_actions_via_llm(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Use LLM to map free-text actions to playbooks when heuristics fail.

    This is a fallback that ensures richer mapping when available. Returns [] when no LLM.
    """
    if cached_generate is None:
        return []
    try:
        prompt = f"Map the following analyst actions to one of these playbooks: {list(PLAYBOOKS.keys())}. Actions: {parsed.get('actions')}"
        resp = cached_generate({'prompt': prompt, 'max_tokens': 200})
        text = resp.get('text') if isinstance(resp, dict) else str(resp)
        # simple parser: look for playbook names in response
        result = []
        for pb_name in PLAYBOOKS.keys():
            if pb_name in (text or '').lower():
                pb = PLAYBOOKS[pb_name].copy()
                result.append({'playbook': pb_name, 'title': pb['title'], 'steps': pb['steps'], 'urgency': 'normal'})
        return result
    except Exception:
        return []
