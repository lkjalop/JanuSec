from typing import Any, Dict, List, Tuple
from src.core.rules.schema import load_rule_from_yaml, DetectionRule
from src.core.rules.join_helpers import _get_adj_list
import re
import os
from collections import deque
try:
    import requests
except Exception:
    requests = None
import logging
_log = logging.getLogger(__name__)


def _get_node_field(node: Dict[str, Any], field_path: str):
    """Resolve nested dotted field path from node dict, return None if missing."""
    try:
        parts = field_path.split('.') if isinstance(field_path, str) else [field_path]
        cur = node
        for p in parts:
            if cur is None:
                return None
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return None
        return cur
    except Exception:
        return None


def _match_condition_on_node_dict(node: Dict[str, Any], field: str, op: str, value: Any) -> bool:
    """Evaluate a single condition against a node attribute dictionary."""
    if not isinstance(node, dict):
        return False
    left = _get_node_field(node, field)
    if op == 'eq':
        return left == value
    if op == 'in':
        try:
            return left in value
        except Exception:
            return False
    if op == 'contains':
        # if left is a list, check membership
        if isinstance(left, (list, tuple, set)):
            try:
                return value in left
            except Exception:
                return False
        try:
            return str(value) in ('' if left is None else str(left))
        except Exception:
            return False
    if op == 'regex' or op == 're':
        try:
            pat = str(value)
            txt = '' if left is None else str(left)
            if re.search(pat, txt) is not None:
                return True
            # Fallback: some YAML loaders produce double-escaped backslashes (\\.)
            # try collapsing double-backslashes to single and test again.
            try:
                collapsed = pat.replace('\\\\', '\\')
                return re.search(collapsed, txt) is not None
            except Exception:
                return False
        except Exception:
            return False
    return False


def _eval_conditions(rule: DetectionRule) -> List[Tuple[str, Any, str]]:
    """Return conditions as tuples (field, value, op)."""
    res: List[Tuple[str, Any, str]] = []
    for c in rule.conditions:
        res.append((c.field, c.value, c.op))
    return res


def _match_condition_on_node(node: str, op: str, value: Any) -> bool:
    """Evaluate a single condition against a node id."""
    if op == 'eq':
        return node == value
    if op == 'contains':
        try:
            return str(value) in str(node)
        except Exception:
            return False
    if op == 'regex' or op == 're':
        try:
            return re.search(str(value), str(node)) is not None
        except Exception:
            return False
    return False


def _resolve_join_targets(hg: Any, join: Dict[str, Any], anchor: str | None = None) -> List[str]:
    """Resolve a join mapping by traversing the graph from an anchor node.

    Supports BFS up to `max_hops` and returns collected node ids (excluding anchor).
    """
    adj = _get_adj_list(hg)
    # Allow caller to provide the anchor node (dynamic join resolution)
    if anchor is None:
        anchor = join.get('anchor') or None
        if not anchor:
            mapping = join.get('mapping') or {}
            if isinstance(mapping, dict) and mapping:
                # Pick first mapping value as anchor if provided as node id
                anchor = list(mapping.values())[0]
    if not anchor:
        return []

    max_hops = int(join.get('max_hops') or 1)
    try:
        q = deque([(anchor, 0)])
        seen = {anchor}
        outs: List[str] = []
        while q:
            node, depth = q.popleft()
            if depth >= 1:
                outs.append(node)
            if depth >= max_hops:
                continue
            for e in (adj(node) or ()):  # edges can be dicts or tuples
                try:
                    if isinstance(e, dict):
                        dst = e.get('id') or e.get('dst')
                    elif isinstance(e, (list, tuple)) and len(e) > 0:
                        dst = e[0]
                    else:
                        dst = None
                except Exception:
                    dst = None
                if not dst:
                    continue
                if dst in seen:
                    continue
                seen.add(dst)
                q.append((dst, depth + 1))
        return outs
    except Exception:
        return []


def _resolve_mapping_for_join(hg: Any, mapping: Dict[str, str]) -> List[str]:
    """Try to resolve mapping values (like 'user','host') into actual node ids by
    scanning `hg.adj` keys for matching prefixes or contained strings.
    Returns a list of candidate node ids.
    """
    candidates: List[str] = []
    try:
        # If hg is a callable graph (CallableHG), it may expose an internal map
        if callable(hg):
            if hasattr(hg, 'map') and isinstance(getattr(hg, 'map'), dict):
                keys = list(getattr(hg, 'map').keys())
            else:
                # fall back to nodes mapping if available
                try:
                    keys = list(getattr(hg, 'nodes', {}).keys())
                except Exception:
                    keys = []
        else:
            keys = list(getattr(hg, 'adj', {}).keys())
    except Exception:
        keys = []
    for field, example in (mapping.items() if isinstance(mapping, dict) else []):
        # if example already looks like a node id (contains ':'), prefer it
        if isinstance(example, str) and ':' in example:
            candidates.append(example)
            continue
        # try prefix match
        pref = f"{field}:"
        for k in keys:
            if k.startswith(pref) or (isinstance(example, str) and example in k):
                candidates.append(k)
    return list(dict.fromkeys(candidates))


def run_rule(rule: DetectionRule, hg: Any, confidence: float = 0.8, emit_incident: bool = False, dry_run: bool = True, incident_url: str | None = None) -> List[Dict[str, Any]]:
    """Execute rule and return standardized action objects.

    Options:
      - emit_incident: if True and dry_run False, POST actions to incident API.
      - dry_run: if True, do not send HTTP requests.
    """
    actions: List[Dict[str, Any]] = []
    conds = _eval_conditions(rule)
    if not conds:
        return actions

    adj = _get_adj_list(hg)

    # Build anchor candidates by evaluating conditions against node dicts when available
    anchor_candidates: List[str] = []
    try:
        # If hg is a callable graph (CallableHG), it may expose an internal map
        if callable(hg):
            if hasattr(hg, 'map') and isinstance(getattr(hg, 'map'), dict):
                keys = list(getattr(hg, 'map').keys())
            else:
                try:
                    keys = list(getattr(hg, 'nodes', {}).keys())
                except Exception:
                    keys = []
        else:
            keys = list(getattr(hg, 'adj', {}).keys())
    except Exception:
        keys = []

    # If graph exposes node dicts via hg.nodes, prefer those for matching
    nodes_map = getattr(hg, 'nodes', {}) or {}
    for (_f, v, op) in conds:
        # If op is eq and value looks like an explicit node id, use it
        if op == 'eq' and isinstance(v, str) and v in keys:
            if v not in anchor_candidates:
                anchor_candidates.append(v)
            continue
        # otherwise evaluate against available nodes
        for k in keys:
            node_dict = nodes_map.get(k)
            matched = False
            if node_dict is not None:
                try:
                    if _match_condition_on_node_dict(node_dict, _f, op, v):
                        matched = True
                except Exception:
                    matched = False
            else:
                # fallback: evaluate against key string
                if _match_condition_on_node(k, op, v):
                    matched = True
            if matched and k not in anchor_candidates:
                anchor_candidates.append(k)

    # If no anchor candidates found, fall back to all adj keys for best-effort evaluation
    if not anchor_candidates:
        try:
            anchor_candidates = list(getattr(hg, 'adj', {}).keys())
        except Exception:
            anchor_candidates = []

    _log.debug('anchor_candidates=%s', anchor_candidates)
    for node in anchor_candidates:
        # verify all conditions hold for this node (prefer node dict matching)
        ok = True
        node_dict = (getattr(hg, 'nodes', {}) or {}).get(node)
        for (_f, v, op) in conds:
            matched = False
            if node_dict is not None:
                try:
                    matched = _match_condition_on_node_dict(node_dict, _f, op, v)
                except Exception:
                    matched = False
            else:
                matched = _match_condition_on_node(node, op, v)
            if not matched:
                ok = False
                break
        if not ok:
            continue

        try:
            neighbors = [e for e in adj(node)]
        except Exception:
            neighbors = []
        _log.debug('evaluating node=%s neighbors=%s', node, neighbors)

        # Resolve joins declared in rule
        resolved: Dict[str, List[str]] = {}
        for j in getattr(rule, 'joins', []) or []:
            try:
                targets = _resolve_join_targets(hg, j, anchor=node)
            except Exception:
                targets = []
            resolved[j.get('name', 'unnamed')] = targets

        if neighbors or any(resolved.values()):
            # adjust confidence slightly from joins
            adj_conf = float(getattr(rule, 'score', confidence) or confidence)
            for j in getattr(rule, 'joins', []) or []:
                if j.get('join_type') == 'inner':
                    adj_conf = min(1.0, adj_conf + 0.05)
                elif j.get('join_type') == 'left':
                    adj_conf = max(0.0, adj_conf - 0.02)

            evidence = {'node': node, 'neighbors': neighbors, 'joins': resolved}
            action = {
                'action_type': 'create_incident',
                'rule_id': getattr(rule.meta, 'id', None),
                'rule_name': getattr(rule.meta, 'name', None),
                'evidence': evidence,
                'evidence_node': node,
                'evidence_neighbors': neighbors,
                'mitre': getattr(rule.meta, 'tags', None),
                'confidence': float(adj_conf),
            }
            actions.append(action)

            if emit_incident and not dry_run:
                url = incident_url or os.environ.get('INCIDENT_API_URL') or 'http://localhost:8080/api/v1/incidents'
                if requests:
                    headers = {'Content-Type': 'application/json'}
                    api_key = os.environ.get('API_KEY')
                    if api_key:
                        headers['x-api-key'] = api_key
                    # Retry with exponential backoff
                    attempt = 0
                    backoff = 0.5
                    while attempt < 3:
                        try:
                            resp = requests.post(url, json=action, headers=headers, timeout=5)
                            # treat 2xx as success
                            if resp is not None and getattr(resp, 'status_code', 0) // 100 == 2:
                                break
                        except Exception:
                            pass
                        attempt += 1
                        try:
                            import time
                            time.sleep(backoff)
                        except Exception:
                            pass
                        backoff *= 2

    return actions


def load_and_run(path: str, hg: Any, **kwargs) -> List[Dict[str, Any]]:
    r = load_rule_from_yaml(path)
    return run_rule(r, hg, **kwargs)


