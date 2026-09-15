from __future__ import annotations

import json
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)


def _normalize_principal(p: Any) -> str:
    # Simplified normalization: handle ARN strings and account ids
    if not p:
        return ''
    if isinstance(p, str):
        return p
    # AWS principal can be dict like {"AWS": "*"} or list
    if isinstance(p, dict):
        # pick common keys
        for k in ('AWS', 'Service', 'Federated'):
            if k in p:
                return str(p[k])
        # fallback to json
        return json.dumps(p)
    try:
        return str(p)
    except Exception:
        return ''


def parse_policy_document(policy: Dict[str, Any]) -> Tuple[List[Tuple[str, List[str]]], List[Dict[str, Any]]]:
    """Parse an AWS-like policy document into a list of (principal, actions)

    Returns:
      - principals_actions: list of (principal_identifier, [actions])
      - edges: list of edge dicts for trust relationships (from, to, weight, condition)
    """
    principals_actions: List[Tuple[str, List[str]]] = []
    edges: List[Dict[str, Any]] = []
    if not isinstance(policy, dict):
        return principals_actions, edges
    statements = policy.get('Statement') or policy.get('statement') or []
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        try:
            effect = str(stmt.get('Effect') or stmt.get('effect') or 'Allow')
            if effect.lower() != 'allow':
                continue
            actions = stmt.get('Action') or stmt.get('action') or []
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get('Resource') or stmt.get('resource') or []
            principals = stmt.get('Principal') or stmt.get('principal') or stmt.get('NotPrincipal')
            # Normalize principals
            if principals is None:
                principals = []
            if isinstance(principals, (str, dict)):
                principals = [principals]
            # For each principal, map actions
            for p in principals:
                pid = _normalize_principal(p)
                if not pid:
                    continue
                principals_actions.append((pid, [str(a) for a in actions]))
                # If principal looks like a role/arn, create a trust edge from principal -> resource
                # resource may be a role ARN; we'll generate lightweight edges mapping
                for r in (resources if isinstance(resources, list) else [resources]):
                    if not r:
                        continue
                    edge = {
                        'from': pid,
                        'to': str(r),
                        'weight': _heuristic_edge_weight(pid, r, stmt),
                        'condition': stmt.get('Condition') or stmt.get('condition') or None,
                        'action_count': len(actions) if actions else 0,
                    }
                    edges.append(edge)
        except Exception:
            logger.exception('failed to parse statement')
            continue
    return principals_actions, edges


def _heuristic_edge_weight(principal: str, resource: str, stmt: Dict[str, Any]) -> float:
    """Compute a heuristic weight for a trust edge.

    Heuristics:
      - same account (account ids match) -> 1.0
      - cross-account (different account ids in ARNs) -> 2.0
      - wildcard or public principal -> 5.0
      - unknown/unparsable -> 10.0
    """
    try:
        p = str(principal)
        r = str(resource)
        # public wildcard
        if p.strip() in {'*', '"*"', '"AWS":"*"'} or p.strip().endswith(':*'):
            return 5.0
        # try to extract AWS account id from arn
        def _acct(s: str) -> str | None:
            if s.startswith('arn:'):
                parts = s.split(':')
                if len(parts) > 4:
                    return parts[4]
            # fallback: plain numeric
            if s.isdigit() and len(s) >= 10:
                return s
            return None
        pa = _acct(p)
        ra = _acct(r)
        if pa and ra:
            if pa == ra:
                return 1.0
            return 2.5
        # If condition allows external accounts (AWS:SourceAccount mismatch) bump
        cond = stmt.get('Condition') or {}
        if cond and any('Source' in k or 'Account' in k for k in json.dumps(cond)):
            return 3.0
        return 10.0
    except Exception:
        return 10.0


__all__ = ['parse_policy_document', '_normalize_principal', '_heuristic_edge_weight', 'parse_trust_policy', 'ingest_policy_to_graph']


from typing import Optional
from src.domains.iam.graph_store import PermissionGraphStore


def parse_trust_policy(trust: Dict[str, Any]) -> List[Tuple[str, str, float]]:
    """Parse a trust relationship that maps principals to trusted roles.

    Returns list of (src_principal, dst_role, weight).
    Weight heuristics: if Principal == '*', weight=5.0 (public); if arn contains
    another account id, weight=3.0 (cross-account); otherwise 1.0.
    """
    out: List[Tuple[str, str, float]] = []
    if not isinstance(trust, dict):
        return out
    stmts = trust.get('Statement') or trust.get('statement') or []
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        principals = s.get('Principal') or s.get('principal') or {}
        actions = s.get('Action') or s.get('action') or []
        if isinstance(actions, str):
            actions = [actions]
        pids: List[str] = []
        if isinstance(principals, dict):
            for k, v in principals.items():
                if isinstance(v, list):
                    pids.extend(v)
                else:
                    pids.append(v)
        elif isinstance(principals, list):
            pids.extend(principals)
        elif isinstance(principals, str):
            pids.append(principals)

        for p in pids:
            # heuristic weight
            if p == '*' or p == 'All':
                w = 5.0
            elif isinstance(p, str) and ':' in p and '/' in p:
                # rudimentary cross-account check (arn:aws:iam::123456789012:user/xxx)
                w = 3.0
            else:
                w = 1.0
            # for each action mapped to role assume semantics
            for a in actions:
                out.append((p, a, w))
    return out


def ingest_policy_to_graph(graph: PermissionGraphStore, policy: Dict[str, Any], principal_prefix: str = '', weight_overrides: Optional[Dict[str, Any]] = None) -> None:
    """Populate the provided PermissionGraphStore from policy document.

    This will upsert principals with action levels inferred from simple mapping
    (caller should map action name to level separately). This helper is
    intentionally small for common test/demo shapes.
    """
    pairs, edges = parse_policy_document(policy)
    # build upsert mapping
    by_principal: Dict[str, List[Tuple[str, int]]] = {}
    for p, acts in pairs:
        key = f"{principal_prefix}{p}" if principal_prefix else p
        for a in acts:
            by_principal.setdefault(key, []).append((a, 1))
    for p, acts in by_principal.items():
        try:
            graph.upsert_principal(p, acts)
        except Exception:
            pass
    # add edges
    try:
        for e in edges:
            src = e.get('from')
            dst = e.get('to')
            w = float(e.get('weight') or 1.0)
            # apply overrides if provided
            if weight_overrides and isinstance(weight_overrides, dict):
                w = _apply_weight_overrides(src, dst, w, weight_overrides)
            if not src or not dst:
                continue
            src_k = f"{principal_prefix}{src}" if principal_prefix else src
            try:
                graph.add_weighted_edge(src_k, dst, w)
            except Exception:
                try:
                    graph.add_edge(src_k, dst)
                except Exception:
                    pass
    except Exception:
        pass


def _apply_weight_overrides(src: str, dst: str, current: float, overrides: Dict[str, Any]) -> float:
    """Apply simple override rules to the computed weight.

    Supported override keys (optional):
      - same_account: float
      - cross_account: float
      - public: float
      - unknown: float
      - default: float
    """
    try:
        # direct default
        if 'default' in overrides:
            base = float(overrides.get('default'))
        else:
            base = current
        s = str(src or '')
        d = str(dst or '')
        def _acct(s: str) -> str | None:
            if s.startswith('arn:'):
                parts = s.split(':')
                if len(parts) > 4:
                    return parts[4]
            if s.isdigit() and len(s) >= 10:
                return s
            return None
        sa = _acct(s)
        da = _acct(d)
        if s.strip() in {'*', '"*"', '"AWS":"*"'} or s.strip().endswith(':*'):
            return float(overrides.get('public', base))
        if sa and da:
            if sa == da:
                return float(overrides.get('same_account', base))
            return float(overrides.get('cross_account', base))
        # condition-based or unknown
        return float(overrides.get('unknown', base))
    except Exception:
        return current
