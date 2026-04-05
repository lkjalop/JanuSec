"""IAM privilege escalation detection helpers.

This module provides heuristics to score IAM-related events such as
role assumption, policy attachment, and admin group changes.
"""
from typing import Dict, Any


def score_iam_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Return a scoring dict for an IAM event.

    Score components:
      - root_account_use: +0.4
      - unusual_source_ip: +0.2
      - policy_attachment_high_priv: +0.3
    """
    score = 0.0
    reasons = []

    etype = event.get('eventName') or event.get('action')
    user = event.get('userIdentity') or {}

    if etype in ('DeleteUser','AttachUserPolicy','PutUserPolicy','PutRolePolicy'):
        score += 0.25
        reasons.append('suspicious_policy_change')

    if etype in ('CreateAccessKey','UpdateAccessKey'):
        score += 0.2
        reasons.append('access_key_activity')

    if user and user.get('type') == 'Root':
        score += 0.4
        reasons.append('root_account')

    src_ip = event.get('sourceIPAddress')
    if src_ip and src_ip.startswith('203.0.113.'):
        score += 0.2
        reasons.append('unusual_ip')

    return {'score': min(1.0, score), 'reasons': reasons}


__all__ = ['score_iam_event']
from typing import List, Dict, Any, Tuple, Optional
import time

# Simple permission level mapping for common AWS managed roles/actions.
# In a real system this would be built from policy documents and action sets.
ACTION_LEVEL = {
    'iam:CreateAccessKey': 9,
    'iam:AttachUserPolicy': 8,
    'iam:AttachRolePolicy': 8,
    'iam:PutUserPolicy': 7,
    'iam:AddUserToGroup': 8,
    'sts:AssumeRole': 10,
    'iam:CreateUser': 6,
    'iam:DeleteUser': 9,
}


def action_permission_level(action: str) -> int:
    return ACTION_LEVEL.get(action, 1)


def detect_assume_role_abuse(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    # detect when a low-privilege user assumes a high-privilege role
    for ev in events:
        if ev.get('eventName') == 'AssumeRole' or ev.get('eventName') == 'sts:AssumeRole':
            actor = ev.get('userIdentity', {}).get('arn') or ev.get('userIdentity', {}).get('userName')
            role = ev.get('requestParameters', {}).get('roleArn') or ev.get('requestParameters', {}).get('role')
            actor_level = int(ev.get('actor_permission_level', 1))
            role_level = int(ev.get('role_permission_level', 10))
            if actor_level + 2 <= role_level:
                findings.append({
                    'factor': 'iam:assume_role_abuse',
                    'actor': actor,
                    'role': role,
                    'actor_level': actor_level,
                    'role_level': role_level,
                    'score': min(1.0, (role_level - actor_level) / 10.0),
                    'ts': ev.get('eventTime', time.time())
                })
    return findings


def detect_policy_attachment_to_self(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    # detect AttachUserPolicy where the actor is same as target user
    for ev in events:
        if ev.get('eventName') in ('AttachUserPolicy', 'iam:AttachUserPolicy'):
            actor = ev.get('userIdentity', {}).get('userName') or ev.get('userIdentity', {}).get('arn')
            target = ev.get('requestParameters', {}).get('userName') or ev.get('requestParameters', {}).get('user')
            policy = ev.get('requestParameters', {}).get('policyArn')
            if actor and target and actor == target:
                findings.append({
                    'factor': 'iam:attach_policy_to_self',
                    'actor': actor,
                    'target': target,
                    'policy': policy,
                    'score': 0.9,
                    'ts': ev.get('eventTime', time.time())
                })
    return findings


def detect_adding_user_to_admin_group(events: List[Dict[str, Any]], admin_group_names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    findings = []
    admin_group_names = admin_group_names or ['Administrators', 'admin', 'Admins', 'AdministratorsGroup']
    for ev in events:
        if ev.get('eventName') in ('AddUserToGroup', 'iam:AddUserToGroup'):
            group = ev.get('requestParameters', {}).get('groupName') or ev.get('requestParameters', {}).get('group')
            target = ev.get('requestParameters', {}).get('userName') or ev.get('requestParameters', {}).get('user')
            actor = ev.get('userIdentity', {}).get('userName') or ev.get('userIdentity', {}).get('arn')
            if group and any(g.lower() == group.lower() for g in admin_group_names):
                findings.append({
                    'factor': 'iam:add_user_to_admin_group',
                    'actor': actor,
                    'target': target,
                    'group': group,
                    'score': 0.95,
                    'ts': ev.get('eventTime', time.time())
                })
    return findings


def detect_create_access_key_for_privileged_user(events: List[Dict[str, Any]], privileged_level: int = 8) -> List[Dict[str, Any]]:
    findings = []
    for ev in events:
        if ev.get('eventName') in ('CreateAccessKey', 'iam:CreateAccessKey'):
            target = ev.get('requestParameters', {}).get('userName') or ev.get('requestParameters', {}).get('user')
            # caller may include 'target_permission_level' if precomputed
            target_level = int(ev.get('target_permission_level', 1))
            actor = ev.get('userIdentity', {}).get('userName') or ev.get('userIdentity', {}).get('arn')
            if target_level >= privileged_level:
                findings.append({
                    'factor': 'iam:create_access_key_privileged',
                    'actor': actor,
                    'target': target,
                    'target_level': target_level,
                    'score': 0.9,
                    'ts': ev.get('eventTime', time.time())
                })
    return findings


def detect_permission_boundary_bypass(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    # Detect PutUserPolicy or PutGroupPolicy that results in policy exceeding a permission boundary
    for ev in events:
        if ev.get('eventName') in ('PutUserPolicy', 'PutGroupPolicy', 'iam:PutUserPolicy'):
            actor = ev.get('userIdentity', {}).get('userName') or ev.get('userIdentity', {}).get('arn')
            target = ev.get('requestParameters', {}).get('userName') or ev.get('requestParameters', {}).get('groupName')
            # heuristics: event includes 'bypass_permission_boundary': True when simulated
            if ev.get('requestParameters', {}).get('bypass_permission_boundary'):
                findings.append({
                    'factor': 'iam:permission_boundary_bypass',
                    'actor': actor,
                    'target': target,
                    'score': 1.0,
                    'ts': ev.get('eventTime', time.time())
                })
    return findings


def aggregate_iam_findings(events: List[Dict[str, Any]], admin_group_names: Optional[List[str]] = None) -> Dict[str, Any]:
    # Run all detectors and return an aggregated summary
    findings = []
    findings.extend(detect_assume_role_abuse(events))
    findings.extend(detect_policy_attachment_to_self(events))
    findings.extend(detect_adding_user_to_admin_group(events, admin_group_names))
    findings.extend(detect_create_access_key_for_privileged_user(events))
    findings.extend(detect_permission_boundary_bypass(events))

    score = 0.0
    for f in findings:
        try:
            score += float(f.get('score', 0.0))
        except Exception:
            pass
    return {
        'count': len(findings),
        'score': min(1.0, score),
        'findings': findings
    }


def build_permission_graph_from_state(state: Dict[str, List[str]]) -> Dict[str, List[Tuple[str,int]]]:
    """
    Build a simple permission-level graph from a mapping of principals -> actions
    state: { 'user:alice': ['iam:CreateAccessKey', 's3:PutObject'] }
    returns: { 'user:alice': [('iam:CreateAccessKey', 9), ('s3:PutObject', 1)] }
    """
    graph = {}
    for principal, actions in state.items():
        graph[principal] = [(a, action_permission_level(a)) for a in actions]
    return graph


def evaluate_lateral_risk(graph: Dict[str, List[Tuple[str,int]]]) -> Dict[str, Any]:
    """Score accounts by maximum permission they hold and surface risky lateral movement edges."""
    summary = {}
    for p, acts in graph.items():
        max_level = max((lvl for (_a, lvl) in acts), default=1)
        summary[p] = {'max_level': max_level, 'actions': acts}
    # naive lateral edges: if any actor can take an action with level >=9, mark as high risk
    high_risk = [p for p,v in summary.items() if v['max_level'] >= 9]
    return {'accounts': summary, 'high_risk_accounts': high_risk}


def reevaluate_on_iam_event(event: Dict[str, Any], runtime=None, tenant_id: str | None = None, targets: list | None = None) -> List[Dict[str, Any]]:
    """Re-evaluate escalation risk for principals affected by an IAM event.

    Writes results into runtime.tenants[tenant]['iam_eval_results'] (list) for visibility.
    Returns list of evaluation dicts for affected principals.
    """
    try:
        from src.api.runtime_state import get_server_runtime_state, get_permission_graph
    except Exception:
        return []
    if runtime is None:
        try:
            runtime = get_server_runtime_state(None)  # may raise
        except Exception:
            runtime = None
    if runtime is None:
        return []
    tid = tenant_id or 'global'
    pg = get_permission_graph(runtime, tenant_id)
    # candidates: principal in event (actor/target) or provided targets list
    candidates = set(targets or [])
    try:
        actor = event.get('userIdentity', {}).get('userName') or event.get('userIdentity', {}).get('arn')
        if actor:
            candidates.add(actor)
    except Exception:
        pass
    try:
        tgt = event.get('requestParameters', {}).get('userName') or event.get('requestParameters', {}).get('user')
        if tgt:
            candidates.add(tgt)
    except Exception:
        pass

    results = []
    # Build enriched evals and enqueue into EVENT_QUEUE for asynchronous HopGraph processing
    try:
        from src.api.runtime_state import EVENT_QUEUE
        from src.api import iam_metrics
    except Exception:
        EVENT_QUEUE = None
        iam_metrics = None

    for c in list(candidates):
        try:
            res = pg.find_risk_weighted_path(c, target_level=9)
            if not res:
                continue
            rec = {'principal': c, 'eval': res, 'ts': time.time(), 'tenant': tid}

            # Attempt to attach Tier-1 LLM short summary locally (best-effort)
            try:
                from src.api.graph_sessions import _maybe_llm_summarize
                try:
                    narrative = f"Principal {c} can reach {res.get('target_node')} via {len(res.get('path',[]))} hops (cost={res.get('cost')})."
                    tier1 = _maybe_llm_summarize(narrative)
                    rec.setdefault('llm_summaries', {})['tier1'] = {'summary': tier1}
                except Exception:
                    pass
            except Exception:
                pass

            # Tier2 recommendations: lightweight structured suggestions
            try:
                tier2 = {
                    'summary': f"Recommend review of role {res.get('target_node')} and rotation of credentials. Path: {'->'.join(res.get('path',[]))}",
                    'recommendations': [
                        'Review role trust policies and remove unused cross-account trusts',
                        'Rotate/disable exposed access keys',
                        'Add monitoring for assume-role events from unexpected principals'
                    ]
                }
                rec.setdefault('llm_summaries', {})['tier2'] = tier2
            except Exception:
                pass

            results.append(rec)

            # record metrics: increment eval counter and set last risk gauge
            try:
                if iam_metrics:
                    iam_metrics.incr_eval(tid, verdict='risk_found')
                    # Set escalation risk to reported cost if available
                    cost = float(res.get('cost') or 0.0)
                    iam_metrics.set_escalation_risk(tid, c, cost)
            except Exception:
                pass

            # enqueue for HopGraph ingestion / downstream processing
            try:
                if EVENT_QUEUE is not None and hasattr(EVENT_QUEUE, 'enqueue'):
                    # Enqueue minimal record for hopgraph: include path and provenance
                    ev = {'source': 'iam_eval', 'tenant': tid, 'principal': c, 'path': res.get('path', []), 'cost': res.get('cost'), 'ts': rec['ts']}
                    import asyncio
                    try:
                        loop = asyncio.get_running_loop()
                        if loop.is_running():
                            loop.create_task(EVENT_QUEUE.enqueue(ev))
                        else:
                            loop.run_until_complete(EVENT_QUEUE.enqueue(ev))
                    except Exception:
                        try:
                            asyncio.run(EVENT_QUEUE.enqueue(ev))
                        except Exception:
                            pass
            except Exception:
                pass
        except Exception:
            continue

    # persist into tenant runtime mapping for UI visibility
    try:
        tmap = runtime.tenants.setdefault(tid, {})
        arr = tmap.setdefault('iam_eval_results', [])
        arr.extend(results)
        if len(arr) > 200:
            del arr[:-200]
    except Exception:
        pass
    return results
