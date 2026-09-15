from typing import Dict, List, Tuple, Any, Optional, Set
import json
import os
from collections import deque


# Richer in-memory permission graph with principals, roles, actions and trust edges.
class PermissionGraphStore:
    def __init__(self, persist_path: Optional[str] = None):
        # node -> list of (action, level)
        self.actions: Dict[str, List[Tuple[str, int]]] = {}
        # directed edges representing delegation/assume relationships: node -> {dst: weight}
        # weight: float (risk cost) where lower is easier/cheaper to traverse
        self.edges: Dict[str, Dict[str, float]] = {}
        self.persist_path = persist_path
        if self.persist_path and os.path.exists(self.persist_path):
            try:
                self.load()
            except Exception:
                pass

    def upsert_principal(self, principal: str, actions: List[Tuple[str, int]]):
        self.actions[principal] = actions
        self.edges.setdefault(principal, {})
        self._maybe_persist()

    def add_edge(self, src: str, dst: str):
        # default weight 1.0 if not provided
        self.edges.setdefault(src, {})
        self.edges[src].setdefault(dst, 1.0)
        self.edges.setdefault(dst, {})
        self._maybe_persist()

    def add_weighted_edge(self, src: str, dst: str, weight: float = 1.0):
        self.edges.setdefault(src, {})
        self.edges[src][dst] = float(weight)
        self.edges.setdefault(dst, {})
        self._maybe_persist()

    def remove_edge(self, src: str, dst: str):
        if src in self.edges:
            try:
                self.edges[src].pop(dst, None)
            except Exception:
                pass
        self._maybe_persist()

    def get_principal_actions(self, principal: str) -> List[Tuple[str, int]]:
        return self.actions.get(principal, [])

    def get_principal(self, principal: str) -> Optional[Dict[str, Any]]:
        if principal not in self.actions and principal not in self.edges:
            return None
        return {
            'principal': principal,
            'actions': list(self.actions.get(principal, [])),
            'neighbors': list(self.edges.get(principal, {}).keys()),
        }

    def get_neighbors(self, principal: str) -> List[str]:
        return list(self.edges.get(principal, {}).keys())

    def _maybe_persist(self):
        if not self.persist_path:
            return
        try:
            # edges is a mapping node -> {dst: weight}
            data = {'actions': {k: v for k, v in self.actions.items()}, 'edges': {k: {dst: float(w) for dst, w in v.items()} for k, v in self.edges.items()}}
            with open(self.persist_path, 'w', encoding='utf-8') as fh:
                json.dump(data, fh)
        except Exception:
            pass

    def load(self):
        with open(self.persist_path, 'r', encoding='utf-8') as fh:
            raw = json.load(fh)
            self.actions = {k: [(a, int(l)) for a, l in v] for k, v in raw.get('actions', {}).items()}
            edges_raw = raw.get('edges', {}) or {}
            parsed = {}
            for k, v in edges_raw.items():
                # if v is a list (legacy), convert to dict with weight 1.0
                if isinstance(v, list):
                    parsed[k] = {str(dst): 1.0 for dst in v}
                elif isinstance(v, dict):
                    try:
                        parsed[k] = {str(dst): float(w) for dst, w in v.items()}
                    except Exception:
                        parsed[k] = {str(dst): 1.0 for dst in v.keys()}
                else:
                    parsed[k] = {}
            self.edges = parsed

    def find_shortest_escalation_path(self, start_principal: str, target_level: int) -> Optional[Dict[str, Any]]:
        """
        BFS over principals/roles using edges to find a path from start_principal to any node
        that has an action with level >= target_level. Return path and risk score.
        """
        if start_principal not in self.edges and start_principal not in self.actions:
            return None

        visited: Set[str] = set()
        q = deque()
        # store predecessors for path reconstruction
        pred: Dict[str, Optional[str]] = {}

        q.append(start_principal)
        visited.add(start_principal)
        pred[start_principal] = None

        target_node = None
        while q:
            node = q.popleft()
            # check node's actions for threshold
            for act, lvl in self.get_principal_actions(node):
                if lvl >= target_level:
                    target_node = node
                    break
            if target_node:
                break
            # traverse neighbors
            for nb in self.get_neighbors(node):
                if nb not in visited:
                    visited.add(nb)
                    pred[nb] = node
                    q.append(nb)

        if not target_node:
            return None

        # reconstruct path nodes
        path_nodes = []
        cur = target_node
        while cur is not None:
            path_nodes.append(cur)
            cur = pred.get(cur)
        path_nodes.reverse()

        # Compose a path of actions for the target node
        target_actions = self.get_principal_actions(target_node)
        best_action = max(target_actions, key=lambda t: t[1]) if target_actions else (None, 0)

        # risk score: normalized by target level (simple heuristic)
        risk = min(1.0, best_action[1] / max(1, target_level))

        return {
            'start': start_principal,
            'target_node': target_node,
            'path': path_nodes,
            'target_action': best_action,
            'risk': risk
        }

    def find_shortest_path_to_level(self, start_principal: str, target_level: int) -> Optional[Dict[str, Any]]:
        return self.find_shortest_escalation_path(start_principal, target_level)

    def find_risk_weighted_path(self, start_principal: str, target_level: int) -> Optional[Dict[str, Any]]:
        """
        Use Dijkstra to find the lowest-risk path (sum of edge weights) from start to
        any node that has an action with level >= target_level.
        """
        import math
        if start_principal not in self.edges and start_principal not in self.actions:
            return None

        # Priority queue of (cost, node)
        from heapq import heappush, heappop
        costs: Dict[str, float] = {start_principal: 0.0}
        pred: Dict[str, Optional[str]] = {start_principal: None}
        pq: List[Tuple[float, str]] = []
        heappush(pq, (0.0, start_principal))

        target_node = None
        best_cost = math.inf
        while pq:
            cost, node = heappop(pq)
            if cost > costs.get(node, math.inf):
                continue
            # check if this node meets target
            for act, lvl in self.get_principal_actions(node):
                if lvl >= target_level:
                    if cost < best_cost:
                        best_cost = cost
                        target_node = node
            if target_node is not None and cost > best_cost:
                # We already found a better target; stop
                break
            # relax neighbors
            for nb, w in self.edges.get(node, {}).items():
                ncost = cost + (float(w) if w is not None else 1.0)
                if ncost < costs.get(nb, math.inf):
                    costs[nb] = ncost
                    pred[nb] = node
                    heappush(pq, (ncost, nb))

        if target_node is None:
            return None

        # reconstruct path
        path_nodes = []
        cur = target_node
        while cur is not None:
            path_nodes.append(cur)
            cur = pred.get(cur)
        path_nodes.reverse()

        target_actions = self.get_principal_actions(target_node)
        best_action = max(target_actions, key=lambda t: t[1]) if target_actions else (None, 0)

        # normalize risk: lower costs mean easier for attacker; invert to a 0..1 risk score
        # simple heuristic: risk = 1 - exp(-cost/ (1+best_action_level)) capped 0..1
        try:
            import math as _m
            risk = 1.0 - _m.exp(-best_cost / max(1.0, best_action[1] or 1.0))
        except Exception:
            risk = min(1.0, best_cost / max(1.0, best_action[1] or 1.0))

        return {'start': start_principal, 'target_node': target_node, 'path': path_nodes, 'target_action': best_action, 'cost': best_cost, 'risk': risk}
