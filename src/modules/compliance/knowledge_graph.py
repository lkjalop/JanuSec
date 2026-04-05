from __future__ import annotations

from typing import Dict, Any, List

NodeId = str


class KnowledgeGraph:
    def __init__(self) -> None:
        self.nodes: Dict[NodeId, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._adj_out: Dict[NodeId, List[Dict[str, Any]]] = {}
        self._adj_in: Dict[NodeId, List[Dict[str, Any]]] = {}

    def add_node(self, node_type: str, **props) -> NodeId:
        node_id = str(props.get('id') or props.get('control_id') or props.get('chunk_id') or f"{node_type}:{len(self.nodes)+1}")
        rec = {'id': node_id, 'type': node_type, **props}
        self.nodes[node_id] = rec
        return node_id

    def add_edge(self, source: NodeId, target: NodeId, rel_type: str, **props) -> None:
        e = {'source': source, 'target': target, 'type': rel_type, **props}
        self.edges.append(e)
        self._adj_out.setdefault(source, []).append(e)
        self._adj_in.setdefault(target, []).append(e)

    def to_graphml(self) -> str:
        lines = ["<graphml>", "  <graph id=\"G\" edgedefault=\"directed\">"]
        for n in self.nodes.values():
            lines.append(f"    <node id=\"{n['id']}\"><data key=\"type\">{n['type']}</data></node>")
        for e in self.edges:
            lines.append(f"    <edge source=\"{e['source']}\" target=\"{e['target']}\"><data key=\"type\">{e['type']}</data></edge>")
        lines.append("  </graph>")
        lines.append("</graphml>")
        return "\n".join(lines)

__all__ = ["KnowledgeGraph"]

