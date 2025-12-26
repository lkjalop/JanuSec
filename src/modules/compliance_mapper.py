from __future__ import annotations

from typing import Any, Dict, List

from .compliance.document_ingestion import ingest_documents_memory
from .compliance.gates import LogicGateEngine


class ComplianceMapper:
    """High-level orchestrator for compliance assessment.

    Usage:
      mapper = ComplianceMapper({})
      result = await mapper.assess_documents(framework, docs=[{'filename': 'policy.pdf', 'content': b'...'}])
    """
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    async def initialize(self) -> None:  # noqa: D401
        return None

    async def health_check(self) -> bool:
        return True

    async def shutdown(self) -> None:
        return None

    async def assess_documents(self, framework: str, docs: List[dict]) -> dict[str, Any]:
        chunks = ingest_documents_memory(docs)
        engine = LogicGateEngine()
        state: Dict[str, Any] = {
            'framework': framework,
            'chunks': chunks,
        }
        state = await engine.run(state)
        # Summarize graph
        graph_summary = {
            'nodes': len(engine.graph.nodes),
            'edges': len(engine.graph.edges),
        }
        return {
            'framework': framework,
            'overall_score': state.get('overall_score'),
            'risk_matrix': state.get('risk_matrix'),
            'control_results': state.get('control_results', []),
            'gaps': state.get('gaps', []),
            'graph_summary': graph_summary,
            '_graph': engine.graph,  # internal use by API layer (not serialized to clients)
        }
