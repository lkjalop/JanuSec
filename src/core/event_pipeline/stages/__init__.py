from __future__ import annotations

from .advanced import (
    cluster_dedupe_stage,
    correlation_stage,
    coverage_stage,
    embedding_stage,
    hunt_lanes_stage,
    mapping_stage,
    quality_stage,
)
from .base import StageDefinition, StageResult, StageContext
from .network import beacon_stage, domain_novelty_stage, egress_stage, rare_token_stage
from .primitives import (
    adaptive_pre_stage,
    auth_burst_stage,
    baseline_stage,
    endpoint_stage,
    graph_stage,
    packet_summary_stage,
    parent_child_stage,
    regex_stage,
)
from .sbom import sbom_execution_stage, sbom_vulnerability_stage

STAGE_DEFINITIONS: list[StageDefinition] = [
    StageDefinition('baseline', baseline_stage),
    StageDefinition('regex', regex_stage),
    StageDefinition('parent_child', parent_child_stage),
    StageDefinition('endpoint', endpoint_stage),
    StageDefinition('auth_burst', auth_burst_stage),
    StageDefinition('graph', graph_stage),
    StageDefinition('adaptive_pre', adaptive_pre_stage),
    StageDefinition('packet_summary', packet_summary_stage),
    StageDefinition('sbom_exec', sbom_execution_stage),
    StageDefinition('sbom_vuln', sbom_vulnerability_stage),
    StageDefinition('beacon', beacon_stage, heavy=True),
    StageDefinition('egress', egress_stage, heavy=True),
    StageDefinition('domain_novelty', domain_novelty_stage, heavy=True),
    StageDefinition('rare_token', rare_token_stage),
    StageDefinition('hunt_lanes', hunt_lanes_stage),
    StageDefinition('correlation', correlation_stage),
    StageDefinition('quality_filter', quality_stage),
    StageDefinition('mapping', mapping_stage),
    StageDefinition('cluster_dedupe', cluster_dedupe_stage),
    StageDefinition('coverage_tracker', coverage_stage),
    StageDefinition('embedding', embedding_stage),
]

__all__ = [
    'StageDefinition',
    'StageResult',
    'StageContext',
    'STAGE_DEFINITIONS',
]
