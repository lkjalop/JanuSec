from __future__ import annotations

import os
from types import SimpleNamespace

from .advanced import (
    cluster_dedupe_stage,
    correlation_stage,
    coverage_stage,
    embedding_stage,
    hunt_lanes_stage,
    mapping_stage,
    quality_stage,
)
from .base import StageContext, StageDefinition, StageResult
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
from .ebpf_analysis import ebpf_analysis_stage
from .identity import identity_stage
from .supply_chain import (
    binary_payload_stage,
    cicd_stage,
    npm_stage,
)
from .threat_intel import threat_intel_stage
from .email import run_email_enrichment


async def certificate_stage(event, ctx: StageContext) -> StageResult:
    from modules.certificate_analysis import CertificateAnalysis  # type: ignore
    # Ensure a simple registry exists so we can cache analyzer instances when
    # the pipeline doesn't provide a full registry object (tests often pass None).
    if ctx.registry is None:
        ctx.registry = SimpleNamespace()
    analyzer = getattr(ctx.registry, 'certificate_analysis', None)
    if analyzer is None:
        analyzer = CertificateAnalysis(ctx.config)
        ctx.registry.certificate_analysis = analyzer
    result = await analyzer.analyze_event(event)
    return StageResult(name='cert_analysis', factors=result['factors'], confidence_delta=result['confidence_delta'])

async def http_header_stage(event, ctx: StageContext) -> StageResult:
    from modules.http_header_analysis import HTTPHeaderAnalysis  # type: ignore
    # Ensure a simple registry exists so we can cache analyzer instances when
    # the pipeline doesn't provide a full registry object (tests often pass None).
    if ctx.registry is None:
        ctx.registry = SimpleNamespace()
    analyzer = getattr(ctx.registry, 'http_header_analysis', None)
    if analyzer is None:
        analyzer = HTTPHeaderAnalysis(ctx.config)
        ctx.registry.http_header_analysis = analyzer
    result = await analyzer.analyze_event(event)
    return StageResult(name='http_header', factors=result['factors'], confidence_delta=result['confidence_delta'])

STAGE_DEFINITIONS: list[StageDefinition] = [
    StageDefinition('baseline', baseline_stage),
    StageDefinition('regex', regex_stage),
    StageDefinition('parent_child', parent_child_stage),
    StageDefinition('endpoint', endpoint_stage),
    StageDefinition('email_enrichment', run_email_enrichment),
    StageDefinition('auth_burst', auth_burst_stage),
    StageDefinition('identity', identity_stage),
    StageDefinition('graph', graph_stage),
    StageDefinition('adaptive_pre', adaptive_pre_stage),
    StageDefinition('packet_summary', packet_summary_stage),
    StageDefinition('threat_intel', threat_intel_stage),
    StageDefinition('supply_chain_npm', npm_stage),
    StageDefinition('supply_chain_cicd', cicd_stage),
    StageDefinition('binary_payload', binary_payload_stage, heavy=True),
    StageDefinition('sbom_exec', sbom_execution_stage),
    StageDefinition('sbom_vuln', sbom_vulnerability_stage),
    StageDefinition('ebpf_analysis', ebpf_analysis_stage),
    # Optional new analysis stages (feature-flagged by their internal enabled check)
    StageDefinition('cert_analysis', certificate_stage, heavy=False),
    StageDefinition('http_header', http_header_stage, heavy=False),
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
