"""EndpointEmailMLPipeline — orchestrator for all ML-backed detector modules.

Wires together:
    1. URLRiskScorer             (url_risk_scorer.py)
    2. AttachmentRiskAnalyzer    (attachment_risk_analyzer.py)
    3. BECScoringModel           (bec_scoring_model.py)
    4. ProcessTreeAnomalyDetector (process_tree_anomaly.py)
    5. PersistenceScoringModel    (persistence_scoring_model.py)
    6. AdvancedEndpointThreats    (advanced_endpoint_threats.py)
    7. Basic BEC detector         (email_bec.py)
    8. Basic attachment detector  (attachment_analyzer.py)

Then:
    - Emits all factors via emission_tracker.record_emission()
    - Adds HopGraph edges for each factor cluster
    - Maps factors → MITRE ATT&CK + compliance controls via factor_to_compliance.py
    - Returns a unified PipelineResult compatible with the existing assessment schema

Usage (from auto_llm.py or deep_analyze_endpoints.py):
    from src.core.ml_pipeline import EndpointEmailMLPipeline
    pipeline = EndpointEmailMLPipeline()
    result = pipeline.run(runtime, tenant_id='default', event_id='abc-123')
    # result.factors — all emitted factors
    # result.hopgraph_edges — edges to add to HopGraph
    # result.compliance_hits — compliance control violations
    # result.mitre_techniques — ATT&CK techniques
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Detector imports (all gracefully degrade if not available)
# ---------------------------------------------------------------------------
try:
    from src.core.detectors.url_risk_scorer import analyze_email_url_risk
except Exception:
    analyze_email_url_risk = None  # type: ignore

try:
    from src.core.detectors.attachment_risk_analyzer import analyze_attachments_risk
except Exception:
    analyze_attachments_risk = None  # type: ignore

try:
    from src.core.detectors.bec_scoring_model import detect_bec_advanced
except Exception:
    detect_bec_advanced = None  # type: ignore

try:
    from src.core.detectors.process_tree_anomaly import detect_process_tree_anomalies
except Exception:
    detect_process_tree_anomalies = None  # type: ignore

try:
    from src.core.detectors.persistence_scoring_model import detect_persistence_signals
except Exception:
    detect_persistence_signals = None  # type: ignore

try:
    from src.core.detectors.advanced_endpoint_threats import detect_advanced_threats
except Exception:
    detect_advanced_threats = None  # type: ignore

# Existing basic detectors
try:
    from src.core.detectors.email_bec import detect_email_bec
except Exception:
    detect_email_bec = None  # type: ignore

try:
    from src.core.attachment_analyzer import analyze_attachments as analyze_attachments_basic
except Exception:
    analyze_attachments_basic = None  # type: ignore

# Factor emission
try:
    from src.core.factors.emission_tracker import record_emission
except Exception:
    def record_emission(factor, **kwargs): pass  # type: ignore

# Compliance mapping
try:
    from src.core.mappings.factor_to_compliance import get_compliance_hits
except Exception:
    def get_compliance_hits(factors): return {}  # type: ignore

# MITRE mapping
try:
    from src.core.mappings.factor_to_mitre import get_all_mappings
except Exception:
    def get_all_mappings(factors): return {'mitre': [], 'atlas': [], 'owasp_llm': []}  # type: ignore

# HopGraph (optional)
try:
    from src.core.graph.hopgraph_core import get_hopgraph
    _HOPGRAPH_AVAILABLE = True
except Exception:
    _HOPGRAPH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class PipelineResult:
    """Unified output from EndpointEmailMLPipeline.run()."""
    factors: List[Dict[str, Any]] = field(default_factory=list)
    hopgraph_edges: List[Dict[str, Any]] = field(default_factory=list)
    compliance_hits: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    severity_score: float = 0.0
    top_factor: Optional[str] = None
    run_time_ms: float = 0.0
    detectors_run: List[str] = field(default_factory=list)
    detectors_skipped: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            'factors': self.factors,
            'hopgraph_edges': self.hopgraph_edges,
            'compliance_hits': self.compliance_hits,
            'mitre_techniques': self.mitre_techniques,
            'severity_score': self.severity_score,
            'top_factor': self.top_factor,
            'run_time_ms': round(self.run_time_ms, 1),
            'detectors_run': self.detectors_run,
            'detectors_skipped': self.detectors_skipped,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class EndpointEmailMLPipeline:
    """Orchestrates all email and endpoint ML detectors.

    Designed to be called once per event cluster / assessment.
    Thread-safe: each call is stateless except for tenant-scoped baselines
    maintained inside each detector module.
    """

    def __init__(self, hopgraph_enabled: bool = True):
        self._hopgraph_enabled = hopgraph_enabled and _HOPGRAPH_AVAILABLE

    def run(
        self,
        runtime,
        tenant_id: str = 'default',
        event_id: Optional[str] = None,
        skip_detectors: Optional[List[str]] = None,
    ) -> PipelineResult:
        """Run all detectors and aggregate results.

        Args:
            runtime:          Runtime object with sanitized_events, email_messages, etc.
            tenant_id:        Tenant ID for baseline isolation.
            event_id:         Optional event/assessment ID for factor dedup.
            skip_detectors:   List of detector names to skip (e.g. ['url_risk', 'steg']).

        Returns:
            PipelineResult with all factors, edges, compliance hits, MITRE techniques.
        """
        t0 = time.time()
        skip = set(skip_detectors or [])
        result = PipelineResult()

        # ----------------------------------------------------------------
        # Run detectors
        # ----------------------------------------------------------------
        detectors = [
            ('bec_basic',        detect_email_bec,            {'runtime': runtime}),
            ('bec_advanced',     detect_bec_advanced,          {'runtime': runtime, 'tenant_id': tenant_id, 'event_id': event_id}),
            ('url_risk',         analyze_email_url_risk,       {'runtime': runtime, 'event_id': event_id}),
            ('attachment_basic', analyze_attachments_basic,    {'runtime': runtime}),
            ('attachment_risk',  analyze_attachments_risk,     {'runtime': runtime, 'event_id': event_id}),
            ('process_tree',     detect_process_tree_anomalies, {'runtime': runtime, 'tenant_id': tenant_id, 'event_id': event_id}),
            ('persistence',      detect_persistence_signals,   {'runtime': runtime, 'tenant_id': tenant_id, 'event_id': event_id}),
            ('advanced_threats', detect_advanced_threats,      {'runtime': runtime, 'tenant_id': tenant_id, 'event_id': event_id}),
        ]

        for name, fn, kwargs in detectors:
            if name in skip or fn is None:
                result.detectors_skipped.append(name)
                continue
            try:
                output = fn(**kwargs)
                if isinstance(output, list):
                    result.factors.extend(output)
                result.detectors_run.append(name)
            except Exception as exc:
                result.detectors_skipped.append(f'{name}:error({type(exc).__name__})')

        # ----------------------------------------------------------------
        # Emit factors via emission tracker
        # ----------------------------------------------------------------
        for f in result.factors:
            factor_name = f.get('factor')
            if factor_name:
                try:
                    record_emission(
                        factor_name,
                        decision_id=event_id,
                        node_ids=_extract_node_ids(f),
                    )
                except Exception:
                    pass

        # ----------------------------------------------------------------
        # HopGraph wiring
        # ----------------------------------------------------------------
        if self._hopgraph_enabled:
            result.hopgraph_edges = self._build_hopgraph_edges(result.factors, runtime)
            self._apply_hopgraph_edges(result.hopgraph_edges, tenant_id)

        # ----------------------------------------------------------------
        # Compliance + MITRE mapping
        # ----------------------------------------------------------------
        factor_names = [f.get('factor', '') for f in result.factors if f.get('factor')]
        try:
            result.compliance_hits = get_compliance_hits(factor_names)
        except Exception:
            result.compliance_hits = {}
        try:
            all_maps = get_all_mappings(factor_names)
            result.mitre_techniques = all_maps.get('mitre', [])
        except Exception:
            result.mitre_techniques = []

        # ----------------------------------------------------------------
        # Severity aggregation (max score weighted by factor confidence)
        # ----------------------------------------------------------------
        if result.factors:
            scores = [f.get('score', 0.0) for f in result.factors]
            result.severity_score = round(min(max(scores), 1.0), 3)
            top = max(result.factors, key=lambda f: f.get('score', 0.0))
            result.top_factor = top.get('factor')

        result.run_time_ms = (time.time() - t0) * 1000
        return result

    # ----------------------------------------------------------------
    # HopGraph edge construction
    # ----------------------------------------------------------------

    def _build_hopgraph_edges(
        self,
        factors: List[Dict[str, Any]],
        runtime,
    ) -> List[Dict[str, Any]]:
        """Derive HopGraph edges from factor metadata."""
        edges = []
        for f in factors:
            factor = f.get('factor', '')
            score  = float(f.get('score', 0.5))

            try:
                # Email factors: sender → recipient via risk edge
                if factor.startswith('email:'):
                    from_domain = f.get('from_domain') or f.get('sender_domain') or ''
                    recipient   = f.get('recipient_domain') or ''
                    domain      = f.get('domain') or from_domain
                    sha256      = f.get('sha256') or ''
                    if from_domain:
                        edges.append({
                            'src': f'domain:{from_domain}',
                            'dst': f'domain:{recipient}' if recipient else f'factor:{factor}',
                            'edge_type': 'email_risk',
                            'weight': score,
                            'factor': factor,
                            'source': 'ml_pipeline',
                        })
                    if sha256:
                        edges.append({
                            'src': f'hash:{sha256}',
                            'dst': f'domain:{from_domain}' if from_domain else f'factor:{factor}',
                            'edge_type': 'attachment_risk',
                            'weight': score,
                            'factor': factor,
                            'source': 'ml_pipeline',
                        })

                # Endpoint factors: process → host via risk edge
                elif factor.startswith('endpoint:'):
                    proc    = f.get('process') or ''
                    parent  = f.get('parent') or ''
                    host    = f.get('hostname') or ''
                    pid     = f.get('pid') or ''
                    if proc and host:
                        src_node = f'process:{proc}:{pid}' if pid else f'process:{proc}'
                        edges.append({
                            'src': src_node,
                            'dst': f'host:{host}',
                            'edge_type': 'endpoint_risk',
                            'weight': score,
                            'factor': factor,
                            'source': 'ml_pipeline',
                        })
                    if proc and parent:
                        edges.append({
                            'src': f'process:{parent}',
                            'dst': f'process:{proc}:{pid}' if pid else f'process:{proc}',
                            'edge_type': 'spawned_by',
                            'weight': score,
                            'factor': factor,
                            'source': 'ml_pipeline',
                        })
            except Exception:
                continue

        return edges

    def _apply_hopgraph_edges(self, edges: List[Dict[str, Any]], tenant_id: str) -> None:
        """Push edges into HopGraph if available."""
        if not edges or not self._hopgraph_enabled:
            return
        try:
            hg = get_hopgraph(tenant_id=tenant_id)
            for edge in edges:
                hg.add_edge(
                    edge['src'],
                    edge['dst'],
                    edge_type=edge.get('edge_type', 'ml_risk'),
                    weight=edge.get('weight', 0.5),
                    source='ml_pipeline',
                    metadata={'factor': edge.get('factor', '')},
                )
        except Exception:
            pass


def _extract_node_ids(factor: Dict[str, Any]) -> List[str]:
    """Extract node ID hints from a factor dict for emission tracking."""
    nodes = []
    for field_name in ('domain', 'from_domain', 'sha256', 'hostname', 'process'):
        val = factor.get(field_name)
        if val:
            nodes.append(f'{field_name}:{val[:80]}')
    return nodes[:5]


# ---------------------------------------------------------------------------
# Module-level default instance
# ---------------------------------------------------------------------------
_DEFAULT_PIPELINE: Optional[EndpointEmailMLPipeline] = None


def get_pipeline() -> EndpointEmailMLPipeline:
    """Return the module-level singleton pipeline."""
    global _DEFAULT_PIPELINE
    if _DEFAULT_PIPELINE is None:
        _DEFAULT_PIPELINE = EndpointEmailMLPipeline()
    return _DEFAULT_PIPELINE


__all__ = ['EndpointEmailMLPipeline', 'PipelineResult', 'get_pipeline']
