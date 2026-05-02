"""Executive summary pipeline — per-cluster, bitemporal, grounded narratives.

Modules:
    schemas            — Pydantic models for ClusterScope, BeliefTrajectory, etc.
    belief_trajectory  — Extract classification evolution from bitemporal trace store
    evidence_frame     — TemporalRAG-bounded evidence retrieval per cluster
    narrative_synthesis— Per-cluster narrative generation with structured citation
    grounding_validator— Deterministic + semantic claim-to-evidence verification
    rollup_synthesis   — Assessment-level rollup from cluster narratives
    persona_adapters   — Reframe cluster narratives for different audiences
"""
