# System Overview

JanuSec is an AI-powered pre-SIEM triage platform that ingests multi-domain telemetry, applies a 30-stage event pipeline, and produces explainable triage outputs (T1/T2) and correlation graphs (HopGraph).

This document summarizes the system components and dataflow at a high level. Implementation details and sensitive heuristics are intentionally omitted from this public repository.

Components:
- Ingest: connectors for cloud providers, endpoint telemetry, network feeds, threat intel and SBOM data.
- Event Pipeline: 30 stages including enrichment, heavy analysis stages, correlation and embedding.
- HopGraph: graph model used for attack reconstruction and lateral movement visualization.
- LLM Summaries: T1 (fast triage) and T2 (deep investigation) with persona-based outputs and budget gating.
- Storage: tiered storage model (hot/warm/cold) and per-tenant quotas.

For more detail, see `detection-pipeline.md` and `correlation-engine.md`.
