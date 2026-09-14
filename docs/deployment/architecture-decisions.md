# Architecture Decisions

This document records high-level architecture decisions and their rationale. Details that contain proprietary heuristics are omitted.

Key decisions:
- Pre-SIEM triage: Reduce SIEM ingestion by filtering noise upstream.
- Explainable factor engine: Use deterministic factors with provenance to satisfy regulatory needs.
- Tiered storage: Hot/Warm/Cold to optimize cost/performance.
- Heavy stage gating: Per-event confidence-based skipping to control compute.
- SBOM runtime fusion: Correlate SBOM inventory with runtime telemetry for active exploitation detection.

These choices prioritize explainability, cost efficiency, and multi-domain correlation.
