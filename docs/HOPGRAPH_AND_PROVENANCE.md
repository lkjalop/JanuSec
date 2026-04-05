Hopgraph / APT mapping guidance & factor->technique provenance

This short doc explains how technique provenance and hopgraph-style enrichment are represented in the codebase.

Core concepts
- factor: a detection signal emitted by hunters (e.g., `ssl:ja3_rare`, `http:host_mismatch`).
- technique (ATT&CK id, or internal tag): a named technique like `T1059` or `lateral:mimikatz`.
- provenance: the mapping of which sources (feeds/hunters) contributed to a technique association.

Where it's stored
- `ThreatIntelClient.factor_techniques` is a dict mapping factor keys to lists of technique ids. This is persisted to `data/ti_factor_techniques.json` if available.
- `ThreatIntelClient._technique_provenance` is a nested dict of the form { factor: { technique_id: set([sources]) } }.
  - This structure is converted to lists for API exposure via `technique_provenance()`.

How to add mappings
1. Add an entry programmatically (runtime):
   - `client.factor_techniques.setdefault('ssl:ja3_rare', []).append('T1059')`
   - `client._technique_provenance.setdefault('ssl:ja3_rare', {}).setdefault('T1059', set()).add('opencti')`
2. Persisted technique lists can be loaded from `data/ti_factor_techniques.json` on startup; follow the existing loader semantics.

Design notes
- Keep provenance sets small and de-duplicated; they are used to compute confidence and to explain why a technique was suggested for an incident.
- Hopgraph enrichment: actors/campaigns should be associated through a separate mapping service or DB (not stored directly on the client) and queried lazily by the API layer to avoid heavy memory use.
- If you need to correlate across events (multi-hop), implement a separate graph service that consumes `ThreatIntelClient`'s outputs and stores aggregated edges.

Operational advice
- Use conservative default weights for automated blocking decisions; provenance can be surfaced for human review.
- Expose `technique_provenance()` via the API when building explainability UIs.
