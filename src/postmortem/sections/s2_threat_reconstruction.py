"""
Section 2 — Threat Reconstruction (MITRE + STRIDE)
==================================================

v1 status: STUB

In v2 this section will produce:
  - Per-phase MITRE ATT&CK technique chain with row evidence
  - STRIDE per stage (what trust assumption was violated)
  - Visibility gap analysis (what telemetry was missing that would have
    caught it earlier)

In v1 we emit a minimal pass-through so downstream sections (especially s3
and s7) that depend on technique lists keep working. The UI renders this
section with an "Available in v2" badge.

CONTRACT WITH s3 AND s7
-----------------------
Even though this is a stub, we MUST emit ``mitre_techniques`` in
auto_output. s3 and s7 read this rather than reaching back into the
narrative directly, so when v2 lands and the techniques get re-derived
with phase tagging, s3 and s7 don't need to change.
"""
from __future__ import annotations


def build_s2_threat_reconstruction(
    *,
    cluster: dict,
    narrative: dict,
    register: dict,
    evidence_rows: list[dict],
    tenant_config: dict,
    entity_context: dict,
) -> dict:
    """Stub that maintains the dependency contract with s3, s7."""
    techniques = list(narrative.get("mitre_techniques") or [])
    kill_chain_stage = narrative.get("kill_chain_stage") or "unknown"

    # Minimal pass-through so downstream sections still resolve.
    auto_output = {
        "mitre_techniques":      techniques,
        "kill_chain_stage":      kill_chain_stage,
        "phases":                [],   # populated in v2
        "stride_per_stage":      [],   # populated in v2
        "visibility_gaps":       [],   # populated in v2
        "threat_actor_profile":  None, # populated in v2
        "v1_note":               "Threat reconstruction with phase-by-phase MITRE + STRIDE arrives in v2. "
                                 "The technique list above is the raw set surfaced by the cluster narrative.",
    }
    return {
        "title": "Threat Reconstruction (MITRE ATT&CK + STRIDE)",
        "auto_output": auto_output,
    }
