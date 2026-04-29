"""
Section 4 — SABSA Architecture & Policy Implications
====================================================

v1 status: STUB

In v2 this section will produce:
  - SABSA business attributes breached (confidentiality, availability,
    integrity, accessible, accurate, assured, etc.)
  - Trace from violated business attribute to required architecture pattern
  - Policy library deltas — which policies need amendment given this failure
  - Architectural recommendations grouped by SABSA layer
    (contextual / conceptual / logical / physical / component / operational)

In v1 we pass through whatever the existing dread_narrative pipeline produced
in ``narrative['dread_narrative']['sabsa_attributes']`` and the
``sabsa_coda_draft`` paragraph that the narrative renderer composed. This is
already in production via prefill_engine.py; we just surface it here so
Section 4 isn't completely empty.

CONTRACT
--------
Even as a stub we MUST emit ``sabsa_attributes`` because Section 6's NDB
form pre-fill checks this list when classifying breach impact for the
``kinds_of_information_involved`` field.
"""
from __future__ import annotations


def build_s4_sabsa_architecture(
    *,
    cluster: dict,
    narrative: dict,
    register: dict,
    evidence_rows: list[dict],
    tenant_config: dict,
    entity_context: dict,
) -> dict:
    """Stub that lifts existing SABSA coda from dread_narrative."""
    dread = narrative.get("dread_narrative") or {}
    sabsa_attributes = list(dread.get("sabsa_attributes") or [])
    sabsa_coda_draft = (dread.get("sabsa_coda_draft") or "").strip()
    rendered_with_coda = (dread.get("rendered") or "").strip()

    # Try to extract the SABSA paragraph from the rendered narrative if
    # present — it's marked with "Business consequence." per the prompt
    # template in dread_narrative_render.txt.
    sabsa_paragraph = None
    if "Business consequence." in rendered_with_coda:
        idx = rendered_with_coda.find("Business consequence.")
        sabsa_paragraph = rendered_with_coda[idx:].strip()

    auto_output = {
        "sabsa_attributes_breached": sabsa_attributes,
        "sabsa_coda_draft":          sabsa_coda_draft,
        "sabsa_paragraph_rendered":  sabsa_paragraph,
        # Populated in v2 — placeholders for the schema.
        "architectural_changes":     [],
        "policy_deltas":             [],
        "sabsa_layers_affected":     [],
        "v1_note":                   "Architectural recommendations and policy deltas arrive in v2. "
                                     "The SABSA attribute list and coda paragraph above are surfaced "
                                     "from the existing dread_narrative pipeline (see prefill_engine.py).",
    }
    return {
        "title": "SABSA Architecture & Policy Implications",
        "auto_output": auto_output,
    }
