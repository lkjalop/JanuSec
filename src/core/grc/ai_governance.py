"""AI-governance self-assessment (G3 — the 'reference implementation of governed AI').

Maps the platform's OWN AI decisions and the controls it applies to them onto
ISO/IEC 42001 (AI management), the EU AI Act, and MAESTRO (agentic-AI threat model).
This is a platform-level posture description, NOT a per-input mapping table, so it is
robust by construction — it does not depend on which detectors fired.

It is deliberately evidence-linked: each control cites the concrete mechanism in the
codebase that implements it (deterministic verdict floor, entity-constrained grounding,
provenance, human-in-the-loop), and each is marked implemented / partial / planned so
the posture is honest rather than aspirational.
"""
from __future__ import annotations

from typing import Any

# Each control: how JanuSec governs its own AI, the frameworks it satisfies, the
# code mechanism that implements it, and an honest status.
_AI_CONTROLS: list[dict[str, Any]] = [
    {
        "id": "AIG-1", "title": "Human decision authority — AI narrates, determinism decides",
        "mechanism": "The breach verdict is set by deterministic detectors/correlation; the LLM only "
                     "narrates it and cannot upgrade or invent a verdict (verdict rank-merge, confidence floor).",
        "iso42001": ["A.9.2", "A.6.2.6"], "eu_ai_act": ["Art.14 Human oversight"],
        "maestro": ["L7 Agent ecosystem"], "status": "implemented",
    },
    {
        "id": "AIG-2", "title": "Output grounding — no fabricated entities",
        "mechanism": "Entity-constrained generation + deterministic scrub: any host/IP/domain/user in the "
                     "narrative not present in the evidence is substituted or redacted before it ships.",
        "iso42001": ["A.8.3", "A.6.2.4"], "eu_ai_act": ["Art.15 Accuracy & robustness"],
        "maestro": ["L2 Data operations"], "status": "implemented",
    },
    {
        "id": "AIG-3", "title": "Deterministic technique/verdict correctness over LLM guesses",
        "mechanism": "MITRE technique IDs and DREAD-derived priority come from deterministic maps, not the "
                     "LLM; wrong LLM T-codes are stripped.",
        "iso42001": ["A.8.3"], "eu_ai_act": ["Art.15 Accuracy"],
        "maestro": ["L4 Deployment & infra"], "status": "implemented",
    },
    {
        "id": "AIG-4", "title": "Provenance & traceability of every AI claim",
        "mechanism": "Each narrative claim carries cited evidence row indices (a subset of the fed provenance); "
                     "findings link claim -> evidence -> control.",
        "iso42001": ["A.6.2.8", "A.9.2"], "eu_ai_act": ["Art.12 Record-keeping", "Art.13 Transparency"],
        "maestro": ["L6 Security & compliance"], "status": "implemented",
    },
    {
        "id": "AIG-5", "title": "Graceful degradation — LLM is optional, not load-bearing",
        "mechanism": "The executive summary and narrative fall back to a deterministic render when the LLM is "
                     "unavailable, times out, or drifts; the assessment is never empty or blocked on the model.",
        "iso42001": ["A.8.4"], "eu_ai_act": ["Art.15 Robustness"],
        "maestro": ["L5 Evaluation & observability"], "status": "implemented",
    },
    {
        "id": "AIG-6", "title": "Prompt-injection defence on attacker-controlled input",
        "mechanism": "Evidence rows (attacker-influenced log fields) are sanitised before entering the prompt.",
        "iso42001": ["A.8.2"], "eu_ai_act": ["Art.15 Robustness"],
        "maestro": ["L1 Foundation models", "L2 Data operations"], "status": "implemented",
    },
    {
        "id": "AIG-7", "title": "Data sovereignty — local inference, no egress",
        "mechanism": "Local LLM (Ollama) by default; self-hosted/air-gapped deployment so telemetry and "
                     "inference never leave the network.",
        "iso42001": ["A.7.4"], "eu_ai_act": ["Art.10 Data governance"],
        "maestro": ["L4 Deployment & infra"], "status": "implemented",
    },
    {
        "id": "AIG-8", "title": "Adversarial verification of AI output",
        "mechanism": "An adversarial critic pass and an evidence-integrity gate re-check the narrative for "
                     "false-positive probability and ungrounded claims.",
        "iso42001": ["A.6.2.5", "A.6.2.6"], "eu_ai_act": ["Art.9 Risk management"],
        "maestro": ["L5 Evaluation & observability"], "status": "implemented",
    },
    {
        "id": "AIG-9", "title": "Model/version + evaluation record",
        "mechanism": "Narrator model and elapsed time are recorded per narrative; an acceptance harness "
                     "gates correctness. Continuous bias/drift monitoring is not yet automated.",
        "iso42001": ["A.6.2.7", "A.9.3"], "eu_ai_act": ["Art.9 Risk management", "Art.61 Post-market monitoring"],
        "maestro": ["L5 Evaluation & observability"], "status": "partial",
    },
]

# MAESTRO layers relevant to the AI/agent attack surface the platform DETECTS
# (as opposed to its own governance above).
_MAESTRO_LAYERS = {
    "L1": "Foundation models", "L2": "Data operations", "L3": "Agent frameworks",
    "L4": "Deployment & infrastructure", "L5": "Evaluation & observability",
    "L6": "Security & compliance", "L7": "Agent ecosystem",
}


def ai_governance_posture() -> dict[str, Any]:
    """The platform's AI-governance self-assessment: controls, framework coverage, and
    an honest implemented/partial tally."""
    controls = list(_AI_CONTROLS)
    iso = sorted({c for ctl in controls for c in ctl["iso42001"]})
    eu = sorted({c for ctl in controls for c in ctl["eu_ai_act"]})
    maestro = sorted({m for ctl in controls for m in ctl["maestro"]})
    implemented = sum(1 for c in controls if c["status"] == "implemented")
    return {
        "controls": controls,
        "maestro_layers": _MAESTRO_LAYERS,
        "summary": {
            "total_controls": len(controls),
            "implemented": implemented,
            "partial": sum(1 for c in controls if c["status"] == "partial"),
            "planned": sum(1 for c in controls if c["status"] == "planned"),
            "iso42001_controls": iso,
            "eu_ai_act_articles": eu,
            "maestro_layers_covered": maestro,
        },
    }


def ai_surface_maestro(audit_pack: dict) -> dict[str, Any]:
    """Map any AI/agent-surface techniques DETECTED in this assessment onto MAESTRO
    layers (reuses the finding phases; coarse layer-level mapping, not per-technique)."""
    ai_phase_layer = {
        "mcp_tool_abuse": ["L3", "L7"], "prompt_injection": ["L1", "L2"],
        "ai_security": ["L1", "L5"],
    }
    hits: dict[str, list[str]] = {}
    for f in audit_pack.get("findings", []):
        for p in f.get("phases", []) if isinstance(f.get("phases"), list) else []:
            for layer in ai_phase_layer.get(str(p), []):
                hits.setdefault(layer, [])
                if f.get("actor") not in hits[layer]:
                    hits[layer].append(f.get("actor"))
    return {"detected_ai_surface": {_MAESTRO_LAYERS.get(k, k): v for k, v in hits.items()}}
