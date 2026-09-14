"""Structured-slot LLM narration for the executive summary (Step 2).

The deterministic 3-paragraph summary (finding_summary.build_finding_summary) already
contains every fact — window, entities, damage, complexity, actions, controls. This
layer asks the LLM ONLY to rewrite that draft into more fluent prose, in exactly the
same three paragraphs, using ONLY the facts already present. The output is validated
against the deterministic draft: any entity-shaped token or MITRE code the model
introduces that is not in the draft causes a fall back to the deterministic text. The
LLM is therefore an optional polish, never load-bearing — if it is unavailable, times
out, or drifts, the guaranteed deterministic brief ships.
"""
from __future__ import annotations

import json
import logging
import os
import re

logger = logging.getLogger(__name__)

_ENABLED = lambda: os.getenv("JANUSEC_GRC_LLM_SUMMARY", "1").lower() in {"1", "true", "yes"}
_TIMEOUT = float(os.getenv("JANUSEC_GRC_SUMMARY_TIMEOUT_S", "60"))
_MODEL = os.getenv("JANUSEC_GRC_SUMMARY_MODEL") or os.getenv("JANUSEC_T2_NARRATOR_MODEL", "qwen2.5:14b")


def _build_prompt(summary: dict) -> str:
    det = summary.get("paragraphs") or []
    occ = summary.get("occurred") or {}
    facts = {
        "actor": occ.get("actor"), "verdict": occ.get("verdict"),
        "start": occ.get("start"), "end": occ.get("end"), "duration": occ.get("duration"),
        "kill_chain": occ.get("kill_chain"),
        "affected_identities": occ.get("affected_identities"),
        "affected_hosts": occ.get("affected_hosts"),
        "asset_classes": occ.get("asset_classes"),
        "data_scope": occ.get("data_scope"),
        "damage_level": occ.get("damage_level"),
        "complexity": occ.get("complexity_label"),
        "do_next": [f'[{a.get("priority")}/{a.get("sla_hours")}h] {a.get("action")}' for a in (summary.get("do_next") or [])[:6]],
        "controls_affected": summary.get("controls_affected"),
    }
    return (
        "You are writing an executive breach summary for a CISO / board reader. You are "
        "given VERIFIED FACTS and a correct DRAFT. Rewrite the draft as EXACTLY THREE "
        "short paragraphs with clearer, plainer wording.\n\n"
        "HARD RULES:\n"
        f"- Name the responsible actor explicitly as \"{(summary.get('occurred') or {}).get('actor')}\" — "
        "do NOT anonymise them to 'the user' or 'the account'.\n"
        "- Use ONLY the facts below. Do NOT introduce any host, IP, domain, username, "
        "number, date, MITRE code, or control ID that is not in the facts/draft.\n"
        "- Paragraph 1 = what happened (timeframe, actor, how, what was affected, damage, "
        "how easy the attack was).\n"
        "- Paragraph 2 = what to do next (the actions, keep the priority/SLA).\n"
        "- Paragraph 3 = which controls were affected.\n"
        "- Plain and direct. No markdown, no headings.\n\n"
        f"VERIFIED FACTS:\n{json.dumps(facts, indent=1)}\n\n"
        "DRAFT (already correct — improve wording, keep every fact):\n"
        + "\n".join(f"P{i}: {p}" for i, p in enumerate(det, 1))
        + '\n\nRespond ONLY with JSON: {"paragraphs": ["<p1>", "<p2>", "<p3>"]}'
    )


def _parse_paragraphs(raw: str) -> list[str]:
    if not raw:
        return []
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return []
    try:
        obj = json.loads(m.group(0))
    except Exception:
        return []
    paras = obj.get("paragraphs")
    if isinstance(paras, list):
        return [str(p).strip() for p in paras if str(p).strip()]
    return []


def _is_grounded(candidate_paras: list[str], draft_paras: list[str], finding_mitre=None) -> bool:
    """The rewrite is grounded iff it introduces no entity-shaped token or MITRE code
    absent from the deterministic draft."""
    try:
        from src.core.ingest.entity_constraints import scrub_ungrounded_entities, correct_mitre_ids
    except Exception:
        return True  # can't validate -> accept (deterministic draft was the input anyway)
    haystack = " ".join(draft_paras)
    allowed_mitre = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", haystack)) | {str(m).upper() for m in (finding_mitre or [])}
    for p in candidate_paras:
        _, redactions = scrub_ungrounded_entities(p, [{"_facts": haystack}])
        if redactions:
            logger.debug("grc summary narration rejected — ungrounded entity: %s", [r["original"] for r in redactions])
            return False
        _, removed = correct_mitre_ids(p, allowed_mitre) if allowed_mitre else (p, [])
        # if there are no allowed MITRE codes, any T-code in output is ungrounded
        if not allowed_mitre and re.search(r"\bT\d{4}(?:\.\d{3})?\b", p):
            return False
        if removed:
            return False
    return True


def narrate_summary(summary: dict, *, client=None, finding_mitre=None) -> dict:
    """Return the summary with LLM-polished paragraphs when they validate against the
    deterministic draft, else the deterministic paragraphs. Adds narration_source."""
    det = summary.get("paragraphs") or []
    if len(det) < 3 or not _ENABLED():
        return {**summary, "narration_source": "deterministic"}
    if client is None:
        try:
            from src.integrations.llm_client import DEFAULT_CLIENT as client
        except Exception:
            return {**summary, "narration_source": "deterministic"}
    try:
        result = client.generate(
            _build_prompt(summary), max_tokens=700, model=_MODEL,
            overrides={"timeout": _TIMEOUT, "retries": 0},
        )
        raw = result if isinstance(result, str) else (result or {}).get("text") or ""
        paras = _parse_paragraphs(raw)
        joined = " ".join(paras).lower()
        actor = str((summary.get("occurred") or {}).get("actor") or "").lower()
        # Stay-on-topic check (NOT a hallucination guard — entity grounding below is):
        # accept the actor in any reasonable form (case-insensitive, or its localpart,
        # e.g. 'Martin Chen' for 'martin.chen').
        actor_ok = bool(actor) and (actor in joined or actor.split(".")[0] in joined)
        if len(paras) == 3 and actor_ok and _is_grounded(paras, det, finding_mitre):
            return {**summary, "paragraphs": paras, "narration_source": "llm"}
        logger.info("grc summary narration fell back to deterministic (invalid/ungrounded)")
    except Exception as exc:
        logger.debug("grc summary narration failed: %s", exc)
    return {**summary, "narration_source": "deterministic"}
