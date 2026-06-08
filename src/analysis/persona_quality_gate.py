from __future__ import annotations

import re


def summary_sections_useful(sections: dict) -> bool:
    useful_keys = ("what_is_happening", "why_it_matters", "what_to_do", "investigate_next", "verdict_line")
    return any(str(sections.get(key) or "").strip() for key in useful_keys)


def summary_sections_complete_for_elevated(sections: dict) -> bool:
    required = ("what_is_happening", "why_it_matters", "investigate_next", "verdict_line")
    return all(str(sections.get(key) or "").strip() for key in required)


_ACTION_VERBS = re.compile(
    r"\b(block|isolate|alert|query|run|check|review|confirm|investigate|revoke|reset|"
    r"escalate|contain|hunt|pivot|correlate|verify|remediate|disable|monitor|collect)\b",
    re.IGNORECASE,
)
_ROW_REF_PAT = re.compile(r"\brow\[?\d+\]?|\bR\d{2,}|\b#\d{2,}|\[\d{2,}\]")
_ENTITY_PAT = re.compile(
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    r"|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}"
    r"|[a-zA-Z0-9-]{2,}\.[a-zA-Z]{2,6}\b"
    r"|[A-Z][A-Z0-9_-]{3,}"
)


def output_grounding_score(sections: dict) -> int:
    """Return 0-3 based on row citation, entity citation, and actionability."""
    combined = " ".join(
        str(sections.get(key) or "")
        for key in ("what_is_happening", "why_it_matters", "what_to_do", "investigate_next", "verdict_line")
    )
    score = 0
    if _ROW_REF_PAT.search(combined):
        score += 1
    if _ENTITY_PAT.search(combined):
        score += 1
    if _ACTION_VERBS.search(combined):
        score += 1
    return score
