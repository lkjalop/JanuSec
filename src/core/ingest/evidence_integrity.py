"""Evidence-integrity verification + adversarial re-verification loop.

Addresses the platform's measured brittleness in the LLM narrative path:

  1. Entity hallucination — a 14B model invents plausible host/domain names that are
     not in the evidence (VESPER benchmark: qwen2.5:14b produced the correct
     VALIDATED_BREACH verdict but hallucinated svr-db-01 / svr-file-01 / vesper.local).
     The existing _validate_ioc_grounding only ANNOTATES, and its substring check
     (`short in haystack`) lets a fabricated `admin.corp` pass whenever `admin` appears
     anywhere in evidence.

  2. Swallowed evidence — a cluster asserts a shared entity (user/host/ip) for which
     NO supporting row survived to the LLM, so the narrative is built on a claim with
     no backing evidence (information lost upstream).

This module provides a deterministic verifier and a bounded regenerate loop so a
factually-incorrect narrative is caught, re-generated with the violations fed back,
and — only if still wrong — replaced by a deterministic fallback and flagged, never
published silently.

Design notes:
  * Grounding uses token-boundary matching, not substring, fixing the escape above.
  * The regenerate/critic/fallback steps are injected as callables so the whole loop
    is testable without a live LLM.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

_MITRE_ID_RE = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)

# Entity candidate extraction (mirrors _validate_ioc_grounding so the runtime gate
# and the offline scorer agree on what counts as an entity).
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_FQDN_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]{2,}\.[A-Za-z][A-Za-z0-9]{2,}\b")
_DASH_HOST_RE = re.compile(r"\b[A-Za-z]{2,4}-[A-Za-z0-9]{2,}-\d+\b")
# Token = a dotted/dashed compound OR a bare alphanumeric word, from evidence values.
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_CITATION_RE = re.compile(r"\[(\d+)\]")


@dataclass
class EvidenceIntegrityReport:
    ok: bool
    score: float
    ungrounded_entities: list[str] = field(default_factory=list)
    swallowed_claims: list[str] = field(default_factory=list)
    citation_count: int = 0
    required_citations: int = 0
    candidate_entities: int = 0
    issues: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "score": self.score,
            "ungrounded_entities": self.ungrounded_entities,
            "swallowed_claims": self.swallowed_claims,
            "citation_count": self.citation_count,
            "required_citations": self.required_citations,
            "candidate_entities": self.candidate_entities,
            "issues": self.issues,
        }

    def feedback(self) -> str:
        """A prompt fragment describing the violations, to feed a regeneration."""
        parts: list[str] = []
        if self.ungrounded_entities:
            parts.append(
                "These names are NOT present in the evidence and must be removed or "
                "replaced with an entity that is cited in the evidence rows: "
                + ", ".join(self.ungrounded_entities)
            )
        if self.citation_count < self.required_citations:
            parts.append(
                f"Cite at least {self.required_citations} evidence rows by [row_index]; "
                f"only {self.citation_count} were cited."
            )
        if self.swallowed_claims:
            parts.append(
                "Do not assert these entities — no supporting evidence row is present "
                "for them: " + ", ".join(self.swallowed_claims)
            )
        return " ".join(parts)


def _narrative_text(narrative: dict) -> str:
    return " ".join(
        str(narrative.get(k) or "")
        for k in ("attack_narrative", "ioc_summary", "what_happened", "root_cause")
    )


def _evidence_token_set(evidence_rows: list[dict]) -> set[str]:
    tokens: set[str] = set()
    for row in evidence_rows or []:
        if not isinstance(row, dict):
            continue
        for v in row.values():
            if isinstance(v, str):
                blob = v.lower()
            elif isinstance(v, (int, float, bool)):
                blob = str(v).lower()
            elif isinstance(v, (list, dict)):
                try:
                    blob = json.dumps(v).lower()
                except (TypeError, ValueError):
                    continue
            else:
                continue
            tokens.update(_TOKEN_RE.findall(blob))
    return tokens


def _narrative_entities(narrative: dict) -> set[str]:
    text = _narrative_text(narrative)
    if not text.strip():
        return set()
    cands: set[str] = set()
    for rx in (_IP_RE, _FQDN_RE, _DASH_HOST_RE):
        for tok in rx.findall(text):
            cands.add(tok.lower())
    return {c for c in cands if not _MITRE_ID_RE.match(c)}


def _is_grounded(entity: str, evidence_tokens: set[str]) -> bool:
    """Token-boundary grounding: entity is grounded iff it is a whole evidence token
    or a dot/dash-delimited segment of one. This replaces the old substring check that
    grounded `admin.corp` whenever `admin` appeared anywhere."""
    if entity in evidence_tokens:
        return True
    for tok in evidence_tokens:
        if (
            tok.endswith("." + entity)
            or tok.endswith("-" + entity)
            or tok.startswith(entity + ".")
            or tok.startswith(entity + "-")
            or ("." + entity + ".") in tok
            or ("-" + entity + "-") in tok
        ):
            return True
    return False


def _count_citations(narrative: dict) -> int:
    refs = narrative.get("_llm_evidence_refs") or narrative.get("evidence_row_ids")
    if isinstance(refs, (list, tuple, set)):
        n = len({r for r in refs if isinstance(r, int)})
        if n:
            return n
    return len(set(_CITATION_RE.findall(_narrative_text(narrative))))


def _cluster_shared_entities(cluster: Optional[dict]) -> list[str]:
    if not isinstance(cluster, dict):
        return []
    out: list[str] = []
    for key in ("shared_users", "shared_accounts", "shared_hosts", "shared_ips"):
        for v in cluster.get(key) or []:
            if isinstance(v, str) and v.strip():
                out.append(v.strip().lower())
    return out


def check_evidence_integrity(
    narrative: dict,
    evidence_rows: list[dict],
    cluster: Optional[dict] = None,
    *,
    min_citations: int = 3,
    full_evidence_rows: Optional[list[dict]] = None,
) -> EvidenceIntegrityReport:
    """Deterministically verify a narrative against its evidence.

    Flags (a) entity names in the narrative absent from the evidence the LLM saw
    (hallucination), (b) a citation shortfall, and (c) cluster-claimed shared entities
    with no supporting row ANYWHERE (swallowed/lost evidence).

    Hallucination is checked against `evidence_rows` (what the model was shown), but a
    swallowed-claim is checked against `full_evidence_rows` when provided (the whole
    cluster) so an entity merely deselected by the evidence cap is not mistaken for
    lost evidence. Returns a structured report; never raises."""
    evidence_tokens = _evidence_token_set(evidence_rows)
    entities = _narrative_entities(narrative)
    ungrounded = sorted(e for e in entities if not _is_grounded(e, evidence_tokens))

    citation_count = _count_citations(narrative)

    # Swallowed-claim detection grounds against the FULL cluster evidence when given.
    claim_tokens = _evidence_token_set(full_evidence_rows) if full_evidence_rows else evidence_tokens
    swallowed: list[str] = []
    for ent in _cluster_shared_entities(cluster):
        if not _is_grounded(ent, claim_tokens):
            swallowed.append(ent)

    issues: list[str] = []
    if ungrounded:
        issues.append(f"{len(ungrounded)} ungrounded entity name(s): {', '.join(ungrounded)}")
    if citation_count < min_citations:
        issues.append(f"only {citation_count}/{min_citations} evidence citations")
    if swallowed:
        issues.append(f"{len(swallowed)} claimed entity/entities lack any evidence row: {', '.join(swallowed)}")

    # Score: 1.0 perfect; penalise each class. Grounding is weighted highest.
    total_ent = max(1, len(entities))
    grounding_score = 1.0 - (len(ungrounded) / total_ent)
    citation_score = min(1.0, citation_count / max(1, min_citations))
    swallow_score = 0.0 if swallowed else 1.0
    score = round(0.6 * grounding_score + 0.2 * citation_score + 0.2 * swallow_score, 3)

    ok = not ungrounded and citation_count >= min_citations and not swallowed
    return EvidenceIntegrityReport(
        ok=ok,
        score=score,
        ungrounded_entities=ungrounded,
        swallowed_claims=swallowed,
        citation_count=citation_count,
        required_citations=min_citations,
        candidate_entities=len(entities),
        issues=issues,
    )


def regenerate_until_grounded(
    narrative: dict,
    evidence_rows: list[dict],
    cluster: Optional[dict],
    regenerate_fn: Optional[Callable[[str, dict], dict]] = None,
    *,
    min_citations: int = 3,
    max_retries: int = 1,
    critic_fn: Optional[Callable[[dict], dict]] = None,
    fallback_fn: Optional[Callable[[dict, EvidenceIntegrityReport], dict]] = None,
    full_evidence_rows: Optional[list[dict]] = None,
) -> tuple[dict, EvidenceIntegrityReport, dict]:
    """Bounded adversarial re-verification loop.

    1. Verify the narrative's evidence integrity.
    2. While it fails and retries remain, call regenerate_fn(feedback, narrative) to
       produce a fresh narrative (the caller re-runs the LLM with the violations fed
       back), then re-verify.
    3. Optionally run critic_fn on the surviving narrative.
    4. If still failing, apply fallback_fn (deterministic narrative) and mark the
       narrative `_integrity_degraded` with the reasons — nothing is published clean.

    All callbacks are optional so the loop is unit-testable without a live LLM.
    Returns (narrative, final_report, meta)."""
    meta: dict[str, Any] = {"attempts": 0, "regenerated": False, "critic": None, "fell_back": False}
    report = check_evidence_integrity(narrative, evidence_rows, cluster, min_citations=min_citations, full_evidence_rows=full_evidence_rows)

    attempt = 0
    while not report.ok and regenerate_fn is not None and attempt < max_retries:
        attempt += 1
        meta["attempts"] = attempt
        feedback = report.feedback()
        logger.info("evidence_integrity: regenerating narrative (attempt %d) — %s", attempt, "; ".join(report.issues))
        try:
            new_narrative = regenerate_fn(feedback, narrative)
        except Exception as exc:  # regeneration failure — keep the prior narrative
            logger.debug("evidence_integrity: regenerate_fn failed: %s", exc)
            break
        if isinstance(new_narrative, dict) and new_narrative:
            narrative = new_narrative
            meta["regenerated"] = True
            report = check_evidence_integrity(narrative, evidence_rows, cluster, min_citations=min_citations, full_evidence_rows=full_evidence_rows)

    if critic_fn is not None:
        try:
            meta["critic"] = critic_fn(narrative)
        except Exception as exc:
            logger.debug("evidence_integrity: critic_fn failed: %s", exc)

    if not report.ok:
        # Still not grounded after retries. Fall back if possible, and always flag.
        if fallback_fn is not None:
            try:
                fb = fallback_fn(narrative, report)
                if isinstance(fb, dict) and fb:
                    narrative = fb
                    meta["fell_back"] = True
                    # Re-verify the fallback so the report reflects what actually ships.
                    report = check_evidence_integrity(narrative, evidence_rows, cluster, min_citations=min_citations, full_evidence_rows=full_evidence_rows)
            except Exception as exc:
                logger.debug("evidence_integrity: fallback_fn failed: %s", exc)
        narrative["_integrity_degraded"] = True
        narrative["_integrity_issues"] = report.issues
    narrative["_evidence_integrity"] = report.as_dict()
    return narrative, report, meta
