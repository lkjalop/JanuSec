"""AdversarialCritic — second-pass LLM agent that challenges cluster narratives.

The critic receives the narrator's verdict + evidence and attempts to falsify it.
Its job is *not* to produce a different verdict — it's to surface the strongest
counter-argument so the analyst can decide whether the narrator was too hasty.

The critic runs as a separate, low-temperature LLM call after ``narrate_cluster``
completes.  It is gated behind ``ENABLE_ADVERSARIAL_CRITIC`` (defaults to "1")
so it can be disabled in resource-constrained environments.

Attach point: ``cluster_narrator.narrate_cluster()`` calls
``AdversarialCritic().critique(cluster, narrative, evidence_rows)`` and stores
the result under ``cluster["_critic"]``.

Critic output schema (stored in ``cluster["_critic"]``):
    {
        "challenge":          str,    # 2-4 sentence counter-argument
        "fp_probability":     float,  # 0.0-1.0
        "confidence_delta":   float,  # how much the critic would move confidence
        "weakest_evidence":   [str],  # evidence snippets the critic finds weakest
        "verdict":            str,    # critic's own verdict (may differ from narrator)
        "mitre_check":        dict,   # {"claimed": [...], "unsupported": [...]}
        "citation_count":     int,    # how many evidence_refs in the narrative
        "low_citation":       bool,   # True when citation_count < 3
        "model":              str,    # which model ran the critique
        "tokens_used":        int,
        "skipped":            bool,   # True if critic was disabled or errored
        "skip_reason":        str,
    }
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

_CRITIC_ENABLED_DEFAULT = "1"
_CRITIC_LOCK = threading.Lock()

_SYSTEM_PROMPT = """\
You are an adversarial security analyst. Your ONLY job is to challenge the
verdict produced by a first-pass analyst.  You are not being asked to confirm
the verdict — you are being asked to find the strongest reason it might be
WRONG.

Rules:
1. Read the cluster data and evidence carefully.
2. Identify the weakest pieces of supporting evidence.
3. Propose the most plausible benign or alternative explanation.
4. MITRE VALIDATION: Check each claimed MITRE technique against the evidence.
   If the evidence does not contain artifacts that support a claimed technique
   (e.g., T1558.003 requires RC4 Kerberos tickets in the evidence), name it as
   unsupported and reduce confidence accordingly.
5. IOC HALLUCINATION CHECK: If the narrator narrative mentions specific IPs,
   usernames, or hostnames that do NOT appear in the evidence rows provided,
   flag them as hallucinated IOCs. This significantly increases FP probability.
6. EVIDENCE CITATION CHECK: If fewer than 3 evidence rows are cited, treat the
   narrative as under-evidenced and penalise fp_probability by +0.15.
7. Output ONLY valid JSON — no prose, no markdown.
"""

_USER_TEMPLATE = """\
NARRATOR VERDICT: {verdict} (confidence={confidence:.2f})
NARRATOR NARRATIVE: {attack_narrative}
NARRATOR CLAIMED MITRE TECHNIQUES: {mitre}
NARRATOR FP INDICATORS: {fp_indicators}
NARRATOR EVIDENCE CITATIONS: {citation_count} row(s) cited (minimum expected: 3)

PRE-VALIDATION FLAGS (computed deterministically before this call):
{pre_validation_block}

CLUSTER ENTITIES:
  Users: {users}
  Hosts: {hosts}
  IPs:   {ips}

TOP EVIDENCE (up to 15 rows):
{evidence_block}

Now produce your adversarial critique. For each claimed MITRE technique, verify
it appears in the evidence. List any that are unsupported under
"mitre_unsupported". Flag IOC hallucinations if entities named in the narrative
do not appear in any evidence row above.

Respond ONLY with valid JSON:
{{
  "challenge": "<2-4 sentences: the strongest counter-argument to the narrator verdict>",
  "fp_probability": <float 0.0-1.0 — probability this is a false positive>,
  "confidence_delta": <float -0.5 to 0.0 — how much you would reduce narrator confidence>,
  "weakest_evidence": ["<row snippet 1>", "<row snippet 2>"],
  "mitre_unsupported": ["<T-ID not grounded in evidence>"],
  "hallucinated_iocs": ["<entity name found in narrative but absent from evidence rows>"],
  "verdict": "<your verdict: VALIDATED_BREACH | SUSPECTED_BREACH | BENIGN_EXPECTED | REQUIRES_INVESTIGATION | INSUFFICIENT_EVIDENCE>"
}}"""


def _evidence_block(evidence_rows: list[dict], cap: int = 15) -> str:
    lines = []
    for i, r in enumerate(evidence_rows[:cap]):
        ts = str(r.get("timestamp") or r.get("_ts_epoch") or "?")[:19]
        user = str(r.get("user_canonical") or r.get("user") or "-")[:20]
        src = str(r.get("src_ip") or r.get("ip") or "-")[:16]
        event = str(
            r.get("event_type") or r.get("action") or r.get("process_name") or "-"
        )[:40]
        score = float(r.get("triage_score") or 0)
        lines.append(f"  {i+1:2d}. [{ts}] {user:<20s} {src:<16s} {event} (score={score:.2f})")
    return "\n".join(lines) or "  (no evidence rows)"


def _extract_evidence_entities(evidence_rows: list[dict]) -> Set[str]:
    """Extract all user/IP/host values from evidence for hallucination checking.

    Delegates to the canonical extractor so the critic and the narrator use the SAME
    field list and normalization — previously the critic's list was narrower, so the
    two hallucination checks could disagree on the same evidence.
    """
    from src.core.entities import extract_entities
    entities: Set[str] = set()
    for r in evidence_rows:
        entities |= extract_entities(r)
    return entities


def _build_pre_validation(
    cluster: dict,
    narrative: dict,
    evidence_rows: list[dict],
) -> tuple[str, dict]:
    """Build a structured pre-validation block for the critic prompt.

    Returns (formatted_text, raw_dict) so the raw dict can be stored in critic output.
    """
    lines: list[str] = []
    raw: dict = {}

    # Citation count check
    evidence_refs = narrative.get("evidence_refs") or []
    citation_count = len(evidence_refs) if isinstance(evidence_refs, list) else 0
    raw["citation_count"] = citation_count
    raw["low_citation"] = citation_count < 3
    if citation_count < 3:
        lines.append(f"  LOW_CITATION: only {citation_count} evidence row(s) cited (< 3 required)")
    else:
        lines.append(f"  CITATION_OK: {citation_count} evidence row(s) cited")

    # MITRE technique grounding check
    # Compare cluster's detected factor_tags → expected MITRE techniques
    # vs. narrator's claimed MITRE from cluster.mitre_techniques
    claimed_mitre: list[str] = list(cluster.get("mitre_techniques") or [])
    raw["claimed_mitre"] = claimed_mitre

    # Known factor-to-MITRE mapping (subset for critic pre-check)
    _FACTOR_MITRE_HINTS: dict[str, set[str]] = {
        "iam:kerberoasting": {"T1558.003"},
        "iam:golden_ticket": {"T1558.001"},
        "iam:asrep_roasting": {"T1558.004"},
        "iam:pass_the_hash": {"T1550.002"},
        "iam:pass_the_ticket": {"T1550.003"},
        "iam:dcsync": {"T1003.006"},
        "iam:rc4_kerberos": {"T1558.003"},
        "endpoint:lolbin_execution": {"T1218"},
        "endpoint:wmi_lateral": {"T1047"},
        "endpoint:powershell_encoded": {"T1059.001"},
        "endpoint:process_injection": {"T1055"},
        "exfil:large_upload": {"T1041", "T1567"},
        "exfil:dns_tunnel": {"T1071.004"},
        "net:c2_beacon": {"T1071"},
        "cloud:privilege_escalation": {"T1078"},
        "cloud:ssm_run_command_unusual": {"T1651"},
        "iam:adcs_cert_request_abuse": {"T1649"},
    }
    factor_tags = cluster.get("factor_tags") or {}
    if isinstance(factor_tags, list):
        active_factors = set(factor_tags)
    elif isinstance(factor_tags, dict):
        active_factors = {k for k, v in factor_tags.items() if v}
    else:
        active_factors = set()

    supported_mitre: set[str] = set()
    for factor in active_factors:
        supported_mitre.update(_FACTOR_MITRE_HINTS.get(factor, set()))
    # Any MITRE technique not in supported set (and claimed by narrator) is "unverified"
    unverified = [t for t in claimed_mitre if t not in supported_mitre] if supported_mitre else []
    raw["unverified_mitre"] = unverified
    if unverified:
        lines.append(f"  UNVERIFIED_MITRE: {', '.join(unverified)} — not grounded by detected factor_tags")
    else:
        lines.append(f"  MITRE_OK: all claimed techniques have supporting factor_tags (or no factor_tags available)")

    # Evidence entity set for IOC hallucination check
    ev_entities = _extract_evidence_entities(evidence_rows)
    raw["evidence_entity_count"] = len(ev_entities)
    lines.append(f"  EVIDENCE_ENTITIES: {len(ev_entities)} distinct user/IP/host values in evidence rows")

    # Authoritative IOC grounding: prefer the narrator's deterministic _ioc_grounding
    # (cluster_narrator._validate_ioc_grounding) over re-deriving here with a narrower
    # field list. Single source of truth — the critic LLM is handed the confirmed
    # ungrounded entities instead of guessing.
    grounding = narrative.get("_ioc_grounding") if isinstance(narrative, dict) else None
    if isinstance(grounding, dict):
        det_hallucinated = list(grounding.get("hallucinated_iocs") or [])
        raw["hallucinated_iocs_deterministic"] = det_hallucinated
        raw["ioc_grounding_rate"] = grounding.get("grounding_rate")
        if det_hallucinated:
            lines.append(
                f"  DETERMINISTIC_HALLUCINATION: {len(det_hallucinated)} entit(ies) named in the "
                f"narrative are ABSENT from evidence — treat as confirmed hallucinations: "
                f"{', '.join(str(h) for h in det_hallucinated[:10])}"
            )
        else:
            lines.append("  IOC_GROUNDING_OK: deterministic check found no ungrounded entities")

    return "\n".join(lines), raw


class AdversarialCritic:
    """Stateless critic — create one per call or keep as singleton."""

    def critique(
        self,
        cluster: dict,
        narrative: dict,
        evidence_rows: list[dict],
        *,
        assessment_id: str = "",
    ) -> dict:
        """Run the adversarial critique.

        Returns the critique dict (also appropriate to store as ``cluster['_critic']``).
        Never raises — returns ``{"skipped": True, ...}`` on any failure.
        """
        enabled = os.getenv("ENABLE_ADVERSARIAL_CRITIC", _CRITIC_ENABLED_DEFAULT)
        if enabled.lower() in ("0", "false", "no", "off"):
            return {"skipped": True, "skip_reason": "disabled_by_env"}

        verdict = str(narrative.get("verdict") or cluster.get("verdict") or "REQUIRES_INVESTIGATION")
        confidence = float(narrative.get("confidence") or cluster.get("confidence") or 0.5)

        # Skip only fully benign / no-signal verdicts. Low-confidence breach clusters
        # *should* face adversarial pressure — lowered threshold from 0.30 → 0.15.
        if verdict in ("BENIGN_EXPECTED", "INSUFFICIENT_EVIDENCE") or confidence < 0.15:
            return {
                "skipped": True,
                "skip_reason": f"verdict={verdict} confidence={confidence:.2f} below critic threshold",
            }

        pre_val_text, pre_val_raw = _build_pre_validation(cluster, narrative, evidence_rows)
        citation_count = pre_val_raw.get("citation_count", 0)

        prompt = _USER_TEMPLATE.format(
            verdict=verdict,
            confidence=confidence,
            attack_narrative=str(narrative.get("attack_narrative") or "")[:600],
            mitre=", ".join(pre_val_raw.get("claimed_mitre") or []) or "-",
            fp_indicators=", ".join(narrative.get("fp_indicators") or [])[:200] or "none",
            citation_count=citation_count,
            pre_validation_block=pre_val_text,
            users=", ".join((cluster.get("shared_accounts") or [])[:5]) or "-",
            hosts=", ".join((cluster.get("shared_hosts") or [])[:5]) or "-",
            ips=", ".join((cluster.get("shared_ips") or [])[:5]) or "-",
            evidence_block=_evidence_block(evidence_rows),
        )

        try:
            from src.integrations.llm_client import DEFAULT_CLIENT as _client
        except ImportError:
            try:
                from integrations.llm_client import DEFAULT_CLIENT as _client  # type: ignore
            except ImportError:
                return {"skipped": True, "skip_reason": "llm_client_unavailable"}

        with _CRITIC_LOCK:
            try:
                # Match the narrator's T2 settings: a clean-JSON, non-reasoning model and
                # a budget that actually completes. With the old default (slow reasoning
                # model + 40s) the critic silently timed out on every T2 cluster — the
                # CEO-grade narrative got NO adversarial/hallucination review at all.
                call_timeout = float(os.getenv("JANUSEC_CRITIC_TIMEOUT_S", "90"))
                _critic_model = (os.getenv("JANUSEC_CRITIC_MODEL")
                                 or os.getenv("JANUSEC_T2_NARRATOR_MODEL", "qwen2.5:14b"))
                result = _client.generate(
                    prompt,
                    system=_SYSTEM_PROMPT,
                    max_tokens=800,
                    model=_critic_model,
                    tenant_id=assessment_id or "critic",
                    overrides={"timeout": call_timeout, "retries": 0, "temperature": 0.2},
                )
            except Exception as exc:
                logger.debug("AdversarialCritic LLM call failed: %s", exc)
                return {"skipped": True, "skip_reason": f"llm_error:{exc}"}

        raw = result if isinstance(result, str) else (result or {}).get("text") or ""
        parsed = self._parse(raw)
        parsed["mitre_check"] = {
            "claimed": pre_val_raw.get("claimed_mitre", []),
            "unverified": pre_val_raw.get("unverified_mitre", []),
            "llm_unsupported": parsed.pop("mitre_unsupported", []),
        }
        parsed["citation_count"] = citation_count
        parsed["low_citation"] = pre_val_raw.get("low_citation", False)
        # Authoritative hallucination set = deterministic grounding ∪ LLM-reported.
        # The deterministic list (from the narrator's _ioc_grounding) is never dropped
        # even if the critic LLM overlooks an entity — single source of truth.
        _det_hall = pre_val_raw.get("hallucinated_iocs_deterministic") or []
        _llm_hall = parsed.get("hallucinated_iocs") or []
        _union: list[str] = []
        for h in [*_det_hall, *_llm_hall]:
            hs = str(h)
            if hs and hs not in _union:
                _union.append(hs)
        parsed["hallucinated_iocs"] = _union[:10]
        parsed["hallucinated_iocs_deterministic"] = list(_det_hall)
        parsed["ioc_grounding_rate"] = pre_val_raw.get("ioc_grounding_rate")
        parsed["model"] = str(
            (result or {}).get("model") if isinstance(result, dict) else ""
        ) or os.getenv("OLLAMA_MODEL", "unknown")
        parsed["tokens_used"] = int(
            (result or {}).get("usage", {}).get("total_tokens", 0)
            if isinstance(result, dict) else 0
        )
        parsed["skipped"] = False
        parsed["skip_reason"] = ""
        return parsed

    @staticmethod
    def _parse(raw: str) -> dict:
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text.rstrip())
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            text = m.group(0)
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return {
                "challenge": raw[:400] or "(parse failed)",
                "fp_probability": 0.1,
                "confidence_delta": 0.0,
                "weakest_evidence": [],
                "mitre_unsupported": [],
                "hallucinated_iocs": [],
                "verdict": "REQUIRES_INVESTIGATION",
            }

        fp_prob = max(0.0, min(1.0, float(obj.get("fp_probability") or 0.1)))
        c_delta = max(-0.5, min(0.0, float(obj.get("confidence_delta") or 0.0)))
        valid_verdicts = {
            "VALIDATED_BREACH", "SUSPECTED_BREACH", "BENIGN_EXPECTED",
            "REQUIRES_INVESTIGATION", "INSUFFICIENT_EVIDENCE",
        }
        critic_verdict = str(obj.get("verdict") or "REQUIRES_INVESTIGATION").upper()
        if critic_verdict not in valid_verdicts:
            critic_verdict = "REQUIRES_INVESTIGATION"
        return {
            "challenge": str(obj.get("challenge") or "")[:800],
            "fp_probability": round(fp_prob, 3),
            "confidence_delta": round(c_delta, 3),
            "weakest_evidence": [str(s) for s in (obj.get("weakest_evidence") or [])[:5]],
            "mitre_unsupported": [str(s) for s in (obj.get("mitre_unsupported") or [])[:10]],
            "hallucinated_iocs": [str(s) for s in (obj.get("hallucinated_iocs") or [])[:10]],
            "verdict": critic_verdict,
        }


# ── Module-level singleton ────────────────────────────────────────────────────
CRITIC = AdversarialCritic()

__all__ = ["AdversarialCritic", "CRITIC"]
