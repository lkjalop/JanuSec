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
from typing import Any, Dict, List, Optional

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
4. Output ONLY valid JSON — no prose, no markdown.
"""

_USER_TEMPLATE = """\
NARRATOR VERDICT: {verdict} (confidence={confidence:.2f})
NARRATOR NARRATIVE: {attack_narrative}
NARRATOR FP INDICATORS: {fp_indicators}

CLUSTER ENTITIES:
  Users: {users}
  Hosts: {hosts}
  IPs:   {ips}
  MITRE: {mitre}

TOP EVIDENCE (up to 15 rows):
{evidence_block}

Now produce your adversarial critique. Respond ONLY with valid JSON:
{{
  "challenge": "<2-4 sentences: the strongest counter-argument to the narrator verdict>",
  "fp_probability": <float 0.0-1.0 — probability this is a false positive>,
  "confidence_delta": <float -0.5 to 0.0 — how much you would reduce narrator confidence>,
  "weakest_evidence": ["<row snippet 1>", "<row snippet 2>"],
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

        # Skip if already low-confidence or benign — no point attacking weak verdicts
        if verdict in ("BENIGN_EXPECTED", "INSUFFICIENT_EVIDENCE") or confidence < 0.30:
            return {
                "skipped": True,
                "skip_reason": f"verdict={verdict} confidence={confidence:.2f} below critic threshold",
            }

        prompt = _USER_TEMPLATE.format(
            verdict=verdict,
            confidence=confidence,
            attack_narrative=str(narrative.get("attack_narrative") or "")[:600],
            fp_indicators=", ".join(narrative.get("fp_indicators") or [])[:200] or "none",
            users=", ".join((cluster.get("shared_accounts") or [])[:5]) or "-",
            hosts=", ".join((cluster.get("shared_hosts") or [])[:5]) or "-",
            ips=", ".join((cluster.get("shared_ips") or [])[:5]) or "-",
            mitre=", ".join((cluster.get("mitre_techniques") or [])[:6]) or "-",
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
                call_timeout = float(os.getenv("JANUSEC_CRITIC_TIMEOUT_S", "40"))
                result = _client.generate(
                    prompt,
                    system=_SYSTEM_PROMPT,
                    max_tokens=500,
                    tenant_id=assessment_id or "critic",
                    overrides={"timeout": call_timeout, "retries": 0, "temperature": 0.2},
                )
            except Exception as exc:
                logger.debug("AdversarialCritic LLM call failed: %s", exc)
                return {"skipped": True, "skip_reason": f"llm_error:{exc}"}

        raw = result if isinstance(result, str) else (result or {}).get("text") or ""
        parsed = self._parse(raw)
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
            "verdict": critic_verdict,
        }


# ── Module-level singleton ────────────────────────────────────────────────────
CRITIC = AdversarialCritic()

__all__ = ["AdversarialCritic", "CRITIC"]
