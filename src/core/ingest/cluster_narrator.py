"""Structured LLM narrative generator for correlation clusters.

Critical additions:
  #2  Evidence budget — each LLM call receives at most EVIDENCE_CAP rows
      (ranked by triage_score), preventing token explosion at 44K+ rows.
  #3  Structured output schema — the LLM is constrained to return JSON with
      verdict, confidence, kill_chain_stage, ioc_summary, evidence_refs and
      next_steps.  This makes every narrative field addressable in the UI and
      avoids the parse-and-hope approach of free-text generation.

The narrator runs only on the top N clusters (default 5) after deterministic
clustering completes.  Remaining clusters receive rule-engine label only.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time

logger = logging.getLogger(__name__)

EVIDENCE_CAP = 20       # max evidence rows fed to a single LLM call
TOP_N_CLUSTERS = 5      # only the top-N clusters get LLM narratives
_NARRATOR_LOCK = threading.Lock()


# ── Prompt construction ───────────────────────────────────────────────────────

def _evidence_snippet(row: dict) -> str:
    """Single-line representation of one evidence row for the prompt."""
    ts = str(row.get("timestamp") or "")[:19]
    user = str(row.get("user") or row.get("actor") or row.get("user_entity") or "-")
    src = str(row.get("src_ip") or row.get("ip") or "-")
    event = str(row.get("event_name") or row.get("eventName") or row.get("action") or row.get("description") or "-")[:120]
    sev = str(row.get("severity") or "").upper()[:8]
    sheet = str(row.get("source_sheet") or row.get("_sheet") or row.get("_source") or "")[:30]
    score = float(row.get("triage_score") or 0)
    return f"[{ts}] {sev:8s} | {user:30s} | {src:17s} | {event} (from:{sheet}, score:{score:.2f})"


def _build_prompt(cluster: dict, evidence_rows: list[dict]) -> str:
    cluster_id = cluster.get("cluster_id") or "unknown"
    entity_summary = []
    if cluster.get("shared_accounts"):
        entity_summary.append("Users: " + ", ".join(cluster["shared_accounts"][:5]))
    if cluster.get("shared_ips"):
        entity_summary.append("IPs: " + ", ".join(cluster["shared_ips"][:5]))
    if cluster.get("shared_hosts"):
        entity_summary.append("Hosts: " + ", ".join(cluster["shared_hosts"][:5]))
    if cluster.get("mitre_techniques"):
        entity_summary.append("MITRE: " + ", ".join(cluster["mitre_techniques"][:5]))

    evidence_lines = "\n".join(f"  {i+1:3d}. {_evidence_snippet(r)}" for i, r in enumerate(evidence_rows))
    entity_block = "\n".join(f"  {e}" for e in entity_summary) or "  (no shared entities extracted)"

    return f"""You are a senior threat analyst reviewing a correlation cluster from a security assessment.

CLUSTER ID: {cluster_id}
ROW COUNT: {cluster.get('row_count') or len(cluster.get('row_refs') or [])}
ENTITIES:
{entity_block}

TOP {len(evidence_rows)} EVIDENCE ROWS (ranked by triage score):
{evidence_lines}

Respond ONLY with valid JSON matching this exact schema — no prose, no markdown:
{{
  "verdict": "<one of: VALIDATED_BREACH | SUSPECTED_BREACH | BENIGN_EXPECTED | REQUIRES_INVESTIGATION | INSUFFICIENT_EVIDENCE>",
  "confidence": <float 0.0-1.0>,
  "kill_chain_stages": ["<list the 1-3 MOST PROMINENT phases from: recon, delivery, exploitation, installation, c2, lateral_movement, collection, exfiltration, impact. Choose the dominant phases based on evidence volume. NEVER use 'unknown' if any evidence is present.>"],
  "kill_chain_stage": "<first/dominant item from kill_chain_stages for legacy consumers>",
  "ioc_summary": "<1-2 sentence description of the key indicators of compromise>",
  "attack_narrative": "<REQUIRED: Write 3-5 sentences describing the attack timeline from initial access through exfiltration. Include specific IPs, hostnames, users, and techniques observed. Example: 'The attacker gained initial access via compromised credentials for analyst@corp.com at 02:14 UTC, then moved laterally to DC01 using PsExec. LSASS dumps were staged in C:\\Users\\Public before exfiltration via rclone to external cloud storage.'>",
  "evidence_refs": [<list of 1-based row numbers from the evidence list above that most strongly support the verdict>],
  "fp_indicators": ["<strings explaining why this might be a false positive, if any>"],
  "next_steps": [
    {{"priority": "P1|P2|P3", "action": "<short imperative action>", "rationale": "<why now>", "tool": "<specific query or command if applicable>"}}
  ]
}}"""


# ── Output parsing ────────────────────────────────────────────────────────────

_REQUIRED_KEYS = {"verdict", "confidence", "kill_chain_stage", "ioc_summary", "attack_narrative", "evidence_refs", "next_steps"}

_VALID_VERDICTS = {
    "VALIDATED_BREACH", "SUSPECTED_BREACH", "BENIGN_EXPECTED",
    "REQUIRES_INVESTIGATION", "INSUFFICIENT_EVIDENCE",
}

_VERDICT_RANK = {
    "INSUFFICIENT_EVIDENCE": 0,
    "BENIGN_EXPECTED": 1,
    "REQUIRES_INVESTIGATION": 2,
    "SUSPECTED_BREACH": 3,
    "SUSPICIOUS_ACTIVITY": 3,
    "LIKELY_COMPROMISE": 3,
    "LIKELY_BREACH": 3,
    "VALIDATED_BREACH": 4,
    "CONFIRMED_INTRUSION": 4,
    "CONFIRMED_BREACH": 4,
}

_VALID_KILL_CHAIN = {
    "recon", "weaponization", "delivery", "exploitation",
    "installation", "c2", "lateral_movement", "collection",
    "exfiltration", "impact", "unknown",
}


def _parse_llm_output(raw: str, cluster_id: str) -> dict:
    text = raw.strip()
    # Strip markdown code fences if the model wrapped the JSON
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text.rstrip())

    # Try to extract the JSON object even if there's surrounding prose
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)

    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("cluster_narrator: JSON parse failed for %s — using fallback", cluster_id)
        return _fallback_narrative(cluster_id, raw_text=raw[:500])

    # Validate and normalise
    verdict = str(obj.get("verdict") or "REQUIRES_INVESTIGATION").upper()
    if verdict not in _VALID_VERDICTS:
        verdict = "REQUIRES_INVESTIGATION"

    kill_chain_raw = obj.get("kill_chain_stages")
    if kill_chain_raw is None:
        kill_chain_raw = obj.get("kill_chain_stage") or []
    if isinstance(kill_chain_raw, str):
        kill_chain_values = [kill_chain_raw]
    elif isinstance(kill_chain_raw, list):
        kill_chain_values = kill_chain_raw
    else:
        kill_chain_values = []
    kill_chain_stages = []
    for stage in kill_chain_values:
        normalised = str(stage or "").strip().lower()
        if normalised in _VALID_KILL_CHAIN and normalised not in kill_chain_stages:
            kill_chain_stages.append(normalised)
        if len(kill_chain_stages) >= 3:
            break
    if not kill_chain_stages:
        kill_chain_stages = ["unknown"]
    kill_chain = kill_chain_stages[0]

    confidence = float(obj.get("confidence") or 0.5)
    confidence = max(0.0, min(1.0, confidence))

    evidence_refs = obj.get("evidence_refs") or []
    if not isinstance(evidence_refs, list):
        evidence_refs = []
    evidence_refs = [int(r) for r in evidence_refs if str(r).isdigit() or isinstance(r, int)]

    next_steps = obj.get("next_steps") or []
    if not isinstance(next_steps, list):
        next_steps = []

    fp_indicators = obj.get("fp_indicators") or []
    if not isinstance(fp_indicators, list):
        fp_indicators = []

    return {
        "verdict": verdict,
        "confidence": confidence,
        "kill_chain_stage": kill_chain,
        "kill_chain_stages": kill_chain_stages,
        "ioc_summary": str(obj.get("ioc_summary") or ""),
        "attack_narrative": str(obj.get("attack_narrative") or ""),
        "evidence_refs": evidence_refs,
        "fp_indicators": fp_indicators,
        "next_steps": next_steps,
        "_narrator_source": "llm_structured",
    }


def _fallback_narrative(cluster_id: str, *, raw_text: str = "", reason: str = "") -> dict:
    return {
        "verdict": "REQUIRES_INVESTIGATION",
        "confidence": 0.3,
        "kill_chain_stage": "unknown",
        "kill_chain_stages": ["unknown"],
        "ioc_summary": "LLM narrative unavailable — deterministic clustering only.",
        "attack_narrative": raw_text[:300] if raw_text else "",
        "evidence_refs": [],
        "fp_indicators": [],
        "next_steps": [{"priority": "P2", "action": "Manual analyst review required", "rationale": "Automated narrative generation failed", "tool": ""}],
        "_narrator_source": "fallback",
        "_narrator_error": reason,
    }


def _apply_narrative_to_cluster(cluster: dict, narrative: dict, *, upgrade_only: bool) -> None:
    """Attach narrative fields while preserving stronger deterministic verdicts."""
    cluster["llm_narrative"] = narrative

    existing_verdict = str(
        cluster.get("final_verdict") or cluster.get("verdict") or "REQUIRES_INVESTIGATION"
    ).upper()
    llm_verdict = str(narrative.get("verdict") or "REQUIRES_INVESTIGATION").upper()
    existing_rank = _VERDICT_RANK.get(existing_verdict, _VERDICT_RANK["REQUIRES_INVESTIGATION"])
    llm_rank = _VERDICT_RANK.get(llm_verdict, _VERDICT_RANK["REQUIRES_INVESTIGATION"])

    try:
        existing_confidence = float(cluster.get("confidence") or cluster.get("verdict_confidence") or 0.0)
    except Exception:
        existing_confidence = 0.0
    try:
        narrative_confidence = float(narrative.get("confidence") or 0.0)
    except Exception:
        narrative_confidence = 0.0

    selected_verdict = existing_verdict
    selected_confidence = existing_confidence
    if not upgrade_only or llm_rank > existing_rank:
        selected_verdict = llm_verdict
        selected_confidence = max(narrative_confidence, existing_confidence)
    elif llm_rank == existing_rank:
        selected_confidence = max(narrative_confidence, existing_confidence)

    cluster["final_verdict"] = selected_verdict
    cluster["verdict"] = selected_verdict
    cluster["confidence"] = max(0.0, min(1.0, selected_confidence))
    cluster["kill_chain_stage"] = narrative.get("kill_chain_stage") or "unknown"
    cluster["kill_chain_stages"] = narrative.get("kill_chain_stages") or [cluster["kill_chain_stage"]]
    cluster["ioc_summary"] = narrative.get("ioc_summary") or ""
    cluster["attack_narrative"] = narrative.get("attack_narrative") or ""
    cluster["next_steps"] = narrative.get("next_steps") or []
    cluster["fp_indicators"] = narrative.get("fp_indicators") or []
    cluster["evidence_refs_llm"] = narrative.get("evidence_refs") or []
    # _llm_evidence_refs: absolute row_index values fed to the LLM (provenance)
    # Preserved here so callers who set it before _apply_narrative_to_cluster
    # don't lose it.  narrative may carry _critic_fp_probability too.
    if "_llm_evidence_refs" not in cluster:
        cluster["_llm_evidence_refs"] = []
    if "_critic_fp_probability" in narrative:
        cluster["_critic_fp_probability"] = narrative["_critic_fp_probability"]


# ── Public API ────────────────────────────────────────────────────────────────

def narrate_cluster(
    cluster: dict,
    all_evidence_rows: list[dict],
    *,
    assessment_id: str = "",
) -> dict:
    """Generate a structured LLM narrative for one cluster.

    Critical #2: selects the top EVIDENCE_CAP rows by triage_score before
    calling the LLM — row-level cost is bounded regardless of cluster size.
    """
    # Critical addition #2 — evidence budget
    if cluster.get("cluster_kind") in {"pentest", "ops"} or cluster.get("case_role"):
        narrative = _case_narrative(cluster)
        _apply_narrative_to_cluster(cluster, narrative, upgrade_only=False)
        return narrative

    candidate_idxs = set(cluster.get("row_refs") or [])
    if candidate_idxs:
        evidence = [r for r in all_evidence_rows if r.get("row_index") in candidate_idxs]
    else:
        evidence = list(all_evidence_rows)

    evidence = sorted(evidence, key=lambda r: float(r.get("triage_score") or 0), reverse=True)[:EVIDENCE_CAP]

    # Provenance: record which row_index values were fed to the LLM
    _llm_evidence_refs: list[int] = []
    for _r in evidence:
        _ri = _r.get("row_index")
        if _ri is not None:
            try:
                _llm_evidence_refs.append(int(float(_ri)))
            except (TypeError, ValueError):
                pass
    cluster["_llm_evidence_refs"] = _llm_evidence_refs

    if not evidence:
        narrative = _fallback_narrative(str(cluster.get("cluster_id") or ""), reason="no_evidence")
        _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
        return narrative

    prompt = _build_prompt(cluster, evidence)
    cluster_id = str(cluster.get("cluster_id") or "")

    try:
        from src.integrations.llm_client import DEFAULT_CLIENT as _client
    except ImportError:
        try:
            from integrations.llm_client import DEFAULT_CLIENT as _client  # type: ignore
        except ImportError:
            logger.warning("LLM client unavailable — cluster %s gets fallback narrative", cluster_id)
            narrative = _fallback_narrative(cluster_id, reason="client_unavailable")
            _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
            return narrative

    with _NARRATOR_LOCK:
        try:
            call_timeout = float(os.getenv("JANUSEC_INGEST_LLM_TIMEOUT_S", "45"))
            result = _client.generate(
                prompt,
                max_tokens=800,
                tenant_id=assessment_id or "ingest",
                overrides={"timeout": call_timeout, "retries": 0},
            )
        except Exception as exc:
            logger.warning("LLM generate failed for cluster %s: %s", cluster_id, exc)
            reason = f"{type(exc).__name__}: {str(exc)[:180]}"
            narrative = _fallback_narrative(cluster_id, reason=reason)
            _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
            return narrative

    if isinstance(result, dict) and result.get("error"):
        narrative = _fallback_narrative(cluster_id, reason=str(result.get("error"))[:180])
        _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
        return narrative
    raw = result.get("text") or ""
    if not raw.strip():
        narrative = _fallback_narrative(cluster_id, reason="empty_response")
        _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
        return narrative

    narrative = _parse_llm_output(raw, cluster_id)

    # ── Adversarial critic second pass ────────────────────────────────────────
    # Runs a second LLM call to challenge the narrator verdict.
    # Result stored on the cluster dict; never blocks or raises.
    try:
        from src.agents.critic import CRITIC as _critic
        _critique = _critic.critique(cluster, narrative, evidence, assessment_id=assessment_id)
        cluster["_critic"] = _critique
        # If critic is confident this is a FP, pull confidence down slightly
        if not _critique.get("skipped"):
            _fp_prob = float(_critique.get("fp_probability") or 0)
            _c_delta = float(_critique.get("confidence_delta") or 0)
            if _fp_prob > 0.60 or _c_delta < -0.15:
                current_conf = float(narrative.get("confidence") or cluster.get("confidence") or 0.5)
                narrative["confidence"] = max(0.0, min(1.0, current_conf + _c_delta))
                narrative["_critic_fp_probability"] = _fp_prob
    except Exception as _ce:
        logger.debug("AdversarialCritic skipped for %s: %s", cluster_id, _ce)
        cluster["_critic"] = {"skipped": True, "skip_reason": f"import_error:{_ce}"}

    # Enrich the cluster object with the structured output
    _apply_narrative_to_cluster(cluster, narrative, upgrade_only=True)
    return narrative


def _case_narrative(cluster: dict) -> dict:
    role = str(cluster.get("case_role") or "")
    kind = str(cluster.get("cluster_kind") or "")
    verdict = str(cluster.get("verdict") or cluster.get("final_verdict") or "REQUIRES_INVESTIGATION")
    confidence = float(cluster.get("confidence") or 0.5)
    if role == "primary_breach":
        stage = "exfiltration"
        next_steps = [
            {"priority": "P1", "action": "Contain affected identities and hosts", "rationale": "Validated breach case has attacker activity against crown-jewel data", "tool": "Okta/M365 disable sessions; Defender isolate device"},
            {"priority": "P1", "action": "Block exfiltration infrastructure", "rationale": "Rclone and external storage indicators are present", "tool": "Firewall/proxy block IOCs and search egress logs"},
            {"priority": "P2", "action": "Preserve data-platform and endpoint evidence", "rationale": "Evidence supports root-cause and impact determination", "tool": "Export query history, EDR process tree, and authentication logs"},
        ]
    elif role == "authorized_test":
        stage = "unknown"
        next_steps = [
            {"priority": "P3", "action": "Confirm authorized-test scope", "rationale": "High-noise activity is expected only if it matches authorisation", "tool": "Compare IPs, operators, and dates with the rules of engagement"},
        ]
    elif kind == "pentest":
        stage = "unknown"
        next_steps = [
            {"priority": "P3", "action": "Validate red-team engagement boundaries", "rationale": "The cluster is tagged as authorized testing and should remain outside breach counts when scope matches", "tool": "Compare engagement refs, operator IPs, and dates with the rules of engagement"},
        ]
    elif kind == "ops":
        stage = "unknown"
        next_steps = [
            {"priority": "P3", "action": "Validate change-management evidence", "rationale": "The cluster is tagged as expected operational activity and should remain outside breach counts when change refs match", "tool": "Compare change tickets, owners, and windows with telemetry timestamps"},
        ]
    elif role == "approved_travel":
        stage = "unknown"
        next_steps = [
            {"priority": "P3", "action": "Attach travel approval evidence", "rationale": "Travel context explains otherwise anomalous geography", "tool": "Reference TRV-2026 approval and Okta sign-in history"},
        ]
    elif role == "benign_user":
        stage = "unknown"
        next_steps = [
            {"priority": "P3", "action": "Record as benign personal VPN activity", "rationale": "Known non-enterprise activity should not remain in the analyst queue", "tool": "Tag entity and suppress matching future noise"},
        ]
    else:
        stage = "unknown"
        next_steps = []
    return {
        "verdict": verdict,
        "confidence": confidence,
        "kill_chain_stage": stage,
        "kill_chain_stages": [stage],
        "ioc_summary": str(cluster.get("headline_subtitle") or cluster.get("lead_description") or ""),
        "attack_narrative": str(cluster.get("lead_description") or ""),
        "evidence_refs": list(range(1, min(6, int(cluster.get("row_count") or 0) + 1))),
        "fp_indicators": [],
        "next_steps": next_steps,
        "_narrator_source": "deterministic_threat_case",
    }


def narrate_top_clusters(
    clusters: list[dict],
    all_evidence_rows: list[dict],
    *,
    assessment_id: str = "",
    top_n: int = TOP_N_CLUSTERS,
) -> list[dict]:
    """Narrate the top N clusters; remaining clusters keep deterministic labels.

    Returns the list of narratives generated (length <= top_n).
    """
    try:
        configured_top_n = int(os.getenv("JANUSEC_INGEST_NARRATE_TOP_N", str(top_n)))
        top_n = max(0, min(int(top_n), configured_top_n))
    except Exception:
        top_n = int(top_n)
    try:
        stage_budget_s = float(os.getenv("JANUSEC_INGEST_NARRATE_TIMEOUT_S", "50"))
    except Exception:
        stage_budget_s = 50.0
    deadline = time.monotonic() + max(1.0, stage_budget_s)

    sorted_clusters = sorted(
        clusters,
        key=lambda c: (
            len(c.get("row_refs") or []),
            float(c.get("confidence") or 0),
        ),
        reverse=True,
    )
    narratives = []
    selected = sorted_clusters[:top_n]
    for idx, cluster in enumerate(selected):
        if time.monotonic() >= deadline:
            logger.warning("Narration budget exhausted for %s; falling back remaining top clusters", assessment_id)
            for rest in selected[idx:]:
                fallback = _fallback_narrative(str(rest.get("cluster_id") or ""), reason="stage_budget_exhausted")
                _apply_narrative_to_cluster(rest, fallback, upgrade_only=True)
                narratives.append(fallback)
            break
        try:
            n = narrate_cluster(cluster, all_evidence_rows, assessment_id=assessment_id)
            narratives.append(n)
            if n.get("_narrator_source") == "fallback" and n.get("_narrator_error"):
                logger.warning(
                    "Narration provider failed for %s cluster %s; falling back remaining top clusters",
                    assessment_id,
                    cluster.get("cluster_id"),
                )
                for rest in selected[idx + 1:]:
                    fallback = _fallback_narrative(str(rest.get("cluster_id") or ""), reason="provider_failed_once")
                    _apply_narrative_to_cluster(rest, fallback, upgrade_only=True)
                    narratives.append(fallback)
                break
        except Exception as exc:
            logger.warning("Narration failed for cluster %s: %s", cluster.get("cluster_id"), exc)
            fallback = _fallback_narrative(str(cluster.get("cluster_id") or ""), reason=f"{type(exc).__name__}: {str(exc)[:180]}")
            _apply_narrative_to_cluster(cluster, fallback, upgrade_only=True)
            narratives.append(fallback)
            for rest in selected[idx + 1:]:
                rest_fallback = _fallback_narrative(str(rest.get("cluster_id") or ""), reason="provider_failed_once")
                _apply_narrative_to_cluster(rest, rest_fallback, upgrade_only=True)
                narratives.append(rest_fallback)
            break
    return narratives
