"""Multi-pass adversarial reasoner.

Implements a prosecution → defense → synthesis debate pattern that
gives the LLM structured constraints to reason multi-hop instead of
just summarising. Each pass is aware of the previous pass's output.

Pass 1 — PROSECUTION:
  "Build the strongest possible case that this is a confirmed breach.
   Cite specific row indices. Do not mention counter-arguments."

Pass 2 — DEFENSE:
  "You are a skeptical analyst reviewing this prosecution case.
   For each claim, find the most plausible innocent explanation.
   Cite specific row indices that support alternative interpretations."

Pass 3 — SYNTHESIS:
  "Given the prosecution and defense, return a final structured verdict.
   State which prosecution claims survived the defense challenge.
   State the final confidence level and why."

This is the core reasoning upgrade — it forces the model to actively
test hypotheses against evidence rather than pattern-matching to a verdict.

Deterministic fallback: when no LLM is available, produces a rule-based
verdict from the cross-source stitches and sequence validation.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── Prompt templates ──────────────────────────────────────────────────────────

_PROSECUTION_PROMPT = """\
You are the prosecution analyst. Your job is to build the strongest possible \
case that the following cluster represents a {verdict}.

RULES:
- Cite specific row indices in [brackets] for every factual claim.
- Focus on: WHO was compromised, HOW they moved laterally, WHAT data was accessed.
- Be specific — use exact usernames, IPs, hostnames from the evidence.
- Do NOT mention alternative explanations. That comes later.

CLUSTER: {incident_name}
PHASE SEQUENCE: {sequence_narrative}
CROSS-SOURCE STITCHES (rows confirmed across multiple telemetry sources):
{stitches_block}

EVIDENCE ({row_count} rows, {source_count} source(s)):
{evidence_block}

Write the prosecution case in 4-6 sentences. End with:
EVIDENCE_ROWS_CITED: [list row indices you used]
"""

_DEFENSE_PROMPT = """\
You are the defense analyst. Your job is to challenge the following prosecution \
case and find the most plausible innocent explanations for each claim.

RULES:
- For each prosecution claim, provide either: (a) an innocent explanation backed \
  by specific evidence rows, or (b) acknowledge the claim is sound if no \
  counter-evidence exists.
- Cite specific row indices in [brackets] for any counter-evidence.
- Focus on: FP patterns, authorized testing, human behavior, single-source risks, \
  sequence anomalies.

PROSECUTION CASE:
{prosecution_text}

ADDITIONAL CONTEXT (counter-evidence candidates):
SEQUENCE ANOMALIES: {anomalies_block}
DISPOSITION BREAKDOWN: {disposition_block}
CAVEATS FROM GRADER: {caveats_block}

Write the defense challenge in 3-5 sentences. End with:
SURVIVING_CLAIMS: [list claim numbers that survived the challenge]
CHALLENGED_CLAIMS: [list claim numbers with counter-explanations]
"""

_SYNTHESIS_PROMPT = """\
You are the final adjudicator. Based on the prosecution case and the defense \
challenge below, produce a final structured verdict.

PROSECUTION:
{prosecution_text}

DEFENSE:
{defense_text}

OUTPUT FORMAT — return JSON only:
{{
  "final_verdict": "CONFIRMED_BREACH | LIKELY_BREACH | UNCERTAIN | DISMISSED",
  "confidence": 0.0-1.0,
  "verdict_rationale": "2-3 sentences explaining why the verdict holds after \
challenge",
  "surviving_prosecution_claims": ["claim 1", "claim 2"],
  "accepted_defense_points": ["point 1"],
  "recommended_actions": ["action 1", "action 2"],
  "analyst_escalation_required": true|false,
  "ceo_one_liner": "One sentence for the board — start with the verdict"
}}
"""

# ── Evidence formatter ────────────────────────────────────────────────────────


def _format_evidence_block(rows: list[dict], limit: int = 40) -> str:
    """Format evidence rows for prompt injection."""
    lines: list[str] = []
    for r in rows[:limit]:
        idx = r.get('row_index', '?')
        entity = r.get('entity') or r.get('user') or r.get('ip') or '-'
        desc = str(r.get('description') or r.get('event_type') or '')[:100]
        severity = r.get('severity') or '-'
        source = r.get('_source') or r.get('source') or '-'
        ts = r.get('timestamp_utc') or r.get('timestamp') or ''
        lines.append(f'[{idx}] {source} | {entity} | {severity} | {desc} | {ts}')
    return '\n'.join(lines) or '(no evidence rows)'


def _format_stitches(stitches: list[dict], limit: int = 6) -> str:
    """Format cross-source stitches for prompt injection."""
    cross = [s for s in stitches if s.get('cross_source')][:limit]
    if not cross:
        return '(no cross-source corroborated events found)'
    lines: list[str] = []
    for s in cross:
        rows_str = ', '.join(str(i) for i in s.get('row_indices', [])[:8])
        sources_str = ' + '.join(s.get('sources', []))
        users_str = ', '.join(s.get('users', [])[:3]) or '-'
        ips_str = ', '.join(s.get('ips', [])[:3]) or '-'
        lines.append(
            f'  Rows [{rows_str}] corroborated across {sources_str}: '
            f'user={users_str}, ip={ips_str}'
        )
    return '\n'.join(lines)


# ── Core reasoner ─────────────────────────────────────────────────────────────


class AdversarialReasoner:
    """Multi-pass prosecution/defense/synthesis reasoner for a cluster."""

    def __init__(
        self,
        llm_func: Callable,
        model: str = 'qwen3:14b',
        max_tokens_per_pass: int = 500,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ):
        self.llm_func = llm_func
        self.model = model
        self.max_tokens = max_tokens_per_pass
        self.progress = progress_callback or (lambda phase, pct: None)

    def reason(
        self,
        cluster: dict,
        rows: list[dict],
        stitches: list[dict],
        sequence_result: dict,
        verdict_reasoning: Optional[dict] = None,
    ) -> dict:
        """Run the full 3-pass adversarial reasoning loop.

        Returns:
            {
              prosecution_text: str,
              defense_text: str,
              synthesis: dict,
              passes_completed: int,
              provenance: str,
            }
        """
        prefill = cluster.get('tier1_prefill') or {}
        incident_name = prefill.get('incident_name') or str(cluster.get('cluster_id', ''))
        verdict = str(cluster.get('verdict') or cluster.get('final_verdict') or 'UNCERTAIN').upper()
        vr = verdict_reasoning or {}

        evidence_block = _format_evidence_block(rows)
        stitches_block = _format_stitches(stitches)
        sequence_narrative = sequence_result.get('sequence_narrative', 'No sequence data.')
        anomalies = sequence_result.get('anomalies', [])
        anomalies_block = '\n'.join(f'  - {a}' for a in anomalies) or '(none detected)'
        disposition = vr.get('disposition_breakdown', {})
        disposition_block = ', '.join(f'{k}={v}' for k, v in disposition.items()) or '(no data)'
        caveats_block = '; '.join(vr.get('grader_caveats', [])[:3]) or '(none)'

        prosecution_text = ''
        defense_text = ''
        synthesis: dict = {}
        passes_completed = 0

        # ── Pass 1: Prosecution ──────────────────────────────────────────
        self.progress('adversarial:prosecution', 33)
        prosecution_prompt = _PROSECUTION_PROMPT.format(
            verdict=verdict,
            incident_name=incident_name,
            sequence_narrative=sequence_narrative,
            stitches_block=stitches_block,
            evidence_block=evidence_block,
            row_count=len(rows),
            source_count=len({r.get('_source') or r.get('source') for r in rows if r.get('_source') or r.get('source')}),
        )
        try:
            resp = self._call_llm(prosecution_prompt)
            prosecution_text = resp.strip()
            passes_completed += 1
        except Exception as exc:
            logger.debug('prosecution pass failed: %s', exc)
            prosecution_text = f'Prosecution unavailable ({exc})'

        # ── Pass 2: Defense ──────────────────────────────────────────────
        self.progress('adversarial:defense', 66)
        if prosecution_text and passes_completed >= 1:
            defense_prompt = _DEFENSE_PROMPT.format(
                prosecution_text=prosecution_text,
                anomalies_block=anomalies_block,
                disposition_block=disposition_block,
                caveats_block=caveats_block,
            )
            try:
                resp = self._call_llm(defense_prompt)
                defense_text = resp.strip()
                passes_completed += 1
            except Exception as exc:
                logger.debug('defense pass failed: %s', exc)
                defense_text = f'Defense unavailable ({exc})'

        # ── Pass 3: Synthesis ────────────────────────────────────────────
        self.progress('adversarial:synthesis', 90)
        if passes_completed >= 2:
            synthesis_prompt = _SYNTHESIS_PROMPT.format(
                prosecution_text=prosecution_text,
                defense_text=defense_text,
            )
            try:
                resp = self._call_llm(synthesis_prompt)
                parsed = _parse_json(resp)
                if parsed and 'final_verdict' in parsed:
                    synthesis = parsed
                    passes_completed += 1
                else:
                    # Try to extract partial result
                    synthesis = {'raw_synthesis': resp.strip(), 'final_verdict': verdict}
            except Exception as exc:
                logger.debug('synthesis pass failed: %s', exc)
                synthesis = {'error': str(exc), 'final_verdict': verdict}

        # Fallback synthesis if LLM failed
        if not synthesis:
            synthesis = _deterministic_synthesis(cluster, sequence_result, vr)

        return {
            'prosecution_text': prosecution_text,
            'defense_text': defense_text,
            'synthesis': synthesis,
            'passes_completed': passes_completed,
            'provenance': f'adversarial_llm_{self.model}' if passes_completed >= 3 else 'adversarial_partial',
        }

    def _call_llm(self, prompt: str) -> str:
        resp = self.llm_func(
            prompt,
            self.max_tokens,
            None,
            {'ollama_model': self.model},
            self.model,
        )
        return (resp.get('text') or '').strip()


# ── Deterministic fallback synthesis ─────────────────────────────────────────


def _deterministic_synthesis(
    cluster: dict,
    sequence_result: dict,
    verdict_reasoning: dict,
) -> dict:
    """Rule-based synthesis when LLM is unavailable."""
    verdict = str(cluster.get('verdict') or cluster.get('final_verdict') or 'UNCERTAIN').upper()
    composite = verdict_reasoning.get('composite_score', 0.0)
    fp_risk = verdict_reasoning.get('fp_risk', 0.0)
    sequence_coherent = sequence_result.get('sequence_coherent', False)
    phase_count = sequence_result.get('phase_count', 0)

    # Adjust confidence based on hard signals
    confidence = composite
    rationale_parts: list[str] = []

    if phase_count >= 3 and sequence_coherent:
        rationale_parts.append(f'{phase_count} ATT&CK phases observed in correct sequence')
    elif phase_count < 2:
        confidence *= 0.8
        rationale_parts.append('fewer than 2 kill-chain phases evidenced')

    if fp_risk > 0.5:
        confidence *= 0.7
        rationale_parts.append(f'elevated FP risk ({fp_risk:.0%})')

    anomalies = sequence_result.get('anomalies', [])
    if anomalies:
        confidence *= 0.85
        rationale_parts.append(f'{len(anomalies)} sequence anomaly(s) detected')

    rationale = '. '.join(rationale_parts) or 'Based on grader composite score'
    prefill = cluster.get('tier1_prefill') or {}
    incident_name = prefill.get('incident_name') or str(cluster.get('cluster_id', ''))

    return {
        'final_verdict': verdict,
        'confidence': round(min(max(confidence, 0.0), 1.0), 3),
        'verdict_rationale': rationale,
        'surviving_prosecution_claims': [],
        'accepted_defense_points': verdict_reasoning.get('counter_hypotheses', [])[:2],
        'recommended_actions': [],
        'analyst_escalation_required': confidence < 0.6 or fp_risk > 0.4,
        'ceo_one_liner': (
            f'{verdict}: {incident_name}. '
            f'Evidence quality: {verdict_reasoning.get("evidence_quality", "unknown")}. '
            f'Confidence: {confidence:.0%}.'
        ),
    }


def _parse_json(text: str) -> Optional[dict]:
    """Extract JSON from LLM output."""
    match = re.search(r'```(?:json)?\s*\n?(.*?)```', text, re.DOTALL)
    if match:
        text = match.group(1).strip()
    text = text.strip()
    if not text.startswith('{'):
        # Find first { in text
        start = text.find('{')
        if start >= 0:
            text = text[start:]
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
