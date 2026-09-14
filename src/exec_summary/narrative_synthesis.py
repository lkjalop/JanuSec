"""Per-cluster narrative synthesis with structured citation.

Generates a ClusterNarrative for each cluster using:
    1. The deterministic attack-chain backbone (always runs)
    2. BeliefTrajectory one-liner
    3. TemporalRAG context injection
    4. Optional LLM colour pass with citation requirements
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from .schemas import (
    BeliefTrajectory,
    Claim,
    ClusterNarrative,
    ClusterScope,
    EvidenceFrame,
)

logger = logging.getLogger(__name__)


# ── LLM prompt with citation requirement ─────────────────────────────────────

_CITATION_PROMPT = """\
You are a senior security analyst writing an executive cluster summary.
Use ONLY the evidence provided below. Do not invent facts not present in the evidence.

OUTPUT FORMAT: Return a JSON object with exactly these fields:
{{
  "summary_paragraph": "3-4 sentence factual narrative",
  "key_decisions_required": ["decision 1", "decision 2"],
  "claims": [
    {{"text": "factual claim", "evidence_row_ids": [1, 5, 12], "valid_time": "2026-02-24T10:00:00Z"}}
  ]
}}

RULES:
- Every factual claim in summary_paragraph MUST appear in the claims array with supporting evidence_row_ids
- evidence_row_ids must reference actual row indices from the EVIDENCE section
- If you cannot support a claim with evidence, do not make it
- Do not infer attacker motivation or attribution unless explicitly in evidence
- Belief trajectory values must match the ones provided — do not invent confidence scores

CLUSTER: {incident_name} (verdict: {verdict})
BELIEF EVOLUTION: {trajectory_oneliner}
{temporal_context}

EVIDENCE (row indices in brackets):
{evidence_block}

{deterministic_narrative}
"""


# ── Phase 3 — two-stage chain-of-thought prompts (quality_mode='high') ───────
#
# Stage 1 produces a <thinking> scratchpad; Stage 2 consumes the scratchpad
# plus the same evidence to produce the final cited JSON.  We then run a
# consistency check that verifies every JSON claim's row IDs were referenced
# in the scratchpad — claims that contradict or extend beyond the scratchpad
# get downgraded.

_COT_STAGE1_PROMPT = """\
You are a senior security analyst.  Before writing the final cluster summary,
think through the evidence step by step.

Output ONLY a <thinking> block.  Inside it:

1. List which evidence rows are most informative and why (cite them as [N]).
2. Note any rows that contradict each other or undermine the verdict.
3. Identify the strongest counter-hypothesis to the stated verdict.
4. Decide which 2-3 facts must appear in the final summary and which are
   speculative and should be excluded.

DO NOT WRITE THE FINAL SUMMARY YET.  Stop after the </thinking> tag.

CLUSTER: {incident_name} (verdict: {verdict})
BELIEF EVOLUTION: {trajectory_oneliner}
{temporal_context}

EVIDENCE:
{evidence_block}

<thinking>
"""


_COT_STAGE2_PROMPT = """\
You are a senior security analyst.  You have already produced this reasoning
scratchpad:

<thinking>
{scratchpad}
</thinking>

Now produce the final structured summary.  You may use ONLY:
* Facts present in the EVIDENCE section below
* Conclusions you justified in the <thinking> block above

Do NOT introduce facts that did not appear in either source.

OUTPUT FORMAT: Return a JSON object with exactly these fields:
{{
  "summary_paragraph": "3-4 sentence factual narrative",
  "key_decisions_required": ["decision 1", "decision 2"],
  "claims": [
    {{"text": "factual claim", "evidence_row_ids": [1, 5, 12], "valid_time": "2026-02-24T10:00:00Z"}}
  ]
}}

RULES:
- Every factual claim in summary_paragraph MUST appear in the claims array.
- evidence_row_ids must reference rows you cited in <thinking>.
- Counter-hypothesis from the scratchpad must be addressed (mentioned or rebutted).

CLUSTER: {incident_name} (verdict: {verdict})

EVIDENCE:
{evidence_block}
"""


def _scratchpad_row_ids(scratchpad: str) -> set[int]:
    """Extract every [N] row reference from a CoT scratchpad."""
    import re
    return {
        int(m) for m in re.findall(r'\[(\d+)\]', scratchpad or '')
    }


def cot_consistency_score(scratchpad: str, claims: list) -> dict:
    """Score whether the claims' evidence_row_ids overlap with the scratchpad's
    cited rows.  Returns ``{score, claim_ids_total, claim_ids_in_scratchpad,
    contradictions}``.

    A score < 0.5 means the model's final JSON is making claims it never
    reasoned about — typical of CoT hallucination.  Callers should refuse
    the result and fall back to single-stage output.
    """
    sp_ids = _scratchpad_row_ids(scratchpad or '')
    claim_ids: set[int] = set()
    for c in claims or []:
        if hasattr(c, 'evidence_row_ids'):
            claim_ids.update(int(x) for x in (c.evidence_row_ids or []))
        elif isinstance(c, dict):
            claim_ids.update(
                int(x) for x in (c.get('evidence_row_ids') or [])
                if isinstance(x, (int, float, str)) and str(x).isdigit()
            )
    if not claim_ids:
        return {
            'score': 0.0,
            'claim_ids_total': 0,
            'claim_ids_in_scratchpad': 0,
            'contradictions': [],
        }
    overlap = claim_ids & sp_ids
    score = len(overlap) / len(claim_ids) if claim_ids else 0.0
    contradictions = sorted(claim_ids - sp_ids)
    return {
        'score': round(score, 3),
        'claim_ids_total': len(claim_ids),
        'claim_ids_in_scratchpad': len(overlap),
        'contradictions': contradictions[:10],
    }



def build_cluster_scope(cluster: dict, assessment: dict) -> ClusterScope:
    """Extract the formal ClusterScope from a cluster + assessment."""
    prefill = cluster.get('tier1_prefill') or {}
    row_refs = cluster.get('row_refs') or []
    sources = set()
    entities: dict[str, list[str]] = {'accounts': [], 'hosts': [], 'ips': []}

    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    row_map = {r.get('row_index', i): r for i, r in enumerate(all_rows)}

    timestamps: list[str] = []
    for ref in row_refs:
        row = row_map.get(ref, {})
        src = row.get('_source') or row.get('source')
        if src:
            sources.add(str(src))
        ts = row.get('timestamp_utc') or row.get('timestamp') or row.get('ts')
        if ts:
            timestamps.append(str(ts))

    entities['accounts'] = list(set(
        str(v) for v in (prefill.get('affected_users') or cluster.get('shared_accounts') or []) if v
    ))[:10]
    entities['hosts'] = list(set(
        str(v) for v in (prefill.get('affected_assets') or cluster.get('shared_hosts') or []) if v
    ))[:10]
    entities['ips'] = list(set(
        str(v) for v in (cluster.get('shared_external_ips') or cluster.get('external_ips') or []) if v
    ))[:10]

    from .schemas import TimeRange
    time_window = TimeRange(
        start=min(timestamps) if timestamps else None,
        end=max(timestamps) if timestamps else None,
    )

    return ClusterScope(
        cluster_id=str(cluster.get('cluster_id', '')),
        threat_case_id=cluster.get('threat_case_id'),
        evidence_row_ids=sorted(int(r) for r in row_refs if isinstance(r, (int, str)) and str(r).isdigit()),
        entities=entities,
        valid_time_window=time_window,
        phase_count=len(cluster.get('phases') or []),
        telemetry_sources=sorted(sources),
        verdict=str(cluster.get('verdict') or cluster.get('final_verdict') or 'UNCERTAIN').upper(),
        confidence=cluster.get('confidence'),
        incident_name=prefill.get('incident_name') or str(cluster.get('cluster_id', '')),
        row_count=len(row_refs),
    )


def _build_evidence_block(
    scope: ClusterScope,
    assessment: dict,
    evidence_frame: Optional[EvidenceFrame] = None,
) -> str:
    """Build the EVIDENCE section for the LLM prompt."""
    all_rows = (assessment.get('normalized_rows') or
                assessment.get('evidence_rows') or
                assessment.get('rows') or [])
    row_map = {r.get('row_index', i): r for i, r in enumerate(all_rows)}

    lines: list[str] = []
    for ref in scope.evidence_row_ids[:30]:  # Cap at 30 rows for prompt size
        row = row_map.get(ref, {})
        entity = row.get('entity') or row.get('user') or row.get('ip') or '-'
        desc = row.get('description') or row.get('event_type') or ''
        severity = row.get('severity') or ''
        ts = row.get('timestamp_utc') or row.get('timestamp') or ''
        lines.append(f'[{ref}] {entity} | {severity} | {str(desc)[:120]} | {ts}')

    if evidence_frame and evidence_frame.rag_available:
        lines.append('')
        lines.append('TEMPORAL RAG CONTEXT (similar recent events):')
        for s in evidence_frame.snippets[:5]:
            lines.append(f'  {s.entity or "-"} | {s.severity or "-"} | {s.description[:80]} | {s.ts or "-"}')

    return '\n'.join(lines)


def synthesize_cluster_narrative(
    cluster: dict,
    assessment: dict,
    trajectory: BeliefTrajectory,
    evidence_frame: Optional[EvidenceFrame] = None,
    deterministic_text: str = '',
    llm_func: Optional[Any] = None,
    model: str = 'qwen3:14b',
    verdict_reasoning: Optional[dict] = None,
    quality_mode: str = 'standard',
) -> ClusterNarrative:
    """Generate a ClusterNarrative for a single cluster.

    quality_mode:
        'standard' — single-prompt cited synthesis (default; ~6-12s)
        'high'     — two-stage chain-of-thought with consistency check
                     (~25-50s; only invoked on explicit user regenerate).
                     If the CoT consistency score is < 0.5 the result is
                     rejected and we fall back to standard synthesis.
    """
    from .belief_trajectory import format_trajectory_oneliner

    scope = build_cluster_scope(cluster, assessment)
    trajectory_oneliner = format_trajectory_oneliner(trajectory)

    # Temporal context from RAG
    temporal_context = ''
    if evidence_frame and evidence_frame.rag_available:
        temporal_context = f'TEMPORAL CONTEXT: {evidence_frame.summary_hint}'

    # Verdict reasoning enrichment
    vr = verdict_reasoning or {}
    verdict_confidence = vr.get('verdict_confidence_sentence', '')
    evidence_quality = vr.get('evidence_quality', '')
    counter_hyps = vr.get('counter_hypotheses', [])
    confirming_ev = vr.get('confirming_evidence', [])
    grader_composite = vr.get('composite_score')
    grader_caveats = vr.get('grader_caveats', [])

    # Enrich deterministic text with verdict reasoning
    enriched_det = deterministic_text
    if verdict_confidence and deterministic_text:
        enriched_det = f'{deterministic_text} {verdict_confidence}'

    narrative = ClusterNarrative(
        cluster_id=scope.cluster_id,
        incident_name=scope.incident_name,
        verdict=scope.verdict,
        summary_paragraph=enriched_det,
        belief_trajectory_oneliner=trajectory_oneliner,
        verdict_confidence_sentence=verdict_confidence,
        evidence_quality=evidence_quality,
        counter_hypotheses=counter_hyps,
        confirming_evidence=confirming_ev,
        grader_composite=grader_composite,
        grader_caveats=grader_caveats,
        temporal_context=temporal_context,
        deterministic_fallback=True,
        provenance='deterministic',
    )

    if not llm_func:
        return narrative

    # Attempt LLM synthesis with citation
    evidence_block = _build_evidence_block(scope, assessment, evidence_frame)

    # ── Phase 3 — high-quality two-stage CoT (opt-in) ────────────────────────
    if quality_mode == 'high':
        try:
            stage1_prompt = _COT_STAGE1_PROMPT.format(
                incident_name=scope.incident_name,
                verdict=scope.verdict,
                trajectory_oneliner=trajectory_oneliner,
                temporal_context=temporal_context,
                evidence_block=evidence_block,
            )
            resp1 = llm_func(stage1_prompt, 800, None, {'ollama_model': model}, model)
            scratchpad = (resp1.get('text') or '').strip()
            # Strip any closing </thinking> the model may add and any
            # accidental JSON it tries to write past the scratchpad.
            for marker in ('</thinking>', '\n```', '\n{'):
                if marker in scratchpad:
                    scratchpad = scratchpad.split(marker, 1)[0].strip()

            if scratchpad and len(scratchpad) > 30:
                stage2_prompt = _COT_STAGE2_PROMPT.format(
                    incident_name=scope.incident_name,
                    verdict=scope.verdict,
                    scratchpad=scratchpad[:4000],
                    evidence_block=evidence_block,
                )
                resp2 = llm_func(stage2_prompt, 600, None, {'ollama_model': model}, model)
                raw2 = (resp2.get('text') or '').strip()
                parsed2 = _parse_llm_json(raw2)
                if parsed2:
                    summary2 = parsed2.get('summary_paragraph', '')
                    decisions2 = parsed2.get('key_decisions_required', [])
                    raw_claims2 = parsed2.get('claims', [])
                    claims2 = []
                    for rc in raw_claims2:
                        if isinstance(rc, dict):
                            claims2.append(Claim(
                                text=str(rc.get('text', '')),
                                evidence_row_ids=[
                                    int(x) for x in rc.get('evidence_row_ids', [])
                                    if isinstance(x, (int, float, str)) and str(x).isdigit()
                                ],
                                valid_time=rc.get('valid_time'),
                            ))

                    consistency = cot_consistency_score(scratchpad, claims2)
                    if summary2 and len(summary2) > 30 and consistency['score'] >= 0.5:
                        narrative.summary_paragraph = summary2
                        narrative.key_decisions_required = decisions2[:5]
                        narrative.claims = claims2
                        narrative.deterministic_fallback = False
                        narrative.provenance = (
                            f'llm_{model}_cot_score{int(consistency["score"]*100)}'
                        )
                        return narrative

                    logger.warning(
                        'CoT consistency too low for %s (score=%.2f, contradictions=%s) — '
                        'falling back to single-stage',
                        scope.cluster_id, consistency['score'], consistency['contradictions'],
                    )
                else:
                    logger.warning(
                        'CoT stage 2 produced unparseable JSON for %s — falling back',
                        scope.cluster_id,
                    )
        except Exception as exc:
            logger.warning('CoT high-quality path failed for %s: %s — falling back',
                           scope.cluster_id, exc)
    # If quality_mode='high' falls through, we attempt standard synthesis below.

    # Build verdict reasoning context for the LLM prompt
    verdict_block = ''
    if verdict_reasoning:
        vr_parts = []
        if verdict_confidence:
            vr_parts.append(f'VERDICT VALIDATION: {verdict_confidence}')
        if grader_composite is not None:
            vr_parts.append(
                f'Evidence quality: {evidence_quality} '
                f'(sufficiency={vr.get("sufficiency", 0):.0%}, '
                f'coherence={vr.get("coherence", 0):.0%}, '
                f'FP risk={vr.get("fp_risk", 0):.0%})'
            )
        if counter_hyps:
            vr_parts.append('COUNTER-HYPOTHESES (address these):')
            for ch in counter_hyps[:3]:
                vr_parts.append(f'  - {ch}')
        if grader_caveats:
            vr_parts.append('CAVEATS: ' + '; '.join(grader_caveats[:3]))
        verdict_block = '\n'.join(vr_parts)

    prompt = _CITATION_PROMPT.format(
        incident_name=scope.incident_name,
        verdict=scope.verdict,
        trajectory_oneliner=trajectory_oneliner,
        temporal_context=temporal_context,
        evidence_block=evidence_block,
        deterministic_narrative=(
            f'DETERMINISTIC NARRATIVE (improve, do not contradict):\n{deterministic_text}'
            + (f'\n\n{verdict_block}' if verdict_block else '')
            if deterministic_text else (verdict_block or '')
        ),
    )

    try:
        prompt_len = len(prompt)
        logger.warning(
            'cluster_narrative_prompt cluster_id=%s prompt_len=%d',
            scope.cluster_id, prompt_len,
        )
        resp = llm_func(prompt, 1200, None, {'ollama_model': model}, model)
        raw = (resp.get('text') or '').strip()
        # Also log full resp keys for debugging
        logger.warning(
            'cluster_narrative_resp cluster_id=%s resp_keys=%s resp_text_type=%s resp_meta=%s',
            scope.cluster_id, list(resp.keys()) if isinstance(resp, dict) else type(resp),
            type(resp.get('text')) if isinstance(resp, dict) else 'N/A',
            str(resp.get('meta', {}))[:200] if isinstance(resp, dict) else 'N/A',
        )

        logger.warning(
            'cluster_narrative_raw cluster_id=%s raw_len=%d first200=%r',
            scope.cluster_id, len(raw), raw[:200],
        )

        # Try to parse structured JSON
        parsed = _parse_llm_json(raw)
        logger.warning(
            'cluster_narrative_parsed cluster_id=%s parsed_keys=%s summary_len=%d',
            scope.cluster_id,
            list(parsed.keys()) if parsed else None,
            len(parsed.get('summary_paragraph', '')) if parsed else 0,
        )
        if parsed:
            summary = parsed.get('summary_paragraph', '')
            decisions = parsed.get('key_decisions_required', [])
            raw_claims = parsed.get('claims', [])

            claims = []
            for rc in raw_claims:
                if isinstance(rc, dict):
                    claims.append(Claim(
                        text=str(rc.get('text', '')),
                        evidence_row_ids=[
                            int(x) for x in rc.get('evidence_row_ids', [])
                            if isinstance(x, (int, float, str)) and str(x).isdigit()
                        ],
                        valid_time=rc.get('valid_time'),
                    ))

            if summary and len(summary) > 30:
                narrative.summary_paragraph = summary
                narrative.key_decisions_required = decisions[:5]
                narrative.claims = claims
                narrative.deterministic_fallback = False
                narrative.provenance = f'llm_{model}'
                return narrative

        # Fallback: accept raw text if it looks good
        if raw and len(raw) > 30 and not raw.startswith('{'):
            narrative.summary_paragraph = raw
            narrative.deterministic_fallback = False
            narrative.provenance = f'llm_{model}_unstructured'

    except Exception as exc:
        logger.warning('cluster narrative LLM failed for %s: %s', scope.cluster_id, exc)

    return narrative


def _parse_llm_json(text: str) -> Optional[dict]:
    """Try to extract JSON from LLM output (handles markdown code fences and
    qwen3-style <think>...</think> reasoning blocks)."""
    import re
    if not text:
        return None
    # Strip qwen3 reasoning block(s) wherever they appear
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
    # Strip any unclosed leading <think>...
    text = re.sub(r'^<think>.*?(?=\{)', '', text, flags=re.DOTALL).strip()
    # Strip markdown code fence if present
    match = re.search(r'```(?:json)?\s*\n?(.*?)```', text, re.DOTALL)
    if match:
        text = match.group(1).strip()
    # If still doesn't start with `{`, try to find the first JSON object
    if not text.startswith('{'):
        idx = text.find('{')
        if idx == -1:
            return None
        text = text[idx:]
    # Trim trailing junk after the last balanced `}`
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Try to extract the first balanced JSON object
        depth = 0
        for i, ch in enumerate(text):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[:i + 1])
                    except (json.JSONDecodeError, ValueError):
                        return None
        return None
