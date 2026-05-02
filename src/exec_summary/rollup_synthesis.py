"""Assessment-level rollup from per-cluster narratives.

Synthesizes a 1-paragraph executive summary combining all cluster narratives,
using either deterministic concatenation or an optional LLM pass.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .schemas import ClusterNarrative

logger = logging.getLogger(__name__)


def synthesize_rollup(
    cluster_narratives: list[ClusterNarrative],
    assessment_verdict: str = 'UNCERTAIN',
    total_rows: int = 0,
    llm_func: Optional[Any] = None,
    model: str = 'qwen3:14b',
) -> tuple[str, str]:
    """Produce a 1-paragraph rollup from cluster narratives.

    Returns (rollup_text, provenance).
    """
    if not cluster_narratives:
        return ('No clusters to summarise.', 'deterministic')

    # Deterministic backbone — always usable
    deterministic = _deterministic_rollup(
        cluster_narratives, assessment_verdict, total_rows,
    )

    if not llm_func:
        return (deterministic, 'deterministic')

    # Attempt LLM rollup
    per_cluster_block = '\n\n'.join(
        f'--- Cluster: {cn.incident_name} ({cn.verdict}) ---\n{cn.summary_paragraph}'
        for cn in cluster_narratives
    )

    prompt = (
        'You are writing a 1-paragraph executive rollup (4-5 sentences) for a CISO.\n'
        'Combine the following per-cluster summaries into a single coherent narrative.\n'
        'Do not add new facts. Cross-reference shared entities where clusters overlap.\n'
        f'Overall assessment verdict: {assessment_verdict}. Total evidence rows: {total_rows}.\n\n'
        'CLUSTER SUMMARIES:\n'
        f'{per_cluster_block}\n\n'
        'Write the rollup paragraph now.'
    )

    try:
        resp = llm_func(prompt, 400, None, {'ollama_model': model}, model)
        text = (resp.get('text') or '').strip()
        if text and len(text) > 40 and not text.startswith('{'):
            return (text, f'llm_{model}')
    except Exception as exc:
        logger.debug('rollup LLM failed: %s', exc)

    return (deterministic, 'deterministic')


def _deterministic_rollup(
    cluster_narratives: list[ClusterNarrative],
    assessment_verdict: str,
    total_rows: int,
) -> str:
    """Build a deterministic rollup from cluster narratives."""
    n = len(cluster_narratives)
    confirmed = sum(1 for cn in cluster_narratives if cn.verdict == 'CONFIRMED')
    uncertain = sum(1 for cn in cluster_narratives if cn.verdict == 'UNCERTAIN')
    dismissed = n - confirmed - uncertain

    parts = [
        f'This assessment analysed {total_rows} evidence rows across {n} threat cluster{"s" if n > 1 else ""}.'
    ]

    verdict_parts = []
    if confirmed:
        verdict_parts.append(f'{confirmed} confirmed')
    if uncertain:
        verdict_parts.append(f'{uncertain} uncertain')
    if dismissed:
        verdict_parts.append(f'{dismissed} dismissed')
    if verdict_parts:
        parts.append(f'Verdicts: {", ".join(verdict_parts)}.')

    # Top 3 cluster headlines
    for cn in cluster_narratives[:3]:
        # Take first sentence of each cluster summary
        first_sentence = cn.summary_paragraph.split('.')[0].strip()
        if first_sentence:
            parts.append(f'{cn.incident_name}: {first_sentence}.')

    parts.append(f'Overall assessment: {assessment_verdict}.')
    return ' '.join(parts)
