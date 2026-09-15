"""Incident summarization utilities (Phase 1).

Dual-mode:
 1. Factor list condensation (legacy behavior)
 2. Narrative augmentation via simple rule templates (analyst oriented)

Future: plug-in interface for ML (SecBERT/CyBERT style) summarizer.
"""
from __future__ import annotations

from typing import List

BASE_TEMPLATES = [
    (lambda f: any(x.startswith('corr_') for x in f),
     lambda f: "Correlation combined multiple weak signals raising confidence."),
    (lambda f: any('ja3' in x for x in f),
     lambda f: "Novel TLS client fingerprint (JA3 rarity) may indicate uncommon tooling."),
    (lambda f: any('proc_parent_chain' in x for x in f),
     lambda f: "Suspicious parent-child process lineage suggests lateral movement or staged execution."),
]

def _condense(factors: list[str], max_len: int) -> str:
    core = [f for f in factors if not f.startswith('timings:')]
    seen = set(); ordered: list[str] = []
    for f in core:
        if f not in seen:
            seen.add(f); ordered.append(f)
    summary = ', '.join(ordered[:25])
    if len(summary) > max_len:
        summary = summary[:max_len-3] + '...'
    return summary

def summarize_factors(factors: list[str], max_len: int = 240, narrative: bool = True) -> str:
    if not factors:
        return "no factors"
    compressed = _condense(factors, max_len)
    if not narrative:
        return compressed
    messages: list[str] = []
    for pred, builder in BASE_TEMPLATES:
        try:
            if pred(factors):
                messages.append(builder(factors))
        except Exception:
            continue
    if messages:
        return compressed + " | " + " ".join(messages)
    return compressed

__all__ = ['summarize_factors']
