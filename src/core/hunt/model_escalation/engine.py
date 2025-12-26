"""Model Escalation Engine Scaffold

Phase 1: heuristic confidence gain via multi-tier provider chain.
This module is intentionally lightweight; real provider adapters should be
placed under providers/ with a consistent async interface.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

# ---------------- Config & Types -----------------

@dataclass
class ProviderTier:
    tier: int
    provider: str
    model: str
    max_cost_units: float
    timeout_s: float = 6.0

@dataclass
class ProviderResult:
    text: str
    tokens: int
    cost_units: float
    latency_s: float
    error: str | None = None

class ModelProvider(Protocol):
    name: str
    async def generate(self, prompt: str, context: dict[str, Any]) -> ProviderResult: ...

# ---------------- Chain Loader -----------------

def load_chain() -> list[ProviderTier]:
    raw = os.getenv('MODEL_ESCALATION_CHAIN_JSON')
    if not raw:
        return []
    try:
        data = json.loads(raw)
        out: list[ProviderTier] = []
        for d in data:
            out.append(ProviderTier(
                tier=int(d.get('tier',0)),
                provider=d['provider'],
                model=d['model'],
                max_cost_units=float(d.get('max_cost_units',0.1)),
                timeout_s=float(d.get('timeout_s',6.0))
            ))
        out.sort(key=lambda x: x.tier)
        return out
    except Exception:
        return []

# ---------------- Provider Registry (Stubs) -----------------

async def call_provider(tier: ProviderTier, prompt: str, context: dict[str, Any]) -> ProviderResult:
    start = time.time()
    # Placeholder logic – integrate real adapters (ollama/openai/anthropic) later.
    await asyncio.sleep(min(0.05, tier.timeout_s/100))
    # Pseudo tokens: length / 4
    toks = max(1, len(prompt)//4)
    base_cost = toks/1000.0 * 0.01  # fake micro-cost
    return ProviderResult(
        text=f"[tier {tier.tier} {tier.provider}:{tier.model}] analysis placeholder.",
        tokens=toks,
        cost_units=base_cost,
        latency_s=time.time()-start,
        error=None
    )

# ---------------- Gain Estimation Heuristic -----------------

_DECISIVE = ("malicious","confirmed","definitive","benign")
_HEDGE = ("maybe","unclear","ambiguous","potentially")

def estimate_gain(text: str) -> float:
    lower = text.lower()
    decisive = sum(lower.count(w) for w in _DECISIVE)
    hedge = sum(lower.count(w) for w in _HEDGE)
    # novelty proxy via digest entropy
    digest = hashlib.sha256(lower.encode()).digest()
    entropy = len(set(digest)) / 32.0  # 0..1
    gain = 0.08*entropy + 0.05*decisive - 0.04*hedge
    return max(0.0, min(gain, 0.25))

# ---------------- Escalation Core -----------------

CONF_MIN = float(os.getenv('ESCALATION_CONF_MIN','0.55'))
CONF_TARGET = float(os.getenv('ESCALATION_CONF_TARGET','0.70'))
MAX_ESCALATION_GAIN = float(os.getenv('ESCALATION_MAX_GAIN','0.35'))
PER_ITEM_BUDGET = float(os.getenv('ESCALATION_PER_ITEM_BUDGET','1.0'))

@dataclass
class EscalationResult:
    final_confidence: float
    trace: list[dict[str, Any]]
    status: str  # accepted|none|partial|budget_exceeded|all_failed

# triggers() expects obs like artifact observation dict

def triggers(obs: dict[str, Any], base_conf: float, base_risk: float, escalate_thr: float, block_thr: float) -> bool:
    if base_risk < escalate_thr or base_risk >= block_thr:
        return False
    if base_conf >= CONF_MIN and (obs.get('ambiguity') or 0) <= 0.4:
        return False
    factors = obs.get('factors') or []
    catalyst = any(f.startswith(('rare_','corr_','multi_factor','lane_')) for f in factors)
    return catalyst or base_conf < CONF_MIN

async def escalate(obs: dict[str, Any], base_conf: float, base_risk: float, escalate_thr: float, block_thr: float) -> EscalationResult:
    if not triggers(obs, base_conf, base_risk, escalate_thr, block_thr):
        return EscalationResult(base_conf, [], 'none')
    chain = load_chain()
    if not chain:
        return EscalationResult(base_conf, [], 'none')
    cumulative = 0.0
    trace: list[dict[str, Any]] = []
    budget_used = 0.0
    # Lazy metric creation
    try:  # pragma: no cover - metrics optional
        from prometheus_client import Counter as _C  # type: ignore
        if 'model_escalation_attempts_total' not in globals():
            globals()['model_escalation_attempts_total'] = _C(
                'model_escalation_attempts_total',
                'Model escalation provider attempts by status',
                ['provider','status']
            )  # type: ignore
        if 'model_escalation_confidence_gain_total' not in globals():
            globals()['model_escalation_confidence_gain_total'] = _C(
                'model_escalation_confidence_gain_total',
                'Confidence gain accumulated from model escalations by provider',
                ['provider']
            )  # type: ignore
    except Exception:
        pass
    for tier in chain:
        if budget_used >= PER_ITEM_BUDGET:
            return EscalationResult(base_conf + cumulative, trace, 'budget_exceeded')
        try:
            prompt = build_prompt(obs, base_conf + cumulative, base_risk)
            res = await call_provider(tier, prompt, {'artifact_id': obs.get('artifact_id')})
            budget_used += res.cost_units
            if res.error:
                trace.append({
                    'tier': tier.tier,
                    'provider': tier.provider,
                    'model': tier.model,
                    'confidence_gain': 0.0,
                    'cost_units': res.cost_units,
                    'latency_ms': int(res.latency_s*1000),
                    'accepted': False,
                    'error': res.error
                })
                try:
                    if 'model_escalation_attempts_total' in globals():
                        globals()['model_escalation_attempts_total'].labels(provider=tier.provider, status='error').inc()  # type: ignore
                except Exception:
                    pass
                continue
            gain = estimate_gain(res.text)
            allowed_gain = min(gain, MAX_ESCALATION_GAIN - cumulative)
            cumulative += allowed_gain
            achieved = base_conf + cumulative
            accepted = achieved >= CONF_TARGET
            trace.append({
                'tier': tier.tier,
                'provider': tier.provider,
                'model': tier.model,
                'confidence_gain': round(allowed_gain,4),
                'cost_units': res.cost_units,
                'latency_ms': int(res.latency_s*1000),
                'accepted': accepted,
                'error': None
            })
            try:
                if 'model_escalation_attempts_total' in globals():
                    globals()['model_escalation_attempts_total'].labels(provider=tier.provider, status='accepted' if accepted else 'attempt').inc()  # type: ignore
                if allowed_gain > 0 and 'model_escalation_confidence_gain_total' in globals():
                    globals()['model_escalation_confidence_gain_total'].labels(provider=tier.provider).inc(allowed_gain)  # type: ignore
            except Exception:
                pass
            if accepted:
                return EscalationResult(achieved, trace, 'accepted')
        except Exception as e:  # provider call error
            trace.append({
                'tier': tier.tier,
                'provider': tier.provider,
                'model': tier.model,
                'confidence_gain': 0.0,
                'cost_units': 0.0,
                'latency_ms': 0,
                'accepted': False,
                'error': str(e)
            })
            try:
                if 'model_escalation_attempts_total' in globals():
                    globals()['model_escalation_attempts_total'].labels(provider=tier.provider, status='error').inc()  # type: ignore
            except Exception:
                pass
    status = 'partial' if cumulative > 0 else 'all_failed'
    return EscalationResult(base_conf + cumulative, trace, status)

# ---------------- Prompt Builder -----------------

def build_prompt(obs: dict[str, Any], current_conf: float, risk: float) -> str:
    factors = ', '.join((obs.get('factors') or [])[:12])
    return (
        f"Artifact risk context: risk={risk:.2f} current_conf={current_conf:.2f}\n"
        f"Factors: {factors}\n"
        "Goal: Provide concise decisive classification cues; avoid hedging."
    )
