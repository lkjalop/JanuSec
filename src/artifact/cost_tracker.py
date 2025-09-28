from __future__ import annotations
import os, time
from typing import Dict, Any

# Centralized cost tracking state to avoid circular imports with server.

COST_STATE: Dict[str, Any] = {
    'embedding_calls': 0,
    'embedding_ms': 0.0,
    'reputation_queries': 0,
    'artifacts_processed': 0,
    'llm_tokens': 0,
    'daily_rollups': []  # list of {day, estimated_usd}
}

def prices() -> Dict[str,float]:
    return {
        'embedding_call': float(os.getenv('COST_PER_EMBED_CALL','0.0005')),
        'reputation_query': float(os.getenv('COST_PER_REPUTATION_QUERY','0.002')),
        'llm_1k_tokens': float(os.getenv('COST_PER_LLM_1K_TOKENS','0.03')),
        'artifact_base': float(os.getenv('COST_PER_ARTIFACT_BASE','0.00005')),
    }

def record_artifacts(n:int):
    COST_STATE['artifacts_processed'] += n

def record_embedding(calls:int, ms:float):
    COST_STATE['embedding_calls'] += calls
    COST_STATE['embedding_ms'] += ms

def record_reputation(n:int):
    COST_STATE['reputation_queries'] += n

def record_llm_tokens(tokens:int):
    COST_STATE['llm_tokens'] += tokens

def day_estimate() -> float:
    p = prices()
    return (
        COST_STATE['embedding_calls'] * p['embedding_call'] +
        COST_STATE['reputation_queries'] * p['reputation_query'] +
        (COST_STATE['llm_tokens']/1000.0) * p['llm_1k_tokens'] +
        COST_STATE['artifacts_processed'] * p['artifact_base']
    )

def summary() -> Dict[str,Any]:
    day = time.strftime('%Y-%m-%d', time.gmtime())
    month_prefix = day[:7]
    est_day = day_estimate()
    month_total = est_day
    for r in COST_STATE['daily_rollups']:
        if r['day'].startswith(month_prefix):
            month_total += r['estimated_usd']
    return {
        'day': day,
        'embedding_calls': COST_STATE['embedding_calls'],
        'reputation_queries': COST_STATE['reputation_queries'],
        'artifacts_processed': COST_STATE['artifacts_processed'],
        'llm_tokens': COST_STATE['llm_tokens'],
        'estimated_usd_day': round(est_day,6),
        'estimated_usd_month_to_date': round(month_total,6),
        'unit_prices': prices()
    }
