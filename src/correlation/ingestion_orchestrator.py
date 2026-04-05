"""Ingestion orchestrator: parse raw records into canonical events, extract factors, reconstruct kill chain."""
from typing import List, Dict, Any
from .canonical_event import CanonicalEvent
from .parsers.email_parser import parse_email_record
from .parsers.network_parser import parse_network_record
from .parsers.endpoint_parser import parse_endpoint_record
from .parsers.remote_parser import parse_remote_record
from .parsers.iam_parser import parse_iam_record
from .parsers.data_parser import parse_data_record
from .parsers.api_parser import parse_api_record
from .parsers.other_parser import parse_other_record
from .parsers.ai_parser import parse_ai_record
from .factors.factors_email import extract_email_factors
from .factors.factors_network import extract_network_factors
from .factors.factors_remote import extract_remote_factors
from .factors.factors_iam import extract_iam_factors
from .factors.factors_endpoint import extract_endpoint_factors
from .factors.factors_data import extract_data_factors
from .factors.factors_api import extract_api_factors
from .factors.factors_cross import extract_cross_domain_factors
from .factors.factors_ai import extract_ai_factors
from .killchain_reconstruct import reconstruct_kill_chain
from .explanations.mappings import build_explanations
from src.core.baseline_context import build_baseline_context

PARSERS = {
    'email': parse_email_record,
    'network': parse_network_record,
    'endpoint': parse_endpoint_record,
    'remote': parse_remote_record,
    'iam': parse_iam_record,
    'data': parse_data_record,
    'api': parse_api_record,
    'ai': parse_ai_record,
    'other': parse_other_record,
}

def ingest_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    events: List[CanonicalEvent] = []
    for r in records:
        st = str(r.get('source_type') or r.get('domain_type') or 'other').lower()
        parser = PARSERS.get(st)
        if not parser:
            continue
        try:
            ev = parser(r)
            events.append(ev)
        except Exception:
            continue
    # Factor extraction across domains
    email_factors = extract_email_factors(events)
    network_factors = extract_network_factors(events)
    remote_factors = extract_remote_factors(events)
    iam_factors = extract_iam_factors(events)
    endpoint_factors = extract_endpoint_factors(events)
    data_factors = extract_data_factors(events)
    api_factors = extract_api_factors(events)
    ai_factors = extract_ai_factors(events)
    cross_factors = extract_cross_domain_factors(events)
    factors = email_factors + network_factors + remote_factors + iam_factors + endpoint_factors + data_factors + api_factors + ai_factors + cross_factors
    kill_chain = reconstruct_kill_chain(factors)
    explanations = build_explanations(factors, kill_chain)
    baseline_ctx = {}
    try:
        tenant_id = None
        if events:
            tenant_id = events[0].tenant
        baseline_ctx = build_baseline_context(
            events[0].raw if events else {},
            tenant_id,
            value=float(len(factors)),
        )
    except Exception:
        baseline_ctx = {}
    # Confidence scoring based on kill chain stage confidences and continuity/diversity bonuses
    stage_conf = {entry['stage']: entry['confidence'] for entry in kill_chain}
    distinct_order = [entry['stage'] for entry in kill_chain]
    continuity_bonus = 0.05 * max(0, len(distinct_order) - 1)
    diversity_bonus = 0.03 * len(stage_conf.keys())
    base = (sum(stage_conf.values()) / max(1, len(stage_conf))) if stage_conf else 0.0
    overall_confidence = min(0.99, base + continuity_bonus + diversity_bonus)
    explanations['confidence_overall'] = overall_confidence
    explanations['confidence_breakdown'] = {
        'per_stage': stage_conf,
        'continuity_bonus': continuity_bonus,
        'diversity_bonus': diversity_bonus,
        'base': base
    }
    if baseline_ctx:
        explanations['baseline_context'] = baseline_ctx
    return {
        'events_count': len(events),
        'factors': factors,
        'kill_chain': kill_chain,
        'explanations': explanations,
        'baseline_context': baseline_ctx
    }
