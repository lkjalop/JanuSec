"""Minimal HopGraph-like helpers for Sultry: rare_prevalence, multi-host emergence."""
from collections import Counter, defaultdict
from typing import List, Dict, Any


def rare_prevalence(entities: List[str], threshold: float = 0.01) -> float:
    """Compute prevalence of rare entities in the list.

    Returns fraction of entities that appear less than threshold of total.
    """
    n = len(entities)
    if n == 0:
        return 0.0
    counts = Counter(entities)
    rare = sum(1 for v in counts.values() if v / n < threshold)
    return rare / len(counts)


def multi_host_emergence(records: List[Dict[str, Any]], entity_key: str = 'file_hash') -> Dict[str, float]:
    """Detect emergence of identical entity appearing across multiple hosts.

    records: list of records each containing at least `host` and `entity_key`.
    Returns mapping entity -> emergence_score (0..1) where score = distinct_hosts / total_hosts
    """
    hosts = set()
    entity_hosts = defaultdict(set)
    for r in records:
        h = r.get('host') or r.get('ip') or 'unknown'
        hosts.add(h)
        e = r.get(entity_key)
        if e:
            entity_hosts[e].add(h)

    total_hosts = max(1, len(hosts))
    return {e: len(hs) / total_hosts for e, hs in entity_hosts.items()}


def summarize_context(records: List[Dict[str, Any]], entity_key: str = 'file_hash') -> Dict[str, Any]:
    """Return compact contextual features used by Sultry: rare_prevalence and multi_host_emergence top items."""
    # collect entities list for prevalence
    entities = [r.get(entity_key) for r in records if r.get(entity_key)]
    rp = rare_prevalence(entities)
    mhe = multi_host_emergence(records, entity_key=entity_key)
    # pick top 3 emergent
    top = sorted(mhe.items(), key=lambda kv: kv[1], reverse=True)[:3]
    return {
        'rare_prevalence': rp,
        'multi_host_top': top,
        'multi_host_count': len(mhe),
    }
