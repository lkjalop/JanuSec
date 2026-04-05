from __future__ import annotations
import time
from typing import Any, Dict, Optional, Tuple
from functools import lru_cache

CACHE_TTL = int( ( __import__('os').environ.get('GRAPH_FEATURES_CACHE_TTL', '45') ) )


class _SimpleCache:
    def __init__(self):
        self._store: Dict[Tuple[str,str], Tuple[float, Dict[str, Any]]] = {}

    def get(self, key: Tuple[str,str]) -> Optional[Dict[str, Any]]:
        v = self._store.get(key)
        if not v:
            return None
        ts, payload = v
        if time.time() - ts > CACHE_TTL:
            try:
                del self._store[key]
            except Exception:
                pass
            return None
        return payload

    def set(self, key: Tuple[str,str], payload: Dict[str, Any]) -> None:
        self._store[key] = (time.time(), payload)


_CACHE = _SimpleCache()


def enrich_event_with_graph(event: Dict[str, Any], seed_event_id: Optional[str] = None, user: Optional[str] = None, within_seconds: int = 3600, depth: int = 3) -> Dict[str, Any]:
    """Enrich event dict with graph-derived features. Best-effort; non-throwing.

    Adds keys:
      - graph_lateral_chain_len: int
      - graph_lateral_chain_hosts: int
      - graph_phase_counts: dict
      - graph_first_dc_ts: float | None
      - graph_initial_access_ts: float | None
    """
    try:
        from src.core.graph.hopgraph_lite import get_graph
    except Exception:
        return event

    key_user = user or event.get('user') or ''
    key_seed = seed_event_id or event.get('id') or ''
    cache_key = (key_user, key_seed)
    cached = _CACHE.get(cache_key)
    if cached:
        event.update(cached)
        return event

    out: Dict[str, Any] = {}
    try:
        g = get_graph()
        # lateral chains
        try:
            chains = g.detect_lateral_chain(key_user, within_seconds)
            # chains: list of chain objects or sequences
            max_len = 0
            hosts = set()
            if chains:
                for ch in chains:
                    # accept dict or list
                    nodes = ch.get('nodes') if isinstance(ch, dict) and 'nodes' in ch else (list(ch) if hasattr(ch, '__iter__') else [])
                    l = len(nodes)
                    if l > max_len:
                        max_len = l
                    for n in nodes:
                        try:
                            h = n.get('host') if isinstance(n, dict) else None
                            if h:
                                hosts.add(h)
                        except Exception:
                            pass
            out['graph_lateral_chain_len'] = int(max_len or 0)
            out['graph_lateral_chain_hosts'] = int(len(hosts))
        except Exception:
            out['graph_lateral_chain_len'] = 0
            out['graph_lateral_chain_hosts'] = 0

        # reconstruct to derive phase counts and timestamps
        try:
            recon = g.reconstruct_attack({'user': key_user, 'id': key_seed} if key_user or key_seed else None, depth=depth)
            # recon assumed to have nodes and timeline
            phase_counts = {'initial_access': 0, 'execution': 0, 'lateral': 0, 'exfil': 0}
            first_dc_ts = None
            initial_access_ts = None
            try:
                # iterate timeline entries if present
                timeline = recon.get('timeline') if isinstance(recon, dict) else None
                if timeline and isinstance(timeline, list):
                    for entry in timeline:
                        ttype = entry.get('phase') if isinstance(entry, dict) else None
                        ts = entry.get('ts') if isinstance(entry, dict) else None
                        if ttype and ttype in phase_counts:
                            phase_counts[ttype] += 1
                        if ttype == 'initial_access' and initial_access_ts is None:
                            initial_access_ts = ts
                        # detect DC
                        host = entry.get('host') if isinstance(entry, dict) else None
                        if host and ('dc' in str(host).lower() or 'domaincontroller' in str(host).lower()):
                            if first_dc_ts is None:
                                first_dc_ts = ts
            except Exception:
                pass
            out['graph_phase_counts'] = phase_counts
            out['graph_first_dc_ts'] = first_dc_ts
            out['graph_initial_access_ts'] = initial_access_ts
        except Exception:
            out['graph_phase_counts'] = {'initial_access': 0, 'execution': 0, 'lateral': 0, 'exfil': 0}
            out['graph_first_dc_ts'] = None
            out['graph_initial_access_ts'] = None

    except Exception:
        # If anything fails, keep defaults
        out.setdefault('graph_lateral_chain_len', 0)
        out.setdefault('graph_lateral_chain_hosts', 0)
        out.setdefault('graph_phase_counts', {'initial_access': 0, 'execution': 0, 'lateral': 0, 'exfil': 0})
        out.setdefault('graph_first_dc_ts', None)
        out.setdefault('graph_initial_access_ts', None)

    # update cache & event
    try:
        _CACHE.set(cache_key, out)
    except Exception:
        pass
    event.update(out)
    return event


def sample_graph_examples(event: Dict[str, Any], seed_event_id: Optional[str] = None, user: Optional[str] = None, max_examples: int = 3, depth: int = 4) -> list[Dict[str, Any]]:
    """Best-effort sampler that returns a small list of reconstructed graph examples.

    Each example is a compact dict with a short node path and a brief timeline excerpt
    suitable for inclusion in a decision object's `graph_evidence.examples` field.

    This is intentionally conservative (size-limited and non-throwing).
    """
    try:
        from src.core.graph.hopgraph_lite import get_graph
    except Exception:
        return []

    key_user = user or event.get('user') or ''
    key_seed = seed_event_id or event.get('id') or ''
    examples: list[Dict[str, Any]] = []
    try:
        g = get_graph()
        recon = g.reconstruct_attack({'user': key_user, 'id': key_seed} if key_user or key_seed else None, depth=depth)
        # recon may be a dict with 'chains' or 'timeline'; extract compact examples
        if not isinstance(recon, dict):
            return []
        # prefer chains if present
        chains = recon.get('chains') or recon.get('detected_chains') or []
        if chains and isinstance(chains, list):
            for ch in chains[:max_examples]:
                try:
                    nodes = ch.get('nodes') if isinstance(ch, dict) else (list(ch) if hasattr(ch, '__iter__') else [])
                    path = [ (n.get('host') or n.get('id') or str(n)) for n in nodes ]
                    examples.append({'path': path, 'length': len(path)})
                except Exception:
                    pass
        # fallback to timeline snippets
        if not examples:
            timeline = recon.get('timeline') if isinstance(recon, dict) else None
            if timeline and isinstance(timeline, list):
                for entry in timeline[:max_examples]:
                    try:
                        examples.append({'phase': entry.get('phase'), 'ts': entry.get('ts'), 'host': entry.get('host')})
                    except Exception:
                        pass
    except Exception:
        return []
    return examples
