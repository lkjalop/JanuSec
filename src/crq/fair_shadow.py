"""FAIR-lite shadow overlay prototypes.
Provides compute_fair_row and aggregate_persona_rollup functions and persists observations.
"""
from __future__ import annotations
import json, time
from pathlib import Path
from typing import Dict, Any, List, Optional
try:
    from src.enrichment.mapping import enrichment_to_dread_inputs
except Exception:
    enrichment_to_dread_inputs = None

from src.crq.persistence import FileCRQPersistence, CRQPersistence

# Default persistence (file-backed). Can be overridden in tests via set_crq_persistence()
_PERSIST_INSTANCE: Optional[CRQPersistence] = None

def _default_persist_instance() -> CRQPersistence:
    global _PERSIST_INSTANCE
    if _PERSIST_INSTANCE is None:
        _PERSIST_INSTANCE = FileCRQPersistence()
    return _PERSIST_INSTANCE

def set_crq_persistence(instance: CRQPersistence) -> None:
    global _PERSIST_INSTANCE
    _PERSIST_INSTANCE = instance

def compute_fair_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Heuristic FAIR-lite computation returning lef, lm, expected_loss.
    Expects row to contain 'canonical' with 'file_hash' and 'host' etc.
    """
    # rudimentary priors — to be calibrated
    exposure = 1.0
    # Likelihood of action (LOA) proxy: presence of file_hash increases LOA
    loa = 0.05
    if row.get('canonical', {}).get('file_hash'):
        loa = 0.2
    # Vulnerability/Exploitability proxy (use EPSS if available in reputation)
    ep = 0.01
    rep = row.get('reputation') or {}
    # if any hash is tagged high risk, bump
    for k,v in (rep or {}).items():
        if isinstance(v, dict) and v.get('severity') in ('high','critical'):
            ep = max(ep, 0.5)
    # Asset value proxy (LEF) by sensitivity meta
    sensitivity = float(row.get('meta', {}).get('sensitivity') or row.get('sensitivity') or 1.0)
    lef = 1000.0 * sensitivity
    expected_loss = lef * loa * ep
    out = {'lef': lef, 'loa': loa, 'ep': ep, 'expected_loss': expected_loss, 'ts': time.time()}
    # Include DREAD inputs when enrichment mapping available
    rep = row.get('reputation') or {}
    try:
        if enrichment_to_dread_inputs is not None and isinstance(rep, dict):
            # pick first enrichment record for mapping heuristics
            # rep may be a dict keyed by source
            if rep:
                # flatten to first value
                first = None
                for v in rep.values():
                    first = v; break
                if first is None:
                    first = rep
                dre = enrichment_to_dread_inputs(first if isinstance(first, dict) else {})
                out['dread_inputs'] = dre
    except Exception:
        pass
    return out

def persist_shadow_observation(obs: Dict[str, Any]) -> None:
    try:
        inst = _PERSIST_INSTANCE or _default_persist_instance()
        inst.persist(obs)
    except Exception:
        # best-effort persistence
        pass


def link_observation_to_tenant(obs: Dict[str, Any], tenant: str) -> None:
    """Simple helper to tag and persist tenant-linked view for persona rollups.

    This appends `tenant` to the observation and writes once more to disk.
    """
    try:
        obs2 = dict(obs)
        obs2['tenant'] = tenant
        try:
            inst = _PERSIST_INSTANCE or _default_persist_instance()
            inst.persist(obs2)
        except Exception:
            pass
    except Exception:
        pass

def aggregate_persona_rollup(observations: List[Dict[str, Any]]) -> Dict[str, Any]:
    # personas: exec, grc, soc, owner — map to simple aggregations
    total = sum(o.get('expected_loss', 0.0) for o in observations)
    return {
        'count': len(observations),
        'aggregate_expected_loss': total,
        'per_persona': {
            'exec': {'annualized_expected_loss': total},
            'grc': {'exposures': len(observations)},
            'soc': {'alerts': len(observations)},
            'owner': {'items': len(observations)}
        }
    }
