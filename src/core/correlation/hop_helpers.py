from typing import List, Dict, Any, Optional
import os

# Simple in-memory test neighbor mapping that tests can populate.
_TEST_NEIGHBORS = {}


def set_test_neighbors(mapping: Dict[str, List[Dict[str, Any]]]) -> None:
    _TEST_NEIGHBORS.clear()
    for k, v in mapping.items():
        _TEST_NEIGHBORS[k] = v


def hopgraph_neighbors(host: str, process_contains: Optional[str] = None) -> List[Dict[str, Any]]:
    """Prototype HopGraph neighbor lookup.

    Test mode: if `_TEST_NEIGHBORS` populated, return entries for `host`.
    Production: this should call the HopGraph service (not implemented here).
    """
    if not host:
        return []
    # Test override
    if host in _TEST_NEIGHBORS:
        res = _TEST_NEIGHBORS[host]
        if process_contains:
            return [n for n in res if process_contains.lower() in (n.get('process','').lower() or '')]
        return res
    # Production path would query HopGraph/adjacency store; return empty for now.
    return []

