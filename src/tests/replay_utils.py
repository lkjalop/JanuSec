"""Helpers for deterministic replay during tests.

This module exposes `reset_for_replay()` which attempts to clear common
process-global state that influences detection factor emission and hashing.
It is intentionally defensive (best-effort) — some state is module- or
instance-scoped and must be reset by the owning component; this helper
clears the most impactful global caches used in tests.
"""
from __future__ import annotations

import importlib
import os
import random
from typing import Optional


def reset_for_replay() -> None:
    """Clear global singletons and sketches to improve determinism.

    This function is best-effort: it imports known modules and clears
    common global caches (cluster dedupe, hopgraph default graph,
    streaming rarity last_seen, etc.). It also seeds the `random`
    module and sets `REPLAY_DETERMINISTIC` in the environment for
    detectors that honor that flag.
    """
    # seed standard RNG
    random.seed(0)
    os.environ['REPLAY_DETERMINISTIC'] = '1'

    # reset cluster dedupe seen map via public helper when available
    try:
        try:
            mod = importlib.import_module('core.correlation.cluster_dedupe')
        except Exception:
            mod = importlib.import_module('src.core.correlation.cluster_dedupe')
        if hasattr(mod, 'reset_cluster_cache'):
            try:
                mod.reset_cluster_cache()
            except Exception:
                pass
        if hasattr(mod, '_seen'):
            try:
                mod._seen.clear()
            except Exception:
                pass
    except Exception:
        pass

    # reset hopgraph module-level default
    try:
        try:
            hg = importlib.import_module('src.core.graph.hopgraph_lite')
        except Exception:
            hg = importlib.import_module('core.graph.hopgraph_lite')
        try:
            hg._default_graph = hg.HopGraphLite()
        except Exception:
            # some variants may name the class differently; ignore failures
            pass
    except Exception:
        pass

    # clear streaming rarity last_seen map used by novelty detectors
    try:
        try:
            stream = importlib.import_module('src.metrics.streaming')
        except Exception:
            stream = importlib.import_module('metrics.streaming')
        if hasattr(stream, 'RARITY_DAILY') and hasattr(stream.RARITY_DAILY, 'last_seen'):
            try:
                stream.RARITY_DAILY.last_seen.clear()
            except Exception:
                pass
    except Exception:
        pass

    # Best-effort: clear any commonly-used module-level maps that are
    # plausibly present (examples discovered in the codebase).
    candidates = [
        'src.core.hunt.lanes.ja3_novelty',
        'core.hunt.lanes.ja3_novelty',
    ]
    for c in candidates:
        try:
            mod = importlib.import_module(c)
            if hasattr(mod, 'GLOBAL_FREQ'):
                try:
                    getattr(mod, 'GLOBAL_FREQ').clear()
                except Exception:
                    pass
        except Exception:
            continue
