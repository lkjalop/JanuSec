"""Unified HopGraph Interface

Provides a thin abstraction over the currently co-existing graph variants in the
codebase (graph.hopgraph.HopGraph, core.graph.hopgraph_lite.HopGraphLite,
core.hunt.hopgraph_light.HopGraphLight, artifact.hopgraph_lite.HopGraphLite).

Goals:
 - Offer a single import point for future code (`from graph.unified import UG`) without
   forcing an immediate invasive refactor of legacy modules.
 - Normalize a minimal surface: add_edge(src,dst,etype,**kw), explain_chain(node,...),
   k_hops(node,k), stats().
 - Provide lazy detection & selection: prefer persistent full HopGraph if available,
   else fall back to lightweight ephemeral implementations.
 - Allow future injection of a temporal windowing strategy or alternate backend
   (e.g., TigerGraph / Neo4j) without touching callers.

This is intentionally lightweight; it does NOT attempt to coalesce data between
multiple variants. The first viable provider discovered wins. A future migration
could add federation or a write-through model.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
import importlib
import logging

logger = logging.getLogger(__name__)


@dataclass
class _ProviderCaps:
    name: str
    obj: Any
    weight: int  # preference ordering (higher wins)


class UnifiedGraph:
    def __init__(self) -> None:
        self._provider: Optional[_ProviderCaps] = None
        self._detect_provider()

    # ---------------- Provider Detection -----------------
    def _detect_provider(self) -> None:
        candidates: list[_ProviderCaps] = []
        # Full enhanced HopGraph
        for mod_name, attr, weight in [
            ("graph.hopgraph", "GLOBAL_HOPGRAPH", 100),
            ("core.graph.hopgraph_lite", "get_graph", 60),
            ("core.hunt.hopgraph_light", "get_hopgraph", 55),
            ("artifact.hopgraph_lite", "HopGraphLite", 40),
        ]:
            try:
                mod = importlib.import_module(mod_name)
                obj = getattr(mod, attr)
                # call factory functions
                if callable(obj) and attr.startswith("get_"):
                    obj = obj()
                # instantiate class if raw type provided
                if hasattr(obj, "__class__"):
                    candidates.append(_ProviderCaps(mod_name, obj, weight))
            except Exception:
                continue
        if not candidates:
            logger.warning("UnifiedGraph: no graph provider available")
            return
        # Pick highest weight
        candidates.sort(key=lambda c: c.weight, reverse=True)
        self._provider = candidates[0]
        logger.info("UnifiedGraph bound to provider %s (weight=%s)", self._provider.name, self._provider.weight)

    # ---------------- Core Facade Methods -----------------
    def _p(self) -> Any:
        if not self._provider:
            raise RuntimeError("No graph provider available")
        return self._provider.obj

    def add_edge(self, src: str, dst: str, etype: str, **kwargs) -> None:
        try:
            p = self._p()
            if hasattr(p, "add_edge"):
                return p.add_edge(src, dst, etype, **kwargs)
            # Fallback naming variants
            if hasattr(p, "add"):
                return p.add(src, dst, etype, **kwargs)
        except Exception as e:  # pragma: no cover
            logger.debug("UnifiedGraph.add_edge failed: %s", e)

    def explain_chain(self, node: str, max_depth: int = 4, top_k: int = 3, beam_width: int = 5) -> dict:
        try:
            p = self._p()
            if hasattr(p, "explain_chain"):
                return p.explain_chain(node, max_depth=max_depth, top_k=top_k, beam_width=beam_width)
            # Minimal synthetic fallback
            return {"node": node, "paths": []}
        except Exception as e:  # pragma: no cover
            return {"error": str(e), "node": node}

    def k_hops(self, node: str, k: int = 2) -> dict:
        try:
            p = self._p()
            if hasattr(p, "k_hops"):
                return p.k_hops(node, k=k)  # type: ignore[arg-type]
            return {"nodes": [], "edges": []}
        except Exception as e:  # pragma: no cover
            return {"error": str(e), "nodes": [], "edges": []}

    def stats(self) -> dict:
        p = self._provider.obj if self._provider else None
        if not p:
            return {"provider": None, "edges": 0}
        out = {"provider": self._provider.name}
        try:
            if hasattr(p, "edge_count"):
                out["edges"] = p.edge_count  # attr
            elif hasattr(p, "stats"):
                s = p.stats()  # type: ignore
                if isinstance(s, dict):
                    out.update({k: v for k, v in s.items() if k in {"edges", "nodes", "edge_count"}})
        except Exception:
            pass
        return out


# Global singleton
UG = UnifiedGraph()

__all__ = ["UG", "UnifiedGraph"]
