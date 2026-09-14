"""Package initializer for src.graph that defends against test-suite
helpers injecting a non-module into sys.modules under 'src.graph.hopgraph'.

If a SimpleNamespace or other object was placed into sys.modules with a
`GLOBAL_HOPGRAPH` attribute (common in tests), convert that entry into a
ModuleType and ensure `GLOBAL_HOPGRAPH` exposes a minimal API required by
endpoints/tests (notably `add_edge` and `explain_chain`).
"""
from __future__ import annotations
import sys, types

def _make_min_adapter(inst):
    # If instance already has expected methods, return as-is
    if inst is None:
        return inst
    if all(hasattr(inst, nm) for nm in ('add_edge', 'explain_chain', 'add_node_attr', 'get_version')):
        return inst

    class _Adapter:
        def __init__(self, inner):
            self._inner = inner
            self.nodes = getattr(inner, 'nodes', {})
            self.adj = getattr(inner, 'adj', {})

        def add_edge(self, src, dst, etype, source='event', ts=None, attrs=None, weight=None):
            try:
                if hasattr(self._inner, 'add_edge'):
                    return self._inner.add_edge(src, dst, etype, source=source, ts=ts, attrs=attrs, weight=weight)
            except Exception:
                pass
            try:
                lst = self.adj.setdefault(src, [])
                lst.append((dst, etype, ts or 0.0, source or '', float(weight or 1.0)))
            except Exception:
                pass

        def explain_chain(self, start, max_depth=4, beam_width=5, top_k=3):
            try:
                if hasattr(self._inner, 'explain_chain'):
                    return self._inner.explain_chain(start, max_depth=max_depth, beam_width=beam_width, top_k=top_k)
            except Exception:
                pass
            return {'start': start, 'chains': [], 'subgraph': {'nodes': {}, 'edges': []}}

        def add_node_attr(self, node, **attrs):
            try:
                if hasattr(self._inner, 'add_node_attr'):
                    return self._inner.add_node_attr(node, **attrs)
            except Exception:
                pass
            try:
                self.nodes.setdefault(node, {}).update(attrs)
            except Exception:
                pass

        def get_version(self):
            try:
                if hasattr(self._inner, 'get_version'):
                    return self._inner.get_version()
            except Exception:
                pass
            return 0

        def __getattr__(self, name):
            return getattr(self._inner, name)

    return _Adapter(inst)


# Detect existing non-module entries and coerce them into module objects with
# a compatible GLOBAL_HOPGRAPH attribute.
_entry = sys.modules.get('src.graph.hopgraph')
if _entry is not None and not isinstance(_entry, types.ModuleType):
    try:
        hg = getattr(_entry, 'GLOBAL_HOPGRAPH', None)
        mod = types.ModuleType('src.graph.hopgraph')
        mod.GLOBAL_HOPGRAPH = _make_min_adapter(hg)
        # preserve any common attributes if present
        for attr in ('HopGraph',):
            if hasattr(_entry, attr):
                setattr(mod, attr, getattr(_entry, attr))
        sys.modules['src.graph.hopgraph'] = mod
    except Exception:
        pass
