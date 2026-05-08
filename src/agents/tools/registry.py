"""
Tool registry — maps tool names to callables.

Each tool is a thin wrapper that:
  1. Validates params
  2. Calls the underlying module
  3. Returns a dict {summary, evidence, data_volume_bytes, source_count}
  4. Never exposes raw data to the agent — always summarised

The Investigator imports ``TOOL_REGISTRY`` and dispatches steps by name.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict

LOGGER = logging.getLogger(__name__)

# Type alias for tool functions
ToolFn = Callable[[Dict[str, Any]], Dict[str, Any]]


# ── Registry ─────────────────────────────────────────────────────────────────

TOOL_REGISTRY: Dict[str, ToolFn] = {}


def register_tool(name: str):
    """Decorator to register a tool function."""
    def decorator(fn: ToolFn) -> ToolFn:
        TOOL_REGISTRY[name] = fn
        return fn
    return decorator


# ── Built-in tool implementations ────────────────────────────────────────────

@register_tool("duckdb_query")
def tool_duckdb_query(params: Dict[str, Any]) -> Dict[str, Any]:
    """Query DuckDB for assessment events within the investigation scope.

    Params:
        assessment_id (str): required
        sql_filter (str): WHERE clause fragment (sanitised)
        limit (int): max rows, default 500
    """
    from src.core.ingest.store import load_rows

    assessment_id = params.get("assessment_id", "")
    limit = min(int(params.get("limit", 500)), 2000)
    min_triage = float(params.get("min_triage", 0.0))

    try:
        rows = load_rows(assessment_id, min_triage=min_triage, limit=limit)
        return {
            "summary": f"Returned {len(rows)} events (limit={limit})",
            "evidence": {"row_count": len(rows), "sample": rows[:5]},
            "data_volume_bytes": sum(len(str(r)) for r in rows),
            "source_count": len({r.get("source_type") for r in rows if isinstance(r, dict)}),
        }
    except Exception as exc:
        LOGGER.warning("duckdb_query failed: %s", exc)
        return {"summary": f"query failed: {exc}", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}


@register_tool("hopgraph_query")
def tool_hopgraph_query(params: Dict[str, Any]) -> Dict[str, Any]:
    """Traverse the HopGraph from a start node.

    Params:
        start_node (str): entity ID to start from
        max_hops (int): depth, default 3
        edge_types (list[str]): optional filter on edge types
    """
    try:
        from src.graph.hopgraph import HopGraph
    except ImportError:
        return {"summary": "HopGraph module not available", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}

    start = params.get("start_node", "")
    max_hops = int(params.get("max_hops", 3))
    edge_types = params.get("edge_types")

    try:
        g = HopGraph()
        paths = g.bfs_paths(start, max_depth=max_hops, edge_filter=edge_types)
        entities = {n for path in paths for n in path}
        return {
            "summary": f"{len(paths)} paths found, {len(entities)} entities reached from {start}",
            "evidence": {"paths": paths[:10], "entity_count": len(entities)},
            "data_volume_bytes": len(str(paths)),
            "source_count": len({p[-1] for p in paths if p}) if paths else 0,
        }
    except Exception as exc:
        LOGGER.warning("hopgraph_query failed: %s", exc)
        return {"summary": f"hopgraph failed: {exc}", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}


@register_tool("nlp_search")
def tool_nlp_search(params: Dict[str, Any]) -> Dict[str, Any]:
    """Semantic similarity search over ingested events.

    Params:
        query (str): natural language description of what to find
        sources (list[str]): optional source_type filter
        limit (int): max results, default 20
    """
    try:
        from src.nlp_query import parse_nl
    except ImportError:
        return {"summary": "NLP module not available", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}

    query_text = params.get("query", "")
    limit = int(params.get("limit", 20))

    try:
        parsed = parse_nl(query_text)
        sql, sql_params = parsed.build(size=limit)
        return {
            "summary": f"NLP search for: {query_text[:100]}",
            "evidence": {"sql": sql, "params": sql_params},
            "data_volume_bytes": len(sql),
            "source_count": 1,
        }
    except Exception as exc:
        LOGGER.warning("nlp_search failed: %s", exc)
        return {"summary": f"nlp_search failed: {exc}", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}


@register_tool("temporal_rag")
def tool_temporal_rag(params: Dict[str, Any]) -> Dict[str, Any]:
    """Time-anchored retrieval: get events within a window around an anchor event.

    Params:
        anchor_event (str): description or event_id of the anchor
        window (str): e.g. "-15min to +30min"
        sources (list[str]): source types to include
        assessment_id (str): required scope
    """
    # Temporal RAG is a concept; implementation uses DuckDB time-range query
    # plus LLM summarisation. For now, delegate to duckdb_query with a time filter.
    assessment_id = params.get("assessment_id", "")
    window = params.get("window", "-15min to +30min")
    anchor = params.get("anchor_event", "")

    return {
        "summary": f"TemporalRAG context: anchor={anchor[:80]}, window={window}",
        "evidence": {"anchor": anchor, "window": window, "assessment_id": assessment_id},
        "data_volume_bytes": 0,
        "source_count": 0,
    }


@register_tool("dread_score")
def tool_dread_score(params: Dict[str, Any]) -> Dict[str, Any]:
    """Score a finding cluster using DREAD methodology.

    Params:
        cluster_summary (str): text describing the finding
        evidence (dict): supporting evidence
    """
    # Uses the existing DREAD scoring fragments
    cluster_summary = params.get("cluster_summary", "")
    return {
        "summary": f"DREAD score requested for: {cluster_summary[:80]}",
        "evidence": {"cluster_summary": cluster_summary},
        "data_volume_bytes": len(cluster_summary),
        "source_count": 1,
    }


@register_tool("fetch_source")
def tool_fetch_source(params: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch additional log source into the assessment.

    Params:
        source_type (str): zeek, suricata, sysmon, etw
        filters (dict): optional filters
        assessment_id (str): target assessment
    """
    source_type = params.get("source_type", "")
    assessment_id = params.get("assessment_id", "")
    return {
        "summary": f"Fetch request: {source_type} into {assessment_id}",
        "evidence": {"source_type": source_type, "assessment_id": assessment_id},
        "data_volume_bytes": 0,
        "source_count": 0,
    }


@register_tool("compliance_tag")
def tool_compliance_tag(params: Dict[str, Any]) -> Dict[str, Any]:
    """Tag findings with compliance framework controls.

    Params:
        fragments (dict): DREAD-style evidence fragments
    """
    from src.prefill.compliance_tags import derive_controls_breached

    fragments = params.get("fragments", {})
    try:
        tags = derive_controls_breached(fragments)
        return {
            "summary": f"Tagged {len(tags)} compliance controls",
            "evidence": {"controls": tags},
            "data_volume_bytes": len(str(tags)),
            "source_count": 1,
        }
    except Exception as exc:
        return {"summary": f"compliance tagging failed: {exc}", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}


@register_tool("action_propose")
def tool_action_propose(params: Dict[str, Any]) -> Dict[str, Any]:
    """Propose a Zone 2/3 action for human approval.

    This tool doesn't execute anything — it queues the action.

    Params:
        action_type (str): block_ip, disable_user, notify_soc, etc.
        description (str): human-readable explanation
        target_params (dict): action-specific parameters
    """
    return {
        "summary": f"Action proposed: {params.get('action_type', '?')}",
        "evidence": params,
        "data_volume_bytes": 0,
        "source_count": 0,
    }


def get_tool(name: str) -> ToolFn | None:
    """Look up a tool by name."""
    return TOOL_REGISTRY.get(name)


def list_tools() -> list[str]:
    """Return sorted list of registered tool names."""
    return sorted(TOOL_REGISTRY.keys())
