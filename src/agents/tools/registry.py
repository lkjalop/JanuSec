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
    """Traverse the Global IdentityHopGraph via BFS from a start node.

    Params:
        start_node (str): entity ID (plain username or 'user:name' form)
        max_hops (int): depth cap, default 3, max 5
        edge_types (list[str]): optional filter on edge type strings
    """
    try:
        from src.core.graph.global_identity_graph import get_global_identity_graph
        g = get_global_identity_graph()
    except Exception as exc:
        return {"summary": f"IdentityGraph unavailable: {exc}", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}

    start = str(params.get("start_node", ""))
    max_hops = min(int(params.get("max_hops", 3)), 5)
    edge_type_filter: set = set(params.get("edge_types") or [])

    try:
        # BFS traversal using the adjacency dict directly
        visited: set = set()
        frontier = [(start, 0, [start])]
        if f'user:{start}' in (g._adj or {}):
            frontier.append((f'user:{start}', 0, [f'user:{start}']))
        paths: list = []

        while frontier:
            node, depth, path = frontier.pop(0)
            if depth >= max_hops or node in visited:
                continue
            visited.add(node)
            for (dst, etype, last_ts, weight) in (g._adj.get(node) or []):
                if edge_type_filter and etype not in edge_type_filter:
                    continue
                step = f'--[{etype}]-->'
                new_path = path + [step, dst]
                is_hvt = dst in (g._high_value or set())
                paths.append({
                    'path': ' '.join(new_path),
                    'depth': depth + 1,
                    'last_ts': str(last_ts),
                    'weight': float(weight),
                    'reaches_hvt': is_hvt,
                })
                frontier.append((dst, depth + 1, new_path))

        hvt_paths = [p for p in paths if p['reaches_hvt']]
        return {
            "summary": (
                f"{len(paths)} lateral paths from '{start}' (depth≤{max_hops}); "
                f"{len(hvt_paths)} reach high-value targets"
            ),
            "evidence": {
                "paths": paths[:15],
                "hvt_paths": hvt_paths[:5],
                "total_paths": len(paths),
                "start_node": start,
            },
            "data_volume_bytes": len(str(paths)),
            "source_count": len({p['path'].split(' ')[-1] for p in paths}) if paths else 0,
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
    """Query TemporalRAG across four retrieval silos in parallel.

    Params:
        techniques (list[str]): MITRE technique IDs to search
        stage (str): kill-chain stage label
        verdict (str): expected verdict for similarity search
        principals (list[str]): user principals for identity-context retrieval
        entities (list[str]): entity IDs for ChronoGraph anomaly retrieval
        persona (str): persona key for prior-decision lookup (default 'soc_analyst')
        tenant_id (str): tenant scope (default 'default')
    """
    try:
        from src.core.ingest.assessment_worker import _get_incident_index, _get_trace_store
        from src.analysis.temporal_rag_dispatch import TemporalRAGProvider
    except Exception as exc:
        return {"summary": f"TemporalRAG unavailable: {exc}", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}

    tenant_id = str(params.get("tenant_id") or "default")
    techniques = list(params.get("techniques") or [])
    stage = str(params.get("stage") or "unknown")
    verdict = str(params.get("verdict") or "REQUIRES_INVESTIGATION")
    principals = list(params.get("principals") or [])
    # 'hosts' are endpoint hostnames; 'entities' is a generic fallback for both
    hosts = list(params.get("hosts") or params.get("entities") or [])
    persona = str(params.get("persona") or "soc_analyst")

    try:
        rag = TemporalRAGProvider(
            incident_store=_get_incident_index(),
            decision_store=_get_trace_store(),
            tenant_id=tenant_id,
        )

        narrative = {
            'mitre_techniques': techniques,
            'kill_chain_stage': stage,
            'verdict': verdict,
        }

        # Run all four retrieval silos in parallel using a thread pool.
        # Each is a synchronous SQLite read — safe to parallelise.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            f_similar   = pool.submit(rag.retrieve_similar_incidents, narrative, 5)
            f_decisions = pool.submit(rag.retrieve_prior_decisions, techniques, persona)
            f_identity  = pool.submit(rag.retrieve_identity_context, principals)
            # retrieve_chrono_anomalies(principals, hosts) — both args required
            f_chrono    = pool.submit(rag.retrieve_chrono_anomalies, principals, hosts)
            similar   = f_similar.result(timeout=5)
            decisions = f_decisions.result(timeout=5)
            identity  = f_identity.result(timeout=5)
            chrono    = f_chrono.result(timeout=5)

        total_hits = len(similar) + len(decisions)
        return {
            "summary": (
                f"TemporalRAG: {len(similar)} similar incidents, "
                f"{len(decisions)} prior decisions, "
                f"{len(identity)} identity paths, "
                f"{len(chrono)} chrono anomalies"
            ),
            "evidence": {
                "similar_incidents": similar[:5],
                "prior_decisions": decisions[:5],
                "identity_context": identity[:5],
                "chrono_anomalies": chrono[:5],
                "retrieval_count": total_hits,
            },
            "data_volume_bytes": len(str(similar) + str(decisions)),
            "source_count": total_hits,
        }
    except Exception as exc:
        LOGGER.warning("temporal_rag failed: %s", exc)
        return {"summary": f"temporal_rag failed: {exc}", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}


@register_tool("dread_score")
def tool_dread_score(params: Dict[str, Any]) -> Dict[str, Any]:
    """Score a finding cluster using DREAD methodology.

    Params:
        cluster (dict): cluster dict (preferred) or cluster_summary (str)
        rows (list): evidence rows for the cluster
        cluster_summary (str): fallback text description
    """
    cluster = params.get("cluster") or {}
    rows = params.get("rows") or []
    cluster_summary = params.get("cluster_summary", "")
    try:
        from src.core.tier1_prefill.threat_models import _compute_confidence_meter
        confidence = _compute_confidence_meter(cluster, rows)
        composite = confidence.get("total", 0)
        tier = "LOW" if composite < 25 else "MEDIUM" if composite < 55 else "HIGH" if composite < 80 else "CRITICAL"
        return {
            "summary": f"DREAD score: {composite:.0f}/100 ({tier})",
            "evidence": {**confidence, "tier": tier},
            "data_volume_bytes": len(str(confidence)),
            "source_count": cluster.get("source_count", len(rows)),
        }
    except Exception as exc:
        LOGGER.warning("dread_score computation failed: %s", exc)
        return {
            "summary": f"DREAD score requested for: {cluster_summary[:80]}",
            "evidence": {"cluster_summary": cluster_summary, "error": str(exc)},
            "data_volume_bytes": len(cluster_summary),
            "source_count": 1,
        }


@register_tool("fetch_source")
def tool_fetch_source(params: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch additional log source into the assessment.

    Params:
        source_type (str): zeek, suricata, sysmon, etw, crowdstrike, m365, etc.
        filters (dict): optional filters (time range, user, host)
        assessment_id (str): target assessment to attach logs to
        file_path (str): local path to upload directly
    """
    source_type = params.get("source_type", "")
    assessment_id = params.get("assessment_id", "")
    file_path = params.get("file_path", "")
    ingest_url = (
        f"/api/v1/assessments/{assessment_id}/upload"
        if assessment_id else "/api/v1/assessments/upload"
    )
    return {
        "summary": f"Source fetch guidance: {source_type} → assessment {assessment_id or '(new)'}",
        "evidence": {
            "source_type": source_type,
            "assessment_id": assessment_id,
            "file_path": file_path,
            "instructions": (
                f"To ingest {source_type!r} logs: POST multipart/form-data to "
                f"{ingest_url} with file field 'files' and header X-Tenant-ID. "
                "Supported formats: .csv, .json, .ndjson, .jsonl, .xlsx. "
                "Progress available at /api/v1/assessments/{id}/progress/poll"
            ),
        },
        "data_volume_bytes": 0,
        "source_count": 0,
    }


@register_tool("enrich_ioc")
def tool_enrich_ioc(params: Dict[str, Any]) -> Dict[str, Any]:
    """Cross-check an IOC across live threat intelligence feeds.

    Params:
        ioc_value (str): IP, domain, file hash, or URL to enrich
        ioc_type  (str): 'ip' | 'domain' | 'hash' | 'url'  (default: 'ip')

    Requires ABUSEIPDB_API_KEY env var for IP checks; works without key using
    AbuseCH and GreyNoise community feeds.
    """
    ioc_value = str(params.get("ioc_value") or "").strip()
    ioc_type = str(params.get("ioc_type") or "ip").strip().lower()
    if not ioc_value:
        return {"summary": "No IOC value provided", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}
    try:
        from src.security.ioc_cross_reference import IOCCrossReference
        xref = IOCCrossReference()
        record = xref.validate(ioc_value, ioc_type)
        status = "CONFIRMED MALICIOUS" if record.confirmed else "clean/unknown"
        return {
            "summary": f"{status}: {ioc_value} ({ioc_type}) — {record.feed_count} feeds, avg_confidence={record.avg_confidence:.2f}",
            "evidence": {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "confirmed": record.confirmed,
                "feed_count": record.feed_count,
                "avg_confidence": round(record.avg_confidence, 3),
                "categories": list(record.categories),
                "hits": [
                    {
                        "feed": h.feed_name,
                        "confidence": round(h.confidence, 3),
                        "categories": h.categories,
                    }
                    for h in record.hits
                ],
            },
            "data_volume_bytes": len(ioc_value),
            "source_count": record.feed_count,
        }
    except Exception as exc:
        return {
            "summary": f"IOC enrichment error: {exc}",
            "evidence": {"ioc_value": ioc_value, "ioc_type": ioc_type},
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

    Queues the action for operator review — does not execute anything.

    Params:
        action_type (str): block_ip, disable_user, notify_soc, isolate_host, etc.
        description (str): human-readable explanation of why this action is needed
        target_params (dict): action-specific parameters (ip, user, host, etc.)
        tier (int): 1=auto-execute, 2=one-click, 3=CAB, 4=human-only (default 2)
    """
    import uuid as _uuid
    import time as _time

    action_id = _uuid.uuid4().hex[:8]
    action_type = params.get("action_type", "unknown")
    tier = int(params.get("tier", 2))
    entry = {
        "id": action_id,
        "action_type": action_type,
        "description": params.get("description", ""),
        "target_params": params.get("target_params", {}),
        "tier": tier,
        "proposed_at": _time.time(),
        "status": "pending_approval",
    }
    # Best-effort: append to in-process action queue if available
    try:
        from src.api.gaps_endpoints import _ACTION_QUEUE  # type: ignore
        _ACTION_QUEUE.append(entry)
    except Exception:
        pass
    return {
        "summary": f"Action queued [{action_id}]: {action_type} (tier {tier}) — pending approval",
        "evidence": entry,
        "data_volume_bytes": len(str(entry)),
        "source_count": 1,
    }


@register_tool("chrono_query")
def tool_chrono_query(params: Dict[str, Any]) -> Dict[str, Any]:
    """Query ChronoGraph for time-series z-score anomalies.

    Params:
        entity_type (str): 'user', 'host', 'ip' — default 'user'
        entity_id (str): entity identifier
        metrics (list[str]): metric names to check — defaults to common security metrics
        window_hours (int): lookback window in hours — default 72
    """
    try:
        from src.core.chrono.sketch_store import CHRONO
    except Exception as exc:
        return {"summary": f"ChronoGraph unavailable: {exc}", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}

    entity_type = str(params.get("entity_type") or "user")
    entity_id   = str(params.get("entity_id") or "")
    window_hours = min(int(params.get("window_hours") or 72), 720)
    metrics = list(params.get("metrics") or [
        "endpoint:lolbin_count",
        "endpoint:wmi_exec_count",
        "iam:rc4_count",
        "cloud:foreign_asn_count",
        "bytes_out",
        "recon_events",
    ])

    try:
        # ChronoSketchStore.z_score() takes window_seconds and returns key 'z'
        anomalies: Dict[str, Any] = {}
        for metric in metrics[:10]:
            z_result = CHRONO.z_score(entity_type, entity_id, metric,
                                      window_seconds=window_hours * 3600)
            if z_result and float(z_result.get('z') or 0) >= 1.5:
                anomalies[metric] = {
                    'z_score': round(float(z_result.get('z') or 0), 2),
                    'mean': round(float(z_result.get('mean') or 0), 3),
                    'current': round(float(z_result.get('current') or 0), 3),
                }

        top_entities: list = []
        if metrics:
            try:
                top_entities = CHRONO.top_entities(
                    entity_type, metrics[0],
                    window_seconds=window_hours * 3600, n=5,
                )
            except Exception:
                pass

        return {
            "summary": (
                f"ChronoGraph: {len(anomalies)}/{len(metrics)} metrics anomalous "
                f"for {entity_type}:{entity_id} (window={window_hours}h)"
            ),
            "evidence": {
                "entity": f"{entity_type}:{entity_id}",
                "anomalies": anomalies,
                "top_entities": top_entities[:5],
                "window_hours": window_hours,
            },
            "data_volume_bytes": len(str(anomalies)),
            "source_count": len(anomalies),
        }
    except Exception as exc:
        LOGGER.warning("chrono_query failed: %s", exc)
        return {"summary": f"chrono_query failed: {exc}", "evidence": {}, "data_volume_bytes": 0, "source_count": 0}


def get_tool(name: str) -> ToolFn | None:
    """Look up a tool by name."""
    return TOOL_REGISTRY.get(name)


def list_tools() -> list[str]:
    """Return sorted list of registered tool names."""
    return sorted(TOOL_REGISTRY.keys())
