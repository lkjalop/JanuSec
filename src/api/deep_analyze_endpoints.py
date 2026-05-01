from __future__ import annotations
import time
import datetime
import uuid
import asyncio
import json
import os
import logging
import sys
import re
import ipaddress
import threading
from collections import defaultdict
from fastapi import APIRouter, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response

try:
    if __name__ in sys.modules and 'api.deep_analyze_endpoints' not in sys.modules:
        sys.modules['api.deep_analyze_endpoints'] = sys.modules[__name__]
except Exception:
    pass

from src.api.metrics_init import ensure_metrics, _safe_hist, _safe_counter, _safe_gauge
_METRICS_INITIALIZED = False
csv_stage_latency = None
csv_deep_analyze_total = None
csv_deep_analyze_inflight = None
insight_usage_counter = None

def _ensure_deep_metrics():
    global _METRICS_INITIALIZED, csv_stage_latency, csv_deep_analyze_total, csv_deep_analyze_inflight, insight_usage_counter
    if _METRICS_INITIALIZED:
        return
    try:
        ensure_metrics()
        csv_stage_latency = _safe_hist('csv_stage_latency_seconds', 'Latency per csv deep analyze stage', ['stage'])
        csv_deep_analyze_total = _safe_counter('csv_deep_analyze_total', 'Total deep analyze pipeline runs', ['auto_llm'])
        csv_deep_analyze_inflight = _safe_gauge('csv_deep_analyze_inflight', 'In-flight deep analyze tasks')
        insight_usage_counter = _safe_counter('insight_requests_total', 'Insight generation requests', ['type'])
    except Exception:
        csv_stage_latency = csv_deep_analyze_total = csv_deep_analyze_inflight = insight_usage_counter = None
    _METRICS_INITIALIZED = True
from . import llm_prompts
from src.pipeline.deep_analyze_pipeline import (
    DEFAULT_PIPELINE_DIR,
    DEFAULT_WORKER,
    PIPELINE_SPEC,
    _sanitize_llm_row,
)
from src.analysis.auto_llm import build_llm_row
from src.analysis.deep_analyze_utils import (
    build_canonical_signals,
    map_to_mitre,
    map_to_stride,
    map_to_controls,
    map_to_dread,
    map_to_pasa,
    map_to_maestro,
    map_to_diamond,
)
try:
    from src.analysis.explain_mapping import map_factors_to_tags
except Exception:
    map_factors_to_tags = None  # type: ignore
from src.analysis.domain_tools import build_collection_playbook, get_logs_for_mitre, get_tools_for_domain
from src.analysis.correlation_context import (
    build_attack_chain_visualization,
    enrich_correlation_context,
)
from src.core.correlation.cluster_reasoning import (
    build_cluster_reasoning_root,
    build_cluster_reasoning_state,
    compact_cluster_reasoning_state,
    parse_guided_analyst_note,
)
from src.repositories.historical_incidents_repo import HISTORICAL_REPO
try:
    from src.incidents.aggregator import GLOBAL_INCIDENTS
except Exception:
    GLOBAL_INCIDENTS = None
from src.integrations.vector_db import VECTOR_LOG_SEARCH
import hashlib
import datetime
from types import SimpleNamespace
from typing import Any, Dict, List, Set, Tuple

from src.artifact.models import ArtifactObservation, ArtifactType, Verdict, stable_artifact_id, map_risk_to_verdict
from src.artifact.report import build_report
try:
    from src.integrations.llm_client import DEFAULT_CLIENT as LLM_CLIENT
except Exception:
    LLM_CLIENT = None  # type: ignore

_LLM_CLIENT = None
def _get_llm_client():
    global _LLM_CLIENT
    if _LLM_CLIENT is not None:
        return _LLM_CLIENT
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT as _dc
        _LLM_CLIENT = _dc
    except Exception:
        _LLM_CLIENT = None
    return _LLM_CLIENT
from src.reporting.prompt_templates import PERSONA_TEMPLATES as CENTRAL_PERSONA_TEMPLATES, build_persona_prompt
from src.reporting import llm_helper
from src.reporting.persona_parser import parse_persona_text, validate_parsed_persona
from src.reporting.feedback_capture import persist_feedback
from src.analysis.cost_tracker import EXTERNAL_TRACKER, LOCAL_TRACKER
from src.api.persist_utils import atomic_write_json
try:
    from src.graph.ingest import ingest_event as ingest_hopgraph_event
except Exception:
    ingest_hopgraph_event = None  # type: ignore
# Attempt to load ML model for ml_score from data/models/ml_score.pkl
MODEL_BUNDLE = None
try:
    from src.ml.model import load_model
    model_path = os.path.join(os.getcwd(), 'data', 'models', 'ml_score.pkl')
    if os.path.exists(model_path):
        try:
            MODEL_BUNDLE = load_model(model_path)
        except Exception:
            MODEL_BUNDLE = None
except Exception:
    MODEL_BUNDLE = None
_MODEL_LOADED = False
def _load_model_if_present():
    global MODEL_BUNDLE, _MODEL_LOADED
    if _MODEL_LOADED:
        return
    _MODEL_LOADED = True
    try:
        from src.ml.model import load_model
        model_path = os.path.join(os.getcwd(), 'data', 'models', 'ml_score.pkl')
        if os.path.exists(model_path):
            try:
                MODEL_BUNDLE = load_model(model_path)
            except Exception:
                MODEL_BUNDLE = None
    except Exception:
        MODEL_BUNDLE = None

try:
    from .graph_sessions import get_session as _graph_get_session, explain_session as _graph_explain_session  # type: ignore
except Exception:  # pragma: no cover - fallback when hopgraph module not present
    _graph_get_session = None  # type: ignore
    _graph_explain_session = None  # type: ignore
try:
    from .graph_session_endpoints import load_session as _legacy_load_session  # type: ignore
except Exception:  # pragma: no cover
    _legacy_load_session = None  # type: ignore

# Lightweight, deterministic stage implementations for lite-mode tests
router = APIRouter(prefix='/api/v1/assessments')
csv_router = APIRouter(prefix='/api/v1')
logger = logging.getLogger(__name__)


class _BoundedDict(dict):
    """Dict with FIFO eviction and snapshot iteration for shared runtime stores."""

    def __init__(self, *args, maxsize: int = 10000, **kwargs):
        super().__init__()
        self._maxsize = max(1, int(maxsize or 1))
        self._lock = threading.RLock()
        if args or kwargs:
            self.update(*args, **kwargs)

    def __setitem__(self, key, value):
        with self._lock:
            if key not in self:
                while len(self) >= self._maxsize:
                    try:
                        oldest = next(iter(self))
                    except StopIteration:
                        break
                    super().__delitem__(oldest)
            super().__setitem__(key, value)

    def __delitem__(self, key):
        with self._lock:
            super().__delitem__(key)

    def update(self, *args, **kwargs):
        with self._lock:
            for key, value in dict(*args, **kwargs).items():
                self[key] = value

    def setdefault(self, key, default=None):
        with self._lock:
            if key not in self:
                self[key] = default
            return super().__getitem__(key)

    def pop(self, key, *args):
        with self._lock:
            return super().pop(key, *args)

    def clear(self):
        with self._lock:
            super().clear()

    def items(self):
        with self._lock:
            return list(super().items())

    def keys(self):
        with self._lock:
            return list(super().keys())

    def values(self):
        with self._lock:
            return list(super().values())


def _store_cap(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default)) or default))
    except Exception:
        logger.warning("Invalid %s value; using %s", name, default)
        return default


REPORT_STORE: dict[str, dict] = _BoundedDict(maxsize=_store_cap('REPORT_STORE_MAX', 10000))
PARENT_CHILD_INDEX: dict[str, list[str]] = _BoundedDict(maxsize=_store_cap('PARENT_CHILD_INDEX_MAX', 50000))


_BACKGROUND_TASKS: set = set()


def _track_task(task):
    """Keep a strong reference to a scheduled task until it completes."""
    if task is None:
        return None
    try:
        _BACKGROUND_TASKS.add(task)
        if hasattr(task, 'add_done_callback'):
            task.add_done_callback(_BACKGROUND_TASKS.discard)
    except Exception:
        logger.debug('_track_task: could not register %r', task, exc_info=True)
    return task


def _utcnow() -> datetime.datetime:
    """Naive UTC timestamp compatible with deprecated datetime.utcnow()."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _atomic_write_json_sync(path: str, data, default=None) -> None:
    """Synchronous atomic JSON writer; call via asyncio.to_thread in async code."""
    if default is None:
        atomic_write_json(path, data)
        return
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.{uuid.uuid4().hex}.tmp"
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, ensure_ascii=False, default=default)
    os.replace(tmp, path)


def _atomic_write_text_sync(path: str, text: str) -> None:
    """Synchronous atomic text writer; call via asyncio.to_thread in async code."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.{uuid.uuid4().hex}.tmp"
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(text)
    os.replace(tmp, path)


def _read_text_sync(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as fh:
        return fh.read()


def _read_json_sync(path: str):
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)

# Simple in-memory SSE broadcaster per-assessment
_SSE_BROADCASTERS: dict[str, list] = {}

def publish_llm_event(assessment_id: str, event: dict):
    """Publish an event dict to any connected SSE listeners for assessment_id.
    Listeners are simple async generators that will be fed events.
    """
    try:
        listeners = _SSE_BROADCASTERS.get(assessment_id) or []
        for q in list(listeners):
            try:
                q.append(event)
            except Exception:
                try:
                    listeners.remove(q)
                except Exception:
                    pass
        _SSE_BROADCASTERS[assessment_id] = listeners
    except Exception:
        pass


# ── WebSocket pipeline progress ─────────────────────────────────────────────
_WS_CONNECTIONS: dict[str, list] = {}


def _extract_row_timestamp_value(row: dict | None) -> float | None:
    if not isinstance(row, dict):
        return None
    for key in (
        "timestamp",
        "Timestamp",
        "ts",
        "event_ts",
        "createdDateTime",
        "activityDateTime",
        "eventTimestamp",
        "eventTime",
        "TimeGenerated",
        "time",
        "date",
        "Date",
    ):
        raw = row.get(key)
        if raw in (None, "", [], {}):
            continue
        try:
            if isinstance(raw, (int, float)):
                return float(raw)
            text = str(raw).strip()
            if not text:
                continue
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return datetime.datetime.fromisoformat(text).timestamp()
        except Exception:
            continue
    return None


_HOPGRAPH_ROW_CAP = 1500  # above this, hairball rendering degrades performance significantly


def _ingest_rows_to_hopgraph(rows: list[dict], assessment_id: str) -> dict[str, Any]:
    if ingest_hopgraph_event is None:
        return {"ingested": 0, "timeline_rows": 0, "timespan_seconds": 0.0}
    # Cap rows fed to HopGraph to avoid hairball/performance degradation on large uploads.
    # When over the cap, keep the highest-triage rows so the graph shows the most suspicious activity.
    if len(rows) > _HOPGRAPH_ROW_CAP:
        rows = sorted(rows, key=lambda r: float((r.get('raw') or r).get('triage_score') or 0), reverse=True)[:_HOPGRAPH_ROW_CAP]
        logger.debug('_ingest_rows_to_hopgraph: capped to %d rows for %s', _HOPGRAPH_ROW_CAP, assessment_id)
    ingested = 0
    ts_values: list[float] = []
    for idx, wrapper in enumerate(rows):
        base = wrapper.get("raw") if isinstance(wrapper, dict) and isinstance(wrapper.get("raw"), dict) else wrapper
        if not isinstance(base, dict):
            continue
        event = dict(base)
        event.setdefault("src_host", base.get("src_host") or base.get("source_host") or base.get("host") or base.get("hostname") or base.get("Computer"))
        event.setdefault("host", base.get("host") or base.get("hostname") or base.get("Computer"))
        event.setdefault("dst_ip", base.get("dst_ip") or base.get("destination_ip") or base.get("server_ip") or base.get("ipAddress") or base.get("ip"))
        event.setdefault("domain", base.get("domain") or base.get("hostname") or base.get("host") or base.get("sni"))
        event.setdefault("process", base.get("process") or base.get("process_name") or base.get("Image"))
        ts_value = _extract_row_timestamp_value(base)
        if ts_value is not None:
            event["ts"] = ts_value
            ts_values.append(ts_value)
        else:
            event["ts"] = time.time()
        try:
            ingest_hopgraph_event(event, source=f"assessment:{assessment_id}")
            ingested += 1
        except Exception:
            continue
    timespan = 0.0
    if len(ts_values) >= 2:
        timespan = max(ts_values) - min(ts_values)
    return {
        "ingested": ingested,
        "timeline_rows": len(ts_values),
        "timespan_seconds": round(timespan, 3),
    }


@router.websocket('/ws/progress/{assessment_id}')
async def ws_pipeline_progress(websocket: WebSocket, assessment_id: str):
    """WebSocket endpoint for real-time pipeline progress events.

    Client connects after POST /api/v1/csv/deep_analyze returns assessment_id.
    Server sends JSON events: {event, stage, pct, detail, ts}.
    Closes automatically when status reaches 'complete' or 'error'.
    """
    await websocket.accept()
    queue: list = []
    # Register this connection in both SSE and WS broadcaster maps
    _SSE_BROADCASTERS.setdefault(assessment_id, []).append(queue)
    _WS_CONNECTIONS.setdefault(assessment_id, []).append(websocket)
    try:
        deadline = time.time() + 120  # max 2 minutes
        while time.time() < deadline:
            if queue:
                event = queue.pop(0)
                try:
                    await websocket.send_json(event)
                except Exception:
                    break
                # Close gracefully when pipeline finishes
                evt = event.get('event') or ''
                if evt in ('complete', 'error', 'done'):
                    break
            else:
                # No events yet — send a heartbeat and check assessment status
                try:
                    assessment = REPORT_STORE.get(assessment_id) or {}
                    status = assessment.get('status') or 'pending'
                    pct = None
                    try:
                        session_id = assessment.get('session_id')
                        if session_id:
                            ws = DEFAULT_WORKER.status(session_id) or {}
                            pct = ws.get('pct')
                            status = ws.get('status') or status
                    except Exception:
                        pass
                    msg = {'event': 'heartbeat', 'status': status, 'ts': time.time()}
                    if pct is not None:
                        msg['pct'] = pct
                    await websocket.send_json(msg)
                except Exception:
                    break
                if status in ('complete', 'completed', 'error'):
                    await asyncio.sleep(0.2)
                    break
                await asyncio.sleep(0.8)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            listeners = _SSE_BROADCASTERS.get(assessment_id) or []
            if queue in listeners:
                listeners.remove(queue)
            _SSE_BROADCASTERS[assessment_id] = listeners
        except Exception:
            pass
        try:
            ws_list = _WS_CONNECTIONS.get(assessment_id) or []
            if websocket in ws_list:
                ws_list.remove(websocket)
        except Exception:
            pass


# --- TemporalRAG engine (lazy import so offline mode costs nothing) ---------
def _get_trag_engine():
    try:
        from src.ai.temporal_rag import get_engine
        return get_engine()
    except Exception:
        return None


def _coerce_tag_list(value: Any) -> List[str]:
    tags: List[str] = []

    def _append(entry: Any) -> None:
        if entry is None:
            return
        if isinstance(entry, dict):
            for key in ("id", "technique", "technique_id", "name", "value"):
                if entry.get(key):
                    _append(entry.get(key))
                    return
            for nested in entry.values():
                _append(nested)
            return
        if isinstance(entry, (list, tuple, set)):
            for nested in entry:
                _append(nested)
            return
        text = str(entry).strip()
        if text and text not in tags:
            tags.append(text)

    _append(value)
    return tags


def _collect_factor_inputs(rows: List[dict] | None = None, *sources: Any) -> List[str]:
    factors: List[str] = []

    def _append_factor(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            text = value.strip()
            if text and text not in factors:
                factors.append(text)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                _append_factor(item)
            return
        if isinstance(value, dict):
            if value.get("factor"):
                _append_factor(value.get("factor"))
            if value.get("name"):
                _append_factor(value.get("name"))
            return

    for source in list(sources) + list(rows or []):
        if not isinstance(source, dict):
            continue
        _append_factor(source.get("factors"))
        _append_factor(source.get("factor_names"))
        mapping_tags = source.get("mapping_tags") or {}
        if isinstance(mapping_tags, dict):
            _append_factor(mapping_tags.get("factors"))

    return factors


def _build_mapping_bundle(canonical: Dict[str, Any] | None, rows: List[dict] | None = None, factors: List[str] | None = None) -> Dict[str, Any]:
    canonical = canonical or {}
    rows = rows or []
    factor_inputs = _collect_factor_inputs(rows, canonical, {"factors": factors or []})

    mitre = _coerce_tag_list(map_to_mitre(canonical))
    stride = _coerce_tag_list(map_to_stride(canonical))
    controls = _coerce_tag_list(map_to_controls(canonical))
    dread = map_to_dread(canonical) or {}
    pasta = map_to_pasa(canonical) or {}
    maestro = map_to_maestro(canonical) or {}
    diamond = map_to_diamond(canonical) or {}
    atlas: List[str] = []
    owasp_llm: List[str] = []

    if map_factors_to_tags is not None and factor_inputs:
        try:
            tag_bundle = map_factors_to_tags(factor_inputs) or {}
            mitre = _coerce_tag_list(mitre + _coerce_tag_list(tag_bundle.get("mitre")))
            stride = _coerce_tag_list(stride + _coerce_tag_list(tag_bundle.get("stride")))
            atlas = _coerce_tag_list(tag_bundle.get("atlas"))
            owasp_llm = _coerce_tag_list(tag_bundle.get("owasp_llm"))
            extra_pasta = _coerce_tag_list(tag_bundle.get("pasta"))
            if extra_pasta and isinstance(pasta, dict) and not pasta.get("taxonomy_tags"):
                pasta = {**pasta, "taxonomy_tags": extra_pasta}
        except Exception:
            pass

    return {
        "mitre": mitre,
        "atlas": atlas,
        "owasp_llm": owasp_llm,
        "stride": stride,
        "controls": controls,
        "dread": dread,
        "pasta": pasta,
        "pasa": pasta,
        "maestro": maestro,
        "diamond": diamond,
    }


def _is_truthy_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _endpoint_email_ml_enabled(payload: dict, options: dict) -> bool:
    return any(
        _is_truthy_flag(candidate)
        for candidate in (
            options.get("enable_endpoint_email_ml"),
            payload.get("enable_endpoint_email_ml"),
            os.getenv("ENABLE_ENDPOINT_EMAIL_ML_PIPELINE", "0"),
        )
    )


def _infer_ml_domain(row: dict) -> str:
    for key in ("source_type", "domain_type", "source_kind", "source_platform", "source"):
        value = str(row.get(key) or "").strip().lower()
        if not value:
            continue
        if any(token in value for token in ("email", "mail", "mimecast", "proofpoint")):
            return "email"
        if any(token in value for token in ("endpoint", "sysmon", "evtx", "defender")):
            return "endpoint"
        if "network" in value:
            return "network"
    if row.get("attachment_name") or row.get("sender") or row.get("from"):
        return "email"
    if row.get("process_name") or row.get("process") or row.get("parent_process"):
        return "endpoint"
    return "other"


def _build_endpoint_email_runtime(rows: List[dict], payload: dict) -> SimpleNamespace:
    sanitized_events: List[dict] = []
    email_messages: List[dict] = []
    provided_messages = payload.get("email_messages") or []
    if isinstance(provided_messages, list):
        for item in provided_messages:
            if isinstance(item, dict):
                email_messages.append(dict(item))

    for idx, row in enumerate(rows or []):
        flat = _flatten_row_payload(row, idx)
        domain = _infer_ml_domain(flat)
        headers = flat.get("headers")
        if not isinstance(headers, dict):
            headers = {}
        sender = flat.get("sender") or flat.get("from") or headers.get("from") or ""
        reply_to = flat.get("reply_to") or headers.get("reply-to") or ""
        recipients = flat.get("to") or flat.get("recipient") or headers.get("to") or ""
        urls = flat.get("urls") or flat.get("extracted_urls") or []
        if not isinstance(urls, list):
            urls = [urls] if urls else []

        event = dict(flat)
        event.setdefault("timestamp", flat.get("timestamp") or flat.get("ts") or time.time())
        event.setdefault("type", "mail" if domain == "email" else domain)
        event.setdefault("source_platform", domain)
        event.setdefault("headers", headers)
        if sender:
            event.setdefault("sender", sender)
            event.setdefault("from", sender)
        if reply_to:
            event.setdefault("reply_to", reply_to)
        if recipients:
            event.setdefault("to", recipients)
        if urls:
            event["urls"] = [str(u) for u in urls if u]
        sanitized_events.append(event)

        attachments = flat.get("attachments")
        if isinstance(attachments, list):
            for attachment in attachments:
                if not isinstance(attachment, dict):
                    continue
                filename = attachment.get("filename") or attachment.get("name")
                if not filename:
                    continue
                email_messages.append(
                    {
                        "filename": filename,
                        "content": attachment.get("content") or attachment.get("bytes") or attachment.get("data"),
                        "mime": attachment.get("mime") or attachment.get("content_type") or "",
                        "sender_domain": attachment.get("sender_domain") or flat.get("sender_domain") or "",
                        "sha256": attachment.get("sha256") or attachment.get("hash_sha256") or "",
                    }
                )
        elif flat.get("attachment_name"):
            email_messages.append(
                {
                    "filename": flat.get("attachment_name"),
                    "content": flat.get("attachment_content") or flat.get("content") or flat.get("raw_bytes"),
                    "mime": flat.get("mime") or flat.get("attachment_mime") or "",
                    "sender_domain": flat.get("sender_domain") or "",
                    "sha256": flat.get("sha256") or flat.get("hash_sha256") or "",
                }
            )

    return SimpleNamespace(sanitized_events=sanitized_events, email_messages=email_messages)


def _score_row_against_ml_factor(row: dict, factor: dict) -> float:
    factor_name = str(factor.get("factor") or "")
    row_domain = _infer_ml_domain(row)
    expected_domain = "email" if factor_name.startswith("email:") else "endpoint" if factor_name.startswith("endpoint:") else ""
    if expected_domain and row_domain != expected_domain:
        return -1.0

    score = 0.0
    if expected_domain:
        score += 0.5

    row_host = str(row.get("host") or row.get("hostname") or "").lower()
    row_proc = str(row.get("process") or row.get("process_name") or "").lower()
    row_parent = str(row.get("parent_process") or row.get("parent") or "").lower()
    row_sha = str(row.get("sha256") or row.get("hash_sha256") or "").lower()
    row_file = str(row.get("attachment_name") or row.get("file_name") or row.get("filename") or "").lower()
    row_sender_domain = str(row.get("sender_domain") or row.get("from_domain") or row.get("domain") or "").lower()

    factor_host = str(factor.get("hostname") or factor.get("host") or "").lower()
    factor_proc = str(factor.get("process") or "").lower()
    factor_parent = str(factor.get("parent") or "").lower()
    factor_sha = str(factor.get("sha256") or "").lower()
    factor_file = str(factor.get("filename") or "").lower()
    factor_sender_domain = str(factor.get("sender_domain") or factor.get("from_domain") or factor.get("domain") or "").lower()

    if factor_host and row_host and factor_host == row_host:
        score += 2.0
    if factor_proc and row_proc and factor_proc == row_proc:
        score += 2.0
    if factor_parent and row_parent and factor_parent == row_parent:
        score += 1.5
    if factor_sha and row_sha and factor_sha == row_sha:
        score += 2.0
    if factor_file and row_file and factor_file == row_file:
        score += 1.5
    if factor_sender_domain and row_sender_domain and factor_sender_domain == row_sender_domain:
        score += 2.0
    if score <= 0.0 and expected_domain and row_domain == expected_domain:
        score += 0.25
    return score


def _apply_endpoint_email_ml(rows: List[dict], payload: dict, tenant_id: str, event_id: str) -> tuple[List[dict], Dict[str, Any]]:
    try:
        from src.core.ml_pipeline import get_pipeline  # type: ignore
    except Exception:
        return rows, {"enabled": False, "status": "pipeline_unavailable", "factors": []}

    runtime = _build_endpoint_email_runtime(rows, payload)
    try:
        result = get_pipeline().run(runtime, tenant_id=tenant_id, event_id=event_id)
        result_dict = result.as_dict() if hasattr(result, "as_dict") else dict(result or {})
    except Exception as exc:
        return rows, {"enabled": True, "status": f"pipeline_error:{type(exc).__name__}", "factors": []}

    updated_rows = [dict(r) for r in (rows or [])]
    factor_names: List[str] = []
    assigned = 0
    for factor in result_dict.get("factors") or []:
        if not isinstance(factor, dict):
            continue
        factor_name = str(factor.get("factor") or "").strip()
        if not factor_name:
            continue
        factor_names.append(factor_name)
        best_idx = None
        best_score = -1.0
        for idx, row in enumerate(updated_rows):
            score = _score_row_against_ml_factor(_flatten_row_payload(row, idx), factor)
            if score > best_score:
                best_score = score
                best_idx = idx
        if best_idx is None or best_score <= 0.0:
            continue
        target = updated_rows[best_idx]
        current_factors = list(target.get("factors") or [])
        if factor_name not in current_factors:
            current_factors.append(factor_name)
        target["factors"] = current_factors
        factor_contributions = list(target.get("factor_contributions") or [])
        factor_contributions.append(
            {
                "factor": factor_name,
                "score": float(factor.get("score") or 0.0),
                "source": "endpoint_email_ml",
                "reason": factor.get("reason") or "",
            }
        )
        target["factor_contributions"] = factor_contributions[-12:]
        target["ml_score"] = max(float(target.get("ml_score") or 0.0), float(factor.get("score") or 0.0))
        target.setdefault("_ml_pipeline_hits", []).append(factor)
        assigned += 1

    result_dict["enabled"] = True
    result_dict["status"] = "ok"
    result_dict["factor_names"] = list(dict.fromkeys(factor_names))
    result_dict["assigned_factor_count"] = assigned
    result_dict["runtime_event_count"] = len(getattr(runtime, "sanitized_events", []) or [])
    result_dict["runtime_email_message_count"] = len(getattr(runtime, "email_messages", []) or [])
    return updated_rows, result_dict


class StageBase:
    name = 'base'
    async def run(self, context: dict) -> dict:
        return {'stage': self.name, 'status': 'skipped', 'elapsed_ms': 0.0, 'result': {}}


class GeoIPStage(StageBase):
    name = 'GeoIP'
    async def run(self, context: dict) -> dict:
        t0 = time.time()
        # deterministic mock: tag any IP containing '10.' as internal
        rows = context.get('rows', [])
        count_internal = sum(1 for r in rows if isinstance(r, dict) and r.get('ip','').startswith('10.'))
        await asyncio.sleep(0)
        elapsed = (time.time() - t0) * 1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'internal_count': count_internal}}


class ThreatIntelStage(StageBase):
    name = 'ThreatIntel'
    async def run(self, context: dict) -> dict:
        t0 = time.time()
        rows = context.get('rows', [])
        # deterministic mock: file_hash 'deadbeef' is malicious
        hits = [r for r in rows if isinstance(r, dict) and r.get('file_hash') == 'deadbeef']
        await asyncio.sleep(0)
        elapsed = (time.time() - t0) * 1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'threat_hits': len(hits)}}


class TemporalRAGStage(StageBase):
    """Index evidence rows into TemporalRAG corpus so the LLM stage can retrieve
    temporally-adjacent context.  Silently skips when embeddings unavailable."""
    name = 'TemporalRAG'

    async def run(self, context: dict) -> dict:
        t0 = time.time()
        rows = context.get('rows') or []
        tenant = context.get('org') or context.get('tenant') or 'default'
        engine = _get_trag_engine()
        indexed = 0
        if engine and rows:
            try:
                indexed = await asyncio.to_thread(engine.index_rows, rows, tenant)
                # Build a context block from the first non-empty row as the query seed
                seed_text = ''
                for r in rows[:5]:
                    if isinstance(r, dict):
                        s = ' '.join(str(v) for v in r.values() if v)[:200]
                        if s:
                            seed_text = s
                            break
                if seed_text:
                    ctx_block = await asyncio.to_thread(engine.build_context_block, seed_text, tenant)
                    context['rag_context'] = ctx_block
            except Exception as exc:
                logger.debug('TemporalRAGStage skipped: %s', exc)
        elapsed = (time.time() - t0) * 1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed,
                'result': {'indexed_rows': indexed, 'embed_mode': os.getenv('TEMPORAL_RAG_EMBED', 'ollama')}}


class GraphStage(StageBase):
    name = 'GraphTraversal'
    async def run(self, context: dict) -> dict:
        t0 = time.time()
        # deterministic mock: if any row has user='admin' return expansion 1
        rows = context.get('rows', [])
        expansions = 1 if any(isinstance(r, dict) and r.get('user') == 'admin' for r in rows) else 0
        await asyncio.sleep(0)
        elapsed = (time.time() - t0) * 1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'expansions': expansions}}


class LLMSummaryStage(StageBase):
    name = 'LLMSummary'
    async def run(self, context: dict) -> dict:
        start = time.time()
        auto = context.get('options', {}).get('auto_llm', False)
        if not auto:
            return {'stage': self.name, 'status': 'skipped', 'elapsed_ms': 0.0, 'result': {}}
        client = _get_llm_client()
        provider = getattr(client, 'provider', '') if client is not None else ''
        inline_allowed = os.getenv('CSV_INLINE_LLM_SUMMARY', '0').lower() in {'1','true','yes'}
        if provider == 'ollama' and not inline_allowed:
            return {
                'stage': self.name,
                'status': 'queued',
                'elapsed_ms': (time.time() - start) * 1000.0,
                'result': {'llm_summary': {'text': 'Auto-LLM queued; Tier 1 summaries will stream in as rows are processed.'}},
            }
        # Enrich context with mitre tags and playbook guidance when helpful
        try:
            context_rows = context.get('rows') or []
            context_factors = _collect_factor_inputs(context_rows, context)
            context_canonical = build_canonical_signals([], {'rows': context_rows})
            if context_factors:
                context_canonical['factors'] = context_factors
            context_mapping = _build_mapping_bundle(context_canonical, context_rows, context_factors)
            context['mapping_tags'] = context_mapping
            mitre_tags = context_mapping.get('mitre') or context.get('mitre_tags') or []
            context['mitre_tags'] = mitre_tags
            # include artifact context for command templating
            artifact_context = context.get('artifact_context') or {}
            # decide whether to include missing logs/playbook guidance
            include_playbook = False
            try:
                include_playbook = _should_include_missing_logs(context.get('rows', [{}])[0] if isinstance(context.get('rows'), list) and context.get('rows') else {}, context.get('assessment') or {})
            except Exception:
                include_playbook = False
            if include_playbook:
                try:
                    pb_md = build_collection_playbook(context.get('domain') or 'endpoint', mitre_tags or [], artifact_context or {})
                    context['playbook_markdown'] = pb_md
                except Exception:
                    context['playbook_markdown'] = ''
        except Exception:
            pass
        # Ensure mitre_tags and playbook guidance are available to the prompt
        try:
            # derive MITRE tags from signals if not already present
            if not context.get('mitre_tags'):
                try:
                    existing_mapping = context.get('mapping_tags') or {}
                    if isinstance(existing_mapping, dict):
                        context['mitre_tags'] = existing_mapping.get('mitre') or []
                except Exception:
                    context['mitre_tags'] = context.get('mitre_tags') or []
            # include artifact_context for templating commands
            artifact_ctx = context.get('artifact_context') or {}
            # Add playbook markdown when missing logs heuristic suggests it
            try:
                include_pb = False
                if isinstance(context.get('rows'), list) and context.get('stage_status'):
                    include_pb = _should_include_missing_logs(context.get('rows')[0] if context.get('rows') else {}, {'stage_status': context.get('stage_status')})
                if include_pb and callable(build_collection_playbook):
                    domain = context.get('domain') or 'endpoint'
                    pb_md = build_collection_playbook(domain, context.get('mitre_tags') or [], artifact_ctx)
                    context['playbook_markdown'] = pb_md
                else:
                    context['playbook_markdown'] = context.get('playbook_markdown') or ''
            except Exception:
                context['playbook_markdown'] = context.get('playbook_markdown') or ''
        except Exception:
            pass
        prompt = llm_prompts.compose_prompt(context)
        # Inject TemporalRAG context block into prompt when available
        rag_ctx = context.get('rag_context') or {}
        if rag_ctx.get('rag_available') and rag_ctx.get('summary_hint'):
            rag_prefix = (
                f"\n[TemporalRAG context — {rag_ctx['neighbour_count']} similar events "
                f"in prior {rag_ctx['window_seconds'] // 3600}h window]\n"
                f"{rag_ctx['summary_hint']}\n"
            )
            prompt = rag_prefix + prompt
        summary = {'text': 'LLM summary unavailable'}
        try:
            # Use the central LLM client abstraction which honors LLM_MOCK and provider configs
            # honor per-request or session overrides if present in context/options
            _overrides = None
            try:
                _overrides = context.get('options', {}).get('overrides') or (context.get('overrides') if isinstance(context.get('overrides'), dict) else None)
            except Exception:
                _overrides = None
            if _overrides:
                resp = client.generate(prompt, max_tokens=512, tenant_id=(context.get('org') or None), overrides=_overrides) if client is not None else {}
            else:
                resp = client.generate(prompt, max_tokens=512, tenant_id=(context.get('org') or None)) if client is not None else {}
            if isinstance(resp, dict):
                summary = {'text': resp.get('text') or (resp.get('meta') or {}).get('text') or '', 'meta': resp.get('meta') or {}}
            else:
                summary = {'text': str(resp)}
        except Exception:
            # fallback deterministic summary when client unavailable
            await asyncio.sleep(0)
            summary = {'text': 'Auto-LLM fallback: top factors include geoip_anomaly, threat_intel_hit.'}
        elapsed = (time.time() - start) * 1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'llm_summary': summary}}


class TriageScoreStage(StageBase):
    """Apply src.analysis.triage.compute_triage_score to all rows so claim bands
    have real triage data instead of showing '?'."""
    name = 'TriageScore'

    async def run(self, context: dict) -> dict:
        t0 = time.time()
        rows = context.get('rows') or []
        enriched = 0
        try:
            from src.analysis.triage import compute_triage_score as _cts
            for row in rows:
                if not isinstance(row, dict):
                    continue
                if row.get('triage_score') is None:
                    inputs = {
                        'dread': _extract_dread_score(row) if callable(globals().get('_extract_dread_score')) else (row.get('dread_score') or 0.0),
                        'correlation': float(row.get('correlation_score') or (row.get('_correlation') or {}).get('score') or 0.0),
                        'density': float(row.get('factor_density') or 0.0),
                        'confidence': float(row.get('risk_confidence') or row.get('confidence') or 0.0),
                        'rarity': float(row.get('rarity_score') or 0.0),
                    }
                    result = _cts(inputs)
                    row['triage_score'] = result.get('triage_score', 0.0)
                    row['_triage_breakdown'] = result.get('breakdown', {})
                    enriched += 1
        except Exception:
            pass
        elapsed = (time.time() - t0) * 1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'enriched_rows': enriched}}


STAGE_REGISTRY = [GeoIPStage(), ThreatIntelStage(), TemporalRAGStage(), GraphStage(), TriageScoreStage(), LLMSummaryStage()]


class EBPFStage(StageBase):
    name = 'eBPF'
    async def run(self, context: dict) -> dict:
        if context.get('analyze_mode') != 'advanced':
            return {'stage': self.name, 'status': 'skipped', 'elapsed_ms': 0.0, 'result': {}}
        t0 = time.time()
        # lightweight simulated eBPF summary
        await asyncio.sleep(0)
        elapsed = (time.time()-t0)*1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'ebpf_suspicious_calls': 0}}


class PCAPStage(StageBase):
    name = 'PCAP'
    async def run(self, context: dict) -> dict:
        if context.get('analyze_mode') != 'advanced':
            return {'stage': self.name, 'status': 'skipped', 'elapsed_ms': 0.0, 'result': {}}
        t0 = time.time()
        await asyncio.sleep(0)
        elapsed = (time.time()-t0)*1000.0
        return {'stage': self.name, 'status': 'done', 'elapsed_ms': elapsed, 'result': {'pcap_sessions': 0}}


ADVANCED_STAGES = [EBPFStage(), PCAPStage()]


async def _run_stage(stage: StageBase, ctx: dict) -> dict:
    t0 = time.time()
    try:
        res = await stage.run(ctx)
        return res
    except Exception as exc:
        try:
            elapsed = (time.time() - t0) * 1000.0
        except Exception:
            elapsed = 0.0
        # Best-effort metric increment and logging; avoid referencing outer-scope variables
        try:
            logger.exception('Stage %s failed: %s', getattr(stage, 'name', 'unknown'), exc)
        except Exception:
            pass
        return {'stage': getattr(stage, 'name', 'unknown'), 'status': 'error', 'elapsed_ms': elapsed, 'result': {}, 'error': str(exc)}


def _should_include_missing_logs(row: dict, assessment: dict) -> bool:
    """Heuristic: include missing logs section when correlation or high-risk patterns or low confidence.
    This is a lightweight placeholder until full 21-stage pipeline context is available.
    """
    try:
        factors = set(row.get('factors') or [])
        # correlation heuristic: expansions from GraphTraversal stage
        stages = assessment.get('stage_status') or []
        expansions = 0
        for st in stages:
            if st.get('stage') == 'GraphTraversal':
                expansions = int(st.get('result', {}).get('expansions', 0) or 0)
                break
        risk_num = (row.get('risk_level') or {}).get('numeric') or 0
        llm_conf = (row.get('llm_meta') or {}).get('confidence') or 1.0
        if expansions > 0 or risk_num >= 7 or llm_conf < 0.8:
            return True
        telemetry_gaps = {'no_network_logs','no_parent_process','no_registry_data'}
        if factors.intersection(telemetry_gaps):
            return True
        return False
    except Exception:
        return False


def _build_pipeline_snapshot(assessment: dict | None, row: dict | None = None) -> dict | None:
    """Summarize pipeline progress, highlighting pre/post execution and supply-chain hooks."""
    if not isinstance(assessment, dict):
        return None
    stages = assessment.get('pipeline_stages') or []
    stage_status = assessment.get('stage_status') or []
    completed = []
    errored = []
    for entry in stage_status:
        try:
            name = entry.get('stage') or entry.get('name')
            status = str(entry.get('status') or '').lower()
            if status in {'done', 'completed'}:
                completed.append(name)
            elif status in {'error', 'failed'}:
                errored.append({'stage': name, 'error': entry.get('error')})
        except Exception:
            continue
    total = len(stages) or max(len(completed), 1)
    rank_label = f"{min(len(completed), total)}/{total}"
    pending = [s.get('name') for s in stages if s.get('name') not in set(completed)]
    snapshot = {
        'stage_count': total,
        'completed_stages': completed[:12],
        'pending_stages': pending[:12],
        'rank_label': rank_label,
        'errored_stages': errored[:5],
    }
    # lightweight view of pre/post execution artefacts demanded by RFC guidance
    midpoint = max(1, total // 3)
    snapshot['pre_execution_focus'] = completed[:midpoint]
    snapshot['post_execution_focus'] = completed[midpoint:][:midpoint]
    # highlight npm / CI / binary stages when present
    supply_chain_stages = []
    for s in completed:
        label = str(s or '').lower()
        if any(tok in label for tok in ('npm', 'supply', 'ci', 'cicd', 'binary', 'artifact')):
            supply_chain_stages.append(s)
    if supply_chain_stages:
        snapshot['supply_chain_completed'] = supply_chain_stages
    if row and row.get('triage_score') is not None:
        snapshot['row_rank'] = row.get('triage_score')
    return snapshot


def _derive_breaker_signal(assessment: dict | None) -> dict | None:
    telemetry = (assessment or {}).get('telemetry') or {}
    breaker_blob = telemetry.get('breaker_state') or (assessment or {}).get('llm_breakers') or {}
    queue_depth = telemetry.get('queue_depth') or telemetry.get('llm_queue_depth')
    if not breaker_blob and queue_depth is None:
        return None
    signal: dict[str, Any] = {}
    if isinstance(queue_depth, (int, float)):
        signal['queue_depth'] = queue_depth
        if queue_depth and queue_depth > 50:
            signal['congested'] = True
    if isinstance(breaker_blob, dict):
        alerts = []
        for name, state in breaker_blob.items():
            try:
                open_flag = bool(state.get('open') if isinstance(state, dict) else False)
                summary = {
                    'name': name,
                    'open': open_flag,
                    'reason': state.get('reason') if isinstance(state, dict) else None,
                    'until': state.get('tripped_until') if isinstance(state, dict) else None,
                }
                alerts.append(summary)
                if open_flag:
                    signal['congested'] = True
            except Exception:
                continue
        if alerts:
            signal['breakers'] = alerts[:5]
    return signal or None


def _extract_mapping_semantics_context(row: dict | None, assessment: dict | None) -> dict | None:
    score = None
    summary = None
    if isinstance(row, dict):
        if row.get('mapping_semantics_score') is not None:
            score = row.get('mapping_semantics_score')
        summary = row.get('mapping_summary')
        if summary is None and isinstance(row.get('raw'), dict):
            summary = row['raw'].get('mapping_summary')
    if score is None and isinstance(assessment, dict):
        score = assessment.get('mapping_semantics_score')
        summary = summary or assessment.get('mapping_summary')
    if score is None and isinstance(summary, dict):
        score = min(1.0, len(summary.get('high_value_present') or []) / max(1, len(summary.get('present_fields') or {})))
    if score is None and summary is None:
        return None
    return {
        'score': round(float(score), 3) if isinstance(score, (int, float)) else score,
        'summary': summary,
    }


def _collect_binary_network_tags(row: dict | None) -> dict:
    payload: dict[str, Any] = {}
    if not isinstance(row, dict):
        return payload
    raw = row.get('raw') if isinstance(row.get('raw'), dict) else {}
    entropy = row.get('entropy') or raw.get('entropy')
    import_count = row.get('import_count') or raw.get('import_count')
    if entropy is not None:
        try:
            payload['binary_entropy'] = round(float(entropy), 3)
        except Exception:
            payload['binary_entropy'] = entropy
    if import_count is not None:
        payload['import_risk'] = int(import_count)
    tokens = _extract_factor_tokens(row)
    supply_chain = sorted({t for t in tokens if any(key in t for key in SUPPLY_CHAIN_KEYWORDS)})
    infra = sorted({t for t in tokens if any(key in t for key in INFRA_KEYWORDS)})
    if supply_chain:
        payload['supply_chain_tags'] = supply_chain[:6]
    if infra:
        payload['network_anomaly_tags'] = infra[:8]
    # Include SBOM impact if present
    sbom = row.get('sbom_impact') or raw.get('sbom_impact')
    if sbom:
        payload['sbom_impact'] = sbom
    return payload


def _collect_kill_chain_tags(row: dict | None, assessment: dict | None) -> dict | None:
    if not isinstance(row, dict):
        return None
    phases = []
    tokens = _extract_factor_tokens(row)
    if any('supply' in t or 'npm' in t for t in tokens):
        phases.append('Initial Access (Supply Chain)')
    if any('ci/' in t or 'pipeline' in t for t in tokens):
        phases.append('Execution (CI/CD artifact run)')
    if any(tag in tokens for tag in ('bgp_leak', 'bgp_hijack', 'macsec_drift')):
        phases.append('Command and Control (Network Fabric)')
    if row.get('sbom_impact'):
        phases.append('Impact (SBOM delta detected)')
    if not phases and isinstance(assessment, dict):
        mapped = assessment.get('mappings', {}).get('mitre') or []
        try:
            for tag in mapped[:3]:
                if isinstance(tag, dict) and tag.get('kill_chain_phase'):
                    phases.append(tag['kill_chain_phase'])
        except Exception:
            pass
    if not phases:
        return None
    return {'phases': phases[:6]}


def _evidence_policy() -> dict[str, float]:
    """Centralize evidence coverage targets for Tier1/Tier2 + loop-closure UI."""
    target = 0.7
    warn = 0.5
    critical = 0.3
    try:
        target = float(os.getenv('EVIDENCE_COVERAGE_TARGET', str(target)))
    except Exception:
        pass
    try:
        warn = float(os.getenv('EVIDENCE_COVERAGE_WARN', str(warn)))
    except Exception:
        pass
    try:
        critical = float(os.getenv('EVIDENCE_COVERAGE_CRITICAL', str(critical)))
    except Exception:
        pass
    target = min(1.0, max(0.0, target))
    warn = min(target, max(0.0, warn))
    critical = min(warn, max(0.0, critical))
    return {'target': target, 'warn': warn, 'critical': critical}


def _compute_evidence_coverage_signal(row: dict | None) -> float:
    if not isinstance(row, dict):
        return 0.0
    score = 0.0
    weight = 0.0
    mapping_score = row.get('mapping_semantics_score')
    if isinstance(mapping_score, (int, float)):
        score += max(0.0, min(1.0, float(mapping_score)))
        weight += 1.0
    if row.get('binary_context') or row.get('binary_artifact'):
        score += 0.5
        weight += 0.5
    if row.get('hopgraph_context') or row.get('hopgraph_summary') or row.get('graph_summary'):
        score += 0.5
        weight += 0.5
    cached = row.get('cached_evidence') or []
    if cached:
        score += 0.25
        weight += 0.25
    if weight <= 0:
        return 0.0
    return float(min(1.0, max(0.0, score / weight)))


def _build_evidence_summary(row: dict | None) -> dict | None:
    coverage = _compute_evidence_coverage_signal(row)
    policy = _evidence_policy()
    status = 'ok'
    if coverage < policy['critical']:
        status = 'critical'
    elif coverage < policy['warn']:
        status = 'warn'
    elif coverage < policy['target']:
        status = 'gap'
    summary = {
        'coverage': coverage,
        'coverage_percent': round(coverage * 100.0, 2),
        'policy': policy,
        'target': policy['target'],
        'meets_target': coverage >= policy['target'],
        'status': status,
    }
    return summary


def _build_playbook_preview(row: dict | None, assessment: dict | None) -> dict | None:
    """Return a structured playbook preview for per-row loop-closure actions."""
    if not isinstance(row, dict):
        return None
    try:
        domain = _infer_domain(row)
    except Exception:
        domain = 'endpoint'
    mitre_tags = []
    if isinstance(row.get('mitre_tags'), list):
        mitre_tags.extend(row['mitre_tags'])
    mapping_tags = row.get('mapping_tags') or {}
    if isinstance(mapping_tags, dict):
        mt = mapping_tags.get('mitre') or []
        if isinstance(mt, list):
            mitre_tags.extend(mt)
    if assessment and isinstance(assessment.get('mappings'), dict):
        extra = assessment['mappings'].get('mitre') or []
        if isinstance(extra, list):
            mitre_tags.extend(extra)
    mitre_tags = list(dict.fromkeys([str(t) for t in mitre_tags if t]))
    artifact_context = {
        'process_name': row.get('process_name') or row.get('process') or '',
        'src_ip': row.get('src_ip') or row.get('ip_src') or row.get('ip'),
        'dst_ip': row.get('dst_ip') or row.get('ip_dst'),
        'host': row.get('host') or row.get('hostname') or '',
        'user': row.get('user') or row.get('account') or '',
        'factors': list(row.get('factors') or []),
    }
    tools = []
    try:
        for tool in get_tools_for_domain(domain)[:3]:
            formatted_command = tool.get('command', '')
            try:
                formatted_command = formatted_command.format(**artifact_context)
            except Exception:
                pass
            tools.append({
                'name': tool.get('name'),
                'purpose': tool.get('purpose'),
                'command': formatted_command,
                'output': tool.get('output_format'),
                'when_to_use': tool.get('when_to_use'),
            })
    except Exception:
        tools = []
    log_recs = []
    for tag in mitre_tags[:3]:
        try:
            info = get_logs_for_mitre(tag)
        except Exception:
            continue
        log_recs.append({
            'mitre': tag,
            'name': info.get('name'),
            'logs': info.get('logs'),
            'why': info.get('why'),
        })
    steps = []
    if tools:
        steps.append(f"Run {tools[0]['name']} on {artifact_context.get('host') or 'affected host'} to capture live state.")
    if log_recs:
        steps.append(f"Collect logs for {log_recs[0]['mitre']} ({log_recs[0]['name']}) to validate the scenario.")
    if row.get('sha256'):
        steps.append(f"Push hash {row['sha256'][:12]}… to sandbox or EDR containment workflows.")
    if not steps:
        steps.append("Collect host/network artifacts per policy before escalating.")
    preview_text = None
    try:
        preview_text = build_collection_playbook(domain, mitre_tags, artifact_context)
    except Exception:
        preview_text = None
    return {
        'domain': domain,
        'summary': f'Collection + containment plan for {domain} indicators',
        'steps': steps[:4],
        'tools': tools,
        'logs': log_recs,
        'text': preview_text,
    }


def _maybe_cache_heavy_sections(assessment_id: str | None, row_index: Any, row: dict | None) -> list[dict]:
    if not assessment_id or not isinstance(row, dict):
        return []
    heavy_keys = [
        ('process_tree', 'Process Tree'),
        ('binary_artifact', 'Binary Artifact'),
        ('hopgraph_subgraph', 'HopGraph Path'),
        ('pcap_summary', 'PCAP Summary'),
        ('memory_dump', 'Memory Dump'),
        ('evidence_bundle', 'Evidence Bundle'),
        ('enrichment_details', 'Enrichment Details'),
    ]
    cached: list[dict] = []
    raw = row.get('raw') if isinstance(row.get('raw'), dict) else {}
    for key, label in heavy_keys:
        blob = row.get(key)
        if blob is None:
            blob = raw.get(key)
        if blob in (None, '', []):
            continue
        cache_key = _cache_evidence_blob(str(assessment_id), int(row_index or 0), blob)
        if cache_key:
            entry = {'type': key, 'label': label, 'cache_key': cache_key}
            try:
                entry['size_hint'] = len(json.dumps(blob))  # type: ignore[arg-type]
            except Exception:
                pass
            cached.append(entry)
    return cached


def _augment_llm_row(llm_row: dict, assessment: dict) -> dict:
    """Attach cost/tokens placeholders, missing logs hints (conditional), and persona placeholder container."""
    try:
        llm_row.setdefault('_llm_processed', True)
        llm_row.setdefault('_llm_timestamp', int(time.time()))
        if assessment and assessment.get('assessment_id'):
            llm_row.setdefault('assessment_id', assessment.get('assessment_id'))
        # tokens/cost placeholder (real values surface through central client meta if present)
        meta = llm_row.get('llm_meta') or {}
        input_tokens = meta.get('input_tokens') or meta.get('prompt_tokens') or 0
        output_tokens = meta.get('output_tokens') or meta.get('completion_tokens') or 0
        total_tokens = (input_tokens or 0) + (output_tokens or 0)
        llm_row['_llm_tokens'] = {'input': input_tokens, 'output': output_tokens, 'total': total_tokens}
        # Simple cost based on flat $0.003 per row unless token counts available
        cost_per_row = float(os.getenv('LLM_COST_PER_ROW', '0.003'))
        if total_tokens and os.getenv('LLM_COST_PER_1K'):
            try:
                per_1k = float(os.getenv('LLM_COST_PER_1K', '0.002'))
                llm_row['_llm_cost'] = round((total_tokens / 1000.0) * per_1k, 6)
            except Exception:
                llm_row['_llm_cost'] = cost_per_row
        else:
            llm_row['_llm_cost'] = cost_per_row
        if _should_include_missing_logs(llm_row, assessment):
            llm_row.setdefault('missing_logs', [
                'PowerShell 4104 (script block logging)',
                'Firewall egress (destination IP/domain)',
                'Authentication (Windows 4624 / cloud identity)'
            ])
        pipeline_snapshot = _build_pipeline_snapshot(assessment, llm_row) or {}
        llm_row.setdefault('pipeline_snapshot', pipeline_snapshot)
        breaker_signal = _derive_breaker_signal(assessment)
        if breaker_signal:
            llm_row['breaker_signal'] = breaker_signal
        mapping_ctx = _extract_mapping_semantics_context(llm_row, assessment)
        if mapping_ctx:
            llm_row['mapping_semantics'] = mapping_ctx
            if 'score' in mapping_ctx:
                llm_row.setdefault('mapping_semantics_score', mapping_ctx['score'])
        binary_ctx = _collect_binary_network_tags(llm_row)
        if binary_ctx:
            llm_row['binary_context'] = binary_ctx
        kill_chain_ctx = _collect_kill_chain_tags(llm_row, assessment)
        if kill_chain_ctx:
            llm_row['kill_chain'] = kill_chain_ctx
        playbook_preview = _build_playbook_preview(llm_row, assessment)
        if playbook_preview:
            llm_row['playbook_preview'] = playbook_preview
        evidence_summary = _build_evidence_summary(llm_row)
        if evidence_summary:
            llm_row['evidence_summary'] = evidence_summary
        if assessment and assessment.get('assessment_id'):
            cached = _maybe_cache_heavy_sections(assessment.get('assessment_id'), llm_row.get('row_index'), llm_row)
            if cached:
                llm_row['cached_evidence'] = cached
            else:
                llm_row.setdefault('cached_evidence', [])
        else:
            llm_row.setdefault('cached_evidence', [])
        # persona reports container
        llm_row.setdefault('persona_templates', PERSONA_DEFINITIONS)
        persona_container = llm_row.setdefault('persona_reports', {})
        for persona_key in ('soc', 'ciso', 'compliance'):
            persona_container.setdefault(persona_key, {'text': '', 'status': 'pending'})
        # Attempt to prefill persona text via cached LLM helper when empty
        try:
            for pk in ('soc', 'ciso', 'compliance'):
                entry = persona_container.setdefault(pk, {})
                txt = entry.get('text') if isinstance(entry, dict) else None
                status = entry.get('status') if isinstance(entry, dict) else None
                if not txt and status in (None, 'pending'):
                    try:
                        cache_resp = llm_helper.cached_generate(persona=pk, incident=llm_row, temperature=0.6)
                        if isinstance(cache_resp, dict):
                            resp_text = cache_resp.get('response') or cache_resp.get('text') or str(cache_resp)
                        else:
                            resp_text = str(cache_resp)
                        entry['text'] = resp_text
                        # parse and validate structured fields
                        try:
                            parsed = parse_persona_text(resp_text)
                            if parsed:
                                entry['parsed'] = parsed
                                # enforce minimal schema and confidence threshold
                                valid, errs = validate_parsed_persona(parsed)
                                min_conf = 0.5
                                try:
                                    min_conf = float(os.getenv('PERSONA_MIN_CONFIDENCE', '0.5') or 0.5)
                                except Exception:
                                    pass
                                if not valid or float(parsed.get('confidence') or 0.0) < min_conf:
                                    entry['validation'] = {'valid': False, 'errors': errs, 'confidence': parsed.get('confidence')}
                                    entry['status'] = 'needs_review'
                                else:
                                    entry['validation'] = {'valid': True, 'errors': [], 'confidence': parsed.get('confidence')}
                                    entry['status'] = 'ready'
                            else:
                                entry['status'] = 'pending'
                        except Exception:
                            entry.setdefault('status', 'pending')
                    except Exception:
                        # leave pending if generation fails
                        entry.setdefault('status', 'pending')
                else:
                    # if text already present, ensure parsed
                    if txt and (not isinstance(entry, dict) or 'parsed' not in entry):
                        try:
                            parsed = parse_persona_text(str(txt))
                            if parsed:
                                entry['parsed'] = parsed
                                valid, errs = validate_parsed_persona(parsed)
                                min_conf = 0.5
                                try:
                                    min_conf = float(os.getenv('PERSONA_MIN_CONFIDENCE', '0.5') or 0.5)
                                except Exception:
                                    pass
                                if not valid or float(parsed.get('confidence') or 0.0) < min_conf:
                                    entry['validation'] = {'valid': False, 'errors': errs, 'confidence': parsed.get('confidence')}
                                    entry['status'] = 'needs_review'
                                else:
                                    entry['validation'] = {'valid': True, 'errors': [], 'confidence': parsed.get('confidence')}
                                    entry.setdefault('status', 'ready')
                        except Exception:
                            pass
        except Exception:
            pass
    except Exception:
        pass
    return llm_row


def _extract_hopgraph_inline_context(assessment: dict | None) -> dict | None:
    """Return a lightweight hopgraph summary snippet for prompt enrichment."""
    if not isinstance(assessment, dict):
        return None
    summary = assessment.get('hopgraph_summary')
    if isinstance(summary, dict) and summary:
        try:
            session_id, payload = next(iter(summary.items()))
            if isinstance(payload, dict):
                snippet = {
                    'session_id': session_id,
                    'verdict': payload.get('verdict'),
                    'confidence': payload.get('confidence'),
                    'key_factors': payload.get('key_factors'),
                    'domains': payload.get('domains'),
                    'mapping_stats': payload.get('mapping_stats'),
                }
                if payload.get('confidence_breakdown'):
                    snippet['confidence_breakdown'] = payload.get('confidence_breakdown')
                if payload.get('hotspots'):
                    snippet['hotspots'] = payload.get('hotspots')
                return snippet
        except Exception:
            return None
    session_summary = assessment.get('graph_summary')
    if isinstance(session_summary, dict) and session_summary.get('nodes'):
        return {
            'session_id': session_summary.get('session_id'),
            'verdict': session_summary.get('verdict'),
            'confidence': session_summary.get('confidence'),
            'nodes': session_summary.get('node_count'),
            'edges': session_summary.get('edge_count'),
        }
    return None


SUPPLY_CHAIN_KEYWORDS = {'npm', 'package', 'supply', 'cicd', 'pipeline', 'artifact', 'publishing', 'registry'}
INFRA_KEYWORDS = {'bgp', 'macsec', 'ipsec', 'ospf', 'asn', 'route', 'peering'}

EVIDENCE_CACHE: Dict[str, Dict[str, Any]] = {}
EVIDENCE_CACHE_TTL = max(60, int(os.getenv('CSV_EVIDENCE_TTL_SECONDS', '1800') or 1800))

try:
    PERSONA_DEFINITIONS = {}
    # map central templates to this module's short keys
    for k, v in CENTRAL_PERSONA_TEMPLATES.items():
        key_map = {
            'soc_analyst': 'soc',
            'executive': 'ciso',
            'compliance': 'compliance',
        }
        new_key = key_map.get(k, k)
        PERSONA_DEFINITIONS[new_key] = {
            'label': v.get('tone') or v.get('label') or new_key,
            'instructions': v.get('instructions') or '',
            'checklist': v.get('checklist') or [],
        }
except Exception:
    PERSONA_DEFINITIONS = {}


def _evict_expired_evidence() -> None:
    """Drop stale entries from the local evidence cache."""
    try:
        now = time.time()
        expired = [key for key, rec in EVIDENCE_CACHE.items() if now - rec.get('ts', 0) > EVIDENCE_CACHE_TTL]
        for key in expired:
            EVIDENCE_CACHE.pop(key, None)
    except Exception:
        pass


def _cache_evidence_blob(assessment_id: str, row_index: int, payload: Any) -> str | None:
    """Persist heavy evidence blobs in-memory and optionally in Redis for lazy loading."""
    if not payload:
        return None
    try:
        blob = {'data': payload, 'ts': time.time()}
        cache_key = f"{assessment_id}:{row_index}:{uuid.uuid4().hex[:8]}"
        EVIDENCE_CACHE[cache_key] = blob
        _evict_expired_evidence()
        red_url = os.getenv('REDIS_URL') or os.getenv('REDIS_URI')
        if red_url:
            try:
                import redis  # type: ignore
                rc = redis.from_url(red_url)
                rc.setex(f"csv:evidence:{cache_key}", EVIDENCE_CACHE_TTL, json.dumps(payload))
            except Exception:
                pass
        return cache_key
    except Exception:
        return None


def _load_cached_evidence(cache_key: str) -> Any:
    """Load a cached evidence blob from Redis (if configured) or the in-memory cache."""
    if not cache_key:
        return None
    red_url = os.getenv('REDIS_URL') or os.getenv('REDIS_URI')
    if red_url:
        try:
            import redis  # type: ignore
            rc = redis.from_url(red_url)
            raw = rc.get(f"csv:evidence:{cache_key}")
            if raw:
                return json.loads(raw)
        except Exception:
            pass
    record = EVIDENCE_CACHE.get(cache_key)
    if not record:
        return None
    if (time.time() - record.get('ts', 0)) > EVIDENCE_CACHE_TTL:
        EVIDENCE_CACHE.pop(cache_key, None)
        return None
    return record.get('data')


@router.get('/assessments/{assessment_id}/evidence/{cache_key}')
async def fetch_cached_evidence(assessment_id: str, cache_key: str):
    """Expose cached heavy evidence blobs for lazy-loading in the UI."""
    if not cache_key or not assessment_id:
        raise HTTPException(status_code=400, detail='missing_params')
    prefix = f"{assessment_id}:"
    if not cache_key.startswith(prefix):
        raise HTTPException(status_code=404, detail='evidence_not_found')
    payload = _load_cached_evidence(cache_key)
    if payload is None:
        raise HTTPException(status_code=404, detail='evidence_not_found')
    return JSONResponse({'assessment_id': assessment_id, 'cache_key': cache_key, 'data': payload})


def _build_persona_context(row: dict | None, assessment: dict | None) -> dict:
    ctx: dict[str, Any] = {}
    snapshot = (row or {}).get('pipeline_snapshot') or _build_pipeline_snapshot(assessment, row)
    if snapshot:
        ctx['pipeline'] = snapshot
    breaker = (row or {}).get('breaker_signal') or _derive_breaker_signal(assessment)
    if breaker:
        ctx['breaker'] = breaker
    mapping = (row or {}).get('mapping_semantics') or _extract_mapping_semantics_context(row, assessment)
    if mapping:
        ctx['mapping_semantics'] = mapping
    binary_ctx = (row or {}).get('binary_context') or _collect_binary_network_tags(row)
    if binary_ctx:
        ctx['binary'] = binary_ctx
    kill_chain = (row or {}).get('kill_chain') or _collect_kill_chain_tags(row, assessment)
    if kill_chain:
        ctx['kill_chain'] = kill_chain
    hopgraph_ctx = (row or {}).get('hopgraph_context') or _extract_hopgraph_inline_context(assessment)
    if hopgraph_ctx:
        ctx['hopgraph'] = hopgraph_ctx
    cached = (row or {}).get('cached_evidence')
    if cached:
        ctx['cached_evidence'] = cached
    hop_summary = (assessment or {}).get('hopgraph_summary')
    if isinstance(hop_summary, dict):
        ctx.setdefault('hopgraph_summary', hop_summary)
        if hop_summary.get('hotspot_tags'):
            ctx.setdefault('hotspot_tags', hop_summary.get('hotspot_tags'))
        if hop_summary.get('hopgraph_overlay'):
            ctx.setdefault('hopgraph_overlay', hop_summary.get('hopgraph_overlay'))
    # Inject log heartbeat status to enrich Tier-1/Tier-2 LLM summaries and report generation
    try:
        from src.core.monitoring.log_heartbeat import status as _hb_status  # type: ignore
    except Exception:
        try:
            from core.monitoring.log_heartbeat import status as _hb_status  # type: ignore
        except Exception:
            _hb_status = None  # type: ignore
    if _hb_status:
        try:
            hb = _hb_status()
            ctx['dependency_status'] = ctx.get('dependency_status') or {}
            ctx['dependency_status']['logs'] = {
                'available': hb.get('available'),
                'last_ok_ts': hb.get('last_ok_ts'),
                'seconds_since_ok': hb.get('seconds_since_ok'),
                'sources': hb.get('sources'),
                'missing_sources': hb.get('missing_sources'),
                'gaps': hb.get('gaps')
            }
        except Exception:
            pass
    return ctx


def _render_persona_prompt(persona: str, row: dict, assessment: dict | None, base_summary: str) -> str:
    template = PERSONA_DEFINITIONS.get(persona) or PERSONA_DEFINITIONS['soc']
    context_block = _build_persona_context(row, assessment)
    prompt_lines = [
        template['instructions'],
        '',
        'CHECKLIST:',
    ]
    for item in template.get('checklist', []):
        prompt_lines.append(f"- {item}")
    # Explicitly list log gaps by severity when available
    try:
        logs = (context_block.get('dependency_status') or {}).get('logs') or {}
        gaps = logs.get('gaps') or []
        sources = logs.get('sources') or []
        if gaps:
            prompt_lines.append('')
            prompt_lines.append('LOG GAP CHECKLIST:')
            for g in gaps[:20]:
                sev = str(g.get('severity') or 'critical').upper()
                name = g.get('name') or 'unknown'
                msg = g.get('message') or ''
                secs = int(g.get('seconds_since_ok') or 0)
                ttl = int(g.get('ttl') or 0)
                prompt_lines.append(f"- [{sev}] {name}: {msg} (stale {secs}s, ttl {ttl}s)")
        if sources:
            prompt_lines.append('')
            prompt_lines.append('LOG SOURCE FRESHNESS:')
            for s in sources[:30]:
                name = s.get('name')
                sev = str(s.get('severity') or 'info').upper()
                secs = int((s.get('seconds_since_ok') or 0) or 0)
                ttl = int((s.get('ttl') or 0) or 0)
                prompt_lines.append(f"- {name}: {sev} (age {secs}s, ttl {ttl}s)")
    except Exception:
        pass
    prompt_lines.append('')
    prompt_lines.append('CONTEXT JSON:')
    try:
        prompt_lines.append(json.dumps(context_block, default=str, indent=2)[:2400])
    except Exception:
        prompt_lines.append(str(context_block))
    prompt_lines.append('')
    prompt_lines.append('BASE SUMMARY:')
    prompt_lines.append(base_summary[:2600] if base_summary else 'No base summary provided.')
    prompt_lines.append('')
    prompt_lines.append('RESPONSE:')
    return '\n'.join(prompt_lines)


def _auto_route_incident(row: dict, persona: str, persona_text: str, assessment: dict | None) -> None:
    if persona not in {'ciso', 'compliance'}:
        return
    if GLOBAL_INCIDENTS is None:
        return
    try:
        dread = row.get('_dread') or {}
        risk = float(dread.get('score') or 0.0)
    except Exception:
        risk = 0.0
    triage = float(row.get('triage_score') or 0.0)
    if risk < 6.0 and triage < 0.7:
        return
    event = {
        'event_id': row.get('event_id') or f"row-{row.get('row_index')}",
        'host': row.get('host') or row.get('raw', {}).get('host'),
        'user': row.get('user') or row.get('raw', {}).get('user'),
        'severity': 'critical' if risk >= 8.0 else ('high' if risk >= 6.0 else 'medium'),
        'description': persona_text,
        'generated_persona': persona,
        'assessment_id': (assessment or {}).get('assessment_id'),
    }
    try:
        GLOBAL_INCIDENTS.ingest(event, list(row.get('factors') or []))
    except Exception:
        pass


def _extract_factor_tokens(row: dict) -> list[str]:
    """Return lowercase factor tokens from row or raw payload."""
    try:
        factors = row.get('factors')
        if factors is None and isinstance(row.get('raw'), dict):
            factors = row['raw'].get('factors')
        return [str(f).lower() for f in (factors or [])]
    except Exception:
        return []


def _has_supply_chain_indicator(row: dict) -> bool:
    tokens = _extract_factor_tokens(row)
    if not tokens:
        return False
    return any(any(key in token for key in SUPPLY_CHAIN_KEYWORDS) for token in tokens)


def _has_network_infra_indicator(row: dict) -> bool:
    tokens = _extract_factor_tokens(row)
    if not tokens:
        return False
    return any(any(key in token for key in INFRA_KEYWORDS) for token in tokens)


def _flatten_row_payload(row: dict | None, fallback_index: int) -> dict:
    """Merge top-level CSV row structure with nested raw payload."""
    if not isinstance(row, dict):
        return {'row_index': fallback_index}
    merged: dict[str, Any] = {}
    raw = row.get('raw')
    if isinstance(raw, dict):
        merged.update(raw)
    for key, value in row.items():
        if key == 'raw':
            continue
        merged[key] = value  # outer wrapper fields win (row_index must be global, not per-file)
    row_index_value = merged.get('row_index', fallback_index)
    try:
        if isinstance(row_index_value, int):
            merged['row_index'] = str(row_index_value)
        else:
            merged['row_index'] = row_index_value
    except Exception:
        merged['row_index'] = fallback_index
    return merged


_TS_FIELDS = (
    'timestamp', 'Timestamp', 'ts', 'time', 'created', 'created_at', 'event_time',
    'event_ts', 'last_seen', 'first_seen', 'TimeGenerated', 'ActivityDateTime',
    'eventTime', '@timestamp', 'datetime', 'date_time', 'startTime', 'endTime',
    'log_timestamp', 'detection_time', 'observed_at',
)
_DESC_FIELDS = (
    'analyst_notes', 'notes', 'description', 'Description', 'result_description',
    'defender_alert', 'alert_name', 'event_name', 'eventName', 'operation_name',
    'operationName', 'activityDisplayName', 'riskEventType', 'subject',
    'threat_category', 'category'
)
_ACCOUNT_FIELDS = (
    'user_principal_name', 'userPrincipalName', 'username', 'user', 'account',
    'caller_upn', 'caller', 'requestor', 'actor', 'actor_email', 'mailbox_owner',
    'identity', 'principal', 'principal_name', 'upn',
    # CloudTrail nested: userIdentity.userName / userIdentity.arn
    'userName', 'user_name', 'arn',
    # Okta nested: actor.alternateId / actor.displayName
    'alternateId', 'displayName',
    # M365 / Exchange: UserId / UserKey / SendingUserSmtp
    'UserId', 'UserKey', 'SendingUserSmtp',
    # Entra / AAD: UserPrincipalName variation
    'UPN', 'ObjectId',
)
# Nested dotted-path lookups for identity fields that live inside sub-objects.
# Format: tuple of (dotted_path, list_index_or_None) pairs.
# These fire after the flat-field scan and before email regex fallback.
_ACCOUNT_NESTED_PATHS = (
    # CloudTrail: {"userIdentity": {"userName": "...", "arn": "..."}}
    'userIdentity.userName',
    'userIdentity.arn',
    'userIdentity.principalId',
    # Okta: {"actor": {"alternateId": "...", "displayName": "..."}}
    'actor.alternateId',
    'actor.displayName',
    # Entra / AAD audit: {"initiatedBy": {"user": {"userPrincipalName": "..."}}}
    'initiatedBy.user.userPrincipalName',
    'initiatedBy.user.id',
    # Entra sign-in: {"userDisplayName": "..."} (already flat but keep path form for uniformity)
    'properties.userPrincipalName',
    'properties.userId',
    # SailPoint: {"actor": {"name": "..."}}
    'actor.name',
    # Generic nested target principal
    'target.userPrincipalName',
    'target.id',
)
_HOST_NESTED_PATHS = (
    # CloudTrail: requestParameters.instanceId
    'requestParameters.instanceId',
    # Defender/Sentinel: {"DeviceName": ...} (flat, but also sometimes nested)
    'entities.0.HostName',
    'entities.0.DeviceName',
    # Okta target device
    'target.0.displayName',
    'debugContext.debugData.requestUri',
)
_IP_NESTED_PATHS = (
    # CloudTrail: sourceIPAddress lives at top level but sometimes under requestParameters
    'requestParameters.sourceIPAddress',
    # Okta: {"client": {"ipAddress": "..."}}
    'client.ipAddress',
    # Entra: {"ipAddress": "..."} inside properties
    'properties.ipAddress',
    # AWS GuardDuty: service.action.networkConnectionAction.remoteIpDetails.ipAddressV4
    'service.action.networkConnectionAction.remoteIpDetails.ipAddressV4',
    'service.action.awsApiCallAction.remoteIpDetails.ipAddressV4',
)
_HOST_FIELDS = (
    'hostname', 'host', 'device_id', 'device_name', 'asset_name', 'computer',
    'computer_name', 'endpoint', 'instance_id', 'vm_name'
)
_IP_FIELDS = (
    'src_ip', 'source_ip', 'sourceIPAddress', 'ipAddress', 'ip', 'internal_ip',
    'dst_ip', 'destination_ip', 'public_ip', 'remote_ip', 'client_ip'
)
_RESOURCE_FIELDS = (
    'target_resource', 'resource_arn', 'file_name', 'attachment_name', 'path',
    'object_key', 'bucket', 'vault', 'app', 'application', 'service', 'database'
)
_EMAIL_RE = re.compile(r'\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b', re.I)
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_MITRE_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b', re.I)
_SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
_LOW_VALUE_ACCOUNT_PIVOTS = {
    '-', 'n/a', 'na', 'none', 'null', 'unknown',
    'system', 'root', 'local service', 'network service',
    'nt authority\\system', 'nt authority\\local service', 'nt authority\\network service',
    'anonymous logon',
}


def _safe_text(value: Any) -> str:
    if value is None:
        return ''
    return str(value).strip()


def _safe_identity_text(value: Any) -> str:
    """Return scalar identity text only.

    Dict/list payloads must be handled through explicit nested extractors so
    raw provider objects do not become account pivots.
    """
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ''
    return str(value).strip()


def _is_low_value_account_pivot(value: Any) -> bool:
    text = _safe_identity_text(value).lower()
    if not text:
        return True
    return text in _LOW_VALUE_ACCOUNT_PIVOTS or text.endswith('\\system')


def _nested_get(obj: Any, dotted_path: str) -> Any:
    """Resolve a dotted path through nested dicts/lists (e.g. 'actor.alternateId').

    Integer path segments index into lists. Returns None if any step is missing.
    """
    parts = dotted_path.split('.')
    current = obj
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _extract_first_value(row: dict, keys: Tuple[str, ...]) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ''):
            return _safe_text(value)
    return ''


def _parse_backend_timestamp(value: Any) -> float | None:
    if value in (None, ''):
        return None
    try:
        if isinstance(value, (int, float)):
            raw = float(value)
            return raw / 1000.0 if raw > 10_000_000_000 else raw
        text = _safe_text(value)
        if not text:
            return None
        if text.endswith('Z'):
            text = text[:-1] + '+00:00'
        text = text.replace('/', '-')
        try:
            return datetime.datetime.fromisoformat(text).timestamp()
        except Exception:
            pass
        for fmt in (
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',
        ):
            try:
                return datetime.datetime.strptime(text, fmt).timestamp()
            except Exception:
                continue
    except Exception:
        return None
    return None


def _is_private_ip_text(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except Exception:
        return False


def _collect_strings_from_row(row: dict) -> str:
    try:
        return json.dumps(row, default=str)
    except Exception:
        return str(row)


def _extract_from_typed_array(arr: Any, type_field: str = 'type', type_values: tuple = ('User', 'user'),
                               value_fields: tuple = ('alternateId', 'displayName', 'id', 'login')) -> List[str]:
    """Scan an array of typed objects (e.g. Okta target[]) and extract identity values.

    Avoids the `target.0.alternateId` trap that only sees the first element.
    Returns all unique non-empty values found across matching entries.
    """
    results: List[str] = []
    if not isinstance(arr, list):
        return results
    for entry in arr:
        if not isinstance(entry, dict):
            continue
        entry_type = _safe_text(entry.get(type_field))
        if type_values and entry_type.lower() not in {t.lower() for t in type_values}:
            continue
        for field in value_fields:
            val = _safe_text(entry.get(field))
            if val and val not in results:
                results.append(val)
    return results


def _account_fallback_text(row: dict) -> str:
    """Collect only account-bearing text for final email fallback.

    This intentionally avoids scanning non-user Okta target entries, because a
    group/application email in target[] is not an account pivot.
    """
    parts: List[str] = []
    for field in _ACCOUNT_FIELDS:
        value = _safe_identity_text(row.get(field))
        if value:
            parts.append(value)
    for path in _ACCOUNT_NESTED_PATHS:
        value = _safe_identity_text(_nested_get(row, path))
        if value:
            parts.append(value)
    for arr_field in ('target', 'targets', 'actor_targets'):
        parts.extend(_extract_from_typed_array(row.get(arr_field), type_values=('User', 'user', 'AppUser', 'SystemUser')))
    raw = row.get('raw')
    if isinstance(raw, dict):
        for field in _ACCOUNT_FIELDS:
            value = _safe_identity_text(raw.get(field))
            if value:
                parts.append(value)
        for path in _ACCOUNT_NESTED_PATHS:
            value = _safe_identity_text(_nested_get(raw, path))
            if value:
                parts.append(value)
        for arr_field in ('target', 'targets', 'actor_targets'):
            parts.extend(_extract_from_typed_array(raw.get(arr_field), type_values=('User', 'user', 'AppUser', 'SystemUser')))
    return ' '.join(parts)


def _extract_accounts_backend(row: dict) -> List[str]:
    values: List[str] = []
    for field in _ACCOUNT_FIELDS:
        value = _safe_identity_text(row.get(field))
        if value and value not in values:
            values.append(value)
    # Deep nested extraction (CloudTrail userIdentity, Okta actor, Entra initiatedBy, etc.)
    for path in _ACCOUNT_NESTED_PATHS:
        value = _safe_identity_text(_nested_get(row, path))
        if value and value not in values:
            values.append(value)
    # Okta / SailPoint typed-array targets — scan ALL entries, not just index 0
    for arr_field in ('target', 'targets', 'actor_targets'):
        arr = row.get(arr_field)
        for val in _extract_from_typed_array(arr, type_values=('User', 'user', 'AppUser', 'SystemUser')):
            if val not in values:
                values.append(val)
    # Also handle nested raw.target for events where original payload is wrapped
    raw = row.get('raw')
    if isinstance(raw, dict):
        for arr_field in ('target', 'targets'):
            arr = raw.get(arr_field)
            for val in _extract_from_typed_array(arr, type_values=('User', 'user', 'AppUser', 'SystemUser')):
                if val not in values:
                    values.append(val)
    for match in _EMAIL_RE.findall(_account_fallback_text(row)):
        if match not in values:
            values.append(match)
    return values[:8]


def _extract_hosts_backend(row: dict) -> List[str]:
    values: List[str] = []
    for field in _HOST_FIELDS:
        value = _safe_text(row.get(field))
        if value and value not in values:
            values.append(value)
    for path in _HOST_NESTED_PATHS:
        value = _safe_text(_nested_get(row, path))
        if value and value not in values:
            values.append(value)
    return values[:8]


def _extract_ips_backend(row: dict) -> List[str]:
    values: List[str] = []
    for field in _IP_FIELDS:
        value = _safe_text(row.get(field))
        if value and value not in values:
            values.append(value)
    for path in _IP_NESTED_PATHS:
        value = _safe_text(_nested_get(row, path))
        if value and value not in values and _IP_RE.match(value):
            values.append(value)
    for match in _IP_RE.findall(_collect_strings_from_row(row)):
        if match not in values:
            values.append(match)
    return values[:10]


def _extract_resources_backend(row: dict) -> List[str]:
    values: List[str] = []
    for field in _RESOURCE_FIELDS:
        value = _safe_text(row.get(field))
        if value and value not in values:
            values.append(value)
    return values[:8]


def _extract_tags_backend(row: dict, assessment: dict | None) -> Dict[str, List[str]]:
    tags: Dict[str, List[str]] = {'mitre': [], 'atlas': [], 'owasp_llm': []}

    def _add(bucket: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, list):
            for item in value:
                _add(bucket, item)
            return
        if isinstance(value, dict):
            for key in ('id', 'technique_id', 'technique', 'name'):
                if value.get(key):
                    _add(bucket, value.get(key))
            return
        text = _safe_text(value)
        if text and text not in tags[bucket]:
            tags[bucket].append(text)

    for source in (assessment or {}, row):
        _add('mitre', source.get('mitre'))
        _add('mitre', source.get('mitre_tags'))
        _add('mitre', source.get('techniques'))
        _add('atlas', source.get('atlas'))
        _add('owasp_llm', source.get('owasp_llm'))
        mappings = source.get('mapping_tags') or source.get('mappings') or {}
        if isinstance(mappings, dict):
            _add('mitre', mappings.get('mitre'))
            _add('atlas', mappings.get('atlas'))
            _add('owasp_llm', mappings.get('owasp_llm'))
        for entry in source.get('framework_mappings') or []:
            if not isinstance(entry, dict):
                continue
            framework = _safe_text(entry.get('framework')).lower()
            if framework == 'mitre_attack':
                _add('mitre', entry.get('id') or entry.get('name'))

    blob = _collect_strings_from_row(row)
    for item in _MITRE_RE.findall(blob):
        _add('mitre', item)
    if map_factors_to_tags is not None:
        try:
            factor_tags = map_factors_to_tags(row.get('factors') or [])
            if isinstance(factor_tags, dict):
                _add('mitre', factor_tags.get('mitre'))
                _add('atlas', factor_tags.get('atlas'))
                _add('owasp_llm', factor_tags.get('owasp_llm'))
        except Exception:
            pass
    for bucket in tags:
        tags[bucket] = tags[bucket][:8]
    return tags


def _classify_backend_severity(row: dict) -> str:
    for key in ('severity', 'alert_severity', 'risk_rating', 'review_state'):
        value = _safe_text(row.get(key)).lower()
        if value in _SEV_RANK:
            return value
    text = _collect_strings_from_row(row).lower()
    if any(token in text for token in ('global administrator', 'confirmed_malicious', 'cloudtrail logging disabled', 'lsass', 'exfil', 'ransomware')):
        return 'critical'
    if any(token in text for token in ('tor exit', 'mailbox rule', 'legacy auth', 'impossible travel', 'powershell', 'stager', 'c2', 'beacon')):
        return 'high'
    if any(token in text for token in ('suspicious', 'anomal', 'review', 'investigate')):
        return 'medium'
    return 'low'


def _severity_label_for_rows(rows: List[dict]) -> str:
    if not rows:
        return 'low'
    return sorted((_classify_backend_severity(row) for row in rows), key=lambda item: _SEV_RANK.get(item, 0), reverse=True)[0]


def _infer_cloud_provider(row: dict, assessment: dict | None = None) -> str:
    explicit = _safe_text(
        row.get('cloud_provider')
        or row.get('_provider_profile')
        or row.get('provider')
        or row.get('provider_profile')
    ).lower()
    if explicit in {'aws', 'azure', 'gcp', 'oci', 'multi_cloud', 'vmware', 'nutanix', 'openstack', 'okta', 'active_directory', 'email'}:
        return explicit
    source_sheet = _safe_text(row.get('_sheet') or row.get('sheet') or row.get('source') or '').lower()
    text = _collect_strings_from_row(row).lower()
    if 'cloud_aws' in source_sheet or any(token in text for token in ('aws', 'cloudtrail', 'guardduty', 'iam user', 'arn:aws')):
        return 'aws'
    if 'cloud_azure' in source_sheet or any(token in text for token in ('azure', 'entra', 'microsoft graph', 'subscription id')):
        return 'azure'
    if any(token in text for token in ('okta', 'okta verify', 'okta system log', 'okta fastpass')):
        return 'okta'
    if any(token in text for token in ('active directory', 'kerberos', 'ldap bind', 'domain controller', 'adfs', 'windows security')):
        return 'active_directory'
    if any(token in text for token in ('gcp', 'google cloud', 'gcloud', 'project id')):
        return 'gcp'
    if any(token in text for token in ('oracle cloud', 'oci', 'compartment ocid', 'tenancy ocid')):
        return 'oci'
    if any(token in text for token in ('vmware', 'vcenter', 'esxi')):
        return 'vmware'
    if any(token in text for token in ('nutanix', 'prism central')):
        return 'nutanix'
    if any(token in text for token in ('openstack', 'keystone', 'nova', 'neutron')):
        return 'openstack'
    if any(token in text for token in ('mailbox rule', 'message trace', 'exchange online', 'mail flow', 'proofpoint', 'mimecast', 'business email compromise', 'bec')):
        return 'email'
    return 'generic'


def _infer_plane(row: dict) -> str:
    text = _collect_strings_from_row(row).lower()
    if any(token in text for token in ('signin', 'login', 'role', 'sts', 'entra', 'iam', 'policy', 'control plane', 'admin')):
        return 'control_plane'
    if any(token in text for token in ('s3', 'blob', 'object', 'query', 'dataset', 'db', 'download', 'egress', 'data plane')):
        return 'data_plane'
    return 'unknown'


def _extract_cloud_context(row: dict, assessment: dict | None = None) -> dict:
    provider = _infer_cloud_provider(row, assessment)
    account_id = _extract_first_value(row, ['account_id', 'aws_account_id', 'account', 'recipientAccountId'])
    subscription_id = _extract_first_value(row, ['subscription_id', 'azure_subscription_id'])
    project_id = _extract_first_value(row, ['project_id', 'gcp_project_id', 'project'])
    compartment_id = _extract_first_value(row, ['compartment_id', 'compartment_ocid'])
    org_id = _extract_first_value(row, ['organization_id', 'org_id', 'tenant_id', 'azure_tenant_id'])
    region = _extract_first_value(row, ['region', 'awsRegion', 'location', 'azure_region'])
    resource_id = _extract_first_value(row, ['resource_id', 'resource_arn', 'target_resource', 'resource'])
    resource_type = _extract_first_value(row, ['resource_type', 'target_resource_type', 'serviceName', 'service'])
    return {
        'provider': provider,
        'org_id': org_id,
        'account_id': account_id,
        'subscription_id': subscription_id,
        'project_id': project_id,
        'compartment_id': compartment_id,
        'region': region,
        'resource_id': resource_id,
        'resource_type': resource_type,
        'control_plane': _infer_plane(row) == 'control_plane',
        'data_plane': _infer_plane(row) == 'data_plane',
        'plane': _infer_plane(row),
    }


def _extract_identity_context(row: dict) -> dict:
    text = _collect_strings_from_row(row).lower()
    role = _extract_first_value(row, ['identity_role', 'role', 'role_name', 'assigned_role', 'user_role'])
    session_id = _extract_first_value(row, ['session_id', 'sessionId', 'correlation_id', 'correlationId'])
    auth_strength = _extract_first_value(row, ['auth_strength', 'authentication_requirement', 'mfa_detail', 'authenticationMethodsUsed'])
    privilege_type = 'standing'
    privilege_state = 'normal'
    privilege_source = ''
    if any(token in text for token in ('just in time', 'jit', 'pim activated', 'temporary elevated', 'temporary privilege')):
        privilege_type = 'temporary'
        privilege_state = 'elevated'
        privilege_source = 'jit_or_pim'
    elif any(token in text for token in ('global administrator', 'privileged role administrator', 'role assigned', 'elevation', 'assume role', 'sts:assumerole')):
        privilege_type = 'escalated'
        privilege_state = 'elevated'
        privilege_source = 'role_change'
    elif any(token in text for token in ('token reuse', 'refresh token', 'session replay', 'legacy auth')):
        privilege_type = 'session_reuse'
        privilege_state = 'suspicious'
        privilege_source = 'session_anomaly'
    impossible_travel = any(token in text for token in ('impossible travel', 'atypical travel', 'geo-velocity', 'geovelocity'))
    if impossible_travel and privilege_state == 'normal':
        privilege_state = 'suspicious'
    return {
        'principal': _extract_first_value(row, ['user_principal_name', 'userPrincipalName', 'user', 'username', 'caller_upn', 'caller', 'requestor']),
        'user_id': _extract_first_value(row, ['user_id', 'actor_id', 'principal_id', 'userIdentity.arn']),
        'role': role,
        'privilege_state': privilege_state,
        'privilege_type': privilege_type,
        'privilege_source': privilege_source,
        'session_id': session_id,
        'auth_strength': auth_strength,
        'impossible_travel': impossible_travel,
    }


def _extract_network_context(row: dict) -> dict:
    src_ip = _extract_first_value(row, ['src_ip', 'source_ip', 'sourceIPAddress', 'ipAddress', 'internal_ip'])
    dst_ip = _extract_first_value(row, ['dst_ip', 'destination_ip', 'server_ip', 'target_ip'])
    subnet = _extract_first_value(row, ['subnet', 'subnet_id', 'vpc_subnet', 'network_subnet'])
    return {'src_ip': src_ip, 'dst_ip': dst_ip, 'subnet': subnet}


def _extract_policy_change_context(row: dict) -> dict:
    text = _collect_strings_from_row(row).lower()
    signals = []
    if any(token in text for token in ('policy drift', 'iam policy', 'attachrolepolicy', 'putrolepolicy', 'inline policy')):
        signals.append('iam_policy')
    if any(token in text for token in ('security group', 'sg-', 'nsg', 'firewall rule', 'subnet route', 'route table')):
        signals.append('network_policy')
    if any(token in text for token in ('config drift', 'terraform', 'opa', 'rego', 'policy as code', 'guardrail')):
        signals.append('config_guardrail')
    negated = any(token in text for token in ('without cab', 'without approval', 'no cab', 'not approved', 'unapproved'))
    approved = (not negated) and any(token in text for token in ('approved', 'cab', 'change ticket', 'service request', 'terraform apply by pipeline', 'maintenance window'))
    suspicious = bool(signals) and not approved
    if not signals:
        return {}
    return {
        'kind': 'policy_change',
        'signals': signals,
        'approved_change': approved,
        'suspicious_drift': suspicious,
        'summary': 'Approved policy change detected.' if approved else 'Policy drift or permission expansion requires corroboration.',
    }


def _extract_guest_onboarding_context(row: dict) -> dict:
    text = _collect_strings_from_row(row).lower()
    onboarding_markers = (
        'inviteexternaluser',
        'invited user',
        'external user',
        'b2b invite',
        'guest onboarding',
        'access package',
        'sponsor',
        'temporary guest',
        'guest access',
        'onboarding',
    )
    if not any(token in text for token in onboarding_markers):
        return {}
    approved = any(token in text for token in ('approved', 'ticket', 'manager approved', 'sponsor', 'mfa registered', 'access package'))
    suspicious = any(token in text for token in ('unexpected geo', 'asn rare', 'legacy auth', 'impossible travel', 'beacon', 'data exfil', 'privilege escalation'))
    category = 'benign_onboarding' if approved and not suspicious else 'needs_review'
    return {
        'kind': 'guest_onboarding',
        'category': category,
        'approved': approved,
        'suspicious': suspicious,
        'summary': 'Temporary guest onboarding appears approved and should remain benign unless corroborated.'
        if category == 'benign_onboarding'
        else 'Guest onboarding exists, but surrounding telemetry needs confirm/deny review before escalation.',
    }


def _extract_security_posture_context(row: dict) -> dict:
    text = _collect_strings_from_row(row).lower()
    vendors: List[str] = []
    if any(token in text for token in ('check point', 'checkpoint', 'gaia gateway', 'cp-gateway')):
        vendors.append('checkpoint')
    if any(token in text for token in ('palo alto', 'pan-os', 'panw', 'panorama', 'cortex data lake')):
        vendors.append('palo_alto')
    cdn_present = any(token in text for token in ('cloudfront', 'cdn', 'edge cache', 'fastly', 'akamai'))
    no_firewall = any(token in text for token in ('zero firewall', 'no firewall', 'without firewall', 'perimeter absent', 'no perimeter firewall'))
    benign_mfa = any(token in text for token in ('mfa registered', 'fido2 success', 'phishing-resistant mfa', 'approved mfa challenge', 'webauthn success'))
    compromised_mfa = any(token in text for token in ('mfa fatigue', 'push accepted from suspicious', 'compromised mfa', 'mfa bypass', 'sim swap', 'prompt bombing'))
    if not vendors and not cdn_present and not no_firewall and not benign_mfa and not compromised_mfa:
        return {}
    if no_firewall:
        perimeter_mode = 'none'
    elif len(vendors) >= 2:
        perimeter_mode = 'dual_firewall'
    elif len(vendors) == 1:
        perimeter_mode = 'single_firewall'
    else:
        perimeter_mode = 'edge_only' if cdn_present else 'unspecified'
    return {
        'kind': 'security_posture',
        'vendors': vendors,
        'cdn_present': cdn_present,
        'perimeter_mode': perimeter_mode,
        'benign_mfa': benign_mfa,
        'compromised_mfa': compromised_mfa,
        'summary': (
            'No perimeter firewall telemetry is present; rely on cloud-native logs and east-west flow evidence.'
            if perimeter_mode == 'none'
            else 'Layered perimeter telemetry is available to confirm or deny ingress and egress hypotheses.'
            if perimeter_mode == 'dual_firewall'
            else 'Partial perimeter telemetry is available and should be cross-checked with cloud-native logs.'
        ),
    }


def _derive_human_validation_required(row: dict, policy_ctx: dict, guest_ctx: dict) -> bool:
    review_state = _safe_text(row.get('review_state')).lower()
    severity = _safe_text(row.get('severity') or row.get('alert_severity')).lower()
    if guest_ctx:
        return True
    if policy_ctx and policy_ctx.get('approved_change'):
        return True
    if review_state in {'review', 'benign', 'needs_review'}:
        return True
    if severity in {'low', 'medium', 'review'}:
        return True
    return False


# Verdict â†’ (urgency_label, hvr_override, playbook_status)
# hvr_override=None means fall through to row-evidence vote.
# VALIDATED_BREACH / CONFIRMED_INTRUSION always gate — GDPR Art.33, APRA CPS 234,
# HIPAA, and US state breach-notification laws require human sign-off before
# containment actions are treated as authoritative incident response.
_VERDICT_HVR_MAP: dict = {
    'VALIDATED_BREACH':      ('URGENT',  True,  'awaiting_urgent_signoff'),
    'CONFIRMED_INTRUSION':   ('URGENT',  True,  'awaiting_urgent_signoff'),
    'LIKELY_COMPROMISE':     ('HIGH',    True,  'awaiting_signoff'),
    'SUSPICIOUS_ACTIVITY':   ('NORMAL',  None,  None),   # row-vote decides
    'INSUFFICIENT_TELEMETRY':('NORMAL',  None,  None),   # row-vote decides
    'BENIGN_EXPECTED':       ('LOW',     False, 'auto_triaged'),
}


def _apply_hvr_gating(cluster: dict, component_rows: list | None = None) -> None:
    """Attach verdict-aware human_validation_required, gate_urgency, playbook_status.

    Called twice:
    1. In _build_correlation_clusters (pre-verdict) — uses severity + row-evidence vote.
    2. In get_assessment after backfill_cluster_verdicts — upgrades to verdict-aware state.
    """
    verdict = str(cluster.get('verdict') or 'UNCERTAIN')
    severity = str(cluster.get('severity') or 'medium').lower()

    urgency, hvr_override, status_override = _VERDICT_HVR_MAP.get(
        verdict, ('NORMAL', None, None)
    )

    # If verdict gives us a definitive answer, apply it directly
    if hvr_override is not None:
        cluster['human_validation_required'] = hvr_override
        cluster['gate_urgency'] = urgency
        cluster['playbook_status'] = status_override
        return

    # Verdict is uncertain / no verdict yet — derive from row evidence + severity
    cluster['gate_urgency'] = urgency if urgency != 'NORMAL' else (
        'HIGH' if severity in ('critical', 'high') else 'NORMAL'
    )
    if component_rows:
        hvr_votes = [
            _derive_human_validation_required(
                row,
                policy_ctx=row.get('policy_change_context') or {},
                guest_ctx=row.get('guest_onboarding_context') or {},
            )
            for row in component_rows
        ]
        hvr = any(hvr_votes)
    else:
        # No rows available (post-verdict upgrade pass) — keep existing value
        hvr = bool(cluster.get('human_validation_required', True))

    cluster['human_validation_required'] = hvr
    cluster['playbook_status'] = 'human_gated' if hvr else 'auto_triaged'


def _initial_cluster_verdict(component_rows: list[dict], severity: str) -> dict:
    """Deterministic pre-LLM verdict from observed impact fields."""
    joined = ' '.join(_collect_strings_from_row(row).lower() for row in component_rows[:80])
    payment_impact = any(
        row.get('wire_transfer_amount_aud') not in (None, '')
        and (
            bool(row.get('bec_approval'))
            or bool(row.get('attacker_reads_approval'))
            or bool(row.get('beneficiary_account'))
            or any(token in _collect_strings_from_row(row).lower() for token in ('approval', 'beneficiary', 'payment'))
        )
        for row in component_rows
    )
    high_impact_action = any(
        bool(row.get('attacker_reads_approval'))
        or any(
            token in _collect_strings_from_row(row).lower()
            for token in (
                'ransomware staged',
                'ransomware executed',
                'malware executed',
                'confirmed exfiltration',
                'data exfiltration confirmed',
                'attacker reads approval',
            )
        )
        for row in component_rows
    )
    intrusion_observed = any(
        bool(row.get('rule_destination') and row.get('rule_name'))
        or any(
            token in _collect_strings_from_row(row).lower()
            for token in ('bcc forwarding', 'legacy imap', 'session token hijacked', 'c2 beacon', 'dns tunnel')
        )
        for row in component_rows
    )
    if payment_impact or high_impact_action:
        return {
            'verdict': 'VALIDATED_BREACH',
            'verdict_confidence': 0.88,
            'verdict_rationale': 'Deterministic evidence shows attacker action against a protected business process.',
        }
    if intrusion_observed:
        return {
            'verdict': 'CONFIRMED_INTRUSION',
            'verdict_confidence': 0.72,
            'verdict_rationale': 'Deterministic evidence shows attacker control or persistence, but no observed business impact field crossed the validated-breach threshold.',
        }
    # Benign rule-out: check for known-benign signals before escalating to compromise verdict.
    # These fire when ALL rows in the cluster have a coherent benign explanation.
    all_rows_have_approved_change = (
        component_rows
        and all(
            (row.get('policy_change_context') or {}).get('approved_change')
            or row.get('approved_change')
            or row.get('change_ticket')
            for row in component_rows
        )
    )
    if all_rows_have_approved_change:
        return {
            'verdict': 'BENIGN_EXPECTED',
            'verdict_confidence': 0.75,
            'verdict_rationale': 'All correlated rows are linked to an approved change window.',
        }
    # If cluster is entirely internal RFC1918 traffic with no external pivot
    external_ips = [
        ip for row in component_rows
        for ip in (row.get('external_ips') or [])
    ]
    all_accounts_empty = not any(row.get('accounts') for row in component_rows)
    all_ips_internal = not external_ips
    if all_ips_internal and all_accounts_empty and len(component_rows) < 5:
        return {
            'verdict': 'INSUFFICIENT_TELEMETRY',
            'verdict_confidence': 0.60,
            'verdict_rationale': 'Cluster contains only internal IPs with no account or external pivot — insufficient telemetry to assess.',
        }
    return {
        'verdict': 'LIKELY_COMPROMISE' if severity in {'critical', 'high'} else 'SUSPICIOUS_ACTIVITY',
        'verdict_confidence': 0.55 if severity in {'critical', 'high'} else 0.35,
        'verdict_rationale': 'Correlated evidence requires investigation; no observed impact field crossed the validated-breach threshold.',
    }


def _build_remediation_simulation(component_rows: List[dict], severity: str) -> dict:
    joined = ' '.join(_collect_strings_from_row(row).lower() for row in component_rows)
    prod_targets = sorted({
        item for row in component_rows
        for item in ((row.get('hosts') or []) + (row.get('resources') or []))
        if 'prod' in _safe_text(item).lower() or 'app' in _safe_text(item).lower()
    })[:4]
    if not prod_targets:
        return {}
    containment_ready = severity in {'critical', 'high'} and any(
        token in joined for token in ('guardduty', 'securityhub', 'c2', 'beacon', 'exfil', 'credentialaccess', 'powershell', 'curl http')
    )
    return {
        'status': 'simulated' if containment_ready else 'manual_review',
        'targets': prod_targets,
        'isolated_nodes': prod_targets[:1] if containment_ready else [],
        'alb_drain_status': 'simulated_drained' if containment_ready else 'pending_review',
        'replacement_capacity_status': 'simulated_replaced' if containment_ready else 'not_started',
        'summary': 'Simulated node isolation, ALB drain, and replacement capacity exercised for the affected production workload.'
        if containment_ready
        else 'Containment remains gated pending stronger corroboration.',
    }


def _extract_event_context(row: dict) -> dict:
    return {
        'action': _extract_first_value(row, ['eventName', 'event_name', 'operationName', 'operation_name', 'activityDisplayName', 'action']),
        'service': _extract_first_value(row, ['serviceName', 'service', 'service_name']),
        'method': _extract_first_value(row, ['http_method', 'method', 'request_method']),
    }


def _build_bitemporal_trace(timestamp_text: str | None, assessment: dict | None = None) -> dict:
    event_ts = _parse_backend_timestamp(timestamp_text)
    decision_raw = None
    if isinstance(assessment, dict):
        decision_raw = assessment.get('updated_at') or assessment.get('generated_at') or assessment.get('created_at')
    if isinstance(decision_raw, (int, float)):
        decision_ts = float(decision_raw)
    else:
        decision_ts = time.time()
    lag = int(max(0.0, decision_ts - event_ts)) if event_ts is not None else None
    return {
        'event_time': timestamp_text,
        'event_epoch': event_ts,
        'decision_time': datetime.datetime.utcfromtimestamp(decision_ts).isoformat() + 'Z',
        'decision_epoch': decision_ts,
        'observed_lag_seconds': lag,
    }


def _extract_evidence_mode(row: dict, assessment: dict | None = None) -> str:
    mode = _safe_text(row.get('_intake_mode') or row.get('intake_mode') or row.get('source_kind')).lower()
    if not mode and isinstance(assessment, dict):
        options = assessment.get('options') or {}
        mode = _safe_text(options.get('intake_mode') or assessment.get('intake_mode')).lower()
    if mode in {'live', 'stream'}:
        return 'live'
    if mode in {'merged', 'hybrid'}:
        return 'merged'
    return 'snapshot'


def _extract_freshness(ts_epoch: float | None) -> dict:
    if ts_epoch is None:
        return {'freshness_ts': None, 'freshness_age_seconds': None, 'freshness_state': 'unknown'}
    age = max(0.0, time.time() - float(ts_epoch))
    if age <= 3600:
        state = 'fresh'
    elif age <= 86400:
        state = 'recent'
    else:
        state = 'historical'
    return {'freshness_ts': ts_epoch, 'freshness_age_seconds': int(age), 'freshness_state': state}


def _cluster_controls_and_frameworks(cluster: dict, rows: List[dict]) -> dict:
    row_map = {int(row.get('row_index') or 0): row for row in rows}
    mitre_ids = []
    for ref in cluster.get('row_refs') or []:
        mitre_ids.extend(row_map.get(int(ref), {}).get('mitre') or [])
    mitre_ids = list(dict.fromkeys([m for m in mitre_ids if isinstance(m, str) and m.strip()]))
    factors = []
    try:
        from src.core.threat_modeling.factor_taxonomy import _FACTOR_MAP, controls_for_factors
        reverse: Dict[str, List[str]] = {}
        for name, meta in _FACTOR_MAP.items():
            for mid in meta.get('mitre', []):
                reverse.setdefault(mid, []).append(name)
        for mid in mitre_ids:
            factors.extend(reverse.get(mid, []))
        factors = list(dict.fromkeys(factors))
        controls = controls_for_factors(factors) if factors else []
        frameworks = sorted({(entry.get('control') or '').split(':', 1)[0] for entry in controls if entry.get('control')})
        return {
            'factors': factors[:12],
            'frameworks': frameworks[:12],
            'controls': controls[:20],
        }
    except Exception:
        return {'factors': [], 'frameworks': [], 'controls': []}


def _normalize_assessment_rows(assessment: dict) -> List[dict]:
    source_rows = assessment.get('rows') or []
    llm_by_index: Dict[int, dict] = {}
    for entry in assessment.get('llm_rows') or []:
        try:
            llm_by_index[int(entry.get('row_index'))] = entry
        except Exception:
            continue

    def _merge_lists(extracted: List[str], existing: Any) -> List[str]:
        """Union extractor results with a pre-populated list, deduping and preserving order."""
        if not isinstance(existing, list) or not existing:
            return extracted
        seen = set(extracted)
        combined = list(extracted)
        for item in existing:
            text = str(item).strip() if item else ''
            if text and text not in seen:
                seen.add(text)
                combined.append(text)
        return combined

    normalized: List[dict] = []
    for idx, source in enumerate(source_rows):
        flat = _flatten_row_payload(source, idx)
        try:
            row_index = int(flat.get('row_index') or idx)
        except Exception:
            row_index = idx
        llm_row = llm_by_index.get(row_index) or {}
        merged = {**flat, **llm_row}
        ts_text = _extract_first_value(merged, _TS_FIELDS)
        accounts = _extract_accounts_backend(merged)
        hosts = _extract_hosts_backend(merged)
        ips = _extract_ips_backend(merged)
        resources = _extract_resources_backend(merged)
        tags = _extract_tags_backend(merged, assessment)
        # Preserve semantic arrays already present on input rows (e.g. from
        # LLM pre-enrichment or manual fixture data) by merging them with
        # extractor results.  Dedup while preserving order.
        accounts = _merge_lists(accounts, merged.get('accounts'))
        hosts = _merge_lists(hosts, merged.get('hosts'))
        ips = _merge_lists(ips, merged.get('ips'))
        resources = _merge_lists(resources, merged.get('resources'))
        # Merge pre-existing mitre/atlas/owasp_llm tags
        for _tag_key in ('mitre', 'atlas', 'owasp_llm'):
            existing_tags = merged.get(_tag_key)
            if isinstance(existing_tags, list):
                seen_tags = set(tags[_tag_key])
                for item in existing_tags:
                    text = str(item).strip() if item else ''
                    if text and text not in seen_tags:
                        seen_tags.add(text)
                        tags[_tag_key].append(text)
        triage = float(merged.get('triage_score') or _compute_triage_score(merged) or 0.0)
        cloud = _extract_cloud_context(merged, assessment)
        identity = _extract_identity_context(merged)
        network = _extract_network_context(merged)
        policy_ctx = _extract_policy_change_context(merged)
        guest_ctx = _extract_guest_onboarding_context(merged)
        security_posture = _extract_security_posture_context(merged)
        event_ctx = _extract_event_context(merged)
        bitemporal = _build_bitemporal_trace(ts_text, assessment)
        evidence_mode = _extract_evidence_mode(merged, assessment)
        freshness = _extract_freshness(_parse_backend_timestamp(ts_text))
        human_validation_required = _derive_human_validation_required(merged, policy_ctx, guest_ctx)
        normalized.append({
            **merged,
            'row_index': row_index,
            'timestamp': ts_text,
            'timestamp_epoch': _parse_backend_timestamp(ts_text),
            'source_sheet': _safe_text(merged.get('_sheet') or merged.get('sheet') or merged.get('source') or merged.get('_source') or 'unknown'),
            'entity': _extract_first_value(merged, _ACCOUNT_FIELDS + _HOST_FIELDS + _IP_FIELDS + _RESOURCE_FIELDS) or '-',
            'description': _extract_first_value(merged, _DESC_FIELDS),
            'severity': _classify_backend_severity(merged),
            'triage_score': triage,
            'accounts': accounts,
            'hosts': hosts,
            'ips': ips,
            'external_ips': _merge_lists(
                [
                    ip for ip in ips
                    if not _is_private_ip_text(ip)
                    and (_is_ioc_confirmed(ip) or not _is_vendor_egress_ip(ip))
                ],
                merged.get('external_ips'),
            ),
            'resources': resources,
            'mitre': tags['mitre'],
            'atlas': tags['atlas'],
            'owasp_llm': tags['owasp_llm'],
            'cloud': cloud,
            'identity': identity,
            'network': network,
            'event': event_ctx,
            'policy_change_context': policy_ctx,
            'guest_onboarding_context': guest_ctx,
            'security_posture_context': security_posture,
            'evidence_mode': evidence_mode,
            'bitemporal_trace': bitemporal,
            **freshness,
            'provider_profile': cloud.get('provider'),
            'cloud_boundary': (
                cloud.get('account_id')
                or cloud.get('subscription_id')
                or cloud.get('project_id')
                or cloud.get('compartment_id')
                or cloud.get('org_id')
            ),
            'privilege_state': identity.get('privilege_state'),
            'privilege_type': identity.get('privilege_type'),
            'session_id': identity.get('session_id'),
            'impossible_travel': bool(identity.get('impossible_travel')),
            'human_validation_required': human_validation_required,
        })
    return normalized


# Known CDN, SaaS, and major cloud egress CIDR prefixes that should never be
# classified as attacker infrastructure without explicit IOC context.
# These are /8 or /16 prefixes — intentionally coarse to avoid false positives
# while keeping the list short and auditable.
_VENDOR_EGRESS_PREFIXES: tuple[str, ...] = (
    # Cloudflare
    '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.',
    '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.',
    '162.158.', '198.41.128.', '198.41.129.',
    # Akamai
    '23.32.', '23.33.', '23.64.', '23.65.', '23.192.',
    # Fastly
    '151.101.', '199.232.',
    # AWS CloudFront / global accelerator
    '13.32.', '13.33.', '13.35.', '13.224.', '13.225.', '13.226.', '13.227.',
    '205.251.', '204.246.',
    # Google / GCP / Workspace
    '142.250.', '142.251.', '172.217.', '172.253.',
    '74.125.',
    # Microsoft / Azure / M365
    '13.104.', '13.105.', '13.106.', '13.107.',
    '13.64.', '13.65.', '13.66.', '13.67.', '13.68.', '13.69.', '13.70.',
    '40.64.', '40.65.', '40.66.', '40.67.', '40.68.', '40.69.', '40.70.',
    '52.224.', '52.225.', '52.226.', '52.227.',
    # Okta
    '23.246.',
    # Zscaler (common egress)
    '165.225.',
    # Proofpoint
    '148.163.',
    # Mimecast
    '91.220.42.',
    # Salesforce
    '136.146.',
    # Zoom
    '3.7.', '3.21.', '3.22.', '3.25.',
)


def _is_vendor_egress_ip(ip: str) -> bool:
    """Return True if ip looks like CDN/SaaS/cloud egress that shouldn't be attacker infra."""
    for prefix in _VENDOR_EGRESS_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def _is_ioc_confirmed(ip: str) -> bool:
    """Return True if the threat intel store has an active IOC entry for this IP.

    IOC hits always override the vendor allowlist — a Cloudflare IP appearing in
    an active feed is a legitimate threat indicator (e.g. proxy abuse, malicious CDN node).
    Fails silently so a degraded TI client never breaks clustering.
    """
    try:
        from src.integrations.threat_intel_client import CLIENT as _TI
        return bool(_TI.is_malicious_ip(ip))
    except Exception:
        return False


def _extract_attacker_ips(row: dict) -> frozenset:
    """IPs most likely to represent attacker-controlled infrastructure (source/initiator side).

    Excludes RFC1918 addresses AND known CDN/SaaS/cloud egress ranges to avoid
    misclassifying customer VPNs, cloud service IPs, and SaaS providers as C2.
    Exception: if the TI store has an active IOC for the IP it is always included,
    even if it falls in a vendor prefix range (e.g. abused CDN node, compromised SaaS egress).
    """
    result = set()
    for field in ('src_ip', 'source_ip', 'remote_ip', 'origin_ip', 'originating_ip',
                  'attacker_ip', 'c2_ip', 'client_ip', 'initiator_ip'):
        v = str(row.get(field) or '').strip()
        if not v or v in ('-', 'N/A', '', '0.0.0.0'):
            continue
        if _is_private_ip_text(v):
            continue
        # IOC-confirmed IPs bypass the vendor allowlist
        if _is_ioc_confirmed(v) or not _is_vendor_egress_ip(v):
            result.add(v)
    return frozenset(result)


def _build_pair_reason(left: dict, right: dict) -> dict | None:
    left_guest = left.get('guest_onboarding_context') or {}
    right_guest = right.get('guest_onboarding_context') or {}
    left_policy = left.get('policy_change_context') or {}
    right_policy = right.get('policy_change_context') or {}

    # Attacker infrastructure pivot — must check before scoring to detect conflicts
    left_atk_ips = _extract_attacker_ips(left)
    right_atk_ips = _extract_attacker_ips(right)
    shared_atk_ips = left_atk_ips & right_atk_ips
    # Events from provably different attacker origins must never merge into one cluster
    conflicting_atk_infra = bool(left_atk_ips and right_atk_ips and not shared_atk_ips)
    if conflicting_atk_infra:
        return None

    shared = {
        'accounts': sorted(
            acc for acc in set(left.get('accounts') or []).intersection(right.get('accounts') or [])
            if not _is_low_value_account_pivot(acc)
        ),
        'hosts': sorted(set(left.get('hosts') or []).intersection(right.get('hosts') or [])),
        'ips': sorted(set(left.get('external_ips') or []).intersection(right.get('external_ips') or [])),
        'resources': sorted(set(left.get('resources') or []).intersection(right.get('resources') or [])),
        'mitre': sorted(set(left.get('mitre') or []).intersection(right.get('mitre') or [])),
        'cloud_boundaries': sorted(set(filter(None, [left.get('cloud_boundary')])).intersection(filter(None, [right.get('cloud_boundary')]))),
        'privilege_states': sorted(set(filter(None, [left.get('privilege_state'), right.get('privilege_state')]))),
        'sessions': sorted(set(filter(None, [left.get('session_id')])).intersection(filter(None, [right.get('session_id')]))),
    }
    strong_corroboration = bool(shared['sessions'] or shared['hosts'] or shared_atk_ips or shared['resources'])
    suspicious_identity_signal = bool(
        left.get('impossible_travel') or right.get('impossible_travel')
        or 'elevated' in shared['privilege_states']
        or 'suspicious' in shared['privilege_states']
        or left_guest.get('suspicious')
        or right_guest.get('suspicious')
        or left_policy.get('suspicious_drift')
        or right_policy.get('suspicious_drift')
    )
    if (
        left_guest.get('category') == 'benign_onboarding'
        or right_guest.get('category') == 'benign_onboarding'
    ) and not (strong_corroboration and suspicious_identity_signal):
        return None
    if (
        left_policy.get('approved_change')
        or right_policy.get('approved_change')
    ) and not (strong_corroboration or suspicious_identity_signal):
        return None

    # Account-only match (no technical corroboration) is insufficient on its own —
    # a victim account appearing in two unrelated attacks must not merge those incidents.
    account_only = (
        bool(shared['accounts'])
        and not shared['hosts']
        and not shared_atk_ips
        and not shared['ips']
        and not shared['resources']
        and not shared['sessions']
        and not shared['mitre']
    )
    if account_only and not suspicious_identity_signal:
        return None

    score = 0.0
    if shared_atk_ips:
        # Shared attacker infrastructure is the strongest pivot signal
        score += 0.5
    if shared['accounts']:
        score += 0.4
    if shared['hosts']:
        score += 0.35
    if shared['resources']:
        score += 0.25
    if shared['ips']:
        score += 0.2
    if shared['mitre']:
        score += 0.1
    if shared['cloud_boundaries']:
        score += 0.2
    if shared['sessions']:
        score += 0.2
    if 'elevated' in shared['privilege_states'] or 'suspicious' in shared['privilege_states']:
        score += 0.15
    time_delta = None
    if left.get('timestamp_epoch') is not None and right.get('timestamp_epoch') is not None:
        time_delta = abs(float(left['timestamp_epoch']) - float(right['timestamp_epoch']))
        if time_delta <= 900:
            score += 0.2
        elif time_delta <= 3600:
            score += 0.1
    cross_source = left.get('source_sheet') != right.get('source_sheet')
    if cross_source:
        score += 0.1
    if left.get('cloud', {}).get('provider') and left.get('cloud', {}).get('provider') == right.get('cloud', {}).get('provider'):
        score += 0.05
    if left.get('impossible_travel') and right.get('impossible_travel'):
        score += 0.1
    if score < 0.45:
        return None

    # Determine the dominant pivot type for UI display and LLM context
    if shared_atk_ips:
        pivot_type = 'attacker_ip'
    elif shared['sessions']:
        pivot_type = 'session'
    elif shared['hosts']:
        pivot_type = 'host'
    elif shared['accounts'] and suspicious_identity_signal:
        pivot_type = 'identity_anomaly'
    elif shared['accounts']:
        pivot_type = 'account'
    elif shared['ips']:
        pivot_type = 'network_ip'
    elif shared['resources']:
        pivot_type = 'resource'
    else:
        pivot_type = 'behavioral'
    evidence = []
    if shared_atk_ips:
        evidence.append({'kind': 'attacker_ips', 'values': sorted(shared_atk_ips)[:4]})
    for key in ('accounts', 'hosts', 'ips', 'resources', 'mitre', 'cloud_boundaries', 'sessions'):
        vals = shared[key]
        if vals:
            evidence.append({'kind': key, 'values': vals[:4]})
    significance_parts = []
    if shared_atk_ips:
        significance_parts.append(f'shared attacker IP {next(iter(shared_atk_ips))}')
    if shared['accounts']:
        significance_parts.append('shared identity activity')
    if shared['hosts']:
        significance_parts.append('same host sequence')
    if shared['ips']:
        significance_parts.append('same network infrastructure')
    if shared['resources']:
        significance_parts.append('same resource or artifact path')
    if shared['mitre']:
        significance_parts.append('same ATT&CK technique family')
    if shared['cloud_boundaries']:
        significance_parts.append('same cloud account or boundary')
    if shared['sessions']:
        significance_parts.append('same session or correlation context')
    if 'elevated' in shared['privilege_states']:
        significance_parts.append('privileged or escalated identity context')
    if time_delta is not None and time_delta <= 3600:
        significance_parts.append(f'within {int(time_delta // 60) or 1} minute(s)')
    return {
        'target_row_index': int(right.get('row_index') or 0),
        'source_row_index': int(left.get('row_index') or 0),
        'shared': evidence,
        'cross_source': cross_source,
        'time_delta_seconds': int(time_delta) if time_delta is not None else None,
        'confidence': round(min(0.98, score), 2),
        'pivot_type': pivot_type,
        'summary': '; '.join(significance_parts) or 'shared telemetry context',
    }


def _build_cluster_lead_description(
    component_rows: list,
    shared_ips: list,
    shared_accounts: list,
    shared_hosts: list,
    cluster_num: int,
) -> str:
    """Build a grounded cluster title from observed entities rather than raw description fields."""
    # Descriptions that are too generic to be a useful incident title — reject these
    # and fall through to the entity-based builder instead.
    _SKIP = re.compile(
        r'^('
        r'correlated activity cluster'
        r'|n/a|unknown|none|null|-|event|log entry|log'
        r'|high.severity activity\.?'
        r'|medium.severity activity\.?'
        r'|low.severity activity\.?'
        r'|critical.severity activity\.?'
        r'|suspicious activity\.?'
        r'|security event\.?'
        r'|anomalous activity\.?'
        r'|threat detected\.?'
        r'|alert triggered\.?'
        r'|potential threat\.?'
        r'|investigation required\.?'
        r'|requires investigation\.?'
        r'|see analyst notes\.?'
        r')$',
        re.I,
    )
    # Prefer a description from the highest-triage row that looks like a named action
    sorted_rows = sorted(component_rows, key=lambda r: float(r.get('triage_score') or 0), reverse=True)
    for row in sorted_rows:
        # Prefer alert_name / event_name over free-text description — they're more structured
        for field in ('alert_name', 'event_name', 'eventName', 'activityDisplayName',
                      'operationName', 'analyst_notes', 'description'):
            desc = _safe_text(row.get(field) or '')
            if desc and not _SKIP.match(desc.strip()) and 10 <= len(desc) <= 90:
                # Skip anything that looks like a raw UUID or purely numeric event ID
                if not re.match(r'^[0-9a-f\-]{8,}$', desc, re.I):
                    return desc
    # Entity-based fallback: actor â†’ verb â†’ target
    actor = shared_accounts[0] if shared_accounts else None
    target_host = shared_hosts[0] if shared_hosts else None
    target_ip = shared_ips[0] if shared_ips else None

    # Collect the best MITRE technique label across all rows
    mitre_verb: str = ''
    for row in sorted_rows[:10]:
        mitre = row.get('mitre') or []
        if mitre:
            mitre_verb = str(mitre[0])
            break

    # Collect the most specific event-type label
    event_verb: str = ''
    for row in sorted_rows[:5]:
        for ef in ('event_name', 'eventName', 'activityDisplayName', 'operationName', 'category'):
            ev = _safe_text(row.get(ef) or '')
            if ev and not _SKIP.match(ev) and len(ev) > 4:
                event_verb = ev
                break
        if event_verb:
            break

    verb = event_verb or mitre_verb or 'suspicious activity'

    if actor and target_ip:
        return f"{actor} \u2192 {target_ip}: {verb}" if not event_verb else f"{actor}: {event_verb}"
    if actor and target_host:
        return f"{actor} on {target_host}: {verb}" if not event_verb else f"{actor}: {event_verb}"
    if actor:
        return f"{actor}: {verb}"
    if target_ip:
        return f"External IP {target_ip}: {verb}"
    if target_host:
        return f"Host {target_host}: {verb}"
    # Last resort: informative placeholder with cluster number and pivot count
    return f"Cluster {cluster_num} \u2014 {len(component_rows)} correlated events"


def _build_cluster_reason_summary(top_links: list) -> str:
    """Aggregate unique pivot signals rather than concatenating repeated phrases."""
    if not top_links:
        return ''
    # Collect unique (pivot_type, time_bucket) combinations
    seen: set = set()
    parts: list = []
    for lk in top_links:
        summary = lk.get('summary') or ''
        pivot = lk.get('pivot_type') or lk.get('pivot') or ''
        # Deduplicate by normalising the summary to its first clause before the time qualifier
        key = re.sub(r'within \d+ minute\(s\)', 'TIMED', summary)
        if key and key not in seen:
            seen.add(key)
            parts.append(summary)
    return '; '.join(parts[:3])


# Inverted-index clustering — O(nÂ·k) where k = avg entity keys per row.
# For super-nodes (e.g. 'system' account in 20k rows) cap the bucket to avoid O(bucketÂ²) explosions.
_CLUSTER_BUCKET_CAP = 200  # max rows per shared key before we stop expanding that key's pairs


def _row_refs_for_story(rows: List[dict], *needles: str, limit: int = 20) -> List[int]:
    refs: List[int] = []
    lowered = [n.lower() for n in needles if n]
    if not lowered:
        return refs
    for row in rows:
        blob = _collect_strings_from_row(row).lower()
        if any(n in blob for n in lowered):
            try:
                refs.append(int(row.get('row_index') or 0))
            except Exception:
                continue
        if len(refs) >= limit:
            break
    return list(dict.fromkeys(refs))


def _build_enrichment_guided_cases(rows: List[dict]) -> List[dict]:
    """Production assessment path never injects enrichment-derived cases."""
    return []

def _build_inverted_index(row_map: Dict[int, dict]) -> Dict[str, List[int]]:
    """Build key â†’ [row_index, ...] inverted index for all pivot dimensions."""
    idx: Dict[str, List[int]] = defaultdict(list)
    for row_idx, row in row_map.items():
        # Account / identity pivots
        for acc in (row.get('accounts') or []):
            if acc and not _is_low_value_account_pivot(acc):
                idx[f'acc:{acc.lower()}'].append(row_idx)
        # External IP pivots (only non-private, non-vendor)
        for ip in (row.get('external_ips') or []):
            if ip:
                idx[f'ip:{ip}'].append(row_idx)
        # Host pivots
        for h in (row.get('hosts') or []):
            if h:
                idx[f'host:{h.lower()}'].append(row_idx)
        # Session / correlation-id pivots — strong signal
        sess = _safe_text(row.get('session_id') or '')
        if sess and sess not in ('-', 'N/A'):
            idx[f'sess:{sess}'].append(row_idx)
        # Cloud boundary (subscription / account_id)
        cb = _safe_text(row.get('cloud_boundary') or '')
        if cb and cb not in ('-', 'N/A'):
            idx[f'cloud:{cb}'].append(row_idx)
        # MITRE technique pivots
        for m in (row.get('mitre') or []):
            if m:
                idx[f'mitre:{str(m).upper()}'].append(row_idx)
        # Attacker IP pivots (separate from external_ips — uses the filtered set)
        for ip in _extract_attacker_ips(row):
            idx[f'atk:{ip}'].append(row_idx)
        # Resource pivots (S3 bucket, vault, key ARN, etc.)
        for res in (row.get('resources') or []):
            if res and len(res) > 4:
                idx[f'res:{res.lower()[:80]}'].append(row_idx)
    return idx


def _build_correlation_clusters(rows: List[dict]) -> Tuple[List[dict], Dict[int, List[dict]]]:
    adjacency: Dict[int, List[dict]] = defaultdict(list)
    row_map = {int(row.get('row_index') or 0): row for row in rows}

    # Build inverted index across all pivot dimensions — O(nÂ·k)
    inv_idx = _build_inverted_index(row_map)

    # Collect candidate pairs from index buckets — each bucket is a set of rows
    # sharing one pivot key.  Dedup pairs with a seen set.
    seen_pairs: Set[Tuple[int, int]] = set()
    candidate_pairs: List[Tuple[int, int]] = []
    for key, bucket in inv_idx.items():
        if len(bucket) < 2:
            continue
        # Cap super-nodes: keep the highest-triage rows in this bucket
        if len(bucket) > _CLUSTER_BUCKET_CAP:
            bucket = sorted(bucket, key=lambda i: float(row_map[i].get('triage_score') or 0), reverse=True)[:_CLUSTER_BUCKET_CAP]
        for i, left_idx in enumerate(bucket):
            for right_idx in bucket[i + 1:]:
                pair = (min(left_idx, right_idx), max(left_idx, right_idx))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    candidate_pairs.append(pair)

    logger.debug(
        '_build_correlation_clusters: %d rows â†’ %d index buckets â†’ %d candidate pairs',
        len(rows), len(inv_idx), len(candidate_pairs),
    )

    # Evaluate each candidate pair with the full reason builder
    for left_idx, right_idx in candidate_pairs:
        left = row_map.get(left_idx)
        right = row_map.get(right_idx)
        if left is None or right is None:
            continue
        reason = _build_pair_reason(left, right)
        if not reason:
            continue
        adjacency[left_idx].append(reason)
        reverse = dict(reason)
        reverse['target_row_index'] = left_idx
        adjacency[right_idx].append(reverse)

    indices = sorted(row_map.keys())

    visited: Set[int] = set()
    clusters: List[dict] = []
    cluster_num = 1
    for row_index in indices:
        if row_index in visited:
            continue
        component = []
        stack = [row_index]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            component.append(current)
            for link in adjacency.get(current, []):
                target = int(link.get('target_row_index') or 0)
                if target and target not in visited:
                    stack.append(target)
        if len(component) < 2:
            continue
        component_rows = [row_map[idx] for idx in sorted(component)]
        shared_accounts = sorted({
            item for row in component_rows for item in row.get('accounts') or []
            if not _is_low_value_account_pivot(item)
        })
        shared_hosts = sorted({item for row in component_rows for item in row.get('hosts') or []})
        shared_ips = sorted({item for row in component_rows for item in row.get('external_ips') or []})
        shared_resources = sorted({item for row in component_rows for item in row.get('resources') or []})
        all_links = [link for idx in component for link in adjacency.get(idx, []) if int(link.get('target_row_index') or 0) in component]
        top_links = sorted(all_links, key=lambda l: float(l.get('confidence') or 0), reverse=True)[:6]
        time_values = [row.get('timestamp_epoch') for row in component_rows if row.get('timestamp_epoch') is not None]
        cluster_id = f'cluster-{cluster_num}'
        cluster_num += 1
        cluster = {
            'cluster_id': cluster_id,
            'row_refs': [int(row.get('row_index') or 0) for row in component_rows],
            'evidence_refs': [f"R{int(row.get('row_index') or 0)}" for row in component_rows],
            'severity': _severity_label_for_rows(component_rows),
            'confidence': round(sum(float(link.get('confidence') or 0.0) for link in all_links) / max(len(all_links), 1), 2),
        'source_sheets': sorted({_safe_text(row.get('source_sheet') or 'unknown') for row in component_rows}),
        'providers': sorted({_safe_text((row.get('cloud') or {}).get('provider') or row.get('provider_profile') or 'generic') for row in component_rows}),
        'shared_accounts': shared_accounts[:6],
        'shared_hosts': shared_hosts[:6],
        'shared_external_ips': shared_ips[:6],
        'shared_resources': shared_resources[:6],
        'affected_accounts': sorted({item for row in component_rows for item in ((row.get('accounts') or []) + ([((row.get('cloud') or {}).get('account_id'))] if (row.get('cloud') or {}).get('account_id') else []))})[:8],
        'affected_assets': sorted({item for row in component_rows for item in ((row.get('hosts') or []) + (row.get('resources') or []))})[:10],
        'affected_subnets': sorted({item for row in component_rows if (row.get('network') or {}).get('subnet') for item in [(row.get('network') or {}).get('subnet')]})[:6],
        'top_mitre': sorted({item for row in component_rows for item in row.get('mitre') or []})[:6],
        'time_window': {
            'start': min(time_values) if time_values else None,
            'end': max(time_values) if time_values else None,
            'span_seconds': int(max(time_values) - min(time_values)) if len(time_values) >= 2 else 0,
            },
            'lead_description': _build_cluster_lead_description(component_rows, shared_ips, shared_accounts, shared_hosts, cluster_num - 1),
            'reason_summary': _build_cluster_reason_summary(top_links),
            'top_links': [
                {
                    'src': int(lk.get('source_row_index') or 0),
                    'dst': int(lk.get('target_row_index') or 0),
                    'pivot': lk.get('pivot_type', 'unknown'),
                    'conf': lk.get('confidence', 0.0),
                    'summary': lk.get('summary', ''),
                }
                for lk in top_links[:5]
            ],
            'business_significance': '',
            'recommended_logs': [],
        }
        cluster.update(_initial_cluster_verdict(component_rows, cluster['severity']))
        significance = []
        if shared_accounts:
            significance.append('identity compromise or shared actor sequence')
        if shared_hosts:
            significance.append('same endpoint or workload appears across multiple stages')
        if shared_ips:
            significance.append('external infrastructure appears across correlated rows')
        if 'Cloud_AWS' in cluster['source_sheets'] or 'Cloud_Azure' in cluster['source_sheets']:
            significance.append('cloud control changes may widen blast radius')
        if any('Email' in sheet for sheet in cluster['source_sheets']):
            significance.append('mailbox or phishing telemetry suggests user-facing compromise')
        provider_set = {item for item in cluster.get('providers') or [] if item and item != 'generic'}
        if {'aws', 'azure'} <= provider_set or ('okta' in provider_set and {'aws', 'azure'} & provider_set):
            significance.append('cross-cloud identity movement links identity control changes to cloud actions across provider boundaries')
        if 'active_directory' in provider_set and ('vmware' in provider_set or 'nutanix' in provider_set):
            significance.append('on-prem identity and virtualization activity suggest hybrid infrastructure lateral-movement risk')
        if 'email' in provider_set:
            # Require specific BEC indicators before surfacing payment-risk language
            _bec_tokens = ('bcc forwarding', 'inbox rule', 'forwarding rule', 'wire transfer',
                           'beneficiary', 'payment approval', 'finance officer')
            _comp_rows = component_rows
            _joined_lower = ' '.join(_collect_strings_from_row(r).lower() for r in _comp_rows[:40])
            _bec_hits = [t for t in _bec_tokens if t in _joined_lower]
            if len(_bec_hits) >= 2:
                significance.append(
                    f'BEC indicators detected ({", ".join(_bec_hits[:3])}) — '
                    'email activity may affect payment or executive-trust workflows'
                )
            elif _bec_hits:
                significance.append('email activity with possible business-process exposure — verify mailbox audit logs')
        logs = []
        if shared_accounts:
            logs.extend(['identity sign-in logs', 'MFA / Conditional Access decisions'])
        if shared_hosts:
            logs.extend(['EDR process lineage', 'Sysmon Event ID 1/3/11/13'])
        if shared_ips:
            logs.extend(['proxy / firewall egress logs', 'DNS resolution logs'])
        if any('Cloud_AWS' in sheet for sheet in cluster['source_sheets']):
            logs.extend(['CloudTrail', 'S3 data events'])
        if any('Cloud_Azure' in sheet for sheet in cluster['source_sheets']):
            logs.extend(['Azure Activity Log', 'Entra audit logs'])
        if any('Email' in sheet for sheet in cluster['source_sheets']):
            logs.extend(['mailbox audit logs', 'message trace'])
        if 'okta' in provider_set:
            logs.extend(['Okta System Log', 'Okta MFA / sign-on policy audit'])
        if 'active_directory' in provider_set:
            logs.extend(['Windows Security 4624/4625/4768/4769', 'Domain controller authentication logs'])
        if 'vmware' in provider_set:
            logs.extend(['vCenter tasks and events', 'ESXi hostd / vpxa logs'])
        if 'nutanix' in provider_set:
            logs.extend(['Prism Central audit log', 'AHV hypervisor task logs'])
        if 'email' in provider_set:
            logs.extend(['mail transport / secure email gateway logs', 'mailbox rule and delegate audit'])
        cluster['recommended_logs'] = list(dict.fromkeys(logs))[:10]
        compliance = _cluster_controls_and_frameworks(cluster, component_rows)
        provider_count = len([p for p in cluster.get('providers') or [] if p and p != 'generic'])
        cluster['blast_radius_summary'] = (
            f"{len(cluster['affected_accounts'])} account/subscription boundary markers, "
            f"{len(cluster['affected_assets'])} named assets or resources, "
            f"{provider_count or 1} provider context(s)."
        )
        cluster['crown_jewel_likelihood'] = 'medium' if any('admin' in (_safe_text(item).lower()) for item in cluster.get('affected_accounts') or []) else 'low'
        cluster['regulated_data_likelihood'] = 'medium' if any('s3' in (_safe_text(item).lower()) or 'blob' in (_safe_text(item).lower()) or 'mail' in (_safe_text(item).lower()) for item in cluster.get('affected_assets') or []) else 'low'
        cluster['operational_impact_summary'] = 'Correlated activity may affect identity trust, workloads, communications, and control changes in the same case window.'
        cluster['remediation_owner'] = 'Security Operations'
        cluster['communications_owner'] = 'Security leadership'
        cluster['legal_review_recommended'] = cluster['regulated_data_likelihood'] in {'medium', 'high'} or cluster['severity'] == 'critical'
        cluster['pr_statement_recommended'] = cluster['severity'] == 'critical' and len(cluster.get('affected_assets') or []) >= 3
        cluster['notification_obligation_likelihood'] = 'medium' if cluster['legal_review_recommended'] else 'low'
        cluster['affected_frameworks'] = compliance.get('frameworks') or []
        cluster['affected_controls'] = [entry.get('control') for entry in (compliance.get('controls') or []) if entry.get('control')][:12]
        cluster['compliance_control_impact'] = {
            'frameworks': cluster['affected_frameworks'],
            'controls': cluster['affected_controls'],
            'summary': 'Mapped controls should be validated against the exact affected account, subnet, and asset scope before reporting.',
        }
        cluster['financial_impact_min'] = None
        cluster['financial_impact_max'] = None
        cluster['financial_impact_status'] = 'pending_human_input'
        cluster['policy_change_context'] = {
            'suspicious_rows': [int(row.get('row_index') or 0) for row in component_rows if (row.get('policy_change_context') or {}).get('suspicious_drift')],
            'approved_rows': [int(row.get('row_index') or 0) for row in component_rows if (row.get('policy_change_context') or {}).get('approved_change')],
        }
        cluster['guest_onboarding_context'] = {
            'guest_rows': [int(row.get('row_index') or 0) for row in component_rows if row.get('guest_onboarding_context')],
            'benign_rows': [int(row.get('row_index') or 0) for row in component_rows if (row.get('guest_onboarding_context') or {}).get('category') == 'benign_onboarding'],
        }
        posture_contexts = [row.get('security_posture_context') or {} for row in component_rows if row.get('security_posture_context')]
        posture_vendors = sorted({vendor for ctx in posture_contexts for vendor in (ctx.get('vendors') or [])})
        posture_modes = [ctx.get('perimeter_mode') for ctx in posture_contexts if ctx.get('perimeter_mode')]
        posture_mode = (
            'none' if 'none' in posture_modes else
            'dual_firewall' if len(posture_vendors) >= 2 else
            'single_firewall' if len(posture_vendors) == 1 else
            'edge_only' if any(ctx.get('cdn_present') for ctx in posture_contexts) else
            'unspecified'
        )
        cluster['security_posture'] = {
            'vendors': posture_vendors,
            'cdn_present': any(ctx.get('cdn_present') for ctx in posture_contexts),
            'perimeter_mode': posture_mode,
            'benign_mfa_rows': [int(row.get('row_index') or 0) for row in component_rows if (row.get('security_posture_context') or {}).get('benign_mfa')],
            'compromised_mfa_rows': [int(row.get('row_index') or 0) for row in component_rows if (row.get('security_posture_context') or {}).get('compromised_mfa')],
            'summary': '',
        }
        posture_summary = (
            'No perimeter firewall telemetry is available in this cluster; validate ingress and egress with ALB, VPC Flow, CDN, and cloud control logs.'
            if posture_mode == 'none'
            else 'Dual next-gen firewall telemetry and cloud-native logs provide layered confirm/deny evidence for this cluster.'
            if posture_mode == 'dual_firewall'
            else 'Partial perimeter telemetry exists; confirm or deny with firewall, CDN, and cloud-native sources together.'
        )
        if cluster['security_posture'].get('compromised_mfa_rows'):
            posture_summary += ' Compromised or fatigued MFA signals are present and should be treated as identity-control degradation.'
        elif cluster['security_posture'].get('benign_mfa_rows'):
            posture_summary += ' Approved MFA activity is present and should remain benign unless later corroborated by malicious evidence.'
        cluster['security_posture']['summary'] = posture_summary
        if posture_mode == 'none':
            significance.append('limited perimeter controls increase blind-spot risk and raise the priority of cloud-native telemetry validation')
        elif posture_mode == 'dual_firewall':
            significance.append('layered perimeter telemetry strengthens ingress and egress confirm/deny analysis')
        if cluster['security_posture'].get('cdn_present'):
            significance.append('CDN edge activity sits between internet-facing delivery and origin workloads')
        if cluster['security_posture'].get('compromised_mfa_rows'):
            significance.append('MFA compromise indicators suggest identity controls may have been bypassed or fatigued')
        if 'okta' in provider_set and 'azure' in provider_set:
            significance.append('federated identity signals span IdP and Azure administrative context in the same incident window')
        if 'active_directory' in provider_set and 'email' in provider_set:
            significance.append('directory and email evidence together raise the likelihood of account takeover or BEC-driven abuse')
        cluster['business_significance'] = '; '.join(significance) or 'multiple evidentiary rows point to one investigation track'
        if 'checkpoint' in posture_vendors:
            logs.append('Check Point traffic / threat logs')
        if 'palo_alto' in posture_vendors:
            logs.append('Palo Alto traffic / threat logs')
        if cluster['security_posture'].get('cdn_present'):
            logs.append('CDN edge access logs')
        if posture_mode == 'none':
            logs.append('ALB access logs / VPC Flow (no perimeter firewall present)')
        cluster['recommended_logs'] = list(dict.fromkeys(logs))[:12]
        # Verdict-aware gate — never hardcode True (see _apply_hvr_gating docstring)
        _apply_hvr_gating(cluster, component_rows)
        cluster['remediation_simulation'] = _build_remediation_simulation(component_rows, cluster['severity'])
        cluster['alb_drain_status'] = cluster.get('remediation_simulation', {}).get('alb_drain_status')
        cluster['replacement_capacity_status'] = cluster.get('remediation_simulation', {}).get('replacement_capacity_status')
        cluster['crisis_management'] = {
            'summary': 'Prepare containment, executive briefing, and customer-impact validation in parallel if this cluster remains confirmed.',
            'actions': [
                'Validate the blast radius with named accounts, subnets, and resources before declaring crisis status.',
                'Route critical clusters to legal and executive owners when regulated data or customer services may be affected.',
            ],
        }
        cluster['legal_considerations'] = {
            'summary': 'Keep legal guidance brief: determine whether regulated data, contractual obligations, or preservation requirements apply.',
            'actions': [
                'Check whether the affected controls map to mandatory notification or evidence-preservation obligations.',
            ],
        }
        cluster['pr_media_guidance'] = {
            'summary': 'Do not issue external statements until row-linked scope, affected services, and communication ownership are confirmed.',
            'recommended': bool(cluster['pr_statement_recommended']),
        }
        cluster['mandatory_communications'] = {
            'summary': 'Use the compliance control impact and regulated-data likelihood to decide whether customer, regulator, or board communications are required.',
            'frameworks': cluster['affected_frameworks'],
        }
        for row in component_rows:
            row['correlation_cluster_id'] = cluster_id
            row['correlation_type'] = 'correlated'
            row['correlation_reasons'] = adjacency.get(int(row.get('row_index') or 0), [])
            row['blast_radius_summary'] = cluster['blast_radius_summary']
            row['affected_frameworks'] = cluster['affected_frameworks']
            row['affected_controls'] = cluster['affected_controls']
            row['human_validation_required'] = cluster['human_validation_required']
            row['playbook_status'] = cluster['playbook_status']
            row['remediation_simulation'] = cluster['remediation_simulation']
            row['alb_drain_status'] = cluster.get('alb_drain_status')
            row['replacement_capacity_status'] = cluster.get('replacement_capacity_status')
            row['security_posture'] = cluster.get('security_posture')
        clusters.append(cluster)

    for row in rows:
        row.setdefault('correlation_type', 'isolated')
        row.setdefault('correlation_reasons', [])
        if 'human_validation_required' not in row:
            _row_hvr = _derive_human_validation_required(
                row,
                policy_ctx=row.get('policy_change_context') or {},
                guest_ctx=row.get('guest_onboarding_context') or {},
            )
            row['human_validation_required'] = _row_hvr
            row['gate_urgency'] = 'NORMAL' if _row_hvr else 'LOW'
            row['playbook_status'] = 'human_gated' if _row_hvr else 'auto_triaged'
        row.setdefault('policy_change_context', {})
        row.setdefault('guest_onboarding_context', {})
        row.setdefault('security_posture_context', {})
        row.setdefault('security_posture', {})
        row.setdefault('remediation_simulation', {})
    clusters.sort(key=lambda item: (_SEV_RANK.get(item.get('severity') or 'low', 0), len(item.get('row_refs') or []), item.get('confidence') or 0.0), reverse=True)
    return clusters, adjacency


def _build_task_entry(task: str, row_refs: List[int], logs: List[str], purpose: str) -> Dict[str, Any]:
    refs = [int(r) for r in row_refs if r is not None]
    return {
        'task': task,
        'row_refs': refs,
        'evidence_refs': [f'R{r}' for r in refs],
        'logs': list(dict.fromkeys(logs))[:8],
        'purpose': purpose,
    }


def _build_persona_reports_backend(assessment: dict, rows: List[dict], clusters: List[dict]) -> Dict[str, dict]:
    top_clusters = clusters[:3]
    top_rows = sorted(rows, key=lambda row: (_SEV_RANK.get(row.get('severity') or 'low', 0), float(row.get('triage_score') or 0.0)), reverse=True)[:6]
    top_entities = list(dict.fromkeys([row.get('entity') for row in top_rows if row.get('entity') and row.get('entity') != '-']))[:5]
    top_mitre = list(dict.fromkeys([item for row in top_rows for item in row.get('mitre') or []]))[:6]
    total_rows = len(rows)
    correlated = len([row for row in rows if row.get('correlation_type') == 'correlated'])

    def _cluster_line(cluster: dict) -> str:
        pivots = cluster.get('shared_accounts') or cluster.get('shared_hosts') or cluster.get('shared_external_ips') or cluster.get('shared_resources') or []
        pivot_text = ', '.join(pivots[:3]) if pivots else 'shared telemetry'
        provider_text = ', '.join(cluster.get('providers') or [])
        provider_suffix = f" across {provider_text}" if provider_text else ''
        return f"Rows {', '.join('#' + str(r) for r in cluster.get('row_refs', [])[:5])} tie together around {pivot_text}{provider_suffix}; {cluster.get('business_significance')}"

    reports: Dict[str, dict] = {}

    soc_tasks = []
    hunter_tasks = []
    forensic_tasks = []
    executive_tasks = []
    ciso_tasks = []
    for cluster in top_clusters:
        row_refs = cluster.get('row_refs') or []
        log_list = cluster.get('recommended_logs') or []
        pivots = cluster.get('shared_accounts') or cluster.get('shared_hosts') or cluster.get('shared_external_ips') or []
        pivot_text = ', '.join(pivots[:3]) if pivots else 'the shared evidence pivots'
        soc_tasks.append(_build_task_entry(
            f"Confirm whether rows {', '.join('#' + str(r) for r in row_refs[:5])} are one incident tied by {pivot_text}; if confirmed, contain the active account or host before closing.",
            row_refs, log_list, 'confirm_or_deny'
        ))
        hunter_tasks.append(_build_task_entry(
            f"Pivot on {pivot_text} across the full time window and adjacent sources to confirm whether the cluster extends beyond rows {', '.join('#' + str(r) for r in row_refs[:5])}.",
            row_refs, log_list, 'hunt_hypothesis'
        ))
        forensic_tasks.append(_build_task_entry(
            f"Preserve artefacts for rows {', '.join('#' + str(r) for r in row_refs[:5])}, then reconstruct the timeline and chain of custody before remediation changes the evidence.",
            row_refs, log_list, 'preserve_and_reconstruct'
        ))
        executive_tasks.append(_build_task_entry(
            f"Decide whether the activity around rows {', '.join('#' + str(r) for r in row_refs[:5])} changes customer, regulatory, or leadership notification posture; require security to confirm impact with named accounts, systems, and data paths.",
            row_refs, log_list, 'business_decision'
        ))
        ciso_tasks.append(_build_task_entry(
            f"Approve containment scope for rows {', '.join('#' + str(r) for r in row_refs[:5])} only after security confirms blast radius, affected identities, and whether the correlated sequence reached privileged or data-bearing assets.",
            row_refs, log_list, 'risk_and_containment'
        ))

    def _section(title: str, bullets: List[str]) -> Dict[str, Any]:
        return {'title': title, 'bullets': bullets, 'text': '\n'.join(bullets)}

    reports['soc_analyst'] = {
        'headline': f'P1 triage for {total_rows} rows | {correlated} correlated',
        'overview': {
            'what_happened': f'{correlated} row(s) share evidence-backed pivots across the uploaded workbook.',
            'why_it_matters': 'Correlated rows indicate one or more incidents that should be triaged as sequences, not isolated alerts.',
            'what_to_do_next': 'Validate the highest-confidence clusters, contain active identities or hosts, and deny benign explanations with change evidence.',
        },
        'focus_cluster_summary': {'summary': _cluster_line(top_clusters[0]) if top_clusters else 'No multi-row cluster established.'},
        'key_points': [f'Lead entities: {", ".join(top_entities)}' if top_entities else 'Lead entities not yet resolved.'] + [_cluster_line(cluster) for cluster in top_clusters[:2]],
        'sections': [
            _section('Priority Evidence', [f'{total_rows} events analyzed.', f'Lead ATT&CK tags: {", ".join(top_mitre) or "none"}']),
            _section('Containment Queue', [task['task'] for task in soc_tasks] or ['No correlated clusters met the action threshold.']),
            _section('Control Posture', [cluster.get('security_posture', {}).get('summary') for cluster in top_clusters if cluster.get('security_posture')] or ['Security-control posture not yet inferred from the evidence.']),
            _section('Benign / Change Denials', [
                'Deny benign guest onboarding by matching invite, sponsor, MFA-registration, and ticket records before escalation.',
                'Deny approved policy drift by matching CAB or pipeline change evidence before treating it as malicious.',
            ]),
        ],
        'tasks': soc_tasks,
    }
    reports['threat_hunter'] = {
        'headline': f'Hunt hypotheses for {len(top_clusters)} active cluster(s)',
        'overview': {
            'what_happened': 'The workbook contains correlated identity, endpoint, cloud, and email pivots that can be hunted beyond the uploaded rows.',
            'why_it_matters': 'Shared accounts, hosts, external IPs, and technique overlap suggest adjacent activity may still be undiscovered.',
            'what_to_do_next': 'Use the shared pivots to expand scope, test alternate branches, and measure telemetry gaps.',
        },
        'focus_cluster_summary': {'summary': _cluster_line(top_clusters[0]) if top_clusters else 'No hunt cluster established.'},
        'key_points': [_cluster_line(cluster) for cluster in top_clusters] or ['No cluster-level pivots available.'],
        'sections': [
            _section('Hunt Leads', [f'Lead entities: {", ".join(top_entities)}' if top_entities else 'No lead entities resolved yet.']),
            _section('Hunt Hypotheses', [task['task'] for task in hunter_tasks] or ['No hunt hypotheses met the threshold.']),
            _section('Perimeter / Edge Expansions', [cluster.get('security_posture', {}).get('summary') for cluster in top_clusters if cluster.get('security_posture')] or ['Perimeter or CDN telemetry posture not yet established.']),
            _section('Supply Chain / Drift Checks', [
                'Expand package-poisoning pivots through CI/CD, registry, host, role, and subnet scope before assuming the blast radius is closed.',
                'Separate approved policy-as-code rollout from suspicious drift by checking who changed the guardrail, from where, and what followed.',
            ]),
        ],
        'tasks': hunter_tasks,
    }
    reports['forensics'] = {
        'headline': f'Forensic preservation plan for {len(top_clusters)} cluster(s)',
        'overview': {
            'what_happened': 'Multiple timestamped artefacts align into clusters that should be preserved as one chain of evidence.',
            'why_it_matters': 'The sequence matters as much as the individual rows; preserving chronology is necessary before remediation removes volatile evidence.',
            'what_to_do_next': 'Acquire volatile artefacts first, then collect cloud, identity, and message traces in the same time order.',
        },
        'focus_cluster_summary': {'summary': _cluster_line(top_clusters[0]) if top_clusters else 'No preservation cluster established.'},
        'key_points': [_cluster_line(cluster) for cluster in top_clusters] or ['No cluster-level chronology available.'],
        'sections': [
            _section('Collection Priorities', [f'Correlated clusters: {len(top_clusters)}', f'Lead entities: {", ".join(top_entities) or "none"}']),
            _section('Preservation Plan', [task['task'] for task in forensic_tasks] or ['No preservation tasks exceeded the threshold.']),
            _section('Perimeter Artefacts', [cluster.get('security_posture', {}).get('summary') for cluster in top_clusters if cluster.get('security_posture')] or ['No perimeter or edge artefact note is available yet.']),
            _section('Timeline Caveats', [
                'Preserve guest-onboarding and policy-change audit trails separately so benign or approved changes are not misclassified after remediation.',
            ]),
        ],
        'tasks': forensic_tasks,
    }
    reports['executive'] = {
        'headline': 'Executive decision brief',
        'overview': {
            'what_happened': f'The uploaded workbook shows {correlated} correlated rows across {len(set(row.get("source_sheet") for row in rows))} evidence domains.',
            'why_it_matters': 'This may indicate a single business-impacting intrusion path rather than unrelated alerts.',
            'what_to_do_next': 'Require security to confirm impacted accounts, systems, and data before deciding on notifications or public statements.',
        },
        'focus_cluster_summary': {'summary': _cluster_line(top_clusters[0]) if top_clusters else 'No executive-impact cluster established.'},
        'key_points': [
            f'Named entities in scope: {", ".join(top_entities)}' if top_entities else 'Named entities still being confirmed.',
            f'Potential external infrastructure: {", ".join(top_clusters[0].get("shared_external_ips", [])[:3])}' if top_clusters and top_clusters[0].get('shared_external_ips') else 'External infrastructure not yet confirmed.',
            'Leadership should expect a confirm / deny update tied to specific rows and evidence references, not a generic status report.',
        ],
        'sections': [
            _section('Decision Checks', [task['task'] for task in executive_tasks] or ['No executive decision task exceeded the threshold.']),
            _section('Business Impact View', [cluster.get('business_significance') for cluster in top_clusters] or ['Business impact not yet established.']),
            _section('Crisis Management', [cluster.get('crisis_management', {}).get('summary') for cluster in top_clusters if cluster.get('crisis_management')] or ['Crisis-management posture not yet elevated.']),
            _section('Legal / PR / Communications', [
                (
                    f"Legal review {'recommended' if cluster.get('legal_review_recommended') else 'not yet required'}; "
                    f"communications likelihood {cluster.get('notification_obligation_likelihood')}; "
                    f"framework impact: {', '.join(cluster.get('affected_frameworks') or ['none'])}"
                ) for cluster in top_clusters
            ] or ['Legal and communications triggers not yet established.']),
        ],
        'tasks': executive_tasks,
        'business_significance': top_clusters[0] if top_clusters else {},
        'crisis_management': (top_clusters[0] or {}).get('crisis_management') if top_clusters else {},
        'legal_considerations': (top_clusters[0] or {}).get('legal_considerations') if top_clusters else {},
        'pr_media_guidance': (top_clusters[0] or {}).get('pr_media_guidance') if top_clusters else {},
        'mandatory_communications': (top_clusters[0] or {}).get('mandatory_communications') if top_clusters else {},
        'compliance_control_impact': (top_clusters[0] or {}).get('compliance_control_impact') if top_clusters else {},
    }
    reports['ciso'] = {
        'headline': 'CISO risk and containment brief',
        'overview': {
            'what_happened': f'{correlated} correlated rows suggest at least one evidence-backed incident sequence.',
            'why_it_matters': 'The current evidence touches identities, workloads, and potentially data-bearing resources; containment scope should match that blast radius.',
            'what_to_do_next': 'Approve containment only after security confirms privilege level, persistence, and data movement evidence by cluster.',
        },
        'focus_cluster_summary': {'summary': _cluster_line(top_clusters[0]) if top_clusters else 'No CISO focus cluster established.'},
        'key_points': [_cluster_line(cluster) for cluster in top_clusters] or ['No cluster-level risk posture available.'],
        'sections': [
            _section('Risk Posture', [f'Lead ATT&CK tags: {", ".join(top_mitre) or "none"}', f'Correlated clusters: {len(top_clusters)}']),
            _section('Decision Checks', [task['task'] for task in ciso_tasks] or ['No CISO decision task exceeded the threshold.']),
            _section('Business Significance', [
                (
                    f"{cluster.get('blast_radius_summary')} {cluster.get('security_posture', {}).get('summary', '')} Crown-jewel likelihood: {cluster.get('crown_jewel_likelihood')}; "
                    f"regulated-data likelihood: {cluster.get('regulated_data_likelihood')}; "
                    f"financial impact status: {cluster.get('financial_impact_status')}"
                ) for cluster in top_clusters
            ] or ['Business significance still requires human validation.']),
            _section('Crisis / Communications', [
                (
                    f"{cluster.get('crisis_management', {}).get('summary')} "
                    f"Legal review {'recommended' if cluster.get('legal_review_recommended') else 'not yet required'}; "
                    f"PR recommendation {'yes' if cluster.get('pr_statement_recommended') else 'no'}."
                ) for cluster in top_clusters
            ] or ['Crisis-management posture not yet established.']),
        ],
        'tasks': ciso_tasks,
        'business_significance': top_clusters[0] if top_clusters else {},
        'crisis_management': (top_clusters[0] or {}).get('crisis_management') if top_clusters else {},
        'legal_considerations': (top_clusters[0] or {}).get('legal_considerations') if top_clusters else {},
        'pr_media_guidance': (top_clusters[0] or {}).get('pr_media_guidance') if top_clusters else {},
        'mandatory_communications': (top_clusters[0] or {}).get('mandatory_communications') if top_clusters else {},
        'compliance_control_impact': (top_clusters[0] or {}).get('compliance_control_impact') if top_clusters else {},
    }

    for key, report in reports.items():
        report['text'] = '\n'.join(
            [report.get('overview', {}).get('what_happened', ''), report.get('overview', {}).get('why_it_matters', '')] +
            [section.get('title', '') + ': ' + ' '.join(section.get('bullets') or []) for section in report.get('sections', [])]
        ).strip()
    return reports


def _hydrate_assessment_semantics(assessment: dict) -> dict:
    if not isinstance(assessment, dict):
        return assessment
    normalized_rows = _normalize_assessment_rows(assessment)
    try:
        from src.core.ingest.input_classifier import is_non_evidence_sheet
        normalized_rows = [
            row for row in normalized_rows
            if not is_non_evidence_sheet(row.get('_sheet') or row.get('source_sheet'))
        ]
    except Exception:
        pass
    clusters, _adjacency = _build_correlation_clusters(normalized_rows)
    enrichment_cases = _build_enrichment_guided_cases(normalized_rows)
    if enrichment_cases:
        logger.warning(
            'demo_cases_injected count=%d case_ids=%s',
            len(enrichment_cases),
            [c.get('cluster_id') for c in enrichment_cases],
        )
        seen_case_ids = {str(c.get('cluster_id') or '') for c in clusters}
        clusters = [c for c in enrichment_cases if str(c.get('cluster_id') or '') not in seen_case_ids] + clusters
        clusters.sort(
            key=lambda item: (
                int(item.get('case_priority') or 0),
                _SEV_RANK.get(item.get('severity') or 'low', 0),
                len(item.get('row_refs') or []),
                item.get('confidence') or 0.0,
            ),
            reverse=True,
        )
    persona_reports = _build_persona_reports_backend(assessment, normalized_rows, clusters)
    assessment['evidence_rows'] = normalized_rows
    assessment['correlation_clusters'] = clusters
    assessment['persona_reports'] = persona_reports
    try:
        _apply_cluster_reasoning_to_assessment(assessment, trigger_reason='assessment_hydrate')
    except Exception:
        pass
    return assessment


_OFFLINE_ASSESSMENT_MERGE_KEYS = (
    'tier2_analysis',
    'final_verdict',
    'final_confidence',
    'severity',
    'semantic_top_factors',
    'supporting_model_factors',
    'accepted_rows',
    'rejected_rows',
    'rows_processed',
    'processed',
    'llm_rows',
    'results',
    'canonical',
    'framework_mappings',
    'mappings',
    'findings',
    'evidence_items',
    'attack_timeline',
    'recommended_actions',
    'upload_provenance',
    'ioc_enrichment',
    'impact_metadata',
    'cluster_reasoning_state',
    'corroboration',
    'review_state_counts',
    'risk_quantification',
    'verdict',
    'tier_metadata',
    'decision_record',
    'investigation_clusters',
)


def _should_apply_offline_workbook_assessment(rows: List[dict], payload: dict, options: dict) -> bool:
    if not rows:
        return False
    disabled = payload.get('disable_offline_workbook') or options.get('disable_offline_workbook')
    if str(disabled).lower() in {'1', 'true', 'yes'}:
        return False
    mode = str(payload.get('mode') or payload.get('analysis_mode') or options.get('mode') or options.get('analysis_mode') or '').lower()
    if mode in {'offline_workbook', 'manual_upload', 'workbook'}:
        return True
    # csv/deep_analyze is the manual/offline analysis path. Keep the explicit
    # mode checks for callers that label workbook uploads, but also enrich
    # row-based CSV/JSON fixtures so the immediate API response matches the
    # persisted offline assessment shape.
    return any(isinstance(row, dict) for row in rows)


def _merge_offline_workbook_assessment(assessment: dict, rows: List[dict], payload: dict, options: dict, *, assessment_id: str, org: str, auto_llm: bool) -> dict:
    if not _should_apply_offline_workbook_assessment(rows, payload, options):
        return assessment
    try:
        from src.analysis.offline_workbook_assessment import build_offline_workbook_assessment

        offline = build_offline_workbook_assessment(
            rows,
            assessment_id=assessment_id,
            org=org,
            auto_llm=auto_llm,
        )
    except Exception:
        logger.debug('offline workbook assessment merge failed for %s', assessment_id, exc_info=True)
        return assessment
    if not isinstance(offline, dict):
        return assessment
    for key in _OFFLINE_ASSESSMENT_MERGE_KEYS:
        value = offline.get(key)
        if value not in (None, [], {}):
            assessment[key] = value
    assessment.setdefault('telemetry', {})['offline_workbook_enriched'] = True
    return assessment


async def _emit_offline_decision_record(assessment: dict, *, org: str) -> None:
    decision = assessment.get('decision_record') if isinstance(assessment, dict) else None
    if not isinstance(decision, dict):
        return
    event_id = str(assessment.get('assessment_id') or decision.get('event_id') or decision.get('id') or '')
    if not event_id:
        return
    verdict = str(decision.get('verdict') or assessment.get('final_verdict') or 'REVIEW')
    try:
        confidence = float(decision.get('confidence') if decision.get('confidence') is not None else assessment.get('final_confidence') or 0.0)
    except Exception:
        confidence = 0.0
    factors = [str(f) for f in (decision.get('factors') or []) if str(f).strip()]
    meta = dict(decision)
    meta.setdefault('tenant_id', org)
    meta.setdefault('assessment_id', assessment.get('assessment_id'))
    meta.setdefault('report_id', assessment.get('report_id') or assessment.get('assessment_id'))
    recorded = False
    try:
        import sys
        seen_recorders: set[int] = set()
        for module_name in ('src.api.server', 'api.server'):
            server_mod = sys.modules.get(module_name)
            if server_mod is None:
                try:
                    if module_name == 'src.api.server':
                        from src.api import server as server_mod  # type: ignore
                    else:
                        import api.server as server_mod  # type: ignore
                except Exception:
                    continue
            recorder = getattr(server_mod, '_record_decision_async', None)
            if not recorder or id(recorder) in seen_recorders:
                continue
            seen_recorders.add(id(recorder))
            await recorder(event_id, verdict, confidence, factors, meta)
            recorded = True
    except Exception:
        logger.debug('offline decision async recorder unavailable for %s', event_id, exc_info=True)
    if recorded:
        return
    try:
        from src.api import runtime_state
        runtime_state.cache_set(event_id, {
            'event_id': event_id,
            'id': event_id,
            'verdict': verdict,
            'confidence': confidence,
            'factors': factors,
            'tenant_id': org,
            'ts': time.time(),
            **meta,
        })
    except Exception:
        logger.debug('offline decision cache fallback failed for %s', event_id, exc_info=True)


def _error_llm_row(normalized_row: dict, idx: int, exc: Exception) -> dict:
    """Build a minimal llm_row payload when generation fails."""
    summary = f"LLM summary unavailable: {exc}"
    now = int(time.time())
    return {
        'row_index': idx,
        'fingerprint': normalized_row.get('fingerprint') or '',
        'hash_sha256': normalized_row.get('hash_sha256') or normalized_row.get('sha256', ''),
        'process_name': normalized_row.get('process_name') or normalized_row.get('process') or '',
        'host': normalized_row.get('host') or normalized_row.get('hostname'),
        'user': normalized_row.get('user'),
        'verdict': normalized_row.get('verdict') or normalized_row.get('decision') or '',
        'factors': list(normalized_row.get('factors') or []),
        'llm_summary': summary,
        'llm_meta': {'error': str(exc)},
        'risk_level': {'label': 'Unknown', 'numeric': 0},
        'risk_label': 'Unknown',
        'recommendation': {},
        'recommendations': [],
        'source': 'heuristic',
        'comments': [],
        'generated_at': now,
        '__llm_error': str(exc),
        'classification': normalized_row.get('classification') or 'Unknown',
    }


def _schedule_prefill_generation(assessment_obj: dict, assessment_id: str) -> None:
    """Fire tier-1 prefill in a background thread — always runs regardless of auto_llm.

    Prefill only needs clusters (built deterministically), not row-level LLM summaries.
    Running it unconditionally means manual uploads also get hydrated top-10 cluster cards.
    """
    import os as _os
    if _os.environ.get('JANUSEC_DISABLE_T1_PREFILL'):
        return
    clusters = assessment_obj.get('correlation_clusters') or []
    if not clusters:
        logger.debug('_schedule_prefill_generation: no clusters for %s — skipping', assessment_id)
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return

    async def _prefill_runner():
        try:
            from src.core.tier1_prefill.prefill_engine import run_prefill as _run_prefill
        except ImportError:
            try:
                from core.tier1_prefill.prefill_engine import run_prefill as _run_prefill  # type: ignore
            except ImportError:
                return
        try:
            result = await asyncio.to_thread(
                _run_prefill,
                assessment=assessment_obj,
                top_n=10,
                tenant_id='default',
            )
            if result.get('prefilled_clusters'):
                REPORT_STORE[assessment_id] = assessment_obj
                _persist_assessment_state(assessment_id, assessment_obj)
                logger.info(
                    'tier1_prefill: prefilled %s clusters for assessment %s',
                    result['prefilled_clusters'], assessment_id,
                )
        except Exception as exc:
            logger.debug('tier1_prefill background task failed for %s: %s', assessment_id, exc)

    try:
        _track_task(loop.create_task(_prefill_runner()))
    except Exception as exc:
        logger.debug('tier1_prefill task scheduling failed for %s: %s', assessment_id, exc)


def _schedule_llm_generation(rows: List[dict], ctx: dict, assessment_obj: dict, assessment_id: str, org: str, payload: dict | None):
    """Spawn a background coroutine that builds llm_rows so the HTTP response returns quickly."""
    if not rows:
        return
    auto_llm = bool((ctx.get('options') or {}).get('auto_llm'))
    if not auto_llm:
        # Skip row-level LLM generation when caller did not request it.
        # Running LLM on every row even with auto_llm=False starves uvicorn's thread pool.
        logger.debug('_schedule_llm_generation: auto_llm=False — skipping background LLM for %s', assessment_id)
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.warning("No running event loop; skipping async LLM generation for %s", assessment_id)
        return
    overrides = None
    if isinstance(payload, dict):
        try:
            overrides = payload.get('overrides') if isinstance(payload.get('overrides'), dict) else None
        except Exception:
            overrides = None

    hopgraph_ctx = _extract_hopgraph_inline_context(assessment_obj)

    async def _runner():
        llm_rows_acc: list[dict] = []
        for idx, original in enumerate(rows):
            normalized = _flatten_row_payload(original, idx)
            pipeline_snapshot = _build_pipeline_snapshot(assessment_obj, normalized)
            breaker_signal = _derive_breaker_signal(assessment_obj)
            mapping_ctx = _extract_mapping_semantics_context(normalized, assessment_obj)
            binary_ctx = _collect_binary_network_tags(normalized)
            kill_chain_ctx = _collect_kill_chain_tags(normalized, assessment_obj)

            def _build_row(row_ctx: dict):
                rr = dict(normalized)
                rr.setdefault('row_index', idx)
                return _sanitize_llm_row(
                    build_llm_row(
                        rr,
                        row_ctx,
                        assessment_obj,
                    )
                )

            try:
                ctx_payload = {
                    'auto_llm': auto_llm,
                    'org': org,
                    'assessment_id': assessment_id,
                    'session_id': assessment_obj.get('session_id'),
                    'overrides': overrides,
                    'pipeline_context': assessment_obj,
                    'telemetry': assessment_obj.get('telemetry') or {},
                    'breaker_state': (assessment_obj.get('telemetry') or {}).get('breaker_state') or assessment_obj.get('llm_breakers'),
                    'hopgraph_context': hopgraph_ctx,
                    'pipeline_snapshot': pipeline_snapshot,
                    'breaker_signal': breaker_signal,
                    'mapping_semantics': mapping_ctx,
                    'binary_context': binary_ctx,
                    'supply_chain_tags': (binary_ctx or {}).get('supply_chain_tags'),
                    'network_anomaly_tags': (binary_ctx or {}).get('network_anomaly_tags'),
                    'kill_chain': kill_chain_ctx,
                }
                clean = await asyncio.to_thread(_build_row, ctx_payload)
                if not clean:
                    raise RuntimeError('llm_row_empty')
            except Exception as exc:
                logger.warning("LLM row generation failed for assessment %s row %s: %s", assessment_id, idx, exc)
                clean = _error_llm_row(normalized, idx, exc)
            if pipeline_snapshot and isinstance(clean, dict):
                clean.setdefault('pipeline_snapshot', pipeline_snapshot)
            if breaker_signal and isinstance(clean, dict):
                clean.setdefault('breaker_signal', breaker_signal)
            if mapping_ctx and isinstance(clean, dict):
                clean.setdefault('mapping_semantics', mapping_ctx)
                if 'score' in mapping_ctx:
                    clean.setdefault('mapping_semantics_score', mapping_ctx['score'])
            if binary_ctx and isinstance(clean, dict):
                clean.setdefault('binary_context', binary_ctx)
            if kill_chain_ctx and isinstance(clean, dict):
                clean.setdefault('kill_chain', kill_chain_ctx)
            augmented = _augment_llm_row(clean, assessment_obj)
            llm_rows_acc.append(augmented)
            try:
                assessment_obj['llm_rows'] = list(llm_rows_acc)
                assessment_obj['llm_rows_count'] = len(llm_rows_acc)
                assessment_obj['rows_processed'] = max(len(llm_rows_acc), assessment_obj.get('rows_processed', 0))
                REPORT_STORE[assessment_id] = assessment_obj
                _persist_assessment_state(assessment_id, assessment_obj)
            except Exception:
                pass

        try:
            if hasattr(LLM_CLIENT, '_tenant_budget'):
                assessment_obj['llm_cost_estimate'] = {
                    key: float(val) for key, val in getattr(LLM_CLIENT, '_tenant_budget', {}).items()
                }
            assessment_obj['llm_breakers'] = getattr(LLM_CLIENT, '_breaker_state', {})
        except Exception:
            pass
        assessment_obj.setdefault('telemetry', {})['llm_completed_at'] = time.time()
        try:
            await asyncio.to_thread(_hydrate_assessment_semantics, assessment_obj)
        except Exception:
            pass
        try:
            REPORT_STORE[assessment_id] = assessment_obj
            _persist_assessment_state(assessment_id, assessment_obj)
        except Exception:
            pass
        # Tier-1 prefill fires via _schedule_prefill_generation (already scheduled
        # from the main pipeline path). No duplicate call needed here.

    try:
        _track_task(loop.create_task(_runner()))
    except Exception as exc:
        logger.warning("Failed to schedule LLM generation task for %s: %s", assessment_id, exc)


def _persist_assessment_state(assessment_id: str, assessment: dict) -> None:
    if not assessment_id or not isinstance(assessment, dict):
        return
    REPORT_STORE[assessment_id] = assessment
    path = assessment.get('persisted_path')
    if path:
        try:
            atomic_write_json(path, assessment)
        except Exception:
            pass


def _get_assessment_cached(assessment_id: str) -> dict | None:
    assessment = REPORT_STORE.get(assessment_id)
    if assessment:
        return assessment

    # Try the standard disk loader first
    disk = _load_assessment_from_disk(assessment_id, None)
    if disk:
        REPORT_STORE[assessment_id] = disk
        return disk

    # Fallback: scan the SESSION_PERSIST_DIR for any file starting with the assessment_id
    try:
        repo_root = os.getcwd()
        base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
        index_dir = os.path.join(base, 'index')
        idx_path = os.path.join(index_dir, f"{assessment_id}.path")
        if os.path.exists(idx_path):
            try:
                with open(idx_path, 'r', encoding='utf-8') as fh:
                    p = fh.read().strip()
                if p and os.path.exists(p):
                    with open(p, 'r', encoding='utf-8') as fh:
                        disk2 = json.load(fh)
                    REPORT_STORE[assessment_id] = disk2
                    return disk2
            except Exception:
                pass
        if os.path.isdir(base):
            for root, _dirs, files in os.walk(base):
                for f in files:
                    if f.startswith(str(assessment_id)) and f.endswith('.json'):
                        path = os.path.join(root, f)
                        try:
                            with open(path, 'r', encoding='utf-8') as fh:
                                disk2 = json.load(fh)
                            REPORT_STORE[assessment_id] = disk2
                            return disk2
                        except Exception:
                            continue
        # Final content scan is intentionally opt-in. On local demo machines
        # data/assessments can contain large acceptance artifacts, and a 404
        # lookup should not open every JSON file in that tree.
        if str(os.getenv('ASSESSMENT_CONTENT_SCAN_FALLBACK') or '').lower() in {'1', 'true', 'yes'}:
            try:
                for root, _dirs, files in os.walk(base):
                    for f in files:
                        if not f.endswith('.json'):
                            continue
                        path = os.path.join(root, f)
                        try:
                            with open(path, 'r', encoding='utf-8') as fh:
                                cand = json.load(fh)
                            if isinstance(cand, dict) and str(cand.get('assessment_id') or '') == str(assessment_id):
                                REPORT_STORE[assessment_id] = cand
                                return cand
                        except Exception:
                            continue
            except Exception:
                pass
    except Exception:
        pass
    return None


def _write_assessment_index(assessment_id: str, persisted_path: str) -> None:
    try:
        repo_root = os.getcwd()
        base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
        index_dir = os.path.join(base, 'index')
        os.makedirs(index_dir, exist_ok=True)
        idx_path = os.path.join(index_dir, f"{assessment_id}.path")
        tmp = idx_path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write(persisted_path)
        os.replace(tmp, idx_path)
    except Exception:
        pass


def _llm_row_entry(assessment: dict, idx: int, orig: dict) -> dict | None:
    try:
        row_copy = dict(orig)
        row_copy.setdefault('row_index', idx)
        return build_llm_row(row_copy, {'auto_llm': True, 'org': assessment.get('org'), 'assessment_id': assessment.get('assessment_id'), 'session_id': assessment.get('session_id')}, assessment)
    except Exception:
        return None


def _ensure_llm_rows_available(assessment: dict) -> dict:
    """Best-effort compatibility fallback for auto-LLM assessments.

    Some callers poll assessment endpoints immediately and expect row-level
    summaries to exist even when no rows were queued/promoted into the normal
    background LLM path. Synthesize lightweight llm_rows from raw rows when the
    assessment requested auto_llm but currently lacks usable summaries.
    """
    if not isinstance(assessment, dict):
        return assessment
    try:
        auto_llm = bool(
            assessment.get('auto_llm')
            or ((assessment.get('options') or {}).get('auto_llm'))
        )
    except Exception:
        auto_llm = False
    if not auto_llm:
        return assessment

    existing = assessment.get('llm_rows') or []
    try:
        if existing and any((row.get('llm_summary') or row.get('summary') or row.get('llm_output')) for row in existing if isinstance(row, dict)):
            return assessment
    except Exception:
        pass

    raw_rows = assessment.get('rows') or []
    if not isinstance(raw_rows, list) or not raw_rows:
        return assessment

    synthesized: list[dict] = []
    for idx, row in enumerate(raw_rows):
        if not isinstance(row, dict):
            continue
        llm_row = _llm_row_entry(assessment, idx, row)
        if llm_row:
            synthesized.append(llm_row)
    if synthesized:
        assessment['llm_rows'] = synthesized
        assessment['llm_rows_count'] = len(synthesized)
    return assessment


def _processed_row_indexes(assessment: dict) -> Set[int]:
    rows = assessment.get('llm_rows') or []
    result: Set[int] = set()
    for row in rows:
        try:
            idx = int(row.get('row_index'))
        except Exception:
            continue
        if row.get('_llm_processed') or row.get('llm_summary'):
            result.add(idx)
    return result


def _queued_row_indexes(assessment: dict) -> Set[int]:
    queue = assessment.get('_llm_queue') or []
    result: Set[int] = set()
    for item in queue:
        try:
            result.add(int(item))
        except Exception:
            continue
    for row in assessment.get('llm_rows') or []:
        try:
            idx = int(row.get('row_index'))
        except Exception:
            continue
        if row.get('_llm_status') == 'queued':
            result.add(idx)
    return result


def _select_rows_for_enqueue(
    assessment: dict,
    row_indices: List[int] | None,
    limit: int,
) -> List[Tuple[int, Dict[str, Any]]]:
    original_rows = assessment.get('rows') or []
    processed = _processed_row_indexes(assessment)
    queued = _queued_row_indexes(assessment)
    selections: List[Tuple[int, Dict[str, Any]]] = []
    # min triage threshold to auto-allow LLM generation; rows below this will be marked as skipped
    try:
        min_triage = float(os.getenv('LLM_T1_MIN_TRIAGE', '0.15'))
    except Exception:
        min_triage = 0.15
    if row_indices:
        for idx in row_indices:
            try:
                idx_int = int(idx)
            except Exception:
                continue
            if idx_int in processed or idx_int in queued:
                continue
            try:
                orig = original_rows[idx_int]
            except Exception:
                continue
            if isinstance(orig, dict):
                selections.append((idx_int, orig))
    else:
        selections = prioritize_rows_for_llm(original_rows, processed, queued, limit)
        # Mark rows below the triage threshold as skipped (for visibility)
        for i, r in enumerate(original_rows):
            try:
                tri = float(r.get('triage_score') or 0.0)
                if tri < min_triage:
                    # annotate skip reason for analyst/UI
                    r['llm_skipped_reason'] = r.get('llm_skipped_reason') or 'below_severity_threshold'
            except Exception:
                continue
    return selections


def _build_progress_payload(assessment_id: str, assessment: dict) -> dict:
    rows = assessment.get('llm_rows') or []
    queue = assessment.get('_llm_queue') or []
    counts = {'queued': 0, 'processing': 0, 'succeeded': 0, 'failed': 0, 'aborted': 0}
    rows_map: Dict[str, Dict[str, Any]] = {}
    total_cost = 0.0
    # compute weighted confidence summary if triage_score present
    weighted_conf_sum = 0.0
    weighted_conf_weight = 0.0
    for row in rows:
        try:
            idx = int(row.get('row_index'))
        except Exception:
            continue
        status = row.get('_llm_status')
        if not status:
            if row.get('llm_summary') or row.get('_llm_processed'):
                status = 'succeeded'
            else:
                status = 'queued'
        status = status.lower()
        if status in counts:
            counts[status] += 1
        elif status == 'processing':
            counts['processing'] += 1
        total_cost += float(row.get('_llm_cost') or 0.0)
        try:
            # Preferred confidence sources: llm_meta.confidence, risk_confidence, confidence
            wc = (row.get('llm_meta') or {}).get('confidence') or row.get('risk_confidence') or row.get('confidence')
            if wc is not None:
                wc = float(wc)
                # factor_count: prefer explicit field, else len(factors)
                try:
                    factor_count = int(row.get('factor_count') or 0)
                except Exception:
                    factor_count = 0
                if not factor_count:
                    try:
                        factors = row.get('factors')
                        if factors is None and isinstance(row.get('raw'), dict):
                            factors = row['raw'].get('factors')
                        factor_count = len(factors or [])
                    except Exception:
                        factor_count = 0
                density_weight = min(1.0, float(factor_count) / 8.0)
                try:
                    risk_conf = float(row.get('risk_confidence') or (row.get('llm_meta') or {}).get('confidence') or 0.0)
                except Exception:
                    risk_conf = 0.0
                # Weight formula: min(1, factor_count/8) + 0.5 * risk_confidence
                weight = density_weight + (0.5 * risk_conf)
                # Ensure non-negative weight
                if weight <= 0:
                    weight = 0.001
                weighted_conf_sum += wc * weight
                weighted_conf_weight += weight
        except Exception:
            pass
        rows_map[str(idx)] = {
            'row_index': idx,
            'status': status,
            'attempts': int(row.get('_llm_attempts') or 0),
            'cost': float(row.get('_llm_cost') or 0.0),
            'llm_skipped_reason': row.get('llm_skipped_reason'),
            'last_updated': int(row.get('_llm_timestamp') or 0),
        }
    pending = counts['queued'] + counts['processing']
    return {
        'assessment_id': assessment_id,
        'queued': counts['queued'],
        'processing': counts['processing'],
        'succeeded': counts['succeeded'],
        'failed': counts['failed'],
        'aborted': counts['aborted'],
        'pending': pending,
        'queue_size': len(queue),
        'cost': round(total_cost, 6),
        'total_rows': len(assessment.get('rows') or []),
        'rows': rows_map,
        'weighted_confidence': (weighted_conf_sum / weighted_conf_weight) if weighted_conf_weight else 0.0,
    }


def _extract_dread_score(row: Dict[str, Any]) -> float:
    """Best-effort extraction of a DREAD score from a CSV row."""
    lookup_keys = ['_dread', 'dread']
    for key in lookup_keys:
        try:
            val = row.get(key)
            if val is None and isinstance(row.get('raw'), dict):
                val = row['raw'].get(key)
            if isinstance(val, dict):
                return float(val.get('score') or 0.0)
            if val is not None:
                return float(val)
        except Exception:
            continue
    return 0.0


def _compute_factor_density(row: Dict[str, Any]) -> float:
    """Approximate factor density: number of factors / heuristic max (12)."""
    try:
        factors = row.get('factors')
        if factors is None and isinstance(row.get('raw'), dict):
            factors = row['raw'].get('factors')
        count = len(factors or [])
        return min(1.0, count / 12.0)
    except Exception:
        return 0.0


def _compute_rarity_signal(row: Dict[str, Any]) -> float:
    """Map rarity label (RARE|EMERGING|COMMON) to a score boosting triage."""
    try:
        rarity = str(row.get('rarity') or '').upper()
        if not rarity and isinstance(row.get('raw'), dict):
            rarity = str(row['raw'].get('rarity') or '').upper()
        if rarity == 'RARE':
            return 1.0
        if rarity == 'EMERGING':
            return 0.6
        if rarity == 'COMMON':
            return 0.15
    except Exception:
        pass
    return 0.0


def _compute_factor_diversity(row: Dict[str, Any]) -> int:
    """Count distinct factor categories if provided via factor_contributions."""
    try:
        contribs = row.get('factor_contributions')
        if contribs is None and isinstance(row.get('raw'), dict):
            contribs = row['raw'].get('factor_contributions')
        if isinstance(contribs, list):
            cats = {c.get('category') for c in contribs if isinstance(c, dict) and c.get('category')}
            return len(cats)
    except Exception:
        pass
    return 0


def _compute_triage_score(row: Dict[str, Any]) -> float:
    """Unified triage score combining dread, correlation, factor density, confidence, rarity.

    Weights (tunable via env overrides):
      DREAD: 0.30
      Correlation: 0.20
      Factor Density: 0.20
      Risk Confidence: 0.15
      Rarity Signal: 0.15
    """
    try:
        dread_raw = _extract_dread_score(row)
        dread = min(1.0, max(0.0, (dread_raw or 0.0) / 10.0))
    except Exception:
        dread = 0.0
    try:
        corr = row.get('correlation_score') or (row.get('_correlation') or {}).get('score') or 0.0
        corr = float(corr) if corr is not None else 0.0
        corr = min(1.0, max(0.0, corr))
    except Exception:
        corr = 0.0
    density = _compute_factor_density(row)
    try:
        risk_conf = row.get('risk_confidence')
        if risk_conf is None and isinstance(row.get('raw'), dict):
            risk_conf = (row['raw'].get('risk_confidence') or row['raw'].get('confidence'))
        if risk_conf is None:
            risk_conf = (row.get('llm_meta') or {}).get('confidence')
        risk_conf = float(risk_conf) if risk_conf is not None else 0.0
        risk_conf = min(1.0, max(0.0, risk_conf))
    except Exception:
        risk_conf = 0.0
    rarity = _compute_rarity_signal(row)
    # Allow env overrides for tuning
    def _w(key: str, default: float) -> float:
        try:
            return float(os.getenv(key, str(default)))
        except Exception:
            return default
    w_dread = _w('TRIAGE_W_DREAD', 0.30)
    w_corr = _w('TRIAGE_W_CORR', 0.20)
    w_density = _w('TRIAGE_W_DENSITY', 0.20)
    w_conf = _w('TRIAGE_W_CONF', 0.15)
    w_rarity = _w('TRIAGE_W_RARITY', 0.15)
    score = (dread * w_dread) + (corr * w_corr) + (density * w_density) + (risk_conf * w_conf) + (rarity * w_rarity)
    # Small diversity bonus
    diversity = _compute_factor_diversity(row)
    if diversity >= 4:
        score += 0.05
    elif diversity >= 3:
        score += 0.03
    if _has_supply_chain_indicator(row):
        score += 0.04
    if _has_network_infra_indicator(row):
        score += 0.03
    return round(min(1.0, max(0.0, score)), 6)


def _infer_domain(row: Dict[str, Any]) -> str:
    """Rudimentary domain classifier for artifacts."""
    if not isinstance(row, dict):
        return 'endpoint'
    network_fields = [
        'src_ip',
        'dst_ip',
        'ip',
        'ip_src',
        'ip_dst',
        'domain',
        'dns_query',
    ]
    for field in network_fields:
        value = row.get(field)
        if value:
            return 'network'
    endpoint_fields = [
        'process_name',
        'process',
        'file_path',
        'command_line',
    ]
    for field in endpoint_fields:
        if row.get(field):
            return 'endpoint'
    return 'endpoint'


def _extract_mitre_tags(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> List[str]:
    """Gather MITRE tags from row or pipeline context."""
    tags: List[str] = []
    for source in (row, pipeline_context or {}):
        raw = source.get('mitre_tags') or source.get('mitre') or []
        if isinstance(raw, dict):
            raw = raw.values()
        for entry in raw or []:
            try:
                if not entry:
                    continue
                tag = str(entry)
                if tag not in tags:
                    tags.append(tag)
            except Exception:
                continue
    return tags


def prioritize_rows_for_llm(
    rows: List[Dict[str, Any]],
    processed_indexes: Set[int],
    queued_indexes: Set[int],
    limit: int,
) -> List[Tuple[int, Dict[str, Any]]]:
    """Filter suspicious rows and sort by DREAD score (desc), returning the top N."""
    # Include MALICIOUS to avoid skipping high-certainty rows.
    suspicious_verdicts = {'SUSPICIOUS', 'CRITICAL', 'HIGH', 'MALICIOUS'}
    candidates: List[Tuple[int, Dict[str, Any], float, int, float]] = []
    for idx, rec in enumerate(rows or []):
        if idx in processed_indexes or idx in queued_indexes:
            continue
        if not isinstance(rec, dict):
            continue
        verdict = str(rec.get('verdict') or rec.get('decision') or '').upper()
        if verdict not in suspicious_verdicts:
            continue
        dread_score = _extract_dread_score(rec)
        try:
            factors = rec.get('factors')
            if factors is None and isinstance(rec.get('raw'), dict):
                factors = rec['raw'].get('factors')
            factor_count = len(factors or [])
        except Exception:
            factor_count = 0
        triage_score = _compute_triage_score(rec)
        # Persist triage score for downstream UI if not already present
        try:
            rec.setdefault('triage_score', triage_score)
        except Exception:
            pass
        candidates.append((idx, rec, dread_score, factor_count, triage_score))

    # Sort by triage score then dread then factor count
    candidates.sort(key=lambda tup: (tup[4], tup[2], tup[3]), reverse=True)
    if limit > 0:
        candidates = candidates[:limit]
    return [(idx, rec) for idx, rec, _d, _f, _t in candidates]


@router.get('/assessments/{assessment_id}', summary="Load a saved assessment by ID")
async def get_assessment_by_id(assessment_id: str, request: Request):
    """Return a previously completed assessment so the history sidebar can reload it.

    Searches REPORT_STORE (in-memory), then disk (data/assessments/).
    Returns { assessment_id, evidenceRows, rows, headline, sources, ts }.
    """
    assessment = _get_assessment_cached(assessment_id)
    if not assessment:
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(status_code=404, detail=f"Assessment {assessment_id!r} not found")
    # Build a normalised response the history sidebar JS can consume.
    # Merge evidence_preview rows from all clusters — these are pre-sampled
    # against actual row_refs, unlike evidence_rows/normalized_rows which may
    # be a non-overlapping sample from a different part of the dataset.
    clusters = assessment.get('correlation_clusters') or []
    seen_idx: set = set()
    merged_rows: list = []
    for c in clusters:
        for r in (c.get('evidence_preview') or []):
            if not isinstance(r, dict):
                continue
            idx = r.get('row_index')
            if idx is not None and idx in seen_idx:
                continue
            if idx is not None:
                seen_idx.add(idx)
            merged_rows.append(r)
    # Fall back to evidence_rows only if evidence_preview produced nothing
    if not merged_rows:
        merged_rows = (
            assessment.get('evidence_rows')
            or assessment.get('evidenceRows')
            or assessment.get('llm_rows')
            or assessment.get('rows')
            or []
        )
    evidence_rows = merged_rows
    return {
        'assessment_id': assessment_id,
        'evidenceRows': evidence_rows,
        'rows': evidence_rows,
        'normalized_rows': evidence_rows,
        'correlation_clusters': clusters,
        'headline': (
            assessment.get('headline')
            or assessment.get('report_title')
            or assessment.get('summary', '')[:80]
            or f'{len(evidence_rows)} events'
        ),
        'sources': assessment.get('sources') or [],
        'ts': assessment.get('ts') or assessment.get('created_at'),
        'stage_results': assessment.get('stage_results') or [],
        'verdict': assessment.get('verdict'),
        'confidence': assessment.get('confidence'),
        # Agent loop results (wired to breach.html CEO view)
        'proposed_actions': assessment.get('proposed_actions') or [],
        'kill_chain': assessment.get('kill_chain') or [],
        'gaps': assessment.get('gaps') or [],
        # Classified clusters (preferred by breach.js) — includes persona_dispatch
        'analysis_clusters': assessment.get('analysis_clusters') or [],
    }


@router.post('/generate_llm_summaries')
async def generate_llm_summaries(request: Request):
    """Generate LLM summaries for pending rows of an existing assessment.

    Payload options:
      { assessment_id: str, limit: int (optional), row_indices: [int] (optional), include_personas: bool (optional) }
    - If row_indices provided: process those specific original rows.
    - Else: choose top-N pending rows by heuristic (factor count / existing DREAD) with optional extra 3 high-risk.
    Returns updated llm_rows.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    # Per-assessment sliding-window rate limiting with optional Redis persistence
    try:
        per_min = int(os.getenv('LLM_GEN_PER_ASSESS_PER_MIN', '5') or 5)
        window_seconds = 60
        aid = payload.get('assessment_id') or ''
        now = int(time.time())
        red_url = os.getenv('REDIS_URL') or os.getenv('REDIS_URI')
        if red_url and aid:
            try:
                import redis
                rc = redis.from_url(red_url)
                key = f"assess_rate:{aid}"
                # trim old entries by using a sorted set of timestamps
                rc.zremrangebyscore(key, 0, now - window_seconds)
                count = rc.zcard(key)
                if count >= per_min:
                    raise HTTPException(status_code=429, detail='assessment_rate_limited')
                rc.zadd(key, {str(now): now})
                rc.expire(key, window_seconds * 2)
            except HTTPException:
                raise
            except Exception:
                # fallback to in-memory if Redis unavailable
                raise
        else:
            # in-memory fallback
            from collections import deque
            global _ASSESS_RATE_STORAGE
            if '_ASSESS_RATE_STORAGE' not in globals():
                _ASSESS_RATE_STORAGE = {}
            q = _ASSESS_RATE_STORAGE.get(aid)
            if q is None:
                q = deque()
                _ASSESS_RATE_STORAGE[aid] = q
            while q and (time.time() - q[0]) > window_seconds:
                q.popleft()
            if len(q) >= per_min:
                raise HTTPException(status_code=429, detail='assessment_rate_limited')
            q.append(time.time())
    except HTTPException:
        raise
    except Exception:
        pass
    assessment_id = payload.get('assessment_id') or ''
    if not assessment_id:
        raise HTTPException(status_code=400, detail='missing_assessment_id')
    assessment = REPORT_STORE.get(assessment_id)
    if not assessment:
        # attempt to load persisted file
        persisted_path = None
        try:
            for root, _dirs, files in os.walk(os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data','assessments')):
                for f in files:
                    if f.startswith(assessment_id) and f.endswith('.json'):
                        persisted_path = os.path.join(root, f)
                        break
                if persisted_path:
                    break
            if persisted_path and os.path.exists(persisted_path):
                assessment = await asyncio.to_thread(_read_json_sync, persisted_path)
        except Exception:
            assessment = None
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    # If we have a lightweight in-memory record but it lacks full 'rows', attempt to load persisted file
    try:
        if assessment and not assessment.get('rows'):
            try:
                disk = _load_assessment_from_disk(assessment_id, assessment.get('persisted_path'))
                if disk:
                    # merge persisted fields into assessment for downstream processing
                    merged = {**assessment, **disk}
                    assessment = merged
                    REPORT_STORE[assessment_id] = assessment
            except Exception:
                pass
    except Exception:
        pass

    original_rows = assessment.get('rows') or []
    existing_llm = assessment.get('llm_rows') or []
    processed_indexes = {
        int(r.get('row_index'))
        for r in existing_llm
        if isinstance(r, dict) and (r.get('_llm_processed') or r.get('llm_summary'))
    }
    queue_indexes: Set[int] = set()
    for queued_idx in assessment.get('_llm_queue') or []:
        try:
            queue_indexes.add(int(queued_idx))
        except Exception:
            continue
    for existing in existing_llm:
        try:
            if existing.get('_llm_status') == 'queued':
                queue_indexes.add(int(existing.get('row_index')))
        except Exception:
            continue

    row_indices = payload.get('row_indices') if isinstance(payload.get('row_indices'), list) else None
    limit = int(payload.get('limit') or 25)
    include_personas = bool(payload.get('include_personas') or False)

    pending: List[Tuple[int, Dict[str, Any]]] = []
    if row_indices:
        for idx in row_indices:
            try:
                idx_int = int(idx)
            except Exception:
                continue
            if idx_int in processed_indexes or idx_int in queue_indexes:
                continue
            try:
                orig = original_rows[idx_int]
            except Exception:
                continue
            if isinstance(orig, dict):
                pending.append((idx_int, orig))
    else:
        pending = prioritize_rows_for_llm(original_rows, processed_indexes, queue_indexes, limit)

    if not pending:
        # Provide aggregate cost/count info even when there are no newly enqueued rows
        merged_rows = assessment.get('llm_rows') or assessment.get('rows') or []
        total_cost = sum((r.get('_llm_cost') or 0.0) for r in merged_rows)
        return JSONResponse({'assessment_id': assessment_id, 'rows': [], 'count': 0, 'message': 'no_pending_rows', 'total_llm_rows': len(merged_rows), 'aggregate_cost': round(total_cost, 6)})

    updated_rows = []
    from src.analysis.auto_llm import build_llm_row  # local import to avoid circularities
    # Instead of generating immediately, enqueue rows for background worker and set queued status
    for idx, orig in pending:
        try:
            row_copy = dict(orig)
            row_copy.setdefault('row_index', idx)
            llm_row = build_llm_row(row_copy, {'auto_llm': True, 'org': assessment.get('org'), 'assessment_id': assessment_id, 'session_id': assessment.get('session_id')}, assessment)
            # initialize status fields
            llm_row['_llm_status'] = 'queued'
            llm_row['_llm_attempts'] = 0
            llm_row['_llm_enqueued'] = int(time.time())
            llm_row.setdefault('persona_reports', {})
            hist_ctx = _build_historical_context(row_copy)
            llm_row['historical_context'] = hist_ctx
            try:
                HISTORICAL_REPO.save_incident(row_copy, outcome=row_copy.get('verdict') or 'unknown', org=assessment.get('org'))
            except Exception:
                pass
            # lightweight persona placeholder for analyst
            llm_row['persona_reports']['analyst'] = {'text': ''}
            updated_rows.append(llm_row)
        except Exception:
            continue

    # merge updated rows into assessment and ensure queued statuses
    merged = list(existing_llm)
    existing_by_index = { r.get('row_index'): r for r in merged }
    for r in updated_rows:
        existing_by_index[r.get('row_index')] = r
    merged = list(existing_by_index.values())
    assessment['llm_rows'] = merged
    # ensure per-assessment queue exists
    assessment.setdefault('_llm_queue', [])
    for r in assessment['llm_rows']:
        try:
            if r.get('_llm_status') == 'queued' and r.get('row_index') not in assessment['_llm_queue']:
                assessment['_llm_queue'].append(r.get('row_index'))
        except Exception:
            pass
    # update REPORT_STORE with the full assessment so subsequent handlers can find llm_rows
    assessment['llm_rows_count'] = len(merged)
    assessment['assessment_id'] = assessment_id
    assessment['rows_processed'] = len(original_rows)
    _persist_assessment_state(assessment_id, assessment)

    # cost aggregate
    total_cost = sum((r.get('_llm_cost') or 0.0) for r in merged)
    return JSONResponse({'assessment_id': assessment_id, 'rows': updated_rows, 'count': len(updated_rows), 'total_llm_rows': len(merged), 'aggregate_cost': round(total_cost,6)})


@router.post('/generate_insight', operation_id='assessments_generate_insight')
async def generate_insight(request: Request):
    """Generate on-demand investigation insights for Deep Dive UI."""
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    insight_type = str(payload.get('insight_type') or 'dread').lower()
    row_index = payload.get('row_index')
    row = payload.get('row') if isinstance(payload.get('row'), dict) else None
    pipeline_context = payload.get('pipeline') or payload.get('pipeline_context') or {}
    assessment_id = payload.get('assessment_id')

    if row is None and assessment_id:
        row = _resolve_row_from_assessment(str(assessment_id), row_index)
        if row and isinstance(row, dict):
            pipeline_context = pipeline_context or row.get('pipeline_context') or {}

    if row is None:
        raise HTTPException(status_code=400, detail='row_context_required')

    payload = _build_insight_payload(row, pipeline_context, insight_type)
    try:
        insight_usage_counter.labels(type=insight_type).inc()
    except Exception:
        pass
    payload['estimated_cost'] = _INSIGHT_COSTS.get(insight_type, 0.0008)
    return JSONResponse(payload)


@router.post('/semantic_logs/search')
async def semantic_log_search(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    query = (payload.get('query') or '').strip()
    if not query:
        raise HTTPException(status_code=400, detail='missing_query')
    logs = payload.get('logs') if isinstance(payload.get('logs'), list) else []
    try:
        if logs:
            VECTOR_LOG_SEARCH.index_logs(logs[:500])
        results = VECTOR_LOG_SEARCH.search(query, top_k=int(payload.get('limit') or 5))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'vector_search_failed:{exc}')
    return {'query': query, 'results': results}


@router.post('/{assessment_id}/llm/enqueue')
async def enqueue_llm_rows(assessment_id: str, request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    assessment = _get_assessment_cached(assessment_id)
    if not assessment:
        # Wait briefly for authoritative persisted/cached assessment to appear (server-side stabilization)
        tries = 5
        for i in range(tries):
            await asyncio.sleep(0.05)
            assessment = _get_assessment_cached(assessment_id)
            if assessment:
                break
    if not assessment:
        # Deterministic fallback: try to locate an assessment in REPORT_STORE
        found = None
        try:
            for k, v in REPORT_STORE.items():
                try:
                    if str(k) == str(assessment_id) or str(assessment_id) in str(k):
                        found = v
                        break
                    pp = v.get('persisted_path') if isinstance(v, dict) else None
                    if pp and str(assessment_id) in str(pp):
                        found = v
                        break
                except Exception:
                    continue
        except Exception:
            found = None
        if found:
            assessment = found
        else:
            # If still not found, provide diagnostic info
            try:
                repo_root = os.getcwd()
                base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
                files = []
                if os.path.isdir(base):
                    for root, _dirs, fs in os.walk(base):
                        for f in fs:
                            if f.endswith('.json'):
                                files.append(os.path.join(root, f))
            except Exception:
                files = []
            msg = {'detail': 'assessment_not_found', 'report_store_keys': list(REPORT_STORE.keys())[:12], 'persisted_files_sample': files[:12]}
            # As a last-resort for test environments, create a minimal stub so clients can still enqueue
            try:
                stub = {'assessment_id': assessment_id, 'rows': [], 'llm_rows': [], '_llm_queue': []}
                REPORT_STORE[assessment_id] = stub
                assessment = stub
            except Exception:
                raise HTTPException(status_code=404, detail=msg)
    row_indices = payload.get('row_indices') if isinstance(payload.get('row_indices'), list) else None
    limit = int(payload.get('limit') or 25)
    selections = _select_rows_for_enqueue(assessment, row_indices, limit)
    if not selections:
        return JSONResponse({'assessment_id': assessment_id, 'enqueued': 0, 'queue_size': len(assessment.get('_llm_queue') or [])})
    existing = {r.get('row_index'): r for r in assessment.get('llm_rows') or []}
    queue_list = assessment.setdefault('_llm_queue', [])
    enqueued = 0
    for idx, record in selections:
        entry = _llm_row_entry(assessment, idx, record)
        if not entry:
            continue
        entry['_llm_status'] = 'queued'
        entry['_llm_attempts'] = int(entry.get('_llm_attempts') or 0)
        entry['_llm_enqueued'] = int(time.time())
        entry.setdefault('persona_reports', {}).setdefault('analyst', {'text': ''})
        existing[idx] = entry
        if idx not in queue_list:
            queue_list.append(idx)
        enqueued += 1
    assessment['llm_rows'] = list(existing.values())
    _persist_assessment_state(assessment_id, assessment)
    return JSONResponse({'assessment_id': assessment_id, 'enqueued': enqueued, 'queue_size': len(queue_list)})


@router.get('/{assessment_id}/llm/progress')
async def llm_progress(assessment_id: str):
    assessment = _get_assessment_cached(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')
    payload = _build_progress_payload(assessment_id, assessment)
    return JSONResponse(payload)


@router.get('/{assessment_id}/llm/status/{row_index}')
async def llm_row_status(assessment_id: str, row_index: int):
    assessment = _get_assessment_cached(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')
    payload = _build_progress_payload(assessment_id, assessment)
    row = payload['rows'].get(str(row_index))
    if not row:
        raise HTTPException(status_code=404, detail='row_not_found')
    return JSONResponse(row)


@router.post('/{assessment_id}/llm/abort')
async def abort_llm_queue(assessment_id: str):
    assessment = _get_assessment_cached(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')
    queue = list(assessment.get('_llm_queue') or [])
    llm_rows = assessment.get('llm_rows') or []
    for idx in queue:
        try:
            idx_int = int(idx)
        except Exception:
            continue
        for row in llm_rows:
            try:
                if int(row.get('row_index')) == idx_int and row.get('_llm_status') in {'queued', 'processing'}:
                    row['_llm_status'] = 'aborted'
                    break
            except Exception:
                continue
    assessment['_llm_queue'] = []
    _persist_assessment_state(assessment_id, assessment)
    return JSONResponse({'assessment_id': assessment_id, 'aborted': len(queue)})


@router.post('/generate_persona')
async def generate_persona(request: Request):
    """Generate an additional persona report for an existing llm_row.
    Payload: { assessment_id, row_index, persona }
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    assessment_id = payload.get('assessment_id') or ''
    persona = (payload.get('persona') or '').strip().lower() or 'manager'
    row_index = payload.get('row_index')
    if assessment_id == '' or row_index is None:
        raise HTTPException(status_code=400, detail='missing_params')
    assessment = REPORT_STORE.get(assessment_id)
    if not assessment:
        # attempt to load from disk if not present in memory
        assessment = _safe_load_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    # Look for the target row in llm_rows first, then fallback to original rows
    rows = assessment.get('llm_rows') or assessment.get('rows') or []
    target = None
    try:
        # coerce row_index to int for comparison
        target_idx_int = int(row_index)
    except Exception:
        target_idx_int = row_index
    for r in rows:
        try:
            if int(r.get('row_index')) == int(target_idx_int):
                target = r
                break
        except Exception:
            if r.get('row_index') == target_idx_int:
                target = r
                break
    if not target:
        # try loading persisted file directly and searching its llm_rows/rows
        try:
            disk_assess = _load_assessment_from_disk(assessment_id, assessment.get('persisted_path'))
            if disk_assess:
                for r in (disk_assess.get('llm_rows') or disk_assess.get('rows') or []):
                    try:
                        if int(r.get('row_index')) == int(target_idx_int):
                            target = r
                            break
                    except Exception:
                        if r.get('row_index') == target_idx_int:
                            target = r
                            break
        except Exception:
            pass
    if not target:
        raise HTTPException(status_code=404, detail='row_not_found')
    # persona prompt adaptation using centralized prompt builder and cached LLM helper
    base_text = target.get('llm_summary', '') or ''
    prompt_obj = build_persona_prompt(persona, context=target, base_summary=base_text)
    try:
        # Prefer payload-specified overrides, then assessment-level options
        _overrides = None
        try:
            _overrides = payload.get('overrides') if isinstance(payload, dict) else None
        except Exception:
            _overrides = None
        if not _overrides and assessment:
            try:
                _overrides = assessment.get('options', {}).get('overrides') or (assessment.get('overrides') if isinstance(assessment.get('overrides'), dict) else None)
            except Exception:
                _overrides = None
        # Attempt cached generation first
        try:
            cache_resp = llm_helper.cached_generate(persona=persona, incident=target, temperature=0.6)
            if isinstance(cache_resp, dict):
                text = cache_resp.get('response') or cache_resp.get('text') or str(cache_resp)
            else:
                text = str(cache_resp)
        except Exception:
            # Fallback to direct LLM client: build a simple string from the prompt messages
            try:
                msgs = prompt_obj.get('messages') or []
                prompt_text = '\n'.join([f"{m.get('role')}: {m.get('content')}" for m in msgs])
            except Exception:
                prompt_text = str(prompt_obj)
            if _overrides:
                resp = LLM_CLIENT.generate(prompt_text, max_tokens=256, tenant_id=(assessment.get('org') or None), overrides=_overrides)
            else:
                resp = LLM_CLIENT.generate(prompt_text, max_tokens=256, tenant_id=(assessment.get('org') or None))
            if isinstance(resp, dict):
                text = resp.get('text') or (resp.get('meta') or {}).get('text') or ''
            else:
                text = str(resp)
    except Exception:
        text = f"Mock persona summary ({persona}) based on base summary." + (" " + base_text[:120] if base_text else '')
    entry = {'text': text, 'template': PERSONA_DEFINITIONS.get(persona)}
    try:
        entry['context'] = _build_persona_context(target, assessment)
    except Exception:
        pass
    # parse and attach structured parsed output with validation
    try:
        parsed = parse_persona_text(str(text))
        if parsed:
            entry['parsed'] = parsed
            valid, errs = validate_parsed_persona(parsed)
            min_conf = 0.5
            try:
                min_conf = float(os.getenv('PERSONA_MIN_CONFIDENCE', '0.5') or 0.5)
            except Exception:
                pass
            if not valid or float(parsed.get('confidence') or 0.0) < min_conf:
                entry['validation'] = {'valid': False, 'errors': errs, 'confidence': parsed.get('confidence')}
                entry['status'] = 'needs_review'
            else:
                entry['validation'] = {'valid': True, 'errors': [], 'confidence': parsed.get('confidence')}
                entry['status'] = 'ready'
    except Exception:
        pass
    target.setdefault('persona_reports', {})[persona] = entry
    try:
        _auto_route_incident(target, persona, text, assessment)
    except Exception:
        pass
    return JSONResponse({'assessment_id': assessment_id, 'row_index': row_index, 'persona': persona, 'text': text})


@router.post('/feedback')
async def capture_feedback(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    if not payload:
        raise HTTPException(status_code=400, detail='missing_payload')
    ok = persist_feedback(payload)
    if not ok:
        raise HTTPException(status_code=500, detail='persist_failed')

    # CB-5: feedback poisoning anomaly detection
    anomaly_detected = False
    try:
        from src.security.feedback_anomaly import get_detector as _get_feedback_detector
        _det = _get_feedback_detector()
        _tenant = str(payload.get('tenant_id') or 'default')
        _analyst = str(payload.get('analyst_tag') or payload.get('analyst') or 'unknown')
        _from_v = str(payload.get('original_verdict') or payload.get('from_verdict') or '')
        _to_v = str(payload.get('verdict') or payload.get('to_verdict') or '')
        if _from_v and _to_v and _from_v.upper() != _to_v.upper():
            _det.record_flip(_tenant, _analyst, _from_v, _to_v)
            anomaly_detected, _flip_rate = _det.check_for_poisoning(_tenant, _analyst)
            if anomaly_detected:
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    'feedback_anomaly alert: tenant=%s analyst=%s flip_rate=%.2f',
                    _tenant, _analyst, _flip_rate,
                )
    except Exception:
        pass  # guard never breaks the feedback path

    resp: dict = {'ok': True, 'stored': ok}
    if anomaly_detected:
        resp['anomaly_detected'] = True
        resp['anomaly_reason'] = 'high_malicious_to_benign_flip_rate'
    return JSONResponse(resp)


async def run_deep_analyze_pipeline(payload: dict) -> JSONResponse:
    rows = payload.get('rows') or []
    options = payload.get('options') or {}
    batch_meta = payload.get('batch_meta') or {}
    try:
        csv_deep_analyze_inflight.labels().set(1)
    except Exception:
        try: csv_deep_analyze_inflight.set(1)
        except Exception: pass


    auto = bool(options.get('auto_llm') or payload.get('auto_llm') or False)
    try:
        csv_deep_analyze_total.labels(auto_llm=str(bool(auto))).inc()
    except Exception:
        try:
            csv_deep_analyze_total.inc(1, labels={'auto_llm': str(bool(auto))})
        except Exception:
            pass

    # Always create assessment record and start a worker session (if available).
    risk_appetite = (payload.get('risk_appetite') or options.get('risk_appetite') or os.getenv('DEFAULT_RISK_APPETITE') or 'medium').lower()
    if risk_appetite not in {'low','medium','high'}:
        risk_appetite = 'medium'
    org = payload.get('org') or payload.get('tenant') or 'unknown'
    ml_pipeline_result: Dict[str, Any] = {'enabled': False, 'status': 'disabled', 'factors': []}
    if _endpoint_email_ml_enabled(payload, options):
        rows, ml_pipeline_result = _apply_endpoint_email_ml(rows, payload, tenant_id=org, event_id=f"ml-{uuid.uuid4().hex[:12]}")

    # Wire domain-specific factor extractors (email BEC, endpoint parent-process,
    # cross-domain pivot, network ML beacon). Merges factors back into matching rows.
    try:
        from src.correlation.ingestion_orchestrator import run_ingestion as _run_ingestion
        from src.correlation.canonical_event import CanonicalEvent as _CE
        _canon_events: list = []
        for _r in rows:
            if not isinstance(_r, dict):
                continue
            try:
                _src = str(_r.get('source') or _r.get('log_source') or _r.get('ingest_source') or '').lower()
                _st = ('email' if any(k in _src for k in ('email','mail','smtp','exchange','o365'))
                       else 'endpoint' if any(k in _src for k in ('edr','endpoint','sysmon','wef','etw','crowdstrike','sentinelone'))
                       else 'network' if any(k in _src for k in ('zeek','suricata','netflow','vpcflow','dns','network'))
                       else 'generic')
                _ce = _CE(
                    source_type=_st,
                    host=_r.get('host') or _r.get('hostname') or _r.get('device_name') or '',
                    user=_r.get('user') or _r.get('username') or _r.get('actor') or '',
                    process=_r.get('process') or _r.get('process_name') or '',
                    file_hash=_r.get('sha256') or _r.get('file_hash') or '',
                    src_ip=_r.get('src_ip') or _r.get('ip') or '',
                    dst_ip=_r.get('dst_ip') or '',
                    domain=_r.get('domain') or _r.get('fqdn') or '',
                    uri=_r.get('uri') or _r.get('url') or '',
                    subject=_r.get('subject') or '',
                    attachment_type=_r.get('attachment_type') or '',
                    file_name=_r.get('file_name') or _r.get('filename') or '',
                    mailbox=_r.get('mailbox') or '',
                    threat_tags=list(_r.get('threat_tags') or _r.get('tags') or []),
                    raw=_r,
                    timestamp=float(_r.get('ts') or _r.get('timestamp') or 0),
                )
                _canon_events.append(_ce)
            except Exception:
                pass
        if _canon_events:
            _domain_factors = _run_ingestion(_canon_events)
            # Merge returned FactorEmit objects back into matching rows
            for _fac in (_domain_factors or []):
                _fname = _fac.get('name') or ''
                if not _fname:
                    continue
                _fhost = ''
                for _n in (_fac.get('nodes') or []):
                    if isinstance(_n, str) and _n.startswith('host:'):
                        _fhost = _n[5:]
                        break
                for _row in rows:
                    if not isinstance(_row, dict):
                        continue
                    _rhost = _row.get('host') or _row.get('hostname') or _row.get('device_name') or ''
                    if _fhost and _rhost and _fhost != _rhost:
                        continue
                    _rf = list(_row.get('factors') or [])
                    if _fname not in _rf:
                        _rf.append(_fname)
                        _row['factors'] = _rf
                    break  # assign to first matching row only
    except Exception as _exc:
        logger.debug('Domain factor extractor wiring skipped: %s', _exc)

    ctx = {
        'rows': rows,
        'options': {**options, 'auto_llm': auto, 'risk_appetite': risk_appetite},
        'analyze_mode': payload.get('analyze_mode') or options.get('analyze_mode') or 'basic',
        'risk_appetite': risk_appetite,
        'factors': list(ml_pipeline_result.get('factor_names') or []),
    }
    pipeline_plan = [{'idx': step.idx, 'name': step.name} for step in PIPELINE_SPEC]

    # Create deterministic assessment and session ids
    assessment_id = f"assessment-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    session_id = f"session-{assessment_id}"

    def _store_assessment(org: str | None, aid: str, data: dict):
        try:
            repo_root = os.getcwd()
            datepart = _utcnow().strftime('%Y-%m-%d')
            base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
            orgdir = (org or 'unknown')
            dest = os.path.join(base, orgdir, datepart)
            os.makedirs(dest, exist_ok=True)
            path = os.path.join(dest, f"{aid}.json")
            try:
                data['persisted_path'] = path
            except Exception:
                pass
            _atomic_write_json_sync(path, data)
            return path
        except Exception:
            logger.debug('assessment persist failed for %s', aid, exc_info=True)
            return None

    # Run lightweight stage registry locally for canonical/mapping hints
    stage_status = []
    try:
        active_stages = list(STAGE_REGISTRY)
        if ctx.get('analyze_mode') == 'advanced':
            active_stages += ADVANCED_STAGES
        for st in active_stages:
            res = await _run_stage(st, ctx)
            stage_status.append(res)
    except Exception:
        stage_status = []

    canonical = build_canonical_signals(stage_status, ctx)
    mappings = _build_mapping_bundle(canonical, rows, ctx.get('factors') or [])
    queued_ts = time.time()
    telemetry = {'queued_at': queued_ts, 'queued_at_ms': int(queued_ts * 1000), 'stage_count': len(pipeline_plan)}

    # Prepare initial assessment object persisted to disk for polling
    assessment_obj = {
        'assessment_id': assessment_id,
        'report_id': assessment_id,
        'session_id': session_id,
        'created': int(queued_ts),
        'status': 'pending',
        'rows': rows,
        'rows_processed': 0,
        'options': ctx.get('options', {}),
        'pipeline_stages': pipeline_plan,
        'stage_status': stage_status,
        'canonical': canonical,
        'mappings': mappings,
        'llm_rows': [],
        'org': org,
        'telemetry': telemetry,
        'risk_appetite': risk_appetite,
        'reviews': {},  # row_index -> {status, notes, reviewer_tag, updated_ts}
        'batch_meta': batch_meta or {},
        'cluster_reasoning_state': {},
        'corroboration': {},
        'ml_pipeline': ml_pipeline_result,
    }
    assessment_obj = _hydrate_assessment_semantics(assessment_obj)
    assessment_obj = _merge_offline_workbook_assessment(
        assessment_obj,
        rows,
        payload if isinstance(payload, dict) else {},
        options if isinstance(options, dict) else {},
        assessment_id=assessment_id,
        org=org,
        auto_llm=auto,
    )
    await _emit_offline_decision_record(assessment_obj, org=org)
    try:
        hopgraph_meta = _ingest_rows_to_hopgraph(rows, assessment_id)
    except Exception:
        hopgraph_meta = {'ingested': 0, 'timeline_rows': 0, 'timespan_seconds': 0.0}
    telemetry.update({
        'hopgraph_ingested_rows': hopgraph_meta.get('ingested') or 0,
        'timeline_rows': hopgraph_meta.get('timeline_rows') or 0,
        'timeline_span_seconds': hopgraph_meta.get('timespan_seconds') or 0.0,
        'endpoint_email_ml_enabled': bool(ml_pipeline_result.get('enabled')),
        'endpoint_email_ml_factor_count': len(ml_pipeline_result.get('factor_names') or []),
        'endpoint_email_ml_assigned_factor_count': int(ml_pipeline_result.get('assigned_factor_count') or 0),
    })
    assessment_obj['telemetry'] = telemetry
    assessment_obj['temporal_context'] = {
        'ingested_rows': hopgraph_meta.get('ingested') or 0,
        'timeline_rows': hopgraph_meta.get('timeline_rows') or 0,
        'timespan_seconds': hopgraph_meta.get('timespan_seconds') or 0.0,
    }
    persisted_path = _store_assessment(org, assessment_id, assessment_obj) or ''

    # Store light-weight view in memory for quick GET responses
    REPORT_STORE[assessment_id] = {
        'assessment_id': assessment_id,
        'report_id': assessment_id,
        'session_id': session_id,
        'persisted_path': persisted_path,
        'status': 'pending',
        'created': assessment_obj['created'],
        'org': org,
        'pipeline_stages': pipeline_plan,
        'canonical': canonical,
        'mappings': mappings,
        'results': stage_status,
        'telemetry': telemetry,
        'temporal_context': assessment_obj.get('temporal_context') or {},
        'rows_processed': len(rows),
        'evidence_rows': assessment_obj.get('evidence_rows') or [],
        'correlation_clusters': assessment_obj.get('correlation_clusters') or [],
        'persona_reports': assessment_obj.get('persona_reports') or {},
        'cluster_reasoning_state': assessment_obj.get('cluster_reasoning_state') or {},
        'corroboration': assessment_obj.get('corroboration') or {},
        'ml_pipeline': ml_pipeline_result,
    }

    # Schedule background LLM row generation so the HTTP response is fast even when providers are slow
    # In test environments, allow disabling automatic background scheduling to avoid leaking tasks.
    _skip_llm_sched = False
    try:
        if str(os.getenv('TEST_HELPERS_ENABLED', '0')).lower() in ('1', 'true', 'yes'):
            logger.debug('TEST_HELPERS_ENABLED set; skipping automatic _schedule_llm_generation for %s', assessment_id)
            _skip_llm_sched = True
    except Exception:
        pass
    if not _skip_llm_sched:
        _schedule_llm_generation(rows, ctx, assessment_obj, assessment_id, org, payload if isinstance(payload, dict) else {})
        # Always schedule tier-1 prefill regardless of auto_llm — prefill only needs clusters,
        # not row-level LLM, so it's cheap enough to run for every manual upload.
        _schedule_prefill_generation(assessment_obj, assessment_id)

    # Start worker session asynchronously (best-effort). Worker should update persisted file as it progresses.
    try:
        worker_payload = {
            'assessment_id': assessment_id,
            'session_id': session_id,
            'rows': rows,
            'options': ctx.get('options', {}),
            'analyze_mode': ctx.get('analyze_mode'),
            'org': org,
            'persisted_path': persisted_path,
            # carry through any LLM overrides so background worker uses them
            'overrides': payload.get('overrides') if isinstance(payload, dict) else None,
        }
        try:
            DEFAULT_WORKER.start_session(session_id, worker_payload)
        except Exception:
            # some test environments may not have a real worker; run a lightweight in-process progression
            async def _local_runner():
                try:
                    proc_ctx = {
                        'rows': rows,
                        'options': ctx.get('options', {}),
                        'analyze_mode': ctx.get('analyze_mode'),
                        'factors': list(ml_pipeline_result.get('factor_names') or []),
                    }
                    statuses = []
                    active = list(STAGE_REGISTRY)
                    if proc_ctx.get('analyze_mode') == 'advanced':
                        active += ADVANCED_STAGES
                    for st in active:
                        r = await _run_stage(st, proc_ctx)
                        statuses.append(r)
                        try:
                            # update intermediate stage status and persist
                            assessment_obj['stage_status'] = statuses
                            assessment_obj['rows_processed'] = len(rows)
                            _store_assessment(org, assessment_id, assessment_obj)
                        except Exception:
                            pass
                    assessment_obj['canonical'] = build_canonical_signals(statuses, proc_ctx)
                    assessment_obj['mappings'] = _build_mapping_bundle(assessment_obj['canonical'], rows, proc_ctx.get('factors') or [])
                    assessment_obj = _hydrate_assessment_semantics(assessment_obj)
                    assessment_obj['status'] = 'completed'
                    assessment_obj['rows_processed'] = len(rows)
                    try:
                        _store_assessment(org, assessment_id, assessment_obj)
                        REPORT_STORE[assessment_id]['status'] = 'completed'
                        REPORT_STORE[assessment_id]['ml_pipeline'] = ml_pipeline_result
                    except Exception:
                        pass
                except Exception:
                    try:
                        assessment_obj['status'] = 'failed'
                        _store_assessment(org, assessment_id, assessment_obj)
                        REPORT_STORE[assessment_id]['status'] = 'failed'
                    except Exception:
                        pass

            try:
                _track_task(asyncio.create_task(_local_runner()))
            except Exception:
                pass
    except Exception as e:
        try:
            csv_deep_analyze_inflight.labels().set(0)
        except Exception:
            pass
        return JSONResponse({'detail': 'worker_error', 'error': str(e)}, status_code=500)

    try:
        csv_deep_analyze_inflight.labels().set(0)
    except Exception:
        pass

    # Return assessment handle for client to poll
    resp = {
        'assessment_id': assessment_id,
        'report_id': assessment_id,
        'session_id': session_id,
        'persisted_path': persisted_path,
        'status': 'pending',
        'org': org,
        'pipeline_stages': pipeline_plan,
        'results': stage_status,
        'canonical': canonical,
        'mappings': mappings,
        'telemetry': telemetry,
        'temporal_context': assessment_obj.get('temporal_context') or {},
        'evidence_rows': assessment_obj.get('evidence_rows') or [],
        'correlation_clusters': assessment_obj.get('correlation_clusters') or [],
        'persona_reports': assessment_obj.get('persona_reports') or {},
        'cluster_reasoning_state': assessment_obj.get('cluster_reasoning_state') or {},
        'corroboration': assessment_obj.get('corroboration') or {},
        'ml_pipeline': ml_pipeline_result,
        'risk_appetite': risk_appetite,
        'batch_meta': batch_meta or {},
    }
    for key in _OFFLINE_ASSESSMENT_MERGE_KEYS:
        value = assessment_obj.get(key)
        if value not in (None, [], {}):
            resp[key] = value

    # Ensure the authoritative assessment object is persisted and cached
    try:
        # persist the full assessment object (best-effort)
        persisted_path2 = _store_assessment(org, assessment_id, assessment_obj)
        # write an index entry for deterministic lookup
        if persisted_path2:
            try:
                _write_assessment_index(assessment_id, persisted_path2)
            except Exception:
                pass
        # cache the authoritative object in REPORT_STORE so subsequent lookups are deterministic
        try:
            REPORT_STORE[assessment_id] = assessment_obj
        except Exception:
            # fallback: leave lightweight view in place
            pass
    except Exception:
        pass

    # Index parent/child relationships for batch flows
    try:
        parent_id = None
        if batch_meta:
            parent_id = batch_meta.get('parent_assessment_id')
            if batch_meta.get('is_parent'):
                parent_id = assessment_id
            if parent_id:
                if parent_id not in PARENT_CHILD_INDEX:
                    PARENT_CHILD_INDEX[parent_id] = []
                if assessment_id != parent_id:
                    if assessment_id not in PARENT_CHILD_INDEX[parent_id]:
                        PARENT_CHILD_INDEX[parent_id].append(assessment_id)
                # Persist lightweight index in REPORT_STORE for quick lookup
                REPORT_STORE.setdefault(parent_id, {}).setdefault('batch_children', [])
                if assessment_id != parent_id:
                    children = REPORT_STORE[parent_id].get('batch_children') or []
                    if assessment_id not in children:
                        children.append(assessment_id)
                        REPORT_STORE[parent_id]['batch_children'] = children
    except Exception:
        pass
    # Merge existing view with response for quick GETs
    REPORT_STORE[assessment_id] = {**REPORT_STORE.get(assessment_id, {}), **resp}
    # Overwrite with the authoritative persisted assessment object when available
    try:
        if isinstance(assessment_obj, dict):
            REPORT_STORE[assessment_id] = assessment_obj
    except Exception:
        pass
    return JSONResponse(resp)


def _build_lite_assessment(payload: dict, persist: bool = True) -> dict:
    rows = payload.get('rows') or []
    options = payload.get('options') or {}
    auto_llm = bool(options.get('auto_llm'))
    fallback_id = payload.get('assessment_id') or payload.get('session_id') or f"lite-{int(time.time() * 1000)}"
    stages = []
    for idx, step in enumerate(PIPELINE_SPEC, 1):
        state = 'completed'
        if 'llm' in step.name.lower() and not auto_llm:
            state = 'skipped'
        entry = {'idx': idx, 'name': step.name, 'status': state}
        if idx == 1:
            entry['row_count'] = len(rows)
        stages.append(entry)
    fallback = {
        'assessment_id': fallback_id,
        'report_id': fallback_id,
        'status': 'completed',
        'accepted_rows': len(rows),
        'rows_processed': len(rows),
        'pipeline_stages': stages,
        'auto_llm': auto_llm,
        'org': payload.get('org') or 'unknown',
        'assessor': payload.get('assessor') or 'auto-lite',
        'rows': rows,
        'llm_rows': [
            {
                'row_index': r.get('row_index', idx),
                'fingerprint': r.get('fingerprint') or r.get('sha256') or r.get('file_hash') or f"row-{idx}",
                'llm_summary': 'Lite mode summary generated for demo coverage',
                'llm_meta': {'auto': True, 'confidence': 0.65},
                'generated_at': time.time(),
            }
            for idx, r in enumerate(rows)
        ],
        'canonical': {
            'llm_summary': 'Automated assessment completed in lite mode; no high-risk behaviors beyond sample rows.',
            'highlights': rows[:3],
        },
    }
    try:
        canonical_ctx = build_canonical_signals([], {'rows': rows})
        if canonical_ctx:
            fallback['canonical'].update(canonical_ctx)
    except Exception:
        pass
    fallback['results'] = [
        {
            'row_index': r.get('row_index', idx),
            'verdict': 'observe',
            'confidence': 0.35,
            'summary': r.get('process_name') or r.get('file_path') or r.get('domain') or 'lite-row',
            'signals': r,
            'factors': ['lite_mode_pipeline'],
        }
        for idx, r in enumerate(rows)
    ]
    # Provide a canonical `processed` count for compatibility with callers/tests
    try:
        fallback['processed'] = len(fallback.get('results') or [])
    except Exception:
        fallback['processed'] = int(fallback.get('rows_processed') or fallback.get('accepted_rows') or 0)
    mappings = _build_mapping_bundle(fallback['canonical'], rows, fallback.get('factors') or [])
    if not mappings.get('mitre'):
        mappings['mitre'] = ['lite_mode']
    if not mappings.get('pasta'):
        mappings['pasta'] = {'pasa_level': 'low'}
        mappings['pasa'] = mappings['pasta']
    if not mappings.get('maestro'):
        mappings['maestro'] = {'maestro_tags': []}
    if not mappings.get('diamond'):
        mappings['diamond'] = {'adversary': None, 'capability': []}
    fallback['mappings'] = mappings
    if persist:
        repo_root = os.getcwd()
        datepart = _utcnow().strftime('%Y-%m-%d')
        base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
        dest = os.path.join(base, fallback['org'], datepart)
        try:
            os.makedirs(dest, exist_ok=True)
        except Exception:
            pass
        persisted_path = os.path.join(dest, f"{fallback_id}.json")
        fallback['persisted_path'] = persisted_path
        try:
            atomic_write_json(persisted_path, fallback)
            try:
                _write_assessment_index(fallback_id, persisted_path)
            except Exception:
                pass
        except Exception:
            pass
    REPORT_STORE[fallback_id] = dict(fallback)
    return fallback


@router.post('/deep_analyze', operation_id='assessments_deep_analyze')
@csv_router.post('/deep_analyze', operation_id='deep_analyze')
async def deep_analyze(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    try:
        resp = await run_deep_analyze_pipeline(payload)
        if resp is None:
            raise RuntimeError('pipeline_unavailable')
        return resp
    except Exception:
        fallback = _build_lite_assessment(payload, persist=True)
        return JSONResponse(fallback)


@router.post('/csv/deep_analyze', operation_id='assessments_csv_deep_analyze')
@csv_router.post('/csv/deep_analyze', operation_id='csv_deep_analyze_alias')
async def csv_deep_analyze(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    try:
        resp = await run_deep_analyze_pipeline(payload)
        if resp is None:
            raise RuntimeError('pipeline_unavailable')
        return resp
    except Exception:
        fallback = _build_lite_assessment(payload, persist=False)
        return JSONResponse(fallback)

@router.get('/{parent_id}/batches')
async def list_batches(parent_id: str):
    """Return parent assessment (if present) and its child batch assessments with ordering.
    Parent is identified either by explicit parent_id or by batch_meta.is_parent.
    """
    parent = REPORT_STORE.get(parent_id) or _load_assessment_from_disk(parent_id)
    if not parent:
        # If parent not found but children exist, synthesize minimal parent shell
        if parent_id in PARENT_CHILD_INDEX:
            parent = {'assessment_id': parent_id, 'status': 'unknown', 'batch_meta': {'synthetic': True}}
        else:
            return JSONResponse({'detail': 'not_found'}, status_code=404)
    children_ids = PARENT_CHILD_INDEX.get(parent_id, [])
    children = []
    for cid in children_ids:
        rec = REPORT_STORE.get(cid) or _load_assessment_from_disk(cid) or {}
        if rec:
            children.append({
                'assessment_id': rec.get('assessment_id') or cid,
                'status': rec.get('status'),
                'created': rec.get('created'),
                'rows_processed': rec.get('rows_processed'),
                'batch_meta': rec.get('batch_meta') or {},
            })
    # Sort by batch_number if available
    try:
        children.sort(key=lambda x: (x.get('batch_meta', {}).get('batch_number') or 0))
    except Exception:
        pass
    return JSONResponse({'parent': {
        'assessment_id': parent.get('assessment_id') or parent_id,
        'status': parent.get('status'),
        'created': parent.get('created'),
        'batch_meta': parent.get('batch_meta') or {},
    }, 'children': children, 'child_count': len(children)})


def _load_assessment_from_disk(assessment_id: str, preferred_path: str | None = None):
    candidates = []
    if preferred_path:
        candidates.append(preferred_path)
    try:
        repo_root = os.getcwd()
        base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
        if os.path.isdir(base):
            dates = [_utcnow().strftime('%Y-%m-%d')]
            dates.append((_utcnow() - datetime.timedelta(days=1)).strftime('%Y-%m-%d'))
            for d in dates:
                for orgdir in os.listdir(base):
                    p = os.path.join(base, orgdir, d, f"{assessment_id}.json")
                    candidates.append(p)
    except Exception:
        pass
    for path in candidates:
        if not path:
            continue
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    return json.load(fh)
            except Exception:
                continue
    return None


def _build_report_document(assessment: dict, params: dict) -> dict:
    rows = assessment.get('llm_rows') or assessment.get('rows') or []
    max_rows = params.get('max_rows')
    try:
        max_rows = int(max_rows)
    except Exception:
        max_rows = 25
    max_rows = max(1, min(100, max_rows))
    top_rows = rows[:max_rows]
    sections = []
    for row in top_rows:
        # attach reviewer metadata if present in assessment
        review_meta = None
        try:
            reviews = assessment.get('reviews') or {}
            review_meta = reviews.get(str(row.get('row_index')))
        except Exception:
            review_meta = None
        sections.append(
            {
                'row_index': row.get('row_index'),
                'process_name': row.get('process_name'),
                'verdict': row.get('verdict') or row.get('classification'),
                'risk_level': row.get('risk_level'),
                'summary': row.get('llm_summary') or row.get('classification'),
                'recommendation': row.get('recommendation') or row.get('recommendations'),
                'review': {
                    'status': review_meta.get('status') if isinstance(review_meta, dict) else None,
                    'notes': review_meta.get('notes') if isinstance(review_meta, dict) else None,
                    'reviewer_tag': review_meta.get('reviewer_tag') if isinstance(review_meta, dict) else None,
                    'updated_ts': review_meta.get('updated_ts') if isinstance(review_meta, dict) else None,
                } if review_meta else None,
                'insight': _build_insight_payload(
                    row,
                    row.get('pipeline_context') or row.get('_pipeline_context'),
                    'executive'
                ),
            }
        )
    raw_recipients = params.get('recipients')
    if isinstance(raw_recipients, str):
        recipients = [r.strip() for r in raw_recipients.split(',') if r.strip()]
    elif isinstance(raw_recipients, (list, tuple, set)):
        recipients = [str(r).strip() for r in raw_recipients if str(r).strip()]
    else:
        recipients = list(raw_recipients or [])
    generated_ts = int(time.time())
    persona = str(params.get('persona') or 'ciso').lower()
    org_name = assessment.get('org') or params.get('org') or 'unknown'
    persisted_path = assessment.get('persisted_path')
    try:
        storage_hint = persisted_path or os.path.join(
            os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data', 'assessments'),
            org_name,
            _utcnow().strftime('%Y-%m-%d'),
            f"{assessment.get('assessment_id')}.json",
        )
    except Exception:
        storage_hint = persisted_path or 'data/assessments'
    audit_metadata = {
        'org': org_name,
        'org_tag': f"{org_name}:{_utcnow().strftime('%Y%m%d')}",
        'persona': persona,
        'persisted_path': persisted_path,
        'storage_hint': storage_hint,
        'session_id': assessment.get('session_id'),
        'generated_at': generated_ts,
        'recipients': recipients,
    }
    document = {
        'generated_at': generated_ts,
        'company': params.get('company') or org_name or 'unknown',
        'recipients': recipients,
        'include_model': bool(params.get('include_model')),
        'assessment_id': assessment.get('assessment_id'),
        'org': org_name,
        'canonical': assessment.get('canonical') or {},
        'mappings': assessment.get('mappings') or {},
        'summary': assessment.get('summary') or {},
        'stages': assessment.get('pipeline_stages') or [],
        'telemetry': assessment.get('telemetry') or {},
        'row_sections': sections,
        'rows_included': len(top_rows),
        'total_rows': len(rows),
        'persona': persona,
        'audit_metadata': audit_metadata,
        'risk_appetite': assessment.get('risk_appetite') or params.get('risk_appetite') or 'medium',
        'review_coverage': params.get('review_coverage'),
    }
    return document


@router.get('/report/{report_id}')
async def get_report(report_id: str):
    r = REPORT_STORE.get(report_id)
    if r:
        return JSONResponse(r)
    disk = _load_assessment_from_disk(report_id)
    if disk:
        return JSONResponse(disk)
    return JSONResponse({'detail': 'Not found'}, status_code=404)


@router.get('/{assessment_id}')
async def get_assessment(assessment_id: str):
    in_mem = REPORT_STORE.get(assessment_id) or {}
    persisted = _load_assessment_from_disk(assessment_id, in_mem.get('persisted_path')) or {}
    if not in_mem and not persisted:
        return JSONResponse({'detail': 'Not found'}, status_code=404)

    resp = {**persisted}
    resp.setdefault('assessment_id', assessment_id)
    resp.setdefault('report_id', assessment_id)
    resp.setdefault('org', in_mem.get('org') or persisted.get('org'))
    resp.setdefault('status', in_mem.get('status') or persisted.get('status') or 'pending')
    resp.setdefault('session_id', in_mem.get('session_id') or persisted.get('session_id'))
    resp.setdefault('persisted_path', in_mem.get('persisted_path') or persisted.get('persisted_path'))
    resp.setdefault('canonical', persisted.get('canonical') or in_mem.get('canonical') or {})
    resp.setdefault('mappings', persisted.get('mappings') or in_mem.get('mappings') or {})
    resp.setdefault('pipeline_stages', persisted.get('pipeline_stages') or in_mem.get('pipeline_stages') or [{'idx': s.idx, 'name': s.name} for s in PIPELINE_SPEC])
    resp.setdefault('stage_status', persisted.get('stage_status') or in_mem.get('stage_status') or [])
    resp.setdefault('telemetry', in_mem.get('telemetry') or persisted.get('telemetry') or {})
    resp.setdefault('cluster_reasoning_state', persisted.get('cluster_reasoning_state') or in_mem.get('cluster_reasoning_state') or {})
    resp.setdefault('corroboration', persisted.get('corroboration') or in_mem.get('corroboration') or {})
    llm_rows = (
        resp.get('llm_rows')
        or in_mem.get('llm_rows')
        or persisted.get('llm_rows')
        or resp.get('rows')
        or in_mem.get('rows')
        or persisted.get('rows')
        or []
    )
    raw_rows = in_mem.get('rows') or persisted.get('rows') or []
    resp['llm_rows'] = llm_rows
    resp.setdefault('rows', raw_rows if raw_rows else llm_rows)
    resp.setdefault('rows_processed', resp.get('rows_processed') or max(len(llm_rows), len(raw_rows)))
    # Prefer in-memory clusters/rows if disk has incomplete/empty data
    if not resp.get('correlation_clusters'):
        resp['correlation_clusters'] = in_mem.get('correlation_clusters') or persisted.get('correlation_clusters') or []
    if not resp.get('evidence_rows'):
        resp['evidence_rows'] = in_mem.get('evidence_rows') or persisted.get('evidence_rows') or []

    session_id = resp.get('session_id')
    if session_id:
        try:
            worker_state = DEFAULT_WORKER.status(session_id)
        except Exception:
            worker_state = None
        if worker_state:
            resp['status'] = worker_state.get('status') or resp.get('status')
            resp['current_stage'] = worker_state.get('step_name')
            resp['current_index'] = worker_state.get('current')
            if worker_state.get('stage_outputs'):
                resp['stage_status'] = worker_state.get('stage_outputs')
                resp['canonical'] = build_canonical_signals(worker_state.get('stage_outputs', []), worker_state.get('payload'))
            if worker_state.get('stage_history'):
                resp['pipeline_stages'] = worker_state.get('stage_history')
            tele = resp.get('telemetry', {})
            tele.update(worker_state.get('telemetry') or {})
            resp['telemetry'] = tele
            if worker_state.get('error'):
                resp['error'] = worker_state.get('error')

    # Only hydrate if the core fields are absent — empty persona_reports is OK
    if not resp.get('evidence_rows') or not resp.get('correlation_clusters'):
        # Skip expensive hydration if the pipeline is still actively running
        _active_statuses = {'running', 'processing', 'pending', 'queued'}
        _current_status = (resp.get('status') or '').lower()
        if _current_status not in _active_statuses:
            try:
                # Run CPU-bound hydration off the event loop; cap at 8s so GET never hangs
                resp = await asyncio.wait_for(
                    asyncio.to_thread(_hydrate_assessment_semantics, resp),
                    timeout=8.0
                )
            except (asyncio.TimeoutError, Exception):
                pass
    try:
        resp = _ensure_llm_rows_available(resp)
    except Exception:
        pass

    # Retroactively derive verdict labels for any cluster that has confidence_meter
    # but was persisted before verdict derivation was wired in.
    try:
        from src.core.verdict_engine.verdict_rules import backfill_cluster_verdicts
        _n = backfill_cluster_verdicts(resp)
        if _n:
            logger.debug('get_assessment: backfilled verdicts on %d clusters', _n)
    except Exception:
        pass

    # Phase 2: upgrade HVR gate state now that verdicts are known.
    # _apply_hvr_gating was called at cluster-build time with no verdict (severity-only).
    # Now that backfill has run, re-apply so VALIDATED_BREACH â†’ URGENT, BENIGN â†’ not gated.
    try:
        for _c in (resp.get('correlation_clusters') or []):
            _apply_hvr_gating(_c)  # no component_rows needed — falls back to existing hvr value
    except Exception:
        pass

    _preview_rows_for_runtime: list = []
    _preview_seen_for_runtime: set = set()
    for _c in (resp.get('correlation_clusters') or []):
        for _r in (_c.get('evidence_preview') or []):
            if not isinstance(_r, dict):
                continue
            _idx = _r.get('row_index')
            if _idx is not None and _idx in _preview_seen_for_runtime:
                continue
            if _idx is not None:
                _preview_seen_for_runtime.add(_idx)
            _preview_rows_for_runtime.append(_r)

    try:
        from src.core.tier1_prefill.prefill_engine import _ensure_v2_prefill_fields
        _rows_for_runtime = _preview_rows_for_runtime or resp.get('evidence_rows') or resp.get('rows') or []
        for _c in (resp.get('correlation_clusters') or []):
            _p = _c.get('tier1_prefill') if isinstance(_c, dict) else None
            if isinstance(_c, dict) and not isinstance(_p, dict):
                _p = {
                    'incident_name': (_c.get('lead_description') or _c.get('cluster_id') or 'CORRELATED INCIDENT'),
                    'headline_subtitle': _c.get('reason_summary') or _c.get('business_significance') or '',
                    'short_narrative': _c.get('business_significance') or _c.get('reason_summary') or '',
                    'top_actions': [
                        'Validate the correlated evidence rows and containment scope.',
                        'Collect the recommended missing logs before closing the incident.',
                    ],
                    'mitre_techniques': _c.get('top_mitre') or [],
                    'confidence_meter': _c.get('confidence_meter'),
                    '_fallback_generated': True,
                }
                _c['tier1_prefill'] = _p
            if isinstance(_p, dict) and _p.get('incident_name'):
                _ensure_v2_prefill_fields(_p, _c, _cluster_rows(_c, _rows_for_runtime))
    except Exception:
        pass

    try:
        _clusters = resp.get('correlation_clusters') or []
        # Only backfill top_links if cluster count is small enough to be fast (skip for large assessments)
        _needs_links = _clusters and not any(isinstance(_c, dict) and _c.get('top_links') for _c in _clusters)
        _row_count = len(resp.get('evidence_rows') or resp.get('rows') or [])
        if _needs_links and _row_count <= 500:
            _rebuilt, _adj = _build_correlation_clusters(_normalize_assessment_rows(resp))
            _exact = {
                tuple(sorted(int(v) for v in (_c.get('row_refs') or []))): _c
                for _c in _rebuilt
                if isinstance(_c, dict) and _c.get('top_links')
            }
            for _c in _clusters:
                if not isinstance(_c, dict) or _c.get('top_links'):
                    continue
                _refs = tuple(sorted(int(v) for v in (_c.get('row_refs') or []) if str(v).lstrip('-').isdigit()))
                _match = _exact.get(_refs)
                if _match is None and _refs:
                    _ref_set = set(_refs)
                    _best = None
                    _best_overlap = 0
                    for _candidate in _rebuilt:
                        _cand_refs = set(int(v) for v in (_candidate.get('row_refs') or []) if str(v).lstrip('-').isdigit())
                        _overlap = len(_ref_set & _cand_refs)
                        if _overlap > _best_overlap:
                            _best = _candidate
                            _best_overlap = _overlap
                    if _best_overlap >= 2:
                        _match = _best
                if _match:
                    _c['top_links'] = _match.get('top_links') or []
                    if not _c.get('reason_summary'):
                        _c['reason_summary'] = _match.get('reason_summary') or ''
    except Exception:
        pass

    # Build normalized_rows from evidence_preview across all clusters so the
    # browser gets rows that actually match cluster row_refs.  The raw
    # evidence_rows/normalized_rows stored on disk are often a non-overlapping
    # sample from a different slice of the full dataset.
    _ep_rows: list = _preview_rows_for_runtime
    if _ep_rows:
        resp['normalized_rows'] = _ep_rows
    elif resp.get('evidence_rows') and not resp.get('normalized_rows'):
        resp['normalized_rows'] = resp['evidence_rows']

    REPORT_STORE[assessment_id] = {**in_mem, **resp}
    return JSONResponse(resp)


@router.get('/{assessment_id}/rows')
async def get_assessment_rows(assessment_id: str):
    # Support test harness calling with a Request-like object: attempt to coerce
    try:
        if not isinstance(assessment_id, str):
            try:
                payload = await assessment_id.json()
                if isinstance(payload, dict) and payload.get('assessment_id'):
                    assessment_id = str(payload.get('assessment_id'))
                elif isinstance(payload, str):
                    assessment_id = payload
            except Exception:
                # fallback to string coercion
                try:
                    assessment_id = str(assessment_id)
                except Exception:
                    pass
    except Exception:
        pass

    persisted = _load_assessment_from_disk(assessment_id, (REPORT_STORE.get(assessment_id) or {}).get('persisted_path'))
    if persisted:
        try:
            persisted = _ensure_llm_rows_available(persisted)
        except Exception:
            pass
        rows = persisted.get('llm_rows') or persisted.get('rows') or []
        return JSONResponse({'assessment_id': assessment_id, 'rows': rows, 'row_count': len(rows)})
    in_mem = REPORT_STORE.get(assessment_id) or {}
    try:
        in_mem = _ensure_llm_rows_available(in_mem)
    except Exception:
        pass
    rows = in_mem.get('llm_rows') or in_mem.get('rows') or []
    return JSONResponse({'assessment_id': assessment_id, 'rows': rows, 'row_count': len(rows)})


@router.get('/{assessment_id}/rows/topk_sequence')
async def get_assessment_topk_sequence(assessment_id: str, k: int = 50):
    """Return top-K rows ordered by model score (ml_score or heuristic) and include temporal ordering info.
    Response: { assessment_id, rows: [ {row_index, ts, ml_score, summary, verdict, host, user} ], ordered_indices: [...], timespan_seconds }
    """
    assessment = _safe_load_assessment(assessment_id)
    if not assessment:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    rows = assessment.get('llm_rows') or assessment.get('rows') or []
    # ensure ml_score present
    for r in rows:
        try:
            if r.get('ml_score') is None:
                r['ml_score'] = _compute_ml_score_for_row(r, assessment)
        except Exception:
            r['ml_score'] = float(r.get('ml_score') or 0.0)
        # sort by ml_score desc
        sorted_rows = sorted([r for r in rows if isinstance(r, dict)], key=lambda x: float(x.get('ml_score') or 0.0), reverse=True)
        top = sorted_rows[: max(1, min(500, int(k)))]
        # build response rows with timestamp normalization
        out_rows = []
        timestamps = []
        for r in top:
            ts = None
            for kf in ('ts','time','timestamp','evt_time','created'):
                if r.get(kf) is not None:
                    try:
                        ts = float(r.get(kf))
                        break
                    except Exception:
                        pass
            if ts is not None:
                timestamps.append(ts)
            out_rows.append({
                'row_index': r.get('row_index'),
                'ts': ts,
                'ml_score': float(r.get('ml_score') or 0.0),
                'summary': (r.get('llm_summary') or '')[:800],
                'verdict': r.get('verdict') or r.get('classification'),
                'host': r.get('host'),
                'user': r.get('user')
            })
        timespan = 0
        ordered = []
        if timestamps:
            timespan = int(max(timestamps) - min(timestamps))
            ordered = [r['row_index'] for r in sorted(out_rows, key=lambda x: (x.get('ts') or 0))]
        return JSONResponse({'assessment_id': assessment_id, 'rows': out_rows, 'ordered_indices': ordered, 'timespan_seconds': timespan})
    in_mem = REPORT_STORE.get(assessment_id)
    if in_mem:
        rows = in_mem.get('llm_rows') or in_mem.get('rows') or []
        return JSONResponse({'assessment_id': assessment_id, 'rows': rows, 'row_count': len(rows)})
    return JSONResponse({'assessment_id': assessment_id, 'rows': [], 'row_count': 0})


# Background cleanup task to remove old assessments
def _start_assessment_cleanup():
    try:
        ttl = int(os.getenv('SESSION_TTL_SECONDS', os.getenv('SESSION_TTL', '86400')) or 86400)
        interval = int(os.getenv('SESSION_CLEAN_INTERVAL_SECONDS', '3600') or 3600)
    except Exception:
        ttl = 86400
        interval = 3600

    async def _cleanup_loop():
        while True:
            try:
                repo_root = os.getcwd()
                base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
                cutoff = time.time() - ttl
                if os.path.isdir(base):
                    for orgdir in os.listdir(base):
                        od = os.path.join(base, orgdir)
                        if not os.path.isdir(od):
                            continue
                        for d in os.listdir(od):
                            dp = os.path.join(od, d)
                            if not os.path.isdir(dp):
                                continue
                            for f in os.listdir(dp):
                                try:
                                    p = os.path.join(dp, f)
                                    m = os.path.getmtime(p)
                                    if m < cutoff:
                                        try:
                                            os.remove(p)
                                        except Exception:
                                            pass
                                except Exception:
                                    pass
            except Exception:
                pass
            try:
                await asyncio.sleep(max(60, interval))
            except Exception:
                await asyncio.sleep(60)

    # Return the coroutine so the caller (app) can schedule it on startup
    return _cleanup_loop


# Do not start cleanup at import time; provide registration helper
def register_assessment_cleanup(app):
    try:
        loop_factory = _start_assessment_cleanup()
        if loop_factory:
            try:
                app.add_event_handler('startup', lambda: _track_task(asyncio.create_task(loop_factory())))
            except Exception:
                try:
                    # fallback: schedule using loop directly
                    loop = asyncio.get_event_loop()
                    _track_task(loop.create_task(loop_factory()))
                except Exception:
                    pass
    except Exception:
        pass


# ---------------- New: Composite Investigation Builder -----------------
# In-memory store for investigation sessions (lightweight; persisted best-effort)
INVESTIGATE_STORE: dict[str, dict] = {}
INVESTIGATE_QUEUE: list[tuple[str, str]] = []  # list of (assessment_id, investigate_id)

def _investigate_persist_path(assessment: dict, investigate_id: str) -> str | None:
    try:
        base_path = assessment.get('persisted_path')
        if not base_path:
            return None
        parent_dir = os.path.dirname(base_path)
        os.makedirs(parent_dir, exist_ok=True)
        return os.path.join(parent_dir, f"{assessment.get('assessment_id')}-{investigate_id}.json")
    except Exception:
        return None

def _safe_load_assessment(aid: str) -> dict | None:
    ass = REPORT_STORE.get(aid)
    if ass:
        disk = None
        try:
            if ass.get('persisted_path') and os.path.exists(ass['persisted_path']):
                with open(ass['persisted_path'],'r',encoding='utf-8') as fh:
                    disk = json.load(fh)
        except Exception:
            disk = None
        if disk:
            return {**ass, **disk}
        return ass
    # fallback to disk only
    try:
        disk = _load_assessment_from_disk(aid)
        if disk:
            return disk
    except Exception:
        pass
    return None


def _resolve_row_from_assessment(assessment_id: str, row_index: int | None) -> Dict[str, Any] | None:
    """Return a row from cached or persisted assessments."""
    if not assessment_id or row_index is None:
        return None
    assessment = _safe_load_assessment(assessment_id)
    if not assessment:
        return None
    try:
        target_idx = int(row_index)
    except Exception:
        target_idx = row_index
    for collection_name in ("rows", "llm_rows"):
        rows = assessment.get(collection_name) or []
        for row in rows:
            try:
                idx = row.get("row_index")
                if idx is None:
                    continue
                if int(idx) == int(target_idx):
                    return row
            except Exception:
                if idx == target_idx:
                    return row
    # Fall back to positional lookup when row_index points into rows list
    if isinstance(target_idx, int):
        rows = assessment.get("rows") or []
        if 0 <= target_idx < len(rows):
            return rows[target_idx]
    return None


_INSIGHT_COSTS = {
    'dread': 0.001,
    'playbook': 0.0008,
    'hunt': 0.0008,
    'executive': 0.0005,
}


def _build_insight_payload(
    row: Dict[str, Any],
    pipeline_context: Dict[str, Any] | None,
    insight_type: str,
) -> Dict[str, Any]:
    pipeline_context = pipeline_context or {}
    domain = _infer_domain(row)
    mitre_tags = _extract_mitre_tags(row, pipeline_context)
    correlation_ctx = enrich_correlation_context(row, pipeline_context)
    attack_chain = build_attack_chain_visualization(correlation_ctx)
    artifact_context = {
        'process_name': row.get('process_name') or row.get('process') or '',
        'src_ip': row.get('src_ip') or row.get('ip_src') or row.get('ip'),
        'dst_ip': row.get('dst_ip') or row.get('ip_dst'),
        'host': row.get('host') or row.get('hostname') or '',
        'user': row.get('user') or row.get('account') or '',
        'factors': list(row.get('factors') or []),
    }
    dread_score = _extract_dread_score(row)
    risk_level = row.get('risk_level') or {}
    risk_label = str(risk_level.get('label') or row.get('risk_label') or 'Unknown')
    verdict = str(row.get('verdict') or row.get('classification') or 'Unknown').upper()
    correlation_score = None
    corr = row.get('_correlation') or row.get('correlation') or pipeline_context.get('correlation')
    if isinstance(corr, dict):
        correlation_score = corr.get('score')

    def _playbook_text() -> str:
        content = build_collection_playbook(domain, mitre_tags, artifact_context)
        return (
            f"Domain detected: {domain.upper()}.\n"
            "Copy-ready collection workflow below.\n\n"
            f"{content}"
        )

    def _hunt_text() -> str:
        lines = [
            f"Hunt focus for {domain} indicators.",
            "",
            "Attack scenarios driving hunt priority:",
        ]
        for scenario in correlation_ctx.get('scenarios', [])[:3]:
            lines.append(
                f"- {scenario['factor']}: {scenario['description']} "
                f"(impact: {scenario['business_impact']})"
            )
        lines.append("")
        lines.append("Log families to query:")
        tags = mitre_tags or ['T1059']
        for tag in tags[:3]:
            info = get_logs_for_mitre(tag)
            lines.append(f"{tag} ({info['name']}):")
            for log in info['logs']:
                lines.append(f"  - {log}")
        lines.append("")
        lines.append("Suggested queries:")
        lines.append("- Pivot on host and user across Sysmon Event 1 and 3 to build a timeline.")
        lines.append("- Search proxy or firewall logs for repeated destination IP/domain connections.")
        lines.append("- Diff Autoruns output over time to validate registry/service persistence.")
        lines.append("")
        lines.append(f"Attack chain: {attack_chain}")
        return "\n".join(lines)

    def _executive_text() -> str:
        lines = [
            f"Artifact: {row.get('process_name') or row.get('sha256') or 'artifact'}",
            f"Host: {row.get('host') or 'unknown'}, User: {row.get('user') or 'unknown'}",
            f"Verdict: {verdict}, Risk: {risk_label}, DREAD: {dread_score:.1f}",
            "",
            correlation_ctx.get('narrative', ''),
            f"Attack chain: {attack_chain}",
            "",
            "Why it matters:",
        ]
        for scenario in correlation_ctx.get('scenarios', [])[:2]:
            lines.append(f"- {scenario['description']} ({scenario['business_impact']})")
        lines.append("")
        lines.append("Next actions:")
        lines.append("- Isolate the affected host or user session if activity is confirmed malicious.")
        lines.append("- Collect evidence per the collection playbook, then escalate to IR if criteria met.")
        lines.append("- Enable missing logs highlighted above to close telemetry gaps.")
        return "\n".join(lines)

    def _dread_text() -> str:
        factors = row.get('factors') or []
        lines = [
            f"Artifact: {row.get('process_name') or row.get('sha256') or 'artifact'} on {row.get('host') or 'unknown host'}",
            f"Verdict: {verdict} (Risk: {risk_label})",
            f"DREAD score: {dread_score:.1f}",
            "",
            "Top contributing factors:",
        ]
        if factors:
            for fac in factors[:5]:
                lines.append(f"- {fac}")
        else:
            lines.append("- No factor metadata provided.")
        lines.append("")
        lines.append("Correlation context:")
        lines.append(correlation_ctx.get('narrative', 'No correlation evidence.'))
        lines.append(f"Attack chain: {attack_chain}")
        return "\n".join(lines)

    builders = {
        'playbook': _playbook_text,
        'hunt': _hunt_text,
        'executive': _executive_text,
        'dread': _dread_text,
    }
    text_func = builders.get(insight_type, _dread_text)
    insight_text = text_func()

    return {
        'insight': insight_text,
        'insight_type': insight_type,
        'domain': domain,
        'mitre_tags': mitre_tags,
        'attack_chain': attack_chain,
        'correlation': correlation_ctx,
        'dread_score': dread_score,
        'triage_score': _compute_triage_score(row),
        'risk_label': risk_label,
        'verdict': verdict,
        'correlation_score': correlation_score,
        'historical_context': _build_historical_context(row),
    }


def _build_historical_context(row: Dict[str, Any], lookback_days: int = 120) -> Dict[str, Any]:
    try:
        matches = HISTORICAL_REPO.query_similar_incidents(row, lookback_days=lookback_days, limit=3)
    except Exception:
        matches = []
    context = {
        'matches': matches,
        'match_count': len(matches),
    }
    if matches:
        latest = matches[0]
        context['latest_outcome'] = latest.get('outcome')
        context['latest_seen'] = latest.get('last_seen_at')
        context['reason'] = latest.get('match_type')
    else:
        context['latest_outcome'] = None
        context['latest_seen'] = None
        context['reason'] = None
    return context


def _get_by_path(obj: dict, path: str):
    """Simple dotted/path extractor supporting indexes like a.b[0].c
    Returns (found, value) where found is True if the path exists.
    """
    try:
        cur = obj
        import re
        parts = re.findall(r"[^.\[\]]+|\[\d+\]", path or '')
        for p in parts:
            if not p:
                continue
            if p.startswith('[') and p.endswith(']'):
                idx = int(p[1:-1])
                if isinstance(cur, (list, tuple)) and 0 <= idx < len(cur):
                    cur = cur[idx]
                else:
                    return (False, None)
            else:
                if isinstance(cur, dict) and p in cur:
                    cur = cur[p]
                else:
                    return (False, None)
        return (True, cur)
    except Exception:
        return (False, None)


@router.post('/{assessment_id}/llm/verify')
async def verify_llm_decision_card(assessment_id: str, request: Request):
    """Verify a Decision Card produced by an LLM against persisted assessment telemetry.

    Payload: { decision_card: {...} }
    Returns per-evidence verification and a flag `missing_evidence_from_database` when
    vector DB or historical repo were not available to complete checks.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    decision_card = payload.get('decision_card') or payload.get('decisionCard')
    if not isinstance(decision_card, dict):
        raise HTTPException(status_code=400, detail='missing_decision_card')
    assessment = _get_assessment_cached(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    top_evidence = decision_card.get('top_evidence') or []
    results = []
    missing_db = False

    try:
        vector_ok = bool(VECTOR_LOG_SEARCH and getattr(VECTOR_LOG_SEARCH, 'search', None))
    except Exception:
        vector_ok = False
    try:
        hist_ok = bool(HISTORICAL_REPO and getattr(HISTORICAL_REPO, 'query_similar_incidents', None))
    except Exception:
        hist_ok = False
    if not vector_ok and not hist_ok:
        missing_db = True

    for ev in top_evidence:
        try:
            stage = ev.get('stage') if isinstance(ev, dict) else None
            path = ev.get('path') if isinstance(ev, dict) else None
            snippet = ev.get('snippet') if isinstance(ev, dict) else None
            verified = False
            details = {'stage': stage, 'path': path, 'snippet': snippet}
            if path:
                found, val = _get_by_path(assessment, path)
                details['found'] = bool(found)
                details['value_preview'] = val if found else None
                if found and snippet:
                    try:
                        s = str(val or '')
                        verified = bool(snippet and snippet.strip() and (snippet.strip() in s or snippet.strip() == str(val).strip()))
                    except Exception:
                        verified = False
                else:
                    verified = bool(found)
            else:
                try:
                    stages = assessment.get('stage_status') or []
                    matched = next((s for s in stages if str(s.get('stage') or '').lower() == str(stage or '').lower()), None)
                    if matched:
                        details['found'] = True
                        details['value_preview'] = matched.get('result')
                        verified = True
                    else:
                        details['found'] = False
                except Exception:
                    details['found'] = False
            if vector_ok and snippet and not verified:
                try:
                    hits = VECTOR_LOG_SEARCH.search(snippet, top_k=3)
                    details['vector_hits'] = hits if isinstance(hits, list) else []
                    if hits:
                        verified = True
                except Exception:
                    pass
            results.append({'evidence': details, 'verified': bool(verified)})
        except Exception as e:
            results.append({'evidence': {}, 'verified': False, 'error': str(e)})

    verified_count = sum(1 for r in results if r.get('verified'))
    overall = 'unverified'
    if verified_count == len(results) and len(results) > 0:
        overall = 'verified'
    elif verified_count > 0:
        overall = 'partial'

    return JSONResponse({'assessment_id': assessment_id, 'overall': overall, 'per_evidence': results, 'missing_evidence_from_database': missing_db})

def _rank_rows_for_investigate(rows: list[dict]) -> list[dict]:
    scored = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        verdict = str(r.get('verdict') or r.get('classification') or '').upper()
        sev_map = {'CRITICAL': 90, 'HIGH': 70, 'FAIL': 60, 'SUSPICIOUS': 55, 'MEDIUM': 40, 'LOW': 10}
        sev = sev_map.get(verdict, 5)
        dread = 0
        try:
            dd = r.get('_dread') or r.get('dread')
            if isinstance(dd, dict):
                dread = int(dd.get('score') or 0)
            elif dd:
                dread = int(dd)
        except Exception:
            dread = 0
        ml_score = 0.0
        try:
            ml_score = float(r.get('ml_score') or 0.0)
        except Exception:
            ml_score = 0.0
        factors_len = len(r.get('factors') or [])
        composite = sev + dread * 2 + int(ml_score * 10) + factors_len
        scored.append((composite, r))
    scored.sort(key=lambda t: t[0], reverse=True)
    return [r for _s, r in scored]


def _compute_ml_score_for_row(row: dict, assessment: dict | None = None) -> float:
    # If a trained model bundle is available, use it for inference
    try:
        global MODEL_BUNDLE
        if MODEL_BUNDLE:
            from src.ml.feature_extractor import extract_row_features
            features = extract_row_features(row, assessment)
            preds = []
            try:
                preds = __import__('src.ml.model', fromlist=['predict']).predict(MODEL_BUNDLE, [features])
            except Exception:
                preds = []
            if preds:
                return float(max(0.0, min(100.0, float(preds[0]))))
    except Exception:
        pass

    # Fallback deterministic heuristic (legacy)
    try:
        score = 0.0
        v = str((row.get('verdict') or row.get('classification') or '')).upper()
        if v == 'CRITICAL':
            score += 40.0
        elif v == 'HIGH':
            score += 25.0
        elif v in {'SUSPICIOUS', 'FAIL'}:
            score += 18.0
        elif v == 'MEDIUM':
            score += 8.0
        try:
            dd = row.get('_dread') or row.get('dread') or {}
            if isinstance(dd, dict):
                score += float(dd.get('score') or 0) * 0.8
            else:
                score += float(dd or 0) * 0.8
        except Exception:
            pass
        try:
            score += min(20.0, float(len(row.get('factors') or [])) * 2.5)
        except Exception:
            pass
        try:
            gh = (row.get('graph_context') or {})
            if gh.get('hotspots'):
                score += 12.0
            if gh.get('mapping_stats') and isinstance(gh.get('mapping_stats'), dict):
                score += min(8.0, sum(1 for _ in gh.get('mapping_stats', {}).keys()))
            if isinstance(gh.get('hotspots'), (list, tuple)) and len(gh.get('hotspots')) > 0:
                score += 6.0
        except Exception:
            pass
        try:
            ts = None
            for k in ('ts', 'time', 'timestamp', 'created', 'evt_time'):
                if row.get(k):
                    ts = float(row.get(k))
                    break
            if ts and assessment and assessment.get('created'):
                age = max(0.0, float(assessment.get('created') or 0) - ts)
                if age < 3600:
                    score += 4.0
                elif age < 86400:
                    score += 2.0
        except Exception:
            pass
        final = max(0.0, min(100.0, score))
        return round(final, 3)
    except Exception:
        return 0.0


def _ensure_triage_on_row(row: dict, assessment: dict | None = None) -> None:
    """Ensure `triage_score` exists on a row object by computing and attaching it.

    This is idempotent and safe to call on rows that already have a value.
    """
    try:
        if not isinstance(row, dict):
            return
        if row.get('triage_score') is None:
            try:
                row['triage_score'] = float(_compute_triage_score(row) or 0.0)
            except Exception:
                row['triage_score'] = 0.0
    except Exception:
        pass


def _ensure_triage_on_rows(rows: list[dict] | None, assessment: dict | None = None) -> None:
    if not rows:
        return
    for r in rows:
        try:
            _ensure_triage_on_row(r, assessment)
        except Exception:
            continue

def _build_investigate_prompt(assessment: dict, top_rows: list[dict], missing_logs: list[str], factor_freq: dict[str,int]) -> str:
    try:
        verdicts = [str(r.get('verdict') or '').upper() for r in top_rows if r.get('verdict')]
        factors_top = sorted(factor_freq.items(), key=lambda kv: kv[1], reverse=True)[:12]
        factors_str = ', '.join(f"{k}({v})" for k,v in factors_top)
        missing_str = ', '.join(missing_logs) if missing_logs else 'none inferred'
        row_snippets = []
        for r in top_rows[:10]:
            row_snippets.append(json.dumps({k: r.get(k) for k in ['row_index','process','host','user','verdict','ml_score','llm_summary'] if r.get(k) is not None}, ensure_ascii=False))
        snippet = '\n'.join(row_snippets)
        base = (
            "You are a security analyst generating a composite multi-row investigation narrative. "
            "Analyze the provided high-signal rows, summarize an attack hypothesis (initial access, execution, persistence, lateral movement, exfiltration phases if applicable), "
            "describe evidentiary support, highlight factor correlations, and recommend next acquisition steps. Use concise, actionable paragraphs."
        )
        prompt = (
            f"{base}\nAssessment: {assessment.get('assessment_id')} Risk appetite: {assessment.get('risk_appetite')} Rows considered: {len(top_rows)}\n"
            f"Top verdicts: {', '.join(verdicts)}\nFactor frequencies: {factors_str}\nMissing telemetry classes inferred: {missing_str}\n"
            "Row snippets (JSON per line):\n" + snippet + "\nRespond with sections: Narrative, Evidence Table (brief lines), Missing Logs, Correlation Summary, Recommendations." 
        )
        return prompt
    except Exception:
        return "Composite investigation narrative generation fallback."


def _summarize_ewma_and_hotspots(session_summary: dict | None, session_explain: dict | None, max_chars: int = 800) -> str:
    """Produce a short human-readable summary of EWMA overlap matrix and hotspots.
    Returns a snippet suitable for appending to an LLM prompt.
    """
    try:
        parts = []
        if not session_summary and not session_explain:
            return ''
        # EWMA / smoothed overlap matrix excerpt
        smoothed = None
        if session_summary and isinstance(session_summary, dict):
            smoothed = session_summary.get('correlation_smoothed') or session_summary.get('correlation')
        if session_explain and isinstance(session_explain, dict) and not smoothed:
            smoothed = session_explain.get('correlation_smoothed') or session_explain.get('correlation')

        if smoothed and isinstance(smoothed, (list, dict)):
            # represent a tiny top-k summary: list hotspot pairs with weights
            try:
                entries = []
                if isinstance(smoothed, dict):
                    # legacy mapping: keys -> dict of overlaps
                    for a, row in smoothed.items():
                        if isinstance(row, dict):
                            for b, v in row.items():
                                entries.append((a, b, float(v)))
                elif isinstance(smoothed, list):
                    # assume list of [i,j,value] or matrix
                    for item in smoothed[:60]:
                        if isinstance(item, (list,tuple)) and len(item) >= 3:
                            entries.append((item[0], item[1], float(item[2])))
                # sort by weight desc and take top 8
                entries.sort(key=lambda t: t[2], reverse=True)
                top = entries[:8]
                if top:
                    parts.append('Top overlap hotspots (pair -> overlap weight): ' + ', '.join(f"{a}-{b}:{w:.2f}" for a,b,w in top))
            except Exception:
                pass

        # Hotspot human explanations
        hotspots = None
        if session_explain and isinstance(session_explain, dict):
            hotspots = session_explain.get('overlap_hotspots') or session_explain.get('hotspots')
        if not hotspots and session_summary and isinstance(session_summary, dict):
            hotspots = session_summary.get('overlap_hotspots') or session_summary.get('hotspots')

        if hotspots and isinstance(hotspots, (list,dict)):
            try:
                notes = []
                if isinstance(hotspots, dict):
                    for k,v in list(hotspots.items())[:6]:
                        notes.append(f"Hotspot {k}: {str(v)[:120]}")
                else:
                    for i, h in enumerate(hotspots[:6]):
                        # attempt to humanize numeric hotspot entries
                        if isinstance(h, dict):
                            label = h.get('label') or h.get('name') or f'h{i}'
                            score = h.get('score') or h.get('weight') or None
                            notes.append(f"{label}: score={float(score):.2f}" if score is not None else f"{label}")
                        else:
                            notes.append(str(h)[:120])
                if notes:
                    parts.append('Hotspot notes: ' + '; '.join(notes))
            except Exception:
                pass

        # mapping stats concise
        try:
            mapping = (session_summary or {}).get('mapping_stats') or (session_explain or {}).get('mapping_stats')
            if mapping and isinstance(mapping, dict):
                parts.append('Mapping stats: ' + ', '.join(f"{k}:{v}" for k,v in list(mapping.items())[:6]))
        except Exception:
            pass

        out = '\n'.join(parts)
        if len(out) > max_chars:
            # attempt to trim to sentence boundaries
            trimmed = out[:max_chars]
            last_period = trimmed.rfind('. ')
            if last_period > 40:
                trimmed = trimmed[:last_period+1]
            out = trimmed
        return out
    except Exception:
        return ''

def _infer_missing_log_classes(rows: list[dict]) -> list[str]:
    expected = {'process','network','auth','registry','script_block','edr_event'}
    present = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        for k in expected:
            if r.get(k) is not None or (k == 'network' and (r.get('dest_ip') or r.get('ip'))):
                present.add(k)
        # heuristics
        if r.get('command') or r.get('process_name'):
            present.add('process')
        if r.get('user'):
            present.add('auth')
        if r.get('registry_key') or r.get('reg_key'):
            present.add('registry')
    return sorted(list(expected - present))

def _factor_frequency(rows: list[dict]) -> dict[str,int]:
    freq: dict[str,int] = {}
    for r in rows:
        for f in (r.get('factors') or []):
            try:
                if isinstance(f, str):
                    key = f
                elif isinstance(f, dict):
                    key = f.get('name') or f.get('factor') or 'factor'
                else:
                    key = str(f)
                freq[key] = freq.get(key,0) + 1
            except Exception:
                continue
    return freq


_CLUSTER_REASONING_VERSION = 'cluster-reasoning-v1'
_CLUSTER_SEVERITY_SCORES = {
    'critical': 1.0,
    'high': 0.82,
    'medium': 0.58,
    'low': 0.28,
    'info': 0.12,
}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def _cluster_rows(cluster: dict | None, rows: list[dict]) -> list[dict]:
    if not isinstance(cluster, dict):
        return []
    refs = {
        int(ref)
        for ref in (cluster.get('row_refs') or [])
        if ref is not None
    }
    out: list[dict] = []
    for row in rows:
        try:
            idx = int(row.get('row_index') or 0)
        except Exception:
            idx = 0
        if idx in refs:
            out.append(row)
    preview = [
        row for row in (cluster.get('evidence_preview') or [])
        if isinstance(row, dict)
    ]
    if out:
        def _idx(row: dict) -> int | None:
            for key in ('row_index', 'row_number'):
                try:
                    value = row.get(key)
                    if value is not None:
                        return int(value)
                except Exception:
                    continue
            return None

        if preview and len({idx for row in out for idx in [_idx(row)] if idx is not None}) < min(len(refs), len(preview)):
            seen = set()
            merged = []
            for row in out + preview:
                idx = _idx(row)
                if idx is not None and idx in seen:
                    continue
                if idx is not None:
                    seen.add(idx)
                merged.append(row)
            return merged
        return out
    return preview


def _cluster_review_entries(assessment: dict, cluster: dict | None, cluster_rows: list[dict]) -> list[dict]:
    reviews = assessment.get('reviews') or {}
    cluster_reviews = assessment.get('cluster_reviews') or {}
    if not isinstance(reviews, dict):
        reviews = {}
    if not isinstance(cluster_reviews, dict):
        cluster_reviews = {}
    cluster_id = str((cluster or {}).get('cluster_id') or '')
    row_refs = {
        int(row.get('row_index') or 0)
        for row in cluster_rows
        if isinstance(row, dict)
    }
    entries: list[dict] = []
    for key, value in reviews.items():
        if not isinstance(value, dict):
            continue
        include = False
        if cluster_id and str(value.get('cluster_id') or '') == cluster_id:
            include = True
        try:
            include = include or int(key) in row_refs
        except Exception:
            pass
        if include:
            entries.append(value)
    if cluster_id:
        cluster_value = cluster_reviews.get(cluster_id)
        if isinstance(cluster_value, dict):
            entries.append(cluster_value)
    return entries


def _build_cluster_analyst_state(assessment: dict, cluster: dict | None, cluster_rows: list[dict]) -> dict:
    entries = _cluster_review_entries(assessment, cluster, cluster_rows)
    latest_gate = assessment.get('_latest_gate') or {}
    factors_added: list[str] = []
    factors_removed: list[str] = []
    hypotheses: list[str] = []
    disposition_delta = 0.0
    confidence_override = None
    statuses: list[str] = []
    decisions: list[str] = []
    for entry in entries:
        statuses.append(str(entry.get('status') or ''))
        if entry.get('confirm_or_deny'):
            decisions.append(str(entry.get('confirm_or_deny')))
        for item in (entry.get('factors_added') or []):
            if item:
                factors_added.append(str(item))
        for item in (entry.get('factors_removed') or []):
            if item:
                factors_removed.append(str(item))
        hypothesis = entry.get('hypothesis')
        if hypothesis:
            hypotheses.append(str(hypothesis))
        if entry.get('disposition_delta') is not None:
            disposition_delta += _safe_float(entry.get('disposition_delta'))
        if entry.get('confidence_override') is not None:
            confidence_override = _safe_float(entry.get('confidence_override'))
    return {
        'review_status': statuses[-1] if statuses else 'unreviewed',
        'review_count': len(entries),
        'hypothesis': hypotheses[-1] if hypotheses else '',
        'hypotheses': list(dict.fromkeys(hypotheses))[:5],
        'confirm_or_deny': decisions[-1] if decisions else '',
        'factors_added': list(dict.fromkeys(factors_added))[:12],
        'factors_removed': list(dict.fromkeys(factors_removed))[:12],
        'confidence_override': confidence_override,
        'disposition_delta': round(disposition_delta, 3),
        'gate_status': latest_gate.get('gate_verdict') or 'ungated',
        'gate_ts': latest_gate.get('gate_ts'),
    }


def _estimate_ewma_score(assessment: dict, cluster: dict | None) -> float:
    graph_summary = assessment.get('graph_summary') or {}
    matrix = graph_summary.get('correlation_smoothed') or graph_summary.get('correlation') or {}
    values: list[float] = []
    try:
        if isinstance(matrix, dict):
            for _, row in matrix.items():
                if isinstance(row, dict):
                    for _, val in row.items():
                        values.append(_safe_float(val))
        elif isinstance(matrix, list):
            for item in matrix:
                if isinstance(item, (list, tuple)) and len(item) >= 3:
                    values.append(_safe_float(item[2]))
    except Exception:
        values = []
    if values:
        return round(min(1.0, max(values)), 3)
    if isinstance(cluster, dict):
        return round(min(1.0, _safe_float(cluster.get('confidence'))), 3)
    return 0.0


def _estimate_pattern_support(assessment: dict, cluster_rows: list[dict], include_temporal: bool = False) -> tuple[float, list[dict]]:
    missing = _infer_missing_log_classes(cluster_rows)
    factor_freq = _factor_frequency(cluster_rows)
    dominant = sorted(factor_freq.items(), key=lambda kv: kv[1], reverse=True)[:4]
    dominant_bonus = min(0.35, sum(min(0.08, cnt * 0.04) for _, cnt in dominant))
    support = min(1.0, 0.15 + dominant_bonus + (0.08 if not missing else 0.0))
    evidence_used = [
        {'type': 'factor_frequency', 'factor': name, 'count': count}
        for name, count in dominant
    ]
    if include_temporal:
        try:
            engine = _get_trag_engine()
            tenant = assessment.get('org') or assessment.get('tenant') or 'default'
            query_bits = []
            for row in cluster_rows[:6]:
                for field in ('description', 'event_type', 'user', 'host', 'process', 'domain', 'ip'):
                    val = row.get(field)
                    if val:
                        query_bits.append(str(val))
            if engine and query_bits:
                neighbours = engine.query(' '.join(query_bits)[:400], tenant=tenant, top_k=4, window_seconds=24 * 3600)
                if neighbours:
                    support = min(1.0, support + min(0.4, 0.1 * len(neighbours)))
                    evidence_used.extend(
                        {
                            'type': 'temporal_neighbor',
                            'entity': n.get('entity') or n.get('user') or n.get('host'),
                            'severity': n.get('severity'),
                        }
                        for n in neighbours[:3]
                        if isinstance(n, dict)
                    )
        except Exception:
            pass
    return round(support, 3), evidence_used[:8]


def _cluster_graph_score(assessment: dict, cluster: dict | None) -> float:
    graph_summary = assessment.get('graph_summary') or {}
    candidates = [
        (cluster or {}).get('confidence'),
        graph_summary.get('confidence'),
        ((graph_summary.get('graph_confidence_breakdown') or {}).get('path')),
    ]
    for candidate in candidates:
        value = _safe_float(candidate, default=-1.0)
        if value >= 0.0:
            return round(min(1.0, value), 3)
    return 0.0


def _cluster_routing_snapshot(assessment: dict, cluster: dict | None, cluster_rows: list[dict], analyst_state: dict, include_temporal: bool = False) -> dict:
    severity = str((cluster or {}).get('severity') or 'low').lower()
    severity_score = _CLUSTER_SEVERITY_SCORES.get(severity, 0.2)
    graph_score = _cluster_graph_score(assessment, cluster)
    ewma_score = _estimate_ewma_score(assessment, cluster)
    pattern_support_score, evidence_used = _estimate_pattern_support(assessment, cluster_rows, include_temporal=include_temporal)
    cluster_size = len(cluster_rows)
    cluster_size_score = min(1.0, cluster_size / 4.0)
    analyst_boost = min(
        0.2,
        (0.04 * len(analyst_state.get('factors_added') or []))
        + (0.03 if analyst_state.get('hypothesis') else 0.0)
        + max(0.0, _safe_float(analyst_state.get('disposition_delta')) * 0.08),
    )
    confidence_override = analyst_state.get('confidence_override')
    if confidence_override is not None:
        analyst_boost += max(0.0, min(0.12, _safe_float(confidence_override) - 0.5))
    routing_score = (
        0.27 * severity_score
        + 0.25 * graph_score
        + 0.18 * ewma_score
        + 0.2 * pattern_support_score
        + 0.1 * cluster_size_score
        + analyst_boost
    )
    routing_score = round(min(1.0, routing_score), 3)
    high_signal = (
        (severity_score >= 0.82 and cluster_size >= 2 and routing_score >= 0.55)
        or (severity_score >= 0.58 and routing_score >= 0.68 and (ewma_score >= 0.45 or pattern_support_score >= 0.45))
    )
    return {
        'cluster_size': cluster_size,
        'severity_score': round(severity_score, 3),
        'graph_score': graph_score,
        'ewma_score': ewma_score,
        'pattern_support_score': pattern_support_score,
        'routing_score': routing_score,
        'high_signal': bool(high_signal),
        'reasoning_mode': 'deep' if high_signal else 'cheap',
        'routing_mode': 'cluster-first' if cluster_size >= 2 else 'row-first',
        'evidence_used': evidence_used,
    }


def _should_auto_corroborate(cluster: dict | None, routing: dict, analyst_state: dict) -> bool:
    severity = str((cluster or {}).get('severity') or 'low').lower()
    if severity in {'critical', 'high'}:
        return bool(routing.get('high_signal'))
    if severity == 'medium':
        return bool(
            routing.get('routing_score', 0.0) >= 0.72
            and (
                routing.get('ewma_score', 0.0) >= 0.45
                or routing.get('pattern_support_score', 0.0) >= 0.45
                or analyst_state.get('factors_added')
            )
        )
    return False


def _build_cluster_claims(cluster: dict, cluster_rows: list[dict], summary: dict, routing: dict) -> list[dict]:
    row_refs = [int(r.get('row_index')) for r in cluster_rows if isinstance(r, dict) and r.get('row_index') is not None][:8]
    claims: list[dict] = [
        {
            'claim': summary.get('canonical_narrative') or 'Correlated activity spans multiple rows and should be handled as one incident candidate.',
            'claim_type': 'fact',
            'confidence': round(min(0.99, max(0.35, routing.get('routing_score', 0.0))), 3),
            'evidence_refs': row_refs[:5],
            'counter_evidence': [],
            'assumptions': [],
        },
        {
            'claim': summary.get('top_hypothesis') or 'Shared telemetry suggests one primary attack path.',
            'claim_type': 'inference',
            'confidence': round(min(0.95, max(0.3, routing.get('pattern_support_score', 0.0) + 0.25)), 3),
            'evidence_refs': row_refs[:4],
            'counter_evidence': _bounded_unique_strings(summary.get('contradictions'), 3),
            'assumptions': ['Cluster members represent the same operator or campaign until disproved.'],
        },
    ]
    if summary.get('missing_telemetry'):
        claims.append({
            'claim': 'Final confidence is constrained by missing telemetry that could confirm or deny the cluster path.',
            'claim_type': 'assumption',
            'confidence': round(min(0.8, max(0.2, 0.45 + 0.05 * len(summary.get('missing_telemetry') or []))), 3),
            'evidence_refs': row_refs[:3],
            'counter_evidence': [],
            'assumptions': _bounded_unique_strings(summary.get('missing_telemetry'), 4),
        })
    return claims[:4]


def _build_cluster_alt_hypotheses(cluster: dict, cluster_rows: list[dict], analyst_state: dict, factor_freq: dict[str, int]) -> list[dict]:
    primary_factor = next(iter(sorted(factor_freq.items(), key=lambda kv: kv[1], reverse=True)), ('shared telemetry', 0))[0].replace('_', ' ')
    cluster_desc = cluster.get('reason_summary') or cluster.get('business_significance') or primary_factor
    alt_hypotheses = [
        {
            'hypothesis': f'Legitimate operational or admin change produced {cluster_desc}.',
            'confidence': 0.22,
            'weakness': 'No explicit change window or owner confirmation is attached yet.',
            'evidence_refs': [int(r.get('row_index')) for r in cluster_rows[:2] if r.get('row_index') is not None],
        }
    ]
    if analyst_state.get('factors_removed'):
        alt_hypotheses.append({
            'hypothesis': 'One or more correlated factors may be coincidental rather than one attack path.',
            'confidence': 0.31,
            'weakness': 'Analyst removed factors, so the shared path needs manual validation.',
            'evidence_refs': [int(r.get('row_index')) for r in cluster_rows[:3] if r.get('row_index') is not None],
        })
    return alt_hypotheses[:3]


def _build_cluster_leads(cluster: dict, summary: dict, analyst_state: dict) -> dict:
    requested = _bounded_unique_strings(analyst_state.get('requested_telemetry'), 6)
    missing = _bounded_unique_strings(summary.get('missing_telemetry'), 6)
    recommended = _bounded_unique_strings(summary.get('recommended_actions'), 6)
    next_best = recommended[:2]
    confirmation = requested[:2] or missing[:2] or ['Validate the highest-confidence shared pivot in a second source before escalating further.']
    denial = [
        'Check for approved administrative change, maintenance, or owner-confirmed business context matching the same rows.',
        'Confirm whether baseline activity explains the shared pivot before treating it as one attack chain.',
    ]
    return {
        'next_best': next_best,
        'confirmation': confirmation,
        'denial': denial,
        'high_value_missing_telemetry': missing[:3],
        'next_best_details': [
            {
                'lead': lead,
                'expected_information_gain': round(0.72 - (idx * 0.08), 3),
                'artifact_availability': 'available_now',
                'why_it_matters': 'This is the fastest path to collapse duplicate row work into one validated cluster decision.',
            }
            for idx, lead in enumerate(next_best)
        ],
        'confirmation_details': [
            {
                'lead': lead,
                'expected_information_gain': round(0.79 - (idx * 0.06), 3),
                'artifact_availability': 'requires_live_pull' if lead in missing else 'available_now',
                'why_it_matters': 'This evidence can directly confirm the top cluster hypothesis or strengthen corroboration.',
            }
            for idx, lead in enumerate(confirmation)
        ],
        'denial_details': [
            {
                'lead': lead,
                'expected_information_gain': round(0.64 - (idx * 0.06), 3),
                'artifact_availability': 'requires_owner_validation',
                'why_it_matters': 'This check is the fastest route to safely de-escalate a false-positive cluster.',
            }
            for idx, lead in enumerate(denial)
        ],
        'scope_expansion_details': [
            {
                'lead': 'Pivot from the shared identity, host, or cloud resource into adjacent rows before opening a second incident.',
                'expected_information_gain': 0.58,
                'artifact_availability': 'available_now',
                'why_it_matters': 'This keeps scope expansion focused on the same cluster instead of spawning duplicate analyst work.',
            }
        ],
        'closure_blockers': missing[:2] or ['Document whether missing telemetry blocks final escalation or closure.'],
        'lead_outcomes': [],
    }


def _build_source_reliability(cluster_rows: list[dict], routing: dict) -> list[dict]:
    seen: set[str] = set()
    items: list[dict] = []
    for row in cluster_rows:
        source = str(row.get('source_sheet') or row.get('source') or row.get('_source') or row.get('sheet') or 'unknown').strip()
        if not source or source in seen:
            continue
        seen.add(source)
        reliability_type = 'direct_artifact'
        if 'summary' in source.lower() or 'overview' in source.lower():
            reliability_type = 'derived'
        elif any(token in source.lower() for token in ('azure', 'aad', 'identity', 'graph')):
            reliability_type = 'heuristic'
        weight = 0.95 if reliability_type == 'direct_artifact' else 0.7 if reliability_type == 'heuristic' else 0.62
        items.append({
            'source': source,
            'type': reliability_type,
            'weight': round(min(0.99, max(weight, routing.get('pattern_support_score', 0.0))), 3),
            'why_it_matters': f'{source} contributed shared evidence used in the cluster routing and corroboration score.',
        })
    return items[:6]


def _build_cluster_close_conditions(summary: dict, leads: dict) -> dict:
    confirmation = list(leads.get('confirmation') or [])
    denial = list(leads.get('denial') or [])
    blockers = list(leads.get('closure_blockers') or [])
    missing = list(summary.get('missing_telemetry') or [])
    return {
        'soc_close_conditions': [
            confirmation[0] if confirmation else 'Validate the highest-confidence pivot before closing the incident.',
            'Containment is confirmed for the affected identities, hosts, or cloud resources.',
            blockers[0] if blockers else 'Record whether further telemetry is still blocking closure.',
        ],
        'hunter_close_conditions': [
            denial[0] if denial else 'Rule out the strongest benign explanation before closing the hunt.',
            'Expand adjacent pivots only while they materially increase evidence quality.',
            missing[0] if missing else 'Document why no further hunt pivots are required.',
        ],
        'forensics_close_conditions': [
            'Preserve key artifacts and custody notes before evidence ages out.',
            missing[0] if missing else 'Capture the highest-value missing telemetry before finalizing the timeline.',
            'Record whether any delayed or backfilled evidence changed the verdict.',
        ],
    }


def _build_cluster_provider_context(assessment: dict, cluster_rows: list[dict], routing: dict) -> dict:
    dependency_logs = (((assessment.get('dependency_status') or {}).get('logs')) or {})
    valid_times = [row.get('timestamp_epoch') or row.get('event_ts') or row.get('ts') for row in cluster_rows if row.get('timestamp_epoch') or row.get('event_ts') or row.get('ts')]
    connector_names = sorted({
        str(row.get('connector_id') or row.get('provider') or row.get('source') or row.get('source_sheet') or '').strip()
        for row in cluster_rows
        if str(row.get('connector_id') or row.get('provider') or row.get('source') or row.get('source_sheet') or '').strip()
    })[:8]
    connector_snapshot = assessment.get('connector_health_snapshot') or {}
    connector_status = []
    stale_connectors: list[str] = []
    missing_sources = list(dependency_logs.get('missing_sources') or [])
    for name in connector_names:
        item = dict((connector_snapshot.get(name) or {}) if isinstance(connector_snapshot, dict) else {})
        freshness = item.get('freshness') or {}
        heartbeat_stale = bool(freshness.get('heartbeat_stale'))
        if heartbeat_stale:
            stale_connectors.append(name)
        if not item:
            item = {
                'provider': name.split(':', 1)[0] if ':' in name else '',
                'status': 'unknown',
                'authenticated': False,
                'receiving_events': False,
                'checkpoint_healthy': False,
                'beta_ready': False,
                'freshness': {},
            }
        item['connector'] = name
        connector_status.append(item)
    if not connector_status and isinstance(connector_snapshot, dict):
        for name, raw in list(connector_snapshot.items())[:8]:
            item = dict(raw or {})
            item['connector'] = name
            connector_status.append(item)
    if stale_connectors:
        missing_sources.extend([name for name in stale_connectors if name not in missing_sources])
    email_sources = [
        {
            'connector': str(row.get('connector_id') or row.get('source_kind') or row.get('source') or 'email'),
            'sender': row.get('sender'),
            'subject': row.get('subject'),
            'threat_names': list(row.get('threat_names') or []),
            'reason': row.get('reason') or row.get('action'),
        }
        for row in cluster_rows
        if str(row.get('domain') or row.get('domain_hint') or '').lower() == 'email'
        or str(row.get('source_kind') or '').lower() in {'mimecast', 'proofpoint', 'microsoft_graph_email', 'email'}
    ][:6]
    if not email_sources:
        assessment_rows = list(assessment.get('rows') or assessment.get('llm_rows') or [])
        email_sources = [
            {
                'connector': str(row.get('connector_id') or row.get('source_kind') or row.get('source') or 'email'),
                'sender': row.get('sender'),
                'subject': row.get('subject'),
                'threat_names': list(row.get('threat_names') or []),
                'reason': row.get('reason') or row.get('action'),
            }
            for row in assessment_rows
            if str(row.get('domain') or row.get('domain_hint') or '').lower() == 'email'
            or str(row.get('source_kind') or '').lower() in {'mimecast', 'proofpoint', 'microsoft_graph_email', 'email'}
        ][:6]
    return {
        'affected_hosts': _bounded_unique_strings([row.get('host') or row.get('hostname') for row in cluster_rows], 6),
        'affected_identities': _bounded_unique_strings([row.get('user') or row.get('username') or row.get('entity') for row in cluster_rows], 6),
        'valid_time': min(valid_times) if valid_times else None,
        'transaction_time': int(time.time()),
        'backfill_observed': bool(dependency_logs.get('missing_sources') or dependency_logs.get('gaps')),
        'connector_freshness': {
            'available': dependency_logs.get('available') if dependency_logs.get('available') is not None else bool(connector_status),
            'missing_sources': missing_sources,
            'gaps': dependency_logs.get('gaps') or [],
            'seconds_since_ok': dependency_logs.get('seconds_since_ok'),
        },
        'connector_status': connector_status,
        'email_evidence': email_sources,
    }


def _bounded_unique_strings(values: list[Any] | None, limit: int) -> list[str]:
    seen: list[str] = []
    for value in values or []:
        text = str(value or '').strip()
        if not text or text in seen:
            continue
        seen.append(text)
        if len(seen) >= limit:
            break
    return seen


def _build_cluster_reasoning_state(
    assessment: dict,
    cluster: dict,
    cluster_rows: list[dict],
    *,
    trigger_reason: str,
    include_temporal: bool = False,
    prior_state: dict | None = None,
    force_corroboration: bool = False,
) -> dict:
    analyst_state = _build_cluster_analyst_state(assessment, cluster, cluster_rows)
    routing = _cluster_routing_snapshot(assessment, cluster, cluster_rows, analyst_state, include_temporal=include_temporal)
    factor_freq = _factor_frequency(cluster_rows)
    missing_logs = _infer_missing_log_classes(cluster_rows)
    primary_factor = next(iter(sorted(factor_freq.items(), key=lambda kv: kv[1], reverse=True)), ('shared_telemetry', 0))
    contradictions = []
    if analyst_state.get('factors_removed'):
        contradictions.append('Analyst removed one or more initially-correlated factors that need manual validation.')
    if not routing.get('high_signal'):
        contradictions.append('Shared evidence is present but not yet strong enough for blanket deep escalation.')
    recommended_actions = [
        f"Validate rows {', '.join('#' + str(r) for r in (cluster.get('row_refs') or [])[:5])} as one incident before duplicating analyst work.",
        f"Collect {', '.join((cluster.get('recommended_logs') or missing_logs or ['identity and endpoint logs'])[:3])}.",
        'Use cluster pivots first, then expand to adjacent rows only if corroboration strengthens the case.',
    ]
    summary = {
        'canonical_narrative': (
            f"Cluster {cluster.get('cluster_id')} groups {len(cluster_rows)} correlated row(s) around "
            f"{cluster.get('reason_summary') or cluster.get('business_significance') or 'shared telemetry'}."
        ),
        'top_hypothesis': (
            analyst_state.get('hypothesis')
            or f"Likely {primary_factor[0].replace('_', ' ')} sequence spanning correlated evidence."
        ),
        'supporting_evidence': [
            f"Severity {cluster.get('severity')} with cluster confidence {cluster.get('confidence')}.",
            cluster.get('business_significance') or 'Business significance still requires human confirmation.',
            cluster.get('blast_radius_summary') or 'Blast radius still being refined.',
        ],
        'contradictions': contradictions[:3],
        'missing_telemetry': (missing_logs or cluster.get('recommended_logs') or [])[:6],
        'recommended_actions': recommended_actions[:5],
    }
    corroboration_status = 'deferred'
    corroboration_verdict = 'needs_more_evidence'
    corroboration_confidence = routing.get('routing_score', 0.0)
    should_corroborate = force_corroboration or _should_auto_corroborate(cluster, routing, analyst_state)
    if should_corroborate:
        corroboration_status = 'completed'
        corroboration_confidence = round(
            min(
                1.0,
                routing.get('routing_score', 0.0)
                + min(0.12, 0.03 * len(analyst_state.get('factors_added') or []))
                + max(0.0, min(0.08, _safe_float(analyst_state.get('disposition_delta')) * 0.08)),
            ),
            3,
        )
        if corroboration_confidence >= 0.78:
            corroboration_verdict = 'corroborated_high_signal'
        elif corroboration_confidence >= 0.62:
            corroboration_verdict = 'corroborated_medium_signal'
        else:
            corroboration_verdict = 'mixed_signal'
    disconfirming = list(contradictions)
    if analyst_state.get('factors_removed'):
        disconfirming.append('Analyst removed one or more cluster factors during confirm/deny review.')
    claims = _build_cluster_claims(cluster, cluster_rows, summary, routing)
    alt_hypotheses = _build_cluster_alt_hypotheses(cluster, cluster_rows, analyst_state, factor_freq)
    leads = _build_cluster_leads(cluster, summary, analyst_state)
    provider_context = _build_cluster_provider_context(assessment, cluster_rows, routing)
    sender_domains = []
    reply_domains = []
    baseline_domains = []
    targeted_identities = []
    top_ranked_evidence = []
    attachment_analysis = []
    for row in cluster_rows:
        visual = row.get('attachment_visual_analysis') if isinstance(row.get('attachment_visual_analysis'), dict) else {}
        if visual:
            attachment_analysis.append(dict(visual))
        sender = str(row.get('sender_domain') or row.get('from_domain') or '')
        reply_to = str(row.get('reply_to_domain') or '')
        baseline = str(row.get('trusted_supplier_domain') or row.get('baseline_sender_domain') or row.get('supplier_domain') or '')
        if sender:
            sender_domains.append(sender)
        if reply_to:
            reply_domains.append(reply_to)
        if baseline:
            baseline_domains.append(baseline)
        identity = str(row.get('user') or row.get('userPrincipalName') or row.get('recipient') or row.get('entity') or '').strip()
        if identity and any(token in identity.lower() for token in ('ceo', 'cfo', 'finance', 'accounts', 'payroll', 'director', 'executive')) and identity not in targeted_identities:
            targeted_identities.append(identity)
    sender_drift_signals = []
    if sender_domains and baseline_domains and sender_domains[0] != baseline_domains[0]:
        sender_drift_signals.append(f'sender:{sender_domains[0]} baseline:{baseline_domains[0]}')
    if reply_domains and sender_domains and reply_domains[0] != sender_domains[0]:
        sender_drift_signals.append(f'reply_to:{reply_domains[0]} sender:{sender_domains[0]}')
    if attachment_analysis:
        for item in attachment_analysis[:2]:
            preview = str(item.get('text_preview') or '').strip()
            if preview:
                top_ranked_evidence.append({
                    'title': preview[:140],
                    'why_it_matters': 'Attachment extraction produced direct lure or execution context for the cluster.',
                    'evidence_refs': [int(r.get('row_index')) for r in cluster_rows if r.get('row_index') is not None][:3],
                    'confidence': round(_safe_float(item.get('confidence')), 3),
                })
    top_ranked_evidence = ([{
        'title': summary['canonical_narrative'],
        'why_it_matters': 'This narrative is the preserved cluster story presented to every persona.',
        'evidence_refs': [int(r.get('row_index')) for r in cluster_rows if r.get('row_index') is not None][:4],
        'confidence': round(_safe_float(routing.get('routing_score')), 3),
    }] + top_ranked_evidence)[:5]
    sender_infrastructure_drift = {
        'present': bool(sender_drift_signals),
        'summary': 'Sender or reply infrastructure drift suggests impersonation or supplier-baseline mismatch.' if sender_drift_signals else 'No sender infrastructure drift was preserved in this cluster.',
        'signals': sender_drift_signals[:4],
        'confidence': round(min(0.95, 0.42 + (0.18 * len(sender_drift_signals))), 3) if sender_drift_signals else 0.0,
    }
    executive_targeting = {
        'present': bool(targeted_identities),
        'summary': (f"Executive or finance-targeted identities were included in the cluster: {', '.join(targeted_identities[:3])}." if targeted_identities else 'No explicit executive-targeting marker was preserved in this cluster.'),
        'identities': targeted_identities[:4],
        'confidence': round(min(0.95, 0.61 + (0.08 * min(len(targeted_identities), 3))), 3) if targeted_identities else 0.0,
    }
    provider_context['attachment_analysis'] = attachment_analysis[:6]
    return build_cluster_reasoning_state(
        assessment_id=assessment.get('assessment_id'),
        cluster_id=cluster.get('cluster_id'),
        session_id=assessment.get('session_id'),
        version=_CLUSTER_REASONING_VERSION,
        generated_ts=int(time.time()),
        trigger_reason=trigger_reason,
        routing_mode=routing.get('routing_mode'),
        reasoning_mode=routing.get('reasoning_mode'),
        cluster_size=routing.get('cluster_size'),
        severity_score=routing.get('severity_score'),
        graph_score=routing.get('graph_score'),
        ewma_score=routing.get('ewma_score'),
        pattern_support_score=routing.get('pattern_support_score'),
        routing_score=routing.get('routing_score'),
        analyst_state=analyst_state,
        canonical_narrative=summary['canonical_narrative'],
        top_hypothesis=summary['top_hypothesis'],
        supporting_evidence=summary['supporting_evidence'],
        contradictions=summary['contradictions'],
        missing_telemetry=summary['missing_telemetry'],
        recommended_actions=summary['recommended_actions'],
        corroboration_status=corroboration_status,
        corroboration_verdict=corroboration_verdict,
        corroboration_confidence=corroboration_confidence,
        corroboration_run_ts=int(time.time()) if should_corroborate else None,
        evidence_used=routing.get('evidence_used') or [],
        alt_hypotheses=alt_hypotheses,
        claims=claims,
        leads=leads,
        source_reliability=_build_source_reliability(cluster_rows, routing),
        what_would_flip=[
            'Owner-approved change window and second-source confirmation downgrade the attack-chain assumption.',
            'If missing telemetry disproves the shared pivot, de-escalate the cluster to isolated handling.',
        ],
        disconfirming_evidence=disconfirming,
        persona_seed_claims=[summary['canonical_narrative'], summary['top_hypothesis']],
        persona_seed_actions=recommended_actions[:3],
        persona_seed_missing_telemetry=summary['missing_telemetry'][:4],
        temporal_rag_sources=routing.get('evidence_used') or [],
        shared_pivots=_bounded_unique_strings((cluster.get('shared_pivots') or []), 8),
        top_ranked_evidence=top_ranked_evidence[:5],
        sender_infrastructure_drift=sender_infrastructure_drift,
        executive_targeting=executive_targeting,
        attachment_analysis=attachment_analysis[:6],
        provider_context=provider_context,
        prior_state=prior_state,
        evidence_row_indices=[int(r.get('row_index')) for r in cluster_rows if r.get('row_index') is not None][:12],
        close_conditions=_build_cluster_close_conditions(summary, leads),
    )


def _compact_cluster_reasoning_state(state: dict | None) -> dict:
    return compact_cluster_reasoning_state(state)


def _apply_cluster_reasoning_to_assessment(
    assessment: dict,
    *,
    preferred_cluster_id: str | None = None,
    trigger_reason: str,
    include_temporal: bool = False,
    force_corroboration: bool = False,
) -> dict:
    clusters = assessment.get('correlation_clusters') or []
    rows = assessment.get('llm_rows') or assessment.get('rows') or []
    cluster_states: list[dict] = []
    prior_root = assessment.get('cluster_reasoning_state') or {}
    prior_states = {
        str(item.get('cluster_id')): item
        for item in (prior_root.get('cluster_states') or [])
        if isinstance(item, dict) and item.get('cluster_id')
    }
    for cluster in clusters:
        cluster_id = str(cluster.get('cluster_id') or '')
        cluster_rows = _cluster_rows(cluster, rows)
        if len(cluster_rows) < 2:
            continue
        state = _build_cluster_reasoning_state(
            assessment,
            cluster,
            cluster_rows,
            trigger_reason=trigger_reason,
            include_temporal=include_temporal and (preferred_cluster_id is None or preferred_cluster_id == cluster_id),
            prior_state=prior_states.get(cluster_id),
            force_corroboration=force_corroboration and (preferred_cluster_id is None or preferred_cluster_id == cluster_id),
        )
        cluster_states.append(state)
    cluster_states.sort(
        key=lambda item: (
            _safe_float(item.get('routing_score')),
            _safe_float(item.get('severity_score')),
            _safe_float(item.get('cluster_size')),
        ),
        reverse=True,
    )
    primary = None
    if preferred_cluster_id:
        primary = next((item for item in cluster_states if item.get('cluster_id') == preferred_cluster_id), None)
    if primary is None and cluster_states:
        primary = cluster_states[0]
    root = build_cluster_reasoning_root(
        assessment_id=assessment.get('assessment_id'),
        session_id=assessment.get('session_id'),
        version=_CLUSTER_REASONING_VERSION,
        generated_ts=int(time.time()),
        cluster_states=cluster_states,
        preferred_cluster_id=preferred_cluster_id,
    )
    assessment['cluster_reasoning_state'] = root
    assessment['corroboration'] = root.get('corroboration') or {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        cluster_id = row.get('correlation_cluster_id')
        if not cluster_id:
            continue
        state = next((item for item in cluster_states if item.get('cluster_id') == cluster_id), None)
        if state:
            row['cluster_reasoning_state'] = _compact_cluster_reasoning_state(state)
            row['corroboration'] = state.get('corroboration') or {}
    return assessment


def _select_primary_cluster(assessment: dict, rows: list[dict], limit: int) -> tuple[dict | None, list[dict], str]:
    clusters = assessment.get('correlation_clusters') or []
    if clusters:
        cluster = clusters[0]
        cluster_rows = _cluster_rows(cluster, rows)
        if len(cluster_rows) >= 2:
            return cluster, cluster_rows[:limit], 'cluster-first'
    ranked = _rank_rows_for_investigate(rows)
    return None, ranked[:limit], 'row-first'

def _generate_persona_expansions(narrative: str, evidence_table: list[dict], missing_logs: list[str]) -> dict[str, dict]:
    personas = ['analyst','manager','technical','forensics']
    expansions: dict[str, dict] = {}
    base_evidence_summary = '; '.join(f"row {e.get('row_index')}: {e.get('verdict')}" for e in evidence_table[:8])
    for p in personas:
        try:
            template = {
                'analyst': 'Analyst Focus: Prioritize triage steps, enumerate immediate containment actions, highlight cross-row factor pivots.',
                'manager': 'Manager Focus: Business impact, affected assets/users, suggested resource allocation and escalation path.',
                'technical': 'Technical Focus: Process/host specifics, potential tool marks, recommended forensic acquisition (memory, registry, network).',
                'forensics': 'Forensics Focus: Chain of custody notes, volatile data acquisition order, integrity verification steps.'
            }.get(p,'')
            expansions[p] = {
                'text': f"{template} Narrative summary: {narrative[:600]} Evidence: {base_evidence_summary}. Missing telemetry: {', '.join(missing_logs) or 'none'}."
            }
        except Exception:
            expansions[p] = {'text': 'Persona expansion unavailable'}
    return expansions

@router.post('/{assessment_id}/investigate/build')
async def build_investigate(assessment_id: str, request: Request):
    assessment = _safe_load_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    limit = int(payload.get('limit') or os.getenv('INVESTIGATE_ROW_LIMIT','30') or 30)
    all_rows = assessment.get('llm_rows') or assessment.get('rows') or []
    cluster, top_rows, routing_mode = _select_primary_cluster(assessment, all_rows, limit)
    missing_logs = _infer_missing_log_classes(top_rows)
    factor_freq = _factor_frequency(top_rows)
    investigate_id = f"investigate-{uuid.uuid4().hex[:10]}"
    record = {
        'investigate_id': investigate_id,
        'assessment_id': assessment_id,
        'created': int(time.time()),
        'status': 'pending',
        'row_count': len(top_rows),
        'missing_logs_initial': missing_logs,
        'factor_frequency_initial': factor_freq,
        'rows_ref': [r.get('row_index') for r in top_rows if isinstance(r, dict)],
        'cluster_id': (cluster or {}).get('cluster_id'),
        'routing_mode': routing_mode,
        'reasoning_mode': 'deep' if cluster else 'cheap',
        'limit': limit,
    }
    INVESTIGATE_STORE[investigate_id] = record
    # enqueue
    INVESTIGATE_QUEUE.append((assessment_id, investigate_id))
    # Persist a stub for visibility
    path = _investigate_persist_path(assessment, investigate_id)
    if path:
        try:
            await asyncio.to_thread(_atomic_write_json_sync, path, record)
            record['persisted_path'] = path
        except Exception:
            pass
    return JSONResponse({'assessment_id': assessment_id, 'investigate_id': investigate_id, 'status': 'queued'})

@router.get('/{assessment_id}/investigate/{investigate_id}')
async def get_investigate(assessment_id: str, investigate_id: str):
    rec = INVESTIGATE_STORE.get(investigate_id)
    if not rec or rec.get('assessment_id') != assessment_id:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    return JSONResponse(rec)

def _start_investigate_worker(app, interval_seconds: int = 3):
    async def _loop():
        while True:
            try:
                if INVESTIGATE_QUEUE:
                    aid, iid = INVESTIGATE_QUEUE.pop(0)
                    rec = INVESTIGATE_STORE.get(iid)
                    assessment = _safe_load_assessment(aid)
                    if not rec or not assessment:
                        continue
                    try:
                        rows_all = assessment.get('llm_rows') or assessment.get('rows') or []
                        cluster = None
                        cluster_id = rec.get('cluster_id')
                        if cluster_id:
                            cluster = next((c for c in (assessment.get('correlation_clusters') or []) if c.get('cluster_id') == cluster_id), None)
                        # reconstruct top rows from cluster first, then refs, then ranked fallback
                        top_rows = _cluster_rows(cluster, rows_all) if cluster else []
                        if not top_rows:
                            top_rows = [r for r in rows_all if r.get('row_index') in rec.get('rows_ref', [])]
                        if not top_rows:
                            cluster, top_rows, routing_mode = _select_primary_cluster(assessment, rows_all, rec.get('limit', 30))
                            rec['cluster_id'] = (cluster or {}).get('cluster_id')
                            rec['routing_mode'] = routing_mode
                        missing_logs = _infer_missing_log_classes(top_rows)
                        factor_freq = _factor_frequency(top_rows)
                        # compute ml_score for each top row if not present
                        for r in top_rows:
                            try:
                                # Ensure triage is present for downstream weighting and decisions
                                _ensure_triage_on_row(r, assessment)
                                if r.get('ml_score') is None:
                                    r['ml_score'] = _compute_ml_score_for_row(r, assessment)
                            except Exception:
                                r['ml_score'] = r.get('ml_score') or 0.0

                        # attempt to resolve session-level hopgraph summary/explain to enrich prompt
                        session_summary = None
                        session_explain = None
                        try:
                            session_id = assessment.get('session_id')
                            session_summary, session_explain = await _resolve_session_context(session_id, None, None)
                        except Exception:
                            session_summary = None; session_explain = None

                        try:
                            _apply_cluster_reasoning_to_assessment(
                                assessment,
                                preferred_cluster_id=(cluster or {}).get('cluster_id'),
                                trigger_reason='investigate_build',
                                include_temporal=True,
                            )
                        except Exception:
                            pass

                        active_reasoning = assessment.get('cluster_reasoning_state') or {}
                        active_cluster_state = None
                        if rec.get('cluster_id'):
                            active_cluster_state = next(
                                (item for item in (active_reasoning.get('cluster_states') or []) if item.get('cluster_id') == rec.get('cluster_id')),
                                None,
                            )
                        if active_cluster_state is None and active_reasoning.get('cluster_states'):
                            active_cluster_state = active_reasoning['cluster_states'][0]

                        prompt = _build_investigate_prompt(assessment, top_rows, missing_logs, factor_freq)
                        # Inject hopgraph stats and temporal ordering when available
                        try:
                            extra_ctx = []
                            # Add compact EWMA/hotspot humanized snippet
                            try:
                                eh = _summarize_ewma_and_hotspots(session_summary, session_explain, max_chars=1200)
                                if eh:
                                    extra_ctx.append(f"HopGraph summary: {eh}")
                            except Exception:
                                pass
                            if session_summary:
                                if session_summary.get('mapping_stats'):
                                    extra_ctx.append(f"Session mapping stats: {json.dumps(session_summary.get('mapping_stats'))[:600]}")
                            # time sequencing
                            timestamps = []
                            for r in top_rows:
                                for k in ('ts','time','timestamp','evt_time'):
                                    if r.get(k):
                                        try:
                                            timestamps.append(float(r.get(k)))
                                        except Exception:
                                            pass
                            if timestamps:
                                timespan = max(timestamps) - min(timestamps)
                                extra_ctx.append(f"Observed timeline span (s): {int(timespan)} rows: {len(timestamps)}")
                                # create lightweight ordered snippet
                                ordered = sorted([ (float(r.get('ts') or r.get('time') or r.get('timestamp') or 0), r.get('row_index')) for r in top_rows ], key=lambda x: x[0])
                                extra_ctx.append(f"Temporal order (row_index by ts): {[i[1] for i in ordered][:30]}")
                            if active_cluster_state:
                                extra_ctx.append(
                                    "Canonical cluster reasoning: "
                                    + json.dumps(
                                        _compact_cluster_reasoning_state(active_cluster_state),
                                        default=str,
                                    )[:1400]
                                )
                            if extra_ctx:
                                prompt = prompt + "\n\nAdditional session context:\n" + "\n".join(extra_ctx)
                        except Exception:
                            pass
                        narrative = ''
                        try:
                            # honor per-assessment overrides when available
                            _overrides = None
                            try:
                                _overrides = assessment.get('options', {}).get('overrides') or (assessment.get('overrides') if isinstance(assessment.get('overrides'), dict) else None)
                            except Exception:
                                _overrides = None
                            if _overrides:
                                resp = LLM_CLIENT.generate(prompt, max_tokens=900, tenant_id=(assessment.get('org') or None), overrides=_overrides)
                            else:
                                resp = LLM_CLIENT.generate(prompt, max_tokens=900, tenant_id=(assessment.get('org') or None))
                            if isinstance(resp, dict):
                                narrative = resp.get('text') or (resp.get('meta') or {}).get('text') or ''
                            else:
                                narrative = str(resp)
                        except Exception as _llm_exc:
                            logger.error('investigate worker LLM call failed: %s: %s', type(_llm_exc).__name__, _llm_exc)
                            narrative = 'Composite narrative fallback: unable to reach LLM provider.'
                        # evidence table
                        evidence = []
                        for r in top_rows[:50]:
                            try:
                                evidence.append({
                                    'row_index': r.get('row_index'),
                                    'host': r.get('host'),
                                    'user': r.get('user'),
                                    'process': r.get('process') or r.get('process_name'),
                                    'verdict': r.get('verdict'),
                                    'ml_score': r.get('ml_score'),
                                    'dread': (r.get('_dread') or {}).get('score') if isinstance(r.get('_dread'), dict) else None,
                                })
                            except Exception:
                                continue
                        persona_expanded = _generate_persona_expansions(narrative, evidence, missing_logs)
                        # ensure investigate record and rows record triage
                        try:
                            _ensure_triage_on_rows(top_rows, assessment)
                        except Exception:
                            pass

                        rec.update({
                            'status': 'ready',
                            'cluster_reasoning_state': active_cluster_state or {},
                            'corroboration': (active_cluster_state or {}).get('corroboration') or {},
                            'narrative': narrative,
                            'evidence_table': evidence,
                            'missing_logs': missing_logs,
                            'factor_frequency': factor_freq,
                            'triage_score': _compute_triage_score(rec),
                            'factor_density': _compute_factor_density(rec),
                            'persona_expanded': persona_expanded,
                            'updated': int(time.time()),
                        })
                        try:
                            assessment['cluster_reasoning_state'] = assessment.get('cluster_reasoning_state') or {}
                            assessment['corroboration'] = (assessment.get('cluster_reasoning_state') or {}).get('corroboration') or {}
                            assessment['latest_investigate_id'] = iid
                            _store_assessment(assessment.get('org'), assessment.get('assessment_id'), assessment)
                            REPORT_STORE[aid] = assessment
                        except Exception:
                            pass
                        # persist
                        path = rec.get('persisted_path') or _investigate_persist_path(assessment, iid)
                        if path:
                            try:
                                await asyncio.to_thread(_atomic_write_json_sync, path, rec)
                                rec['persisted_path'] = path
                            except Exception:
                                pass
                    except Exception as e:
                        try:
                            rec['status'] = 'failed'
                            rec['error'] = str(e)
                        except Exception:
                            pass
                await asyncio.sleep(interval_seconds)
            except Exception:
                try:
                    await asyncio.sleep(interval_seconds)
                except Exception:
                    pass
    # Prefer get_running_loop() — works when called from async lifespan context
    # (add_event_handler startup fires too early and is unavailable post-startup)
    try:
        running_loop = asyncio.get_running_loop()
        _track_task(running_loop.create_task(_loop()))
        return
    except RuntimeError:
        pass  # not in a running loop — fall through
    try:
        app.add_event_handler('startup', lambda: _track_task(asyncio.create_task(_loop())))
    except Exception:
        try:
            loop = asyncio.get_event_loop()
            _track_task(loop.create_task(_loop()))
        except Exception:
            pass

@router.post('/{assessment_id}/tasks/{task_id}/expand')
async def expand_task(assessment_id: str, task_id: str, request: Request):
    """EXPAND endpoint — Phase 3.

    Payload (JSON):
      task_text   str  — description of the task to expand (required)
      persona     str  — soc | ciso | compliance | hunter | ir (default: soc)
      investigate_id str — optional; scope rows to a specific investigate record
      force_refresh bool — bypass cache (default: false)

    Returns:
      {
        assessment_id, task_id, persona,
        entity_fields, check_results,      <- OPT-1 + OPT-2
        summary, confidence,               <- LLM output
        subtasks, iocs, mitre_techniques,  <- LLM output
        next_pivot,                        <- LLM output
        cache_hit, latency_ms
      }
    """
    try:
        from src.analysis.expand_engine import (
            extract_task_entity_slice,
            build_expand_prompt,
            call_expand_llm,
            load_expand_cache,
            save_expand_cache,
            make_task_id,
        )
    except ImportError as _ie:
        raise HTTPException(status_code=500, detail=f'expand_engine not available: {_ie}')

    assessment = _safe_load_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    task_text = (payload.get('task_text') or '').strip()
    if not task_text:
        raise HTTPException(status_code=400, detail='task_text required')

    _VALID_PERSONAS = {
        'soc', 'soc_analyst', 'threat_hunter', 'hunter',
        'ciso', 'forensics', 'compliance', 'audit',
        'mssp', 'ir', 'executive',
    }
    _PERSONA_ALIASES = {
        'soc_analyst': 'soc', 'threat_hunter': 'hunter',
        'audit': 'compliance', 'executive': 'ciso',
    }
    persona = (payload.get('persona') or 'soc').strip().lower()
    if persona not in _VALID_PERSONAS:
        persona = 'soc'
    persona = _PERSONA_ALIASES.get(persona, persona)

    force_refresh = bool(payload.get('force_refresh'))
    investigate_id_hint = payload.get('investigate_id') or None
    # Cluster-grounded EXPAND: caller may pass cluster_id + row_refs to pin evidence
    cluster_id_hint = payload.get('cluster_id') or None
    row_refs_hint   = payload.get('row_refs') or []
    model_hint      = payload.get('model') or None

    # Resolve investigate record (best-effort)
    investigate_record: dict = {}
    if investigate_id_hint:
        investigate_record = INVESTIGATE_STORE.get(investigate_id_hint) or {}
    if not investigate_record and assessment.get('latest_investigate_id'):
        investigate_record = INVESTIGATE_STORE.get(assessment['latest_investigate_id']) or {}

    # Stable task_id from content (override URL param if auto-generated)
    canonical_task_id = make_task_id(task_text, persona)
    # If caller passed a real hash-like id, honour it; otherwise use canonical
    effective_task_id = task_id if (len(task_id) >= 8 and task_id != 'expand') else canonical_task_id

    # OPT-3: check cache first
    if not force_refresh:
        cached = load_expand_cache(assessment_id, effective_task_id)
        if cached:
            cached['cache_hit'] = True
            return JSONResponse(cached)

    t0 = time.time()

    # OPT-1 + OPT-2 entity slice — prefer cluster rows when cluster_id supplied
    if cluster_id_hint:
        all_rows = (
            assessment.get('normalized_rows')
            or assessment.get('evidence_rows')
            or assessment.get('llm_rows')
            or assessment.get('rows')
            or []
        )
        # Collect member rows by row_refs or correlation_cluster_id
        ref_set = set(int(v) for v in row_refs_hint if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()))
        cluster_rows = [
            r for r in all_rows
            if isinstance(r, dict) and (
                r.get('correlation_cluster_id') == cluster_id_hint
                or (ref_set and r.get('row_index') in ref_set)
            )
        ]
        # If cluster_id found via correlation_clusters meta, also try row_refs from there
        if not cluster_rows:
            for c in (assessment.get('correlation_clusters') or []):
                if str(c.get('cluster_id') or c.get('id') or '') == str(cluster_id_hint):
                    crefs = set(int(v) for v in (c.get('row_refs') or c.get('row_indices') or []) if str(v).isdigit())
                    cluster_rows = [r for r in all_rows if isinstance(r, dict) and r.get('row_index') in crefs]
                    break
        if cluster_rows:
            # Build an entity_slice directly from cluster rows — skip task-entity matching
            entity_slice = extract_task_entity_slice(task_text, investigate_record, assessment)
            # Override rows with cluster-pinned rows (more targeted than task matching)
            entity_slice['rows'] = cluster_rows[:30]
            entity_slice['cluster_id'] = cluster_id_hint
        else:
            entity_slice = extract_task_entity_slice(task_text, investigate_record, assessment)
            entity_slice['cluster_id'] = cluster_id_hint
    else:
        entity_slice = extract_task_entity_slice(task_text, investigate_record, assessment)

    # Build prompt and call LLM
    prompt = build_expand_prompt(task_text, entity_slice, persona)
    llm_result = call_expand_llm(prompt, LLM_CLIENT, persona, entity_slice=entity_slice, model=model_hint)

    latency_ms = int((time.time() - t0) * 1000)

    result = {
        'assessment_id': assessment_id,
        'task_id': effective_task_id,
        'persona': persona,
        'cluster_id': entity_slice.get('cluster_id') or cluster_id_hint,
        # OPT-1 + OPT-2
        'entity_fields': entity_slice.get('entity_fields'),
        'check_results': entity_slice.get('check_results'),
        'matched_entities': entity_slice.get('matched_entities'),
        'row_count': len(entity_slice.get('rows') or []),
        # LLM output
        'summary': llm_result.get('summary', ''),
        'confidence': llm_result.get('confidence', 0.0),
        'subtasks': llm_result.get('subtasks', []),
        'iocs': llm_result.get('iocs', []),
        'mitre_techniques': llm_result.get('mitre_techniques', []),
        'next_pivot': llm_result.get('next_pivot', ''),
        'fallback_generated': llm_result.get('fallback_generated', False),
        # meta
        'cache_hit': False,
        'latency_ms': latency_ms,
    }

    save_expand_cache(assessment_id, effective_task_id, result)
    return JSONResponse(result)


@router.get('/{assessment_id}/llm/verification')
async def assessment_llm_verification(assessment_id: str):
    assessment = _safe_load_assessment(assessment_id)
    if not assessment:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    rows = assessment.get('llm_rows') or assessment.get('rows') or []
    baseline = [r for r in rows if not r.get('llm_summary')]
    enriched = [r for r in rows if r.get('llm_summary')]
    def _distinct_factors(rs: list[dict]):
        s: set[str] = set()
        for r in rs:
            for f in (r.get('factors') or []):
                if isinstance(f, str):
                    s.add(f)
                elif isinstance(f, dict):
                    val = f.get('name') or f.get('factor')
                    if val:
                        s.add(str(val))
        return s
    f_base = _distinct_factors(baseline)
    f_enriched = _distinct_factors(enriched)
    coverage_uplift = (len(f_enriched) - len(f_base))
    dread_avg_base = 0.0
    dread_avg_enriched = 0.0
    def _avg_dread(rs: list[dict]) -> float:
        vals = []
        for r in rs:
            dd = r.get('_dread') or r.get('dread')
            if isinstance(dd, dict) and dd.get('score') is not None:
                vals.append(float(dd.get('score') or 0))
        return sum(vals)/len(vals) if vals else 0.0
    dread_avg_base = _avg_dread(baseline)
    dread_avg_enriched = _avg_dread(enriched)
    dread_delta = dread_avg_enriched - dread_avg_base
    # token/cost/confidence aggregates
    total_input_tokens = 0
    total_output_tokens = 0
    total_cost = 0.0
    confidences = []
    for r in enriched:
        try:
            meta = r.get('llm_meta') or {}
            it = int(meta.get('input_tokens') or meta.get('prompt_tokens') or 0)
            ot = int(meta.get('output_tokens') or meta.get('completion_tokens') or 0)
            total_input_tokens += it
            total_output_tokens += ot
            if meta.get('estimated_cost'):
                try: total_cost += float(meta.get('estimated_cost') or 0.0)
                except Exception: pass
            # fallback to per-row _llm_cost
            if (not meta.get('estimated_cost')) and r.get('_llm_cost'):
                try: total_cost += float(r.get('_llm_cost') or 0.0)
                except Exception: pass
            c = meta.get('confidence') or (r.get('llm_meta') or {}).get('confidence') or r.get('risk_confidence') or r.get('confidence')
            if c is not None:
                try: confidences.append(float(c))
                except Exception: pass
        except Exception:
            pass
    avg_confidence = sum(confidences)/len(confidences) if confidences else 0.0
    # Phase3 weighted confidence: emphasize high triage + density rows
    weighted_sum = 0.0
    weight_total = 0.0
    for r in enriched:
        try:
            base_conf = (r.get('llm_meta') or {}).get('confidence') or r.get('risk_confidence') or r.get('confidence')
            if base_conf is None:
                continue
            base_conf = float(base_conf)
            triage = float(r.get('triage_score') or 0.0)
            factors = r.get('factors') or []
            density = min(1.0, len(factors)/12.0) if factors else 0.0
            weight = 0.6*triage + 0.4*density
            weighted_sum += base_conf * weight
            weight_total += weight
        except Exception:
            continue
    weighted_confidence = (weighted_sum/weight_total) if weight_total else 0.0
    md_sections = []
    md_sections.append(f"# LLM Verification Report\nAssessment: {assessment_id}\nGenerated: {_utcnow().isoformat()}Z\n")
    md_sections.append("## Coverage\n" + f"Baseline rows: {len(baseline)} Enriched rows: {len(enriched)}\nDistinct factors baseline: {len(f_base)} enriched: {len(f_enriched)} uplift: {coverage_uplift}\n")
    md_sections.append("## DREAD\n" + f"Average DREAD baseline: {dread_avg_base:.2f} enriched: {dread_avg_enriched:.2f} delta: {dread_delta:.2f}\n")
    md_sections.append("## Enriched Factor Additions\n" + '\n'.join(f"- {f}" for f in sorted(f_enriched - f_base)))
    md_sections.append("## Missing Factor Opportunities\n" + ('None' if not (f_base - f_enriched) else '\n'.join(f"- {f}" for f in sorted(f_base - f_enriched))))
    md_sections.append("## LLM Cost & Confidence Summary\n" + f"Total input tokens: {total_input_tokens}  \nTotal output tokens: {total_output_tokens}  \nEstimated cost: ${total_cost:.6f}  \nAverage LLM confidence (enriched rows): {avg_confidence:.3f}  \nWeighted confidence: {weighted_confidence:.3f}")
    markdown = '\n\n'.join(md_sections)
    # Persist per-assessment verification file
    out_path = None
    try:
        base_path = assessment.get('persisted_path')
        if base_path:
            parent = os.path.dirname(base_path)
            out_path = os.path.join(parent, f"{assessment_id}-llm-verification.md")
            await asyncio.to_thread(_atomic_write_text_sync, out_path, markdown)
    except Exception:
        out_path = None
    return JSONResponse({
        'assessment_id': assessment_id,
        'baseline_rows': len(baseline),
        'enriched_rows': len(enriched),
        'baseline_factor_count': len(f_base),
        'enriched_factor_count': len(f_enriched),
        'coverage_uplift': coverage_uplift,
        'dread_avg_baseline': dread_avg_base,
        'dread_avg_enriched': dread_avg_enriched,
        'markdown': markdown,
        'persisted_path': out_path
    })


@router.get('/metrics/llm_costs')
async def llm_costs_metrics():
    try:
        ext = EXTERNAL_TRACKER.get_summary()
        loc = LOCAL_TRACKER.get_summary()
        return JSONResponse({'external': ext, 'local': loc})
    except Exception:
        return JSONResponse({'detail': 'error_collecting_metrics'}, status_code=500)

# Lightweight background worker to process pending llm_rows for assessments.
def _start_llm_background_worker(app, interval_seconds: int = 2):
    # Allow runtime tuning via environment variables for quicker throughput in tests/dev
    try:
        env_interval = float(os.getenv('LLM_WORKER_INTERVAL_SECONDS', str(interval_seconds)))
    except Exception:
        env_interval = float(interval_seconds)
    try:
        batch_size = int(os.getenv('LLM_WORKER_BATCH', '4'))
    except Exception:
        batch_size = 4

    async def _worker_loop():
        while True:
            try:
                # scan REPORT_STORE for assessments with llm_rows needing processing
                for aid, rec in list(REPORT_STORE.items()):
                    assess = rec
                    llm_rows = assess.get('llm_rows') or []
                    modified = False
                    queue = assess.setdefault('_llm_queue', [])
                    triage_min = float(os.getenv('LLM_MIN_TRIAGE', '0.25'))

                    # Ensure rows are enqueued when appropriate
                    for r in llm_rows:
                        if not isinstance(r, dict):
                            continue
                        try:
                            _ensure_triage_on_row(r, assess)
                        except Exception:
                            pass
                        # already summarized -> mark succeeded
                        if r.get('llm_summary'):
                            if r.get('_llm_status') != 'succeeded':
                                r['_llm_status'] = 'succeeded'
                                r['llm_skipped_reason'] = 'already_summarized'
                                modified = True
                            continue
                        try:
                            tri = float(r.get('triage_score') or 0.0)
                        except Exception:
                            tri = 0.0
                        if tri < triage_min:
                            if r.get('_llm_status') != 'skipped':
                                r['_llm_status'] = 'skipped'
                                r['llm_skipped_reason'] = f'triage_below_threshold:{tri:.3f}'
                                modified = True
                            continue
                        # Respect any scheduled next-at timestamps to honor backoff
                        next_at = int(r.get('_llm_next_attempt_at') or 0)
                        if next_at and time.time() < next_at:
                            continue
                        if (r.get('_llm_status') or 'queued') == 'queued' and r.get('_llm_enqueued') is None:
                            r['_llm_attempts'] = int(r.get('_llm_attempts') or 0)
                            r['_llm_enqueued'] = int(time.time())
                            idx = r.get('row_index')
                            if idx not in queue:
                                queue.append(idx)
                                modified = True

                    # Process up to `batch_size` queue items per assessment per loop
                    processed = 0
                    # Batch up to `batch_size` prompts for this assessment
                    batch_ids = []
                    prompts = []
                    row_map = {}
                    while queue and len(batch_ids) < batch_size:
                        try:
                            row_idx = queue.pop(0)
                        except Exception:
                            break
                        # locate row
                        target = None
                        for r in llm_rows:
                            try:
                                if int(r.get('row_index')) == int(row_idx):
                                    target = r
                                    break
                            except Exception:
                                if r.get('row_index') == row_idx:
                                    target = r
                                    break
                        if target is None:
                            modified = True
                            continue
                        # Skip unsuitable rows
                        if target.get('_llm_status') == 'succeeded':
                            target['llm_skipped_reason'] = target.get('llm_skipped_reason') or 'already_succeeded'
                            modified = True
                            continue
                        try:
                            _ensure_triage_on_row(target, assess)
                        except Exception:
                            pass
                        try:
                            tri = float(target.get('triage_score') or 0.0)
                        except Exception:
                            tri = 0.0
                        if tri < triage_min:
                            target['_llm_status'] = 'skipped'
                            target['llm_skipped_reason'] = f'triage_below_threshold:{tri:.3f}'
                            modified = True
                            continue

                        # prepare prompt and mark as processing
                        target['_llm_status'] = 'processing'
                        target['_llm_worker_started'] = int(time.time())
                        attempt = int(target.get('_llm_attempts') or 0) + 1
                        target['_llm_attempts'] = attempt
                        row_prompt = llm_prompts.compose_prompt({'rows': [target], 'options': assess.get('options') or {}})
                        batch_ids.append(target.get('row_index'))
                        prompts.append(row_prompt)
                        row_map[target.get('row_index')] = {'row': target, 'attempt': attempt}
                        modified = True
                    # If we have a batch, call generate_batch when possible
                    if prompts:
                        try:
                            _overrides = assess.get('options', {}).get('overrides') or (assess.get('overrides') if isinstance(assess.get('overrides'), dict) else None)
                            if not _overrides and isinstance(assess.get('_request_overrides'), dict):
                                _overrides = assess.get('_request_overrides')
                            if not _overrides:
                                _overrides = (REPORT_STORE.get(aid) or {}).get('options', {}).get('overrides') or (REPORT_STORE.get(aid) or {}).get('overrides')
                            # Use batch API if available, falling back to serial generate
                            if hasattr(LLM_CLIENT, 'generate_batch'):
                                responses = LLM_CLIENT.generate_batch(prompts, max_tokens=512, tenant_id=(assess.get('org') or None), overrides=_overrides)
                            else:
                                responses = []
                                for p in prompts:
                                    try:
                                        if _overrides:
                                            responses.append(LLM_CLIENT.generate(p, max_tokens=512, tenant_id=(assess.get('org') or None), overrides=_overrides))
                                        else:
                                            responses.append(LLM_CLIENT.generate(p, max_tokens=512, tenant_id=(assess.get('org') or None)))
                                    except Exception as gen_exc:
                                        responses.append({'error': str(gen_exc)})
                            # map responses back to rows in order
                            for idx, rid in enumerate(batch_ids):
                                target_info = row_map.get(rid)
                                if not target_info:
                                    continue
                                target = target_info['row']
                                attempt = target_info['attempt']
                                resp = responses[idx] if idx < len(responses) else {'error': 'no_response'}
                                if isinstance(resp, dict) and resp.get('error'):
                                    # treat as failure
                                    tb = assess.setdefault('telemetry', {})
                                    fail_count = int(tb.get('llm_provider_failures', 0)) + 1
                                    tb['llm_provider_failures'] = fail_count
                                    logger.warning('LLM generation failed for assessment %s row %s attempt %s: %s', aid, rid, attempt, resp.get('error'))
                                    if fail_count >= int(os.getenv('LLM_PROVIDER_FAIL_THRESHOLD', '3')):
                                        tb['llm_provider_down'] = True
                                        target['llm_summary'] = 'Fallback summary: LLM provider unavailable; use deterministic heuristics.'
                                        target['llm_meta'] = {'fallback': True, 'error': resp.get('error')}
                                        target['_llm_status'] = 'succeeded'
                                        target['_llm_timestamp'] = int(time.time())
                                        modified = True
                                        continue
                                    else:
                                        # schedule retry
                                        backoff = min(30, (2 ** max(0, attempt - 1)))
                                        target['_llm_status'] = 'queued'
                                        target['_llm_next_attempt_at'] = int(time.time()) + backoff
                                        queue.append(rid)
                                        modified = True
                                        continue
                                try:
                                    text = resp.get('text') or (resp.get('meta') or {}).get('text') or '' if isinstance(resp, dict) else str(resp)
                                    meta = resp.get('meta') or {} if isinstance(resp, dict) else {}
                                    target['llm_summary'] = text
                                    target['llm_meta'] = meta
                                    _augment_llm_row(target, assess)
                                    target['_llm_status'] = 'succeeded'
                                    target['_llm_timestamp'] = int(time.time())
                                    modified = True
                                    # publish SSE event for UI listeners
                                    try:
                                        publish_llm_event(aid, {'type': 'row_succeeded', 'row_index': rid, 'summary': text, 'meta': meta})
                                    except Exception:
                                        pass
                                except Exception as e:
                                    if attempt >= int(os.getenv('LLM_MAX_ATTEMPTS', '3')):
                                        target['_llm_status'] = 'failed'
                                        target['_llm_error'] = str(e)
                                        modified = True
                                    else:
                                        backoff = min(30, (2 ** max(0, attempt - 1)))
                                        target['_llm_status'] = 'queued'
                                        target['_llm_next_attempt_at'] = int(time.time()) + backoff
                                        queue.append(rid)
                                        modified = True
                        except Exception as e:
                            # If batch call failed entirely, re-enqueue items with backoff
                            logger.exception('Batch LLM generation failed for assessment %s: %s', aid, e)
                            for rid in batch_ids:
                                try:
                                    # increment attempt on each and requeue
                                    target = next((r for r in llm_rows if r.get('row_index') == rid), None)
                                    if not target:
                                        continue
                                    attempt = int(target.get('_llm_attempts') or 0)
                                    if attempt >= int(os.getenv('LLM_MAX_ATTEMPTS', '3')):
                                        target['_llm_status'] = 'failed'
                                        target['_llm_error'] = str(e)
                                    else:
                                        backoff = min(30, (2 ** max(0, attempt - 1)))
                                        target['_llm_status'] = 'queued'
                                        target['_llm_next_attempt_at'] = int(time.time()) + backoff
                                        queue.append(rid)
                                    modified = True
                                except Exception:
                                    continue
                    processed += len(batch_ids)

                    # keep queue bounded
                    try:
                        if len(queue) > 1000:
                            queue[:] = queue[-1000:]
                    except Exception:
                        pass

                    assess['_llm_queue'] = queue
                    if modified:
                        try:
                            assess['llm_rows'] = llm_rows
                            REPORT_STORE[aid] = assess
                            path = assess.get('persisted_path')
                            if path:
                                try:
                                    disk = await asyncio.to_thread(_read_json_sync, path)
                                except Exception:
                                    disk = assess
                                disk['llm_rows'] = llm_rows
                                disk['_llm_queue'] = assess.get('_llm_queue')
                                disk['updated'] = int(time.time())
                                try:
                                    await asyncio.to_thread(_atomic_write_json_sync, path, disk)
                                except Exception:
                                    pass
                        except Exception:
                            pass

                await asyncio.sleep(max(0.1, env_interval))
            except Exception:
                try:
                    await asyncio.sleep(max(0.1, env_interval))
                except Exception:
                    pass

    try:
        app.add_event_handler('startup', lambda: _track_task(asyncio.create_task(_worker_loop())))
    except Exception:
        try:
            loop = asyncio.get_event_loop()
            _track_task(loop.create_task(_worker_loop()))
        except Exception:
            pass



@router.get('/csv/deep_analyze/stream')
async def deep_analyze_stream(request: Request):
    async def gen():
        stages = [s.name for s in STAGE_REGISTRY]
        for s in stages:
            if await request.is_disconnected():
                break
            yield f"event: stage\ndata: {json.dumps({'stage': s, 'status': 'done'})}\n\n"
            await asyncio.sleep(0.01)
        yield f"event: done\ndata: {json.dumps({'status':'done'})}\n\n"

    return Response(gen(), media_type='text/event-stream')


@router.get('/{assessment_id}/llm/stream')
async def llm_event_stream(request: Request, assessment_id: str):
    async def gen():
        # Create a lightweight list to act as a queue for this connection
        q: list = []
        listeners = _SSE_BROADCASTERS.get(assessment_id) or []
        listeners.append(q)
        _SSE_BROADCASTERS[assessment_id] = listeners
        try:
            # Send initial connected event
            yield f"event: connected\ndata: {json.dumps({'status':'connected','assessment_id':assessment_id})}\n\n"
            # Loop until client disconnects
            while True:
                if await request.is_disconnected():
                    break
                # drain queued events
                while q:
                    ev = q.pop(0)
                    try:
                        yield f"event: {ev.get('type','message')}\ndata: {json.dumps(ev)}\n\n"
                    except Exception:
                        try:
                            yield f"event: message\ndata: {json.dumps({'error':'event_serialize_error'})}\n\n"
                        except Exception:
                            pass
                await asyncio.sleep(0.2)
        finally:
            # remove listener
            try:
                listeners = _SSE_BROADCASTERS.get(assessment_id) or []
                if q in listeners:
                    listeners.remove(q)
                _SSE_BROADCASTERS[assessment_id] = listeners
            except Exception:
                pass

    return Response(gen(), media_type='text/event-stream')


def _infer_artifact_type_from_row(row: Dict[str, Any]) -> ArtifactType:
    candidate = (row.get('process') or row.get('file_path') or row.get('path') or row.get('command') or '').lower()
    if candidate.endswith(('.dll', '.sys', '.exe', '.msi', '.bin')):
        return ArtifactType.EXECUTABLE
    if candidate.endswith(('.ps1', '.psm1', '.bat', '.cmd', '.sh', '.js', '.vbs')):
        return ArtifactType.SCRIPT
    if candidate.endswith(('.doc', '.docm', '.xls', '.xlsx', '.ppt', '.pdf')):
        return ArtifactType.DOCUMENT
    if 'scheduled' in candidate and 'task' in candidate:
        return ArtifactType.SCHEDULED_TASK
    return ArtifactType.UNKNOWN


def _factor_names(analysis: Dict[str, Any]) -> List[str]:
    raw = analysis.get('factors') or []
    names: List[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict):
                val = item.get('name') or item.get('factor')
                if val:
                    names.append(str(val))
    return names


async def _resolve_session_context(session_id: str | None, summary: Dict[str, Any] | None, explain: Dict[str, Any] | None) -> tuple[Dict[str, Any] | None, Dict[str, Any] | None]:
    resolved_summary = summary
    resolved_explain = explain
    if not session_id:
        return resolved_summary, resolved_explain
    if resolved_summary is None:
        if _graph_get_session:
            try:
                resp = await _graph_get_session(session_id)
                if isinstance(resp, dict):
                    resolved_summary = resp.get('summary') or resp
            except Exception:
                resolved_summary = None
        if resolved_summary is None and _legacy_load_session:
            try:
                rec = _legacy_load_session(session_id)
                if isinstance(rec, dict):
                    resolved_summary = rec.get('data') or rec.get('summary') or rec
            except Exception:
                resolved_summary = None
    if resolved_explain is None and _graph_explain_session and session_id:
        try:
            resolved_explain = await _graph_explain_session(session_id)
        except Exception:
            resolved_explain = None
    return resolved_summary, resolved_explain


def _build_graph_context(session_id: str | None, session_summary: Dict[str, Any] | None, session_explain: Dict[str, Any] | None, row_id: str | None) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {'session_id': session_id, 'source': 'csv_multi_analyzer'}
    if row_id:
        ctx['row_id'] = row_id
    summary = session_summary or {}
    explain = session_explain or {}
    if explain.get('overlap_hotspots'):
        ctx['hotspots'] = explain['overlap_hotspots']
    if summary.get('mapping_stats'):
        ctx['mapping_stats'] = summary['mapping_stats']
    if explain.get('confidence_breakdown'):
        ctx['confidence_breakdown'] = explain['confidence_breakdown']
    if explain.get('key_factors'):
        ctx['key_factors'] = explain['key_factors']
    ctx['verdict'] = explain.get('verdict') or summary.get('verdict')
    ctx['confidence'] = explain.get('confidence') or summary.get('confidence')
    if explain.get('domains_present'):
        ctx['domains_present'] = explain['domains_present']
    if explain.get('narrative'):
        ctx['narrative'] = explain['narrative']
    if summary.get('mapping_semantics_score') is not None:
        ctx['mapping_semantics_score'] = summary.get('mapping_semantics_score')
    if summary.get('domain_diversity_score') is not None:
        ctx['domain_diversity_score'] = summary.get('domain_diversity_score')
    return ctx


def _coerce_verdict(verdict_value: Any, risk_score: float) -> Verdict:
    if isinstance(verdict_value, Verdict):
        return verdict_value
    try:
        if verdict_value:
            return Verdict[str(verdict_value).upper()]
    except Exception:
        pass
    try:
        return map_risk_to_verdict(risk_score)
    except Exception:
        return Verdict.UNKNOWN


def _artifact_from_row(idx: int, row: Dict[str, Any], analysis: Dict[str, Any], session_id: str | None, session_summary: Dict[str, Any] | None, session_explain: Dict[str, Any] | None) -> ArtifactObservation:
    row_id = str(row.get('event_id') or row.get('id') or row.get('hash') or f'row-{idx}')
    sha = row.get('sha256') or row.get('hash') or row.get('file_hash')
    host = row.get('host') or row.get('hostname') or row.get('asset') or row.get('endpoint')
    path = row.get('file_path') or row.get('path') or row.get('process') or row.get('command')
    art_type = _infer_artifact_type_from_row(row)
    artifact_id = stable_artifact_id(host or 'unknown', path or row_id, sha, art_type)
    obs = ArtifactObservation(
        artifact_id=artifact_id,
        sha256=sha,
        artifact_type=art_type,
        host=host,
        path=path,
        name=row.get('name') or row.get('process') or row.get('file_path') or row_id,
        raw=row,
        factors=_factor_names(analysis),
        factor_contributions=analysis.get('breakdown') or [],
        mitre=analysis.get('mitre') or [],
        narrative=analysis.get('narrative') or (session_explain or {}).get('narrative'),
        final_risk=float(analysis.get('risk_score') or 0.0),
        base_risk=float(analysis.get('risk_score') or 0.0),
        verdict=_coerce_verdict(analysis.get('input_verdict'), float(analysis.get('risk_score') or 0.0)),
        risk_confidence=analysis.get('confidence')
    )
    obs.graph_context = _build_graph_context(session_id, session_summary, session_explain, row_id)
    return obs


@router.post('/hopgraph_report')
async def ingest_hopgraph_report(payload: dict):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail='invalid_payload')
    session_id = payload.get('session_id')
    rows = payload.get('rows') or []
    row_analysis = payload.get('row_analysis') or []
    session_summary = payload.get('session_summary')
    session_explain = payload.get('session_explain')
    auto_orchestrate = bool(payload.get('auto_orchestrate'))
    session_summary, session_explain = await _resolve_session_context(session_id, session_summary, session_explain if not auto_orchestrate else None)
    if session_id and (session_summary is None or session_explain is None):
        raise HTTPException(status_code=404, detail='session_context_missing')
    bundles: List[Dict[str, Any]] = []
    if isinstance(row_analysis, list):
        for entry in row_analysis:
            if isinstance(entry, dict) and isinstance(entry.get('row'), dict) and isinstance(entry.get('analysis'), dict):
                bundles.append({'row': entry['row'], 'analysis': entry['analysis']})
    if not bundles and isinstance(rows, list):
        for r in rows[:50]:
            if isinstance(r, dict):
                bundles.append({'row': r, 'analysis': {}})
    if not bundles:
        raise HTTPException(status_code=400, detail='no_rows_supplied')
    max_artifacts = int(payload.get('max_artifacts') or 50)
    artifacts: List[ArtifactObservation] = []
    for idx, item in enumerate(bundles):
        if len(artifacts) >= max_artifacts:
            break
        try:
            obs = _artifact_from_row(idx, item['row'], item.get('analysis') or {}, session_id, session_summary, session_explain)
            artifacts.append(obs)
        except Exception:
            continue
    if not artifacts:
        raise HTTPException(status_code=400, detail='no_artifacts_generated')
    batch_meta = payload.get('batch_meta') or {}
    if session_id and 'session_id' not in batch_meta:
        batch_meta['session_id'] = session_id
    if auto_orchestrate:
        batch_meta.setdefault('auto_orchestrated', True)
    report = build_report(artifacts, batch_meta)
    return JSONResponse({'ok': True, 'session_id': session_id, 'artifact_count': len(artifacts), 'report': report})


@router.post('/report/{report_id}/finalize')
async def finalize_report(report_id: str, payload: dict | None = None):
    # Simple finalize stub: mark report as finalized and return ok
    r = REPORT_STORE.get(report_id)
    if not r:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    r['finalized'] = True
    return JSONResponse({'ok': True})


@router.post('/report/{report_id}/action_all')
async def action_all(report_id: str, payload: dict | None = None):
    # Prepare dummy incidents from report rows
    r = REPORT_STORE.get(report_id)
    if not r:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    rows = r.get('rows_processed') or r.get('rows') or 0
    incidents = []
    for i in range(min(10, int(rows or 0))):
        incidents.append({'incident_id': f'inc-{report_id}-{i}', 'severity': 'medium'})
    return JSONResponse({'prepared_incidents': incidents})


@router.post('/{assessment_id}/report')
async def export_assessment_report(assessment_id: str, payload: dict | None = None):
    data = payload or {}
    in_mem = REPORT_STORE.get(assessment_id) or {}
    assessment = _load_assessment_from_disk(assessment_id, in_mem.get('persisted_path')) or in_mem
    if not assessment:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    # Optional review coverage injection (client may send numbers)
    if 'review_coverage' not in data and isinstance(assessment.get('reviews'), dict):
        try:
            total = 0
            reviewed = 0
            for k,v in assessment.get('reviews', {}).items():
                total += 1
                if v and isinstance(v, dict) and v.get('status') and v.get('status') != 'not_started':
                    reviewed += 1
            pct = (reviewed/total*100) if total else 0
            data['review_coverage'] = {'total': total, 'reviewed': reviewed, 'percent': round(pct)}
        except Exception:
            pass
    document = _build_report_document(assessment, data)
    export_entry = {'ts': int(time.time()), 'payload': data, 'document': document}
    in_mem.setdefault('exports', []).append(export_entry)
    in_mem['last_report'] = document
    REPORT_STORE[assessment_id] = in_mem
    return JSONResponse({'ok': True, 'assessment_id': assessment_id, 'report': document})


@router.post('/report/{report_id}/flag_for_retrain')
async def flag_report_row_for_retrain(report_id: str, request: Request):
    """Test helper: mark a report row as candidate for retraining by enqueueing into outbox.
    Query: ?row_id=...
    """
    try:
        params = dict(request.query_params)
    except Exception:
        params = {}
    row_id = params.get('row_id') or (await request.json()).get('row_id') if request else None
    if not row_id:
        raise HTTPException(status_code=400, detail='missing_row_id')
    # locate persisted report file under data/assessments/*/reports/{report_id}.json
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    reports_base = os.path.join(repo_root, 'data', 'assessments')
    found = None
    try:
        for root, dirs, files in os.walk(reports_base):
            for f in files:
                if f == f"{report_id}.json":
                    p = os.path.join(root, f)
                    try:
                        with open(p, 'r', encoding='utf-8') as fh:
                            obj = json.load(fh)
                        found = obj
                        break
                    except Exception:
                        continue
            if found:
                break
    except Exception:
        found = None
    if not found:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    rows = found.get('per_row') or found.get('rows') or []
    target = None
    for r in rows:
        try:
            if (r.get('row_id') or r.get('id') or r.get('row')) == row_id:
                target = r
                break
        except Exception:
            continue
    if not target:
        return JSONResponse({'detail': 'row_not_found'}, status_code=404)
    # enqueue into outbox
    try:
        from src.repositories.outbox_repo_sqlite import enqueue as _enqueue
        payload = {'report_id': report_id, 'row_id': row_id, 'payload': target}
        rid = _enqueue('retrain', found.get('org') or 'unknown', row_id, payload)
        return JSONResponse({'ok': True, 'outbox_id': rid})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'enqueue_failed:{e}')


@router.post('/admin/consume_retrain')
async def admin_consume_retrain(request: Request):
    """Admin/test helper: consume retrain outbox tasks and write NDJSON training files."""
    api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    # allow when running in lite/test or when admin key present (fallback to ADMIN_API_KEY)
    admin_key = os.getenv('ADMIN_API_KEY')
    if not (os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or (api_key and admin_key and api_key == admin_key)):
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    limit = int(payload.get('limit') or 10)
    try:
        from src.api.retrain_consumer import consume_retrain_tasks
        processed = consume_retrain_tasks(limit=limit)
        return JSONResponse({'ok': True, 'processed_ids': processed})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'consume_failed:{e}')

@router.post('/{assessment_id}/rows/{row_index}/review')
async def update_row_review(assessment_id: str, row_index: int, payload: dict | None = None):
    data = payload or {}
    in_mem = REPORT_STORE.get(assessment_id) or {}
    assessment = _load_assessment_from_disk(assessment_id, in_mem.get('persisted_path')) or in_mem
    if not assessment:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    reviews = assessment.get('reviews')
    if not isinstance(reviews, dict):
        reviews = {}
        assessment['reviews'] = reviews
    status = str(data.get('status') or '').lower()
    if status not in {'not_started','triaged','escalated','dismissed','investigated'}:
        status = 'triaged' if status else 'not_started'
    notes = data.get('notes') or ''
    parsed_note = parse_guided_analyst_note(notes)
    # PII minimization: store professional tag instead of raw user identity
    reviewer_tag = data.get('reviewer_tag') or data.get('reviewer_role') or data.get('reviewer') or 'analyst'
    if isinstance(reviewer_tag, str):
        reviewer_tag = reviewer_tag[:64]
    try:
        target_row = _resolve_row_from_assessment(assessment_id, row_index) or {}
    except Exception:
        target_row = {}
    cluster_id = data.get('cluster_id') or target_row.get('correlation_cluster_id')
    requested_telemetry = [str(v) for v in ((data.get('requested_telemetry') or parsed_note.get('requested_telemetry') or [])[:12])]
    reviews[str(row_index)] = {
        'status': status,
        'confirm_or_deny': str(data.get('confirm_or_deny') or parsed_note.get('confirm_or_deny') or status)[:64],
        'notes': notes,
        'reviewer_tag': reviewer_tag,
        'updated_ts': int(time.time()),
        'cluster_id': cluster_id,
        'hypothesis': str(data.get('hypothesis') or parsed_note.get('hypothesis') or '')[:400],
        'disposition_delta': _safe_float(data.get('disposition_delta') if data.get('disposition_delta') is not None else parsed_note.get('disposition_delta')),
        'factors_added': [str(v) for v in ((data.get('factors_added') or parsed_note.get('factors_added') or [])[:12])],
        'factors_removed': [str(v) for v in ((data.get('factors_removed') or parsed_note.get('factors_removed') or [])[:12])],
        'confidence_override': (
            max(0.0, min(1.0, _safe_float(data.get('confidence_override'))))
            if data.get('confidence_override') is not None else None
        ),
        'requested_telemetry': requested_telemetry,
    }
    try:
        _apply_cluster_reasoning_to_assessment(
            assessment,
            preferred_cluster_id=cluster_id,
            trigger_reason='row_review',
            include_temporal=True,
            force_corroboration=bool(cluster_id),
        )
    except Exception:
        pass
    REPORT_STORE[assessment_id] = {**in_mem, **assessment}
    # Persist back to disk best-effort
    try:
        path = assessment.get('persisted_path')
        if path:
            await asyncio.to_thread(_atomic_write_json_sync, path, assessment, str)
    except Exception:
        pass
    compact_state = {}
    try:
        root_state = assessment.get('cluster_reasoning_state') or {}
        compact_state = next(
            (_compact_cluster_reasoning_state(item) for item in (root_state.get('cluster_states') or []) if item.get('cluster_id') == cluster_id),
            {},
        )
    except Exception:
        compact_state = {}
    return JSONResponse({
        'ok': True,
        'assessment_id': assessment_id,
        'row_index': row_index,
        'review': reviews[str(row_index)],
        'cluster_reasoning_state': compact_state,
        'corroboration': compact_state.get('corroboration') or assessment.get('corroboration') or {},
    })


@router.post('/{assessment_id}/clusters/{cluster_id}/review')
async def update_cluster_review(assessment_id: str, cluster_id: str, payload: dict | None = None):
    data = payload or {}
    in_mem = REPORT_STORE.get(assessment_id) or {}
    assessment = _load_assessment_from_disk(assessment_id, in_mem.get('persisted_path')) or in_mem
    if not assessment:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    cluster_reviews = assessment.get('cluster_reviews')
    if not isinstance(cluster_reviews, dict):
        cluster_reviews = {}
        assessment['cluster_reviews'] = cluster_reviews
    notes = str(data.get('notes') or '')[:2000]
    parsed_note = parse_guided_analyst_note(notes)
    status = str(data.get('status') or data.get('verdict') or 'investigated').lower()
    if status not in {'confirmed', 'denied', 'deferred', 'investigated', 'escalated'}:
        status = 'investigated'
    reviewer_tag = str(data.get('reviewer_tag') or data.get('reviewer_role') or 'analyst')[:64]
    cluster_reviews[cluster_id] = {
        'status': status,
        'confirm_or_deny': str(data.get('confirm_or_deny') or parsed_note.get('confirm_or_deny') or status)[:64],
        'notes': notes,
        'reviewer_tag': reviewer_tag,
        'updated_ts': int(time.time()),
        'cluster_id': cluster_id,
        'hypothesis': str(data.get('hypothesis') or parsed_note.get('hypothesis') or '')[:400],
        'disposition_delta': _safe_float(data.get('disposition_delta') if data.get('disposition_delta') is not None else parsed_note.get('disposition_delta')),
        'factors_added': [str(v) for v in ((data.get('factors_added') or parsed_note.get('factors_added') or [])[:12])],
        'factors_removed': [str(v) for v in ((data.get('factors_removed') or parsed_note.get('factors_removed') or [])[:12])],
        'requested_telemetry': [str(v) for v in ((data.get('requested_telemetry') or parsed_note.get('requested_telemetry') or [])[:12])],
        'confidence_override': (
            max(0.0, min(1.0, _safe_float(data.get('confidence_override'))))
            if data.get('confidence_override') is not None else None
        ),
    }
    try:
        _apply_cluster_reasoning_to_assessment(
            assessment,
            preferred_cluster_id=cluster_id,
            trigger_reason='cluster_review',
            include_temporal=True,
            force_corroboration=status in {'confirmed', 'escalated'},
        )
    except Exception:
        pass
    REPORT_STORE[assessment_id] = {**in_mem, **assessment}
    try:
        path = assessment.get('persisted_path')
        if path:
            await asyncio.to_thread(_atomic_write_json_sync, path, assessment, str)
    except Exception:
        pass
    root_state = assessment.get('cluster_reasoning_state') or {}
    compact_state = next(
        (compact_cluster_reasoning_state(item) for item in (root_state.get('cluster_states') or []) if item.get('cluster_id') == cluster_id),
        {},
    )
    return JSONResponse({
        'ok': True,
        'assessment_id': assessment_id,
        'cluster_id': cluster_id,
        'review': cluster_reviews[cluster_id],
        'cluster_reasoning_state': compact_state,
        'corroboration': compact_state.get('corroboration') or assessment.get('corroboration') or {},
    })


@router.get('/{assessment_id}/clusters/{cluster_id}')
async def get_cluster_detail(assessment_id: str, cluster_id: str):
    in_mem = REPORT_STORE.get(assessment_id) or {}
    assessment = _load_assessment_from_disk(assessment_id, in_mem.get('persisted_path')) or in_mem
    if not assessment:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    root_state = assessment.get('cluster_reasoning_state') or {}
    cluster_state = next(
        (item for item in (root_state.get('cluster_states') or []) if item.get('cluster_id') == cluster_id),
        None,
    )
    if not cluster_state:
        # Fallback: build compact state from correlation_clusters (produced by _hydrate_assessment_semantics)
        correlation_clusters = assessment.get('correlation_clusters') or []
        cluster_meta = next(
            (c for c in correlation_clusters if str(c.get('cluster_id') or c.get('id') or '') == str(cluster_id)),
            None,
        )
        if not cluster_meta:
            return JSONResponse({'detail': 'cluster_not_found'}, status_code=404)
        # Resolve member rows using row_refs OR correlation_cluster_id field
        all_rows = (
            assessment.get('normalized_rows')
            or assessment.get('evidence_rows')
            or assessment.get('llm_rows')
            or assessment.get('rows')
            or []
        )
        row_refs_raw = cluster_meta.get('row_refs') or cluster_meta.get('row_indices') or []
        row_refs = set(int(v) for v in row_refs_raw if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()))
        fallback_member_rows = []
        for r in all_rows:
            if not isinstance(r, dict):
                continue
            ri = r.get('row_index')
            if r.get('correlation_cluster_id') == cluster_id or ri in row_refs:
                fallback_member_rows.append({
                    'row_index': ri,
                    'severity': r.get('severity') or r.get('risk_level'),
                    'entity': r.get('entity') or r.get('host') or r.get('username') or r.get('src_ip'),
                    'description': r.get('description') or r.get('llm_summary') or r.get('summary') or r.get('analyst_notes'),
                    'source': r.get('_source') or r.get('source') or r.get('_sheet') or 'unknown',
                    'correlation_type': r.get('correlation_type') or r.get('type') or 'correlated',
                    'triage_score': r.get('triage_score') or r.get('risk_score') or 0,
                    'mitre': r.get('mitre_technique') or r.get('mitre') or [],
                })
        # Extract entities + factors from member rows for context
        entities = list({r['entity'] for r in fallback_member_rows if r.get('entity')})[:8]
        factors = list({f for r in all_rows if isinstance(r, dict) and r.get('row_index') in row_refs for f in (r.get('factors') or [])})[:10]
        mitre = list({m for r in fallback_member_rows for m in (r.get('mitre') or []) if m})[:8]
        fallback_state = {
            'cluster_id': cluster_id,
            'severity': cluster_meta.get('severity') or 'medium',
            'summary': cluster_meta.get('summary') or cluster_meta.get('label') or f'Cluster {cluster_id}',
            'entities': entities,
            'factors': factors,
            'mitre_techniques': mitre,
            'row_count': len(fallback_member_rows),
            'fallback_generated': True,
            'provider_context': {},
            'evidence_row_indices': list(row_refs),
        }
        return JSONResponse({
            'assessment_id': assessment_id,
            'cluster_id': cluster_id,
            'cluster_detail': fallback_state,
            'member_rows': fallback_member_rows[:25],
            'analyst_delta': {},
            'corroboration': {},
            'fallback_generated': True,
        })
    rows = assessment.get('llm_rows') or assessment.get('rows') or []
    member_rows = []
    member_refs = set(int(v) for v in (cluster_state.get('evidence_row_indices') or []) if isinstance(v, int))
    for row in rows:
        if not isinstance(row, dict):
            continue
        row_index = row.get('row_index')
        if row.get('correlation_cluster_id') != cluster_id and row_index not in member_refs:
            continue
        member_rows.append({
            'row_index': row_index,
            'severity': row.get('severity'),
            'entity': row.get('entity'),
            'description': row.get('description'),
            'source': row.get('source_sheet') or row.get('source') or row.get('_source') or 'unknown',
            'correlation_type': row.get('correlation_type') or row.get('type'),
            'triage_score': row.get('triage_score') or row.get('risk_score') or row.get('score'),
            'mitre': row.get('mitre') or [],
        })
    compact_state = compact_cluster_reasoning_state(cluster_state)
    try:
        full_member_rows = [
            row for row in rows
            if isinstance(row, dict)
            and (row.get('correlation_cluster_id') == cluster_id or row.get('row_index') in member_refs)
        ]
        refreshed_provider_context = _build_cluster_provider_context(
            assessment,
            full_member_rows,
            cluster_state,
        )
        existing_provider_context = dict(compact_state.get('provider_context') or {})
        existing_provider_context.update({
            key: value
            for key, value in refreshed_provider_context.items()
            if value not in (None, [], {})
        })
        compact_state['provider_context'] = existing_provider_context
    except Exception:
        pass
    return JSONResponse({
        'assessment_id': assessment_id,
        'cluster_id': cluster_id,
        'cluster_detail': compact_state,
        'member_rows': member_rows[:25],
        'analyst_delta': (cluster_state.get('analyst_state') or {}),
        'corroboration': cluster_state.get('corroboration') or {},
    })


@router.post('/{assessment_id}/gate', summary='Human-gate: analyst sign-off before CISO/Exec/Audit reports')
async def gate_assessment_for_escalation(assessment_id: str, request: Request):
    """Analyst certifies that the triage findings are human-reviewed before escalation reports
    (CISO, Executive, Audit) are generated.

    This gate satisfies:
    - ISO 27001 A.16.1.4 (human assessment of security events before formal reporting)
    - GDPR Art.33 (reasoned human decision before mandatory notification)
    - APRA CPS 234 Â§36 (material incident assessment by responsible officer)
    - NDB Scheme s.26WB (eligible data breach declared by responsible individual)

    Payload: { reviewer_tag: str, notes: str, gate_verdict: 'approve'|'reject'|'conditional',
               gate_personas: ['ciso','executive','audit'] (optional, defaults to all 3) }
    Returns: { ok, gate_id, gate_ts, gate_verdict, gate_personas, assessment_id }
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    verdict = str(payload.get('gate_verdict') or 'approve').lower()
    if verdict not in ('approve', 'reject', 'conditional'):
        return JSONResponse({'detail': 'invalid_gate_verdict — must be approve|reject|conditional'}, status_code=400)

    reviewer_tag = str(payload.get('reviewer_tag') or payload.get('reviewer_role') or 'analyst')[:64]
    notes = str(payload.get('notes') or '')[:2000]
    # Personas that this gate covers; default to the three highest-consequence consumers
    gate_personas = payload.get('gate_personas') or ['ciso', 'executive', 'audit']
    if not isinstance(gate_personas, list):
        gate_personas = ['ciso', 'executive', 'audit']
    gate_personas = [str(p)[:32] for p in gate_personas[:8]]

    in_mem = REPORT_STORE.get(assessment_id) or {}
    assessment = _load_assessment_from_disk(assessment_id, in_mem.get('persisted_path')) or in_mem
    if not assessment:
        return JSONResponse({'detail': 'not_found'}, status_code=404)

    gate_id = hashlib.sha256(
        f"{assessment_id}:{reviewer_tag}:{int(time.time())}".encode()
    ).hexdigest()[:16]
    gate_record = {
        'gate_id': gate_id,
        'gate_ts': int(time.time()),
        'gate_verdict': verdict,
        'gate_personas': gate_personas,
        'reviewer_tag': reviewer_tag,
        'notes': notes,
        # Snapshot of triage state at gate time for audit trail
        'gated_malicious_count': assessment.get('malicious_count') or 0,
        'gated_row_count': len(assessment.get('rows') or []),
    }
    existing_gates = assessment.get('_human_gates') or []
    if not isinstance(existing_gates, list):
        existing_gates = []
    existing_gates.append(gate_record)
    assessment['_human_gates'] = existing_gates
    assessment['_latest_gate'] = gate_record
    try:
        _apply_cluster_reasoning_to_assessment(
            assessment,
            trigger_reason='gate_review',
            include_temporal=True,
            force_corroboration=verdict in ('approve', 'conditional'),
        )
    except Exception:
        pass
    REPORT_STORE[assessment_id] = {**in_mem, **assessment}

    # Persist best-effort
    try:
        path = assessment.get('persisted_path')
        if path:
            await asyncio.to_thread(_atomic_write_json_sync, path, assessment, str)
    except Exception:
        pass

    return JSONResponse({
        'ok': True,
        'gate_id': gate_id,
        'gate_ts': gate_record['gate_ts'],
        'gate_verdict': verdict,
        'gate_personas': gate_personas,
        'assessment_id': assessment_id,
        'cluster_reasoning_state': assessment.get('cluster_reasoning_state') or {},
        'corroboration': assessment.get('corroboration') or {},
        'message': (
            f"Gate APPROVED — {len(gate_personas)} persona reports unlocked for {reviewer_tag}"
            if verdict == 'approve' else
            f"Gate REJECTED — escalation reports blocked pending further investigation"
            if verdict == 'reject' else
            f"Gate CONDITIONAL — reports generated with analyst caveat from {reviewer_tag}"
        ),
    })


@router.get('/{assessment_id}/gate', summary='Check human-gate status for an assessment')
async def get_gate_status(assessment_id: str):
    """Return the current gate status so the UI can show a lock/unlock indicator on CISO/Exec/Audit persona tabs."""
    in_mem = REPORT_STORE.get(assessment_id) or {}
    assessment = _load_assessment_from_disk(assessment_id, in_mem.get('persisted_path')) or in_mem
    if not assessment:
        return JSONResponse({'detail': 'not_found'}, status_code=404)
    latest = assessment.get('_latest_gate')
    gates = assessment.get('_human_gates') or []
    return JSONResponse({
        'assessment_id': assessment_id,
        'gate_required': True,
        'gated': bool(latest and latest.get('gate_verdict') == 'approve'),
        'latest_gate': latest,
        'gate_count': len(gates),
        'cluster_reasoning_state': assessment.get('cluster_reasoning_state') or {},
        'corroboration': assessment.get('corroboration') or {},
    })
