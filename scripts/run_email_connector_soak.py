#!/usr/bin/env python
"""
Collect long-run soak evidence for email connectors by periodically polling
each worker and writing JSONL snapshots under logs/collectors/email/<name/>.
Manual/offline mode is also supported so analysts can replay exported logs,
derive HopGraph edges, and attach the resulting JSONL files to evidence packs.

Example:
    python scripts/run_email_connector_soak.py --connectors mimecast,abnormal --tenant-id demo --iterations 3 --interval 60
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional

from src.collectors.email.abnormal_collector import AbnormalCollector
from src.collectors.email.defender_collector import DefenderCollector
from src.collectors.email.mimecast_collector import MimecastCollector
from src.schemas.email import NormalizedEmailEvent

ConnectorFactory = Callable[[str], Any]

LOG_ROOT = Path("logs/collectors/email")
EDGE_ROOT = LOG_ROOT / "hopgraph"


def _resolve_factory(name: str) -> ConnectorFactory:
    lowered = name.lower()
    if lowered == "mimecast":
        return lambda tenant: MimecastCollector(tenant_id=tenant)
    if lowered == "abnormal":
        return lambda tenant: AbnormalCollector(tenant_id=tenant)
    if lowered in {"defender", "microsoft_defender"}:
        return lambda tenant: DefenderCollector(tenant_id=tenant)
    raise ValueError(f"unknown connector {name}")


def _get_poll_method(collector: Any) -> Callable[[], Awaitable[List[Any]]]:
    if hasattr(collector, "poll_detections"):
        return collector.poll_detections  # type: ignore[return-value]
    if hasattr(collector, "poll_alerts"):
        return collector.poll_alerts  # type: ignore[return-value]
    raise ValueError(f"collector {collector!r} does not expose poll_* coroutine")


def _event_to_dict(event: Any) -> Dict[str, Any]:
    if hasattr(event, "model_dump"):
        return event.model_dump()  # type: ignore[attr-defined]
    if hasattr(event, "dict"):
        return event.dict()
    if isinstance(event, dict):
        return event
    return {}


def _coerce_timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        from datetime import datetime

        if isinstance(value, datetime):
            return value.isoformat()
    except Exception:
        pass
    return None


def _build_hopgraph_edges(connector: str, tenant_id: str, events: Iterable[Any]) -> List[Dict[str, Any]]:
    edges: List[Dict[str, Any]] = []
    for evt in events:
        as_dict = _event_to_dict(evt)
        ts = _coerce_timestamp(as_dict.get("timestamp"))
        sender = as_dict.get("sender") or as_dict.get("sender_domain")
        recipient = as_dict.get("recipient") or as_dict.get("affected_user_id")
        sender_domain = as_dict.get("sender_domain")
        endpoint = as_dict.get("affected_endpoint")
        base_meta = {
            "connector": connector,
            "tenant": tenant_id,
            "event_id": as_dict.get("event_id"),
            "timestamp": ts,
            "threat_type": as_dict.get("threat_type"),
            "verdict": as_dict.get("verdict"),
            "attack_chain_id": as_dict.get("attack_chain_id"),
            "related_packages": as_dict.get("related_packages"),
            "related_repositories": as_dict.get("related_repositories"),
        }
        if sender and recipient:
            edges.append(
                {
                    **base_meta,
                    "edge_type": "email_delivery",
                    "source": sender,
                    "source_type": "identity",
                    "target": recipient,
                    "target_type": "identity",
                }
            )
        if sender_domain and recipient:
            edges.append(
                {
                    **base_meta,
                    "edge_type": "email_domain_to_identity",
                    "source": sender_domain,
                    "source_type": "domain",
                    "target": recipient,
                    "target_type": "identity",
                }
            )
        if recipient and endpoint:
            edges.append(
                {
                    **base_meta,
                    "edge_type": "email_to_endpoint",
                    "source": recipient,
                    "source_type": "identity",
                    "target": endpoint,
                    "target_type": "endpoint",
                }
            )
    return edges


def _write_edge_file(edge_dir: Path, connector: str, tenant_id: str, ts: int, edges: List[Dict[str, Any]]) -> None:
    if not edges:
        return
    target_dir = edge_dir / connector.lower()
    target_dir.mkdir(parents=True, exist_ok=True)
    edge_path = target_dir / f"edges-{tenant_id}-{ts}.jsonl"
    with edge_path.open("a", encoding="utf-8") as fh:
        for edge in edges:
            fh.write(json.dumps(edge) + "\n")


def _load_manual_events(path: Path) -> List[NormalizedEmailEvent]:
    text = path.read_text(encoding="utf-8")
    payloads: List[Any] = []
    try:
        decoded = json.loads(text)
        if isinstance(decoded, list):
            payloads = decoded
        else:
            payloads = [decoded]
    except json.JSONDecodeError:
        payloads = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            payloads.append(json.loads(line))
    events: List[NormalizedEmailEvent] = []
    for item in payloads:
        candidate = item.get("event", item) if isinstance(item, dict) else item
        if not isinstance(candidate, dict):
            continue
        events.append(NormalizedEmailEvent(**candidate))
    return events


def _parse_manual_logs(raw_entries: Optional[List[str]]) -> Dict[str, List[NormalizedEmailEvent]]:
    mapping: Dict[str, List[NormalizedEmailEvent]] = {}
    if not raw_entries:
        return mapping
    for raw in raw_entries:
        if not raw:
            continue
        if "=" not in raw:
            raise ValueError(f"manual log entry must be connector=path, got {raw}")
        key, path = raw.split("=", 1)
        connector_name = key.strip().lower()
        resolved = Path(path.strip())
        events = _load_manual_events(resolved)
        mapping[connector_name] = events
    return mapping


async def _run_connector(
    name: str,
    tenant_id: str,
    iterations: int,
    interval: float,
    *,
    manual_events: Optional[List[NormalizedEmailEvent]] = None,
    manual_chunk_size: int = 100,
    hopgraph_edge_dir: Optional[Path] = None,
) -> None:
    manual_queue: List[NormalizedEmailEvent] = list(manual_events or [])
    manual_mode = bool(manual_queue)
    connector = None
    poll: Optional[Callable[[], Awaitable[List[Any]]]] = None
    if not manual_mode:
        factory = _resolve_factory(name)
        connector = factory(tenant_id)
        poll = _get_poll_method(connector)
    out_dir = LOG_ROOT / name.lower()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"soak-{int(time.time())}.jsonl"
    edge_dir = hopgraph_edge_dir or EDGE_ROOT
    edge_dir.mkdir(parents=True, exist_ok=True)

    for idx in range(iterations):
        entry: Dict[str, Any] = {
            "ts": int(time.time()),
            "iteration": idx,
            "connector": name.lower(),
            "tenant": tenant_id,
            "status": "ok",
            "mode": "manual" if manual_mode else "live",
        }
        try:
            if manual_mode:
                if not manual_queue:
                    events: List[Any] = []
                else:
                    chunk_size = manual_chunk_size or 1
                    events = manual_queue[:chunk_size]
                    manual_queue = manual_queue[len(events) :]
                entry["manual_remaining"] = len(manual_queue)
            else:
                if poll is None:
                    raise RuntimeError("connector poller unavailable")
                events = await poll()
            entry["event_count"] = len(events)
            if connector is not None and not manual_mode:
                entry["cursor"] = getattr(connector, "_cursor", None)
                try:
                    entry["health"] = connector.health_snapshot()  # type: ignore[attr-defined]
                except Exception:
                    pass
            edges = _build_hopgraph_edges(name.lower(), tenant_id, events)
            entry["hopgraph_edge_count"] = len(edges)
            if edges:
                entry["hopgraph_edges"] = edges
                _write_edge_file(edge_dir, name.lower(), tenant_id, entry["ts"], edges)
        except Exception as exc:  # pragma: no cover - depends on vendor APIs
            entry["status"] = "error"
            entry["error"] = str(exc)
            entry["hopgraph_edge_count"] = 0
        with out_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        if manual_mode and not manual_queue:
            break
        await asyncio.sleep(interval)


async def main_async(args) -> None:
    manual_mapping = getattr(args, "manual_log_map", {})
    tasks = [
        _run_connector(
            name.strip(),
            args.tenant_id,
            args.iterations,
            args.interval,
            manual_events=manual_mapping.get(name.strip().lower()),
            manual_chunk_size=args.manual_chunk_size,
            hopgraph_edge_dir=args.hopgraph_edge_dir,
        )
        for name in args.connectors
        if name.strip()
    ]
    if not tasks:
        raise SystemExit("no connectors specified")
    await asyncio.gather(*tasks)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run soak collectors for email connectors.")
    parser.add_argument("--connectors", default="mimecast,abnormal,defender", help="Comma-separated connector list.")
    parser.add_argument("--tenant-id", default="default", help="Tenant identifier to use for collectors.")
    parser.add_argument("--iterations", type=int, default=3, help="Number of poll iterations per connector.")
    parser.add_argument("--interval", type=float, default=60.0, help="Seconds to wait between polls.")
    parser.add_argument(
        "--manual-log",
        action="append",
        default=[],
        help="Optional connector=path mapping to replay exported JSON/JSONL logs instead of hitting live APIs.",
    )
    parser.add_argument(
        "--manual-chunk-size",
        type=int,
        default=100,
        help="Number of manual events to consume per iteration when --manual-log is supplied.",
    )
    parser.add_argument(
        "--hopgraph-edge-dir",
        type=Path,
        default=EDGE_ROOT,
        help="Directory for HopGraph edge exports (defaults to logs/collectors/email/hopgraph).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.connectors = [c.strip() for c in args.connectors.split(",")]
    args.manual_log_map = _parse_manual_logs(args.manual_log)
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
