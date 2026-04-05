from typing import Any, Dict, List, Optional, Tuple
import time
import asyncio

try:
    from .connector_base import ConnectorBase
except Exception:
    from src.integrations.connector_base import ConnectorBase  # type: ignore


class ZeekAdapter(ConnectorBase):
    """
    Zeek adapter scaffold. Ingests Zeek TSV/JSON lines and normalizes fields.

    - Batch queue with backpressure for incoming records.
    - Normalizes: ts, uid, src_ip, dst_ip, src_port, dst_port, proto, service.
    - Designed to feed HopGraph build sessions downstream; SSE metrics aligned
      to HopGraph overlay doc will be emitted by the publisher in the API layer.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=int(self.config.get("max_queue", 256)))
        self._cursor: Optional[str] = None

    async def connect(self) -> bool:
        return True

    async def enqueue(self, record: Dict[str, Any]) -> bool:
        try:
            self._queue.put_nowait(record)
            return True
        except asyncio.QueueFull:
            return False

    async def fetch_since(self, since: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        batch_size = int(self.config.get("batch_size", 64))
        out: List[Dict[str, Any]] = []
        for _ in range(batch_size):
            if self._queue.empty():
                break
            item = await self._queue.get()
            out.append(self.canonical_event(item))
        # Heartbeat: mark Zeek conn.log as fresh when batch produced
        try:
            from src.core.monitoring.log_heartbeat import update as _hb_update  # type: ignore
        except Exception:
            try:
                from core.monitoring.log_heartbeat import update as _hb_update  # type: ignore
            except Exception:
                _hb_update = None  # type: ignore
        if out and _hb_update:
            try:
                _hb_update('zeek_conn')
            except Exception:
                pass
        new_cursor = str(int(time.time()))
        return out, new_cursor

    async def ack(self, cursor: Optional[str]) -> bool:
        self._cursor = cursor or self._cursor
        return True

    async def health(self) -> Dict[str, Any]:
        return {
            "queue_depth": self._queue.qsize(),
            "cursor": self._cursor,
        }

    def canonical_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ts": raw.get("ts") or int(time.time()),
            "uid": raw.get("uid"),
            "src_ip": raw.get("src_ip") or raw.get("id.orig_h"),
            "dst_ip": raw.get("dst_ip") or raw.get("id.resp_h"),
            "src_port": raw.get("src_port") or raw.get("id.orig_p"),
            "dst_port": raw.get("dst_port") or raw.get("id.resp_p"),
            "proto": raw.get("proto") or raw.get("proto"),
            "service": raw.get("service"),
        }
