from typing import Any, Dict, List, Optional, Tuple
import time
import asyncio

try:
    from .connector_base import ConnectorBase
except Exception:
    from src.integrations.connector_base import ConnectorBase  # type: ignore


class NetworkAdapter(ConnectorBase):
    """
    Network Infrastructure adapter scaffold for Syslog/NetFlow/IPFIX.

    - Syslog collector (UDP/TCP) would enqueue messages; here we simulate.
    - NetFlow/IPFIX parser skeleton: normalized src/dst IP/port and protocol.
    - Basic backpressure: bounded queue; producers drop when full.
    """

    def __init__(self, mode: str = "syslog", config: Optional[Dict[str, Any]] = None):
        self.mode = mode
        self.config = config or {}
        self._cursor: Optional[str] = None
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=int(self.config.get("max_queue", 64)))

    async def connect(self) -> bool:
        # Real impl: bind UDP/TCP sockets; start reader tasks
        return True

    async def enqueue(self, item: Dict[str, Any]) -> bool:
        try:
            self._queue.put_nowait(item)
            return True
        except asyncio.QueueFull:
            # backpressure: drop
            return False

    async def fetch_since(self, since: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        # Drain up to N items from queue and normalize
        batch_size = int(self.config.get("batch_size", 16))
        out: List[Dict[str, Any]] = []
        for _ in range(batch_size):
            if self._queue.empty():
                break
            item = await self._queue.get()
            out.append(self.canonical_event(item))
        new_cursor = str(int(time.time()))
        # Heartbeat: mark source fresh when draining non-empty batches
        if out:
            try:
                from src.core.monitoring.log_heartbeat import update as _hb_update  # type: ignore
            except Exception:
                try:
                    from core.monitoring.log_heartbeat import update as _hb_update  # type: ignore
                except Exception:
                    _hb_update = None  # type: ignore
            if _hb_update:
                try:
                    mode = (self.mode or '').lower()
                    if mode in {"netflow", "ipfix"}:
                        _hb_update('netflow')
                    elif mode.startswith("syslog") or mode == "syslog":
                        # Treat syslog adapter as firewall heartbeat by default
                        _hb_update('firewall')
                except Exception:
                    pass
        return out, new_cursor

    async def ack(self, cursor: Optional[str]) -> bool:
        self._cursor = cursor or self._cursor
        return True

    async def health(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "queue_depth": self._queue.qsize(),
            "cursor": self._cursor,
        }

    def canonical_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "src_ip": raw.get("src_ip"),
            "dst_ip": raw.get("dst_ip"),
            "src_port": raw.get("src_port"),
            "dst_port": raw.get("dst_port"),
            "proto": raw.get("proto"),
            "ts": raw.get("ts") or int(time.time()),
            "mode": self.mode,
        }
