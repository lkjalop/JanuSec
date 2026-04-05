from typing import Any, Dict, List, Optional, Tuple
import time

try:
    from .connector_base import ConnectorBase
except Exception:
    from src.integrations.connector_base import ConnectorBase  # type: ignore


class SysmonAdapter(ConnectorBase):
    """
    Sysmon adapter scaffold consuming Winlogbeat or parsed Sysmon JSON.

    Normalizes canonical fields: process, parent, hash, cmdline, user, container_id, ts.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._cursor: Optional[str] = None

    async def connect(self) -> bool:
        return True

    async def fetch_since(self, since: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        # Dev synthetic events
        base_ts = int(time.time())
        events: List[Dict[str, Any]] = []
        for i in range(3):
            raw = {
                "timestamp": base_ts + i,
                "ProcessName": f"proc{i}.exe",
                "ParentProcessName": "parent.exe",
                "Hashes": {"SHA256": f"deadbeef{i}"},
                "CommandLine": f"C\\\\proc{i}.exe --flag",
                "User": "DOMAIN\\User",
                "ContainerId": None,
            }
            events.append(self.canonical_event(raw))
        cursor = str(base_ts + 3)
        return events, cursor

    async def ack(self, cursor: Optional[str]) -> bool:
        self._cursor = cursor or self._cursor
        return True

    async def health(self) -> Dict[str, Any]:
        return {
            "cursor": self._cursor,
            "connected": True,
        }

    def canonical_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        hashes = raw.get("Hashes") or {}
        sha256 = hashes.get("SHA256") or raw.get("hash")
        return {
            "process": raw.get("ProcessName") or raw.get("process"),
            "parent": raw.get("ParentProcessName") or raw.get("parent"),
            "hash": sha256,
            "cmdline": raw.get("CommandLine") or raw.get("cmdline"),
            "user": raw.get("User") or raw.get("user"),
            "container_id": raw.get("ContainerId") or raw.get("container_id"),
            "ts": raw.get("timestamp") or raw.get("ts") or int(time.time()),
        }
