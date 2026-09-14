from typing import Any, Dict, List, Optional, Tuple
import time

try:
    from .connector_base import ConnectorBase
except Exception:
    from src.integrations.connector_base import ConnectorBase  # type: ignore


class CloudWatchAdapter(ConnectorBase):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._cursor: Optional[str] = None

    async def connect(self) -> bool:
        return True

    async def fetch_since(self, since: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        base_ts = int(time.time())
        logs: List[Dict[str, Any]] = []
        for i in range(2):
            raw = {
                "timestamp": base_ts + i,
                "message": f"Example log line {i}",
                "logStreamName": "app/production",
                "logGroupName": "/aws/lambda/my-func",
            }
            logs.append(self.canonical_event(raw))
        return logs, str(base_ts + 2)

    async def ack(self, cursor: Optional[str]) -> bool:
        self._cursor = cursor or self._cursor
        return True

    async def health(self) -> Dict[str, Any]:
        return {"connected": True, "cursor": self._cursor}

    def canonical_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ts": raw.get("timestamp"),
            "message": raw.get("message"),
            "stream": raw.get("logStreamName"),
            "group": raw.get("logGroupName"),
        }
