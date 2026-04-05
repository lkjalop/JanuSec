"""Click event ingestion scaffold for capturing click-time verdicts."""
from typing import Dict, Any, List
from datetime import datetime


class ClickEvent:
    def __init__(self, message_id: str, user: str, url: str, timestamp: datetime, verdict: str = "unknown", user_agent: str = None, ip: str = None):
        self.message_id = message_id
        self.user = user
        self.url = url
        self.timestamp = timestamp
        self.verdict = verdict
        self.user_agent = user_agent
        self.ip = ip

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "user": self.user,
            "url": self.url,
            "timestamp": self.timestamp.isoformat() if hasattr(self.timestamp, "isoformat") else str(self.timestamp),
            "verdict": self.verdict,
            "user_agent": self.user_agent,
            "ip": self.ip,
        }


class ClickEventHandler:
    def __init__(self, sink=None):
        # sink could be queue/db function to persist click events
        if sink is None:
            try:
                from .click_persistence import add_click
                self.sink = add_click
            except Exception:
                self.sink = None
        else:
            self.sink = sink

    def handle_click(self, evt: ClickEvent) -> None:
        payload = evt.to_dict()
        if self.sink:
            try:
                self.sink(payload)
            except Exception:
                # best-effort: swallow in scaffold
                pass


__all__ = ["ClickEvent", "ClickEventHandler"]
