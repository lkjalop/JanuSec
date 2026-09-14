"""Provider-neutral, replayable model harness with guarded tool execution."""

from __future__ import annotations
from src.security.storage_paths import storage_id, storage_path, confined_path

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class ModelProvider(Protocol):
    def complete(self, events: tuple[dict[str, Any], ...], tools: tuple[dict[str, Any], ...]) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class SessionEvent:
    session_id: str
    tenant_id: str
    case_id: str
    sequence: int
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_hash: str = field(init=False)

    def __post_init__(self) -> None:
        document = {
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "created_at": self.created_at,
        }
        object.__setattr__(self, "event_hash", hashlib.sha256(_canonical(document).encode()).hexdigest())

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "created_at": self.created_at,
            "event_hash": self.event_hash,
        }


class SessionLog:
    _lock = threading.RLock()

    def __init__(self, root: str | Path = "data/agent-sessions") -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, tenant_id: str, session_id: str) -> Path:
        def safe(value: str) -> str:
            return storage_id(value)
        path = Path(storage_path(storage_path(self.root, safe(tenant_id)), f"{safe(session_id)}.jsonl"))
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def read(self, tenant_id: str, session_id: str) -> tuple[dict[str, Any], ...]:
        path = self._path(tenant_id, session_id)
        if not path.exists():
            return ()
        events = tuple(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line)
        previous = "GENESIS"
        for sequence, event in enumerate(events):
            if event["sequence"] != sequence or event["previous_hash"] != previous:
                raise ValueError("session_event_chain_invalid")
            supplied = event.pop("event_hash")
            rebuilt = SessionEvent(**event)
            event["event_hash"] = supplied
            if rebuilt.event_hash != supplied:
                raise ValueError("session_event_hash_invalid")
            previous = supplied
        return events

    def append(
        self, *, tenant_id: str, case_id: str, session_id: str, event_type: str, payload: dict[str, Any]
    ) -> SessionEvent:
        with self._lock:
            events = self.read(tenant_id, session_id)
            event = SessionEvent(
                session_id=session_id,
                tenant_id=tenant_id,
                case_id=case_id,
                sequence=len(events),
                event_type=event_type,
                payload=payload,
                previous_hash=events[-1]["event_hash"] if events else "GENESIS",
            )
            with open(self._path(tenant_id, session_id), "a", encoding="utf-8") as handle:
                handle.write(_canonical(event.to_dict()) + "\n")
            return event

    def fork(self, *, tenant_id: str, case_id: str, session_id: str, at_sequence: int) -> str:
        events = self.read(tenant_id, session_id)
        if at_sequence < 0 or at_sequence >= len(events):
            raise ValueError("fork_sequence_out_of_range")
        child = f"session-{uuid.uuid4().hex[:16]}"
        self.append(
            tenant_id=tenant_id,
            case_id=case_id,
            session_id=child,
            event_type="session_forked",
            payload={
                "parent_session_id": session_id,
                "parent_sequence": at_sequence,
                "parent_event_hash": events[at_sequence]["event_hash"],
            },
        )
        return child


@dataclass(frozen=True, slots=True)
class GuardedTool:
    name: str
    handler: Callable[[dict[str, Any]], dict[str, Any]]
    required_scope: str
    mutating: bool = False

    def invoke(self, arguments: dict[str, Any], *, scopes: set[str], approved: bool = False) -> dict[str, Any]:
        if self.required_scope not in scopes:
            raise PermissionError("tool_scope_denied")
        if self.mutating and not approved:
            raise PermissionError("tool_requires_analyst_approval")
        return self.handler(arguments)


__all__ = ["GuardedTool", "ModelProvider", "SessionEvent", "SessionLog"]
