from __future__ import annotations

import abc
from typing import Any, Dict, List, Tuple


class ConnectorBase(abc.ABC):
    """Unified connector interface for external log sources.

    All connectors should normalize events to the platform's canonical fields
    and implement cursor-based incremental fetching when supported.
    """

    @abc.abstractmethod
    async def connect(self) -> None:
        """Establish sessions or refresh auth tokens as needed."""
        raise NotImplementedError

    @abc.abstractmethod
    async def fetch_since(self, cursor: str | None, *, limit: int = 200) -> Tuple[List[Dict[str, Any]], str | None]:
        """Fetch normalized events since the provided cursor.

        Returns a tuple of (events, next_cursor). The `next_cursor` should be used
        on the next call to continue from the last position. When the source does not
        support cursors, implementations may return None for the next cursor and rely
        on time-based polling.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def ack(self, cursor: str) -> None:
        """Best-effort acknowledgement for cursor-based sources."""
        raise NotImplementedError

    @abc.abstractmethod
    async def health(self) -> Dict[str, Any]:
        """Return connector health status with keys like enabled, last_sync, error."""
        raise NotImplementedError

    def supported_event_types(self) -> List[str]:
        """List of high-level event types the connector produces."""
        return []

    # Convenience async generator wrappers returning individual events.
    # These default implementations call `fetch_since` repeatedly and yield
    # normalized events one-by-one. Adapters may override with more
    # efficient implementations if needed.
    async def fetch_detections(self):
        """Async generator yielding detection events."""
        cursor = None
        while True:
            events, next_cursor = await self.fetch_since(cursor)
            for e in events:
                yield e
            if not next_cursor:
                break
            cursor = next_cursor

    async def fetch_notable_events(self):
        """Async generator yielding notable events (Splunk semantics)."""
        cursor = None
        while True:
            events, next_cursor = await self.fetch_since(cursor)
            for e in events:
                yield e
            if not next_cursor:
                break
            cursor = next_cursor

    async def fetch_incidents(self):
        """Async generator yielding incident events (Sentinel semantics)."""
        cursor = None
        while True:
            events, next_cursor = await self.fetch_since(cursor)
            for e in events:
                yield e
            if not next_cursor:
                break
            cursor = next_cursor

    @staticmethod
    def canonical_event(
        *,
        timestamp: str | None = None,
        source: str | None = None,
        tenant: str | None = None,
        event_type: str | None = None,
        host: str | None = None,
        user: str | None = None,
        process_name: str | None = None,
        cmdline: str | None = None,
        pid: int | None = None,
        ppid: int | None = None,
        local_ip: str | None = None,
        remote_ip: str | None = None,
        local_port: int | None = None,
        remote_port: int | None = None,
        protocol: str | None = None,
        file_hash: str | None = None,
        exe_path: str | None = None,
        container_id: str | None = None,
        container_image: str | None = None,
        raw: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        ev: Dict[str, Any] = {}
        if timestamp is not None: ev['@timestamp'] = timestamp
        if source is not None: ev['source'] = source
        if tenant is not None: ev['tenant'] = tenant
        if event_type is not None: ev['event_type'] = event_type
        if host is not None: ev['host'] = host
        if user is not None: ev['user'] = user
        if process_name is not None: ev['process_name'] = process_name
        if cmdline is not None: ev['cmdline'] = cmdline
        if pid is not None: ev['pid'] = pid
        if ppid is not None: ev['ppid'] = ppid
        if local_ip is not None: ev['local_ip'] = local_ip
        if remote_ip is not None: ev['remote_ip'] = remote_ip
        if local_port is not None: ev['local_port'] = local_port
        if remote_port is not None: ev['remote_port'] = remote_port
        if protocol is not None: ev['protocol'] = protocol
        if file_hash is not None: ev['file_hash'] = file_hash
        if exe_path is not None: ev['exe_path'] = exe_path
        if container_id is not None: ev['container_id'] = container_id
        if container_image is not None: ev['container_image'] = container_image
        if raw is not None: ev['raw'] = raw
        return ev
