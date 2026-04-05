from __future__ import annotations

"""Public CMDB client shim.

This module re-exports the real implementations from src.core.cmdb._impl
so other modules can import from src.core.cmdb.client without pulling in
duplicated or partially-corrupted code. If the internal implementation is
unavailable (e.g. in isolated test runs), a tiny fallback mock is provided.
"""

try:
    from ._impl import AssetRecord, BaseCMDBClient, MockCMDBClient, get_cmdb_client  # type: ignore
except Exception:
    from dataclasses import dataclass
    from typing import Optional, Any, Dict

    @dataclass
    class AssetRecord:
        asset_id: str
        hostname: Optional[str] = None
        ip: Optional[str] = None
        meta: Dict[str, Any] = None

    class BaseCMDBClient:
        def get(self, key: str):
            return None

    class MockCMDBClient(BaseCMDBClient):
        def __init__(self, initial: Optional[Dict[str, Any]] = None):
            self.store = dict(initial or {})

        def get(self, key: str):
            return self.store.get(key)

        def set(self, key: str, value: Any) -> None:
            self.store[key] = value

    def get_cmdb_client(config: Optional[Dict[str, Any]] = None) -> MockCMDBClient:
        return MockCMDBClient(config)

__all__ = ["AssetRecord", "BaseCMDBClient", "MockCMDBClient", "get_cmdb_client"]
