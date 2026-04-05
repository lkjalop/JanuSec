# CMDB Integration (Phase 1)

This document describes the lightweight CMDB client and mock added in Phase 1.

Files added

- `src/core/cmdb/client.py` — `BaseCMDBClient`, `MockCMDBClient`, `AssetRecord`.
- `tests/test_cmdb_client.py` — unit tests for the mock client.

Usage

1. In tests or local development, instantiate `MockCMDBClient()` and seed
   assets with `add_asset()`.

2. Production integrations should implement `BaseCMDBClient.lookup(query)`
   which returns an `AssetRecord` or `None`.

Example

```python
from src.core.cmdb.client import MockCMDBClient, AssetRecord

client = MockCMDBClient()
asset = AssetRecord(
    asset_id='srv-123', business_unit='Payments', criticality=7.5,
    owner='sec-team@example.com', tags=['10.1.2.3','db'], network_zone='prod', public_exposed=False
)
client.add_asset(asset, aliases=['10.1.2.3','db-host'])
res = client.lookup('10.1.2.3')
```

Next steps

- Implement a production `CMDBClient` adapter that talks to your CMDB API.
- Add caching policies and metrics for cache hit/miss.
- Wire into `src/core/scoring/dread_engine.py` to start using asset criticality.
# CMDB Integration (Phase 1)

This document describes the initial CMDB client scaffolding added for Phase 1.

Files added
- `src/core/cmdb/client.py` — Contains `CMDBClient` interface, `MockCMDBClient`, and `get_cmdb_client()` factory.
- `tests/test_cmdb_client.py` — Unit tests for the mock client and cache behavior.

Usage

The repository defaults to a `MockCMDBClient` returned by `get_cmdb_client()` so
local runs and tests are deterministic. Production should replace `get_cmdb_client()`
with an adapter that constructs an HTTP-backed client.

Example

    from src.core.cmdb.client import get_cmdb_client
    client = get_cmdb_client()
    asset = client.lookup(ip='10.0.0.5')
    if asset:
        print(asset.to_dict())

Config / Env

- `CMDB_URL` (future) — URL to CMDB API.
- `CMDB_API_KEY` (future) — API key for CMDB.
- `CMDB_CACHE_TTL` (future) — Default TTL (seconds) for caches.

Next steps

- Implement an HTTP-backed client in `src/core/cmdb/http_client.py`.
- Add a small caching layer with redis support for production caching.
- Wire into `src/core/scoring/dread_engine.py` to enrich DREAD calculations.
