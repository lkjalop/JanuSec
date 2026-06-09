# Bug Fixes — June 2026 Deep-Dive Session

## Summary

| # | Test(s) | Root Cause | Fix Location |
|---|---------|------------|--------------|
| 1 | `test_connector_security::TestBackpressure::test_reject_policy_returns_503_when_queue_full` | CPython import trap: `sys.modules` pre-write inside `find_spec` made Python discard the AliasLoader and re-execute the source file, creating duplicate module objects | `src/api/__init__.py` |
| 2 | `test_isms_endpoints`, `test_isms_persistence` | ISMS router not registered in lite/test mode — `_register_routes()` returns early before the ISMS tuple loop | `src/api/app.py` |
| 3 | `test_ipfix_collector_integration` | New `Collector()` created per-message reset enumerate index, always yielding `dst_port = 2000 + 0` | `src/core/ingest/ipfix_adapter.py` |
| 4 | `test_integration_metrics` | `/api/v1/graph/reconstruct` requires auth — test sent no API key, got 401 instead of 400 | `tests/test_integration_metrics.py` |
| 5 | `test_integrations_sandbox_api` | `Depends(require_roles('admin'))` misused — `require_roles` returns a Python decorator, not a FastAPI dependency; FastAPI tried to inject `fn: Callable` as a query parameter | `src/api/integrations_sandbox_endpoints.py` |
| 6 | `test_intel_status_endpoint` | `/api/v1/intel/status` response missing `counts` and `last_sync` keys expected by the test | `src/api/intel_endpoints.py` |
| 7 | `test_integration_clustering` | `core.enrichment.ENRICHMENT` was a stub `{}` dict — the `src/core/enrichment/` **package** shadows `src/core/enrichment.py` **file**; Python always picks the package, loading the `__init__.py` placeholder instead of the real `EnrichmentService` | `src/core/enrichment/__init__.py` |

---

## Fix 1 — CPython Import Trap (Dual-Module Bug)

### File: [src/api/__init__.py](src/api/__init__.py)

### What was wrong

The project aliases `api.*` → `src.api.*` via `_CanonicalApiAliasFinder`. Inside `find_spec()`, the finder was doing:

```python
sys.modules[fullname] = existing   # ← CAUSED THE BUG
spec = ModuleSpec(fullname, loader=_AliasLoader(existing))
return spec
```

This looks logical ("pre-populate the cache so the alias is ready"), but it triggers a CPython short-circuit inside `importlib._bootstrap._find_spec`:

```python
# CPython Lib/importlib/_bootstrap.py (simplified):
def _find_spec(name, path, target=None):
    if name in sys.modules:
        module = sys.modules[name]
        return module.__spec__   # ← ignores our spec, uses canonical's SourceFileLoader
```

Because `sys.modules['api.stream_ingest']` was already set, CPython fetched the **canonical module's own `__spec__`**, whose loader is a `SourceFileLoader`. Python then **re-executed** `stream_ingest.py` from disk, creating a brand-new module object and storing it under `src.api.stream_ingest`, overwriting the canonical.

The result was **three** independent module instances:
- Module A: original canonical (`id: AAAA`) — `stream_pcap.__globals__` pointed here
- Module B: `api.stream_ingest` entry (`id: BBBB`) — test's `import src.api.stream_ingest as si` pointed here after setattr overwrite
- Module C: fresh re-execution (`id: CCCC`) — `sys.modules['src.api.stream_ingest']` overwritten here

The test patched Module B (`QUEUE_POLICY = "reject"`), but the running `stream_pcap` function read globals from Module A → backpressure never fired → **200 instead of 503**.

### Why the wildcard route made it worse

`ingest_controller_endpoints.py` line ~574:
```python
@router.post("/{sensor}")   # registered at route index 191
async def ingest_anything(sensor: str, ...):
    if sensor == "stream-pcap":
        from src.api.stream_ingest import stream_pcap   # imports the function
        return await stream_pcap(request, ...)
```

FastAPI is first-match-wins. This wildcard route sits at **index 191**, while `stream_ingest`'s own `/stream-pcap` route is at **index 738**. So ALL `/stream-pcap` requests go through the wildcard, importing the function via `from src.api.stream_ingest import stream_pcap` — which binds `stream_pcap.__globals__` to whichever module object was current at import time.

### The fix

Remove `sys.modules[fullname] = existing` from `find_spec()`. Let `_AliasLoader.exec_module()` do the substitution **after** Python creates the shell module:

```python
def find_spec(self, fullname, path, target=None):
    ...
    # DO NOT touch sys.modules here — see class docstring for why
    spec = ModuleSpec(fullname, loader=_AliasLoader(existing))
    spec.has_location = False
    return spec

class _AliasLoader(importlib.abc.Loader):
    def create_module(self, spec):
        return None  # Python creates a fresh shell

    def exec_module(self, _shell):
        # Replace BOTH names with the canonical module object
        sys.modules[_shell.__name__] = self._module       # "api.stream_ingest"
        sys.modules[self._module.__name__] = self._module # "src.api.stream_ingest"
```

CPython's `_load_unlocked()` calls `exec_module(_shell)`, then re-reads `sys.modules[name]` to get the final module. By the time our `exec_module` returns, both names point to the same canonical object.

### Proof

```
Before fix:
  sys.modules['api.stream_ingest']     id: 1950354272512  ← different!
  sys.modules['src.api.stream_ingest'] id: 1949995193968

After fix:
  sys.modules['api.stream_ingest']     id: 2110142191856  ← SAME ✅
  sys.modules['src.api.stream_ingest'] id: 2110142191856
  Same? True

test_connector_security.py before: .................F  (1 fail in 632)
test_connector_security.py after:  ...................................  ✅
```

### What you learn

> **Python's `sys.modules` is a read-cache AND a write-sentinel.** If you write to it before returning a spec from `find_spec`, CPython uses the cached entry's `__spec__` — completely ignoring your loader. The correct hook point for aliasing is `exec_module`, which runs AFTER Python creates the shell module and BEFORE it binds the result to the parent package attribute.

---

## Fix 2 — ISMS Router Not Registered in Lite Mode

### Files: [src/api/app.py](src/api/app.py)

### What was wrong

`src/api/app.py` has a `_register_routes()` function. When `PLATFORM_LITE_INIT=1` (all test runs), it takes a "lite path" that registers a subset of routers, then does an **early `return`** at line 5078:

```python
        _prioritize_lite_events_route()
        return   # ← exits here in lite mode
    # Full set (best-effort, each guarded)
    for label, router_obj in [
        ...
        ('isms', 'isms_router'),   # ← never reached
        ...
    ]:
```

The ISMS router was only in the "full mode" loop, so `/api/v1/isms/*` routes simply didn't exist during tests → **404**.

### The fix

Added ISMS (and `integrations_sandbox`) registration just before the early `return`:

```python
        _prioritize_lite_events_route()
        try:
            if globals().get('isms_router') is not None:
                app.include_router(globals()['isms_router'])
        except Exception as _e:
            logger.debug('isms_router include failed in lite mode: %s', _e)
        try:
            from .integrations_sandbox_endpoints import router as _isb_router
            app.include_router(_isb_router)
        except Exception as _e:
            logger.debug('integrations_sandbox_router include failed: %s', _e)
        return
```

### What you learn

> **Route registration order and mode-gating are invisible failures.** A router can be correctly imported, correctly built, even logged as "present in globals" — but if registration is guarded behind an early `return` or a `full` flag, the routes simply don't exist. Always verify with `[r.path for r in app.router.routes if 'your_prefix' in r.path]`.

---

## Fix 3 — IPFIX Off-by-One (New Collector Per Message)

### File: [src/core/ingest/ipfix_adapter.py](src/core/ingest/ipfix_adapter.py)

### What was wrong

```python
for msg in stream:
    col = pyfixbuf.Collector()   # ← NEW collector each message
    col.addMsg(msg)
    for rec in col:
        recs.append(rec)
```

The `FakeCollector` in the test uses `enumerate(self._msgs)` for record indexing. When a new collector is created per message, each collector has exactly one message (`_msgs = [msg]`), so `i` is always `0`:

```
msg1 → new Collector → i=0 → dst_port = 2000 + 0 = 2000
msg2 → new Collector → i=0 → dst_port = 2000 + 0 = 2000  ← wrong! expected 2001
```

### The fix

Create **one** collector for the entire stream, add all messages to it, then iterate once:

```python
col = pyfixbuf.Collector()
for msg in stream:
    try:
        col.addMsg(msg)
    except Exception:
        try:
            col.add(msg)
        except Exception:
            pass

recs = []
for rec in col:
    recs.append(rec)
```

This correctly yields:
```
i=0: msg1 → dst_port = 2000 + 0 = 2000  ✅
i=1: msg2 → dst_port = 2000 + 1 = 2001  ✅
```

### What you learn

> **Session-oriented protocols like IPFIX are designed around persistent collector sessions.** One collector accumulates multiple PDUs (packets/messages) in sequence, then decodes them together using shared template state. Creating a new collector per PDU resets the session context and gives wrong indices/templates.

---

## Fix 4 — Missing API Key on Auth-Protected Endpoint

### File: [tests/test_integration_metrics.py](tests/test_integration_metrics.py)

### What was wrong

```python
r2 = client.post('/api/v1/graph/reconstruct', json={})
assert r2.status_code == 400   # ← expected "missing seed"
```

`/api/v1/graph/reconstruct` uses `auth=Depends(require_scopes('factors.search'))`. With no API key, auth returns **401** before the input validation fires. The test expected 400 (missing `seed` parameter).

### The fix

```python
r2 = client.post('/api/v1/graph/reconstruct', json={}, headers={'X-Api-Key': 'testkey123'})
assert r2.status_code == 400
```

`testkey123` is a well-known test key granted wildcard scopes by the auth layer when `PYTEST_CURRENT_TEST` or `TEST_HELPERS_ENABLED=1` is set.

---

## Fix 5 — `require_roles` Misused as FastAPI Depends

### Files: [src/api/integrations_sandbox_endpoints.py](src/api/integrations_sandbox_endpoints.py), [tests/test_integrations_sandbox_api.py](tests/test_integrations_sandbox_api.py)

### What was wrong

```python
@router.get('/api/v1/admin/sandbox/tasks')
async def list_sandbox_tasks(limit: int = 50, auth=Depends(require_roles('admin'))):
```

`require_roles('admin')` returns a **Python decorator** — a function with signature `def decorator(fn: Callable[..., Any])`. When used with `Depends(decorator)`, FastAPI sees `fn: Callable` as an unresolvable parameter and treats it as a **required query parameter** of type `Callable`. Every request gets a `422 Unprocessable Entity: Field required: fn (must be callable)`.

This is a common misuse. `require_roles` is designed as `@require_roles('admin')` over a function, **not** as `Depends(require_roles('admin'))`. The router-level pattern `APIRouter(dependencies=[Depends(require_roles('admin'))])` happens to work because FastAPI calls the `decorator` with the route function — but function-level Depends cannot inject a callable.

### The fix

Replaced `require_roles` with a proper async FastAPI dependency:

```python
from src.security.roles import get_request_roles

async def _admin_dep(request: Request) -> None:
    roles = get_request_roles(request)
    if 'admin' not in roles:
        raise HTTPException(status_code=403, detail='forbidden_role')
```

Then: `auth=Depends(_admin_dep)` on all three endpoints.

Also added API key header to test requests:
```python
_hdrs = {'X-Api-Key': 'testkey123'}
r = client.post('/api/v1/integrations/cuckoo/config', json=cfg, headers=_hdrs)
```

### What you learn

> **FastAPI's `Depends()` takes a dependency _provider_ (a callable whose parameters FastAPI resolves from the request). A Python function decorator is NOT a provider — it takes another function, not request state.** Always write dependency providers as `async def dep(request: Request, ...)` or use `Header(None)`, etc.

---

## Fix 6 — Intel Status Missing `counts` and `last_sync`

### File: [src/api/intel_endpoints.py](src/api/intel_endpoints.py)

### What was wrong

The test checks for `counts` and `last_sync` when intel is enabled:
```python
for k in ('counts', 'last_sync', 'freshness_seconds', 'stale'):
    assert k in data
counts = data['counts']
for bucket in ('ips', 'domains', 'urls', 'hashes', 'ja3', 'certfps'):
    assert bucket in counts
```

The `intel_status()` endpoint built `base` from `TI_CLIENT.status()` but never added a `counts` dict with per-bucket sizes, and never guaranteed `last_sync` was present.

### The fix

```python
base['counts'] = {
    'ips':     len(getattr(TI_CLIENT, 'ip_set',     set()) or set()),
    'domains': len(getattr(TI_CLIENT, 'domain_set', set()) or set()),
    'urls':    len(getattr(TI_CLIENT, 'url_set',    set()) or set()),
    'hashes':  len(getattr(TI_CLIENT, 'hash_set',   set()) or set()),
    'ja3':     len(getattr(TI_CLIENT, 'ja3_set',    set()) or set()),
    'certfps': len(getattr(TI_CLIENT, 'certfp_set', set()) or set()),
}
base.setdefault('last_sync', {})
```

---

## Fix 7 — Package Shadows Module (`EnrichmentService` unreachable)

### File: [src/core/enrichment/\_\_init\_\_.py](src/core/enrichment/__init__.py)

### What was wrong

Python's import system prefers **packages (directories)** over **modules (files)**. In `src/core/`, there exist both:
- `src/core/enrichment.py` — defines `class EnrichmentService` and `ENRICHMENT = EnrichmentService()`
- `src/core/enrichment/` — directory with `__init__.py` that exported `ENRICHMENT = {}`

When any code does `from core.enrichment import ENRICHMENT` (or `from src.core.enrichment import ENRICHMENT`), Python loads `src/core/enrichment/__init__.py` (the package), NOT the `.py` file. The `__init__.py` was intentionally a "minimal placeholder":

```python
# OLD __init__.py
ENRICHMENT = {
    'get_last_dkim': get_last_dkim,
    'record_dkim_result': record_dkim_result,
}
```

In `src/api/server.py` line 590: `from core.enrichment import ENRICHMENT`. So `ENRICHMENT` became a plain `dict {}`. When the `log_batch` endpoint called `ENRICHMENT.completeness(event, tenant_ctx)`, a `dict` has no `.completeness` attribute — the `try/except` at line 3473 silently swallowed the `AttributeError`, and the `enrichment` key was **never added** to `processed_event`. The test then asserted `'enrichment' in ev_meta1` → **AssertionError**.

The `src/core/enrichment.py` file was effectively dead code — it could never be imported because the same-named directory (package) always wins.

### The fix

Replaced the stub `__init__.py` with the full `EnrichmentService` class:

```python
class EnrichmentService:
    def __init__(self):
        raw = os.getenv('ENRICH_REQUIRED_FIELDS', '')
        self.required = [p.strip() for p in raw.split(',') if p.strip()]
        self.field_weights = self._load_weights(os.getenv('ENRICH_FIELD_WEIGHTS', ''))

    def completeness(self, event, tenant_id=None):
        # Re-reads env on each call (tests may change env)
        reqs = list(self.required) or [
            p.strip() for p in os.getenv('ENRICH_REQUIRED_FIELDS', '').split(',') if p.strip()
        ]
        # ... computes completeness score ...
        return {
            'required_count': len(reqs),
            'present_count': len(reqs) - len(missing),
            'completeness': completeness,
            'missing': missing,
        }

ENRICHMENT = EnrichmentService()
```

### What you learn

> **Python package vs module shadowing is silent.** If you have both `foo.py` and `foo/` in the same directory, `foo/` ALWAYS wins. No warning, no error — `foo.py` is simply unreachable by normal import. The symptom is that the "real" code is never executed while a stub or placeholder is silently used instead. Always check with `import foo; print(foo.__file__)` to confirm you're loading the file you think you are.

---

## Final Verification

All previously-failing tests now pass:

```
tests/test_connector_security.py .......................................  ✅
tests/test_ingest_and_playbook_smoke.py .                                ✅
tests/test_integration_clustering.py .                                   ✅
tests/test_integration_metrics.py .                                      ✅
tests/test_integrations_sandbox_api.py .                                 ✅
tests/test_intel_status_endpoint.py .                                    ✅
tests/test_ipfix_collector_integration.py .                              ✅
tests/test_isms_endpoints.py .                                           ✅
tests/test_isms_persistence.py .                                         ✅
tests/test_kape_persistent_worker.py .                                   ✅
```

### Pydantic Deprecation Warning (non-blocking)

`src/api/isms_endpoints.py:91` uses `.dict()` (Pydantic v1 API). Change to `.model_dump()` when upgrading to Pydantic v3:
```python
# Current (deprecated):
obj = item.dict()
# Fix:
obj = item.model_dump()
```
