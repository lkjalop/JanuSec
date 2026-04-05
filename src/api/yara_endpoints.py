from __future__ import annotations

"""
Feature-gated YARA endpoints for rule management and sample scanning.

Routes (require x-api-key with scopes matching factors.search):
- GET    /api/v1/yara/rules                 -> list saved rules (names only)
- POST   /api/v1/yara/rules                 -> save/update a rule {name, rule}
- DELETE /api/v1/yara/rules?name=...        -> delete a rule by name
- POST   /api/v1/yara/scan_path             -> scan a server-side file path {path}
- POST   /api/v1/yara/scan_upload           -> scan an uploaded file (multipart/form-data)

Gates:
- YARA_ENABLED must be truthy (1/true/yes). Otherwise endpoints return 503.
- yara-python must be importable; else 503 with detail 'yara_not_installed'.

Safety:
- scan_path respects YARA_SAMPLES_DIR as base. Absolute paths are rejected unless
  YARA_ALLOW_ABS_PATH is truthy.
- Scan size is capped by YARA_MAX_SCAN_BYTES (default 25 MiB).
"""

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, File, HTTPException, UploadFile, Request, Depends

from security.auth import require_scopes


router: APIRouter = APIRouter(prefix="/api/v1/yara", tags=["YARA"])


def _enabled() -> bool:
    return os.getenv("YARA_ENABLED", "0").lower() in {"1", "true", "yes"}


def _import_yara():
    try:
        import yara  # type: ignore
        return yara
    except Exception:
        return None


_RULES: dict[str, str] = {}
_RULE_META: dict[str, dict[str, Any]] = {}
_SEM = None  # concurrency semaphore

def _sequential_enabled() -> bool:
    try:
        return os.getenv('YARA_SEQUENTIAL_PER_RULE', '0').lower() in {'1','true','yes'}
    except Exception:
        return False


@dataclass
class _RuleItem:
    name: str
    length: int
    updated_at: float


def _list_rule_items() -> list[_RuleItem]:
    items: list[_RuleItem] = []
    for name, text in _RULES.items():
        items.append(_RuleItem(name=name, length=len(text or ""), updated_at=0.0))
    return items


def _compile_all():
    yara = _import_yara()
    if yara is None:
        raise HTTPException(status_code=503, detail="yara_not_installed")
    if not _RULES:
        raise HTTPException(status_code=400, detail="no_rules")
    # Compile from multiple sources: {name: rule_text}
    try:
        return yara.compile(sources={k: v for k, v in _RULES.items()})
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"compile_failed: {exc}")


def _rules_dir() -> Path:
    base = os.getenv("YARA_RULES_DIR") or str(Path.cwd() / "rules" / "yara")
    p = Path(base)
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return p


def _load_rules_from_disk() -> None:
    if not _enabled():
        return
    d = _rules_dir()
    idx = d / "index.json"
    try:
        if idx.exists():
            import json
            data = json.loads(idx.read_text(encoding="utf-8"))
            arr = data.get("rules") or []
            if isinstance(arr, list):
                for r in arr:
                    name = (r or {}).get("name")
                    text = (r or {}).get("text")
                    meta = (r or {}).get("meta") or {}
                    if name and isinstance(text, str):
                        _RULES[name] = text
                        if isinstance(meta, dict):
                            _RULE_META[name] = meta
    except Exception:
        pass
    # Initialize semaphore lazily based on env
    global _SEM
    try:
        max_c = int(os.getenv('YARA_MAX_CONCURRENT_SCANS', '2') or 2)
        if max_c and max_c > 0:
            import asyncio as _a
            _SEM = _a.Semaphore(max_c)
    except Exception:
        _SEM = None


def _save_rules_to_disk() -> None:
    d = _rules_dir()
    try:
        payload = {"rules": []}
        for name, text in _RULES.items():
            payload["rules"].append({"name": name, "text": text, "meta": _RULE_META.get(name) or {}})
        import json
        (d / "index.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        # Optional mirroring to individual files
        try:
            if os.getenv('YARA_MIRROR_RULE_FILES','1').lower() in {'1','true','yes'}:
                for name, text in _RULES.items():
                    safe = name.replace('/', '_').replace('\\','_')
                    (d / f"{safe}.yar").write_text(text, encoding='utf-8')
                # Remove stray .yar files for deleted rules
                for f in d.glob('*.yar'):
                    base = f.stem
                    if base not in _RULES:
                        try: f.unlink()
                        except Exception: pass
        except Exception:
            pass
    except Exception:
        pass


def _parse_rule_meta(text: str) -> dict[str, Any]:
    """Parse optional // meta: key=value pairs in rule text.

    Example: // meta: family=QakBot, severity=high, mitre=T1059,T1105, pack=Community, version=2025.10.06
    """
    meta: dict[str, Any] = {}
    try:
        candidate = None
        for ln in text.splitlines():
            s = ln.strip()
            if s.lower().startswith('// meta:'):
                candidate = s[8:].strip()
                break
        if not candidate:
            return meta
        parts = [p.strip() for p in candidate.split(',') if p.strip()]
        for p in parts:
            if '=' in p:
                k, v = p.split('=', 1)
                k = k.strip().lower()
                v = v.strip()
                if k == 'mitre':
                    meta['mitre'] = [t.strip() for t in v.split(',') if t.strip()]
                else:
                    meta[k] = v
    except Exception:
        pass
    return meta


# Initial load
try:
    _load_rules_from_disk()
except Exception:
    pass


def _cap_bytes_limit(raw: bytes) -> bytes:
    max_bytes_env = os.getenv("YARA_MAX_SCAN_BYTES", str(25 * 1024 * 1024))
    try:
        max_bytes = int(max_bytes_env)
    except Exception:
        max_bytes = 25 * 1024 * 1024
    if len(raw) > max_bytes:
        return raw[:max_bytes]
    return raw


def _resolve_scan_path(p: str) -> Path:
    base = os.getenv("YARA_SAMPLES_DIR")
    allow_abs = os.getenv("YARA_ALLOW_ABS_PATH", "0").lower() in {"1", "true", "yes"}
    if not p:
        raise HTTPException(status_code=400, detail="path_required")
    user_path = Path(p)
    if user_path.is_absolute():
        if not allow_abs:
            raise HTTPException(status_code=400, detail="absolute_paths_disabled")
        return user_path
    # relative path -> resolve under base (or ./samples fallback)
    base_dir = Path(base) if base else Path.cwd() / "samples"
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    resolved = (base_dir / user_path).resolve()
    try:
        base_resolved = base_dir.resolve()
    except Exception:
        base_resolved = base_dir
    if str(resolved).startswith(str(base_resolved)):
        return resolved
    raise HTTPException(status_code=400, detail="path_outside_base")


def _maybe_apply_timeout(fn, *args, **kwargs):
    """Optionally run scan with a timeout using a thread executor.

    Configure via YARA_SCAN_TIMEOUT_SECONDS. If set > 0, execute in a thread and
    wait up to the timeout; if exceeded, raise 504.
    """
    try:
        import concurrent.futures
        timeout_env = os.getenv("YARA_SCAN_TIMEOUT_SECONDS", "0")
        timeout = float(timeout_env) if timeout_env else 0.0
    except Exception:
        timeout = 0.0
    if timeout and timeout > 0:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(fn, *args, **kwargs)
                return fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise HTTPException(status_code=504, detail="scan_timeout")
    # direct
    return fn(*args, **kwargs)


def _sequential_match_per_rule(data: bytes) -> tuple[list[Any], bool, bool]:
    """Run per-rule matching with precise timeout/error attribution.

    Returns (matches, had_timeout, had_error). Does not raise on per-rule issues; instead
    increments per-rule metrics and continues to next rule.
    """
    matches: list[Any] = []
    had_timeout = False
    had_error = False
    yara = _import_yara()
    if yara is None:
        raise HTTPException(status_code=503, detail="yara_not_installed")
    # Iterate each saved rule as its own compiled unit
    for rname, rtext in list(_RULES.items()):
        try:
            compiled = yara.compile(source=rtext)
        except Exception:
            # compile error for this rule
            had_error = True
            try:
                if _y_rule_errors: _y_rule_errors.labels(rule=str(rname)).inc()
            except Exception:
                pass
            continue
        try:
            def _run():
                return compiled.match(data=data)
            # Note: Apply timeout individually per rule
            out = _maybe_apply_timeout(_run)
            if out:
                # Accumulate matches; downstream will handle per-rule match/bytes metrics
                for m in out:
                    matches.append(m)
        except HTTPException as he:
            # Timeout only increments the specific rule
            if he.status_code == 504:
                had_timeout = True
                try:
                    if _y_rule_timeouts: _y_rule_timeouts.labels(rule=str(rname)).inc()
                except Exception:
                    pass
                # continue to next rule
                continue
            # Other HTTP error while matching this rule
            had_error = True
            try:
                if _y_rule_errors: _y_rule_errors.labels(rule=str(rname)).inc()
            except Exception:
                pass
            continue
        except Exception:
            had_error = True
            try:
                if _y_rule_errors: _y_rule_errors.labels(rule=str(rname)).inc()
            except Exception:
                pass
            continue
    return matches, had_timeout, had_error


# ---------- Optional Prometheus Metrics (guarded) ----------
try:
    from core.metrics.registry import metric_counter, metric_histogram  # type: ignore
    _y_scans = metric_counter('yara_scans_total', 'YARA scans', labels=['mode','outcome'])
    _y_latency = metric_histogram('yara_scan_latency_seconds', 'YARA scan latency seconds', labels=['mode'])
    _y_matches = metric_counter('yara_matches_total', 'YARA matches', labels=['pack'])
    _y_rule_match = metric_counter('yara_rule_matches_total','YARA rule matches', labels=['rule'])
    _y_rule_bytes = metric_counter('yara_rule_bytes_scanned_total','YARA bytes scanned', labels=['rule'])
    _y_rule_timeouts = metric_counter('yara_rule_timeouts_total','YARA timeouts', labels=['rule'])
    _y_rule_errors = metric_counter('yara_rule_errors_total','YARA errors', labels=['rule'])
except Exception:  # safe no-ops
    _y_scans = None
    _y_latency = None
    _y_matches = None
    _y_rule_match = None
    _y_rule_bytes = None
    _y_rule_timeouts = None
    _y_rule_errors = None


@router.get("/rules", operation_id='yara_list_rules')
async def list_rules(auth=Depends(require_scopes("factors.search"))):
    if not _enabled():
        raise HTTPException(status_code=503, detail="yara_disabled")
    rules = []
    for it in sorted(_list_rule_items(), key=lambda r: r.name):
        rules.append({"name": it.name, "length": it.length, "meta": _RULE_META.get(it.name) or {}})
    return {"rules": rules}


@router.post("/rules")
async def save_rule(payload: dict[str, Any], auth=Depends(require_scopes("factors.search"))):
    if not _enabled():
        raise HTTPException(status_code=503, detail="yara_disabled")
    name = (payload.get("name") or "").strip()
    rule_text = payload.get("rule") or ""
    if not name:
        raise HTTPException(status_code=400, detail="name_required")
    if not isinstance(rule_text, str) or not rule_text.strip():
        raise HTTPException(status_code=400, detail="rule_required")
    # Validate by compiling just this rule first
    yara = _import_yara()
    if yara is None:
        raise HTTPException(status_code=503, detail="yara_not_installed")
    try:
        yara.compile(source=rule_text)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid_rule: {exc}")
    _RULES[name] = rule_text
    _RULE_META[name] = _parse_rule_meta(rule_text)
    _save_rules_to_disk()
    return {"saved": True, "name": name, "meta": _RULE_META.get(name)}


@router.delete("/rules", operation_id='yara_delete_rule')
async def delete_rule(name: str, auth=Depends(require_scopes("factors.search"))):
    if not _enabled():
        raise HTTPException(status_code=503, detail="yara_disabled")
    if not name:
        raise HTTPException(status_code=400, detail="name_required")
    existed = name in _RULES
    _RULES.pop(name, None)
    _RULE_META.pop(name, None)
    _save_rules_to_disk()
    # Also remove mirrored file if present
    try:
        if os.getenv('YARA_MIRROR_RULE_FILES','1').lower() in {'1','true','yes'}:
            d = _rules_dir()
            safe = name.replace('/', '_').replace('\\','_')
            p = d / f"{safe}.yar"
            if p.exists():
                p.unlink()
    except Exception:
        pass
    return {"deleted": existed, "name": name}


@router.post("/scan_path")
async def scan_path(payload: dict[str, Any], auth=Depends(require_scopes("factors.search"))):
    if not _enabled():
        raise HTTPException(status_code=503, detail="yara_disabled")
    path = payload.get("path") if isinstance(payload, dict) else None
    if not path or not isinstance(path, str):
        raise HTTPException(status_code=400, detail="path_required")
    resolved = _resolve_scan_path(path)
    if not resolved.exists() or not resolved.is_file():
        raise HTTPException(status_code=404, detail="file_not_found")
    try:
        raw = resolved.read_bytes()
    except Exception:
        raise HTTPException(status_code=500, detail="read_failed")
    limited = _cap_bytes_limit(raw)
    # Optional hash reputation check (if event_id provided)
    _maybe_add_hash_reputation(payload, limited)
    rules = None if _sequential_enabled() else _compile_all()
    started = time.time()
    outcome = 'ok'
    try:
        if _sequential_enabled():
            # Sequential precise mode
            if _SEM is not None:
                import asyncio as _a
                async with _SEM:  # type: ignore
                    matches, had_to, had_err = await _a.get_running_loop().run_in_executor(None, lambda: _sequential_match_per_rule(limited))
            else:
                matches, had_to, had_err = _sequential_match_per_rule(limited)
            if had_to:
                outcome = 'timeout'
            elif had_err:
                outcome = 'error'
        else:
            def _run():
                return rules.match(data=limited)  # type: ignore[union-attr]
            if _SEM is not None:
                import asyncio as _a
                async with _SEM:  # type: ignore
                    matches = await _a.get_running_loop().run_in_executor(None, lambda: _maybe_apply_timeout(_run))
            else:
                matches = _maybe_apply_timeout(_run)
    except HTTPException as he:
        outcome = 'timeout' if he.status_code == 504 else 'error'
        if _y_scans: 
            try: _y_scans.labels(mode='path', outcome=outcome).inc()
            except Exception: pass
        # Approximate per-rule timeout/error increments for all compiled rules
        try:
            if he.status_code == 504 and _y_rule_timeouts:
                for rname in list(_RULES.keys()):
                    try: _y_rule_timeouts.labels(rule=str(rname)).inc()
                    except Exception: pass
            elif he.status_code != 504 and _y_rule_errors:
                for rname in list(_RULES.keys()):
                    try: _y_rule_errors.labels(rule=str(rname)).inc()
                    except Exception: pass
        except Exception:
            pass
        raise
    except Exception as exc:
        outcome = 'error'
        if _y_scans:
            try: _y_scans.labels(mode='path', outcome=outcome).inc()
            except Exception: pass
        try:
            if _y_rule_errors:
                for rname in list(_RULES.keys()):
                    try: _y_rule_errors.labels(rule=str(rname)).inc()
                    except Exception: pass
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"scan_failed: {exc}")
    elapsed_ms = int((time.time() - started) * 1000)
    if _y_latency:
        try: _y_latency.labels(mode='path').observe(elapsed_ms/1000.0)
        except Exception: pass
    if _y_scans:
        try: _y_scans.labels(mode='path', outcome=outcome).inc()
        except Exception: pass
    matches = _cap_matches(matches)
    # increment matches by pack if available
    if _y_matches and matches:
        try:
            seen_packs = set()
            for m in matches:
                name = getattr(m, 'rule', None) or getattr(m, 'name', None) or str(m)
                meta = _RULE_META.get(str(name)) or {}
                pack = (meta.get('pack') or 'unknown')
                if pack not in seen_packs:
                    _y_matches.labels(pack=str(pack)).inc()
                    seen_packs.add(pack)
        except Exception:
            pass
    # per-rule metrics for matches and bytes
    try:
        if matches:
            for m in matches:
                name = getattr(m, 'rule', None) or getattr(m, 'name', None) or str(m)
                if _y_rule_match: _y_rule_match.labels(rule=str(name)).inc()
                if _y_rule_bytes: _y_rule_bytes.labels(rule=str(name)).inc(len(limited))
    except Exception:
        pass
    result = {
        "path": str(resolved),
        "size": len(raw),
        "scanned_bytes": len(limited),
        "elapsed_ms": elapsed_ms,
        "matches": _serialize_matches(matches),
    }
    # Optional annotation of existing decision or artifact
    _maybe_annotate_decision(payload, matches)
    return result


def _serialize_matches(matches: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in matches or []:
        try:
            name = getattr(m, "rule", None) or getattr(m, "name", None) or str(m)
            strings = []
            for s in getattr(m, "strings", []) or []:
                try:
                    sid, off, data = s
                    strings.append({"id": sid, "offset": int(off), "length": len(data) if data is not None else 0})
                except Exception:
                    pass
            out.append({"rule": str(name), "string_hits": len(strings), "strings": strings})
        except Exception:
            out.append({"rule": str(m), "string_hits": 0, "strings": []})
    return out


@router.post("/scan_upload")
async def scan_upload(file: UploadFile = File(...), request: Request = None, auth=Depends(require_scopes("factors.search"))):
    if not _enabled():
        raise HTTPException(status_code=503, detail="yara_disabled")
    if not file:
        raise HTTPException(status_code=400, detail="file_required")
    try:
        content = await file.read()
    except Exception:
        raise HTTPException(status_code=400, detail="read_failed")
    limited = _cap_bytes_limit(content)
    # Optional hash reputation check from query
    try:
        qp = {} if request is None else dict(request.query_params)
        _maybe_add_hash_reputation(qp, limited)
    except Exception:
        pass
    rules = None if _sequential_enabled() else _compile_all()
    started = time.time()
    outcome = 'ok'
    try:
        if _sequential_enabled():
            if _SEM is not None:
                import asyncio as _a
                async with _SEM:  # type: ignore
                    matches, had_to, had_err = await _a.get_running_loop().run_in_executor(None, lambda: _sequential_match_per_rule(limited))
            else:
                matches, had_to, had_err = _sequential_match_per_rule(limited)
            if had_to:
                outcome = 'timeout'
            elif had_err:
                outcome = 'error'
        else:
            def _run():
                return rules.match(data=limited)  # type: ignore[union-attr]
            if _SEM is not None:
                import asyncio as _a
                async with _SEM:  # type: ignore
                    matches = await _a.get_running_loop().run_in_executor(None, lambda: _maybe_apply_timeout(_run))
            else:
                matches = _maybe_apply_timeout(_run)
    except HTTPException as he:
        outcome = 'timeout' if he.status_code == 504 else 'error'
        if _y_scans:
            try: _y_scans.labels(mode='upload', outcome=outcome).inc()
            except Exception: pass
        try:
            if he.status_code == 504 and _y_rule_timeouts:
                for rname in list(_RULES.keys()):
                    try: _y_rule_timeouts.labels(rule=str(rname)).inc()
                    except Exception: pass
            elif he.status_code != 504 and _y_rule_errors:
                for rname in list(_RULES.keys()):
                    try: _y_rule_errors.labels(rule=str(rname)).inc()
                    except Exception: pass
        except Exception:
            pass
        raise
    except Exception as exc:
        outcome = 'error'
        if _y_scans:
            try: _y_scans.labels(mode='upload', outcome=outcome).inc()
            except Exception: pass
        try:
            if _y_rule_errors:
                for rname in list(_RULES.keys()):
                    try: _y_rule_errors.labels(rule=str(rname)).inc()
                    except Exception: pass
        except Exception:
            pass
        raise HTTPException(status_code=500, detail=f"scan_failed: {exc}")
    elapsed_ms = int((time.time() - started) * 1000)
    if _y_latency:
        try: _y_latency.labels(mode='upload').observe(elapsed_ms/1000.0)
        except Exception: pass
    if _y_scans:
        try: _y_scans.labels(mode='upload', outcome=outcome).inc()
        except Exception: pass
    matches = _cap_matches(matches)
    if _y_matches and matches:
        try:
            seen_packs = set()
            for m in matches:
                name = getattr(m, 'rule', None) or getattr(m, 'name', None) or str(m)
                meta = _RULE_META.get(str(name)) or {}
                pack = (meta.get('pack') or 'unknown')
                if pack not in seen_packs:
                    _y_matches.labels(pack=str(pack)).inc()
                    seen_packs.add(pack)
        except Exception:
            pass
    try:
        if matches:
            for m in matches:
                name = getattr(m, 'rule', None) or getattr(m, 'name', None) or str(m)
                if _y_rule_match: _y_rule_match.labels(rule=str(name)).inc()
                if _y_rule_bytes: _y_rule_bytes.labels(rule=str(name)).inc(len(limited))
    except Exception:
        pass
    result = {
        "filename": file.filename,
        "size": len(content),
        "scanned_bytes": len(limited),
        "elapsed_ms": elapsed_ms,
        "matches": _serialize_matches(matches),
    }
    # Optional annotation if query/body includes event_id or artifact_id
    try:
        # Multipart form fields can be retrieved from request.query_params if provided as query
        if request is not None:
            qp = request.query_params
            payload = { 'event_id': qp.get('event_id'), 'artifact_id': qp.get('artifact_id') }
            _maybe_annotate_decision(payload, matches)
    except Exception:
        pass
    return result


def _maybe_annotate_decision(payload: dict[str, Any] | None, matches: list[Any]) -> None:
    """If event_id is provided and matches exist, attach malware:yara_match_<rule> factors.

    Uses DECISION_CACHE when available; updates factors in-place and re-records via
    server._record_decision to publish SSE and persist.
    """
    if not payload or not matches:
        return
    event_id = None
    try:
        event_id = payload.get('event_id') or payload.get('eventId')
    except Exception:
        event_id = None
    if not event_id:
        return
    try:
        from .server import DECISION_CACHE, _record_decision
    except Exception:
        return
    try:
        dec = DECISION_CACHE.get(event_id)
        if not dec:
            return
        # Build factors
        factors = list(dec.get('factors') or []) if isinstance(dec, dict) else list(getattr(dec, 'factors', []) or [])
        # Serialize matches to factor names
        factor_names: list[str] = []
        for m in matches or []:
            try:
                name = getattr(m, 'rule', None) or getattr(m, 'name', None) or str(m)
                if name:
                    fname = f"malware:yara_match_{str(name)}"
                    factor_names.append(fname)
                    # Add metadata-derived factors
                    meta = _RULE_META.get(str(name)) or {}
                    fam = (meta.get('family') or '').strip()
                    sev = (meta.get('severity') or '').strip().lower()
                    mitre = meta.get('mitre') or []
                    if fam:
                        factor_names.append(f"threat:family:{fam}")
                    if sev in {'low','medium','high'}:
                        factor_names.append(f"risk:{sev}")
                    if isinstance(mitre, list):
                        for t in mitre:
                            if t:
                                factor_names.append(f"mitre:{t}")
            except Exception:
                continue
        # De-duplicate and update
        changed = False
        for fn in factor_names:
            if fn not in factors:
                factors.append(fn)
                changed = True
        if not changed:
            return
        verdict = (dec.get('verdict') if isinstance(dec, dict) else getattr(dec, 'verdict', 'OBSERVE')) or 'OBSERVE'
        confidence = float((dec.get('confidence') if isinstance(dec, dict) else getattr(dec, 'confidence', 0.0)) or 0.0)
        # Include bounded evidence snapshot in meta
        meta_payload = { 'yara_evidence': _build_evidence_snapshot(matches) }
        # Re-record decision to propagate via SSE + persistence
        _record_decision(str(event_id), str(verdict), float(confidence), factors, meta_payload)
    except Exception:
        return


def _cap_matches(matches: list[Any]) -> list[Any]:
    try:
        MAX = int(os.getenv('YARA_MAX_MATCHES_PER_FILE', '100') or 100)
    except Exception:
        MAX = 100
    try:
        return list(matches)[:MAX] if matches else []
    except Exception:
        return []


def _build_evidence_snapshot(matches: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        import hashlib
        MAX = 5
        for m in matches or []:
            for s in getattr(m, 'strings', []) or []:
                try:
                    sid, off, data = s
                    h = hashlib.sha1(data or b'').hexdigest()[:8] if isinstance(data, (bytes, bytearray)) else None
                    out.append({ 'id': sid, 'offset': int(off), 'length': (len(data) if data is not None else 0), 'sha1_8': h })
                    if len(out) >= MAX:
                        return out
                except Exception:
                    continue
    except Exception:
        pass
    return out


def _maybe_add_hash_reputation(payload: dict[str, Any] | None, content: bytes | None) -> None:
    if not payload or not content:
        return
    event_id = payload.get('event_id') if isinstance(payload, dict) else None
    if not event_id:
        return
    try:
        import hashlib
        digest = hashlib.sha256(content).hexdigest()
    except Exception:
        return
    try:
        from integrations.threat_intel_client import CLIENT as _TI  # type: ignore
        if hasattr(_TI, 'is_malicious_hash') and _TI.is_malicious_hash(digest):
            from .server import DECISION_CACHE, _record_decision
            dec = DECISION_CACHE.get(event_id)
            if not dec:
                return
            factors = list(dec.get('factors') or []) if isinstance(dec, dict) else list(getattr(dec, 'factors', []) or [])
            fn = 'reputation:hash_known_bad'
            if fn not in factors:
                factors.append(fn)
                verdict = (dec.get('verdict') if isinstance(dec, dict) else getattr(dec, 'verdict', 'OBSERVE')) or 'OBSERVE'
                confidence = float((dec.get('confidence') if isinstance(dec, dict) else getattr(dec, 'confidence', 0.0)) or 0.0)
                _record_decision(str(event_id), str(verdict), float(confidence), factors, None)
    except Exception:
        return
