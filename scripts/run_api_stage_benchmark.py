#!/usr/bin/env python
"""
API security authorization harness and soak runner.

Usage:
    python scripts/run_api_stage_benchmark.py \
        --base-url http://127.0.0.1:8080 \
        --api-key devkey123 \
        --vectors tests/data/api_security_auth_harness.json

Long-run TestClient soaks must disable the built-in rate limiter in the
same shell invocation, for example:

    $env:RATE_LIMIT_ENABLED='0'; `
    $env:RATE_LIMIT_MAX_REQUESTS='100000'; `
    $env:RATE_LIMIT_WINDOW_SECONDS='1'; `
    python scripts/run_api_stage_benchmark.py --tenant-config config/api_stage_tenants.ci.json --use-testclient

The script sends the harness vectors to `/api/v1/api_security/ingest`,
captures latency + factor comparisons, and writes the run details to
`logs/perf/api_stage/benchmark-<ts>.json`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

import requests
from src.core.pipeline.api_stage_profiles import (
    append_manifest_entry,
    load_pipeline_profile_map,
    merge_vector_paths,
)

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover
    TestClient = None  # type: ignore

DEFAULT_VECTORS = Path("tests/data/api_security_auth_harness.json")
LOG_DIR = Path("logs/perf/api_stage")
LOG_DIR.mkdir(parents=True, exist_ok=True)
INVENTORY_DIR = LOG_DIR / "inventory"
INVENTORY_DIR.mkdir(parents=True, exist_ok=True)
OPENAPI_SOURCE = Path(os.getenv("API_STAGE_OPENAPI_PATH", "docs/api/openapi.json"))
OPENAPI_SUBDIR = "openapi"


@dataclass
class TenantProfile:
    name: str
    base_url: str
    api_key: str
    vector_files: List[Path]
    soak_count: int
    soak_payload: Optional[Path]
    pipeline_profile: Optional[str] = None
    pipeline_meta: Optional[Dict[str, Any]] = None

    @staticmethod
    def _safe_label(value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", value.strip().lower())
        cleaned = cleaned.strip("-")
        return cleaned or "tenant"

    @property
    def safe_name(self) -> str:
        return self._safe_label(self.name)

    @property
    def filename_prefix(self) -> str:
        if not self.pipeline_profile:
            return self.safe_name
        suffix = self._safe_label(self.pipeline_profile)
        return f"{self.safe_name}-{suffix}"

    @property
    def vector_sources(self) -> List[str]:
        return [str(p) for p in self.vector_files]


def load_vectors(paths: List[Path]) -> List[Dict[str, Any]]:
    combined: List[Dict[str, Any]] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"auth harness vectors missing: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(f"vector pack must be a list of cases: {path}")
        for entry in data:
            if not isinstance(entry, dict):
                continue
            augmented = dict(entry)
            augmented.setdefault("_vector_source", str(path))
            combined.append(augmented)
    return combined


def _coerce_vector_list(value: Any, default_path: Path) -> List[Path]:
    paths: List[Path] = []
    if value is None:
        paths.append(default_path)
    elif isinstance(value, str):
        paths.append(Path(value))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                paths.append(Path(item))
    elif isinstance(value, dict):
        base = value.get("base")
        overrides = value.get("overrides") or []
        if base:
            paths.append(Path(base))
        elif not overrides:
            paths.append(default_path)
        for item in overrides:
            if isinstance(item, str):
                paths.append(Path(item))
    else:
        paths.append(default_path)

    deduped: List[Path] = []
    seen: set[str] = set()
    for entry in paths or [default_path]:
        key = str(entry)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped or [default_path]


def _coerce_extra_vectors(value: Any) -> List[Path]:
    extras: List[Path] = []
    if isinstance(value, str):
        extras.append(Path(value))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                extras.append(Path(item))
    return extras


def _resolve_run_url() -> Optional[str]:
    explicit = os.getenv("API_STAGE_ARTIFACT_URL")
    if explicit:
        return explicit
    run_id = os.getenv("GITHUB_RUN_ID")
    repo = os.getenv("GITHUB_REPOSITORY")
    if not (run_id and repo):
        return None
    server = os.getenv("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    return f"{server}/{repo}/actions/runs/{run_id}"


def compare_expected(result: Dict[str, Any], expected: Dict[str, Any]) -> Dict[str, Any]:
    actual = set(result.get("factors") or [])
    expected_subset = set(expected.get("factors_contains") or [])
    missing = [f for f in expected_subset if f not in actual]
    return {
        "ok": not missing,
        "missing": missing,
        "reported": sorted(actual),
    }


def run_harness(post_func, vectors: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary: List[Dict[str, Any]] = []
    latencies: List[float] = []
    for vector in vectors:
        payload = vector.get("event") or {}
        expected = vector.get("expected") or {}
        name = vector.get("name", "vector")
        start = time.perf_counter()
        resp = post_func("/api/v1/api_security/ingest", payload)
        dur_ms = (time.perf_counter() - start) * 1000.0
        latencies.append(dur_ms)
        if resp.status_code != 200:
            summary.append(
                {
                    "name": name,
                    "ok": False,
                    "error": f"HTTP {resp.status_code}",
                    "duration_ms": round(dur_ms, 3),
                    "body": resp.text[:512],
                }
            )
            continue
        result = resp.json()
        cmp = compare_expected(result, expected)
        summary.append(
            {
                "name": name,
                "ok": cmp["ok"],
                "duration_ms": round(dur_ms, 3),
                "missing_factors": cmp["missing"],
                "reported_factors": cmp["reported"],
            }
        )
    metrics = {
        "count": len(latencies),
        "avg_ms": round(mean(latencies), 3) if latencies else 0.0,
        "p95_ms": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 3) if latencies else 0.0,
    }
    return {"cases": summary, "metrics": metrics}


def run_soak(post_func, event: Dict[str, Any], iterations: int) -> Dict[str, Any]:
    latencies: List[float] = []
    failures = 0
    for _ in range(iterations):
        start = time.perf_counter()
        resp = post_func("/api/v1/api_security/ingest", event)
        dur_ms = (time.perf_counter() - start) * 1000.0
        latencies.append(dur_ms)
        if resp.status_code != 200:
            failures += 1
    duration_seconds = sum(latencies) / 1000.0
    p95 = round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 3) if latencies else 0.0
    return {
        "count": iterations,
        "avg_ms": round(mean(latencies), 3) if latencies else 0.0,
        "p95_ms": p95,
        "failures": failures,
        "throughput_eps": round(iterations / duration_seconds, 2) if duration_seconds else 0.0,
    }


def build_post_func(base_url: str, api_key: str, *, use_testclient: bool):
    headers = {"x-api-key": api_key}
    if use_testclient:
        if TestClient is None:
            raise SystemExit("fastapi.testclient is not available")
        from src.api.app import app  # lazy import to avoid heavy startup unless needed

        client = TestClient(app)

        def _post(path: str, payload: Dict[str, Any]):
            return client.post(path, headers=headers, json=payload)

        return _post

    def _post(path: str, payload: Dict[str, Any]):
        return requests.post(
            f"{base_url.rstrip('/')}{path}",
            headers=headers,
            json=payload,
            timeout=30,
        )

    return _post


def collect_observed_routes(vectors: List[Dict[str, Any]]) -> List[str]:
    observed: set[str] = set()
    for vector in vectors:
        if vector.get("skip_inventory_assert"):
            continue
        event = vector.get("event") or {}
        uri = event.get("uri")
        if uri:
            observed.add(str(uri))
    return sorted(observed)


def run_inventory_assertion(post_func, observed_routes: List[str]) -> Dict[str, Any]:
    payload = {"observed_routes": observed_routes}
    resp = post_func("/api/v1/api_security/inventory/assert", payload)
    result: Dict[str, Any] = {
        "status_code": resp.status_code,
        "observed_routes": observed_routes,
    }
    try:
        result["response"] = resp.json()
    except Exception:
        result["response_text"] = resp.text
    result["ok"] = resp.status_code == 200
    return result


def validate_pipeline_profile_coverage(
    profiles: List[TenantProfile],
    pipeline_profiles: Dict[str, Dict[str, Any]],
) -> None:
    if not pipeline_profiles:
        return
    configured = {
        profile.pipeline_profile
        for profile in profiles
        if profile.pipeline_profile
    }
    optional = {
        name
        for name, meta in pipeline_profiles.items()
        if isinstance(meta, dict) and meta.get("harness_optional")
    }
    missing = sorted(
        name for name in pipeline_profiles.keys()
        if name not in configured and name not in optional
    )
    allow_missing = os.getenv("API_STAGE_ALLOW_MISSING_PROFILES", "").lower()
    if missing and allow_missing not in {"1", "true", "yes"}:
        raise SystemExit(
            "Tenant config missing pipeline profiles: "
            f"{', '.join(missing)}. Update config/api_stage_tenants*.json."
        )


def publish_openapi_bundle(output_dir: Path) -> Optional[Dict[str, Any]]:
    if not OPENAPI_SOURCE.exists():
        return None
    try:
        raw = OPENAPI_SOURCE.read_text(encoding="utf-8")
    except Exception:
        return None
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    dest_dir = output_dir / OPENAPI_SUBDIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"openapi-{digest[:12]}.json"
    dest.write_text(raw, encoding="utf-8")
    print(f"Published OpenAPI bundle: {dest}")
    return {
        "file": str(dest.relative_to(output_dir)),
        "hash": digest,
        "source": str(OPENAPI_SOURCE),
    }


def load_tenant_profiles(
    path: Path,
    default_base: str,
    default_key: str,
    default_vectors: Path,
    default_soak: int,
    default_soak_payload: Optional[Path],
    pipeline_profiles: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[TenantProfile]:
    data = json.loads(path.read_text(encoding="utf-8"))
    profiles: List[TenantProfile] = []
    for entry in data:
        name = str(entry.get("name") or "tenant")
        base_url = str(entry.get("base_url") or default_base)
        api_key = str(entry.get("api_key") or default_key)
        base_vectors = _coerce_vector_list(entry.get("vectors"), default_vectors)
        extra_vectors = _coerce_extra_vectors(entry.get("extra_vectors"))
        soak_count = int(entry.get("soak_count", default_soak))
        soak_payload_value = entry.get("soak_payload")
        soak_payload = Path(soak_payload_value) if soak_payload_value else default_soak_payload
        pipeline_profile = entry.get("pipeline_profile")
        pipeline_meta = None
        if pipeline_profile and pipeline_profiles:
            pipeline_meta = pipeline_profiles.get(pipeline_profile)
        vector_files = merge_vector_paths(base_vectors, pipeline_meta, extra_vectors)
        profiles.append(
            TenantProfile(
                name=name,
                base_url=base_url,
                api_key=api_key,
                vector_files=vector_files,
                soak_count=soak_count,
                soak_payload=soak_payload,
                pipeline_profile=pipeline_profile,
                pipeline_meta=pipeline_meta,
            )
        )
    return profiles


def build_profiles(args, pipeline_profiles: Dict[str, Dict[str, Any]]) -> List[TenantProfile]:
    soak_payload = args.soak_payload if (args.soak_payload and args.soak_payload.is_file()) else None
    if args.tenant_config:
        return load_tenant_profiles(
            args.tenant_config,
            args.base_url,
            args.api_key,
            args.vectors,
            args.soak_count,
            soak_payload,
            pipeline_profiles=pipeline_profiles,
        )
    pipeline_profile = args.pipeline_profile or os.getenv("API_STAGE_PIPELINE", "").strip() or None
    pipeline_meta = pipeline_profiles.get(pipeline_profile) if pipeline_profile else None
    vector_files = merge_vector_paths([args.vectors], pipeline_meta)
    return [
        TenantProfile(
            name="default",
            base_url=args.base_url,
            api_key=args.api_key,
            vector_files=vector_files,
            soak_count=args.soak_count,
            soak_payload=soak_payload,
            pipeline_profile=pipeline_profile,
            pipeline_meta=pipeline_meta,
        )
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run API security auth harness.")
    parser.add_argument("--base-url", default=os.getenv("API_STAGE_BASE", "http://127.0.0.1:8080"))
    parser.add_argument("--api-key", default=os.getenv("API_STAGE_KEY", "devkey123"))
    parser.add_argument("--vectors", type=Path, default=Path(os.getenv("API_STAGE_VECTORS", str(DEFAULT_VECTORS))))
    parser.add_argument("--output-dir", type=Path, default=LOG_DIR)
    parser.add_argument("--soak-count", type=int, default=int(os.getenv("API_STAGE_SOAK_COUNT", "0")))
    parser.add_argument("--soak-payload", type=Path, default=Path(os.getenv("API_STAGE_SOAK_PAYLOAD", "")))
    parser.add_argument("--tenant-config", type=Path, help="Optional JSON file describing tenant harness profiles.")
    parser.add_argument("--pipeline-config", type=Path, default=None, help="Optional pipeline metadata file (defaults to config/api_stage_pipeline_profiles.json).")
    parser.add_argument("--pipeline-profile", default=os.getenv("API_STAGE_PIPELINE", "").strip() or None, help="Pipeline profile name when a tenant config is not supplied.")
    parser.add_argument("--use-testclient", action="store_true", help="Run harness via FastAPI TestClient instead of HTTP requests.")
    args = parser.parse_args()

    pipeline_profiles = load_pipeline_profile_map(args.pipeline_config)
    profiles = build_profiles(args, pipeline_profiles)
    if args.tenant_config:
        validate_pipeline_profile_coverage(profiles, pipeline_profiles)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    overall_ok = True
    run_url = _resolve_run_url()
    openapi_bundle = publish_openapi_bundle(args.output_dir)

    for profile in profiles:
        vectors = load_vectors(profile.vector_files)
        post_func = build_post_func(profile.base_url, profile.api_key, use_testclient=args.use_testclient)
        results = run_harness(post_func, vectors)
        results["tenant"] = profile.name
        if profile.pipeline_profile:
            results["pipeline_profile"] = profile.pipeline_profile
        results["vector_sources"] = profile.vector_sources

        ts = int(time.time())
        bench_filename = f"benchmark-{profile.filename_prefix}-{ts}.json"
        out_path = args.output_dir / bench_filename
        out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"Wrote API stage benchmark for {profile.name}: {out_path}")
        ok = all(case.get("ok") for case in results["cases"])
        overall_ok = overall_ok and ok
        if not ok:
            print(json.dumps(results, indent=2))

        soak_count = profile.soak_count
        soak_results: Optional[Dict[str, Any]] = None
        soak_filename: Optional[str] = None
        if soak_count > 0:
            if profile.soak_payload and profile.soak_payload.is_file():
                raw = json.loads(profile.soak_payload.read_text(encoding="utf-8"))
                # Allow soak payloads that reuse vector packs by grabbing the first event.
                if isinstance(raw, list) and raw:
                    candidate = raw[0]
                else:
                    candidate = raw
                if isinstance(candidate, dict) and "event" in candidate:
                    soak_event = candidate["event"]
                elif isinstance(candidate, dict):
                    soak_event = candidate
                else:
                    soak_event = vectors[0].get("event", {})
            else:
                soak_event = vectors[0].get("event", {})
            soak_results = run_soak(post_func, soak_event, soak_count)
            soak_results["tenant"] = profile.name
            if profile.pipeline_profile:
                soak_results["pipeline_profile"] = profile.pipeline_profile
            soak_filename = f"soak-{profile.filename_prefix}-{ts}.json"
            soak_path = args.output_dir / soak_filename
            soak_path.write_text(json.dumps(soak_results, indent=2), encoding="utf-8")
            print(f"Wrote API stage soak metrics for {profile.name}: {soak_path}")
        manifest_entry = {
            "ts": ts,
            "tenant": profile.name,
            "pipeline_profile": profile.pipeline_profile,
            "pipeline_meta": profile.pipeline_meta or {},
            "files": {
                "benchmark": bench_filename,
                "soak": soak_filename,
            },
            "metrics": results.get("metrics"),
            "soak_metrics": soak_results,
            "vector_sources": profile.vector_sources,
            "github_run_url": run_url or (profile.pipeline_meta or {}).get("artifact_base_url"),
        }
        if openapi_bundle:
            manifest_entry["openapi"] = openapi_bundle
        observed_routes = collect_observed_routes(vectors)
        inventory_filename = None
        if observed_routes:
            inventory_result = run_inventory_assertion(post_func, observed_routes)
            inventory_filename = f"inventory-assert-{profile.filename_prefix}-{ts}.json"
            inventory_path = INVENTORY_DIR / inventory_filename
            inventory_path.write_text(json.dumps(inventory_result, indent=2), encoding="utf-8")
            print(f"Wrote inventory assertion for {profile.name}: {inventory_path} (ok={inventory_result.get('ok')})")
            manifest_entry["inventory_assert"] = inventory_filename

        append_manifest_entry(manifest_entry)

    if not overall_ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
