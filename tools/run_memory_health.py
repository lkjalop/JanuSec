from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from src.artifact.memory_pipeline import MemoryPipeline


def _default_fixture_dir() -> Path:
    return Path("tests/fixtures/memory/health")


def _artifact_root() -> Path:
    return Path(os.getenv("API_STAGE_ARTIFACT_DIR", "logs/perf/api_stage/artifacts")) / "memory" / "health"


class _FixtureAdapter:
    def __init__(self, results: Dict[str, Any]) -> None:
        self._results = results or {}

    def run_plugins(self, dump_path, *, plugins=None, profile=None, plugin_args=None):
        return self._results


class _FixtureRekall:
    def __init__(self, results: Dict[str, Any]) -> None:
        self._results = results or {}

    def run_plugins(self, dump_path, *, profile=None, plugins=None, plugin_args=None):
        return self._results


class _FixtureSandbox:
    def __init__(self, payload: Dict[str, Any]) -> None:
        self._payload = payload or {}

    def submit(self, job, analysis: Dict[str, Any]) -> Dict[str, Any]:
        data = dict(self._payload)
        data.setdefault("adapter", "fixture")
        data.setdefault("status", "submitted")
        data.setdefault("submissions", self._payload.get("submissions") or [])
        return data


def _ensure_env_defaults() -> None:
    os.environ.setdefault("MEMORY_KMS_DISABLED", "1")
    os.environ.setdefault("MEMORY_ACQUISITION_DISABLED", "1")


def _load_fixtures(directory: Path) -> List[Path]:
    return sorted(p for p in directory.glob("*.json") if p.is_file())


def _process_fixture(path: Path, artifact_root: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    host = payload.get("host") or path.stem
    platform = payload.get("platform") or "windows"

    adapter = _FixtureAdapter(payload.get("volatility", {}))
    rekall_adapter = _FixtureRekall(payload.get("rekall", {}))
    sandbox_runner = _FixtureSandbox(payload.get("sandbox", {}))

    storage_dir = Path(tempfile.mkdtemp(prefix="mem-health-"))
    pipeline = MemoryPipeline(
        storage_dir=storage_dir,
        adapter=adapter,
        rekall_adapter=rekall_adapter,
        sandbox_runner=sandbox_runner,
        key_manager=None,
        acquisition_guide=None,
    )

    job = pipeline.submit_job(
        host=host,
        case_id=f"{host}-case",
        filename=f"{path.stem}.raw",
        dump_bytes=b"\x00\x00",
        metadata={"platform": platform, "tenant_id": payload.get("tenant_id", "health-fixture"), "run_sandbox": True},
    )
    pipeline.process_job(job.job_id, auto_cleanup=True)
    analysis = job.metadata.get("analysis") or {}
    sandbox = analysis.get("sandbox") or {}

    summary = {
        "fixture": path.name,
        "job_id": job.job_id,
        "host": host,
        "platform": platform,
        "volatility_plugins": sorted(list((analysis.get("plugin_results") or {}).keys())),
        "rekall_plugins": sorted(list((analysis.get("rekall") or {}).keys())),
        "sandbox_status": sandbox.get("status"),
        "sandbox_adapters": [sub.get("adapter") for sub in sandbox.get("submissions", []) if isinstance(sub, dict)],
        "timeline_length": len(analysis.get("timeline") or []),
        "factors": analysis.get("factors") or [],
    }

    artifact_root.mkdir(parents=True, exist_ok=True)
    (artifact_root / f"{path.stem}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def run_health_checks(fixture_dir: Path, artifact_root: Path) -> None:
    _ensure_env_defaults()
    fixtures = _load_fixtures(fixture_dir)
    if not fixtures:
        print(f"[memory-health] No fixtures found in {fixture_dir}, skipping.")  # noqa: T201
        return
    manifest = []
    for fixture in fixtures:
        summary = _process_fixture(fixture, artifact_root)
        manifest.append(summary)
        print(f"[memory-health] processed {fixture.name} -> {summary['job_id']}")  # noqa: T201
    (artifact_root / "manifest.json").write_text(json.dumps({"entries": manifest}, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run memory health checks using fixtures or dumps.")
    parser.add_argument(
        "--fixture-dir",
        default=str(_default_fixture_dir()),
        help="Directory containing fixture JSON files (default: tests/fixtures/memory/health).",
    )
    parser.add_argument(
        "--artifact-dir",
        default=str(_artifact_root()),
        help="Directory to store health artefacts (default: logs/perf/api_stage/artifacts/memory/health).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    fixture_dir = Path(args.fixture_dir)
    artifact_root = Path(args.artifact_dir)
    run_health_checks(fixture_dir, artifact_root)


if __name__ == "__main__":
    main()
