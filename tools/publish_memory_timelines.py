from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict

from src.artifact.memory_pipeline import MemoryPipeline


def _fixture_dir() -> Path:
    return Path("tests/fixtures/memory/health")


def _artifact_dir() -> Path:
    return Path(os.getenv("API_STAGE_ARTIFACT_DIR", "logs/perf/api_stage/artifacts")) / "memory" / "timelines"


class _Adapter:
    def __init__(self, results: Dict[str, Any]) -> None:
        self._results = results or {}

    def run_plugins(self, dump_path, *, plugins=None, profile=None, plugin_args=None):
        return self._results


class _SandboxStub:
    def submit(self, job, analysis: Dict[str, Any]) -> Dict[str, Any]:
        return {"status": "stub", "submissions": []}


def _ensure_env() -> None:
    os.environ.setdefault("MEMORY_KMS_DISABLED", "1")
    os.environ.setdefault("MEMORY_ACQUISITION_DISABLED", "1")


def _build_pipeline(volatility_results: Dict[str, Any]) -> MemoryPipeline:
    storage_dir = Path(tempfile.mkdtemp(prefix="timeline-"))
    return MemoryPipeline(
        storage_dir=storage_dir,
        adapter=_Adapter(volatility_results),
        rekall_adapter=None,
        sandbox_runner=_SandboxStub(),
        key_manager=None,
        acquisition_guide=None,
    )


def process_fixture(path: Path, artifact_dir: Path) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    host = payload.get("host") or path.stem
    platform = payload.get("platform", "windows")
    pipeline = _build_pipeline(payload.get("volatility", {}))
    job = pipeline.submit_job(
        host=host,
        case_id=f"{host}-timeline",
        filename=f"{path.stem}.raw",
        dump_bytes=b"\x00",
        metadata={"platform": platform, "tenant_id": "timeline-fixture"},
    )
    pipeline.process_job(job.job_id, auto_cleanup=True)
    analysis = job.metadata.get("analysis") or {}
    timeline = analysis.get("timeline") or []
    payload = {
        "fixture": path.name,
        "platform": platform,
        "timeline_entries": timeline,
        "registry": analysis.get("registry") or {},
    }
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / f"{path.stem}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run(fixtures: Path, artifact_dir: Path) -> None:
    _ensure_env()
    entries = list(sorted(fixtures.glob("*.json")))
    if not entries:
        print(f"[timeline] no fixtures found in {fixtures}")  # noqa: T201
        return
    for fixture in entries:
        process_fixture(fixture, artifact_dir)
        print(f"[timeline] published {fixture.name}")  # noqa: T201


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Publish anonymized memory timeline artefacts.")
    parser.add_argument("--fixture-dir", default=str(_fixture_dir()))
    parser.add_argument("--artifact-dir", default=str(_artifact_dir()))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run(Path(args.fixture_dir), Path(args.artifact_dir))


if __name__ == "__main__":
    main()
