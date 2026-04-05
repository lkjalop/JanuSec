from __future__ import annotations

import json
import os
from pathlib import Path

from src.artifact.memory_pipeline import MemoryPipeline


class _FixtureAdapter:
    def __init__(self, results: dict) -> None:
        self._results = results

    def run_plugins(self, dump_path, *, plugins=None, profile=None, plugin_args=None):
        return self._results


class _SandboxStub:
    def __init__(self) -> None:
        self.submissions = []

    def submit(self, job, analysis):
        self.submissions.append({"job_id": job.job_id, "platform": job.metadata.get("platform")})
        return {"adapter": "stub", "status": "submitted"}


def _load_fixture(name: str) -> dict:
    path = Path("tests/fixtures/memory") / name
    return json.loads(path.read_text(encoding="utf-8"))


def _build_pipeline(tmp_path: Path, results: dict, sandbox: _SandboxStub) -> MemoryPipeline:
    os.environ.setdefault("MEMORY_KMS_DISABLED", "1")
    os.environ.setdefault("MEMORY_ACQUISITION_DISABLED", "1")
    return MemoryPipeline(
        storage_dir=tmp_path / "jobs",
        adapter=_FixtureAdapter(results),
        sandbox_runner=sandbox,
        key_manager=None,
        acquisition_guide=None,
    )


def test_memory_pipeline_multi_platform_sandbox_parity(tmp_path):
    fixtures = [
        ("window_sample.json", "windows"),
        ("mac_arm_dump.json", "macos"),
        ("linux_sample.json", "linux"),
        ("arm_sample.json", "windows"),
    ]
    sandbox = _SandboxStub()
    for filename, platform in fixtures:
        results = _load_fixture(filename)
        pipeline = _build_pipeline(tmp_path, results, sandbox)
        job = pipeline.submit_job(
            host=f"{platform}-host",
            case_id=f"{platform}-case",
            filename=f"{platform}.raw",
            dump_bytes=b"00",
            metadata={"platform": platform, "tenant_id": "tenant", "run_sandbox": True},
        )
        pipeline.process_job(job.job_id, auto_cleanup=True)

    platforms = [submission["platform"] for submission in sandbox.submissions]
    assert {"windows", "macos", "linux"}.issubset(set(platforms))
    assert len(platforms) == len(fixtures)
