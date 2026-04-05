from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from src.artifact.memory_pipeline import MemoryPipeline


class _StubAdapter:
    def __init__(self, results: Dict[str, Any]) -> None:
        self._results = results

    def run_plugins(self, dump_path: Path, *, plugins=None, profile=None, plugin_args=None) -> Dict[str, Any]:
        return self._results


class _StubHopGraph:
    def __init__(self) -> None:
        self.observations: List[Any] = []

    def update(self, obs) -> None:
        self.observations.append(obs)


class _StubGraphSink:
    def __init__(self) -> None:
        self.edges: List[Dict[str, Any]] = []

    def add_edge(self, src: str, dst: str, etype: str, **kwargs: Any) -> None:
        self.edges.append({"src": src, "dst": dst, "etype": etype, "kwargs": kwargs})


class _StubRekall:
    def run_plugins(self, dump_path: Path, *, profile=None, plugins=None, plugin_args=None):
        return {"pslist": [{"ImageFileName": "rekall.exe", "PID": 1111}]}


class _StubSandbox:
    def __init__(self) -> None:
        self.submissions: List[Dict[str, Any]] = []

    def submit(self, job, analysis: Dict[str, Any]) -> Dict[str, Any]:
        submission = {
            "adapter": "local",
            "status": "submitted",
            "verdict": analysis.get("dread", {}).get("damage"),
        }
        payload = {"job_id": job.job_id, "status": "submitted", "verdict": submission["verdict"], "submissions": [submission]}
        self.submissions.append(payload)
        return payload


def _sample_results() -> Dict[str, Any]:
    return {
        "windows.pslist": [
            {
                "ImageFileName": "mimikatz.exe",
                "PID": 4242,
                "path": "C:\\mimikatz.exe",
                "sha256": "abc123",
            }
        ],
        "windows.dlllist": [{"BaseDllName": "evil.dll", "PID": 4242}],
        "windows.malfind": [
            {"PID": 4242, "Process": "mimikatz.exe", "Tag": "TAG", "Protection": "PAGE_EXECUTE_READWRITE"}
        ],
        "windows.netscan": [
            {"Process": "mimikatz.exe", "ForeignAddr": "10.0.0.5:443", "Info": "beacon ready"},
        ],
        "windows.registry.shimcache": [
            {"path": "C:\\\\Temp\\\\evil.exe", "timestamp": 1700000000, "Signed": False},
        ],
    }


def test_memory_pipeline_emits_threat_model_and_edges(tmp_path):
    storage = tmp_path / "jobs"
    adapter = _StubAdapter(_sample_results())
    hopgraph = _StubHopGraph()
    graph_sink = _StubGraphSink()
    sandbox = _StubSandbox()
    pipeline = MemoryPipeline(
        storage_dir=storage,
        adapter=adapter,
        hopgraph=hopgraph,
        graph_sink=graph_sink,
        rekall_adapter=_StubRekall(),
        sandbox_runner=sandbox,
        dump_ttl_seconds=1,
    )

    job = pipeline.submit_job(
        host="host-1",
        case_id="case-9",
        filename="dump.raw",
        dump_bytes=b"\x00" * 8,
        metadata={"run_sandbox": True, "tenant_id": "tenant-1"},
    )
    pipeline.process_job(job.job_id)

    analysis = job.metadata.get("analysis") or {}
    assert analysis.get("factors"), "factors should be populated"
    assert analysis.get("hopgraph_edges"), "hopgraph edges should be recorded"
    assert analysis["hopgraph_edges"][0].get("source_node"), "canonical node ids should be present"
    threat_model = analysis.get("threat_model") or {}
    assert "mitre" in threat_model and threat_model["mitre"], "threat model should include MITRE tags"
    assert "dread" in analysis and analysis["dread"]["damage"] > 0
    assert analysis.get("rekall"), "rekall adapter results should be present"
    assert analysis.get("timeline"), "timeline should be generated"
    assert all(entry.get("platform") for entry in analysis["timeline"]), "timeline entries include platform tag"
    assert analysis.get("registry"), "registry summary should be attached"
    assert analysis.get("malware_family"), "malware family should be identified"
    assert analysis.get("sandbox", {}).get("status") == "submitted"
    assert sandbox.submissions, "sandbox runner should capture submissions"
    assert graph_sink.edges, "edges should be forwarded to the unified hopgraph sink"
    first_edge = graph_sink.edges[0]
    assert first_edge["src"].startswith("process:"), "memory edges should normalize process nodes"
