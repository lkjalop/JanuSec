import base64
import os
from datetime import datetime, timedelta

from src.core.detectors import endpoint_ransom as det


def test_entropy_detector_flags_sample():
    sample = os.urandom(2048)
    runtime = {
        "file_events": [
            {"host": "h1", "path": "C:\\\\share\\\\doc1.bin", "content_sample": base64.b64encode(sample).decode("ascii")}
        ]
    }
    hits = det.detect_file_entropy_writes(runtime, entropy_threshold=6.0)
    assert hits and hits[0]["factor"] == "file_write_entropy_high"


def test_shadowcopy_and_vss_detection():
    runtime = {
        "process_events": [
            {"host": "h1", "exe": "C:\\\\Windows\\\\System32\\\\vssadmin.exe", "command_line": "vssadmin delete shadows /all"}
        ],
        "registry_events": [
            {
                "host": "h1",
                "key": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VSS",
                "action": "SetValue",
            }
        ],
        "service_events": [{"host": "h1", "service": "VSS", "state": "disable"}],
    }
    cmds = det.detect_shadowcopy_commands(runtime)
    svc = det.detect_vss_service_tamper(runtime)
    assert cmds and svc
    assert cmds[0]["factor"] == "vss_shadow_copy_delete"
    assert any(entry.get("factor") == "vss_service_tamper" for entry in svc)


def test_file_write_rate_spike():
    now = datetime.utcnow()
    file_events = []
    for i in range(0, 120):
        file_events.append({"host": "burst-host", "timestamp": (now + timedelta(seconds=i * 0.05)).isoformat()})
    for i in range(0, 20):
        file_events.append({"host": "burst-host", "timestamp": (now + timedelta(seconds=600 + i * 20)).isoformat()})
    runtime = {"file_events": file_events}
    spikes = det.detect_file_write_rate_spike(runtime, window_seconds=10, min_events=60, multiplier=3.0)
    assert spikes and spikes[0]["factor"] == "file_write_burst"


def test_orchestrator_generates_incident():
    runtime = det.generate_synthetic_ransomware_runtime()
    entropy_hits = det.detect_file_entropy_writes(runtime, entropy_threshold=6.0)
    burst_hits = det.detect_file_write_rate_spike(runtime, window_seconds=30, min_events=20, multiplier=1.0)
    vss_hits = det.detect_shadowcopy_commands(runtime)
    signals = entropy_hits + burst_hits + vss_hits
    incident = det.orchestrate_ransomware_signals(runtime, signals)
    assert incident.get("factor") == "ransomware_auto_incident"
    assert incident["host_count"] >= 1


def test_ransomware_summary_surfaces_metrics_and_missing_logs():
    runtime = det.generate_synthetic_ransomware_runtime()
    entropy_hits = det.detect_file_entropy_writes(runtime, entropy_threshold=6.0)
    burst_hits = det.detect_file_write_rate_spike(runtime, window_seconds=30, min_events=20, multiplier=1.0)
    metrics = det.summarize_ransomware_context(runtime, entropy_hits + burst_hits)
    assert metrics.get("ransomware_confidence") and metrics["ransomware_confidence"] > 0.4
    missing = metrics.get("missing_logs") or []
    assert any(entry.get("source") == "network" for entry in missing if isinstance(entry, dict))
