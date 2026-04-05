from __future__ import annotations

import base64
import math
from collections import Counter, defaultdict, deque
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:  # metrics are optional in lite/test mode
    from src.api.metrics_init import (  # type: ignore
        ensure_metrics as _ensure_metrics,
        ransomware_signal_total,
        ransomware_auto_incident_total,
        ransomware_missing_log_requests_total,
    )
except Exception:  # pragma: no cover - fallback for tests without metrics
    ransomware_signal_total = None
    ransomware_auto_incident_total = None
    ransomware_missing_log_requests_total = None

    def _ensure_metrics() -> None:  # type: ignore
        return None


def _shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = float(len(data))
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _maybe_bytes(sample: Any) -> bytes:
    if sample is None:
        return b""
    if isinstance(sample, bytes):
        return sample
    if isinstance(sample, str):
        try:
            return base64.b64decode(sample, validate=False)
        except Exception:
            try:
                return sample.encode("utf-8", errors="ignore")
            except Exception:
                return b""
    return b""


def _metric_inc(counter: Any, labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
    if counter is None:
        return
    try:
        _ensure_metrics()
    except Exception:
        return
    try:
        if labels:
            counter.labels(**labels).inc(value)
        else:
            counter.inc(value)
    except Exception:
        pass


def _runtime_events(runtime: Any, key: str) -> List[Dict[str, Any]]:
    if runtime is None:
        return []
    # Prefer ServerRuntime snapshot helper when available
    snapshot = None
    if hasattr(runtime, 'snapshot_endpoint_events'):
        try:
            snapshot = runtime.snapshot_endpoint_events()
        except Exception:
            snapshot = None
    if isinstance(snapshot, dict):
        data = snapshot.get(key) or []
        if isinstance(data, (list, tuple, deque)):
            return list(data)
    if isinstance(runtime, dict):
        data = runtime.get(key) or []
        if isinstance(data, (list, tuple, deque)):
            return list(data)
    try:
        attr = getattr(runtime, key)
        if isinstance(attr, (list, tuple, deque)):
            return list(attr)
    except Exception:
        pass
    return []


def detect_rare_parent_child(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    proc_events = _runtime_events(runtime, "process_events")
    child_counts: Dict[str, int] = {}
    for event in proc_events:
        try:
            child = event.get("exe") or event.get("image")
            if child:
                child_counts[child] = child_counts.get(child, 0) + 1
        except Exception:
            continue
    for event in proc_events:
        try:
            parent = event.get("parent_exe") or event.get("parent")
            child = event.get("exe") or event.get("image")
            host = event.get("host")
            if parent and child and child_counts.get(child, 0) < 2:
                out.append(
                    {
                        "factor": "rare_parent_child",
                        "host": host,
                        "parent": parent,
                        "child": child,
                        "score": 0.55,
                        "reason": "rare child observed across processes",
                    }
                )
        except Exception:
            continue
    return out


def detect_file_encryption_wave(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    files = _runtime_events(runtime, "file_events")
    counts_by_host: Dict[str, int] = {}
    encrypted_exts = {".locked", ".encrypted", ".crypt", ".cry", ".enc", ".rag"}
    for event in files:
        try:
            host = event.get("host")
            path = (event.get("path") or "").lower()
            if not host or not path:
                continue
            if any(path.endswith(ext) for ext in encrypted_exts):
                counts_by_host[host] = counts_by_host.get(host, 0) + 1
        except Exception:
            continue
    for host, count in counts_by_host.items():
        if count >= 50:
            out.append(
                {
                    "factor": "file_encryption_wave",
                    "host": host,
                    "count": count,
                    "score": 0.9,
                    "reason": "many encrypted files observed",
                    "stride": ["tampering", "denial"],
                    "mitre": ["T1486"],
                }
                )
    if out:
        _metric_inc(ransomware_signal_total, {'factor': 'file_encryption_wave'}, len(out))
    return out


def detect_unsigned_network_launch(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    net_events = _runtime_events(runtime, "network_events")
    for event in net_events:
        try:
            signer = event.get("binary_signed")
            exe = event.get("exe") or event.get("image")
            host = event.get("host")
            if signer is False and exe and event.get("outbound"):
                out.append(
                    {
                        "factor": "unsigned_binary_network_launch",
                        "host": host,
                        "exe": exe,
                        "score": 0.6,
                        "reason": "unsigned binary opened outbound connection",
                        "mitre": ["T1071"],
                    }
                )
        except Exception:
            continue
    if out:
        _metric_inc(ransomware_signal_total, {'factor': 'unsigned_binary_network_launch'}, len(out))
    return out


def detect_file_entropy_writes(runtime, entropy_threshold: float = 7.2, min_sample: int = 256) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    file_events = _runtime_events(runtime, "file_events")
    for event in file_events:
        try:
            path = event.get("path")
            host = event.get("host")
            entropy = event.get("entropy")
            if entropy is None:
                sample = (
                    event.get("content_sample")
                    or event.get("sample_bytes")
                    or event.get("bytes_sample")
                    or event.get("sample")
                )
                sample_bytes = _maybe_bytes(sample)
                if len(sample_bytes) < min_sample:
                    continue
                entropy = _shannon_entropy_bytes(sample_bytes[:4096])
            if entropy and entropy >= entropy_threshold:
                out.append(
                    {
                        "factor": "file_write_entropy_high",
                        "host": host,
                        "path": path,
                        "entropy": round(float(entropy), 3),
                        "score": 0.85,
                        "reason": f"Shannon entropy {entropy:.2f} on recent write",
                        "mitre": ["T1486"],
                        "stride": ["tampering"],
                    }
                )
        except Exception:
            continue
    if out:
        _metric_inc(ransomware_signal_total, {'factor': 'file_write_entropy_high'}, len(out))
    return out


def detect_shadowcopy_commands(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    proc_events = _runtime_events(runtime, "process_events")
    keywords = ("delete shadows", "shadowcopy delete", "win32_shadowcopy", "bcdedit /set {default} recoveryenabled no")
    for event in proc_events:
        try:
            cmd = (event.get("command_line") or event.get("cmdline") or event.get("command") or "").lower()
            exe = (event.get("exe") or event.get("image") or "").lower()
            host = event.get("host")
            if not cmd and not exe:
                continue
            if "vssadmin" in cmd and "delete" in cmd:
                hit = True
            elif "wmic" in cmd and "shadowcopy" in cmd and "delete" in cmd:
                hit = True
            elif "powershell" in exe and any(k in cmd for k in keywords):
                hit = True
            else:
                hit = False
            if hit:
                out.append(
                    {
                        "factor": "vss_shadow_copy_delete",
                        "host": host,
                        "process": event.get("exe") or event.get("image"),
                        "command": event.get("command_line") or event.get("cmdline"),
                        "score": 0.92,
                        "reason": "Shadow copy deletion command observed",
                        "mitre": ["T1490"],
                        "stride": ["tampering", "denial"],
                    }
                )
        except Exception:
            continue
    if out:
        _metric_inc(ransomware_signal_total, {'factor': 'vss_shadow_copy_delete'}, len(out))
    return out


def detect_vss_service_tamper(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    registry_events = _runtime_events(runtime, "registry_events")
    service_events = _runtime_events(runtime, "service_events")
    vss_keys = ("system\\currentcontrolset\\services\\vss", "services\\vss")
    for event in registry_events:
        try:
            key = (event.get("key") or event.get("path") or "").lower()
            if any(k in key for k in vss_keys):
                action = event.get("action") or event.get("type") or "write"
                out.append(
                    {
                        "factor": "vss_service_tamper",
                        "host": event.get("host"),
                        "key": event.get("key") or event.get("path"),
                        "action": action,
                        "score": 0.78,
                        "reason": "VSS service registry modified",
                        "mitre": ["T1490"],
                    }
                )
        except Exception:
            continue
    for event in service_events:
        try:
            service = (event.get("service") or event.get("service_name") or "").lower()
            state = (event.get("state") or event.get("action") or "").lower()
            if "vss" in service and any(tag in state for tag in ("disable", "stop", "delete")):
                out.append(
                    {
                        "factor": "vss_service_tamper",
                        "host": event.get("host"),
                        "service": event.get("service") or event.get("service_name"),
                        "action": state,
                        "score": 0.82,
                        "reason": "VSS service stop/disable detected",
                        "mitre": ["T1490"],
                    }
                )
        except Exception:
            continue
    if out:
        _metric_inc(ransomware_signal_total, {'factor': 'vss_service_tamper'}, len(out))
    return out


def detect_file_write_rate_spike(runtime, window_seconds: int = 30, min_events: int = 200, multiplier: float = 4.0) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    file_events = _runtime_events(runtime, "file_events")

    def _to_epoch(value: Any) -> float:
        if value is None:
            return 0.0
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            except Exception:
                return 0.0
        return 0.0

    counts: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for event in file_events:
        try:
            host = event.get("host") or "unknown"
            ts = _to_epoch(event.get("timestamp") or event.get("time") or event.get("ts"))
            if not ts:
                continue
            bucket = int(ts // window_seconds)
            counts[host][bucket] += 1
        except Exception:
            continue
    for host, series in counts.items():
        if not series:
            continue
        bucket_counts = list(series.values())
        avg = sum(bucket_counts) / max(1, len(bucket_counts))
        peak_bucket, peak = max(series.items(), key=lambda item: item[1])
        if peak >= min_events and peak >= avg * multiplier:
            out.append(
                {
                    "factor": "file_write_burst",
                    "host": host,
                    "peak_rate": peak,
                    "avg_rate": round(avg, 2),
                    "bucket": peak_bucket * window_seconds,
                    "score": 0.88,
                    "reason": f"File write burst {peak} vs avg {avg:.1f}",
                    "mitre": ["T1486"],
                }
                )
    if out:
        _metric_inc(ransomware_signal_total, {'factor': 'file_write_burst'}, len(out))
    return out


def orchestrate_ransomware_signals(runtime, signals: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    if signals is None:
        signals = []
        detectors = [
            detect_file_encryption_wave,
            detect_file_entropy_writes,
            detect_shadowcopy_commands,
            detect_vss_service_tamper,
            detect_file_write_rate_spike,
            detect_unsigned_network_launch,
        ]
        for detector in detectors:
            try:
                signals.extend(detector(runtime) or [])
            except Exception:
                continue
    strong_factors = {"file_encryption_wave", "file_write_entropy_high", "vss_shadow_copy_delete", "file_write_burst"}
    strong_hits = [s for s in signals if s.get("factor") in strong_factors]
    if len(strong_hits) >= 2 and len(signals) >= 3:
        hosts = {s.get("host") for s in signals if s.get("host")}
        result = {
            "factor": "ransomware_auto_incident",
            "host_count": len(hosts),
            "signals": signals,
            "score": 0.95 if len(strong_hits) >= 3 else 0.9,
            "reason": f"Ransomware pattern fused from {len(signals)} signals",
            "verdict": "malicious",
            "mitre": ["T1486", "T1490"],
        }
        _metric_inc(
            ransomware_auto_incident_total,
            {'verdict': str(result.get('verdict') or 'malicious')}
        )
        return result
    return {}


def summarize_ransomware_context(runtime, signals: Optional[Sequence[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Aggregate ransomware-related metrics for UI + report surfaces."""
    signals = list(signals or [])
    metrics: Dict[str, Any] = {}
    entropies = []
    bursts = []
    hosts: set[str] = set()
    for sig in signals:
        try:
            h = sig.get('host')
            if h:
                hosts.add(str(h))
        except Exception:
            continue
        if sig.get('factor') == 'file_write_entropy_high':
            try:
                entropies.append(float(sig.get('entropy') or 0.0))
            except Exception:
                continue
        if sig.get('factor') == 'file_write_burst':
            try:
                bursts.append(float(sig.get('peak_rate') or 0.0))
            except Exception:
                continue
    if entropies:
        metrics['entropy_score'] = max(entropies)
        metrics['entropy_sample_count'] = len(entropies)
    if bursts:
        metrics['file_mod_rate'] = max(bursts)
    vss_tamper = sum(
        1
        for sig in signals
        if sig.get('factor') in {'vss_service_tamper', 'vss_shadow_copy_delete'}
    )
    if vss_tamper:
        metrics['vss_tamper_count'] = vss_tamper
    metrics['ransomware_signal_count'] = len(signals)
    strong = sum(
        1
        for sig in signals
        if sig.get('factor') in {'file_encryption_wave', 'file_write_entropy_high', 'file_write_burst'}
    )
    composite = 0.45 + 0.1 * strong + 0.05 * len(signals)
    if vss_tamper:
        composite += 0.08
    metrics['ransomware_confidence'] = round(min(0.99, composite), 3)
    metrics['related_hosts'] = sorted(h for h in hosts if h)
    # Framework mappings (static per blueprint)
    metrics['maestro'] = ['Goal 2.4 - Establish Persistence', 'Goal 3.3 - Execute Impact']
    metrics['pasta'] = ['Stage 4', 'Stage 5', 'Stage 6']
    metrics['stride'] = sorted(
        {axis for sig in signals for axis in (sig.get('stride') or [])}
    ) or ['Tampering', 'InformationDisclosure']
    metrics['mitre'] = sorted(
        {tech for sig in signals for tech in (sig.get('mitre') or [])}
    ) or ['T1486', 'T1490', 'T1059']
    metrics['cvss'] = {'base_score': 9.8, 'vector': 'CVSS:3.1/AV=N/AC=L/PR=N/UI=N/S=U/C=H/I=H/A=H'}
    missing_logs = []
    def _event_count(bucket: str) -> int:
        try:
            return len(_runtime_events(runtime, bucket))
        except Exception:
            return 0
    if _event_count('file_events') == 0:
        missing_logs.append({'source': 'windows_security', 'reason': 'No file events observed for entropy scoring'})
    if _event_count('process_events') == 0:
        missing_logs.append({'source': 'sysmon_process', 'reason': 'Process telemetry missing (vssadmin/wmic detection)'})
    if _event_count('registry_events') == 0:
        missing_logs.append({'source': 'registry', 'reason': 'Registry/VSS keys not ingesting'})
    if _event_count('service_events') == 0:
        missing_logs.append({'source': 'service_control', 'reason': 'Service control events absent (VSS tamper)'})
    if _event_count('network_events') == 0:
        missing_logs.append({'source': 'network', 'reason': 'No outbound network telemetry for unsigned binaries'})
    metrics['missing_logs'] = missing_logs
    for entry in missing_logs:
        src = entry.get('source') or 'unknown'
        _metric_inc(ransomware_missing_log_requests_total, {'source': str(src)})
    return metrics


def generate_synthetic_ransomware_runtime(host: str = "host-1", file_count: int = 150, include_entropy: bool = True, include_vss: bool = True) -> Dict[str, Any]:
    now = datetime.utcnow().timestamp()
    file_events: List[Dict[str, Any]] = []
    base_sample = bytearray([i % 256 for i in range(4096)])
    for idx in range(file_count):
        entry = {
            "host": host,
            "path": f"C:\\share\\doc_{idx}.locked",
            "timestamp": now + (idx * 0.2),
        }
        if include_entropy and idx == 0:
            entry["content_sample"] = base64.b64encode(base_sample).decode("ascii")
        file_events.append(entry)
    process_events: List[Dict[str, Any]] = []
    if include_vss:
        process_events.append(
            {
                "host": host,
                "exe": "C:\\Windows\\System32\\vssadmin.exe",
                "command_line": "vssadmin delete shadows /all /quiet",
            }
        )
    return {
        "file_events": file_events,
        "process_events": process_events,
        "registry_events": [
            {
                "host": host,
                "key": r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\VSS",
                "action": "SetValue",
            }
        ],
    }
