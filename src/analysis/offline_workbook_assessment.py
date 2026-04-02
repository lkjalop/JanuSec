from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlparse

from src.core.detect.isolation_forest import IsolationForestDetector
from src.ml.tfidf_profile import TfidfProfile


_LATERAL_PORTS = {135, 139, 445, 3389, 5985, 5986}
_SUSPICIOUS_PATH_MARKERS = (
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\public\\",
    "\\downloads\\",
)
_SUSPICIOUS_PROCESS_MARKERS = (
    "evil",
    "wmiexec",
    "psexec",
    "rundll32",
    "powershell",
    "cmd.exe",
    "regsvr32",
)
_PHISHING_MARKERS = (
    "invoice",
    "enable macros",
    "credentials",
    "login",
    "update required",
    "urgent",
    "password",
)
_IOC_PATTERN = re.compile(r"(https?://[^\s]+|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)
_TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_.:-]{3,}")
_BENIGN_PATH_PATTERNS: dict[str, tuple[str, ...]] = {
    "windows_update": (
        "\\windows\\softwaredistribution\\",
        "\\softwaredistribution\\download\\",
        "\\windows\\winsxs\\",
        "\\windows\\servicing\\",
    ),
    "defender_signature_update": (
        "\\microsoft\\windows defender\\definition updates\\",
        "\\microsoft\\windows defender advanced threat protection\\",
        "\\programdata\\microsoft\\windows defender\\",
    ),
    "defender_temp": (
        "\\programdata\\microsoft\\windows defender\\platform\\",
        "\\microsoft\\windows defender\\scans\\history\\",
    ),
}
_BENIGN_PROCESS_ALLOWLIST = {
    "mpam-d.exe",
    "mpas-fe.exe",
    "wuauclt.exe",
    "usoclient.exe",
    "tiworker.exe",
    "trustedinstaller.exe",
    "msiexec.exe",
    "dism.exe",
    "sconfig.exe",
    "servermanager.exe",
    "mmc.exe",
    "compattelrunner.exe",
    "veeamagent.exe",
    "ccmexec.exe",
}
_BENIGN_ADMIN_PATH_MARKERS = (
    "\\windows\\ccm\\",
    "\\program files\\microsoft monitoring agent\\",
    "\\program files\\microsoft defender\\",
    "\\program files\\windows defender\\",
)
_FACTOR_WEIGHTS = {
    "network:suspicious_external_ip": 0.12,
    "network:lateral_movement_port": 0.14,
    "endpoint:suspicious_process_path": 0.11,
    "endpoint:repeated_hash": 0.07,
    "identity:cloud_signin_external": 0.06,
    "identity:cloud_signin_risk": 0.12,
    "email:phishing_lure": 0.14,
    "cloud:privilege_change": 0.14,
    "cloud:access_key_creation": 0.13,
    "cloud:defender_high_severity": 0.16,
    "cloud:guardduty_high_severity": 0.16,
    "cloud:securityhub_high": 0.13,
    "cloud:resource_admin_write": 0.12,
    "cloud:config_drift": 0.1,
    "identity:conditional_access_failure": 0.11,
    "identity:identity_protection_risk": 0.14,
    "network:vpc_external_flow": 0.08,
    "corr:cross_sheet_indicator_pivot": 0.16,
    "network:adaptive_ewma_regular_cadence": 0.08,
    "context:tfidf_rare_tokens": 0.06,
    "ml:isolation_forest_outlier": 0.09,
    "ml:dbscan_sparse_cluster": 0.07,
    "stats:mad_volume_outlier": 0.08,
    "sequence:kill_chain_progression": 0.1,
    "graph:anomalous_path": 0.11,
    "graph:anomalous_edge_chain": 0.13,
}
_FACTOR_PRIORITY = {
    "email": 7,
    "cloud": 7,
    "identity": 6,
    "network": 6,
    "endpoint": 6,
    "corr": 5,
    "sequence": 5,
    "graph": 3,
    "ml": 2,
    "stats": 2,
    "context": 1,
}
_SEMANTIC_FACTOR_CATEGORIES = {"email", "cloud", "identity", "network", "endpoint", "corr", "sequence"}
_SUPPORTING_FACTOR_CATEGORIES = {"graph", "ml", "stats", "context"}
_MICROSOFT_SIGNERS = {
    "microsoft corporation",
    "microsoft windows",
    "microsoft",
}
_EXPECTED_PARENT_PROCESSES = {
    "services.exe",
    "svchost.exe",
    "trustedinstaller.exe",
    "msiexec.exe",
    "taskeng.exe",
    "taskhostw.exe",
    "wuauclt.exe",
    "usoclient.exe",
}
_APPROVED_ADMIN_HOST_MARKERS = ("jump", "admin", "mgmt", "it-", "sccm", "wsus", "backup", "veeam")
_KNOWN_UPDATE_DEST_MARKERS = (
    "windowsupdate.microsoft.com",
    "update.microsoft.com",
    "delivery.mp.microsoft.com",
    "definitionupdates.microsoft.com",
    "download.windowsupdate.com",
)
_MAINTENANCE_HOURS = set(range(0, 7))
_DEFAULT_OFFLINE_BASELINE_DIR = "data/offline_baselines"
_DEFAULT_OFFLINE_CALIBRATION_PATH = "data/offline_baselines/calibration_labels.json"
_DEFAULT_BASELINE_MAX_AGE_DAYS = 30.0
_DEFAULT_BASELINE_HALF_LIFE_DAYS = 14.0


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except Exception:
        return None


def _coerce_timestamp(value: Any) -> float | None:
    numeric = _as_float(value)
    if numeric is not None:
        return numeric
    if value in (None, ""):
        return None
    text = _text(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _lower(value: Any) -> str:
    return _text(value).strip().lower()


def _safe_ip(value: Any) -> str | None:
    raw = _lower(value)
    if not raw:
        return None
    try:
        ipaddress.ip_address(raw)
        return raw
    except Exception:
        return None


def _is_external_ip(value: Any) -> bool:
    raw = _safe_ip(value)
    if not raw:
        return False
    try:
        parsed = ipaddress.ip_address(raw)
        return not (parsed.is_private or parsed.is_loopback or parsed.is_multicast or parsed.is_link_local)
    except Exception:
        return False


def _extract_urls_and_emails(row: Dict[str, Any]) -> tuple[list[str], list[str]]:
    text = " ".join(_text(v) for v in row.values() if isinstance(v, (str, int, float)))
    urls: list[str] = []
    emails: list[str] = []
    for match in _IOC_PATTERN.findall(text):
        if match.lower().startswith("http"):
            urls.append(match)
        elif "@" in match:
            emails.append(match.lower())
    return urls, emails


def _extract_domains(urls: Iterable[str]) -> list[str]:
    domains: list[str] = []
    for url in urls:
        try:
            host = urlparse(url).hostname
        except Exception:
            host = None
        if host:
            domains.append(host.lower())
    return domains


def _tokenize_row(row: Dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    for value in row.values():
        if isinstance(value, (str, int, float)):
            tokens.extend(t.lower() for t in _TOKEN_PATTERN.findall(str(value)))
    return tokens[:256]


def _tokenize_feature_family(row: Dict[str, Any], family: str) -> list[str]:
    fields = {
        "path": ("process_path", "path", "image_path"),
        "process": ("process", "process_name", "parent_process"),
        "command": ("command_line", "cmdline", "command"),
        "email": ("subject", "body", "from", "to"),
        "cloud_action": ("event_type", "action", "operation", "app", "resource"),
    }.get(family, ())
    values = [_text(row.get(field)) for field in fields if row.get(field) is not None]
    tokens: list[str] = []
    for value in values:
        tokens.extend(t.lower() for t in _TOKEN_PATTERN.findall(value))
    return tokens[:256]


def _domain_family(row: Dict[str, Any]) -> str:
    hinted = _lower(row.get("domain_hint"))
    if hinted:
        return hinted
    sheet = _sheet_name(row).lower()
    if "email" in sheet:
        return "email"
    if sheet in {"network", "c2"} or row.get("dst_ip") or row.get("src_ip"):
        return "network"
    if sheet in {"endpoint", "edr"} or row.get("process") or row.get("process_name"):
        return "endpoint"
    if any(row.get(key) for key in ("provider", "cloud", "account_id", "subscription_id")):
        return "cloud"
    if any(row.get(key) for key in ("user", "username", "tenant_id", "app", "resource", "service_principal")):
        return "identity"
    return "other"


def _mad_outlier_score(values: list[float]) -> list[float]:
    if len(values) < 3:
        return [0.0 for _ in values]
    sorted_vals = sorted(values)
    median = sorted_vals[len(sorted_vals) // 2]
    deviations = [abs(v - median) for v in values]
    sorted_dev = sorted(deviations)
    mad = sorted_dev[len(sorted_dev) // 2]
    if mad <= 0:
        return [0.0 for _ in values]
    return [0.6745 * abs(v - median) / mad for v in values]


def _sequence_progression_score(domains: list[str]) -> float:
    if len(domains) < 2:
        return 0.0
    stages = {"email": 1, "identity": 2, "endpoint": 3, "network": 4}
    seq = [stages.get(domain, 0) for domain in domains if domain in stages]
    if len(seq) < 2:
        return 0.0
    progression = sum(1 for idx in range(1, len(seq)) if seq[idx] >= seq[idx - 1] and seq[idx] != 0)
    return progression / max(len(seq) - 1, 1)


def _row_hour(ts: float | None) -> int | None:
    if ts is None:
        return None
    try:
        return int((ts % 86400) // 3600)
    except Exception:
        return None


def _baseline_path(tenant_id: str) -> Path:
    base_dir = Path(os.getenv("OFFLINE_BASELINE_DIR", _DEFAULT_OFFLINE_BASELINE_DIR))
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", tenant_id or "default")
    return base_dir / f"{safe}.json"


def _aged_count(value: Any, now_ts: float, *, default_ts: float | None = None) -> int:
    half_life_days = float(os.getenv("OFFLINE_BASELINE_HALF_LIFE_DAYS", str(_DEFAULT_BASELINE_HALF_LIFE_DAYS)) or _DEFAULT_BASELINE_HALF_LIFE_DAYS)
    half_life_days = max(1.0, half_life_days)
    if isinstance(value, dict):
        count = int(value.get("count") or 0)
        last_seen_ts = float(_as_float(value.get("last_seen_ts")) or default_ts or now_ts)
    else:
        count = int(_as_int(value) or 0)
        last_seen_ts = float(default_ts or now_ts)
    age_days = max(0.0, (now_ts - last_seen_ts) / 86400.0)
    decay = math.exp(-math.log(2.0) * (age_days / half_life_days))
    return max(0, int(round(count * decay)))


def _age_persisted_baseline(payload: dict[str, Any], now_ts: float) -> dict[str, Any]:
    max_age_days = float(os.getenv("OFFLINE_BASELINE_MAX_AGE_DAYS", str(_DEFAULT_BASELINE_MAX_AGE_DAYS)) or _DEFAULT_BASELINE_MAX_AGE_DAYS)
    max_age_seconds = max_age_days * 86400.0
    updated_ts = float(_as_float(payload.get("updated_ts")) or now_ts)
    aged = dict(payload)
    entity_pairs = {}
    for key, timestamps in (payload.get("entity_pairs") or {}).items():
        if not isinstance(timestamps, list):
            continue
        recent = [float(ts) for ts in timestamps if _as_float(ts) is not None and (now_ts - float(ts)) <= max_age_seconds]
        if recent:
            entity_pairs[key] = recent[-80:]
    aged["entity_pairs"] = entity_pairs
    graph_path_meta = payload.get("graph_path_meta") or {}
    graph_edge_meta = payload.get("graph_edge_meta") or {}
    provider_action_meta = payload.get("provider_action_meta") or {}
    if not graph_path_meta:
        graph_path_meta = {k: {"count": int(v), "last_seen_ts": updated_ts} for k, v in (payload.get("graph_paths") or {}).items()}
    if not graph_edge_meta:
        graph_edge_meta = {k: {"count": int(v), "last_seen_ts": updated_ts} for k, v in (payload.get("graph_edges") or {}).items()}
    if not provider_action_meta:
        provider_action_meta = {k: {"count": int(v), "last_seen_ts": updated_ts} for k, v in (payload.get("provider_action_frequency") or {}).items()}
    aged["graph_path_meta"] = {
        k: {"count": _aged_count(v, now_ts, default_ts=updated_ts), "last_seen_ts": float((v or {}).get("last_seen_ts") or updated_ts)}
        for k, v in graph_path_meta.items()
        if _aged_count(v, now_ts, default_ts=updated_ts) > 0
    }
    aged["graph_edge_meta"] = {
        k: {"count": _aged_count(v, now_ts, default_ts=updated_ts), "last_seen_ts": float((v or {}).get("last_seen_ts") or updated_ts)}
        for k, v in graph_edge_meta.items()
        if _aged_count(v, now_ts, default_ts=updated_ts) > 0
    }
    aged["provider_action_meta"] = {
        k: {"count": _aged_count(v, now_ts, default_ts=updated_ts), "last_seen_ts": float((v or {}).get("last_seen_ts") or updated_ts)}
        for k, v in provider_action_meta.items()
        if _aged_count(v, now_ts, default_ts=updated_ts) > 0
    }
    aged["graph_paths"] = {k: v["count"] for k, v in aged["graph_path_meta"].items()}
    aged["graph_edges"] = {k: v["count"] for k, v in aged["graph_edge_meta"].items()}
    aged["provider_action_frequency"] = {k: v["count"] for k, v in aged["provider_action_meta"].items()}
    return aged


def _load_persisted_baseline(tenant_id: str) -> dict[str, Any]:
    path = _baseline_path(tenant_id)
    try:
        if path.exists():
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                return _age_persisted_baseline(payload, time.time())
    except Exception:
        pass
    return {
        "profiles": {},
        "family_profiles": {},
        "entity_pairs": {},
        "graph_paths": {},
        "graph_path_meta": {},
        "graph_edges": {},
        "graph_edge_meta": {},
        "provider_action_frequency": {},
        "provider_action_meta": {},
        "seen_suppressors": {},
        "updated_ts": 0.0,
    }


def _save_persisted_baseline(tenant_id: str, payload: dict[str, Any]) -> None:
    path = _baseline_path(tenant_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    except Exception:
        pass


def _load_calibration_labels() -> dict[str, dict[str, float]]:
    calibration_path = Path(os.getenv("OFFLINE_CALIBRATION_PATH", _DEFAULT_OFFLINE_CALIBRATION_PATH))
    try:
        if calibration_path.exists():
            data = json.loads(calibration_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {str(k): v for k, v in data.items() if isinstance(v, dict)}
    except Exception:
        pass
    return {}


def _density_dbscan_scores(vectors: list[list[float]], eps: float = 0.9, min_samples: int = 2) -> list[float]:
    if len(vectors) < min_samples:
        return [0.0 for _ in vectors]

    def _distance(a: list[float], b: list[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    neighbor_counts: list[int] = []
    for idx, vec in enumerate(vectors):
        count = 0
        for jdx, other in enumerate(vectors):
            if idx == jdx:
                continue
            if _distance(vec, other) <= eps:
                count += 1
        neighbor_counts.append(count)
    scores: list[float] = []
    for count in neighbor_counts:
        if count >= min_samples:
            scores.append(0.0)
        else:
            scores.append(1.0 - (count / max(min_samples, 1)))
    return scores


def _precision_adjustment(stats: dict[str, Any]) -> float:
    tp = float(stats.get("tp", 0.0))
    fp = float(stats.get("fp", 0.0))
    total = tp + fp
    if total <= 0:
        return 0.0
    precision = tp / total
    return (precision - 0.5) * 0.18


def _calibration_adjustment(factors: list[str], calibrations: dict[str, dict[str, Any]], provider: str = "") -> float:
    adjustment = 0.0
    provider_stats = calibrations.get("providers") or {}
    factor_stats = calibrations.get("factors") or calibrations
    for factor in factors:
        stats = factor_stats.get(factor) or {}
        if isinstance(stats, dict):
            adjustment += _precision_adjustment(stats)
        if provider:
            pstats = (((provider_stats.get(provider) or {}) if isinstance(provider_stats, dict) else {}).get(factor) or {})
            if isinstance(pstats, dict):
                adjustment += _precision_adjustment(pstats) * 0.7
    return max(-0.22, min(0.22, adjustment))


def _rank_factor_entries(ranked_factors: list[tuple[str, int]], total_rows: int) -> list[dict[str, Any]]:
    return [
        {
            "factor_name": factor,
            "contribution_score": round(count / max(total_rows, 1), 3),
            "evidence_count": count,
            "factor_category": ("stats" if factor == "network:adaptive_ewma_regular_cadence" else factor.split(":", 1)[0]),
        }
        for factor, count in ranked_factors
    ]


def _split_factor_views(
    ranked_factors: list[tuple[str, int]],
    total_rows: int,
    graph_anomaly_score: float,
    corroborating_domains: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    ranked_entries = _rank_factor_entries(ranked_factors, total_rows)
    semantic_entries = [entry for entry in ranked_entries if entry["factor_category"] in _SEMANTIC_FACTOR_CATEGORIES]
    supporting_entries = [entry for entry in ranked_entries if entry["factor_category"] in _SUPPORTING_FACTOR_CATEGORIES]
    if graph_anomaly_score >= 0.5:
        graph_entry = {
            "factor_name": "graph:anomalous_edge_chain" if graph_anomaly_score >= 0.6 else "graph:anomalous_path",
            "contribution_score": round(graph_anomaly_score, 3),
            "evidence_count": max(1, len(corroborating_domains)),
            "factor_category": "graph",
        }
        supporting_entries = [graph_entry] + [entry for entry in supporting_entries if entry["factor_name"] != graph_entry["factor_name"]]
    top_semantic = semantic_entries[:6]
    top_supporting = supporting_entries[:4]
    top_contributing = (top_semantic + top_supporting)[:8]
    if not top_contributing:
        top_contributing = ranked_entries[:8]
    return top_contributing, top_semantic, top_supporting


def _adaptive_ewma_alpha(values: list[float], base: float = 0.6, min_alpha: float = 0.3, max_alpha: float = 0.85, scale: float = 0.4) -> float:
    if len(values) < 2:
        return base
    mean = sum(values) / len(values)
    if mean <= 0:
        return base
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    volatility = variance / max(mean, 1.0)
    alpha = base / (1.0 + (volatility * scale))
    return max(min_alpha, min(max_alpha, alpha))


def _ewma_regular_intervals(timestamps: list[float]) -> tuple[bool, float]:
    if len(timestamps) < 3:
        return False, 0.0
    timestamps = sorted(timestamps)
    intervals = [max(1.0, timestamps[i] - timestamps[i - 1]) for i in range(1, len(timestamps))]
    alpha = _adaptive_ewma_alpha(intervals)
    ewma = intervals[0]
    residuals: list[float] = []
    for value in intervals[1:]:
        ewma = ewma + alpha * (value - ewma)
        residuals.append(abs(value - ewma))
    if not residuals:
        return False, 0.0
    mean_residual = sum(residuals) / len(residuals)
    mean_interval = sum(intervals) / len(intervals)
    regularity = 1.0 - min(1.0, mean_residual / max(mean_interval, 1.0))
    return regularity >= 0.75, regularity


def _severity_from_confidence(confidence: float) -> str:
    if confidence >= 0.85:
        return "CRITICAL"
    if confidence >= 0.7:
        return "HIGH"
    if confidence >= 0.5:
        return "MEDIUM"
    return "LOW"


def _verdict_from_confidence(confidence: float) -> str:
    if confidence >= 0.82:
        return "THREAT"
    if confidence >= 0.55:
        return "SUSPICIOUS"
    return "REVIEW"


def _row_entity(row: Dict[str, Any]) -> str:
    host = row.get("host") or row.get("hostname")
    if host:
        return f"host:{host}"
    user = row.get("user") or row.get("username") or row.get("userPrincipalName") or row.get("actor") or row.get("caller")
    if user:
        return f"user:{user}"
    service_principal = row.get("service_principal") or row.get("servicePrincipalName") or row.get("appId")
    if service_principal:
        return f"sp:{service_principal}"
    resource = row.get("resource") or row.get("resourceDisplayName") or row.get("target_resource")
    if resource:
        return f"cloud:{resource}"
    src_ip = row.get("src_ip") or row.get("ip")
    if src_ip:
        return f"ip:{src_ip}"
    return f"row:{row.get('row_index', 'unknown')}"


def _sheet_name(row: Dict[str, Any]) -> str:
    return str(row.get("sheet") or row.get("sheet_name") or "unknown")


def _base_summary(row: Dict[str, Any]) -> str:
    return (
        row.get("title")
        or row.get("event_type")
        or row.get("action")
        or row.get("process")
        or row.get("process_name")
        or row.get("subject")
        or row.get("path")
        or row.get("resource")
        or row.get("dst_ip")
        or "offline-row"
    )


def _row_summary(row: Dict[str, Any], factors: list[str], evidence: list[str], confidence: float) -> str:
    subject = _base_summary(row)
    factor_text = ", ".join(factors[:3]) if factors else "heuristic review"
    evidence_text = "; ".join(evidence[:2]) if evidence else "limited supporting evidence"
    return f"{subject}: {factor_text}. Evidence: {evidence_text}. Confidence {confidence:.2f}."


def _benign_context_tags(path: str, process: str, row: Dict[str, Any]) -> list[str]:
    tags: list[str] = []
    for tag, patterns in _BENIGN_PATH_PATTERNS.items():
        if any(pattern in path for pattern in patterns):
            tags.append(tag)
    process_name = process.split("\\")[-1]
    if process_name in _BENIGN_PROCESS_ALLOWLIST:
        tags.append("benign_admin_tooling")
    cmdline = _lower(row.get("command_line") or row.get("cmdline"))
    host = _lower(row.get("host") or row.get("hostname"))
    if any(marker in path for marker in _BENIGN_ADMIN_PATH_MARKERS) or any(marker in cmdline for marker in ("windows defender", "softwaredistribution", "microsoft monitoring agent")):
        tags.append("known_admin_maintenance")
    if process.split("\\")[-1] == "veeamagent.exe" or " backup" in f" {cmdline}" or "veeam" in path or "backup" in host:
        tags.append("known_backup_activity")
    if bool(row.get("approved_change")) or _lower(row.get("change_ticket")):
        tags.append("approved_admin_change")
    deduped: list[str] = []
    for tag in tags:
        if tag not in deduped:
            deduped.append(tag)
    return deduped


def _confidence_from_factors(factors: list[str], benign_tags: list[str]) -> float:
    confidence = 0.18
    categories = set()
    for factor in factors:
        confidence += _FACTOR_WEIGHTS.get(factor, 0.04)
        categories.add(factor.split(":", 1)[0])
    if len(categories) >= 3:
        confidence += 0.05
    elif len(categories) >= 2:
        confidence += 0.03
    if benign_tags:
        low_signal = not any(f.startswith("email:") or f.startswith("corr:") or f == "network:lateral_movement_port" for f in factors)
        confidence -= 0.18 if low_signal else 0.08
    return max(0.12, min(0.96, confidence))


def _suppressor_tags(row: Dict[str, Any], benign_tags: list[str], url_domains: list[str], dst_ip: str | None, ts: float | None) -> list[str]:
    suppressors: list[str] = []
    signer = _lower(row.get("signed_vendor") or row.get("signer") or row.get("publisher"))
    if signer and any(vendor in signer for vendor in _MICROSOFT_SIGNERS):
        suppressors.append("signed_microsoft_binary")
    parent = _lower(row.get("parent_process") or row.get("parent_image") or row.get("parent"))
    if parent and parent.split("\\")[-1] in _EXPECTED_PARENT_PROCESSES:
        suppressors.append("expected_parent_process")
    host = _lower(row.get("host") or row.get("hostname"))
    if host and any(marker in host for marker in _APPROVED_ADMIN_HOST_MARKERS):
        suppressors.append("approved_admin_host")
    if any(domain in _KNOWN_UPDATE_DEST_MARKERS for domain in url_domains):
        suppressors.append("known_update_cdn")
    if dst_ip and dst_ip.startswith("13.107."):
        suppressors.append("known_update_cdn")
    if benign_tags:
        suppressors.append("allowlisted_behavior")
    if bool(row.get("approved_change")) or _lower(row.get("change_ticket")):
        suppressors.append("successful_prior_allowlisted_behavior")
    hour = _row_hour(ts)
    if hour is not None and hour in _MAINTENANCE_HOURS and benign_tags:
        suppressors.append("expected_maintenance_window")
    deduped: list[str] = []
    for tag in suppressors:
        if tag not in deduped:
            deduped.append(tag)
    return deduped


def _confidence_with_context(
    factors: list[str],
    benign_tags: list[str],
    suppressors: list[str],
    corroboration_count: int,
    domain_diversity: int,
    recency_score: float,
    asset_criticality: float,
    sensitivity_score: float,
) -> float:
    confidence = _confidence_from_factors(factors, benign_tags)
    low_signal_only = all(
        factor.startswith(("context:", "ml:", "stats:"))
        for factor in factors
    ) if factors else True
    confidence += min(0.08, corroboration_count * 0.02)
    confidence += min(0.06, max(domain_diversity - 1, 0) * 0.02)
    confidence += recency_score * 0.03
    confidence += asset_criticality * 0.05
    confidence += sensitivity_score * 0.04
    confidence -= min(0.22, len(suppressors) * 0.05)
    if suppressors and low_signal_only:
        confidence -= 0.16
    if "successful_prior_allowlisted_behavior" in suppressors:
        confidence -= 0.08
    return max(0.08, min(0.97, confidence))


def _estimate_expected_loss(severity: str, affected_users: int, suspicious_rows: int, critical_assets: int) -> int:
    base = {
        "LOW": 2500,
        "MEDIUM": 12000,
        "HIGH": 35000,
        "CRITICAL": 90000,
    }.get(severity, 2500)
    user_component = min(25000, max(affected_users, 1) * 3500)
    row_component = min(15000, suspicious_rows * 750)
    asset_component = min(40000, critical_assets * 12000)
    return int(base + user_component + row_component + asset_component)


def _collect_indicator_maps(rows: list[Dict[str, Any]]) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, set[str]]]:
    ip_to_sheets: dict[str, set[str]] = defaultdict(set)
    domain_to_sheets: dict[str, set[str]] = defaultdict(set)
    hash_to_sheets: dict[str, set[str]] = defaultdict(set)
    user_to_sheets: dict[str, set[str]] = defaultdict(set)
    resource_to_sheets: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        sheet = _sheet_name(row)
        for key in ("src_ip", "dst_ip", "ip"):
            ip = _safe_ip(row.get(key))
            if ip:
                ip_to_sheets[ip].add(sheet)
        for domain in [row.get("domain"), row.get("sni")]:
            d = _lower(domain)
            if d:
                domain_to_sheets[d].add(sheet)
        urls, _ = _extract_urls_and_emails(row)
        for domain in _extract_domains(urls):
            domain_to_sheets[domain].add(sheet)
        for key in ("sha256", "file_hash"):
            h = _lower(row.get(key))
            if h:
                hash_to_sheets[h].add(sheet)
        user = _lower(row.get("user") or row.get("username") or row.get("userPrincipalName") or row.get("actor") or row.get("caller"))
        if user:
            user_to_sheets[user].add(sheet)
        resource = _lower(row.get("resource") or row.get("resourceDisplayName") or row.get("target_resource"))
        if resource:
            resource_to_sheets[resource].add(sheet)
    return ip_to_sheets, domain_to_sheets, hash_to_sheets, user_to_sheets, resource_to_sheets


def _classify_cloud_export_row(row: Dict[str, Any]) -> str | None:
    if row.get("policyName") and row.get("result") is not None:
        return "azure_conditional_access_export"
    if row.get("riskType") and row.get("riskLevel") and row.get("userPrincipalName"):
        return "azure_identity_protection_export"
    if row.get("createdDateTime") and row.get("userPrincipalName") and row.get("appDisplayName"):
        return "azure_entra_signin_export"
    if row.get("activityDisplayName") and row.get("initiatedBy"):
        return "azure_entra_audit_export"
    if row.get("incidentId") and row.get("alerts") is not None:
        return "azure_defender_incident_export"
    if row.get("operationName") and row.get("caller"):
        return "azure_activity_log_export"
    if row.get("srcIp") and row.get("destIp"):
        return "azure_nsg_flow_export"
    if row.get("eventName") and row.get("eventSource"):
        return "aws_cloudtrail_export"
    if row.get("resourceType") and row.get("configurationItemStatus"):
        return "aws_config_export"
    if row.get("srcaddr") and row.get("dstaddr"):
        return "aws_vpc_flow_export"
    if row.get("type") and row.get("severity") is not None and row.get("accountId"):
        return "aws_guardduty_export"
    if row.get("Id") and row.get("Severity") and row.get("Resources"):
        return "aws_securityhub_export"
    return None


def _normalize_cloud_export_row(row: Dict[str, Any], tenant_id: str) -> Dict[str, Any]:
    kind = _classify_cloud_export_row(row)
    if not kind:
        return dict(row)
    normalized = dict(row)
    normalized.setdefault("tenant_id", tenant_id)
    normalized["cloud_export_kind"] = kind

    if kind == "azure_entra_signin_export":
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AzureSignIn",
                "provider": "azure_entra",
                "event_type": "signin",
                "action": normalized.get("appDisplayName") or "signin",
                "user": normalized.get("userPrincipalName"),
                "app": normalized.get("appDisplayName"),
                "resource": normalized.get("appDisplayName"),
                "ip": normalized.get("ipAddress"),
                "src_ip": normalized.get("ipAddress"),
                "event_ts": normalized.get("createdDateTime"),
                "ts": _coerce_timestamp(normalized.get("createdDateTime")),
                "domain_hint": "identity",
            }
        )
    elif kind == "azure_entra_audit_export":
        actor = (((normalized.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName"))
        targets = normalized.get("targetResources") or []
        target_name = ""
        if targets and isinstance(targets[0], dict):
            target_name = targets[0].get("displayName") or targets[0].get("userPrincipalName") or targets[0].get("id") or ""
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AzureAudit",
                "provider": "azure_entra",
                "event_type": normalized.get("activityDisplayName") or "audit",
                "action": normalized.get("activityDisplayName") or "audit",
                "user": actor,
                "actor": actor,
                "resource": target_name,
                "event_ts": normalized.get("activityDateTime"),
                "ts": _coerce_timestamp(normalized.get("activityDateTime")),
                "domain_hint": "identity",
            }
        )
    elif kind == "azure_defender_incident_export":
        severity = _lower(normalized.get("severity"))
        alert_sources = [
            str(alert.get("serviceSource"))
            for alert in (normalized.get("alerts") or [])
            if isinstance(alert, dict) and alert.get("serviceSource")
        ]
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AzureDefender",
                "provider": "azure_defender",
                "event_type": "defender_incident",
                "action": normalized.get("title") or "defender_incident",
                "resource": normalized.get("incidentId"),
                "severity_label": severity,
                "event_ts": normalized.get("createdDateTime") or normalized.get("updatedTime") or normalized.get("firstActivity"),
                "ts": _coerce_timestamp(normalized.get("createdDateTime") or normalized.get("updatedTime") or normalized.get("firstActivity")),
                "alert_source": ",".join(alert_sources),
                "domain_hint": "cloud",
            }
        )
    elif kind == "azure_activity_log_export":
        operation = normalized.get("operationName")
        if isinstance(operation, dict):
            operation = operation.get("value")
        category = normalized.get("category")
        if isinstance(category, dict):
            category = category.get("value")
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AzureActivity",
                "provider": "azure_activity",
                "event_type": operation or "activity_log",
                "action": operation or "activity_log",
                "user": normalized.get("caller"),
                "actor": normalized.get("caller"),
                "resource": normalized.get("resourceGroupName") or normalized.get("resourceId"),
                "event_ts": normalized.get("time"),
                "ts": _coerce_timestamp(normalized.get("time")),
                "category_name": category,
                "domain_hint": "cloud",
            }
        )
    elif kind == "azure_nsg_flow_export":
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AzureNSGFlow",
                "provider": "azure_nsg",
                "event_type": "nsg_flow",
                "action": normalized.get("flowState") or "nsg_flow",
                "src_ip": normalized.get("srcIp"),
                "dst_ip": normalized.get("destIp"),
                "dst_port": normalized.get("destPort"),
                "bytes": normalized.get("bytes"),
                "event_ts": normalized.get("time"),
                "ts": _coerce_timestamp(normalized.get("time")),
                "domain_hint": "network",
            }
        )
    elif kind == "azure_conditional_access_export":
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AzureConditionalAccess",
                "provider": "azure_conditional_access",
                "event_type": "conditional_access",
                "action": normalized.get("policyName") or "conditional_access",
                "user": normalized.get("userPrincipalName"),
                "resource": normalized.get("appDisplayName") or normalized.get("policyName"),
                "result": normalized.get("result"),
                "event_ts": normalized.get("createdDateTime"),
                "ts": _coerce_timestamp(normalized.get("createdDateTime")),
                "domain_hint": "identity",
            }
        )
    elif kind == "azure_identity_protection_export":
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AzureIdentityProtection",
                "provider": "azure_identity_protection",
                "event_type": "identity_protection",
                "action": normalized.get("riskType") or "identity_protection",
                "user": normalized.get("userPrincipalName"),
                "resource": normalized.get("riskEventType") or normalized.get("riskType"),
                "severity_label": _lower(normalized.get("riskLevel")),
                "event_ts": normalized.get("detectedDateTime") or normalized.get("createdDateTime"),
                "ts": _coerce_timestamp(normalized.get("detectedDateTime") or normalized.get("createdDateTime")),
                "domain_hint": "identity",
            }
        )
    elif kind == "aws_cloudtrail_export":
        user_identity = normalized.get("userIdentity") or {}
        arn = user_identity.get("arn") if isinstance(user_identity, dict) else None
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AWSCloudTrail",
                "provider": "aws_cloudtrail",
                "event_type": normalized.get("eventName") or "cloudtrail",
                "action": normalized.get("eventName") or "cloudtrail",
                "user": arn or (user_identity.get("userName") if isinstance(user_identity, dict) else None),
                "actor": arn or (user_identity.get("userName") if isinstance(user_identity, dict) else None),
                "resource": normalized.get("eventSource"),
                "ip": normalized.get("sourceIPAddress"),
                "src_ip": normalized.get("sourceIPAddress"),
                "account_id": normalized.get("recipientAccountId") or normalized.get("accountId"),
                "event_ts": normalized.get("eventTime"),
                "ts": _coerce_timestamp(normalized.get("eventTime")),
                "domain_hint": "cloud",
            }
        )
    elif kind == "aws_guardduty_export":
        severity = float(_as_float(normalized.get("severity")) or 0.0)
        service = normalized.get("service") if isinstance(normalized.get("service"), dict) else {}
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AWSGuardDuty",
                "provider": "aws_guardduty",
                "event_type": normalized.get("type") or "guardduty",
                "action": normalized.get("type") or "guardduty",
                "resource": normalized.get("id"),
                "severity_score": severity,
                "account_id": normalized.get("accountId"),
                "event_ts": service.get("eventFirstSeen") or normalized.get("updatedAt"),
                "ts": _coerce_timestamp(service.get("eventFirstSeen") or normalized.get("updatedAt")),
                "domain_hint": "cloud",
            }
        )
    elif kind == "aws_securityhub_export":
        sev = normalized.get("Severity") if isinstance(normalized.get("Severity"), dict) else {}
        resources = normalized.get("Resources") or []
        resource_id = ""
        if resources and isinstance(resources[0], dict):
            resource_id = resources[0].get("Id") or resources[0].get("Type") or ""
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AWSSecurityHub",
                "provider": "aws_securityhub",
                "event_type": "securityhub_finding",
                "action": normalized.get("Title") or "securityhub_finding",
                "resource": resource_id,
                "severity_label": _lower(sev.get("Label")),
                "event_ts": normalized.get("UpdatedAt"),
                "ts": _coerce_timestamp(normalized.get("UpdatedAt")),
                "domain_hint": "cloud",
            }
        )
    elif kind == "aws_config_export":
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AWSConfig",
                "provider": "aws_config",
                "event_type": normalized.get("resourceType") or "config",
                "action": normalized.get("configurationItemStatus") or "config",
                "resource": normalized.get("resourceId") or normalized.get("resourceType"),
                "severity_label": _lower(normalized.get("complianceType")),
                "account_id": normalized.get("accountId"),
                "event_ts": normalized.get("configurationItemCaptureTime"),
                "ts": _coerce_timestamp(normalized.get("configurationItemCaptureTime")),
                "domain_hint": "cloud",
            }
        )
    elif kind == "aws_vpc_flow_export":
        normalized.update(
            {
                "sheet": normalized.get("sheet") or "AWSVPCFlow",
                "provider": "aws_vpc_flow",
                "event_type": "vpc_flow",
                "action": normalized.get("action") or "vpc_flow",
                "src_ip": normalized.get("srcaddr"),
                "dst_ip": normalized.get("dstaddr"),
                "dst_port": normalized.get("dstport"),
                "bytes": normalized.get("bytes"),
                "event_ts": normalized.get("start") or normalized.get("eventTime"),
                "ts": _coerce_timestamp(normalized.get("start") or normalized.get("eventTime")),
                "domain_hint": "network",
            }
        )
    return normalized


def build_offline_workbook_assessment(rows: list[Dict[str, Any]], *, assessment_id: str, org: str, auto_llm: bool) -> dict[str, Any]:
    now = time.time()
    persisted = _load_persisted_baseline(org)
    calibrations = _load_calibration_labels()
    rows = [_normalize_cloud_export_row(row, org) for row in rows]
    tfidf = TfidfProfile()
    family_profiles = {name: TfidfProfile() for name in ("path", "process", "command", "email", "cloud_action")}
    tenant_domain_profiles: dict[tuple[str, str], TfidfProfile] = {}
    try:
        for profile_key, data in (persisted.get("profiles") or {}).items():
            if ":" in profile_key:
                tenant_key, domain_key = profile_key.split(":", 1)
                tenant_domain_profiles[(tenant_key, domain_key)] = TfidfProfile.from_dict(data)
        for family_name, data in (persisted.get("family_profiles") or {}).items():
            if family_name in family_profiles:
                family_profiles[family_name] = TfidfProfile.from_dict(data)
    except Exception:
        pass
    row_tokens: list[list[str]] = []
    family_tokens_by_row: list[dict[str, list[str]]] = []
    row_domains: list[str] = []
    for row in rows:
        tokens = _tokenize_row(row)
        row_tokens.append(tokens)
        tfidf.add_document(tokens)
        domain = _domain_family(row)
        row_domains.append(domain)
        family_tokens = {name: _tokenize_feature_family(row, name) for name in family_profiles}
        family_tokens_by_row.append(family_tokens)
        for family_name, profile in family_profiles.items():
            profile.add_document(family_tokens.get(family_name) or [])
        tenant_domain_profiles.setdefault((org, domain), TfidfProfile()).add_document(tokens)

    ip_to_sheets, domain_to_sheets, hash_to_sheets, user_to_sheets, resource_to_sheets = _collect_indicator_maps(rows)
    endpoint_hash_counts = Counter(_lower(row.get("sha256") or row.get("file_hash")) for row in rows if row.get("sha256") or row.get("file_hash"))
    network_groups: dict[Tuple[str, str, int], list[float]] = defaultdict(list)
    entity_pair_groups: dict[Tuple[str, str, str], list[float]] = defaultdict(list)
    value_groups: dict[tuple[str, str], list[float]] = defaultdict(list)
    historical_graph_paths = dict(persisted.get("graph_paths") or {})
    historical_graph_edges = dict(persisted.get("graph_edges") or {})
    historical_action_frequency = dict(persisted.get("provider_action_frequency") or {})
    historical_graph_path_meta = dict(persisted.get("graph_path_meta") or {})
    historical_graph_edge_meta = dict(persisted.get("graph_edge_meta") or {})
    historical_action_meta = dict(persisted.get("provider_action_meta") or {})
    for row in rows:
        src_ip = _safe_ip(row.get("src_ip") or row.get("ip"))
        dst_ip = _safe_ip(row.get("dst_ip"))
        port = _as_int(row.get("dst_port"))
        ts = _coerce_timestamp(row.get("ts") or row.get("event_ts"))
        if src_ip and dst_ip and port is not None and ts is not None:
            network_groups[(src_ip, dst_ip, port)].append(ts)
            entity_pair_groups[("host_dst_ip", _lower(row.get("host") or row.get("hostname") or src_ip), dst_ip)].append(ts)
            value_groups[("network_payload", f"{src_ip}->{dst_ip}:{port}")].append(float(_as_float(row.get("payload_len") or row.get("bytes")) or 0.0))
        user = _lower(row.get("user") or row.get("username") or row.get("userPrincipalName") or row.get("actor") or row.get("caller"))
        app = _lower(row.get("app") or row.get("application") or row.get("client_app"))
        if user and app and ts is not None:
            entity_pair_groups[("user_app", user, app)].append(ts)
        spn = _lower(row.get("service_principal") or row.get("servicePrincipalName") or row.get("appId"))
        resource = _lower(row.get("resource") or row.get("resourceDisplayName") or row.get("target_resource"))
        provider = _lower(row.get("provider") or row.get("cloud_export_kind"))
        action = _lower(row.get("action") or row.get("event_type"))
        if spn and resource and ts is not None:
            entity_pair_groups[("sp_resource", spn, resource)].append(ts)
        if user and resource and ts is not None:
            entity_pair_groups[("user_resource", user, resource)].append(ts)
        if provider and action:
            key = f"{provider}|{action}"
            historical_action_frequency[key] = int(historical_action_frequency.get(key, 0))
        if ts is not None:
            path_key = _lower(row.get("process_path") or row.get("path") or row.get("process") or row.get("process_name") or _sheet_name(row))
            value_groups[("activity_volume", path_key)].append(float(_as_float(row.get("payload_len") or row.get("size") or row.get("bytes")) or 1.0))
    for pair_key, hist_values in (persisted.get("entity_pairs") or {}).items():
        try:
            pair_kind, pair_a, pair_b = pair_key.split("|", 2)
            entity_pair_groups[(pair_kind, pair_a, pair_b)].extend([float(v) for v in hist_values][-50:])
        except Exception:
            continue

    row_feature_vectors: list[list[float]] = []
    base_rows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    evidence_items: list[dict[str, Any]] = []
    attack_timeline: list[dict[str, Any]] = []
    factor_counter: Counter[str] = Counter()
    recommended_actions: list[dict[str, Any]] = []

    for idx, row in enumerate(rows):
        factors: list[str] = []
        evidence: list[str] = []
        urls, emails = _extract_urls_and_emails(row)
        url_domains = _extract_domains(urls)
        src_ip = _safe_ip(row.get("src_ip") or row.get("ip"))
        dst_ip = _safe_ip(row.get("dst_ip"))
        dst_port = _as_int(row.get("dst_port"))
        path = _lower(row.get("process_path") or row.get("path"))
        process = _lower(row.get("process") or row.get("process_name"))
        sha256 = _lower(row.get("sha256") or row.get("file_hash"))
        subject = _lower(row.get("subject"))
        body = _lower(row.get("body"))
        sheet = _sheet_name(row)
        domain = row_domains[idx]
        provider = _lower(row.get("provider") or row.get("cloud_export_kind"))
        event_type = _lower(row.get("event_type") or row.get("action"))
        resource = _lower(row.get("resource") or row.get("resourceDisplayName") or row.get("target_resource"))
        user = _lower(row.get("user") or row.get("username") or row.get("userPrincipalName") or row.get("actor") or row.get("caller"))
        tfidf_rarity = tfidf.get_rarity_score(row_tokens[idx])
        tenant_domain_rarity = tenant_domain_profiles.get((org, domain), tfidf).get_rarity_score(row_tokens[idx])
        family_rarity_scores = {
            family_name: family_profiles[family_name].get_rarity_score(family_tokens_by_row[idx].get(family_name) or [])
            for family_name in family_profiles
        }
        benign_tags = _benign_context_tags(path, process, row)

        external_dst = 1.0 if _is_external_ip(dst_ip) else 0.0
        lateral_port = 1.0 if dst_port in _LATERAL_PORTS else 0.0
        suspicious_path = 1.0 if any(marker in path for marker in _SUSPICIOUS_PATH_MARKERS) else 0.0
        suspicious_process = 1.0 if any(marker in process for marker in _SUSPICIOUS_PROCESS_MARKERS) else 0.0
        if benign_tags:
            suspicious_path = 0.0
            if process.split("\\")[-1] in _BENIGN_PROCESS_ALLOWLIST:
                suspicious_process = 0.0
        if "known_backup_activity" in benign_tags and (bool(row.get("approved_change")) or bool(_lower(row.get("change_ticket"))) or bool(row.get("maintenance_window"))):
            external_dst = 0.0
            lateral_port = 0.0
        phishing_keywords = sum(1 for marker in _PHISHING_MARKERS if marker in subject or marker in body)
        malicious_links = float(len(urls))
        repeated_hash = 1.0 if sha256 and endpoint_hash_counts[sha256] > 1 else 0.0
        cross_pivot_score = 0.0
        suppressors = _suppressor_tags(row, benign_tags, url_domains, dst_ip, _coerce_timestamp(row.get("ts") or row.get("event_ts")))
        approved_change = bool(row.get("approved_change")) or bool(_lower(row.get("change_ticket")))
        suppress_backup_pivots = "known_backup_activity" in benign_tags and approved_change

        if external_dst:
            factors.append("network:suspicious_external_ip")
            evidence.append(f"external destination {dst_ip}")
        if lateral_port:
            factors.append("network:lateral_movement_port")
            evidence.append(f"lateral movement port {dst_port}")
        if suspicious_path or suspicious_process:
            factors.append("endpoint:suspicious_process_path")
            evidence.append(_text(row.get("process_path") or row.get("path") or row.get("process") or row.get("process_name")))
        if repeated_hash:
            factors.append("endpoint:repeated_hash")
        if malicious_links or phishing_keywords:
            factors.append("email:phishing_lure")
            if urls:
                evidence.append(f"embedded links {', '.join(url_domains[:2] or urls[:2])}")
            if phishing_keywords:
                evidence.append(f"phishing keywords {phishing_keywords}")
        for ip in ([] if suppress_backup_pivots else list(filter(None, [src_ip, dst_ip]))):
            other_ip_sheets = {name for name in ip_to_sheets.get(ip, set()) if name != sheet}
            if other_ip_sheets:
                cross_pivot_score += 1.0
                if "corr:cross_sheet_indicator_pivot" not in factors:
                    factors.append("corr:cross_sheet_indicator_pivot")
                    evidence.append(f"IP pivot {ip} across {sorted(other_ip_sheets | {sheet})}")
        for domain in ([] if suppress_backup_pivots else url_domains):
            other_ip_sheets = {name for name in ip_to_sheets.get(domain, set()) if name != sheet}
            if _safe_ip(domain) and other_ip_sheets:
                cross_pivot_score += 1.0
                if "corr:cross_sheet_indicator_pivot" not in factors:
                    factors.append("corr:cross_sheet_indicator_pivot")
                    evidence.append(f"IP pivot {domain} across {sorted(other_ip_sheets | {sheet})}")
            other_domain_sheets = {name for name in domain_to_sheets.get(domain, set()) if name != sheet}
            if other_domain_sheets:
                cross_pivot_score += 1.0
                if "corr:cross_sheet_indicator_pivot" not in factors:
                    factors.append("corr:cross_sheet_indicator_pivot")
                    evidence.append(f"domain pivot {domain} across {sorted(other_domain_sheets | {sheet})}")
        other_hash_sheets = {name for name in hash_to_sheets.get(sha256, set()) if name != sheet} if sha256 else set()
        if sha256 and other_hash_sheets and not suppress_backup_pivots:
            cross_pivot_score += 1.0
            if "corr:cross_sheet_indicator_pivot" not in factors:
                factors.append("corr:cross_sheet_indicator_pivot")
                evidence.append(f"hash pivot {sha256[:12]} across {sorted(other_hash_sheets | {sheet})}")
        if user and not approved_change and not suppress_backup_pivots:
            other_user_sheets = {name for name in user_to_sheets.get(user, set()) if name != sheet}
            if other_user_sheets:
                cross_pivot_score += 1.0
                if "corr:cross_sheet_indicator_pivot" not in factors:
                    factors.append("corr:cross_sheet_indicator_pivot")
                    evidence.append(f"user pivot {user} across {sorted(other_user_sheets | {sheet})}")
        if resource and not approved_change and not suppress_backup_pivots:
            other_resource_sheets = {name for name in resource_to_sheets.get(resource, set()) if name != sheet}
            if other_resource_sheets:
                cross_pivot_score += 1.0
                if "corr:cross_sheet_indicator_pivot" not in factors:
                    factors.append("corr:cross_sheet_indicator_pivot")
                    evidence.append(f"resource pivot {resource} across {sorted(other_resource_sheets | {sheet})}")

        ts = _coerce_timestamp(row.get("ts") or row.get("event_ts"))
        if src_ip and dst_ip and dst_port is not None:
            regular, regularity = _ewma_regular_intervals(network_groups.get((src_ip, dst_ip, dst_port), []))
            if regular:
                factors.append("network:adaptive_ewma_regular_cadence")
                evidence.append(f"regular cadence score {regularity:.2f}")
        for pair_kind, pair_a, pair_b in (
            ("user_app", _lower(row.get("user") or row.get("username") or row.get("userPrincipalName")), _lower(row.get("app") or row.get("application") or row.get("client_app"))),
            ("user_resource", _lower(row.get("user") or row.get("username") or row.get("userPrincipalName") or row.get("actor") or row.get("caller")), _lower(row.get("resource") or row.get("resourceDisplayName") or row.get("target_resource"))),
            ("host_dst_ip", _lower(row.get("host") or row.get("hostname") or src_ip), dst_ip or ""),
            ("sp_resource", _lower(row.get("service_principal") or row.get("servicePrincipalName") or row.get("appId")), _lower(row.get("resource") or row.get("resourceDisplayName") or row.get("target_resource"))),
        ):
            if pair_a and pair_b:
                regular, regularity = _ewma_regular_intervals(entity_pair_groups.get((pair_kind, pair_a, pair_b), []))
                if regular and regularity >= 0.82:
                    factors.append("network:adaptive_ewma_regular_cadence")
                    evidence.append(f"{pair_kind} cadence score {regularity:.2f}")
                    break

        risk_detail = _lower(row.get("riskDetail") or row.get("riskState") or row.get("riskLevelDuringSignIn"))
        provider_action_key = f"{provider}|{event_type}"
        prior_action_count = int(historical_action_frequency.get(provider_action_key, 0)) if provider_action_key.strip("|") else 0
        if provider.startswith("azure_entra") and event_type == "signin":
            if src_ip and _is_external_ip(src_ip):
                factors.append("identity:cloud_signin_external")
                evidence.append(f"cloud sign-in from external IP {src_ip}")
            if risk_detail and risk_detail not in {"none", "hidden", "low"}:
                factors.append("identity:cloud_signin_risk")
                evidence.append(f"sign-in risk detail {risk_detail}")
        if (not approved_change) and provider.startswith("azure_entra") and any(token in event_type for token in ("role", "admin", "privilege", "eligible member", "consent")):
            factors.append("cloud:privilege_change")
            evidence.append(f"entra audit activity {row.get('activityDisplayName') or row.get('action')}")
        if (not approved_change) and provider == "azure_activity" and any(token in event_type for token in ("roleassignments/write", "policyassignments/write", "authorization")):
            factors.append("cloud:resource_admin_write")
            evidence.append(f"azure activity operation {row.get('action')}")
        severity_label = _lower(row.get("severity_label") or row.get("severity"))
        severity_score = float(_as_float(row.get("severity_score") or row.get("severity")) or 0.0)
        if provider == "azure_defender" and (severity_label in {"high", "critical"} or "impossible travel" in _lower(row.get("title"))):
            factors.append("cloud:defender_high_severity")
            evidence.append(f"defender incident {row.get('title') or row.get('incidentId')}")
        if provider == "azure_conditional_access" and _lower(row.get("result")) not in {"success", "allow", "notapplied"}:
            factors.append("identity:conditional_access_failure")
            evidence.append(f"conditional access result {row.get('result')}")
        if provider == "azure_identity_protection" and severity_label in {"medium", "high", "critical"}:
            factors.append("identity:identity_protection_risk")
            evidence.append(f"identity protection risk {row.get('riskType') or row.get('action')}")
        if (not approved_change) and provider == "aws_cloudtrail" and any(token in event_type for token in ("createaccesskey", "attachuserpolicy", "putrolepolicy", "putuserpolicy", "addusertogroup")):
            factors.append("cloud:access_key_creation" if "createaccesskey" in event_type else "cloud:privilege_change")
            evidence.append(f"cloudtrail event {row.get('eventName') or row.get('action')}")
        if provider == "aws_config" and severity_label in {"non_compliant", "failed"}:
            factors.append("cloud:config_drift")
            evidence.append(f"aws config compliance {row.get('complianceType')}")
        if provider == "aws_vpc_flow" and dst_ip and _is_external_ip(dst_ip) and "known_backup_activity" not in benign_tags:
            factors.append("network:vpc_external_flow")
            evidence.append(f"vpc flow to external IP {dst_ip}")
        if provider == "aws_guardduty" and (severity_score >= 7.0 or "credentialaccess" in event_type or "anomalousbehavior" in event_type):
            factors.append("cloud:guardduty_high_severity")
            evidence.append(f"guardduty finding {row.get('type') or row.get('action')}")
        if provider == "aws_securityhub" and (severity_label in {"high", "critical"} or "unusual" in _lower(row.get("Title") or row.get("title"))):
            factors.append("cloud:securityhub_high")
            evidence.append(f"security hub finding {row.get('Title') or row.get('title')}")
        if provider and event_type and prior_action_count == 0 and any(f.startswith(("cloud:", "identity:")) for f in factors):
            evidence.append(f"novel provider action {provider_action_key}")

        rarity_threshold = 0.78 if benign_tags else 0.55
        effective_rarity = max(tfidf_rarity, tenant_domain_rarity, max(family_rarity_scores.values() or [0.0]))
        if effective_rarity >= rarity_threshold:
            factors.append("context:tfidf_rare_tokens")
            evidence.append(
                f"rare token score global={tfidf_rarity:.2f} tenant_domain={tenant_domain_rarity:.2f} family={max(family_rarity_scores.values() or [0.0]):.2f}"
            )
        mad_key = ("network_payload", f"{src_ip}->{dst_ip}:{dst_port}") if src_ip and dst_ip and dst_port is not None else ("activity_volume", _lower(row.get("process_path") or row.get("path") or row.get("process") or row.get("process_name") or sheet))
        mad_values = value_groups.get(mad_key, [])
        if mad_values:
            mad_scores = _mad_outlier_score(mad_values)
            try:
                current_value = float(_as_float(row.get("payload_len") or row.get("size") or row.get("bytes")) or (mad_values[-1] if mad_values else 1.0))
                current_index = next(i for i, value in enumerate(mad_values) if abs(value - current_value) < 1e-9)
            except Exception:
                current_index = len(mad_values) - 1
            mad_score = mad_scores[current_index] if 0 <= current_index < len(mad_scores) else 0.0
            if mad_score >= 3.5:
                factors.append("stats:mad_volume_outlier")
                evidence.append(f"MAD outlier score {mad_score:.2f}")
        if benign_tags:
            evidence.append(f"benign maintenance context {', '.join(benign_tags[:2])}")
        if suppressors:
            evidence.append(f"suppressors {', '.join(suppressors[:3])}")

        row_feature_vectors.append(
            [
                external_dst,
                lateral_port,
                suspicious_path + suspicious_process,
                float(phishing_keywords),
                malicious_links,
                repeated_hash,
                effective_rarity if not benign_tags else max(0.0, effective_rarity - 0.2),
                cross_pivot_score,
                1.0 if any(f.startswith("cloud:") or f.startswith("identity:cloud_") for f in factors) else 0.0,
            ]
        )
        base_rows.append(
            {
                "row_index": row.get("row_index", idx),
                "row": row,
                "factors": factors,
                "evidence": evidence,
                "sheet": sheet,
                "timestamp": ts,
                "entity": _row_entity(row),
                "benign_tags": benign_tags,
                "suppressors": suppressors,
                "domain": domain,
                "tenant_domain_rarity": tenant_domain_rarity,
                "family_rarity_scores": family_rarity_scores,
            }
        )

    if row_feature_vectors:
        global_detector = IsolationForestDetector(n_estimators=80, random_state=42)
        global_detector.fit(row_feature_vectors)
        detectors_by_domain: dict[str, IsolationForestDetector] = {}
        domain_vectors: dict[str, list[list[float]]] = defaultdict(list)
        domain_indexes: dict[str, list[int]] = defaultdict(list)
        for idx, vec in enumerate(row_feature_vectors):
            domain_vectors[base_rows[idx]["domain"]].append(vec)
            domain_indexes[base_rows[idx]["domain"]].append(idx)
        for domain_name, vectors in domain_vectors.items():
            if len(vectors) >= 3:
                detector = IsolationForestDetector(n_estimators=60, random_state=42)
                detector.fit(vectors)
                detectors_by_domain[domain_name] = detector
        for idx, vec in enumerate(row_feature_vectors):
            domain_detector = detectors_by_domain.get(base_rows[idx]["domain"])
            score = domain_detector.score(vec) if domain_detector is not None else global_detector.score(vec)
            base_rows[idx]["if_score"] = score
            benign_tags = base_rows[idx].get("benign_tags") or []
            threshold = 0.78 if benign_tags else 0.62
            if score >= threshold:
                base_rows[idx]["factors"].append("ml:isolation_forest_outlier")
                base_rows[idx]["evidence"].append(f"isolation forest score {score:.2f}")
        dbscan_scores = _density_dbscan_scores(row_feature_vectors)
        for idx, cluster_score in enumerate(dbscan_scores):
            if cluster_score >= 0.9:
                base_rows[idx]["factors"].append("ml:dbscan_sparse_cluster")
                base_rows[idx]["evidence"].append(f"DBSCAN sparse-cluster score {cluster_score:.2f}")

    for item in base_rows:
        factors = sorted(set(item["factors"]))
        evidence = item["evidence"]
        row = item["row"]
        corroboration_count = len({factor.split(":", 1)[0] for factor in factors if ":" in factor})
        domain_diversity = len({_domain_family(other["row"]) for other in base_rows if other["entity"] == item["entity"] and other["factors"]})
        recency_score = 1.0 if item.get("timestamp") and float(item["timestamp"]) >= (now - 86400) else 0.0
        asset_criticality = min(1.0, float(_as_float(row.get("asset_criticality")) or 0.0))
        sensitivity_score = min(1.0, float(_as_float(row.get("resource_sensitivity")) or _as_float(row.get("user_sensitivity")) or 0.0))
        confidence = _confidence_with_context(
            factors,
            list(item.get("benign_tags") or []),
            list(item.get("suppressors") or []),
            corroboration_count,
            domain_diversity,
            recency_score,
            asset_criticality,
            sensitivity_score,
        )
        confidence = max(0.08, min(0.97, confidence + _calibration_adjustment(factors, calibrations, str(row.get("provider") or row.get("cloud_export_kind") or ""))))
        verdict = _verdict_from_confidence(confidence)
        summary = _row_summary(row, factors, evidence, confidence)
        item["confidence"] = confidence
        item["verdict"] = verdict
        item["summary"] = summary
        for factor in factors:
            factor_counter[factor] += 1
        if factors:
            findings.append(
                {
                    "row_index": row.get("row_index"),
                    "sheet": item["sheet"],
                    "entity": item["entity"],
                    "title": summary,
                    "severity": _severity_from_confidence(confidence),
                    "confidence": round(confidence, 2),
                    "factors": factors,
                    "evidence": evidence[:4],
                    "benign_context": item.get("benign_tags") or [],
                }
            )
        row_iocs = {
            "ip": [ip for ip in [row.get("src_ip"), row.get("dst_ip"), row.get("ip")] if _safe_ip(ip)],
            "domain": sorted(set(_extract_domains(_extract_urls_and_emails(row)[0]) + [d for d in [_lower(row.get("domain")), _lower(row.get("sni"))] if d])),
            "hash": [sha for sha in [row.get("sha256"), row.get("file_hash")] if _lower(sha)],
            "email": [e for e in _extract_urls_and_emails(row)[1]],
        }
        if any(row_iocs.values()):
            evidence_items.append(
                {
                    "row_index": row.get("row_index"),
                    "sheet": item["sheet"],
                    "summary": summary,
                    "extracted_iocs": row_iocs,
                    "supporting_factors": factors,
                }
            )
        if factors:
            attack_timeline.append(
                {
                    "ts": item["timestamp"] or now,
                    "entity": item["entity"],
                    "event_type": item["sheet"].lower(),
                    "summary": summary,
                    "factors": factors,
                }
            )

    attack_timeline.sort(key=lambda x: x.get("ts", now))
    suspicious_rows = [item for item in base_rows if item["factors"]]
    sequence_score = _sequence_progression_score([item.get("domain", "other") for item in suspicious_rows])
    sequence_eligible = any(
        any(not factor.startswith(("context:", "ml:", "stats:")) for factor in item.get("factors", []))
        and not item.get("suppressors")
        for item in suspicious_rows
    )
    if sequence_score >= 0.66 and suspicious_rows and sequence_eligible:
        factor_counter["sequence:kill_chain_progression"] += 1
        top_item = suspicious_rows[min(len(suspicious_rows) - 1, 0)]
        top_item["factors"].append("sequence:kill_chain_progression")
        top_item["evidence"].append(f"kill-chain progression score {sequence_score:.2f}")
    corroborating_domains = sorted({item.get("domain", "other") for item in suspicious_rows})
    max_confidence = max((item["confidence"] for item in base_rows), default=0.28)
    if sequence_score >= 0.66 and sequence_eligible:
        max_confidence = min(0.97, max_confidence + 0.06)
    suspicious_rows_sorted = sorted(suspicious_rows, key=lambda item: item.get("timestamp") or now)
    graph_nodes: list[str] = []
    graph_edges: list[dict[str, Any]] = []
    graph_edge_keys: list[str] = []
    graph_edge_types: list[str] = []
    for item in suspicious_rows_sorted[:10]:
        row = item.get("row") or {}
        actor = _lower(row.get("user") or row.get("username") or row.get("userPrincipalName") or row.get("actor") or row.get("caller")) or item.get("entity") or "unknown"
        action = _lower(row.get("action") or row.get("event_type") or item.get("sheet"))
        target = _lower(row.get("resource") or row.get("resourceDisplayName") or row.get("target_resource") or row.get("dst_ip") or row.get("host") or row.get("hostname")) or item.get("domain", "other")
        provider = _lower(row.get("provider") or row.get("cloud_export_kind")) or item.get("domain", "other")
        graph_nodes.append(f"{provider}:{actor}->{action}->{target}")
    for idx in range(1, len(graph_nodes)):
        edge_key = f"{graph_nodes[idx - 1]}=>{graph_nodes[idx]}"
        prev_domain = suspicious_rows_sorted[idx - 1].get("domain", "other")
        next_domain = suspicious_rows_sorted[idx].get("domain", "other")
        edge_type = f"{prev_domain}->{next_domain}"
        graph_edge_keys.append(edge_key)
        graph_edge_types.append(edge_type)
        graph_edges.append(
            {
                "source": graph_nodes[idx - 1],
                "target": graph_nodes[idx],
                "edge_type": edge_type,
                "score": round(0.4 + min(0.5, suspicious_rows_sorted[idx].get("confidence", 0.0)), 2),
            }
        )
    graph_path = " | ".join(graph_nodes[:8]) or "empty"
    prior_graph_count = int(historical_graph_paths.get(graph_path, 0))
    graph_path_score = 1.0 / (1.0 + prior_graph_count)
    edge_novelties = [1.0 / (1.0 + int(historical_graph_edges.get(edge_key, 0))) for edge_key in graph_edge_keys] or [graph_path_score]
    historical_edge_type_counts = Counter(
        key.split("=>", 1)[0].split(":", 1)[0] + "->" + key.split("=>", 1)[1].split(":", 1)[0]
        for key in historical_graph_edges
        if "=>" in key and ":" in key
    )
    edge_type_novelties = [1.0 / (1.0 + int(historical_edge_type_counts.get(edge_type, 0))) for edge_type in graph_edge_types] or [graph_path_score]
    graph_anomaly_score = ((sum(edge_novelties) / max(len(edge_novelties), 1)) * 0.7) + ((sum(edge_type_novelties) / max(len(edge_type_novelties), 1)) * 0.3)
    if graph_path_score >= 0.5 and len(corroborating_domains) >= 2:
        factor_counter["graph:anomalous_path"] += 1
    if graph_anomaly_score >= 0.55 and len(graph_edge_keys) >= 2:
        factor_counter["graph:anomalous_edge_chain"] += 1
        max_confidence = min(0.97, max_confidence + 0.07)
    elif graph_path_score >= 0.5 and len(corroborating_domains) >= 2:
        max_confidence = min(0.97, max_confidence + 0.05)
    final_verdict = _verdict_from_confidence(max_confidence)
    ranked_factors = sorted(
        factor_counter.items(),
        key=lambda item: (
            -((math.sqrt(item[1]) * max(_FACTOR_WEIGHTS.get(item[0], 0.04), 0.04)) + (_FACTOR_PRIORITY.get(item[0].split(":", 1)[0], 0) * 0.05)),
            -_FACTOR_PRIORITY.get(item[0].split(":", 1)[0], 0),
            -item[1],
            -_FACTOR_WEIGHTS.get(item[0], 0.0),
            item[0],
        ),
    )
    top_factors, semantic_top_factors, supporting_top_factors = _split_factor_views(
        ranked_factors,
        len(rows),
        graph_anomaly_score,
        corroborating_domains,
    )

    corroboration_count = len(corroborating_domains)
    missing_evidence: list[str] = []
    if any(f.startswith("email:") for f in factor_counter):
        action = {
            "primary_action": "Request mailbox trace, click telemetry, and attachment detonation evidence",
            "urgency": "urgent",
            "persona": "soc_analyst",
            "requires": {"confidence_threshold": 0.45, "corroborating_domain_count": 1, "approval_state": "not_required"},
        }
        recommended_actions.append(action)
        missing_evidence.extend(["mailbox_trace", "click_telemetry"])
    if any(f.startswith("network:") for f in factor_counter):
        recommended_actions.append({
            "primary_action": "Pull DNS, proxy, firewall, and east-west flow telemetry for the implicated destinations",
            "urgency": "urgent",
            "persona": "threat_hunter",
            "requires": {"confidence_threshold": 0.5, "corroborating_domain_count": 1, "approval_state": "not_required"},
        })
        missing_evidence.extend(["dns", "proxy", "firewall"])
    if any(f.startswith("endpoint:") for f in factor_counter):
        recommended_actions.append({
            "primary_action": "Validate signer, parent process, lineage, persistence, and memory artifacts for the suspect endpoint chain",
            "urgency": "immediate",
            "persona": "forensics",
            "requires": {"confidence_threshold": 0.5, "corroborating_domain_count": 1, "approval_state": "not_required"},
        })
        missing_evidence.extend(["process_lineage", "signer_metadata", "memory_capture"])
    if any(f.startswith("identity:") for f in factor_counter) or any(item.get("row", {}).get("resource") for item in suspicious_rows):
        recommended_actions.append({
            "primary_action": "Request Entra audit logs, Conditional Access results, Defender incident context, and target-resource activity",
            "urgency": "immediate",
            "persona": "soc_analyst",
            "requires": {"confidence_threshold": 0.52, "corroborating_domain_count": 2, "approval_state": "not_required"},
        })
        missing_evidence.extend(["entra_audit", "conditional_access", "defender_incident"])
    if any(f.startswith("cloud:") for f in factor_counter):
        recommended_actions.append({
            "primary_action": "Pull Azure Activity Logs, CloudTrail, GuardDuty, Security Hub, and resource access telemetry to confirm cloud control-plane abuse",
            "urgency": "immediate",
            "persona": "soc_analyst",
            "requires": {"confidence_threshold": 0.58, "corroborating_domain_count": 2, "approval_state": "not_required"},
        })
        missing_evidence.extend(["activity_log", "cloudtrail", "guardduty", "securityhub"])
    if any(f.startswith("corr:") for f in factor_counter) or sequence_score >= 0.66:
        recommended_actions.append({
            "primary_action": "Escalate the corroborated multi-stage chain for analyst review and controlled containment planning",
            "urgency": "immediate",
            "persona": "soc_analyst",
            "requires": {"confidence_threshold": 0.62, "corroborating_domain_count": 2, "approval_state": "pending"},
        })
    if any(item.get("benign_tags") for item in suspicious_rows):
        recommended_actions.append({
            "primary_action": "Verify Windows Update, Defender, and maintenance allowlists before escalation",
            "urgency": "normal",
            "persona": "soc_analyst",
            "requires": {"confidence_threshold": 0.0, "corroborating_domain_count": 0, "approval_state": "not_required"},
        })

    likelihood = min(99, int(max_confidence * 100))
    severity = _severity_from_confidence(max_confidence)
    affected_identities = {
        _lower(item["row"].get("user") or item["row"].get("username") or item["row"].get("email"))
        for item in suspicious_rows
        if _lower(item["row"].get("user") or item["row"].get("username") or item["row"].get("email"))
    }
    affected_hosts = {
        _lower(item["row"].get("host") or item["row"].get("hostname"))
        for item in suspicious_rows
        if _lower(item["row"].get("host") or item["row"].get("hostname"))
    }
    high_entity_count = len(affected_identities | affected_hosts | {item["entity"] for item in suspicious_rows if item["entity"]})
    critical_asset_count = len([item for item in suspicious_rows if any(f.startswith("corr:") or f.startswith("endpoint:") for f in item["factors"])])
    expected_loss = _estimate_expected_loss(severity, max(1, len(affected_identities) or len(affected_hosts) or high_entity_count), len(suspicious_rows), critical_asset_count)
    risk_quantification = {
        "severity": severity,
        "likelihood_percent": likelihood,
        "expected_loss_usd": expected_loss,
        "damage_potential": min(10, 2 + len(affected_hosts) + len([f for f in factor_counter if f.startswith("endpoint:") or f.startswith("corr:")])),
        "reproducibility": min(10, 2 + len([f for f in factor_counter if f.startswith("network:")])),
        "exploitability": min(10, 2 + len([f for f in factor_counter if f.startswith("email:") or f.startswith("endpoint:") or f.startswith("corr:")])),
        "affected_users": max(1, len(affected_identities) or len(affected_hosts) or high_entity_count),
        "discoverability": min(10, 3 + len([f for f in factor_counter if f.startswith("corr:")])),
        "impact_range_usd": [expected_loss, expected_loss * 3],
    }

    llm_rows = []
    results = []
    for item in base_rows:
        row = item["row"]
        llm_rows.append(
            {
                "row_index": row.get("row_index"),
                "fingerprint": row.get("fingerprint") or row.get("sha256") or row.get("file_hash") or f"row-{row.get('row_index')}",
                "llm_summary": item["summary"],
                "llm_meta": {
                    "auto": True,
                    "confidence": round(item["confidence"], 2),
                    "factors": item["factors"][:5],
                    "sheet": item["sheet"],
                    "evidence": item["evidence"][:4],
                },
                "generated_at": now,
            }
        )
        results.append(
            {
                "row_index": row.get("row_index"),
                "verdict": item["verdict"].lower(),
                "confidence": round(item["confidence"], 2),
                "summary": item["summary"],
                "signals": row,
                "factors": item["factors"][:6],
            }
        )

    highlighted_findings = findings[:5]
    canonical = {
        "llm_summary": (
            f"{final_verdict} with {len(suspicious_rows)} suspicious rows across "
            f"{len({item['sheet'] for item in suspicious_rows}) or 1} workbook sheets. "
            f"Top factors: {', '.join([entry['factor_name'] for entry in (semantic_top_factors or top_factors)[:4]]) or 'none'}."
        ),
        "highlights": highlighted_findings,
        "sheet_count": len({_sheet_name(row) for row in rows}),
        "suspicious_row_count": len(suspicious_rows),
        "high_confidence_rows": len([item for item in base_rows if item["confidence"] >= 0.7]),
        "tfidf_rarity_max": max((tfidf.get_rarity_score(row_tokens[idx]) for idx in range(len(row_tokens))), default=0.0),
        "risk_drivers": [entry["factor_name"] for entry in (semantic_top_factors or top_factors)[:5]],
        "benign_context_rows": len([item for item in base_rows if item.get("benign_tags")]),
        "corroborating_domains": corroborating_domains,
        "corroboration_count": corroboration_count,
        "sequence_score": round(sequence_score, 2),
    }
    updated_pairs: dict[str, list[float]] = {}
    for (pair_kind, pair_a, pair_b), timestamps in entity_pair_groups.items():
        updated_pairs[f"{pair_kind}|{pair_a}|{pair_b}"] = [float(v) for v in timestamps][-80:]
    persisted_payload = {
        "profiles": {
            f"{tenant_key}:{domain_key}": profile.to_dict()
            for (tenant_key, domain_key), profile in tenant_domain_profiles.items()
            if tenant_key == org
        },
        "family_profiles": {name: profile.to_dict() for name, profile in family_profiles.items()},
        "entity_pairs": updated_pairs,
        "graph_paths": {
            **historical_graph_paths,
            graph_path: int(historical_graph_paths.get(graph_path, 0)) + 1,
        },
        "graph_path_meta": {
            **historical_graph_path_meta,
            graph_path: {
                "count": int(historical_graph_paths.get(graph_path, 0)) + 1,
                "last_seen_ts": now,
            },
        },
        "graph_edges": {
            **historical_graph_edges,
            **{edge_key: int(historical_graph_edges.get(edge_key, 0)) + 1 for edge_key in graph_edge_keys},
        },
        "graph_edge_meta": {
            **historical_graph_edge_meta,
            **{
                edge_key: {
                    "count": int(historical_graph_edges.get(edge_key, 0)) + 1,
                    "last_seen_ts": now,
                }
                for edge_key in graph_edge_keys
            },
        },
        "provider_action_frequency": {
            **historical_action_frequency,
            **{
                f"{_lower(item['row'].get('provider') or item['row'].get('cloud_export_kind'))}|{_lower(item['row'].get('event_type') or item['row'].get('action'))}":
                int(historical_action_frequency.get(f"{_lower(item['row'].get('provider') or item['row'].get('cloud_export_kind'))}|{_lower(item['row'].get('event_type') or item['row'].get('action'))}", 0)) + 1
                for item in base_rows
                if _lower(item["row"].get("provider") or item["row"].get("cloud_export_kind")) and _lower(item["row"].get("event_type") or item["row"].get("action"))
            },
        },
        "provider_action_meta": {
            **historical_action_meta,
            **{
                f"{_lower(item['row'].get('provider') or item['row'].get('cloud_export_kind'))}|{_lower(item['row'].get('event_type') or item['row'].get('action'))}": {
                    "count": int(historical_action_frequency.get(f"{_lower(item['row'].get('provider') or item['row'].get('cloud_export_kind'))}|{_lower(item['row'].get('event_type') or item['row'].get('action'))}", 0)) + 1,
                    "last_seen_ts": now,
                }
                for item in base_rows
                if _lower(item["row"].get("provider") or item["row"].get("cloud_export_kind")) and _lower(item["row"].get("event_type") or item["row"].get("action"))
            },
        },
        "seen_suppressors": dict(Counter(tag for item in base_rows for tag in (item.get("suppressors") or []))),
        "updated_ts": now,
    }
    _save_persisted_baseline(org, persisted_payload)

    return {
        "assessment_id": assessment_id,
        "report_id": assessment_id,
        "status": "completed",
        "accepted_rows": len(rows),
        "rows_processed": len(rows),
        "processed": len(rows),
        "auto_llm": auto_llm,
        "org": org,
        "assessor": "offline-workbook",
        "rows": rows,
        "llm_rows": llm_rows,
        "results": results,
        "canonical": canonical,
        "findings": findings,
        "evidence_items": evidence_items,
        "attack_timeline": attack_timeline,
        "recommended_actions": recommended_actions,
        "impact_metadata": {
            "affected_identities": sorted(x for x in affected_identities if x)[:12],
            "affected_hosts": sorted(x for x in affected_hosts if x)[:12],
            "control_objectives": [
                "identity_access_review",
                "endpoint_lineage_validation",
                "network_containment_readiness",
            ],
            "corroborating_domains": corroborating_domains,
            "missing_evidence": sorted(set(missing_evidence)),
        },
        "risk_quantification": risk_quantification,
        "verdict": {
            "final_verdict": final_verdict,
            "final_confidence": round(max_confidence, 2),
            "all_factors": _rank_factor_entries(ranked_factors, len(rows))[:12],
            "top_contributing_factors": top_factors,
            "semantic_top_factors": semantic_top_factors,
            "supporting_model_factors": supporting_top_factors,
        },
        "tier_metadata": {
            "tier1_mode": "offline_evidence",
            "tier2_mode": "grounded_fallback" if auto_llm else "disabled",
            "calibration_status": {
                "mode": "replay_supervised_priors" if calibrations else "uncalibrated",
                "live_labeled_corpus": False,
                "provider_aware": bool(calibrations.get("providers")) if isinstance(calibrations, dict) else False,
                "source_path": os.getenv("OFFLINE_CALIBRATION_PATH", _DEFAULT_OFFLINE_CALIBRATION_PATH),
            },
            "ml_techniques": [
                "isolation_forest",
                "dbscan_density",
                "adaptive_ewma",
                "tfidf_rarity",
                "tenant_domain_baselines",
                "provider_action_frequency",
                "mad_outliering",
                "sequence_scoring",
                "graph_edge_anomaly",
                "provider_aware_calibration",
                "cross_sheet_pivoting",
            ],
        },
        "decision_record": {
            "verdict": final_verdict,
            "confidence": round(max_confidence, 2),
            "factors": [entry["factor_name"] for entry in top_factors[:8]],
            "hopgraph_context": {
                "assessment_id": assessment_id,
                "sheet_count": len({_sheet_name(row) for row in rows}),
                "suspicious_row_count": len(suspicious_rows),
                "corroborating_domains": corroborating_domains,
                "sequence_score": round(sequence_score, 2),
                "graph_anomaly_score": round(graph_anomaly_score, 2),
                "graph_path_score": round(graph_path_score, 2),
                "path_signature": graph_path,
                "factor_views": {
                    "semantic_top_factors": [entry["factor_name"] for entry in semantic_top_factors[:5]],
                    "supporting_model_factors": [entry["factor_name"] for entry in supporting_top_factors[:4]],
                },
                "chains": [{"nodes": graph_nodes[:8], "score": round(graph_anomaly_score, 2)}] if graph_nodes else [],
                "edges": graph_edges[:8],
            },
            "dependency_status": {
                "mode": "offline_replay",
                "healthy": True,
                "degraded": False,
            },
            "calibration_status": {
                "mode": "replay_supervised_priors" if calibrations else "uncalibrated",
                "live_labeled_corpus": False,
                "provider_aware": bool(calibrations.get("providers")) if isinstance(calibrations, dict) else False,
            },
            "evidence_summary": {
                "summary": canonical["llm_summary"],
                "items": highlighted_findings,
            },
            "recommendation_actions": recommended_actions[:4],
            "approval_state": {
                "required": final_verdict in {"THREAT", "SUSPICIOUS"} and corroboration_count >= 2,
                "status": "pending" if final_verdict in {"THREAT", "SUSPICIOUS"} and corroboration_count >= 2 else "not_required",
            },
        },
    }


def build_grounded_tier2_json(payload: Dict[str, Any]) -> Dict[str, Any]:
    rows = payload.get("rows") or []
    if not isinstance(rows, list):
        rows = []
    evidence_rows = rows[:8]
    assessment_id = payload.get("assessment_id") or f"tier2-{int(time.time() * 1000)}"
    offline = build_offline_workbook_assessment(rows, assessment_id=str(assessment_id), org=str(payload.get("org") or "unknown"), auto_llm=True)
    verdict = offline.get("verdict") or {}
    findings = offline.get("findings") or []
    evidence_items = offline.get("evidence_items") or []
    timeline = offline.get("attack_timeline") or []
    recommended_actions = offline.get("recommended_actions") or []
    return {
        "verdict": {
            "summary": verdict.get("final_verdict", "REVIEW"),
            "confidence": verdict.get("final_confidence", 0.0),
        },
        "actions": {
            "action_list": [entry.get("primary_action") for entry in recommended_actions[:4] if entry.get("primary_action")],
            "priority": (offline.get("risk_quantification") or {}).get("severity", "LOW").lower(),
        },
        "evidence": {
            "items": [
                {
                    "type": "finding",
                    "value": item.get("title"),
                    "confidence": item.get("confidence"),
                    "row_index": item.get("row_index"),
                    "sheet": item.get("sheet"),
                }
                for item in findings[:5]
            ],
            "missing_info": ["real EDR telemetry", "real identity logs"] if not evidence_rows else [],
        },
        "reasoning": {
            "narrative": offline.get("canonical", {}).get("llm_summary"),
            "top_factors": [entry.get("factor_name") for entry in (verdict.get("top_contributing_factors") or [])[:5]],
            "ml_techniques": offline.get("tier_metadata", {}).get("ml_techniques", []),
        },
        "timeline": [
            {
                "ts": entry.get("ts"),
                "event_type": entry.get("event_type"),
                "entity": entry.get("entity"),
                "summary": entry.get("summary"),
            }
            for entry in timeline[:6]
        ],
        "threat_intel": {
            "domains": sorted({domain for evidence in evidence_items for domain in (evidence.get("extracted_iocs", {}) or {}).get("domain", [])})[:6],
            "ips": sorted({ip for evidence in evidence_items for ip in (evidence.get("extracted_iocs", {}) or {}).get("ip", [])})[:6],
            "hashes": sorted({h for evidence in evidence_items for h in (evidence.get("extracted_iocs", {}) or {}).get("hash", [])})[:6],
        },
        "graph_context": {
            "assessment_id": assessment_id,
            "suspicious_rows": offline.get("canonical", {}).get("suspicious_row_count"),
            "sheet_count": offline.get("canonical", {}).get("sheet_count"),
        },
        "business_impact": offline.get("risk_quantification", {}),
        "recommendations": recommended_actions[:4],
        "controls": offline.get("mappings", {}).get("controls", []),
        "mitre": offline.get("mappings", {}).get("mitre", []),
        "next_steps": [entry.get("primary_action") for entry in recommended_actions[:3] if entry.get("primary_action")],
    }
