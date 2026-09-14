from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path
from typing import Any, Iterable


DEFAULT_ARTIFACT_PATH = Path("models/calibration/confidence_v1.json")

_ARTIFACT_CACHE: tuple[str, float, dict[str, Any] | None] | None = None


def _as_probability(value: Any) -> float:
    try:
        val = float(value)
    except Exception:
        return 0.0
    if val > 1.0:
        val = val / 100.0
    return max(0.0, min(1.0, val))


def dataset_family(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "default"
    for token in ("vesper", "meridian", "santos", "alice"):
        if token in text:
            return token
    return text.replace(" ", "_")[:64]


def label_from_verdict(verdict: Any) -> int | None:
    text = str(verdict or "").strip().upper()
    if not text:
        return None
    if text in {"VALIDATED_BREACH", "CONFIRMED_BREACH", "CONFIRMED_INTRUSION", "LIKELY_REAL"}:
        return 1
    if text in {"BENIGN_EXPECTED", "NO_VALIDATED_BREACH", "FALSE_POSITIVE", "CLEARED", "BENIGN"}:
        return 0
    return None


def _cluster_confidence(cluster: dict[str, Any]) -> float:
    meter = cluster.get("confidence_meter") if isinstance(cluster.get("confidence_meter"), dict) else {}
    for value in (
        meter.get("total"),
        cluster.get("confidence"),
        cluster.get("verdict_confidence"),
        cluster.get("triage_score"),
    ):
        if value is not None:
            return _as_probability(value)
    return 0.0


def _cluster_factors(cluster: dict[str, Any]) -> set[str]:
    factors: set[str] = set()
    for key in ("factor_tags", "_chrono_factors", "_campaign_factor_tags", "factors"):
        values = cluster.get(key) or []
        if not isinstance(values, list):
            continue
        for item in values:
            if isinstance(item, dict):
                value = item.get("name") or item.get("factor") or item.get("id") or item.get("label")
            else:
                value = item
            text = str(value or "").strip()
            if text:
                factors.add(text)
    return factors


def samples_from_assessment(assessment: dict[str, Any], *, dataset: str | None = None) -> list[dict[str, Any]]:
    clusters = (
        assessment.get("clusters")
        or assessment.get("raw_correlation_clusters")
        or assessment.get("correlation_clusters")
        or assessment.get("analysis_clusters")
        or []
    )
    if not isinstance(clusters, list):
        return []
    family = dataset_family(dataset or assessment.get("org") or assessment.get("tenant_id") or assessment.get("assessment_id"))
    out: list[dict[str, Any]] = []
    for cluster in clusters:
        if not isinstance(cluster, dict):
            continue
        verdict = cluster.get("final_verdict") or cluster.get("verdict") or assessment.get("final_verdict") or assessment.get("verdict")
        label = label_from_verdict(verdict)
        if label is None:
            continue
        factors = _cluster_factors(cluster)
        sources = cluster.get("source_types") or cluster.get("sources") or []
        if not isinstance(sources, list):
            sources = []
        raw = _cluster_confidence(cluster)
        out.append(
            {
                "assessment_id": assessment.get("assessment_id"),
                "cluster_id": cluster.get("cluster_id") or cluster.get("id"),
                "raw_confidence": raw,
                "final_verdict": str(verdict or "").upper(),
                "ground_truth_label": label,
                "dataset": family,
                "source_count": int(cluster.get("source_count") or len(sources) or 0),
                "factor_count": len(factors),
            }
        )
    return out


def export_samples(assessment_paths: Iterable[str | os.PathLike[str]], out_path: str | os.PathLike[str] | None = None) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for path_like in assessment_paths:
        path = Path(path_like)
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            samples.extend(samples_from_assessment(data, dataset=str(path)))
    if out_path:
        dst = Path(out_path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(samples, indent=2, sort_keys=True), encoding="utf-8")
    return samples


def reliability_bins(samples: list[dict[str, Any]], *, bins: int = 10, score_key: str = "raw_confidence") -> list[dict[str, Any]]:
    buckets: list[list[dict[str, Any]]] = [[] for _ in range(max(1, bins))]
    for sample in samples:
        score = _as_probability(sample.get(score_key))
        idx = min(len(buckets) - 1, int(score * len(buckets)))
        buckets[idx].append(sample)
    out: list[dict[str, Any]] = []
    for idx, bucket in enumerate(buckets):
        if bucket:
            avg_conf = sum(_as_probability(s.get(score_key)) for s in bucket) / len(bucket)
            accuracy = sum(int(s.get("ground_truth_label") or 0) for s in bucket) / len(bucket)
        else:
            avg_conf = 0.0
            accuracy = 0.0
        out.append(
            {
                "bin": idx,
                "lower": idx / len(buckets),
                "upper": (idx + 1) / len(buckets),
                "count": len(bucket),
                "avg_confidence": avg_conf,
                "accuracy": accuracy,
                "gap": abs(avg_conf - accuracy),
            }
        )
    return out


def calibration_metrics(samples: list[dict[str, Any]], *, score_key: str = "raw_confidence", bins: int = 10) -> dict[str, Any]:
    if not samples:
        return {"count": 0, "brier": None, "ece": None, "bins": reliability_bins([], bins=bins)}
    brier = sum((_as_probability(s.get(score_key)) - int(s.get("ground_truth_label") or 0)) ** 2 for s in samples) / len(samples)
    bins_out = reliability_bins(samples, bins=bins, score_key=score_key)
    ece = sum((b["count"] / len(samples)) * b["gap"] for b in bins_out)
    return {"count": len(samples), "brier": brier, "ece": ece, "bins": bins_out}


def _fit_platt(samples: list[dict[str, Any]], *, score_key: str = "raw_confidence") -> dict[str, Any]:
    a = 1.0
    b = 0.0
    lr = 0.05
    xs = [_as_probability(s.get(score_key)) for s in samples]
    ys = [int(s.get("ground_truth_label") or 0) for s in samples]
    if not xs:
        return {"method": "platt", "a": a, "b": b}
    for _ in range(600):
        da = 0.0
        db = 0.0
        for x, y in zip(xs, ys):
            z = max(-30.0, min(30.0, a * x + b))
            p = 1.0 / (1.0 + math.exp(-z))
            da += (p - y) * x
            db += p - y
        n = max(1, len(xs))
        a -= lr * da / n
        b -= lr * db / n
    return {"method": "platt", "a": a, "b": b}


def _fit_isotonic(samples: list[dict[str, Any]], *, score_key: str = "raw_confidence") -> dict[str, Any]:
    pairs = sorted((_as_probability(s.get(score_key)), int(s.get("ground_truth_label") or 0)) for s in samples)
    if not pairs:
        return {"method": "isotonic", "points": []}
    blocks: list[dict[str, Any]] = []
    for x, y in pairs:
        blocks.append({"lo": x, "hi": x, "sum": float(y), "count": 1})
        while len(blocks) >= 2:
            left = blocks[-2]
            right = blocks[-1]
            if left["sum"] / left["count"] <= right["sum"] / right["count"]:
                break
            merged = {
                "lo": left["lo"],
                "hi": right["hi"],
                "sum": left["sum"] + right["sum"],
                "count": left["count"] + right["count"],
            }
            blocks[-2:] = [merged]
    points = [
        {"lo": b["lo"], "hi": b["hi"], "probability": max(0.0, min(1.0, b["sum"] / b["count"])), "count": b["count"]}
        for b in blocks
    ]
    return {"method": "isotonic", "points": points}


def fit_artifact(samples: list[dict[str, Any]], *, method: str = "platt", artifact_version: str = "confidence_v1") -> dict[str, Any]:
    families = sorted({dataset_family(s.get("dataset")) for s in samples} | {"default"})
    family_models: dict[str, Any] = {}
    for family in families:
        subset = [s for s in samples if dataset_family(s.get("dataset")) == family] or samples
        model = _fit_isotonic(subset) if method == "isotonic" else _fit_platt(subset)
        family_models[family] = {
            **model,
            "metrics_raw": calibration_metrics(subset, score_key="raw_confidence"),
        }
    return {
        "version": artifact_version,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": method,
        "families": family_models,
        "metrics_raw": calibration_metrics(samples, score_key="raw_confidence"),
        "sample_count": len(samples),
    }


def save_artifact(artifact: dict[str, Any], path: str | os.PathLike[str] = DEFAULT_ARTIFACT_PATH) -> None:
    dst = Path(path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")


def load_artifact(path: str | os.PathLike[str] | None = None) -> dict[str, Any] | None:
    global _ARTIFACT_CACHE
    raw_path = str(path or os.getenv("CONFIDENCE_CALIBRATION_PATH") or DEFAULT_ARTIFACT_PATH)
    p = Path(raw_path)
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return None
    if _ARTIFACT_CACHE and _ARTIFACT_CACHE[0] == raw_path and _ARTIFACT_CACHE[1] == mtime:
        return _ARTIFACT_CACHE[2]
    try:
        artifact = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        artifact = None
    _ARTIFACT_CACHE = (raw_path, mtime, artifact if isinstance(artifact, dict) else None)
    return _ARTIFACT_CACHE[2]


def apply_calibration(raw_confidence: float, *, dataset: str | None = None, artifact: dict[str, Any] | None = None) -> dict[str, Any]:
    raw = _as_probability(raw_confidence)
    artifact = artifact if artifact is not None else load_artifact()
    if not artifact:
        return {"probability": raw, "applied": False, "method": "none", "artifact": None, "family": dataset_family(dataset)}
    family = dataset_family(dataset)
    models = artifact.get("families") or {}
    model = models.get(family) or models.get("default")
    if not isinstance(model, dict):
        return {"probability": raw, "applied": False, "method": "none", "artifact": artifact.get("version"), "family": family}
    method = model.get("method") or artifact.get("method")
    if method == "isotonic":
        prob = raw
        for point in model.get("points") or []:
            if raw <= float(point.get("hi", 1.0)):
                prob = float(point.get("probability", raw))
                break
        else:
            points = model.get("points") or []
            prob = float(points[-1].get("probability", raw)) if points else raw
    else:
        a = float(model.get("a", 1.0))
        b = float(model.get("b", 0.0))
        z = max(-30.0, min(30.0, a * raw + b))
        prob = 1.0 / (1.0 + math.exp(-z))
    return {
        "probability": max(0.0, min(1.0, prob)),
        "applied": True,
        "method": str(method or "platt"),
        "artifact": artifact.get("version"),
        "family": family,
    }


__all__ = [
    "DEFAULT_ARTIFACT_PATH",
    "apply_calibration",
    "calibration_metrics",
    "dataset_family",
    "export_samples",
    "fit_artifact",
    "label_from_verdict",
    "load_artifact",
    "reliability_bins",
    "samples_from_assessment",
    "save_artifact",
]
