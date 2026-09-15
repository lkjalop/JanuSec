"""
Replay Cyberstash CSV sample to measure tier distribution after scoring adjustments.

This is a lightweight diagnostic that does not hit the API. It loads the CSV,
derives a pseudo confidence value from Cyberstash columns, applies the new
adjust_confidence helper, and reports how many rows fall into each tier hint.
"""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from typing import Any

from src.core.event_pipeline.scoring import adjust_confidence


def _load_rows(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        return [dict(row) for row in reader]


def _base_confidence(row: dict[str, Any]) -> float:
    threat_weight = float(row.get("threatWeight") or 0.0)
    av_pos = float(row.get("avPositives") or 0.0)
    suspicious = str(row.get("suspicious") or "").lower() == "true"
    base = min(1.0, (threat_weight / 10.0) * 0.4 + (av_pos / 50.0) * 0.4)
    if suspicious:
        base += 0.15
    threat_score = float(row.get("threatScore") or 0.0)
    if threat_score:
        base += min(0.2, threat_score / 100.0)
    return max(0.0, min(1.0, base))


def _build_event(row: dict[str, Any]) -> dict[str, Any]:
    event = {
        "host": row.get("host") or row.get("hostname") or row.get("device_hostname"),
        "user": row.get("user") or row.get("username") or row.get("userPrincipalName"),
        "parent_process": row.get("parent_process"),
        "signer": row.get("signer_subject") or row.get("publisher"),
        "flag_name": row.get("flagName"),
        "signature_status": row.get("signed"),
        "signature_valid": str(row.get("signed") or "").lower() in {"true", "1", "yes"},
        "process_name": row.get("name"),
        "verdict": row.get("verdict") or row.get("threatName"),
    }
    return event


def _derive_factors(row: dict[str, Any]) -> list[str]:
    factors: list[str] = []
    if str(row.get("suspicious") or "").lower() == "true":
        factors.append("novel_global")
    av_pos = float(row.get("avPositives") or 0.0)
    if av_pos >= 10:
        factors.append("av_high_consensus")
    elif av_pos > 0:
        factors.append("av_low_consensus")
    if str(row.get("path") or "").lower().find("\\temp\\") >= 0:
        factors.append("temp_dropper_path")
    if str(row.get("signed") or "").lower() in {"false", "0"}:
        factors.append("unsigned_sensitive_path")
    return factors


def main() -> None:
    sample_path = Path("reports/cyberstash_csv2_report.csv")
    if not sample_path.exists():
        raise SystemExit(f"Sample file not found: {sample_path}")

    rows = _load_rows(sample_path)
    tier_counter: Counter[str] = Counter()
    for row in rows:
        base_conf = _base_confidence(row)
        event = _build_event(row)
        factors = _derive_factors(row)
        adjusted, meta = adjust_confidence(event, factors, base_conf)
        tier = meta.get("tier") or "unknown"
        tier_counter[tier] += 1

    total = sum(tier_counter.values()) or 1
    print(f"Analyzed {total} rows from {sample_path}")
    for tier, count in tier_counter.most_common():
        percent = (count / total) * 100
        print(f"  {tier:18s} {count:4d} rows ({percent:5.1f}%)")


if __name__ == "__main__":
    main()
