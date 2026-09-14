"""Low-and-slow campaign accumulation beside (not inside) EWMA.

EWMA highlights local rate changes.  This accumulator preserves weak evidence
that recurs across days, phases, and telemetry domains so a quiet campaign is
not forgotten merely because no individual time bucket spikes.
"""

from __future__ import annotations

import datetime as dt
import math
from collections import defaultdict
from typing import Any, Mapping

from src.core.evidence_contract.records import canonical_hash


def _time(row: Mapping[str, Any]) -> dt.datetime | None:
    for key in ("occurred_at", "event_time", "event_ts", "timestamp", "time", "@timestamp"):
        value = row.get(key)
        if not value:
            continue
        try:
            parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
        except Exception:
            continue
    return None


def _principal(row: Mapping[str, Any]) -> str:
    for key in ("principal_id", "user_canonical", "user", "userName", "actor", "mailbox", "host", "hostname"):
        value = str(row.get(key) or "").strip().lower()
        if value:
            return value
    return ""


def _signal(row: Mapping[str, Any]) -> str:
    for key in ("phase_id", "attack_phase", "factor", "anomaly_type", "category", "action_name", "eventName"):
        value = str(row.get(key) or "").strip().lower()
        if value:
            return value
    return "observed_activity"


def accumulate_low_and_slow(
    rows: list[dict[str, Any]], *, half_life_days: float = 14.0,
    minimum_active_days: int = 3, minimum_domains: int = 2, minimum_signals: int = 2,
) -> list[dict[str, Any]]:
    """Return candidate campaign accumulations without changing breach verdicts."""

    grouped: dict[str, list[tuple[dt.datetime, dict[str, Any]]]] = defaultdict(list)
    for row in rows:
        if not isinstance(row, dict):
            continue
        when, entity = _time(row), _principal(row)
        if when is not None and entity:
            grouped[entity].append((when, row))

    results: list[dict[str, Any]] = []
    for entity, events in grouped.items():
        events.sort(key=lambda item: item[0])
        reference = events[-1][0]
        days = {when.date().isoformat() for when, _ in events}
        domains = {
            str(row.get("source_type") or row.get("_source_type") or row.get("cloud_provider") or "unknown").lower()
            for _, row in events
        }
        signals = {_signal(row) for _, row in events}
        daily_counts: dict[str, int] = defaultdict(int)
        score = 0.0
        for when, row in events:
            daily_counts[when.date().isoformat()] += 1
            age_days = max(0.0, (reference - when).total_seconds() / 86400.0)
            decay = math.exp(-math.log(2.0) * age_days / max(0.1, half_life_days))
            strength = float(row.get("triage_score") or row.get("risk_score") or 0.25)
            score += min(1.0, max(0.05, strength)) * decay
        qualifies = len(days) >= minimum_active_days and len(domains) >= minimum_domains and len(signals) >= minimum_signals
        if not qualifies:
            continue
        span_days = max(1, (events[-1][0].date() - events[0][0].date()).days + 1)
        results.append({
            "record_type": "campaign_accumulation",
            "schema_version": "janusec.campaign-accumulation/v1",
            "entity_id": entity,
            "interval_start": events[0][0].isoformat(),
            "interval_end": events[-1][0].isoformat(),
            "span_days": span_days,
            "active_days": len(days),
            "source_domains": sorted(domains),
            "signal_types": sorted(signals),
            "event_count": len(events),
            "peak_daily_count": max(daily_counts.values()),
            "decayed_evidence_score": round(score, 6),
            "half_life_days": half_life_days,
            "classification": "low_and_slow_candidate",
            "epistemic_status": "candidate_not_breach_truth",
        })
    for result in results:
        result["content_hash"] = canonical_hash(result)
    return sorted(results, key=lambda item: (-float(item["decayed_evidence_score"]), item["entity_id"]))


__all__ = ["accumulate_low_and_slow"]
