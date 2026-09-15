"""Telemetry-specific corrective checks for Evidence Pack compilation."""

from __future__ import annotations

import datetime as dt
from typing import Any


def _time(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def action_outcome_policy(
    selected: list[dict[str, Any]], eligible: list[dict[str, Any]], _edges: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Find denied/failed records that challenge a claimed successful action."""
    successful_keys: set[tuple[str, str]] = set()
    for row in selected:
        outcome = str(row.get("action_outcome") or row.get("outcome") or "").lower()
        if outcome in {"success", "succeeded", "allowed", "ok"}:
            successful_keys.add((
                str(row.get("action_name") or row.get("eventName") or row.get("operation") or "").lower(),
                str(row.get("target_resource") or row.get("resource_id") or "").lower(),
            ))
    results = []
    for row in eligible:
        outcome = str(row.get("action_outcome") or row.get("outcome") or "").lower()
        key = (
            str(row.get("action_name") or row.get("eventName") or row.get("operation") or "").lower(),
            str(row.get("target_resource") or row.get("resource_id") or "").lower(),
        )
        if key in successful_keys and outcome in {"denied", "failed", "failure", "blocked"}:
            results.append({
                "policy": "action_outcome",
                "status": "contradiction_candidate",
                "evidence_id": row.get("evidence_id") or row.get("record_id"),
                "reason": "same_action_and_resource_has_denied_or_failed_observation",
            })
    return results


def cloud_direction_policy(
    _selected: list[dict[str, Any]], eligible: list[dict[str, Any]], _edges: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    results = []
    for row in eligible:
        action = str(row.get("action_name") or row.get("eventName") or "").lower().replace("_", "")
        claimed = str(row.get("attack_milestone") or row.get("_anomaly") or "").lower()
        if "putobject" in action and "exfil" in claimed:
            results.append({
                "policy": "cloud_action_direction",
                "status": "semantic_conflict",
                "evidence_id": row.get("evidence_id") or row.get("record_id"),
                "reason": "PutObject is principal-to-resource and cannot alone prove outbound exfiltration",
            })
    return results


def process_parent_time_policy(
    selected: list[dict[str, Any]], eligible: list[dict[str, Any]], _edges: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Expose child-before-parent observations instead of forcing causal order."""

    selected_users = {
        str(row.get("user") or row.get("user_name") or row.get("principal_id") or "").lower()
        for row in selected
    } - {""}
    selected_devices = {
        str(row.get("hostname") or row.get("device_id") or row.get("host") or "").lower()
        for row in selected
    } - {""}
    processes: dict[tuple[str, str], list[dict[str, Any]]] = {}
    processes_by_name: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    scoped: list[dict[str, Any]] = []
    for row in eligible:
        user = str(row.get("user") or row.get("user_name") or row.get("principal_id") or "").lower()
        device = str(row.get("hostname") or row.get("device_id") or row.get("host") or "").lower()
        if selected_users or selected_devices:
            if user not in selected_users and device not in selected_devices:
                continue
        pid = row.get("process_id") or row.get("ProcessId") or row.get("ProcessID")
        if pid not in (None, "") and device:
            processes.setdefault((device, str(pid)), []).append(row)
        image = str(row.get("image_file_name") or row.get("process") or row.get("Image") or "").lower()
        if device and image:
            processes_by_name.setdefault((device, user, image), []).append(row)
        scoped.append(row)

    results: list[dict[str, Any]] = []
    for child in scoped:
        device = str(child.get("hostname") or child.get("device_id") or child.get("host") or "").lower()
        parent_pid = child.get("parent_process_id") or child.get("ParentProcessId") or child.get("ParentProcessID")
        child_time = _time(child.get("occurred_at") or child.get("event_time") or child.get("timestamp"))
        if not device or child_time is None:
            continue
        parents = processes.get((device, str(parent_pid))) or [] if parent_pid not in (None, "") else []
        match_basis = "parent_process_id"
        if not parents:
            command = str(child.get("command_line") or child.get("CommandLine") or "").lower()
            parent_name = str(child.get("parent_process_name") or child.get("ParentImage") or "").lower()
            suspicious_child = any(token in command for token in ("encoded", "-enc", "bypass", "hidden"))
            if parent_name and suspicious_child:
                user = str(child.get("user") or child.get("user_name") or child.get("principal_id") or "").lower()
                parents = processes_by_name.get((device, user, parent_name)) or []
                match_basis = "parent_process_name_without_matching_pid"
        future_parents = [
            (parent, _time(parent.get("occurred_at") or parent.get("event_time") or parent.get("timestamp")))
            for parent in parents
        ]
        future_parents = [
            (parent, when)
            for parent, when in future_parents
            if when and child_time < when <= child_time + dt.timedelta(minutes=5)
        ]
        if not future_parents:
            continue
        parent, parent_time = min(future_parents, key=lambda item: item[1])
        delta = (parent_time - child_time).total_seconds()
        results.append({
            "policy": "process_parent_time",
            "status": "clock_or_order_conflict",
            "evidence_id": child.get("evidence_id") or child.get("record_id"),
            "related_evidence_id": parent.get("evidence_id") or parent.get("record_id"),
            "reason": "child_process_observed_before_referenced_parent_process",
            "delta_seconds": delta,
            "match_basis": match_basis,
        })
    return results


DEFAULT_CONTRADICTION_POLICIES = [action_outcome_policy, cloud_direction_policy, process_parent_time_policy]

__all__ = [
    "DEFAULT_CONTRADICTION_POLICIES", "action_outcome_policy", "cloud_direction_policy",
    "process_parent_time_policy",
]
