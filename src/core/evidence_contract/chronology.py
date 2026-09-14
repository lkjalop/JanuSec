"""Case-scoped chronology compilation with explicit epistemic relationships.

Chronological adjacency is never promoted to causality.  This compiler is the
single boundary between normalized evidence and narrative/presentation views.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any, Callable, Iterable

from .correlation import EdgeType, TypedEdge
from .projection_builder import evidence_id_for_row
from .records import canonical_hash
from .semantic_adapters import normalize_semantics


CHRONOLOGY_SCHEMA_VERSION = "janusec.case-chronology/v1"

_PHASE_MAP: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("initial_access", ("phish", "spear", "bec", "initial access", "credential harvest", "password spray"), ("T1566", "T1078", "T1110")),
    ("credential_access", ("credential", "lsass", "mimikatz", "kerberoast", "token theft", "mfa fatigue"), ("T1003", "T1558", "T1621")),
    ("execution", ("powershell", "cmd.exe", "wscript", "mshta", "execute", "execution"), ("T1059", "T1218")),
    ("persistence", ("persist", "scheduled task", "registry run", "service binary", "backdoor", "startup"), ("T1053", "T1547", "T1543")),
    ("privilege_escalation", ("privilege", "escalat", "sudo", "global admin", "domain admin", "uac bypass"), ("T1548", "T1068", "T1134")),
    ("discovery", ("discovery", "enumerat", "scan", "recon", "bloodhound", "sharphound", "nslookup"), ("T1018", "T1082", "T1087")),
    ("lateral_movement", ("lateral", "rdp", "psexec", "wmiexec", "smb", "pass the hash", "dcom", "ssh"), ("T1021", "T1550")),
    ("collection", ("collect", "staging", "archive", "compress", "screenshot", "keylog"), ("T1560", "T1113")),
    ("exfiltration", ("exfil", "rclone", "mega", "backblaze", "azcopy", "gsutil", "copy_into", "hetzner"), ("T1567", "T1048")),
    ("command_and_control", ("c2", "beacon", "dns tunnel", "cobalt", "command-and-control"), ("T1071", "T1572", "T1573")),
)

_TIME_KEYS = ("occurred_at", "event_time", "event_ts", "timestamp", "ts", "time", "date", "@timestamp")


def _first(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    return None


def parse_event_time(value: Any) -> dict[str, Any]:
    """Return an aware UTC time plus non-destructive source-time metadata."""

    result: dict[str, Any] = {
        "occurred_at": None,
        "original_timestamp": None if value is None else str(value),
        "source_timezone": None,
        "time_precision": "unknown",
    }
    if value in (None, ""):
        return result
    parsed: dt.datetime | None = None
    if isinstance(value, dt.datetime):
        parsed = value
        result["time_precision"] = "microsecond" if value.microsecond else "second"
    elif isinstance(value, (int, float)):
        try:
            parsed = dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc)
            result["time_precision"] = "epoch_millisecond" if abs(float(value)) >= 1e11 else "epoch_second"
            if result["time_precision"] == "epoch_millisecond":
                parsed = dt.datetime.fromtimestamp(float(value) / 1000.0, tz=dt.timezone.utc)
        except (OSError, OverflowError, ValueError):
            parsed = None
    elif isinstance(value, str):
        text = value.strip()
        try:
            if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", text):
                return parse_event_time(float(text)) | {"original_timestamp": text}
            iso = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
            parsed = dt.datetime.fromisoformat(iso)
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
                result["time_precision"] = "day"
            elif "." in text:
                result["time_precision"] = "fractional_second"
            else:
                result["time_precision"] = "second"
        except ValueError:
            parsed = None
    if parsed is None:
        return result
    if parsed.tzinfo is None:
        result["source_timezone"] = "unspecified_assumed_utc"
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    else:
        offset = parsed.utcoffset() or dt.timedelta(0)
        result["source_timezone"] = f"UTC{offset.total_seconds() / 3600:+g}"
        parsed = parsed.astimezone(dt.timezone.utc)
    result["occurred_at"] = parsed.isoformat().replace("+00:00", "Z")
    return result


def _phase(row: dict[str, Any]) -> tuple[str, list[str]]:
    explicit = str(_first(row, "attack_milestone", "kill_chain_stage", "phase", "phase_id") or "").strip().lower()
    if explicit:
        return explicit, []
    text = " ".join(
        str(_first(row, name) or "")
        for name in ("summary", "description", "event_name", "eventName", "action_name", "action", "process", "process_name", "command_line", "url")
    ).lower()
    for phase, keywords, candidates in _PHASE_MAP:
        if any(keyword in text for keyword in keywords):
            return phase, list(candidates)
    return "unknown", []


def _techniques(row: dict[str, Any]) -> list[str]:
    values = _first(row, "observed_mitre_techniques", "mitre_techniques", "technique_ids", "technique_id") or []
    if not isinstance(values, (list, tuple, set)):
        values = [values]
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _actor(row: dict[str, Any]) -> tuple[str, str, str]:
    strong = _first(row, "principal_id", "principal_arn", "user_sid", "user_object_id")
    if strong:
        return str(strong), "provider_identifier", str(_first(row, "actor_role", "case_role", "role") or "actor")
    actor = _first(row, "user_canonical", "user", "actor", "principal", "src_ip", "source_ip")
    basis = str(row.get("_entity_owner_method") or ("source_field" if actor else "unknown"))
    return str(actor or "unknown"), basis, str(_first(row, "actor_role", "case_role", "role") or "actor")


def _target(row: dict[str, Any]) -> str | None:
    value = _first(row, "target_resource", "resource_id", "resource", "object_key", "dst_ip", "destination", "host", "hostname")
    return str(value) if value not in (None, "") else None


def compile_case_chronology(
    *,
    tenant_id: str,
    assessment_id: str,
    case_id: str,
    rows: Iterable[dict[str, Any]],
    allowed_evidence_ids: Iterable[str] | None = None,
    explicit_edges: Iterable[dict[str, Any]] = (),
    evidence_id_fn: Callable[[str, int, dict[str, Any]], str] = evidence_id_for_row,
) -> dict[str, Any]:
    """Compile one case.  Evidence from another partition is never admitted."""

    allowed = {str(value) for value in (allowed_evidence_ids or ())}
    milestones: list[dict[str, Any]] = []
    unsequenced: list[dict[str, Any]] = []
    lineage: list[dict[str, Any]] = []
    relations: list[dict[str, Any]] = []
    evidence_to_milestone: dict[str, str] = {}

    for index, original in enumerate(rows):
        if not isinstance(original, dict):
            continue
        row = normalize_semantics(dict(original))
        evidence_id = evidence_id_fn(assessment_id, index, row)
        if allowed and evidence_id not in allowed:
            continue
        phase, candidate_techniques = _phase(row)
        actor, actor_basis, actor_role = _actor(row)
        target = _target(row)
        time_value = _first(row, *_TIME_KEYS)
        time_meta = parse_event_time(time_value)
        milestone_id = f"milestone_{canonical_hash({'case': case_id, 'evidence': evidence_id})[:24]}"
        milestone = {
            "id": milestone_id,
            "phase_id": milestone_id,
            "case_id": case_id,
            "phase": phase,
            "title": str(_first(row, "description", "summary", "event_name", "eventName", "action_name", "action") or phase.replace("_", " "))[:240],
            "action": str(_first(row, "description", "summary", "event_name", "eventName", "action_name", "action") or "")[:500],
            "actor": actor,
            "actor_role": actor_role,
            "actor_basis": actor_basis,
            "target": target,
            "action_name": row.get("action_name"),
            "action_direction": row.get("action_direction"),
            "action_outcome": row.get("action_outcome", "unknown"),
            "occurred_at": time_meta["occurred_at"],
            "original_timestamp": time_meta["original_timestamp"],
            "source_timezone": time_meta["source_timezone"],
            "time_precision": str(row.get("time_precision") or time_meta["time_precision"]),
            "clock_offset_seconds": float(row.get("clock_offset_seconds") or 0.0),
            "clock_uncertainty_seconds": float(row.get("clock_uncertainty_seconds") or row.get("time_uncertainty_seconds") or 0.0),
            "evidence_ids": [evidence_id],
            "evidence_row_ids": [row.get("row_index", index)],
            "mitre_techniques": _techniques(row),
            "candidate_mitre_techniques": candidate_techniques,
            "enables_phase_id": None,
            "relation_to_next": None,
        }
        evidence_to_milestone[evidence_id] = milestone_id
        lineage.append({
            "lineage_type": "evidence_to_milestone",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "derived_artifact_id": milestone_id,
        })
        (milestones if time_meta["occurred_at"] else unsequenced).append(milestone)

        # Keep denied attempts visible as milestones without emitting a
        # successful interaction/exposure edge downstream could overstate.
        if actor != "unknown" and target and milestone["action_outcome"] != "denied":
            relationship = "configured_exposure" if row.get("action_direction") == "mailbox_to_forward_destination" else "observed_interaction"
            relations.append({
                "source": actor,
                "target": target,
                "relation_type": relationship,
                "case_id": case_id,
                "evidence_ids": [evidence_id],
                "basis": [str(row.get("action_direction") or "same_event")],
            })
        parent = _first(row, "parent_process", "parent_image", "ParentImage")
        process = _first(row, "process", "process_name", "Image", "image")
        if parent and process:
            relations.append({
                "source": str(parent), "target": str(process),
                "relation_type": "observed_causal", "case_id": case_id,
                "evidence_ids": [evidence_id], "basis": ["process_parentage"],
            })

    milestones.sort(key=lambda item: (str(item["occurred_at"]), str(item["id"])))
    for current, following in zip(milestones, milestones[1:]):
        relation = {
            "source": current["id"], "target": following["id"],
            "relation_type": "temporal_precedes", "case_id": case_id,
            "evidence_ids": sorted({*current["evidence_ids"], *following["evidence_ids"]}),
            "basis": ["utc_ordering_only"],
        }
        relations.append(relation)
        current["relation_to_next"] = "temporal_precedes"

    for raw in explicit_edges:
        try:
            edge = TypedEdge.from_dict(raw)
        except (TypeError, ValueError):
            continue
        if edge.edge_type is not EdgeType.OBSERVED_CAUSAL:
            continue
        refs = set(edge.evidence_ids)
        if not refs or (allowed and not refs <= allowed):
            continue
        endpoint_ids = [evidence_to_milestone.get(ref) for ref in edge.evidence_ids]
        endpoint_ids = [value for value in endpoint_ids if value]
        if len(endpoint_ids) >= 2:
            source_id, target_id = endpoint_ids[0], endpoint_ids[-1]
            relations.append({
                "source": source_id, "target": target_id,
                "relation_type": "observed_causal", "case_id": case_id,
                "evidence_ids": list(edge.evidence_ids), "basis": list(edge.match_basis),
            })
            by_id = {item["id"]: item for item in milestones}
            if source_id in by_id:
                by_id[source_id]["enables_phase_id"] = target_id
                by_id[source_id]["relation_to_next"] = "observed_causal"

    content = {
        "schema_version": CHRONOLOGY_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "assessment_id": assessment_id,
        "case_id": case_id,
        "milestones": milestones,
        "unsequenced": unsequenced,
        "relations": relations,
        "lineage": lineage,
    }
    return {**content, "content_hash": canonical_hash(content)}


def compile_partitioned_chronologies(
    *, tenant_id: str, assessment_id: str, rows: Iterable[dict[str, Any]], partitions: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    row_list = list(rows)
    return [
        compile_case_chronology(
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            case_id=str(partition.get("case_id") or partition.get("partition_id")),
            rows=row_list,
            allowed_evidence_ids=partition.get("evidence_ids") or (),
        )
        for partition in partitions
        if isinstance(partition, dict) and partition.get("status") != "background"
    ]


__all__ = ["CHRONOLOGY_SCHEMA_VERSION", "compile_case_chronology", "compile_partitioned_chronologies", "parse_event_time"]
