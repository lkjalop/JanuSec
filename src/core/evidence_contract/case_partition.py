"""Immutable case partitions and multi-resolution security episodes.

An assessment is a container, not an evidentiary case.  These contracts keep
separate investigations separate before retrieval or model narration begins.
They are deliberately deterministic: research retrieval may suggest a merge,
but only an explicit analyst decision may replace these boundaries.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .projection_builder import evidence_id_for_row
from .records import canonical_hash
from .semantic_adapters import normalize_semantics
from .graph_projection import MAPPING_VERSION, NORMALIZER_VERSION


def _timestamp(value: Any) -> dt.datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None


def _row_time(row: Mapping[str, Any]) -> dt.datetime | None:
    for key in ("occurred_at", "event_time", "event_ts", "timestamp", "time", "@timestamp"):
        parsed = _timestamp(row.get(key))
        if parsed is not None:
            return parsed
    return None


def _values(row: Mapping[str, Any], keys: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for key in keys:
        value = row.get(key)
        if value in (None, ""):
            continue
        values = value if isinstance(value, (list, tuple, set)) else (value,)
        for item in values:
            text = str(item).strip()
            if text and text not in result:
                result.append(text)
    return tuple(result)


def _phase(row: Mapping[str, Any]) -> str:
    return str(
        row.get("phase_id")
        or row.get("attack_phase")
        or row.get("case_role")
        or row.get("category")
        or row.get("source_type")
        or "observed_activity"
    ).strip().lower()


@dataclass(frozen=True, slots=True)
class SecurityEpisode:
    episode_id: str
    tenant_id: str
    assessment_id: str
    case_id: str
    resolution: str
    interval_start: str | None
    interval_end: str | None
    phase_ids: tuple[str, ...]
    entity_ids: tuple[str, ...]
    source_domains: tuple[str, ...]
    outcomes: tuple[str, ...]
    child_episode_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    event_count: int
    time_uncertainty_seconds: float = 0.0
    content_hash: str = field(init=False)

    schema_version = "janusec.security-episode/v2"

    def __post_init__(self) -> None:
        object.__setattr__(self, "content_hash", canonical_hash(self._content()))

    def _content(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "normalizer_version": NORMALIZER_VERSION,
            "mapping_version": MAPPING_VERSION,
            "episode_id": self.episode_id,
            "tenant_id": self.tenant_id,
            "assessment_id": self.assessment_id,
            "case_id": self.case_id,
            "resolution": self.resolution,
            "interval_start": self.interval_start,
            "interval_end": self.interval_end,
            "phase_ids": list(self.phase_ids),
            "entity_ids": list(self.entity_ids),
            "source_domains": list(self.source_domains),
            "outcomes": list(self.outcomes),
            "child_episode_ids": list(self.child_episode_ids),
            "evidence_ids": list(self.evidence_ids),
            "event_count": self.event_count,
            "time_uncertainty_seconds": self.time_uncertainty_seconds,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content(), "content_hash": self.content_hash}


@dataclass(frozen=True, slots=True)
class CasePartition:
    partition_id: str
    tenant_id: str
    assessment_id: str
    case_id: str
    status: str
    verdict: str
    title: str
    row_refs: tuple[int, ...]
    evidence_ids: tuple[str, ...]
    evidence_count: int
    source_artifacts: tuple[str, ...]
    source_count: int
    roles: tuple[dict[str, Any], ...]
    phase_ids: tuple[str, ...]
    interval_start: str | None
    interval_end: str | None
    supporting_cluster_ids: tuple[str, ...]
    episodes: tuple[SecurityEpisode, ...] = ()
    content_hash: str = field(init=False)

    schema_version = "janusec.case-partition/v5"

    def __post_init__(self) -> None:
        object.__setattr__(self, "content_hash", canonical_hash(self._content()))

    def _content(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "normalizer_version": NORMALIZER_VERSION,
            "mapping_version": MAPPING_VERSION,
            "partition_id": self.partition_id,
            "tenant_id": self.tenant_id,
            "assessment_id": self.assessment_id,
            "case_id": self.case_id,
            "status": self.status,
            "verdict": self.verdict,
            "title": self.title,
            "row_refs": list(self.row_refs),
            "evidence_ids": list(self.evidence_ids),
            "evidence_count": self.evidence_count,
            "source_artifacts": list(self.source_artifacts),
            "source_count": self.source_count,
            "roles": list(self.roles),
            "phase_ids": list(self.phase_ids),
            "interval_start": self.interval_start,
            "interval_end": self.interval_end,
            "supporting_cluster_ids": list(self.supporting_cluster_ids),
            "episodes": [episode.to_dict() for episode in self.episodes],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content(), "content_hash": self.content_hash}


def _build_episodes(
    *, tenant_id: str, assessment_id: str, case_id: str,
    indexed_rows: list[tuple[int, dict[str, Any]]],
    phases_by_ref: Mapping[int, tuple[str, ...]] | None = None,
) -> tuple[SecurityEpisode, ...]:
    hourly: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    undated: list[tuple[int, dict[str, Any]]] = []
    phases_by_ref = phases_by_ref or {}
    for item in indexed_rows:
        when = _row_time(item[1])
        if when is None:
            undated.append(item)
            continue
        row_phases = phases_by_ref.get(item[0]) or (_phase(item[1]),)
        for phase in row_phases:
            hourly[(when.strftime("%Y-%m-%dT%H:00:00%z"), phase)].append(item)
    if undated:
        for item in undated:
            row_phases = phases_by_ref.get(item[0]) or ("undated_activity",)
            for phase in row_phases:
                hourly[("unknown", phase)].append(item)

    hour_episodes: list[SecurityEpisode] = []
    for ordinal, ((bucket, phase), members) in enumerate(sorted(hourly.items())):
        times = sorted(value for _, row in members if (value := _row_time(row)) is not None)
        evidence_ids = tuple(evidence_id_for_row(assessment_id, index, normalize_semantics(dict(row))) for index, row in members)
        entities = sorted({value.lower() for _, row in members for value in _values(row, (
            "principal_id", "user_canonical", "user", "host", "hostname", "src_ip", "dst_ip",
            "target_resource", "resource_id", "process", "process_name", "destination",
        ))})
        sources = sorted({str(row.get("source_type") or row.get("_source_type") or row.get("cloud_provider") or "unknown").lower() for _, row in members})
        outcomes = sorted({str(row.get("action_outcome") or row.get("result") or "unknown").lower() for _, row in members})
        uncertainty = max((float(row.get("time_uncertainty_seconds") or 0) for _, row in members), default=0.0)
        identity = canonical_hash({"case": case_id, "resolution": "hour", "bucket": bucket, "phase": phase})[:24]
        hour_episodes.append(SecurityEpisode(
            episode_id=f"episode-hour-{identity}", tenant_id=tenant_id, assessment_id=assessment_id,
            case_id=case_id, resolution="hour", interval_start=times[0].isoformat() if times else None,
            interval_end=times[-1].isoformat() if times else None, phase_ids=(phase,),
            entity_ids=tuple(entities), source_domains=tuple(sources), outcomes=tuple(outcomes),
            child_episode_ids=(), evidence_ids=evidence_ids, event_count=len(members),
            time_uncertainty_seconds=uncertainty,
        ))

    by_day: dict[str, list[SecurityEpisode]] = defaultdict(list)
    for episode in hour_episodes:
        day = (episode.interval_start or "unknown")[:10]
        by_day[day].append(episode)
    day_episodes: list[SecurityEpisode] = []
    for day, children in sorted(by_day.items()):
        starts = sorted(value for item in children if (value := _timestamp(item.interval_start)) is not None)
        ends = sorted(value for item in children if (value := _timestamp(item.interval_end)) is not None)
        identity = canonical_hash({"case": case_id, "resolution": "day", "day": day})[:24]
        day_episodes.append(SecurityEpisode(
            episode_id=f"episode-day-{identity}", tenant_id=tenant_id, assessment_id=assessment_id,
            case_id=case_id, resolution="day", interval_start=starts[0].isoformat() if starts else None,
            interval_end=ends[-1].isoformat() if ends else None,
            phase_ids=tuple(sorted({phase for item in children for phase in item.phase_ids})),
            entity_ids=tuple(sorted({entity for item in children for entity in item.entity_ids})),
            source_domains=tuple(sorted({source for item in children for source in item.source_domains})),
            outcomes=tuple(sorted({outcome for item in children for outcome in item.outcomes})),
            child_episode_ids=tuple(item.episode_id for item in children),
            # Parent episodes retain lineage through immutable child IDs. Avoid
            # duplicating every raw evidence reference at every resolution.
            evidence_ids=(),
            event_count=sum(item.event_count for item in children),
            time_uncertainty_seconds=max((item.time_uncertainty_seconds for item in children), default=0.0),
        ))

    if not day_episodes:
        return tuple(hour_episodes)
    starts = sorted(value for item in day_episodes if (value := _timestamp(item.interval_start)) is not None)
    ends = sorted(value for item in day_episodes if (value := _timestamp(item.interval_end)) is not None)
    campaign = SecurityEpisode(
        episode_id=f"episode-campaign-{canonical_hash({'case': case_id, 'days': [item.episode_id for item in day_episodes]})[:24]}",
        tenant_id=tenant_id, assessment_id=assessment_id, case_id=case_id, resolution="campaign",
        interval_start=starts[0].isoformat() if starts else None, interval_end=ends[-1].isoformat() if ends else None,
        phase_ids=tuple(sorted({phase for item in day_episodes for phase in item.phase_ids})),
        entity_ids=tuple(sorted({entity for item in day_episodes for entity in item.entity_ids})),
        source_domains=tuple(sorted({source for item in day_episodes for source in item.source_domains})),
        outcomes=tuple(sorted({outcome for item in day_episodes for outcome in item.outcomes})),
        child_episode_ids=tuple(item.episode_id for item in day_episodes), evidence_ids=(),
        event_count=sum(item.event_count for item in day_episodes),
        time_uncertainty_seconds=max((item.time_uncertainty_seconds for item in day_episodes), default=0.0),
    )
    return tuple([*hour_episodes, *day_episodes, campaign])


def build_case_partitions(
    *, tenant_id: str, assessment_id: str, threat_cases: list[dict[str, Any]],
    analysis_clusters: list[dict[str, Any]], rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build stable non-overwriting case partitions from presentation cases."""

    clusters = {str(item.get("cluster_id") or item.get("case_id") or ""): item for item in analysis_clusters}
    partitions: list[CasePartition] = []
    row_by_ref: dict[int, dict[str, Any]] = {}
    for position, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        try:
            row_ref = int(row.get("row_index", position))
        except (TypeError, ValueError):
            row_ref = position
        row_by_ref[row_ref] = row
    for ordinal, case in enumerate(threat_cases):
        case_id = str(case.get("case_id") or case.get("cluster_id") or f"case-{ordinal}")
        refs = {int(value) for value in case.get("row_refs") or [] if str(value).lstrip("-").isdigit()}
        supporting_ids = tuple(str(value) for value in case.get("supporting_cluster_ids") or [] if value)
        if not supporting_ids and case_id in clusters:
            supporting_ids = (case_id,)
        for cluster_id in supporting_ids:
            refs.update(int(value) for value in (clusters.get(cluster_id, {}).get("row_refs") or []) if str(value).lstrip("-").isdigit())
        refs = {value for value in refs if value in row_by_ref}
        indexed_rows = [(row_ref, row_by_ref[row_ref]) for row_ref in sorted(refs)]
        times = sorted(value for _, row in indexed_rows if (value := _row_time(row)) is not None)
        phases = tuple(sorted({
            str(phase.get("phase_id") or phase.get("id") or "").strip()
            for phase in case.get("phases") or [] if isinstance(phase, Mapping) and (phase.get("phase_id") or phase.get("id"))
        }))
        if not phases:
            phases = tuple(sorted({_phase(row) for _, row in indexed_rows}))
        phases_by_ref: dict[int, set[str]] = defaultdict(set)
        phase_sources = [case, *(clusters.get(cluster_id, {}) for cluster_id in supporting_ids)]
        all_phase_ids = set(phases)
        for phase_source in phase_sources:
            for phase in phase_source.get("phases") or []:
                if not isinstance(phase, Mapping):
                    continue
                phase_id = str(phase.get("phase_id") or phase.get("id") or "").strip()
                if not phase_id:
                    continue
                all_phase_ids.add(phase_id)
                for value in phase.get("row_refs") or []:
                    try:
                        row_ref = int(value)
                    except (TypeError, ValueError):
                        continue
                    if row_ref in refs:
                        phases_by_ref[row_ref].add(phase_id)
        phases = tuple(sorted(all_phase_ids))
        verdict = str(case.get("final_verdict") or case.get("verdict") or "ANALYSIS_INCOMPLETE").upper()
        status = "background" if verdict in {
            "NO_VALIDATED_BREACH", "BENIGN", "BENIGN_EXPECTED", "FALSE_POSITIVE",
            "AUTHORIZED_ACTIVITY", "AUTHORIZED_CHANGE",
        } else "investigation"
        evidence_ids = tuple(evidence_id_for_row(assessment_id, index, normalize_semantics(dict(row))) for index, row in indexed_rows)
        source_artifacts = tuple(sorted({
            str(
                row.get("source_file") or row.get("_source") or row.get("source")
                or row.get("source_type") or row.get("_source_type") or "unknown"
            ).replace("\\", "/").rsplit("/", 1)[-1].lower()
            for _, row in indexed_rows
        }))
        episodes = _build_episodes(
            tenant_id=tenant_id, assessment_id=assessment_id, case_id=case_id, indexed_rows=indexed_rows,
            phases_by_ref={key: tuple(sorted(value)) for key, value in phases_by_ref.items()},
        )
        partition_id = f"cp_{canonical_hash({'tenant': tenant_id, 'assessment': assessment_id, 'case': case_id, 'rows': sorted(refs), 'verdict': verdict})}"
        roles = [dict(item) for item in case.get("entity_roles") or [] if isinstance(item, Mapping)]
        role_keys = {(str(item.get("role") or ""), str(item.get("entity") or "")) for item in roles}
        # Kerberos 4768 with pre-authentication disabled identifies the account
        # being requested/roasted. It is a target, not the initiating actor.
        for _, row in indexed_rows:
            event_id = str(row.get("windows_event_id") or row.get("EventID") or row.get("event_id") or "")
            preauth_value = row.get("pre_auth_type")
            if preauth_value is None:
                preauth_value = row.get("PreAuthType")
            preauth = str(preauth_value or "").lower()
            if event_id == "4768" and preauth in {"0", "0x0"}:
                target = str(
                    row.get("target_account") or row.get("TargetUserName")
                    or row.get("account_name") or ""
                ).strip().lower()
                if target and ("target", target) not in role_keys:
                    roles.append({
                        "role": "target", "entity": target, "status": "observed",
                        "basis": "kerberos_asrep_requested_account",
                    })
                    role_keys.add(("target", target))
        address_roles = (
            ("instrument", ("src_ip", "source_ip", "client_ip"), "event_source_address"),
            ("destination", ("dst_ip", "destination_ip", "server_ip"), "event_destination_address"),
        )
        for role, fields, basis in address_roles:
            values = {
                str(row.get(field)).strip()
                for _, row in indexed_rows for field in fields if row.get(field)
            }
            # Hundreds of rotating/background addresses are topology, not a
            # useful case-role assertion. Keep bounded explicit addresses and
            # leave the complete set in graph/evidence drill-down.
            if len(values) > 16:
                continue
            for value in sorted(values):
                if (role, value) not in role_keys:
                    roles.append({"role": role, "entity": value, "status": "observed", "basis": basis})
                    role_keys.add((role, value))
        actors = sorted({
            str(item.get("entity") or "").strip()
            for item in roles if str(item.get("role") or "").lower() == "actor" and item.get("entity")
        })
        disposition = (
            "Confirmed breach" if verdict in {"VALIDATED_BREACH", "CONFIRMED_BREACH", "CONFIRMED_INTRUSION"}
            else "Suspected activity" if verdict == "SUSPECTED_BREACH"
            else "Contextual activity"
        )
        subject = ", ".join(actors[:2]) if actors else "Unattributed activity"
        title = (
            f"{subject} · {disposition} · {len(phases)} phase(s) · "
            f"{len(evidence_ids)} evidence row(s) · {len(source_artifacts)} telemetry source(s)"
        )
        partitions.append(CasePartition(
            partition_id=partition_id, tenant_id=tenant_id, assessment_id=assessment_id,
            case_id=case_id, status=status, verdict=verdict,
            title=title,
            row_refs=tuple(sorted(refs)), evidence_ids=evidence_ids,
            evidence_count=len(evidence_ids), source_artifacts=source_artifacts,
            source_count=len(source_artifacts),
            roles=tuple(roles),
            phase_ids=phases, interval_start=times[0].isoformat() if times else None,
            interval_end=times[-1].isoformat() if times else None,
            supporting_cluster_ids=supporting_ids, episodes=episodes,
        ))
    return [partition.to_dict() for partition in partitions]


__all__ = ["CasePartition", "SecurityEpisode", "build_case_partitions"]
