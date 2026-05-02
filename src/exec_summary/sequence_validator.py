"""Attack sequence validator.

Validates temporal ordering and ATT&CK kill-chain phase coherence
across a cluster's evidence rows. Surfaces:

- Temporal gaps (dwell time between phases)
- Out-of-order phase transitions (possible artifacts or mis-clustering)
- Phase coverage (which kill-chain stages are evidenced)
- Sequence narrative (machine-readable summary for the LLM prompt)

This is the "sequence-aware" piece that enables the adversarial reasoner
to say things like "the exfiltration event at T+72h preceded any
lateral movement — that's anomalous and weakens the kill-chain narrative."
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

# ATT&CK kill-chain phases in canonical order.
# Phase order is used to validate that the observed sequence is plausible.
_PHASE_ORDER: dict[str, int] = {
    'reconnaissance':        1,
    'resource_development':  2,
    'initial_access':        3,
    'execution':             4,
    'persistence':           5,
    'privilege_escalation':  5,
    'defense_evasion':       5,
    'credential_access':     6,
    'discovery':             6,
    'lateral_movement':      7,
    'collection':            8,
    'command_and_control':   8,
    'exfiltration':          9,
    'impact':               10,
}

# Row-level field that might carry a phase tag
_PHASE_FIELD_CANDIDATES = [
    'kill_chain_phase', 'phase', 'mitre_phase', 'tactic',
    'attack_phase', 'stage',
]

# Keyword → phase inference when no explicit field is present
_PHASE_INFERENCE: list[tuple[str, str]] = [
    ('phish', 'initial_access'),
    ('brute', 'initial_access'),
    ('login fail', 'initial_access'),
    ('powershell', 'execution'),
    ('cmd.exe', 'execution'),
    ('script', 'execution'),
    ('scheduled task', 'persistence'),
    ('registry', 'persistence'),
    ('autorun', 'persistence'),
    ('admin', 'privilege_escalation'),
    ('elevation', 'privilege_escalation'),
    ('lsass', 'credential_access'),
    ('ntds', 'credential_access'),
    ('credential', 'credential_access'),
    ('discovery', 'discovery'),
    ('rdp', 'lateral_movement'),
    ('smb', 'lateral_movement'),
    ('psexec', 'lateral_movement'),
    ('wmi', 'lateral_movement'),
    ('lateral', 'lateral_movement'),
    ('compress', 'collection'),
    ('archive', 'collection'),
    ('staging', 'collection'),
    ('exfil', 'exfiltration'),
    ('upload', 'exfiltration'),
    ('rclone', 'exfiltration'),
    ('c2', 'command_and_control'),
    ('beacon', 'command_and_control'),
    ('callback', 'command_and_control'),
    ('encrypt', 'impact'),
    ('ransom', 'impact'),
    ('wipe', 'impact'),
    ('delete', 'impact'),
]


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    """Parse an ISO timestamp, tolerant of fractional seconds and trailing Z."""
    if not ts:
        return None
    try:
        s = re.sub(r'\.\d+', '', str(ts)).rstrip('Z').strip()
        return datetime.strptime(s, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    except Exception:
        try:
            return datetime.fromisoformat(str(ts).rstrip('Z').strip()).replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _infer_phase(row: dict) -> Optional[str]:
    """Infer ATT&CK phase from a row's fields or description text."""
    # Explicit phase field
    for field in _PHASE_FIELD_CANDIDATES:
        val = row.get(field)
        if val:
            v = str(val).lower().replace('-', '_').replace(' ', '_')
            if v in _PHASE_ORDER:
                return v

    # Infer from description / event_type
    text = ' '.join([
        str(row.get('description') or ''),
        str(row.get('event_type') or ''),
        str(row.get('action') or ''),
    ]).lower()
    for keyword, phase in _PHASE_INFERENCE:
        if keyword in text:
            return phase

    return None


class SequenceValidator:
    """Validate the temporal and ATT&CK phase sequence of cluster evidence."""

    def validate(self, rows: list[dict]) -> dict:
        """Validate a cluster's evidence rows.

        Returns:
            {
              phase_sequence: [{phase, ts, row_index, order}],
              phase_coverage: [str],
              phases_missing: [str],
              out_of_order: [{expected_before, found_after, delta_seconds}],
              first_event_ts: str | None,
              last_event_ts: str | None,
              total_duration_hours: float | None,
              dwell_gaps: [{phase_from, phase_to, gap_hours}],
              phase_count: int,
              sequence_coherent: bool,
              sequence_narrative: str,
              anomalies: [str],
            }
        """
        # Tag each row with phase + timestamp
        tagged: list[dict] = []
        for r in rows:
            phase = _infer_phase(r)
            ts = None
            for tf in ('timestamp_utc', 'timestamp', '@timestamp', 'event_ts',
                       'event_time', 'start_time', 'time', 'ts'):
                v = r.get(tf)
                if v:
                    ts = _parse_ts(str(v))
                    if ts:
                        break
            tagged.append({
                'row_index': r.get('row_index'),
                'phase': phase,
                'ts': ts,
                'ts_iso': ts.isoformat() if ts else None,
                'order': _PHASE_ORDER.get(phase, 0) if phase else 0,
            })

        # Sort by timestamp, then by phase order for ties
        timestamped = [t for t in tagged if t['ts'] is not None]
        timestamped.sort(key=lambda t: (t['ts'], t['order']))

        # Phase sequence (phases that appear, in temporal order)
        phase_sequence = [t for t in timestamped if t['phase']]
        seen_phases: list[str] = []
        for t in phase_sequence:
            if not seen_phases or seen_phases[-1] != t['phase']:
                seen_phases.append(t['phase'])

        phase_coverage = list(dict.fromkeys(t['phase'] for t in phase_sequence))

        # Detect out-of-order phase transitions
        out_of_order: list[dict] = []
        for i in range(1, len(phase_sequence)):
            prev = phase_sequence[i - 1]
            curr = phase_sequence[i]
            if curr['order'] < prev['order'] and curr['phase'] != prev['phase']:
                delta = (curr['ts'] - prev['ts']).total_seconds() if curr['ts'] and prev['ts'] else None
                out_of_order.append({
                    'expected_before': curr['phase'],
                    'found_after': prev['phase'],
                    'prev_order': prev['order'],
                    'curr_order': curr['order'],
                    'delta_seconds': round(delta, 0) if delta is not None else None,
                    'row_index_prev': prev['row_index'],
                    'row_index_curr': curr['row_index'],
                })

        # Time range
        all_ts = [t['ts'] for t in timestamped if t['ts']]
        first_ts = min(all_ts) if all_ts else None
        last_ts = max(all_ts) if all_ts else None
        duration_hours = (
            round((last_ts - first_ts).total_seconds() / 3600, 2)
            if first_ts and last_ts and first_ts != last_ts else None
        )

        # Dwell gaps: time between consecutive distinct phases
        dwell_gaps: list[dict] = []
        phase_first_ts: dict[str, datetime] = {}
        for t in phase_sequence:
            if t['phase'] not in phase_first_ts and t['ts']:
                phase_first_ts[t['phase']] = t['ts']
        phase_order_items = sorted(phase_first_ts.items(), key=lambda x: x[1])
        for i in range(1, len(phase_order_items)):
            prev_ph, prev_time = phase_order_items[i - 1]
            curr_ph, curr_time = phase_order_items[i]
            gap = (curr_time - prev_time).total_seconds() / 3600
            if gap > 0.5:  # Only surface gaps > 30 minutes
                dwell_gaps.append({
                    'phase_from': prev_ph,
                    'phase_to': curr_ph,
                    'gap_hours': round(gap, 2),
                })

        # Anomalies
        anomalies: list[str] = []
        for ooo in out_of_order:
            anomalies.append(
                f'{ooo["expected_before"]} (order {ooo["curr_order"]}) found after '
                f'{ooo["found_after"]} (order {ooo["prev_order"]}) — '
                f'possible mis-clustering or attacker living-off-the-land'
            )
        for gap in dwell_gaps:
            if gap['gap_hours'] > 24:
                anomalies.append(
                    f'{gap["gap_hours"]:.1f}h gap between {gap["phase_from"]} and '
                    f'{gap["phase_to"]} — consistent with deliberate attacker dwell'
                )

        # Phases present in ATT&CK but absent from evidence
        phases_missing = [
            p for p in ['initial_access', 'lateral_movement', 'exfiltration']
            if p not in phase_coverage
        ]

        # Sequence coherence: no out-of-order transitions AND ≥2 distinct phases
        sequence_coherent = len(out_of_order) == 0 and len(phase_coverage) >= 2

        # Build sequence narrative
        narrative = _build_sequence_narrative(
            phase_coverage, out_of_order, dwell_gaps,
            first_ts, last_ts, duration_hours, anomalies,
        )

        return {
            'phase_sequence': phase_sequence,
            'phase_coverage': phase_coverage,
            'phases_missing': phases_missing,
            'out_of_order': out_of_order,
            'first_event_ts': first_ts.isoformat() if first_ts else None,
            'last_event_ts': last_ts.isoformat() if last_ts else None,
            'total_duration_hours': duration_hours,
            'dwell_gaps': dwell_gaps,
            'phase_count': len(phase_coverage),
            'sequence_coherent': sequence_coherent,
            'sequence_narrative': narrative,
            'anomalies': anomalies,
        }


def _build_sequence_narrative(
    phases: list[str],
    out_of_order: list[dict],
    dwell_gaps: list[dict],
    first_ts: Optional[datetime],
    last_ts: Optional[datetime],
    duration_hours: Optional[float],
    anomalies: list[str],
) -> str:
    """Build a compact sequence narrative for injection into reasoning prompts."""
    parts: list[str] = []

    if phases:
        parts.append(f'Attack phases observed (in order): {" → ".join(phases)}.')
    else:
        parts.append('No ATT&CK phase tags found in evidence.')

    if duration_hours is not None:
        if duration_hours < 1:
            parts.append(f'Total breach window: {round(duration_hours * 60)} minutes.')
        elif duration_hours < 24:
            parts.append(f'Total breach window: {duration_hours:.1f} hours.')
        else:
            parts.append(f'Total breach window: {duration_hours / 24:.1f} days.')

    for gap in dwell_gaps[:3]:
        if gap['gap_hours'] > 24:
            parts.append(
                f'Attacker paused {gap["gap_hours"]:.1f}h between '
                f'{gap["phase_from"]} and {gap["phase_to"]} — possible dwell time.'
            )

    if out_of_order:
        parts.append(
            f'{len(out_of_order)} out-of-order phase transition(s) detected — '
            'chain coherence is weak.'
        )

    return ' '.join(parts)
