"""
Kill-chain phase mapping for MITRE ATT&CK techniques.

Used by _tag_cluster_phases() to:
  - Map each T-code to a named kill-chain phase
  - Sort phases in canonical kill-chain order
  - Detect phase transitions (dwell times between phase entries)
  - Build a swimlane dict (phase → [row_index]) for UI rendering

Security persona value:
  SOC analyst   — Immediately see how many stages an attack traversed so
                  triage can be anchored to the earliest phase.
  Threat hunter — Phase dwell-time gaps reveal adversary speed; a 90-second
                  Recon→Execution gap signals an automated initial-access kit.
  CISO/Exec     — "This incident reached Exfil" is a board-level statement;
                  phase_sequence makes it quantifiable.
  IR team       — Containment starting point is always the earliest phase with
                  an unresolved row; phase_entry_ts surfaces that directly.
  Compliance    — Multi-phase attacks that cross credential_access→lateral_movement
                  trigger NIST/SOC2 IR playbook obligations; tagging automates that.
"""
from __future__ import annotations

from typing import Any

# ── Canonical kill-chain phase order ────────────────────────────────────────
PHASE_ORDER: list[str] = [
    "recon",
    "initial_access",
    "execution",
    "persistence",
    "priv_esc",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfil",
    "c2",
    "impact",
]

# Primary T-code prefix → phase mapping (sub-techniques collapse to parent prefix)
_MITRE_PHASE_MAP: dict[str, str] = {
    # Recon
    "T1595": "recon", "T1592": "recon", "T1589": "recon",
    "T1590": "recon", "T1591": "recon", "T1596": "recon",
    "T1597": "recon", "T1598": "recon",
    # Initial Access
    "T1566": "initial_access", "T1078": "initial_access", "T1190": "initial_access",
    "T1091": "initial_access", "T1133": "initial_access", "T1195": "initial_access",
    "T1200": "initial_access", "T1199": "initial_access",
    # Execution
    "T1059": "execution", "T1203": "execution", "T1204": "execution",
    "T1047": "execution", "T1053": "execution", "T1072": "execution",
    "T1569": "execution", "T1559": "execution", "T1106": "execution",
    "T1129": "execution",
    # Persistence
    "T1547": "persistence", "T1136": "persistence", "T1098": "persistence",
    "T1197": "persistence", "T1037": "persistence", "T1176": "persistence",
    "T1554": "persistence", "T1546": "persistence", "T1525": "persistence",
    "T1542": "persistence", "T1574": "persistence", "T1505": "persistence",
    # Privilege Escalation
    "T1548": "priv_esc", "T1134": "priv_esc", "T1055": "priv_esc",
    "T1484": "priv_esc", "T1611": "priv_esc",
    # Defense Evasion
    "T1070": "defense_evasion", "T1036": "defense_evasion", "T1027": "defense_evasion",
    "T1562": "defense_evasion", "T1553": "defense_evasion", "T1112": "defense_evasion",
    "T1218": "defense_evasion", "T1220": "defense_evasion", "T1222": "defense_evasion",
    "T1564": "defense_evasion", "T1497": "defense_evasion", "T1480": "defense_evasion",
    "T1202": "defense_evasion",
    # Credential Access
    "T1110": "credential_access", "T1555": "credential_access", "T1556": "credential_access",
    "T1003": "credential_access", "T1040": "credential_access", "T1111": "credential_access",
    "T1212": "credential_access", "T1539": "credential_access", "T1552": "credential_access",
    "T1558": "credential_access", "T1621": "credential_access",  # MFA fatigue (T1621)
    # Discovery
    "T1087": "discovery", "T1083": "discovery", "T1018": "discovery",
    "T1069": "discovery", "T1046": "discovery", "T1135": "discovery",
    "T1482": "discovery", "T1201": "discovery", "T1217": "discovery",
    "T1526": "discovery", "T1518": "discovery",
    # Lateral Movement
    "T1021": "lateral_movement", "T1570": "lateral_movement", "T1534": "lateral_movement",
    "T1550": "lateral_movement", "T1563": "lateral_movement",
    # Collection
    "T1074": "collection", "T1114": "collection", "T1213": "collection",
    "T1560": "collection", "T1602": "collection", "T1491": "collection",
    "T1005": "collection", "T1025": "collection", "T1039": "collection",
    "T1113": "collection", "T1125": "collection",
    # Exfiltration
    "T1041": "exfil", "T1048": "exfil", "T1567": "exfil", "T1011": "exfil",
    "T1029": "exfil", "T1030": "exfil", "T1052": "exfil",
    # Command & Control (includes BGP T1599)
    "T1071": "c2", "T1095": "c2", "T1571": "c2", "T1572": "c2",
    "T1573": "c2", "T1008": "c2", "T1090": "c2", "T1092": "c2",
    "T1102": "c2", "T1104": "c2", "T1105": "c2", "T1132": "c2",
    "T1568": "c2", "T1599": "c2",  # BGP route hijack (P1.5)
    # Impact
    "T1485": "impact", "T1486": "impact", "T1490": "impact", "T1491": "impact",
    "T1496": "impact", "T1498": "impact", "T1499": "impact", "T1529": "impact",
    "T1561": "impact", "T1565": "impact",
}


def technique_to_phase(t_code: str) -> str | None:
    """Return attack phase name for a MITRE T-code, or None if unknown.

    Handles sub-techniques (T1059.001 → parent T1059) automatically.
    """
    if not t_code:
        return None
    normalized = t_code.strip().upper().split(".")[0]
    return _MITRE_PHASE_MAP.get(normalized)


def tag_cluster_phases(cluster_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive MITRE kill-chain phase annotation from a list of evidence rows.

    Sorts rows by timestamp_epoch (falls back to row_index) then maps each row
    to a phase via its mitre/mitre_techniques fields.

    Returns a dict safe to merge directly into any cluster dict:
    {
        "phase_sequence":   ["initial_access", "credential_access", "lateral_movement"],
        "phase_transitions": [{"from": "initial_access", "to": "credential_access",
                               "dwell_seconds": 3600}],
        "phase_entry_ts":   {"initial_access": 1712000000, "credential_access": 1712003600},
        "is_multi_phase":   True,
        "dominant_phase":   "initial_access",   # earliest kill-chain phase present
        "phase_count":      3,
        "swimlane":         {"initial_access": [0, 1], "credential_access": [5]},
    }
    """
    if not cluster_rows:
        return {
            "phase_sequence": [], "phase_transitions": [],
            "phase_entry_ts": {}, "is_multi_phase": False,
            "dominant_phase": None, "phase_count": 0, "swimlane": {},
        }

    # Sort rows by time, fall back to row_index for stability
    sorted_rows = sorted(
        cluster_rows,
        key=lambda r: (r.get("timestamp_epoch") or 0, r.get("row_index") or 0),
    )

    # Map each row to its first resolvable phase
    row_phases: list[tuple[dict[str, Any], str | None]] = []
    for row in sorted_rows:
        techs: list[str] = list(row.get("mitre") or row.get("mitre_techniques") or [])
        phase: str | None = None
        for t in techs:
            p = technique_to_phase(str(t))
            if p:
                phase = p
                break
        row_phases.append((row, phase))

    # Build ordered unique phase sequence in kill-chain order
    seen_phases: set[str] = set()
    phase_entry_ts: dict[str, int] = {}
    raw_phase_order: list[str] = []  # insertion order from timeline

    for row, phase in row_phases:
        if phase and phase not in seen_phases:
            seen_phases.add(phase)
            raw_phase_order.append(phase)
            ts = row.get("timestamp_epoch")
            if ts is not None:
                try:
                    phase_entry_ts[phase] = int(ts)
                except (TypeError, ValueError):
                    pass

    # Sort by canonical PHASE_ORDER array
    phase_sequence = sorted(
        raw_phase_order,
        key=lambda p: PHASE_ORDER.index(p) if p in PHASE_ORDER else 99,
    )

    # Compute phase transitions (consecutive in kill-chain order) with dwell times
    transitions: list[dict[str, Any]] = []
    for i in range(len(phase_sequence) - 1):
        frm = phase_sequence[i]
        to = phase_sequence[i + 1]
        dwell = 0
        if frm in phase_entry_ts and to in phase_entry_ts:
            dwell = max(0, phase_entry_ts[to] - phase_entry_ts[frm])
        transitions.append({"from": frm, "to": to, "dwell_seconds": dwell})

    # Build swimlane: phase → sorted list of row_indices
    swimlane: dict[str, list[int]] = {p: [] for p in phase_sequence}
    for row, phase in row_phases:
        if phase and phase in swimlane:
            ri = row.get("row_index")
            if ri is not None:
                try:
                    swimlane[phase].append(int(ri))
                except (TypeError, ValueError):
                    pass
    for v in swimlane.values():
        v.sort()

    dominant = phase_sequence[0] if phase_sequence else None

    return {
        "phase_sequence": phase_sequence,
        "phase_transitions": transitions,
        "phase_entry_ts": phase_entry_ts,
        "is_multi_phase": len(phase_sequence) > 1,
        "dominant_phase": dominant,
        "phase_count": len(phase_sequence),
        "swimlane": swimlane,
    }
