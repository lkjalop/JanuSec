"""
Kill chain extractor — orders verified findings into a causal timeline.

Runs after Verifier, before Narrator. Produces an ordered list of
KillChainPhase objects that the Narrator uses to write causal prose
("A enabled B which led to C") instead of bullet-point summaries.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.agents.types import VerifiedFinding


@dataclass
class KillChainPhase:
    """One phase in the attack kill chain."""
    phase: str = ""                    # initial_access | execution | persistence | ...
    timestamp: datetime = field(default_factory=lambda: datetime(2026, 1, 1))
    actor: str = ""                    # principal: user | service account | external IP
    action: str = ""                   # one-sentence what-happened
    evidence_row_ids: List[int] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    enables_phase_id: Optional[str] = None  # causal link to next phase
    phase_id: str = field(default_factory=lambda: f"kc-{uuid.uuid4().hex[:6]}")


# ── Phase classification ─────────────────────────────────────────────────────

_PHASE_MAP: List[tuple[str, List[str], List[str]]] = [
    # (phase_name, keywords, mitre_techniques)
    # Order matters — more specific phases first to avoid false matches
    ("initial_access",    ["phish", "spear", "bec", "initial access", "credential harvest", "brute force", "password spray"],
                          ["T1566", "T1078", "T1110"]),
    ("credential_access", ["credential", "lsass", "mimikatz", "comsvcs.dll", "token theft", "dump", "kerberoast", "mfa fatigue"],
                          ["T1003", "T1558", "T1621"]),
    ("execution",         ["exec", "powershell", "cmd.exe", "wscript", "mshta"],
                          ["T1059", "T1218"]),
    ("persistence",       ["persist", "scheduled task", "registry run", "service binary", "backdoor", "startup"],
                          ["T1053", "T1547", "T1543"]),
    ("privilege_escalation", ["priv", "escalat", "sudo", "global admin", "domain admin", "uac bypass"],
                          ["T1548", "T1068", "T1134"]),
    ("discovery",         ["discovery", "enum", "scan", "recon", "bloodhound", "sharphound", "nslookup"],
                          ["T1018", "T1082", "T1087"]),
    ("lateral_movement",  ["lateral", "rdp", "psexec", "wmiexec", "smb", "pass the hash", "dcom", "ssh"],
                          ["T1021", "T1550"]),
    ("collection",        ["collect", "staging", "archive", "compress", "screenshot", "keylog"],
                          ["T1560", "T1113"]),
    ("exfiltration",      ["exfil", "rclone", "mega", "backblaze", "azcopy", "gsutil", "copy_into", "hetzner", "s3"],
                          ["T1567", "T1048"]),
    ("command_and_control", ["c2", "beacon", "dns tunnel", "cobalt", "command-and-control"],
                          ["T1071", "T1572", "T1573"]),
]


def _classify_phase(summary: str, evidence: Dict[str, Any]) -> tuple[str, List[str]]:
    """Classify a finding into a kill chain phase + MITRE techniques."""
    combined = f"{summary} {str(evidence)}".lower()
    for phase_name, keywords, techniques in _PHASE_MAP:
        if any(kw in combined for kw in keywords):
            return phase_name, techniques
    return "unknown", []


def _extract_timestamp(evidence: Dict[str, Any]) -> datetime:
    """Extract a timestamp from evidence, with fallback."""
    for key in ["timestamp", "ts", "event_time", "created_at", "time"]:
        val = evidence.get(key)
        if val:
            if isinstance(val, datetime):
                return val
            if isinstance(val, (int, float)):
                try:
                    return datetime.fromtimestamp(val)
                except (OSError, ValueError):
                    pass
            if isinstance(val, str):
                for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"]:
                    try:
                        return datetime.strptime(val[:19], fmt)
                    except ValueError:
                        continue
    return datetime(2026, 1, 1)


def _extract_actor(evidence: Dict[str, Any], summary: str) -> str:
    """Extract the principal actor from evidence."""
    for key in ["user", "actor", "principal", "src_ip", "source_ip"]:
        val = evidence.get(key)
        if val:
            return str(val)
    # Fallback: try to extract IP from summary
    ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", summary)
    if ip_match:
        return ip_match.group()
    return "unknown"


def _extract_row_ids(evidence: Dict[str, Any]) -> List[int]:
    """Extract row IDs from evidence."""
    for key in ["row_refs", "sample_row_ids", "row_ids", "event_ids"]:
        val = evidence.get(key)
        if isinstance(val, list):
            return [int(v) for v in val if isinstance(v, (int, float, str)) and str(v).isdigit()][:10]
    return []


def _link_causal_pairs(phases: List[KillChainPhase]) -> None:
    """Link sequential phases that share actor or occur within 60 minutes."""
    for i in range(len(phases) - 1):
        current = phases[i]
        next_phase = phases[i + 1]

        # Same actor OR within 60 min → causal link
        same_actor = (current.actor and current.actor == next_phase.actor)
        time_delta = abs((next_phase.timestamp - current.timestamp).total_seconds())
        within_window = time_delta <= 3600  # 60 min

        if same_actor or within_window:
            current.enables_phase_id = next_phase.phase_id


def extract_kill_chain(verified: List[VerifiedFinding]) -> List[KillChainPhase]:
    """Order verified findings into a temporal kill chain and link causal pairs."""
    phases: List[KillChainPhase] = []

    for vf in verified:
        evidence = vf.raw.evidence if isinstance(vf.raw.evidence, dict) else {}
        phase_name, techniques = _classify_phase(vf.raw.summary, evidence)
        ts = _extract_timestamp(evidence)
        actor = _extract_actor(evidence, vf.raw.summary)
        row_ids = _extract_row_ids(evidence)

        phases.append(KillChainPhase(
            phase=phase_name,
            timestamp=ts,
            actor=actor,
            action=vf.raw.summary[:200],
            evidence_row_ids=row_ids,
            mitre_techniques=techniques,
        ))

    # Sort by timestamp
    phases.sort(key=lambda p: p.timestamp)

    # Link causal pairs
    _link_causal_pairs(phases)

    return phases
