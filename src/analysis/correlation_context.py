"""Lightweight correlation context helpers for Tier 2 prompts."""
from __future__ import annotations

from typing import Any, Dict, List, Sequence

FACTOR_ATTACK_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "lateral_movement": {
        "description": "Attacker attempting to move laterally from a foothold.",
        "techniques": ["SMB sessions", "RDP logons", "WMI or PsExec"],
        "business_impact": "Can spread ransomware or data theft across the network.",
        "indicators": [
            "Unusual SMB connections",
            "RDP logons to multiple servers",
            "Remote service creation",
        ],
        "urgency": "HIGH",
    },
    "credential_access": {
        "description": "Credentials targeted for privilege escalation.",
        "techniques": ["LSASS access", "SAM hive theft", "Memory scraping"],
        "business_impact": "Compromised accounts enable privilege elevation.",
        "indicators": [
            "Access to LSASS process",
            "Dump of SAM/SECURITY hives",
            "Credential dumping tools executed",
        ],
        "urgency": "HIGH",
    },
    "initial_access": {
        "description": "Suspicious initial access vector in progress.",
        "techniques": ["Phishing payload", "Malicious attachment"],
        "business_impact": "Opens foothold into the environment.",
        "indicators": [
            "Email attachment execution",
            "Exploit from external IP",
        ],
        "urgency": "MEDIUM",
    },
    "execution": {
        "description": "Malicious execution behavior detected.",
        "techniques": ["PowerShell abuse", "LOLBin execution"],
        "business_impact": "Allows attacker code to run on hosts.",
        "indicators": [
            "Unsigned PowerShell scripts",
            "Living-off-the-land binaries",
        ],
        "urgency": "MEDIUM",
    },
    "persistence": {
        "description": "Persistence artifact created to survive reboots.",
        "techniques": ["Run keys", "Scheduled tasks", "Services"],
        "business_impact": "Allows attacker to return at will.",
        "indicators": [
            "Registry Run key changes",
            "New scheduled tasks",
            "Service creation events",
        ],
        "urgency": "MEDIUM",
    },
}

KILL_CHAIN_ORDER: Sequence[str] = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "credential_access",
    "lateral_movement",
    "collection",
    "exfiltration",
]


def _collect_factors(row: Dict[str, Any], pipeline_context: Dict[str, Any]) -> List[str]:
    factors: List[str] = []
    for source in (row, pipeline_context or {}):
        raw = source.get("factors") or source.get("factor_keys") or []
        if isinstance(raw, dict):
            raw = raw.keys()
        for val in raw or []:
            try:
                if not val:
                    continue
                factors.append(str(val))
            except Exception:
                continue
    return list(dict.fromkeys(factors))


def _score_urgency(row: Dict[str, Any], scenarios: List[Dict[str, Any]]) -> str:
    dread_score = 0.0
    try:
        dread = row.get("_dread") or row.get("dread") or {}
        dread_score = float(dread.get("score") or 0.0)
    except Exception:
        dread_score = 0.0

    if dread_score >= 7 or any(s.get("urgency") == "HIGH" for s in scenarios):
        return "CRITICAL"
    if dread_score >= 4:
        return "ELEVATED"
    return "NORMAL"


def enrich_correlation_context(
    row: Dict[str, Any],
    pipeline_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Translate raw factors into human-readable attack scenarios."""
    pipeline_context = pipeline_context or {}
    raw_factors = _collect_factors(row, pipeline_context)

    scenarios: List[Dict[str, Any]] = []
    for factor in raw_factors:
        meta = FACTOR_ATTACK_SCENARIOS.get(factor)
        if not meta:
            continue
        entry = {
            "factor": factor,
            "description": meta["description"],
            "techniques": meta["techniques"],
            "business_impact": meta["business_impact"],
            "indicators": meta["indicators"],
            "urgency": meta["urgency"],
        }
        scenarios.append(entry)

    if not scenarios:
        scenarios.append(
            {
                "factor": "execution",
                "description": "Suspicious execution behavior",
                "techniques": ["PowerShell or script abuse"],
                "business_impact": "Potential pivot or malware staging",
                "indicators": ["Unsigned PowerShell scripts", "Encoded commands"],
                "urgency": "MEDIUM",
            }
        )

    urgency = _score_urgency(row, scenarios)

    dread = (row.get("_dread") or row.get("dread") or {}).get("score")
    corr_score = None
    corr = row.get("_correlation") or row.get("correlation") or pipeline_context.get(
        "correlation"
    )
    if isinstance(corr, dict):
        corr_score = corr.get("score")

    mitre_tags = row.get("mitre_tags") or pipeline_context.get("mitre_tags") or []
    mitre_str = ", ".join(str(t) for t in mitre_tags[:3]) or "n/a"

    # Attach playbook guidance for the top mitre tags when available
    playbook_guidance: list[dict] = []
    try:
        try:
            from src.analysis.playbook_db import get_playbook_for_mitre  # type: ignore
        except Exception:
            try:
                from ..analysis.playbook_db import get_playbook_for_mitre  # type: ignore
            except Exception:
                get_playbook_for_mitre = None  # type: ignore
        if mitre_tags and get_playbook_for_mitre:
            for mid in mitre_tags[:3]:
                try:
                    p = get_playbook_for_mitre(str(mid).upper())
                except Exception:
                    p = None
                if p and isinstance(p, dict) and p.get('playbook'):
                    playbook_guidance.append({'mitre_id': mid, 'playbook': p['playbook']})
    except Exception:
        playbook_guidance = []

    narrative = [
        f"Correlation factors highlight {len(scenarios)} attack scenario(s).",
        f"MITRE focus: {mitre_str}.",
    ]
    if dread is not None:
        narrative.append(f"DREAD score: {dread}.")
    if corr_score is not None:
        narrative.append(f"Correlation score: {corr_score}.")

    narrative.append(f"Urgency: {urgency}.")

    if scenarios:
        lead = scenarios[0]
        narrative.append(
            f"Primary scenario: {lead['factor']} — {lead['description']} "
            f"({lead['business_impact']})"
        )

    return {
        "narrative": " ".join(narrative),
        "scenarios": scenarios,
        "primary_scenario": scenarios[0] if scenarios else None,
        "urgency": urgency,
        "playbook_guidance": playbook_guidance,
    }


def build_attack_chain_visualization(correlation_context: Dict[str, Any]) -> str:
    """Render a simple textual attack chain arrow using mapped scenarios."""
    scenarios = correlation_context.get("scenarios") or []
    if not scenarios:
        return "No attack chain identified."

    ordered: List[str] = []
    for stage in KILL_CHAIN_ORDER:
        for scenario in scenarios:
            if scenario.get("factor") == stage:
                ordered.append(stage.replace("_", " ").title())

    if not ordered:
        return "No attack chain identified."

    return " -> ".join(ordered)


__all__ = [
    "FACTOR_ATTACK_SCENARIOS",
    "KILL_CHAIN_ORDER",
    "build_attack_chain_visualization",
    "enrich_correlation_context",
]
