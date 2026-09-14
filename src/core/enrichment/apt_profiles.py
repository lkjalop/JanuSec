"""APT (Advanced Persistent Threat) attribution profiles.

Given a set of phase detector tags + pivot keys observed in a cluster,
return a best-effort attribution to a known threat actor with confidence.

Profiles are intentionally conservative — we never attribute on a single
indicator. Each profile requires multiple distinguishing TTPs before it
fires. The `attribute_apt()` function returns the highest-scoring match
above the floor (default 0.5) or None.

References:
- MITRE ATT&CK Groups https://attack.mitre.org/groups/
- CISA threat actor advisories
- Mandiant / CrowdStrike / Microsoft public reporting

Usage:
    from src.core.enrichment.apt_profiles import attribute_apt
    result = attribute_apt(
        phase_tags={"oauth_device_code","entra_privesc","data_exfiltration_rclone"},
        pivot_keys={"cloud_identity:alice","attacker_zone:azure"},
        cloud_providers={"azure"},
    )
    # → {"actor":"midnight_blizzard","confidence":0.78,"matched_indicators":[...]}
"""
from __future__ import annotations
from typing import Optional
import logging

logger = logging.getLogger(__name__)


# Each profile lists distinguishing indicators. Matching is fuzzy:
# - phase_indicators: phase_ids from PHASE_DETECTORS that this actor commonly chains
# - pivot_indicators: pivot prefixes we expect to see (cloud_identity, attacker_zone, etc.)
# - cloud: cloud platforms typically targeted
# - aliases: alternate names for reporting
# - description: short threat brief for analyst rendering
APT_PROFILES: dict[str, dict] = {
    "apt29": {
        "aliases": ["cozy_bear", "the_dukes", "nobelium"],
        "origin": "RU",
        "phase_indicators": [
            "oauth_device_code", "entra_privesc",
            "credential_theft", "secret_access",
            "data_exfiltration_rclone",
        ],
        "pivot_indicators": ["cloud_identity:", "attacker_zone:"],
        "cloud": ["azure", "aad"],
        "description": (
            "Russian SVR-linked actor specializing in cloud identity abuse, OAuth "
            "consent phishing, and stealthy long-dwell access (SolarWinds, Microsoft "
            "Exchange 2024, HPE 2024)."
        ),
        "min_indicators": 2,
        "confidence_floor": 0.55,
    },
    "midnight_blizzard": {
        "aliases": ["nobelium", "apt29_subset"],
        "origin": "RU",
        "phase_indicators": [
            "oauth_device_code", "entra_privesc", "session_theft",
            "secret_access",
        ],
        "pivot_indicators": ["cloud_identity:", "iam_op:"],
        "cloud": ["azure", "m365"],
        "description": (
            "Microsoft-tracked alias for APT29 cloud campaigns; hallmarked by "
            "OAuth app abuse and password spray on legacy auth endpoints."
        ),
        "min_indicators": 2,
        "confidence_floor": 0.6,
    },
    "apt41": {
        "aliases": ["barium", "winnti", "wicked_panda"],
        "origin": "CN",
        "phase_indicators": [
            "cloud_imds_theft", "cloud_iam_privesc",
            "lolbin_execution", "dns_tunnel",
            "data_exfiltration_rclone",
        ],
        "pivot_indicators": ["cloud_identity:", "attacker_zone:"],
        "cloud": ["aws", "gcp"],
        "description": (
            "Chinese state-aligned dual-mission actor (espionage + financial). "
            "Heavy cloud IAM abuse, IMDS credential theft, supply-chain pivots."
        ),
        "min_indicators": 2,
        "confidence_floor": 0.55,
    },
    "scattered_spider": {
        "aliases": ["unc3944", "octo_tempest", "0ktapus"],
        "origin": "US/UK",
        "phase_indicators": [
            "session_theft", "oauth_device_code",
            "credential_theft", "privilege_escalation_k8s",
            "ransomware_staging", "shadow_copy_deletion",
        ],
        "pivot_indicators": ["cloud_identity:", "iam_op:"],
        "cloud": ["okta", "azure", "aws"],
        "description": (
            "Native English-speaking financially-motivated actor; SIM-swap, "
            "MFA-bombing, social engineering of helpdesks. MGM/Caesars 2023."
        ),
        "min_indicators": 2,
        "confidence_floor": 0.6,
    },
    "lockbit": {
        "aliases": ["lockbit_3", "lockbit_black"],
        "origin": "RU/RaaS",
        "phase_indicators": [
            "credential_theft", "lateral_movement",
            "shadow_copy_deletion", "ransomware_staging",
            "wmi_dcom_lateral", "lolbin_execution",
        ],
        "pivot_indicators": ["host:", "sig:"],
        "cloud": [],
        "description": (
            "Most prolific RaaS family 2022-2024. Affiliates use AnyDesk, "
            "Mimikatz, Cobalt Strike, then LockBit Black encryptor."
        ),
        "min_indicators": 3,
        "confidence_floor": 0.65,
    },
    "blackcat": {
        "aliases": ["alphv", "noberus"],
        "origin": "RU/RaaS",
        "phase_indicators": [
            "credential_theft", "shadow_copy_deletion",
            "ransomware_staging", "powershell_staged_payload",
        ],
        "pivot_indicators": ["host:", "sig:"],
        "cloud": [],
        "description": (
            "Rust-based ransomware (first major Rust ransomware family). "
            "Change Healthcare 2024, Reddit 2023."
        ),
        "min_indicators": 3,
        "confidence_floor": 0.65,
    },
    "lazarus": {
        "aliases": ["hidden_cobra", "apt38"],
        "origin": "KP",
        "phase_indicators": [
            "credential_theft", "secret_access",
            "data_exfiltration_rclone", "dns_tunnel",
            "lolbin_execution",
        ],
        "pivot_indicators": ["attacker_zone:", "host:"],
        "cloud": [],
        "description": (
            "DPRK state actor; financially-motivated cryptocurrency theft "
            "(Ronin Bridge, Atomic Wallet) and espionage (3CX 2023)."
        ),
        "min_indicators": 2,
        "confidence_floor": 0.55,
    },
    "fin7": {
        "aliases": ["carbanak", "carbon_spider"],
        "origin": "RU",
        "phase_indicators": [
            "lolbin_execution", "powershell_staged_payload",
            "wmi_dcom_lateral", "credential_theft",
        ],
        "pivot_indicators": ["host:", "sig:"],
        "cloud": [],
        "description": (
            "Long-running financial cybercrime group; pivoted from POS malware "
            "to ransomware affiliate work (DarkSide, BlackBasta)."
        ),
        "min_indicators": 2,
        "confidence_floor": 0.55,
    },
    "lapsus": {
        "aliases": ["lapsus$", "dev-0537", "strawberry_tempest"],
        "origin": "BR/UK",
        "phase_indicators": [
            "session_theft", "credential_theft",
            "oauth_device_code", "secret_access",
        ],
        "pivot_indicators": ["cloud_identity:", "iam_op:"],
        "cloud": ["okta", "azure", "github"],
        "description": (
            "Extortion-focused teen group; insider recruitment, source-code "
            "theft (Microsoft, Nvidia, Okta, Uber 2022)."
        ),
        "min_indicators": 2,
        "confidence_floor": 0.55,
    },
    "teamtnt": {
        "aliases": ["watchdog"],
        "origin": "DE/unknown",
        "phase_indicators": [
            "cloud_imds_theft", "cloud_iam_privesc",
            "secret_access",
        ],
        "pivot_indicators": ["cloud_identity:", "attacker_zone:"],
        "cloud": ["aws", "gcp", "kubernetes"],
        "description": (
            "Cloud-native cryptojacking + credential theft crew; targets "
            "exposed Docker/K8s APIs and AWS metadata service."
        ),
        "min_indicators": 2,
        "confidence_floor": 0.55,
    },
    "apt40": {
        "aliases": ["leviathan", "kryptonite_panda"],
        "origin": "CN",
        "phase_indicators": [
            "credential_theft", "ntlm_relay_pth",
            "wmi_dcom_lateral", "lolbin_execution",
        ],
        "pivot_indicators": ["host:", "sig:"],
        "cloud": [],
        "description": (
            "Chinese MSS-linked maritime/research espionage actor "
            "(CISA AA24-190A advisory, July 2024)."
        ),
        "min_indicators": 2,
        "confidence_floor": 0.55,
    },
    "volt_typhoon": {
        "aliases": ["bronze_silhouette"],
        "origin": "CN",
        "phase_indicators": [
            "lolbin_execution", "credential_theft",
            "dcsync", "wmi_dcom_lateral",
        ],
        "pivot_indicators": ["host:", "sig:"],
        "cloud": [],
        "description": (
            "Chinese living-off-the-land actor targeting US critical "
            "infrastructure pre-positioning (CISA AA23-144A, May 2023)."
        ),
        "min_indicators": 3,
        "confidence_floor": 0.65,
    },
}


def _pivot_prefixes(pivot_keys) -> set[str]:
    """Extract prefix-only forms (e.g. 'cloud_identity:alice' → 'cloud_identity:')."""
    out: set[str] = set()
    for pk in pivot_keys or []:
        s = str(pk)
        if ":" in s:
            out.add(s.split(":", 1)[0] + ":")
        else:
            out.add(s)
    return out


def attribute_apt(
    phase_tags=None,
    pivot_keys=None,
    cloud_providers=None,
    *,
    floor: float = 0.5,
) -> Optional[dict]:
    """Score every APT profile against observed indicators; return best match
    above floor or None.

    Args:
        phase_tags: iterable of phase_id strings (e.g. {"oauth_device_code"})
        pivot_keys: iterable of full pivot keys (e.g. {"cloud_identity:alice"})
        cloud_providers: iterable of cloud platform names ({"azure","aws"})
        floor: minimum confidence to return a match

    Returns:
        {actor, aliases, origin, confidence, description, matched_indicators}
        or None if no profile crosses the floor.
    """
    phase_tags = set(str(p) for p in (phase_tags or []))
    pivot_prefixes = _pivot_prefixes(pivot_keys or [])
    cloud_providers = set(str(c).lower() for c in (cloud_providers or []))

    best: tuple[Optional[str], float, list[str]] = (None, 0.0, [])

    for actor, profile in APT_PROFILES.items():
        matched: list[str] = []
        score = 0.0

        # Phase indicator matches (weighted heaviest)
        for ind in profile.get("phase_indicators", []):
            if ind in phase_tags:
                matched.append(f"phase:{ind}")
                score += 0.15

        if len(matched) < int(profile.get("min_indicators", 2)):
            continue  # not enough distinguishing TTPs

        # Pivot prefix matches (medium weight)
        for ind in profile.get("pivot_indicators", []):
            if ind in pivot_prefixes:
                matched.append(f"pivot:{ind}")
                score += 0.08

        # Cloud platform alignment (small bonus)
        for cl in profile.get("cloud", []):
            if cl.lower() in cloud_providers:
                matched.append(f"cloud:{cl}")
                score += 0.05

        # Cap at 0.95 — never claim certainty
        score = min(0.95, score + 0.4)  # +0.4 base for clearing min_indicators

        if score >= profile.get("confidence_floor", floor) and score > best[1]:
            best = (actor, score, matched)

    if not best[0]:
        return None

    actor, conf, matched = best
    profile = APT_PROFILES[actor]
    return {
        "actor": actor,
        "aliases": profile.get("aliases", []),
        "origin": profile.get("origin", ""),
        "confidence": round(conf, 3),
        "description": profile.get("description", ""),
        "matched_indicators": matched,
        "min_indicators_required": int(profile.get("min_indicators", 2)),
        "attribution_basis": "ttp_pattern_match",
    }


__all__ = ["APT_PROFILES", "attribute_apt"]
