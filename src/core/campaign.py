"""Canonical campaign object — the single source of breach truth.

Today the campaign view is RECONSTRUCTED ad-hoc by each consumer (report rollups, the
narrator, each persona builder, the grounding logic) from present_phase_ids + cluster
phases + factor_tags + _entry_point + _exfil_destinations. That drift is fragile — it's
how a confirmed breach rendered empty in some surfaces and full in others.

`Campaign` assembles all of it ONCE from a breach cluster. Reports, personas, narration,
and IOC grounding consume `campaigns[]` instead of re-deriving. `present_phase_ids` etc.
remain on the cluster as backward-compatible metadata; this is the primary truth source.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Any

_BREACH_VERDICTS = {
    "VALIDATED_BREACH", "LIKELY_BREACH", "SUSPECTED_BREACH", "INCIDENT", "LIKELY_COMPROMISE",
}


def _is_external_ip(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(str(ip)).is_private
    except Exception:
        return False


@dataclass
class Campaign:
    """One breach campaign, assembled from a cluster. The canonical object all surfaces
    render from."""
    campaign_id: str
    actor: str | None
    verdict: str
    confidence: float
    severity: str
    phases: list[str]                 # ordered kill-chain stages (delivery..exfiltration)
    phase_ids: list[str]              # raw detector phase_ids present for the actor
    factors: list[str]
    entities: dict[str, list[str]]    # users / hosts / ips / external_ips / domains
    entry_point: dict[str, Any] | None
    exfil_destinations: list[str]
    evidence_refs: list[int]
    row_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def is_breach(self) -> bool:
        return self.verdict.upper() in _BREACH_VERDICTS


def _verdict(cluster: dict) -> str:
    return str(cluster.get("verdict") or cluster.get("final_verdict") or "").upper()


def build_campaign(cluster: dict) -> Campaign:
    """Assemble the canonical Campaign from a single breach cluster."""
    # Decomposed children roll up to ONE campaign via the parent id.
    campaign_id = str(cluster.get("parent_cluster_id") or cluster.get("cluster_id") or "campaign")
    users = [str(u) for u in (cluster.get("shared_users") or cluster.get("shared_accounts") or []) if u]
    ips = [str(i) for i in (cluster.get("shared_ips") or []) if i and str(i) != "None"]
    hosts = [str(h) for h in (cluster.get("shared_hosts") or []) if h and str(h) != "None"]
    exfil = cluster.get("_exfil_destinations") or {}
    exfil_dsts = sorted({str(rec.get("destination") or "") for rec in exfil.values()
                         if isinstance(rec, dict) and rec.get("destination")})
    # domains: lookalike exfil destinations are domains, not IPs
    domains = sorted({d for d in exfil_dsts if d and not _is_external_ip(d.split(":")[0]) and "." in d})

    # Kill-chain stages — reuse the single canonical derivation (present_phase_ids + exfil).
    try:
        from src.core.ingest.cluster_narrator import _killchain_from_phases
        phases = _killchain_from_phases(cluster)
    except Exception:
        phases = []
    try:
        from src.core.ingest.cluster_merge import PHASE_DETECTORS
        _known = {d.phase_id for d in PHASE_DETECTORS}
    except Exception:
        _known = set()
    phase_ids = sorted({p for p in (cluster.get("present_phase_ids") or []) if not _known or p in _known})

    return Campaign(
        campaign_id=campaign_id,
        actor=(users[0] if users else None),
        verdict=_verdict(cluster) or "REQUIRES_INVESTIGATION",
        confidence=float(cluster.get("confidence") or 0.0),
        severity=str(cluster.get("severity") or ""),
        phases=phases,
        phase_ids=phase_ids,
        factors=[str(f) for f in (cluster.get("factor_tags") or [])],
        entities={
            "users": users[:10],
            "hosts": hosts[:10],
            "ips": ips[:12],
            "external_ips": [i for i in ips if _is_external_ip(i)][:8],
            "domains": domains[:8],
        },
        entry_point=cluster.get("_entry_point"),
        exfil_destinations=exfil_dsts,
        evidence_refs=[int(i) for i in (cluster.get("row_refs") or []) if isinstance(i, int)][:500],
        row_count=int(cluster.get("row_count") or len(cluster.get("row_refs") or [])),
    )


def build_campaigns(clusters: list[dict], *, breach_only: bool = True) -> list[Campaign]:
    """Build campaigns from actionable clusters, deduped per campaign_id (parent rollup).
    By default keeps only breach-verdict campaigns (what the personas/report care about)."""
    by_id: dict[str, Campaign] = {}
    for c in clusters or []:
        if c.get("_isolated"):
            continue
        if breach_only and _verdict(c) not in _BREACH_VERDICTS:
            continue
        camp = build_campaign(c)
        prev = by_id.get(camp.campaign_id)
        # Prefer the richest representative (most kill-chain phases) per campaign id.
        if prev is None or len(camp.phase_ids) > len(prev.phase_ids):
            by_id[camp.campaign_id] = camp
    return sorted(by_id.values(), key=lambda c: (-c.confidence, -len(c.phase_ids)))
