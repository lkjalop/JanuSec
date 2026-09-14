"""Decomposed, evidence-grounded DREAD — and the wiring from each component to
concrete infrastructure changes, security investments, and process improvements.

A single 0-10 number is useless to an architect. This produces, per breach finding:

  * Damage          — what is destroyed / stolen / how deep the compromise goes.
  * Reproducibility — how reliably the technique can be repeated.
  * Exploitability  — how much skill/tooling it takes (and whether it was ALREADY
                      exploited — for a confirmed breach this is not theoretical).
  * Affected        — a DEEP DIVE on exactly what is affected: which identities,
                      hosts, data, asset classes, and the blast radius.
  * Discoverability — defender visibility (low visibility / stealth => higher risk).

Each component carries a score, a level, and a grounded rationale. The finding then
DRIVES specific actions: infrastructure changes, security purchases, and process
improvements — the "what to actually do / buy" layer that turns a threat model into a
budget line.

Scores are derived deterministically from the cluster's phases + evidence, so the same
finding always yields the same assessment (auditable).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Per-phase base DREAD component scores (1-10) + a one-line rationale each. These are
# the analyst-calibrated priors; the assessment then adjusts them with live evidence.
# keys are phase-detector ids (the vocabulary breach clusters carry).
from src.core.grc import phase_registry as _reg
# Per-phase DREAD components, drivers, and asset class now live in the single phase
# registry; derived views here keep the existing call sites.
_DEFAULT_DREAD = _reg.DEFAULT_DREAD
_DEFAULT_DRIVERS = _reg.DEFAULT_DRIVERS
_PHASE_DREAD = {p: _reg.dread(p) for p in _reg.known_phases() if 'dread' in _reg.PHASE_KNOWLEDGE.get(p, {})}
_PHASE_DRIVERS = {p: _reg.drivers(p) for p in _reg.known_phases() if _reg.drivers(p)}
_ASSET_CLASS_BY_PHASE = {p: _reg.asset_class(p) for p in _reg.known_phases() if _reg.asset_class(p)}


def _level(score: float) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 2:
        return "low"
    return "trace"


def _clamp(v: float, lo: float = 1.0, hi: float = 10.0) -> float:
    return max(lo, min(hi, v))


def _attack_complexity(r_score: float, e_score: float, exploited: bool) -> dict:
    """How hard was the attack to pull off — the inverse of ease. Derived from
    Reproducibility + Exploitability (like CVSS Attack Complexity). High R+E => LOW
    complexity (easy, commodity, repeatable)."""
    ease = (r_score + e_score) / 2.0
    if ease >= 7:
        level, label = "low", "commodity technique — easy and highly repeatable, no 0-day"
    elif ease >= 5:
        level, label = "medium", "moderate skill required"
    else:
        level, label = "high", "sophisticated / bespoke technique"
    if r_score >= 8 and level != "low":
        label += "; highly repeatable"
    return {"level": level, "ease_score": round(ease, 1), "label": label, "exploited": exploited}


@dataclass
class DreadAssessment:
    overall_score: float
    overall_level: str
    damage: dict
    reproducibility: dict
    exploitability: dict
    affected: dict
    discoverability: dict
    drivers: dict  # {infrastructure: [...], investments: [...], improvements: [...]}
    attack_complexity: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "overall_level": self.overall_level,
            "attack_complexity": self.attack_complexity,
            "components": {
                "damage": self.damage,
                "reproducibility": self.reproducibility,
                "exploitability": self.exploitability,
                "affected": self.affected,
                "discoverability": self.discoverability,
            },
            "drivers": self.drivers,
        }


def _phase_keys(cluster: dict) -> list[str]:
    tags = cluster.get("factor_tags") or {}
    return [str(k) for k in (tags.keys() if isinstance(tags, dict) else tags)]


def _affected_deepdive(cluster: dict, phases: list[str]) -> dict:
    """The 'what is affected and how much' deep dive — from live evidence, not static."""
    identities = sorted({str(u) for u in (cluster.get("shared_users") or cluster.get("shared_accounts") or [])})
    # Hosts: shared_hosts UNDERCOUNTS the blast radius — also merge the hosts the actor
    # actually touched per the chrono first-seen map, so a multi-host campaign isn't
    # reported as single-host (evidence completeness).
    _hosts: set[str] = {str(h) for h in (cluster.get("shared_hosts") or [])}
    _cfs = cluster.get("_chrono_first_seen") or {}
    if isinstance(_cfs, dict):
        for _touched in _cfs.values():
            if isinstance(_touched, list):
                _hosts.update(str(h) for h in _touched if h)
    hosts = sorted(_hosts)
    ips = sorted({str(i) for i in (cluster.get("shared_ips") or [])})
    asset_classes = sorted({_ASSET_CLASS_BY_PHASE.get(p) for p in phases if _ASSET_CLASS_BY_PHASE.get(p)})
    # exfil scope, if the chrono layer attached destinations
    exfil = cluster.get("_exfil_destinations") or {}
    data_scope = ""
    total_bytes = 0
    for rec in (exfil.values() if isinstance(exfil, dict) else []):
        try:
            total_bytes += int(rec.get("cumulative_bytes") or 0)
        except Exception:
            pass
    if total_bytes:
        data_scope = f"~{total_bytes / (1024*1024):.0f} MB egressed to {len(exfil)} destination(s)"
    row_count = int(cluster.get("row_count") or len(cluster.get("row_refs") or []))
    # blast radius: scale with distinct identities+hosts and whether impact/exfil present
    reach = len(identities) + len(hosts)
    has_impact = any(p in phases for p in ("dcsync_replication", "ransomware_staging", "esxi_ransomware",
                                           "shadow_copy_deletion")) or bool(exfil) or total_bytes > 0
    blast = "domain/tenant-wide" if any(p in phases for p in ("dcsync_replication", "entra_privesc", "cloud_iam_privesc")) \
        else ("multi-host campaign" if reach >= 3 else "single-entity")
    # affected score: identities/hosts breadth + impact
    a_score = _clamp(3 + min(4, reach) + (2 if has_impact else 0))
    rationale = (
        f"{len(identities)} identity/identities ({', '.join(identities[:4]) or 'n/a'}), "
        f"{len(hosts)} host(s), {len(asset_classes)} asset class(es): {', '.join(asset_classes) or 'n/a'}. "
        f"Blast radius: {blast}." + (f" {data_scope}." if data_scope else "")
    )
    return {
        "score": round(a_score, 1), "level": _level(a_score),
        "identities": identities, "hosts": hosts, "source_ips": ips,
        "asset_classes": asset_classes, "data_scope": data_scope,
        "blast_radius": blast, "event_count": row_count, "rationale": rationale,
    }


def assess_dread(cluster: dict) -> DreadAssessment:
    """Decomposed, evidence-grounded DREAD for a breach cluster, with the driven
    infrastructure / investment / improvement actions."""
    phases = _phase_keys(cluster)
    profiles = [_PHASE_DREAD.get(p, _DEFAULT_DREAD) for p in phases] or [_DEFAULT_DREAD]

    # Component = max across phases (worst-case), with a grounded rationale from the
    # driving phase. Max is the defensible choice: the finding is as bad as its worst
    # technique.
    def _component(key: str) -> tuple[float, str]:
        best_p, best_v = None, 0
        for p in phases:
            v = _PHASE_DREAD.get(p, _DEFAULT_DREAD).get(key, 5)
            if v > best_v:
                best_v, best_p = v, p
        if best_p is None:
            return 5.0, _DEFAULT_DREAD["why"]
        return float(best_v), _PHASE_DREAD.get(best_p, _DEFAULT_DREAD)["why"]

    d_score, d_why = _component("D")
    r_score, r_why = _component("R")
    e_score, e_why = _component("E")
    disc_score, disc_why = _component("Disc")

    # Blend in the EXISTING numeric engine's calibrated D/E/Discoverability scores for
    # the 'domain:factor' tags the cluster also carries (that engine is blind to
    # phase-ids and neutral on R/Affected, but its D/E/Disc priors are analyst-tuned —
    # so we take the worst-case of ours and theirs rather than discard its work).
    try:
        from core.threat_modeling.factor_taxonomy import aggregate_threat_model
    except Exception:
        try:
            from src.core.threat_modeling.factor_taxonomy import aggregate_threat_model
        except Exception:
            aggregate_threat_model = None  # type: ignore
    if aggregate_threat_model is not None:
        try:
            legacy = (aggregate_threat_model(phases) or {}).get("dread", {}).get("max_components", {})
            d_score = _clamp(max(d_score, float(legacy.get("damage", 0)) * 10))
            e_score = _clamp(max(e_score, float(legacy.get("exploitability", 0)) * 10))
            disc_score = _clamp(max(disc_score, float(legacy.get("discoverability", 0)) * 10))
        except Exception:
            pass

    # Exploitability boost: a CONFIRMED breach means it was actually exploited — not
    # theoretical. Raise E to at least 'high' and say so.
    from src.core.verdicts import is_breach, normalize as _nv
    verdict = _nv(cluster.get("final_verdict") or cluster.get("verdict"))
    exploited = is_breach(verdict)
    if exploited:
        e_score = _clamp(max(e_score, 8))
        e_why = "Confirmed exploited in this incident (not theoretical). " + e_why

    affected = _affected_deepdive(cluster, phases)

    damage = {"score": round(d_score, 1), "level": _level(d_score), "rationale": d_why}
    reproducibility = {"score": round(r_score, 1), "level": _level(r_score), "rationale": r_why}
    exploitability = {"score": round(e_score, 1), "level": _level(e_score), "exploited": exploited, "rationale": e_why}
    discoverability = {"score": round(disc_score, 1), "level": _level(disc_score),
                       "rationale": "Defender visibility — lower means stealthier/harder to detect. " + disc_why}

    # Overall: impact-weighted mean (Damage + Affected dominate).
    overall = (0.3 * d_score + 0.25 * affected["score"] + 0.2 * e_score
               + 0.15 * r_score + 0.1 * disc_score)
    overall = round(_clamp(overall, 0.0, 10.0), 1)

    # Drivers: union across phases, deduped, order-stable.
    drivers = {"infrastructure": [], "investments": [], "improvements": []}
    seen = {k: set() for k in drivers}
    for p in phases:
        drv = _PHASE_DRIVERS.get(p)
        if not drv:
            continue
        for k in drivers:
            for item in drv.get(k, []):
                if item not in seen[k]:
                    seen[k].add(item)
                    drivers[k].append(item)
    if not any(drivers.values()):
        drivers = {k: list(v) for k, v in _DEFAULT_DRIVERS.items()}

    return DreadAssessment(
        overall_score=overall, overall_level=_level(overall),
        damage=damage, reproducibility=reproducibility, exploitability=exploitability,
        affected=affected, discoverability=discoverability, drivers=drivers,
        attack_complexity=_attack_complexity(r_score, e_score, exploited),
    )
