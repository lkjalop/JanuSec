"""Evidence-linked corrective-action candidates.

A deterministic breach supports investigation and remediation planning. It does
not establish that a particular control failed, or start a notification clock.
Formal assertions require the reviewed evidence bridge and obligation engine.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

# ── DREAD level -> remediation priority + SLA (hours) ────────────────────────────
# P1 = contain now; SLA hours are the corrective-action deadline. Critical also trips
# the 72h regulatory breach-notification clock (NDB / GDPR Art.33).
_DREAD_PRIORITY: dict[str, tuple[str, int]] = {
    "critical": ("P1", 24),
    "high":     ("P1", 48),
    "medium":   ("P2", 168),   # 7 days
    "low":      ("P3", 720),   # 30 days
    "trace":    ("P4", 720),
}
_NOTIFY_CLOCK_HOURS = 72  # regulatory breach-notification deadline for critical NCs


def dread_priority(dread_level: str) -> tuple[str, int]:
    """Map a DREAD level to (priority, sla_hours). Defensible and deterministic."""
    return _DREAD_PRIORITY.get(str(dread_level or "").lower(), ("P3", 720))


# Phase-id -> controls / remediation now live in the single phase registry
# (src/core/grc/phase_registry.py); derived views here keep the .get() call sites.
from src.core.grc import phase_registry as _reg
PHASE_COMPLIANCE = {p: _reg.controls(p) for p in _reg.known_phases() if _reg.controls(p)}
PHASE_REMEDIATION = {p: _reg.remediation(p) for p in _reg.known_phases() if _reg.remediation(p)}
_D = _reg.DEFAULT_REMEDIATION


@dataclass
class Nonconformity:
    nc_id: str
    title: str
    breach_ref: str
    actor: str
    dread_score: float
    dread_level: str
    priority: str
    sla_hours: int
    control_refs: dict[str, list[str]]
    mitre: list[str]
    remediation: str
    owner: str
    evidence_rows: list[int]
    notify_deadline_hours: Optional[int] = None
    status: str = "candidate"
    _phase: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "nc_id": self.nc_id,
            "title": self.title,
            "breach_ref": self.breach_ref,
            "actor": self.actor,
            "dread_score": self.dread_score,
            "dread_level": self.dread_level,
            "priority": self.priority,
            "sla_hours": self.sla_hours,
            "control_refs": self.control_refs,
            "mitre": self.mitre,
            "remediation": self.remediation,
            "owner": self.owner,
            "evidence_rows": self.evidence_rows,
            "status": self.status,
            "assertion_status": "candidate",
            "failure_verified": False,
            "phase": self._phase,
        }
        if self.notify_deadline_hours is not None:
            d["notify_deadline_hours"] = self.notify_deadline_hours
        return d


def _cluster_factor_keys(cluster: dict) -> list[str]:
    tags = cluster.get("factor_tags") or {}
    return list(tags.keys()) if isinstance(tags, dict) else list(tags)


def _controls_for(factor_keys: list[str]) -> dict[str, list[str]]:
    """Framework controls from BOTH the phase-id map and factor_to_compliance."""
    out: dict[str, set] = {}
    for k in factor_keys:
        m = PHASE_COMPLIANCE.get(str(k))
        if m:
            for fw, ctrls in m.items():
                out.setdefault(fw, set()).update(ctrls)
    try:
        from src.core.mappings.factor_to_compliance import get_compliance_hits
        for fw, ctrls in get_compliance_hits(factor_keys).items():
            out.setdefault(fw, set()).update(ctrls)
    except Exception:
        pass
    return {fw: sorted(c) for fw, c in out.items() if c}


def _cluster_dread(cluster: dict) -> dict:
    """Decomposed DREAD assessment (with drivers) for the cluster."""
    from src.core.grc.dread import assess_dread
    return assess_dread(cluster).to_dict()


def _row_epoch(row: dict):
    for k in ("_ts_epoch", "_epoch"):
        v = row.get(k)
        if v:
            try:
                return float(v)
            except (TypeError, ValueError):
                pass
    return None


def enrich_campaign_windows(clusters: list[dict], rows: list[dict]) -> None:
    """Set cluster['campaign_window'] to the TRUE min/max event time across the
    cluster's rows. The clustering-derived time_window can badly understate dwell time
    (observed: 7.2h reported vs a 15-day campaign), so the exec summary must use the
    real span. Mutates clusters in place; safe no-op when rows lack timestamps."""
    if not rows:
        return
    n = len(rows)
    for c in clusters or []:
        refs = [i for i in (c.get("row_refs") or []) if isinstance(i, int) and 0 <= i < n]
        epochs = [e for e in (_row_epoch(rows[i]) for i in refs) if e]
        if len(epochs) >= 2:
            lo, hi = min(epochs), max(epochs)
            c["campaign_window"] = {"start": lo, "end": hi, "span_seconds": round(hi - lo, 1)}


def _primary_actor(cluster: dict) -> str:
    # Prefer the dominance-based primary actor from clustering (the identity that owns
    # the most breach-phase rows) over the alphabetical shared_users[0].
    if cluster.get("primary_actor"):
        return str(cluster["primary_actor"])
    for key in ("shared_users", "shared_accounts", "shared_ips", "shared_hosts"):
        vals = cluster.get(key) or []
        if vals:
            return str(vals[0])
    return "unknown"


def build_nonconformities(cluster: dict, *, id_prefix: str = "NC") -> list[dict]:
    """Convert one breach cluster into auditable Nonconformity records — one per
    distinct grounded remediation, each carrying the cluster's DREAD-derived priority,
    its control refs, MITRE, owner, SLA, and evidence. Returns [] for non-breach
    clusters."""
    from src.core.verdicts import is_breach, normalize as _nv
    verdict = _nv(cluster.get("final_verdict") or cluster.get("verdict"))
    if not (is_breach(verdict) or verdict == "SUSPECTED_BREACH"):
        return []

    factor_keys = _cluster_factor_keys(cluster)
    dread = _cluster_dread(cluster)
    dread_score = float(dread.get("overall_score") or 0.0)
    dread_level = str(dread.get("overall_level") or "low")
    priority, sla = dread_priority(dread_level)
    actor = _primary_actor(cluster)
    breach_ref = str(cluster.get("cluster_id") or cluster.get("case_id") or "cluster")
    # Evidence provenance: prefer the narrator's cited refs, but fall back to the
    # cluster's row_refs so evidence is NEVER dropped when narration is skipped/failed.
    _ev = cluster.get("_llm_evidence_refs") or cluster.get("row_refs") or []
    evidence = [int(r) for r in _ev[:20] if isinstance(r, (int, float))]

    try:
        from src.core.ingest.cluster_merge import phase_mitre_techniques
        mitre = sorted(phase_mitre_techniques(factor_keys))
    except Exception:
        mitre = sorted({str(t).upper() for t in (cluster.get("mitre_techniques") or []) if str(t).upper().startswith("T")})

    notify = None  # Only approved applicability facts can establish an obligation.

    ncs: list[dict] = []
    seen: set[tuple[str, str]] = set()
    idx = 0
    for phase in factor_keys:
        rem = PHASE_REMEDIATION.get(str(phase))
        if not rem:
            continue
        remediation, owner = rem
        controls = _controls_for([str(phase)]) or _controls_for(factor_keys)
        dedup = (remediation, owner)
        if dedup in seen:
            continue
        seen.add(dedup)
        idx += 1
        nc = Nonconformity(
            nc_id=f"{id_prefix}-{breach_ref[:16]}-{idx}",
            title=f"{str(phase).replace('_', ' ').replace(':', ' / ').title()} — {actor}",
            breach_ref=breach_ref,
            actor=actor,
            dread_score=round(dread_score, 2),
            dread_level=dread_level,
            priority=priority,
            sla_hours=sla,
            control_refs=controls,
            mitre=mitre,
            remediation=remediation,
            owner=owner,
            evidence_rows=evidence,
            notify_deadline_hours=notify,
            _phase=str(phase),
        )
        ncs.append(nc.to_dict())

    # If no phase had a specific remediation, still emit one aggregate NC so a breach
    # never yields an empty corrective-action register.
    if not ncs:
        remediation, owner = _D
        ncs.append(Nonconformity(
            nc_id=f"{id_prefix}-{breach_ref[:16]}-1",
            title=f"Breach investigation — {actor}",
            breach_ref=breach_ref, actor=actor,
            dread_score=round(dread_score, 2), dread_level=dread_level,
            priority=priority, sla_hours=sla,
            control_refs=_controls_for(factor_keys) or {"iso27001": ["A.5.24", "A.5.26"]},
            mitre=mitre, remediation=remediation, owner=owner,
            evidence_rows=evidence, notify_deadline_hours=notify,
        ).to_dict())
    return ncs


def build_finding(cluster: dict, *, id_prefix: str = "NC") -> Optional[dict]:
    """A finding = one breach cluster expressed for GRC: decomposed DREAD, the driven
    infrastructure/investment/improvement actions, MITRE, evidence, and the mapped
    Nonconformities. Returns None for non-breach clusters."""
    ncs = build_nonconformities(cluster, id_prefix=id_prefix)
    if not ncs:
        return None
    dread = _cluster_dread(cluster)
    finding = {
        "breach_ref": str(cluster.get("cluster_id") or cluster.get("case_id") or "cluster"),
        "actor": _primary_actor(cluster),
        "verdict": str(cluster.get("final_verdict") or cluster.get("verdict") or ""),
        "dread": dread,                       # decomposed D/R/E/A/D + rationale + attack_complexity
        "drivers": dread.get("drivers", {}),  # infrastructure / investments / improvements
        "mitre": ncs[0].get("mitre", []),
        "evidence_rows": ncs[0].get("evidence_rows", []),
        # Prefer the true campaign window (min/max real event time) over the clustering
        # time_window, which can badly understate dwell time.
        "window": cluster.get("campaign_window") or cluster.get("time_window") or {},
        "phases": _cluster_factor_keys(cluster),
        "nonconformities": ncs,
    }
    # Attach the deterministic 3-paragraph summary (start/end, affected, damage,
    # complexity, do-next, controls). LLM slot-filling is layered on top downstream.
    try:
        from src.core.grc.finding_summary import build_finding_summary
        finding["summary"] = build_finding_summary(finding)
    except Exception:
        pass
    return finding


def _finding_provenance(finding: dict, rows_by_idx: dict, transaction_time: Optional[str]) -> dict:
    """Bitemporal provenance for a finding-decision (reuses the existing bitemporal
    dispatch-trace primitives): valid_time = when the evidence was actually true;
    transaction_time = when JanuSec made this decision. This makes each AI decision
    reconstructable and defensible — 'at the time we knew X, here is what we decided'."""
    import datetime as _dt
    try:
        from src.analysis.bitemporal_dispatch_trace import _evidence_content_hash, _decision_id
    except Exception:
        return {}
    ev_rows = [rows_by_idx[i] for i in (finding.get("evidence_rows") or []) if i in rows_by_idx]
    content_hash = _evidence_content_hash(ev_rows) if ev_rows else \
        hashlib.sha256(json.dumps(finding.get("evidence_rows") or [], default=str).encode()).hexdigest()
    window = finding.get("window") or {}

    def _iso(ep):
        try:
            return _dt.datetime.utcfromtimestamp(float(ep)).replace(tzinfo=_dt.timezone.utc).isoformat()
        except Exception:
            return None

    valid_time = {}
    if window.get("start"):
        valid_time["from"] = _iso(window["start"])
    if window.get("end"):
        valid_time["to"] = _iso(window["end"])
    did = _decision_id(str(finding.get("breach_ref") or ""), "grc", "default", transaction_time or "", content_hash)
    return {
        "decision_id": did,
        "valid_time": valid_time,
        "transaction_time": transaction_time,
        "evidence_content_hash": content_hash,
        "note": "valid_time = when the evidence was true; transaction_time = when JanuSec decided.",
    }


def build_audit_pack(clusters: list[dict], *, id_prefix: str = "NC",
                     rows: Optional[list[dict]] = None,
                     transaction_time: Optional[str] = None) -> dict[str, Any]:
    """Assemble the auditor-facing corrective-action register from breach clusters:
    findings (with decomposed DREAD + driven actions), the flat Nonconformity register,
    aggregate control coverage, and a summary. When `rows` is provided, cluster
    campaign windows are corrected to the true event-time span first."""
    if rows:
        enrich_campaign_windows(clusters, rows)
    findings: list[dict] = []
    all_ncs: list[dict] = []
    _rows_by_idx = {int(r["row_index"]): r for r in (rows or [])
                    if isinstance(r, dict) and r.get("row_index") is not None}
    for c in clusters or []:
        f = build_finding(c, id_prefix=id_prefix)
        if f:
            f["provenance"] = _finding_provenance(f, _rows_by_idx, transaction_time)
            findings.append(f)
            all_ncs.extend(f["nonconformities"])

    # Aggregate the driven security investments across all findings — the CISO budget view.
    invest: dict[str, int] = {}
    infra: dict[str, int] = {}
    for f in findings:
        for item in (f["drivers"].get("investments") or []):
            invest[item] = invest.get(item, 0) + 1
        for item in (f["drivers"].get("infrastructure") or []):
            infra[item] = infra.get(item, 0) + 1

    control_index: dict[str, dict[str, list[str]]] = {}
    for nc in all_ncs:
        for fw, ctrls in (nc.get("control_refs") or {}).items():
            for ctrl in ctrls:
                control_index.setdefault(fw, {}).setdefault(ctrl, [])
                if nc["nc_id"] not in control_index[fw][ctrl]:
                    control_index[fw][ctrl].append(nc["nc_id"])

    by_priority: dict[str, int] = {}
    for nc in all_ncs:
        by_priority[nc["priority"]] = by_priority.get(nc["priority"], 0) + 1

    # CISO budget view: which security investments recur across the most findings.
    top_investments = [{"item": k, "findings": v} for k, v in
                       sorted(invest.items(), key=lambda kv: -kv[1])]
    top_infrastructure = [{"item": k, "findings": v} for k, v in
                          sorted(infra.items(), key=lambda kv: -kv[1])]

    pack = {
        "findings": findings,                 # decomposed DREAD + driven actions per breach
        "nonconformities": all_ncs,           # flat corrective-action register
        "control_coverage": control_index,
        "recommended_investments": top_investments,
        "recommended_infrastructure": top_infrastructure,
        "summary": {
            "total_findings": len(findings),
            "total_ncs": len(all_ncs),
            "by_priority": by_priority,
            "frameworks": sorted(control_index.keys()),
            "p1_count": by_priority.get("P1", 0),
        },
    }
    # G2: per-control gap scoring (severity + honest framework denominators).
    try:
        from src.core.grc.control_gaps import build_control_gaps
        pack["control_gaps"] = build_control_gaps(pack)
        pack["summary"]["framework_gaps"] = pack["control_gaps"]["summary"]
    except Exception:
        pass
    # Chain of custody: a tamper-evident hash over each finding's immutable core
    # (actor, verdict, cited evidence rows, DREAD) so the audit pack is verifiable and
    # any later alteration is detectable.
    try:
        _custody_src = [
            {"ref": f.get("breach_ref"), "actor": f.get("actor"), "verdict": f.get("verdict"),
             "evidence": sorted(f.get("evidence_rows") or []),
             "dread": (f.get("dread") or {}).get("overall_score")}
            for f in findings
        ]
        _blob = json.dumps(_custody_src, sort_keys=True, default=str, separators=(",", ":"))
        pack["custody"] = {
            "algorithm": "sha256",
            "digest": hashlib.sha256(_blob.encode("utf-8")).hexdigest(),
            "finding_count": len(findings),
        }
    except Exception:
        pass
    # Coverage visibility: surface any detected phase the registry does not fully map,
    # so brittleness is visible instead of silently defaulting to generic output.
    try:
        _all_phases = {p for f in findings for p in (f.get("phases") or [])}
        pack["coverage_gaps"] = _reg.coverage(_all_phases)
    except Exception:
        pass
    # Assessment-level executive summary = the worst finding's 3-paragraph summary,
    # re-rendered with the framework-gap denominator in the controls paragraph.
    if findings:
        try:
            from src.core.grc.finding_summary import build_finding_summary
            top = max(findings, key=lambda f: float((f.get("dread") or {}).get("overall_score") or 0))
            pack["executive_summary"] = build_finding_summary(
                top, framework_gaps=(pack.get("control_gaps") or {}).get("summary"))
        except Exception:
            pass
    return pack
