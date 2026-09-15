"""Deterministic 3-paragraph executive summary of a breach finding.

This is the structured skeleton the LLM narration fills in (structured-slot narration):
every fact — start/end time, affected entities, damage, attack complexity, next
actions, affected controls — is projected from already-computed fields. The LLM never
chooses a fact. If the LLM is unavailable, `paragraphs` renders the same three
paragraphs deterministically, so the executive brief is never empty.

  ¶1  What occurred: window, kill chain, affected users + infrastructure, damage,
       attack complexity (how easy / repeatable).
  ¶2  What to do next: the P1 grounded remediations in DREAD-priority order.
  ¶3  Controls affected: the framework controls the breach bypassed.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any, Optional

# Kill-chain label per phase now lives in the single phase registry (de-brittled).
from src.core.grc import phase_registry as _reg


def _fmt_ts(epoch: Any) -> str:
    try:
        return _dt.datetime.utcfromtimestamp(float(epoch)).strftime("%d %b %H:%M UTC")
    except Exception:
        return ""


def _fmt_duration(span_s: Any) -> str:
    try:
        s = float(span_s)
    except Exception:
        return ""
    if s <= 0:
        return ""
    days = s / 86400.0
    if days >= 1:
        return f"{days:.0f} day{'s' if days >= 2 else ''}"
    hours = s / 3600.0
    if hours >= 1:
        return f"{hours:.0f} hour{'s' if hours >= 2 else ''}"
    return f"{int(s // 60)} min"


def _kill_chain(phases: list[str]) -> list[str]:
    # One representative technique per kill-chain rank, so a chain reads cleanly
    # (e.g. two OAuth phases -> one "initial access" step; two exfil phases -> one).
    by_rank: dict[int, str] = {}
    for p in phases or []:
        kc = _reg.kc(str(p))
        if kc and kc[0] not in by_rank:
            by_rank[kc[0]] = kc[1]
    return [by_rank[r] for r in sorted(by_rank)]


def _oxford(items: list[str]) -> str:
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def build_finding_summary(finding: dict, *, framework_gaps: Optional[dict] = None) -> dict[str, Any]:
    """Project a finding into the structured 3-paragraph exec-summary fields plus a
    deterministic prose render (the guaranteed fallback)."""
    dread = finding.get("dread") or {}
    comps = dread.get("components") or {}
    affected = comps.get("affected") or {}
    damage = comps.get("damage") or {}
    complexity = dread.get("attack_complexity") or {}
    actor = finding.get("actor") or "an unknown actor"
    verdict = str(finding.get("verdict") or "").replace("_", " ").title()
    window = finding.get("window") or {}
    start = _fmt_ts(window.get("start"))
    end = _fmt_ts(window.get("end"))
    duration = _fmt_duration(window.get("span_seconds"))
    kc = _kill_chain(finding.get("phases") or [])

    # ── structured fields ────────────────────────────────────────────────────
    occurred = {
        "actor": actor, "verdict": finding.get("verdict"),
        "kill_chain": kc, "start": start, "end": end, "duration": duration,
        "affected_identities": affected.get("identities") or [],
        "affected_hosts": affected.get("hosts") or [],
        "asset_classes": affected.get("asset_classes") or [],
        "data_scope": affected.get("data_scope") or "",
        "damage_level": damage.get("level"), "damage_rationale": damage.get("rationale"),
        "complexity_level": complexity.get("level"), "complexity_label": complexity.get("label"),
        "dread_score": dread.get("overall_score"), "dread_level": dread.get("overall_level"),
    }
    # ¶2 — P1 remediations first, then the rest, DREAD-priority order.
    ncs = sorted(finding.get("nonconformities") or [],
                 key=lambda n: (0 if n.get("priority") == "P1" else 1, n.get("sla_hours") or 999))
    do_next = [{"priority": n.get("priority"), "sla_hours": n.get("sla_hours"),
                "action": n.get("remediation"), "owner": n.get("owner")} for n in ncs]
    # ¶3 — controls this finding bypassed.
    controls: dict[str, list[str]] = {}
    for n in ncs:
        for fw, cs in (n.get("control_refs") or {}).items():
            controls.setdefault(fw, [])
            for c in cs:
                if c not in controls[fw]:
                    controls[fw].append(c)

    # ── deterministic prose (the fallback / template) ────────────────────────
    when = ""
    if start and end:
        when = f"Between {start} and {end}" + (f" ({duration})" if duration else "")
    elif duration:
        when = f"Over {duration}"
    chain = _oxford(kc) or "malicious activity"
    ids = occurred["affected_identities"]
    hosts = occurred["affected_hosts"]
    assets = occurred["asset_classes"]
    affected_bits = []
    if ids:
        affected_bits.append(f"{len(ids)} identit{'y' if len(ids)==1 else 'ies'} ({_oxford(ids[:3])})")
    if hosts:
        affected_bits.append(f"{len(hosts)} host{'s' if len(hosts)!=1 else ''}")
    if assets:
        affected_bits.append(f"{len(assets)} asset class{'es' if len(assets)!=1 else ''} ({', '.join(assets)})")
    p1 = (
        f"{when + ', ' if when else ''}{actor} was involved in a {verdict or 'breach'} via "
        f"{chain}. Affected: {_oxford(affected_bits) or 'scope undetermined'}."
        + (f" {occurred['data_scope']}." if occurred["data_scope"] else "")
        + (f" Damage: {str(damage.get('level','')).upper()} — {damage.get('rationale','')}" if damage.get("level") else "")
        + (f" Attack complexity: {str(complexity.get('level','')).upper()} — {complexity.get('label','')}." if complexity.get("level") else "")
    )
    p1_all = [a for a in do_next if a["priority"] == "P1"] or do_next
    shown = p1_all[:4]
    action_txt = "; ".join(str(a["action"]).rstrip(".") for a in shown if a.get("action"))
    extra = len(p1_all) - len(shown)
    if extra > 0:
        action_txt += f"; and {extra} more corrective action{'s' if extra != 1 else ''}"
    sla = shown[0]["sla_hours"] if shown else None
    p2 = (f"Do next [{shown[0]['priority']}/{sla}h]: {action_txt}." if action_txt
          else "Do next: contain the affected entities and preserve evidence.")
    fw_parts = []
    for fw in ("iso27001", "soc2", "iso42001"):
        cs = controls.get(fw)
        if cs:
            fw_parts.append(f"{fw.upper()} {', '.join(cs[:4])}")
    fw_summary = ""
    if framework_gaps and framework_gaps.get("iso27001"):
        fg = framework_gaps["iso27001"]
        fw_summary = f" ({fg.get('controls_failing')}/{fg.get('total_controls')} ISO 27001 controls, {fg.get('worst_severity')})"
    p3 = (f"Controls affected: {_oxford(fw_parts)}{fw_summary}." if fw_parts
          else "Controls affected: incident-management controls (A.5.24, A.5.26).")

    return {
        "headline": f"{finding.get('verdict')} · {actor} · DREAD {dread.get('overall_score')} "
                    f"{str(dread.get('overall_level','')).upper()}"
                    + (f" · {start}–{end}" if start and end else ""),
        "occurred": occurred,
        "do_next": do_next,
        "controls_affected": controls,
        "paragraphs": [p1, p2, p3],
    }
