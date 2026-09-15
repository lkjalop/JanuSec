"""Ground-truth gate — assert detection against TRUTH, not metric drift.

The failure mode that produced months of whack-a-mole: the e2e gate asserted on
cluster COUNTS (did clustering move?), never on whether the right BREACH was
detected, the exfil stitched to the actor, or red herrings were suppressed. So
regressions in *correctness* hid behind stable *metrics*.

This gate evaluates each dataset against a ground-truth fixture
(tests/fixtures/ground_truth/<scenario>.json):
  - must_detect   : actor X must surface as a breach (TP) with the right entry point/phases
  - must_suppress : red-herring / sanctioned entity must NOT be a standalone breach (else FP)
  - known_gaps    : the documented breaks this gate exists to close (Phase 1-2) — MEASURED
                    and printed as the truth delta, so a fix is confirmed against truth.

Runs parse -> normalize -> cluster (fast, deterministic). ChronoGraph/narration
assertions are layered in once the entity layer (Phase 1-2) stitches the rows that
those stages need.

    python scripts/ground_truth_gate.py            # print the truth delta for all 3
"""

from __future__ import annotations

import glob
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.core.ingest.file_parser import parse_file  # noqa: E402
from src.pipeline.streaming_ingest import normalize_row  # noqa: E402
from src.core.entity_resolver import resolve_entities  # noqa: E402
from src.core.ingest.cluster_merge import transitive_merge_clusters  # noqa: E402
from src.core.chrono.sketch_store import ChronoSketchStore  # noqa: E402
from src.core.chrono.pipeline import accumulate, elevate_clusters  # noqa: E402
from src.core.acceptance_truth import evaluate_assessment_truth  # noqa: E402
from src.core.evidence_contract.case_partition import build_case_partitions  # noqa: E402

# Ground-truth grading uses the STRICT confirmed-breach set (SUSPECTED_BREACH is a
# weaker signal, so a red herring landing at "suspected" is not counted as an FP).
from src.core.verdicts import CONFIRMED_BREACH_VERDICTS as _BREACH_VERDICTS  # noqa: E402

_DATA = ROOT / "tests" / "fixtures" / "telemetry_corpora"
_FIX = ROOT / "tests" / "fixtures" / "ground_truth"
_FOLDER = {"vesper": "Vesper", "meridian": "Meridian", "santos": "Santos"}


def _load_norm(folder: str) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(glob.glob(str(_DATA / folder / "*"))):
        if path.lower().endswith(".md") or os.path.isdir(path):
            continue
        for raw in parse_file(path, filename=os.path.basename(path)):
            # Benchmark blind: fixture annotations are not production evidence.
            for field in ("_cluster", "_anomaly", "_severity", "_note", "_risk"):
                raw.pop(field, None)
            if "cluster:" in str(raw.get("notes") or "").lower():
                raw.pop("notes", None)
            raw.setdefault("_source", os.path.basename(path))
            rows.append(raw)
    norm = [normalize_row(r) for r in rows]
    # Phase 1: entity resolution — backfill host->owner so host-only telemetry
    # (e.g. the cumulative exfil rows) stitches to the identity campaign.
    resolve_entities(norm)
    for i, r in enumerate(norm):
        r["row_index"] = i
    return norm


def _verdict(c: dict) -> str:
    return str(c.get("verdict") or c.get("final_verdict") or "").upper()


def _users(c: dict) -> list[str]:
    return [str(u).lower() for u in (c.get("shared_users") or c.get("shared_accounts") or [])]


def _matches_selector(cluster: dict, selector: dict) -> bool:
    """Match semantic truth selectors, never unstable cluster IDs."""
    actor = str(selector.get("actor") or "").lower()
    ip = str(selector.get("ip") or "").lower()
    phase = str(selector.get("phase") or "").lower()
    phases = {
        str(p.get("phase_id") if isinstance(p, dict) else p).lower()
        for p in (cluster.get("phases") or [])
    } | {str(p).lower() for p in (cluster.get("present_phase_ids") or [])}
    return (
        (not actor or any(actor == user or actor in user for user in _users(cluster)))
        and (not ip or ip in {str(v).lower() for v in (cluster.get("shared_ips") or [])})
        and (not phase or phase in phases)
    )


def dataset_present(scenario: str) -> bool:
    """True if the scenario's dataset files exist (they're large; some checkouts/CI
    won't have them). Lets the gate skip gracefully instead of failing confusingly."""
    folder = _DATA / _FOLDER[scenario]
    return folder.is_dir() and any(not p.lower().endswith(".md") for p in glob.glob(str(folder / "*")))


def evaluate(scenario: str) -> dict:
    fixture = json.loads((_FIX / f"{scenario}.json").read_text(encoding="utf-8"))
    norm = _load_norm(_FOLDER[scenario])
    diag: dict = {}
    clusters = transitive_merge_clusters(None, norm, diagnostics_out=diag)
    actionable = [c for c in clusters if not c.get("_isolated")]

    # Phase 2 full-pipeline: ChronoGraph long-horizon detection (the SAME code the
    # worker runs). Fresh store per dataset (no cross-contamination). This is where the
    # cumulative <350MB exfil to the lookalike destination becomes a factor on the
    # actor's cluster — the signal that only emerges across the batch, not per-row.
    _chrono = ChronoSketchStore()
    _accum = accumulate(norm, _chrono)
    elevate_clusters(actionable, _accum, _chrono)

    res: dict = {
        "scenario": scenario,
        "rows": len(norm),
        "actionable": len(actionable),
        "tp": [],
        "fn": [],
        "fp": [],
        "false_suspected": [],
        "separation_failures": [],
        "role_failures": [],
        "gaps": {},
    }
    actor_cluster: dict = {}

    for md in fixture.get("must_detect", []):
        actor = str(md.get("actor") or md.get("ip") or md.get("id") or "case").lower()
        candidates = [c for c in actionable if _matches_selector(c, md) and _verdict(c) in _BREACH_VERDICTS]
        want = set(md.get("phases_present_any") or [])

        def rank(candidate: dict) -> tuple[int, int, int]:
            candidate_phases = {
                p.get("phase_id") if isinstance(p, dict) else p for p in (candidate.get("phases") or [])
            } | set(candidate.get("present_phase_ids") or [])
            ep_ok = (candidate.get("_entry_point") or {}).get("type") == md.get("entry_point_type")
            return (int(ep_ok), len(candidate_phases & want), len(candidate_phases))

        hit = max(candidates, key=rank) if candidates else None
        if not hit:
            res["fn"].append({"actor": actor, "why": "no breach cluster for selector"})
            continue
        actor_cluster[actor] = hit
        phases = {(p.get("phase_id") if isinstance(p, dict) else p) for p in (hit.get("phases") or [])} | set(
            hit.get("present_phase_ids") or []
        )
        ep = hit.get("_entry_point") or {}
        res["tp"].append(
            {
                "actor": actor,
                "verdict": _verdict(hit),
                "entry_point_ok": (ep.get("type") == md.get("entry_point_type"))
                if md.get("entry_point_type")
                else None,
                "phases_found": sorted(p for p in (phases & want) if p),
                "phases_ok": bool(phases & want) if want else None,
            }
        )

    for ms in fixture.get("must_suppress", []):
        ent = ms["entity"].lower()
        matching = [
            c
            for c in actionable
            if len(_users(c)) <= 1 and any(ent in u for u in _users(c))
        ]
        if any(
            _verdict(c) in _BREACH_VERDICTS and len(_users(c)) <= 1 and any(ent in u for u in _users(c))
            for c in actionable
        ):
            res["fp"].append({"entity": ms["entity"], "reason": ms["reason"]})
        if any(_verdict(c) == "SUSPECTED_BREACH" for c in matching):
            res["false_suspected"].append({"entity": ms["entity"], "reason": ms["reason"]})

    for group in fixture.get("must_separate", []):
        selectors = group.get("selectors") or []
        for cluster in actionable:
            matched = [selector.get("id") or selector.get("actor") or selector.get("ip") for selector in selectors if _matches_selector(cluster, selector)]
            if len(matched) > 1:
                res["separation_failures"].append(
                    {"assertion": group.get("id"), "cluster_id": cluster.get("cluster_id"), "matched": matched}
                )

    for assertion in fixture.get("role_assertions", []):
        entity = str(assertion.get("entity") or "").lower()
        role = str(assertion.get("role") or "").lower()
        found = any(
            any(
                str(item.get("entity") or "").lower() == entity and str(item.get("role") or "").lower() == role
                for item in (cluster.get("entity_roles") or [])
            )
            for cluster in actionable
        )
        if not found:
            res["role_failures"].append({"entity": entity, "role": role})

    # known-gap measurements (the truth delta)
    expected_non_identity = [item for item in fixture.get("must_detect", []) if item.get("ip") and not item.get("actor")]
    res["gaps"]["fp_network_breaches"] = sum(
        1
        for c in actionable
        if _verdict(c) in _BREACH_VERDICTS
        and not _users(c)
        and not any(_matches_selector(c, selector) for selector in expected_non_identity)
    )
    for g in fixture.get("known_gaps", []):
        if g["id"] == "exfil_stitched_to_actor":
            dest = g["exfil_destination"].lower()
            stitched = False
            for hit in actor_cluster.values():
                # The chrono elevation attaches the cumulative exfil destination to the
                # actor's cluster (even though the benign per-row transfers were filtered
                # out of clustering). That recorded destination IS the stitch.
                exfil_dests = hit.get("_exfil_destinations") or {}
                if any(dest in str(rec.get("destination", "")).lower() for rec in exfil_dests.values()):
                    stitched = True
                    break
                refs = [i for i in (hit.get("row_refs") or []) if isinstance(i, int) and i < len(norm)]
                if any(dest in str(norm[i]).lower() for i in refs):
                    stitched = True
                    break
            res["gaps"]["exfil_stitched_to_actor"] = stitched
        if g["id"] == "full_killchain_one_cluster":
            min_phases = int(g.get("target_min_phases") or 5)
            # present_phase_ids = the actor's full kill chain across the parent campaign
            # (decomposition surfaces it per-actor, so red herrings aren't mixed in).
            best = 0
            for hit in actor_cluster.values():
                best = max(best, len({p for p in (hit.get("present_phase_ids") or []) if p}))
            res["gaps"]["actor_killchain_phases"] = best
            res["gaps"]["full_killchain_one_cluster"] = best >= min_phases
    # Release authority: evaluate immutable, role-aware case partitions. The
    # legacy lists above remain diagnostic compatibility output only.
    partitions = build_case_partitions(
        tenant_id="acceptance", assessment_id=f"acceptance-{scenario}",
        threat_cases=actionable, analysis_clusters=actionable, rows=norm,
    )
    res["authoritative_truth"] = evaluate_assessment_truth(partitions, fixture)
    res["_clusters"] = actionable
    return res


def main() -> None:
    for scenario in ("vesper", "meridian", "santos"):
        r = evaluate(scenario)
        print(f"\n=== {scenario.upper()}: rows={r['rows']} actionable={r['actionable']} ===")
        print(f"  TP (must_detect): {r['tp'] or '—'}")
        print(f"  FN: {r['fn'] or '—'}")
        print(f"  FP (must_suppress fired): {r['fp'] or '—'}")
        print(f"  FALSE SUSPECTED: {r['false_suspected'] or '—'}")
        print(f"  AUTHORITATIVE ROLE-AWARE GATE: {r['authoritative_truth']}")
        print(f"  TRUTH DELTA (known_gaps): {r['gaps']}")


if __name__ == "__main__":
    main()
