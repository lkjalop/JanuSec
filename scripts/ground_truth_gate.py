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
from src.core.ingest.cluster_merge import transitive_merge_clusters  # noqa: E402

_BREACH_VERDICTS = {"VALIDATED_BREACH", "LIKELY_BREACH", "INCIDENT", "LIKELY_COMPROMISE"}
_DATA = ROOT / "dump" / "test files"
_FIX = ROOT / "tests" / "fixtures" / "ground_truth"
_FOLDER = {"vesper": "Vesper", "meridian": "Meridian", "santos": "Santos"}


def _load_norm(folder: str) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(glob.glob(str(_DATA / folder / "*"))):
        if path.lower().endswith(".md") or os.path.isdir(path):
            continue
        for raw in parse_file(path, filename=os.path.basename(path)):
            raw.setdefault("_source", os.path.basename(path))
            rows.append(raw)
    norm = [normalize_row(r) for r in rows]
    for i, r in enumerate(norm):
        r["row_index"] = i
    return norm


def _verdict(c: dict) -> str:
    return str(c.get("verdict") or c.get("final_verdict") or "").upper()


def _users(c: dict) -> list[str]:
    return [str(u).lower() for u in (c.get("shared_users") or c.get("shared_accounts") or [])]


def dataset_present(scenario: str) -> bool:
    """True if the scenario's dataset files exist (they're large; some checkouts/CI
    won't have them). Lets the gate skip gracefully instead of failing confusingly."""
    folder = _DATA / _FOLDER[scenario]
    return folder.is_dir() and any(
        not p.lower().endswith(".md") for p in glob.glob(str(folder / "*"))
    )


def evaluate(scenario: str) -> dict:
    fixture = json.loads((_FIX / f"{scenario}.json").read_text(encoding="utf-8"))
    norm = _load_norm(_FOLDER[scenario])
    diag: dict = {}
    clusters = transitive_merge_clusters(None, norm, diagnostics_out=diag)
    actionable = [c for c in clusters if not c.get("_isolated")]

    res: dict = {"scenario": scenario, "rows": len(norm), "actionable": len(actionable),
                 "tp": [], "fn": [], "fp": [], "gaps": {}}
    actor_cluster: dict = {}

    for md in fixture.get("must_detect", []):
        actor = md["actor"].lower()
        hit = next((c for c in actionable
                    if any(actor in u for u in _users(c)) and _verdict(c) in _BREACH_VERDICTS), None)
        if not hit:
            res["fn"].append({"actor": md["actor"], "why": "no breach cluster for actor"})
            continue
        actor_cluster[md["actor"]] = hit
        phases = {(p.get("phase_id") if isinstance(p, dict) else p) for p in (hit.get("phases") or [])}
        want = set(md.get("phases_present_any") or [])
        ep = hit.get("_entry_point") or {}
        res["tp"].append({
            "actor": md["actor"], "verdict": _verdict(hit),
            "entry_point_ok": (ep.get("type") == md.get("entry_point_type")) if md.get("entry_point_type") else None,
            "phases_found": sorted(p for p in (phases & want) if p),
            "phases_ok": bool(phases & want) if want else None,
        })

    for ms in fixture.get("must_suppress", []):
        ent = ms["entity"].lower()
        if any(_verdict(c) in _BREACH_VERDICTS and len(_users(c)) <= 1
               and any(ent in u for u in _users(c)) for c in actionable):
            res["fp"].append({"entity": ms["entity"], "reason": ms["reason"]})

    # known-gap measurements (the truth delta)
    res["gaps"]["fp_network_breaches"] = sum(
        1 for c in actionable if _verdict(c) in _BREACH_VERDICTS and not _users(c))
    for g in fixture.get("known_gaps", []):
        if g["id"] == "exfil_stitched_to_actor":
            dest = g["exfil_destination"].lower()
            stitched = False
            for hit in actor_cluster.values():
                refs = [i for i in (hit.get("row_refs") or []) if isinstance(i, int) and i < len(norm)]
                if any(dest in str(norm[i]).lower() for i in refs):
                    stitched = True
                    break
            res["gaps"]["exfil_stitched_to_actor"] = stitched
    return res


def main() -> None:
    for scenario in ("vesper", "meridian", "santos"):
        r = evaluate(scenario)
        print(f"\n=== {scenario.upper()}: rows={r['rows']} actionable={r['actionable']} ===")
        print(f"  TP (must_detect): {r['tp'] or '—'}")
        print(f"  FN: {r['fn'] or '—'}")
        print(f"  FP (must_suppress fired): {r['fp'] or '—'}")
        print(f"  TRUTH DELTA (known_gaps): {r['gaps']}")


if __name__ == "__main__":
    main()
