#!/usr/bin/env python3
"""End-to-end clustering regression gate.

Runs the REAL ingest path (parse -> normalize -> transitive_merge_clusters) on the
Vesper / Meridian / Santos datasets and snapshots golden metrics. This is the
deterministic, server-free gate that the HTTP pipeline could not provide reliably
on Windows. It exists because unit tests alone let a 66.7% evidence-loss bug ship —
this asserts on whole-pipeline behavior, not isolated functions.

Metrics captured per scenario (all LLM-free, so it is fast and deterministic):
  - actionable_clusters / isolated_clusters
  - cluster_merge_version
  - evidence_retention_rate, oversized_clusters, oversized_rows_capped
  - behavioral_links
  - empty_entity_clusters  (clusters with no shared_users/ips/hosts — over-merge smell)
  - validated_breaches     (count of VALIDATED_BREACH verdicts)

Usage:
    python scripts/e2e_assess.py                 # run + compare to baseline, exit 1 on regression
    python scripts/e2e_assess.py --update-baseline
    python scripts/e2e_assess.py --json          # emit metrics as JSON only

Baseline lives at tests/fixtures/e2e_golden_baseline.json. Tolerances are relative
(default 15%) so narration/LLM nondeterminism does not flake the gate; structural
invariants (merge version, zero empty-entity clusters) are exact.
"""
from __future__ import annotations
import sys, os, glob, json, argparse, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from src.core.ingest.file_parser import parse_file
from src.core.ingest.assessment_worker import _normalize_ingest_row
from src.core.ingest.cluster_merge import transitive_merge_clusters, _CLUSTER_MERGE_VERSION

DATA = ROOT / "dump" / "test files"
SCENARIOS = {"vesper": "Vesper", "meridian": "Meridian", "santos": "Santos"}
BASELINE = ROOT / "tests" / "fixtures" / "e2e_golden_baseline.json"
REL_TOL = 0.15  # ±15% on count metrics


def _load_rows(folder: str) -> list[dict]:
    files = [f for f in sorted(glob.glob(str(DATA / folder / "*")))
             if not f.lower().endswith(".md") and not os.path.isdir(f)]
    rows: list[dict] = []
    ridx = 0
    for path in files:
        try:
            for raw in parse_file(path, filename=os.path.basename(path)):
                raw.setdefault("_source", os.path.basename(path))
                rows.append(_normalize_ingest_row(raw, ridx))
                ridx += 1
        except Exception as exc:  # pragma: no cover - data-dependent
            print(f"  WARN parse {os.path.basename(path)}: {exc}", file=sys.stderr)
    # Entity resolution (matches production): backfill host->owner so host-only rows
    # stitch to the identity campaign instead of fragmenting into no-user clusters.
    try:
        from src.core.entity_resolver import resolve_entities
        resolve_entities(rows)
    except Exception as exc:  # pragma: no cover
        print(f"  WARN resolve_entities: {exc}", file=sys.stderr)
    return rows


def assess(folder: str) -> dict:
    rows = _load_rows(folder)
    diag: dict = {}
    clusters = transitive_merge_clusters(None, rows, diagnostics_out=diag)
    actionable = [c for c in clusters if not c.get("_isolated")]
    isolated = [c for c in clusters if c.get("_isolated")]
    empty_entity = sum(
        1 for c in actionable
        if not (c.get("shared_users") or c.get("shared_ips") or c.get("shared_hosts"))
    )
    vbreach = sum(
        1 for c in actionable
        if str(c.get("verdict") or c.get("final_verdict") or "").upper() == "VALIDATED_BREACH"
    )
    return {
        "rows": len(rows),
        "actionable_clusters": len(actionable),
        "isolated_clusters": len(isolated),
        "cluster_merge_version": diag.get("cluster_merge_version"),
        "evidence_retention_rate": diag.get("evidence_retention_rate"),
        "oversized_clusters": diag.get("oversized_clusters"),
        "oversized_rows_capped": diag.get("oversized_rows_capped"),
        "behavioral_links": diag.get("behavioral_links"),
        "empty_entity_clusters": empty_entity,
        "validated_breaches": vbreach,
    }


def run_all() -> dict:
    out = {"_merge_version": _CLUSTER_MERGE_VERSION, "scenarios": {}}
    for name, folder in SCENARIOS.items():
        t0 = time.time()
        out["scenarios"][name] = assess(folder)
        out["scenarios"][name]["_elapsed_s"] = round(time.time() - t0, 1)
    return out


# Exact-match invariants (structural correctness, never tolerance-fuzzed).
EXACT_KEYS = {"cluster_merge_version", "empty_entity_clusters"}
# Keys compared with relative tolerance.
TOL_KEYS = {"actionable_clusters", "isolated_clusters", "behavioral_links",
            "validated_breaches", "oversized_clusters"}


def compare(current: dict, baseline: dict) -> list[str]:
    failures: list[str] = []
    for scen, cur in current["scenarios"].items():
        base = baseline.get("scenarios", {}).get(scen)
        if base is None:
            failures.append(f"{scen}: no baseline entry")
            continue
        for k in EXACT_KEYS:
            if cur.get(k) != base.get(k):
                failures.append(f"{scen}.{k}: {cur.get(k)} != baseline {base.get(k)}")
        for k in TOL_KEYS:
            cv, bv = cur.get(k) or 0, base.get(k) or 0
            if bv == 0:
                if cv != 0:
                    failures.append(f"{scen}.{k}: {cv} != baseline 0")
            elif abs(cv - bv) / bv > REL_TOL:
                failures.append(f"{scen}.{k}: {cv} outside ±{int(REL_TOL*100)}% of baseline {bv}")
    return failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    current = run_all()

    if args.json:
        print(json.dumps(current, indent=2))
        return 0

    for scen, m in current["scenarios"].items():
        print(f"{scen:9s} rows={m['rows']:6d} clusters={m['actionable_clusters']:3d}"
              f" (+{m['isolated_clusters']} iso) retention={m['evidence_retention_rate']}"
              f" links={m['behavioral_links']} empty_entity={m['empty_entity_clusters']}"
              f" vbreach={m['validated_breaches']} [{m['_elapsed_s']}s]")

    if args.update_baseline:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(current, indent=2), encoding="utf-8")
        print(f"\nBaseline written to {BASELINE.relative_to(ROOT)}")
        return 0

    if not BASELINE.exists():
        print("\nNo baseline yet. Run with --update-baseline to create one.")
        return 0

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    failures = compare(current, baseline)
    if failures:
        print("\nE2E GATE FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nE2E GATE PASSED (within tolerance of baseline)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
