"""Narration validation harness — runs the REAL pipeline (parse->normalize->resolve->
cluster->chrono->narrate) on a ground-truth dataset and dumps the executive narrative
for the top cluster so its correctness can be judged against ground truth.

Usage: python scripts/validate_narration.py vesper
"""
from __future__ import annotations
import os, sys, glob, json, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.core.ingest.file_parser import parse_file  # noqa: E402
from src.pipeline.streaming_ingest import normalize_row  # noqa: E402
from src.core.entity_resolver import resolve_entities  # noqa: E402
from src.core.ingest.cluster_merge import transitive_merge_clusters  # noqa: E402
from src.core.chrono.pipeline import accumulate, elevate_clusters  # noqa: E402
from src.core.chrono.sketch_store import ChronoSketchStore  # noqa: E402
from src.core.ingest.cluster_narrator import narrate_top_clusters  # noqa: E402

_FOLDER = {"vesper": "Vesper", "meridian": "Meridian", "santos": "Santos"}


def load(folder: str) -> list[dict]:
    rows = []
    for path in sorted(glob.glob(os.path.join(ROOT, "dump", "test files", folder, "*"))):
        if path.lower().endswith(".md") or os.path.isdir(path):
            continue
        for raw in parse_file(path, filename=os.path.basename(path)):
            raw.setdefault("_source", os.path.basename(path))
            rows.append(raw)
    norm = [normalize_row(r) for r in rows]
    resolve_entities(norm)
    for i, r in enumerate(norm):
        r["row_index"] = i
    return norm


def main():
    scen = (sys.argv[1] if len(sys.argv) > 1 else "vesper").lower()
    norm = load(_FOLDER[scen])
    clusters = transitive_merge_clusters(None, norm, diagnostics_out={})
    actionable = [c for c in clusters if not c.get("_isolated")]
    chrono = ChronoSketchStore()
    accum = accumulate(norm, chrono)
    elevate_clusters(actionable, accum, chrono)

    # rank by confidence x rows
    ranked = sorted(actionable, key=lambda c: (float(c.get("confidence") or 0), len(c.get("row_refs") or [])), reverse=True)
    print(f"=== {scen}: {len(norm)} rows, {len(actionable)} actionable clusters ===")
    for i, c in enumerate(ranked[:6]):
        v = str(c.get("verdict") or c.get("final_verdict") or "")
        users = c.get("shared_users") or c.get("shared_accounts") or []
        phases = [p.get("phase_id") if isinstance(p, dict) else p for p in (c.get("phases") or [])]
        print(f"  [{i}] verdict={v} conf={c.get('confidence')} users={users[:4]} entry={c.get('_entry_point')} phases={phases[:8]}")

    # Narrate the top cluster (the one feeding the CEO exec summary)
    t0 = time.time()
    narratives = narrate_top_clusters(ranked, norm, assessment_id=f"validate-{scen}", top_n=1)
    print(f"\n=== NARRATION ({time.time()-t0:.0f}s) ===")
    for n in narratives:
        print(f"tier={ranked and ranked[0].get('_narrator_tier')} model={n.get('_narrator_model')} verdict={n.get('verdict')} conf={n.get('confidence')}")
        for k in ("attack_narrative", "ioc_summary", "kill_chain_stages", "kill_chain_stage",
                  "fp_indicators", "next_steps", "evidence_refs"):
            if n.get(k):
                val = n[k]
                if isinstance(val, list):
                    val = " | ".join(str(x) for x in val)
                print(f"\n--- {k} ---\n{val}")


if __name__ == "__main__":
    main()
