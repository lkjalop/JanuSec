#!/usr/bin/env python3
"""Generate a shareable correctness-proof artifact from the acceptance harness.

`pytest -m acceptance` is JanuSec's deterministic-correctness evidence — the thing an
LLM-wrapper can't produce. This packages a run into a human-readable proof
(artifacts/ACCEPTANCE_PROOF.md) for a buyer / auditor / hiring manager: what is asserted,
against which ground-truth datasets, and the pass/fail result.

Usage:  python scripts/acceptance_proof.py
"""
from __future__ import annotations

import datetime
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The invariants the harness guarantees (kept in sync with tests/ACCEPTANCE.md).
_INVARIANTS = [
    ("Right actor & verdict", "martin.chen -> VALIDATED_BREACH with the OAuth-consent entry point"),
    ("Red herrings suppressed", "anna / svc_jenkins / david never graded as confirmed breaches"),
    ("Full kill chain in one campaign", ">=5 phases for the actor; red herrings stay <=2"),
    ("Exfil stitched to actor", "cumulative lookalike-destination exfil attaches to the breach"),
    ("Detectors don't go silent", "every kill-chain detector fires; NDJSON shadow-shape guarded"),
    ("Narration doesn't fall back", "clean-JSON model, <think> stripped, truncation salvaged"),
    ("CEO report populated", "a VALIDATED_BREACH yields non-empty kill_chain/stride/maestro/controls"),
    ("HTML export carries CEO sections", "Severity Distribution + Top MITRE present"),
    ("LIVE export deterministic", "same assessment_id -> identical report data"),
    ("Canonical campaign truth", "one Campaign object: actor/kill-chain/IOCs/timeline/confidence"),
    ("Personas render from campaign", "all 8 personas ground in the canonical campaign"),
    ("State singleton", "one DECISION_CACHE; a recorded breach is visible to the report"),
]


def main() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-m", "acceptance", "-p", "no:cacheprovider",
         "-o", "addopts=", "--timeout=600", "-q"],
        cwd=str(ROOT), capture_output=True, text=True,
    )
    tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    m = re.search(r"(\d+) passed", tail)
    passed = m.group(1) if m else "?"
    failed = bool(re.search(r"\d+ failed", tail))
    status = "❌ FAILING" if failed or proc.returncode != 0 else "✅ PASSING"
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# JanuSec — Acceptance Proof",
        "",
        f"**Status: {status}** — {passed} acceptance assertions, generated {ts}.",
        "",
        "This is the deterministic-correctness evidence behind JanuSec's breach detection,",
        "validated against ground-truth datasets (not LLM-inferred). Regenerate with",
        "`python scripts/acceptance_proof.py`.",
        "",
        "## Ground-truth datasets",
        "- **VESPER** — true-positive multi-stage breach (APT29-style on martin.chen)",
        "- **Meridian** — clean positive control (no VESPER leakage)",
        "- **Santos** — noisy / pentest / false-positive resistance",
        "",
        "## What every release must satisfy",
        "",
        "| Invariant | Guarantee |",
        "|---|---|",
    ]
    lines += [f"| {name} | {desc} |" for name, desc in _INVARIANTS]
    lines += ["", f"_Result line: `{tail}`_", ""]

    out_dir = ROOT / "artifacts"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / "ACCEPTANCE_PROOF.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    _console = ("FAILING" if (failed or proc.returncode != 0) else "PASSING")
    print(f"{_console} - {passed} passed. Wrote {out}")
    return 0 if not failed and proc.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
