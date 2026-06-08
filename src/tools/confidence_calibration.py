from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.core.calibration.confidence_calibration import (
    calibration_metrics,
    export_samples,
    fit_artifact,
    save_artifact,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Export and fit JanuSec confidence calibration artifacts.")
    parser.add_argument("assessments", nargs="+", help="Assessment JSON files to use as labeled samples.")
    parser.add_argument("--samples-out", default="artifacts/calibration/confidence_samples.json")
    parser.add_argument("--artifact-out", default="models/calibration/confidence_v1.json")
    parser.add_argument("--method", choices=("platt", "isotonic"), default="platt")
    args = parser.parse_args()

    samples = export_samples(args.assessments, args.samples_out)
    artifact = fit_artifact(samples, method=args.method)
    save_artifact(artifact, args.artifact_out)
    summary = {
        "samples": len(samples),
        "samples_out": str(Path(args.samples_out)),
        "artifact_out": str(Path(args.artifact_out)),
        "method": args.method,
        "metrics_raw": calibration_metrics(samples),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
