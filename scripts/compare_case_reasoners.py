"""Run immutable local-model comparisons against saved JanusSec assessments."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.api.case_intelligence_endpoints import _prompt
from src.api.ingest_endpoints import _case_view_model
from src.core.model_run_store import ModelRunStore, run_case_model


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", action="append", required=True)
    parser.add_argument("--model", action="append", required=True)
    parser.add_argument("--provider", default="ollama")
    parser.add_argument("--output", default="dump/reports/qwen-case-comparison")
    args = parser.parse_args()
    store = ModelRunStore(args.output)
    failures = 0
    for fixture_name in args.fixture:
        fixture_path = Path(fixture_name).resolve(strict=True)
        assessment = json.loads(fixture_path.read_text(encoding="utf-8"))
        assessment_id = str(assessment.get("assessment_id") or fixture_path.stem)
        tenant_id = str(assessment.get("org") or "benchmark")
        job = {
            "status": "ready",
            "stage": "complete",
            "percent": 100,
            "row_count": int(assessment.get("rows_processed") or assessment.get("uploaded_row_count") or 0),
        }
        view = _case_view_model(assessment_id, tenant_id, job, assessment)
        for model in args.model:
            try:
                text, meta = run_case_model(args.provider, model, _prompt(view))
                try:
                    output = json.loads(text)
                    parse_error = None
                except json.JSONDecodeError as exc:
                    output = {"raw_text": text}
                    parse_error = str(exc)
                record = store.create(
                    tenant_id,
                    assessment_id,
                    {
                        "provider": args.provider,
                        "model": model,
                        "mode": "compare",
                        "selection": {
                            "scope": "assessment",
                            "provider": args.provider,
                            "model": model,
                            "immutable": True,
                        },
                        "evidence_pack_hash": (view.get("report_context") or {}).get("evidence_pack_hash"),
                        "prompt_version": "janusec.case-review/v1",
                        "output": output,
                        "parse_error": parse_error,
                        **meta,
                    },
                )
                print(json.dumps({
                    "assessment": assessment_id,
                    "model": model,
                    "run_id": record["run_id"],
                    "latency_ms": record.get("latency_ms"),
                    "parse_error": parse_error,
                    "record_hash": record["record_hash"],
                }))
            except Exception as exc:
                failures += 1
                record = store.create(
                    tenant_id,
                    assessment_id,
                    {
                        "provider": args.provider,
                        "model": model,
                        "mode": "compare",
                        "selection": {"scope": "assessment", "provider": args.provider, "model": model, "immutable": True},
                        "evidence_pack_hash": (view.get("report_context") or {}).get("evidence_pack_hash"),
                        "prompt_version": "janusec.case-review/v1",
                        "status": "failed",
                        "error": str(exc),
                    },
                )
                print(json.dumps({"assessment": assessment_id, "model": model, "run_id": record["run_id"], "error": str(exc)}))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
