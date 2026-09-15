"""Evaluate saved agent telemetry locally; never changes the reviewed baseline."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.core.agent_behavior import evaluate_agent_event

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    events = json.loads(args.events.read_text(encoding="utf-8"))
    results = [evaluate_agent_event(item["event"], baseline, descriptors=item["descriptors"]) for item in events]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps({"evaluated": len(results), "review_required": sum(r["status"] == "review_required" for r in results)}))
