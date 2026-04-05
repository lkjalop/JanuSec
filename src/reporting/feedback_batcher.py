import json
import os
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from .feedback_processor import process_batches

FEEDBACK_BATCH_DIR = os.environ.get('FEEDBACK_BATCH_DIR', 'data/feedback')
os.makedirs(FEEDBACK_BATCH_DIR, exist_ok=True)


def persist_feedback(feedback: Dict[str, Any]) -> str:
    """Append a feedback dict to a JSONL batch file and return the path."""
    fname = os.path.join(FEEDBACK_BATCH_DIR, f"feedback_{datetime.utcnow().strftime('%Y%m%d')}.jsonl")
    try:
        with open(fname, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(feedback, default=str) + '\n')
        return fname
    except Exception:
        return ''


def apply_feedback_to_telemetry(feedback: Dict[str, Any], telemetry_path: Optional[str] = None) -> Dict[str, Any]:
    """Apply a lightweight suggested_weight_adjustment to a telemetry JSON file.

    This is intentionally simple: it reads a telemetry JSON (if exists), updates
    factor weight counters based on `suggested_weight_adjustment` in feedback,
    and writes back the telemetry. Returns the updated telemetry dict.
    """
    if telemetry_path is None:
        telemetry_path = os.path.join(FEEDBACK_BATCH_DIR, 'telemetry.json')
    try:
        if os.path.exists(telemetry_path):
            with open(telemetry_path, 'r', encoding='utf-8') as fh:
                tele = json.load(fh)
        else:
            tele = {'factor_weights': {}}
        swa = feedback.get('suggested_weight_adjustment') or {}
        for factor, delta in swa.items():
            tele['factor_weights'][factor] = tele['factor_weights'].get(factor, 0.0) + float(delta)
        with open(telemetry_path, 'w', encoding='utf-8') as fh:
            json.dump(tele, fh)
        return tele
    except Exception:
        return {}


def process_feedback_batches(dry_run: bool = True) -> Dict[str, Any]:
    """Convenience wrapper to process all feedback batches using feedback_processor."""
    try:
        return process_batches(dry_run=dry_run)
    except Exception as e:
        return {'error': str(e)}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true', help='Apply proposals to priors')
    args = parser.parse_args()
    res = process_feedback_batches(dry_run=not args.apply)
    print(res)
