import os
import json
from datetime import datetime
from typing import Dict, Any

FEEDBACK_DIR = os.path.join(os.getcwd(), 'data', 'feedback')
os.makedirs(FEEDBACK_DIR, exist_ok=True)
FEEDBACK_PATH = os.path.join(FEEDBACK_DIR, 'feedback.jsonl')


def persist_feedback(entry: Dict[str, Any]) -> bool:
    try:
        entry_copy = dict(entry)
        entry_copy.setdefault('captured_at', datetime.utcnow().isoformat())
        with open(FEEDBACK_PATH, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(entry_copy) + '\n')
        return True
    except Exception:
        return False


def make_feedback_dict(
    feedback_id: str,
    report_id: str,
    analyst_id: str,
    correction_type: str,
    original: Any,
    corrected: Any,
    reason: str,
) -> Dict[str, Any]:
    return {
        'feedback_id': feedback_id,
        'report_id': report_id,
        'analyst_id': analyst_id,
        'captured_at': datetime.utcnow().isoformat(),
        'correction_type': correction_type,
        'original_value': original,
        'corrected_value': corrected,
        'correction_reasoning': reason,
    }


def make_feedback(*args, **kwargs):
    """Backward-compatible wrapper used by older callers/tests.

    Delegates to `make_feedback_dict` which is the canonical factory.
    """
    return make_feedback_dict(*args, **kwargs)
