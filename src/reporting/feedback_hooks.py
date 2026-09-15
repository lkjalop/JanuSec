from typing import Dict, Any, List
from datetime import datetime
from src.repositories import audit_repo
from src.reporting.feedback_batcher import persist_feedback, apply_feedback_to_telemetry
from .feedback_capture import make_feedback


_FEEDBACK_STORE: List[Dict[str, Any]] = []


def record_feedback(report_id: str, correction_type: str, original: Any, corrected: Any, reason: str, analyst_id: str) -> Dict[str, Any]:
    fid = f"fb_{len(_FEEDBACK_STORE)+1}"
    fb = make_feedback(fid, report_id, analyst_id, correction_type, original, corrected, reason)
    entry = fb.model_dump() if hasattr(fb, "model_dump") else dict(fb)
    _FEEDBACK_STORE.append(entry)
    # append into batch for periodic recompute
    try:
        persist_feedback(entry)
        # attempt a lightweight telemetry update immediately
        try:
            apply_feedback_to_telemetry(entry)
        except Exception:
            pass
    except Exception:
        try:
            audit_repo.insert_audit({'report_id': report_id, 'note': f'failed to enqueue feedback {entry.get("feedback_id")}', 'recipients': []})
        except Exception:
            pass
    return entry


def list_feedback(report_id: str) -> List[Dict[str, Any]]:
    return [f for f in _FEEDBACK_STORE if f.get("report_id") == report_id]


def mark_false_flag(report: Dict[str, Any], analyst_id: str, reason: str) -> Dict[str, Any]:
    verdict = report.get("verdict", {})
    return record_feedback(
        report_id=report.get("report_id", "unknown"),
        correction_type="false_positive",
        original=verdict.get("final_verdict"),
        corrected="CLEAN",
        reason=reason,
        analyst_id=analyst_id,
    )


def adjust_confidence(report: Dict[str, Any], analyst_id: str, new_confidence: float, reason: str) -> Dict[str, Any]:
    verdict = report.get("verdict", {})
    return record_feedback(
        report_id=report.get("report_id", "unknown"),
        correction_type="confidence_adjustment",
        original=verdict.get("final_confidence"),
        corrected=new_confidence,
        reason=reason,
        analyst_id=analyst_id,
    )


def factor_disagreement(report: Dict[str, Any], analyst_id: str, factor_name: str, reason: str) -> Dict[str, Any]:
    return record_feedback(
        report_id=report.get("report_id", "unknown"),
        correction_type="factor_disagreement",
        original=factor_name,
        corrected=f"disagree:{factor_name}",
        reason=reason,
        analyst_id=analyst_id,
    )


def playbook_mismatch(report: Dict[str, Any], analyst_id: str, playbook_id: str, reason: str) -> Dict[str, Any]:
    return record_feedback(
        report_id=report.get("report_id", "unknown"),
        correction_type="playbook_mismatch",
        original=playbook_id,
        corrected=f"mismatch:{playbook_id}",
        reason=reason,
        analyst_id=analyst_id,
    )
