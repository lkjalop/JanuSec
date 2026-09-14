"""Append-only state receipts for asynchronous model execution."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any


_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")
_TERMINAL = {"completed", "failed", "cancelled", "budget_exhausted"}
_TRANSITIONS = {
    None: {"queued"},
    "queued": {"running", "cancelled", "budget_exhausted", "failed"},
    "running": {"correcting", "escalating", "completed", "cancelled", "budget_exhausted", "failed"},
    "correcting": {"escalating", "completed", "cancelled", "budget_exhausted", "failed"},
    "escalating": {"completed", "cancelled", "budget_exhausted", "failed"},
}


def _part(value: str) -> str:
    if not value or not _SAFE.fullmatch(value):
        raise ValueError("invalid_model_job_path_component")
    return value


def _hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


class AsyncModelRunStore:
    """One immutable receipt file per transition; no state file is overwritten."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or os.getenv("MODEL_JOB_ROOT", "data/model-run-jobs")).resolve()

    def _directory(self, tenant_id: str, assessment_id: str, job_id: str) -> Path:
        path = self.root / _part(tenant_id) / _part(assessment_id) / _part(job_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def create(
        self, *, tenant_id: str, assessment_id: str, request: dict[str, Any],
        hard_budget_seconds: float,
    ) -> dict[str, Any]:
        job_id = f"model-job-{uuid.uuid4().hex[:16]}"
        return self.transition(
            tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
            status="queued",
            details={
                "request": request,
                "hard_budget_seconds": hard_budget_seconds,
                "queued_at": time.time(),
            },
        )

    def transition(
        self, *, tenant_id: str, assessment_id: str, job_id: str,
        status: str, details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        directory = self._directory(tenant_id, assessment_id, job_id)
        prior = self.load(tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id, required=False)
        previous_status = prior.get("status") if prior else None
        if previous_status in _TERMINAL:
            raise ValueError("model_job_already_terminal")
        if status not in _TRANSITIONS.get(previous_status, set()):
            raise ValueError(f"invalid_model_job_transition:{previous_status}->{status}")
        sequence = len(prior.get("partial_run_receipts") or []) if prior else 0
        previous_hash = prior.get("receipt_hash") if prior else None
        content = {
            "schema_version": "janusec.model-run-state/v1",
            "job_id": job_id,
            "tenant_id": tenant_id,
            "assessment_id": assessment_id,
            "sequence": sequence,
            "status": status,
            "recorded_at": time.time(),
            "previous_receipt_hash": previous_hash,
            "details": dict(details or {}),
        }
        receipt = {**content, "receipt_hash": _hash(content)}
        path = directory / f"{sequence:04d}-{status}.json"
        with path.open("x", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, ensure_ascii=False, default=str)
        return self.load(tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id)

    def load(
        self, *, tenant_id: str, assessment_id: str, job_id: str, required: bool = True,
    ) -> dict[str, Any]:
        directory = self._directory(tenant_id, assessment_id, job_id)
        paths = sorted(directory.glob("[0-9][0-9][0-9][0-9]-*.json"))
        if not paths:
            if required:
                raise FileNotFoundError("model_job_not_found")
            return {}
        receipts = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        previous = None
        for index, receipt in enumerate(receipts):
            content = {key: value for key, value in receipt.items() if key != "receipt_hash"}
            if receipt.get("sequence") != index or receipt.get("previous_receipt_hash") != previous:
                raise ValueError("model_job_receipt_chain_invalid")
            if _hash(content) != receipt.get("receipt_hash"):
                raise ValueError("model_job_receipt_hash_invalid")
            previous = receipt["receipt_hash"]
        latest = receipts[-1]
        return {
            "job_id": job_id,
            "tenant_id": tenant_id,
            "assessment_id": assessment_id,
            "status": latest["status"],
            "details": latest.get("details") or {},
            "receipt_hash": latest["receipt_hash"],
            "partial_run_receipts": receipts,
            "terminal": latest["status"] in _TERMINAL,
        }


__all__ = ["AsyncModelRunStore"]
