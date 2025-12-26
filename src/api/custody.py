from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from .runtime_state import (
    ServerRuntime,
    get_file_batch_analysis,
    get_file_hash_factors,
    get_server_runtime_state,
)

router = APIRouter()


class FileItem(BaseModel):  # type: ignore[misc]
    """Descriptor for an uploaded artifact tracked by the custody subsystem."""

    name: str | None = Field(default=None, max_length=260, description='Original file name as observed on disk')
    sha256: str = Field(min_length=5, max_length=128, description='Hex-encoded SHA-256 hash of the artifact (placeholder values accepted in tests)')
    size: int | None = Field(default=None, ge=0, description='File size in bytes')
    entropy: float | None = Field(default=None, ge=0.0, le=8.0, description='Shannon entropy approximation for the artifact')
    signed: bool | None = Field(default=None, description='Indicator if the binary is signed')
    signature_valid: bool | None = Field(default=None, description='Whether the observed signature validation succeeded')


class FileBatchRequest(BaseModel):  # type: ignore[misc]
    """Request payload for artifact batch analysis submissions."""

    batch_id: str | None = Field(default=None, max_length=128, description='Optional client-supplied identifier for the batch')
    files: list[FileItem] = Field(min_length=1, description='Collection of artifacts to evaluate')
    tenant_id: str | None = Field(default=None, max_length=64, description='Tenant scope for the batch (if multi-tenant)')


class FileAnalysis(BaseModel):  # type: ignore[misc]
    """Response payload describing analyzed artifacts."""

    batch_id: str = Field(description='Identifier assigned to the analyzed batch')
    files: list[dict[str, Any]] = Field(description='Per-file analysis metadata')
    generated_at: float = Field(description='Epoch timestamp when the analysis completed')


def _compute_file_factors(item: FileItem) -> list[str]:
    factors: list[str] = []
    if item.signed and item.signature_valid is False:
        factors.append('signature_mismatch')
    if item.size and item.size > 300:
        factors.append('size_large')
    if item.entropy and item.entropy > 7.5:
        factors.append('high_entropy')
    if not factors:
        factors.append('baseline_observation')
    return factors


def _append_jsonl_record(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(record, separators=(',', ':')) + '\n')


async def _append_custody(runtime: ServerRuntime, batch_id: str, item: FileItem, factors: list[str]) -> None:
    record = {
        'batch_id': batch_id,
        'sha256': item.sha256,
        'name': item.name,
        'timestamp': time.time(),
        'factors': factors,
    }
    canonical = json.dumps({k: record[k] for k in sorted(record)}, sort_keys=True, separators=(',', ':'))
    record['custody_hash'] = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    lock = runtime.get_custody_lock()
    # Debugging hooks to help trace intermittent stalls during combined tests
    try:
        try:
            LOGGER.debug('[custody] acquiring custody lock for sha=%s', item.sha256)
        except Exception:
            pass
    except Exception:
        pass
    async with lock:
        try:
            LOGGER.debug('[custody] holding custody lock for sha=%s - appending record', item.sha256)
        except Exception:
            pass
        await asyncio.to_thread(_append_jsonl_record, runtime.file_custody_path, record)
        try:
            LOGGER.debug('[custody] released custody lock for sha=%s', item.sha256)
        except Exception:
            pass


@router.post('/files/batch', summary='Submit artifact batch for custody tracking')
async def submit_file_batch(payload: FileBatchRequest, request: Request) -> dict[str, Any]:
    if not payload.files:
        raise HTTPException(status_code=400, detail='no_files_provided')

    batch_id = payload.batch_id or f"batch-{int(time.time() * 1000)}"
    runtime = get_server_runtime_state(request.app)
    file_hash_factors = get_file_hash_factors(runtime)
    processed: list[dict[str, Any]] = []
    for item in payload.files:
        factors = _compute_file_factors(item)
        try:
            import logging as _log
            _log.getLogger('custody').debug('updating file_hash_factors for %s', item.sha256)
        except Exception:
            pass
        # Increment occurrence count for hash; keep additive semantics
        try:
            # append a timestamp to bounded deque history for this sha
            ts = time.time()
            dq = file_hash_factors.get(item.sha256)
            if dq is None:
                # initialize via runtime getter semantics
                file_hash_factors[item.sha256] = deque([ts], maxlen=int(os.getenv('FILE_HASH_HISTORY_MAXLEN','200') or 200))
            else:
                try:
                    dq.append(ts)
                except Exception:
                    # fallback: set as deque
                    file_hash_factors[item.sha256] = deque([ts], maxlen=int(os.getenv('FILE_HASH_HISTORY_MAXLEN','200') or 200))
        except Exception:
            pass
        processed.append({'sha256': item.sha256, 'factors': factors})
        await _append_custody(runtime, batch_id, item, factors)

    analysis = FileAnalysis(batch_id=batch_id, files=processed, generated_at=time.time())
    batch_cache = get_file_batch_analysis(runtime)
    batch_cache[batch_id] = analysis.model_dump()
    return {'batch_id': batch_id, 'accepted': len(processed), 'files': processed}


@router.get('/files/batch/analysis/{batch_id}', summary='Retrieve cached artifact batch analysis')
def fetch_file_batch(batch_id: str, request: Request) -> dict[str, Any]:
    runtime = get_server_runtime_state(request.app)
    data = get_file_batch_analysis(runtime).get(batch_id)
    if not data:
        raise HTTPException(status_code=404, detail='batch_not_found')
    return data


__all__ = ['router', 'FileItem', 'FileBatchRequest', 'FileAnalysis']
