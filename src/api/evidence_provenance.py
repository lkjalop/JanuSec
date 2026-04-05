"""Evidence provenance helpers: compute hashes, sign metadata, persist provenance records."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

from src.api.persist_utils import atomic_write_json


def _compute_sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as fh:
            while True:
                chunk = fh.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def sign_evidence_metadata(evidence_path: str, collected_by: str, collection_method: str, authorization_ticket: Optional[str] = None) -> Dict[str, Any]:
    """Create provenance metadata for an evidence file.

    Writes a .meta.json file next to `evidence_path` containing:
      - sha256
      - hmac (if EVIDENCE_HMAC_SECRET provided)
      - collected_by, method, authorization_ticket, timestamp
      - storage_pointer: file path (local) or URL
    """
    metadata: Dict[str, Any] = {}
    metadata['evidence_path'] = evidence_path
    metadata['collected_by'] = collected_by
    metadata['collection_method'] = collection_method
    metadata['authorization_ticket'] = authorization_ticket
    metadata['collected_ts'] = int(time.time())

    sha = _compute_sha256(evidence_path)
    metadata['sha256'] = sha

    # Optional HMAC signature
    secret = os.getenv('EVIDENCE_HMAC_SECRET')
    if secret and sha:
        try:
            hm = hmac.new(secret.encode('utf-8'), sha.encode('utf-8'), hashlib.sha256).hexdigest()
            metadata['hmac_sha256'] = hm
        except Exception:
            metadata['hmac_sha256'] = None
    else:
        metadata['hmac_sha256'] = None

    # Storage pointer - default local path
    storage_backend = os.getenv('EVIDENCE_STORAGE', 'local')
    if storage_backend == 'local':
        metadata['storage'] = {'backend': 'local', 'path': os.path.abspath(evidence_path)}
    else:
        # Future: S3/GCS pointer creation
        metadata['storage'] = {'backend': storage_backend, 'path': os.path.abspath(evidence_path)}

    # Persist metadata atomically beside evidence
    try:
        meta_path = evidence_path + '.meta.json'
        atomic_write_json(meta_path, metadata)
    except Exception:
        pass

    return metadata


__all__ = ['sign_evidence_metadata']
