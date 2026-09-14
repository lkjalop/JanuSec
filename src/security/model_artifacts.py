"""Load only explicitly approved local Python model artifacts.

Pickle is executable. The manifest must be operator-owned, never uploaded with
an artifact. Hashes authenticate the exact approved bytes, not their safety.
"""
import hashlib
import hmac
import json
import os
import pickle
from pathlib import Path


def load_approved_model(path):
    approved = json.loads(os.getenv('JANUSEC_APPROVED_MODEL_SHA256', '{}'))
    canonical = os.path.normcase(os.path.realpath(path))
    expected = next((value for name, value in approved.items()
                     if os.path.normcase(os.path.realpath(name)) == canonical), None)
    if not isinstance(expected, str) or len(expected) != 64:
        raise RuntimeError('Model artifact requires an operator-approved SHA256')
    raw = Path(canonical).read_bytes()
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected.lower()):
        raise RuntimeError('Model artifact integrity check failed')
    # Deserialize the same verified bytes, preventing a check/read replacement race.
    return pickle.loads(raw)
