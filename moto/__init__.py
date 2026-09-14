"""Local shim for moto decorators used in tests.

Prefer the real installed ``moto`` package when available. If not present,
expose skip-decorator/context-manager shims so tests that rely on moto can
be skipped at runtime rather than failing at import time.
"""
from __future__ import annotations

import importlib
import pytest
from typing import Any


def _make_skip_ctx(reason: str):
    class _SkipCtx:
        def __call__(self, fn: Any):
            return pytest.mark.skip(reason=reason)(fn)

        def __enter__(self):
            return None

        def __exit__(self, exc_type, exc, tb):
            return False

    return _SkipCtx()


# Prefer the real installed moto package when possible
_real = None
try:
    _real = importlib.import_module('moto')
except Exception:
    _real = None

if _real is not None:
    mock_s3 = getattr(_real, 'mock_s3', None)
    mock_sqs = getattr(_real, 'mock_sqs', None)
    mock_aws = getattr(_real, 'mock_aws', None)
    mock_kms = getattr(_real, 'mock_kms', None)
else:
    mock_s3 = None
    mock_sqs = None
    mock_aws = None
    mock_kms = None

if mock_s3 is None:
    def mock_s3(*args, **kwargs):
        return _make_skip_ctx('moto.mock_s3 not available')

if mock_sqs is None:
    def mock_sqs(*args, **kwargs):
        return _make_skip_ctx('moto.mock_sqs not available')

if mock_aws is None:
    def mock_aws(*args, **kwargs):
        return _make_skip_ctx('moto.mock_aws not available')

if mock_kms is None:
    def mock_kms(*args, **kwargs):
        return _make_skip_ctx('moto.mock_kms not available')

__all__ = ['mock_s3', 'mock_sqs', 'mock_aws', 'mock_kms']
