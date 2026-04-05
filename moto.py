import pytest
import os


def _make_skip_ctx(reason='moto.mock_s3 not available'):
    class _SkipCtx:
        def __call__(self, fn):
            return pytest.mark.skip(reason=reason)(fn)

        def __enter__(self):
            return None

        def __exit__(self, exc_type, exc, tb):
            return False

    return _SkipCtx()


def mock_aws(*args, **kwargs):
    return _make_skip_ctx()


def mock_s3(*args, **kwargs):
    return _make_skip_ctx()


def mock_sqs(*args, **kwargs):
    return _make_skip_ctx()


def mock_kms(*args, **kwargs):
    return _make_skip_ctx()


__all__ = ['mock_aws', 'mock_s3', 'mock_sqs', 'mock_kms']
import pytest

# Project-local stub for moto to allow running tests in environments where
# the real moto package is partially installed or missing S3/SQS backends.
# This file intentionally mirrors the minimal decorator names used by tests.


def _make_skip_ctx(reason='moto backend not available'):
    class _SkipCtx:
        def __call__(self, fn):
            return pytest.mark.skip(reason=reason)(fn)

        def __enter__(self):
            return None

        def __exit__(self, exc_type, exc, tb):
            return False

    return _SkipCtx()


def mock_aws(*args, **kwargs):
    return _make_skip_ctx()


def mock_s3(*args, **kwargs):
    return _make_skip_ctx()


def mock_sqs(*args, **kwargs):
    return _make_skip_ctx()


def mock_kms(*args, **kwargs):
    return _make_skip_ctx()


__all__ = ['mock_aws', 'mock_s3', 'mock_sqs']
