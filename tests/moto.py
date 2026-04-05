import pytest

# Lightweight stub used in environments where `moto` package or S3 support
# is not available. Tests decorated with `@mock_aws()` or `@mock_s3()` will
# be skipped instead of failing import-time.

def _make_skip_ctx(reason='moto.mock_s3 not available'):
    class _SkipCtx:
        def __call__(self, fn):
            return pytest.mark.skip(reason=reason)(fn)

        def __enter__(self):
            # When used as context manager, simply do nothing (skip not applied here)
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


# Backwards compatibility: some tests import `from moto import mock_aws, mock_s3`
# while others may call `moto.mock_s3()` directly. Provide both names.

__all__ = ['mock_aws', 'mock_s3', 'mock_sqs']
