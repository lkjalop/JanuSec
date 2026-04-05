"""Lightweight shim for the `vcr` package used by some integration tests.

This shim provides a minimal `VCR` class with a `use_cassette` context
manager that is a no-op. It's intentionally tiny and only intended for
test runs where `TEST_HELPERS_ENABLED=1` or where the real `vcr` package
is not available.

If you have `vcrpy` installed in your environment, the real package will
be used instead of this shim. This file prevents test collection errors
when optional test deps are missing.
"""
import os
import contextlib
from typing import Iterator


class VCR:
    def __init__(self, *args, **kwargs):
        self._args = args
        self._kwargs = kwargs

    @contextlib.contextmanager
    def use_cassette(self, name: str) -> Iterator[None]:
        # No-op context manager for tests: records nothing and allows
        # code that expects a cassette to run without network interception.
        yield


def VCR_deprecated(*args, **kwargs):
    return VCR(*args, **kwargs)


# Backwards-compatible alias (some code may do `vcr.VCR(...)`)
VCR = VCR
