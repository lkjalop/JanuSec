Test and CI notes

SKIP_ISMS_SCAN (env var)
- Purpose: Avoid importing the full server which triggers heavy ISMS/DB scans during pytest collection.
- Usage: set SKIP_ISMS_SCAN=1 (or true/yes) in your environment when running unit tests that do not require the full server startup.

Examples:

# Quick unit tests (skip heavy server import)
$ SKIP_ISMS_SCAN=1 python -m pytest -q tests/test_tier1_summarizer_isolated.py

# Run the subset of tests used during local development (Windows PowerShell)
PS> $env:SKIP_ISMS_SCAN = '1'; python -m pytest -q tests/test_tier1_summarizer_isolated.py

# Full integration tests (no SKIP_ISMS_SCAN) - runs full server init
$ python -m pytest -q

Notes:
- PLATFORM_LITE_INIT=1 can also be used to enable lightweight test shims helpful for TestClient-based API tests.
- CI pipelines may wish to run both modes: quick unit tests with SKIP_ISMS_SCAN=1 and longer integration tests without it.
