@echo off
set TEST_HELPERS_ENABLED=1
set PLATFORM_LITE_INIT=1
set DISABLE_DB=0
set FAST_TEST_MODE=1
"%~dp0\.venv\Scripts\python.exe" -m pytest -q tests/test_ab_full_lifecycle.py::test_ab_full_lifecycle -q -s
