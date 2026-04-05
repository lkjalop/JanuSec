@echo off
set TEST_HELPERS_ENABLED=1
set PLATFORM_LITE_INIT=1
set DISABLE_DB=1
set FAST_TEST_MODE=1
"%~dp0\.venv\Scripts\python.exe" -m pytest -q > "%~dp0test_full_run.log" 2>&1
