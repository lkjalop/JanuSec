@echo off
set TEST_HELPERS_ENABLED=1
set PLATFORM_LITE_INIT=1
set DISABLE_DB=0
set FAST_TEST_MODE=1
"%~dp0\.venv\Scripts\python.exe" -m pytest -q > "%~dp0test_full_run_db_enabled.log" 2>&1
