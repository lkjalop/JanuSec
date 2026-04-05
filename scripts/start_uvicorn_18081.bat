@echo off
set RUN_PORT=18081
set TEST_HELPERS_ENABLED=0
"%~dp0\.venv\Scripts\python.exe" "%~dp0\run_uvicorn_port.py"
