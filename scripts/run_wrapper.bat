@echo off
rem Run the uvicorn wrapper and redirect stdout/stderr to the log
set ROOT=%~dp0..
set LOG=%ROOT%\scripts\logs\uvicorn_wrapper.log
rem ensure log dir exists
if not exist "%ROOT%\scripts\logs" mkdir "%ROOT%\scripts\logs"
python -u "%~dp0run_uvicorn_wrapper.py" > "%LOG%" 2>&1
exit /b %ERRORLEVEL%
