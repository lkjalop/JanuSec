@echo off
echo ============================================================
echo Starting JanuSec Platform (Quick Start Mode)
echo ============================================================
echo.

REM Set working directory
cd /d "D:\AI\Threat_thy_sniffer"

REM Set environment variables
set PYTHONPATH=%CD%
set EVENT_QUEUE_MAX=2000
set API_KEYS_JSON=[{"key":"devkey123","scopes":["*"]}]
set ENABLE_CSV_UPLOAD=true
set FAST_LIVE_MODE=1

echo 🔧 Environment configured
echo 📁 Working directory: %CD%
echo.

REM Start the platform
echo 🚀 Starting JanuSec Platform...
echo.
echo Frontend will be available at: http://localhost:8080
echo API Documentation: http://localhost:8080/docs
echo Console: http://localhost:8080/console
echo.
echo Press Ctrl+C to stop
echo ============================================================
echo.

python start_simple.py

pause