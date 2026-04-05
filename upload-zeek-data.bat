@echo off
echo ============================================================
echo Uploading Sample Zeek Data to JanuSec Platform
echo ============================================================
echo.

REM Set working directory
cd /d "D:\AI\Threat_thy_sniffer"

echo 📊 Uploading sample Zeek events...
echo.

REM Wait for platform to be ready
echo ⏳ Waiting for platform to be ready...
timeout /t 5 /nobreak >nul

REM Upload the sample data
python "D:\AI\Threat_thy_sniffer\data\zeek\upload_to_janusec.py"

echo.
echo ✅ Upload complete!
echo.
echo 🌐 Check results at:
echo   - Frontend: http://localhost:8080/console
echo   - Recent events: http://localhost:8080/api/v1/events/sanitized?limit=10
echo   - Alerts: http://localhost:8080/api/v1/alerts/recent?limit=5
echo.

pause