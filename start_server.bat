@echo off
echo ========================================
echo Starting JanuSec Platform
echo ========================================
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Install requirements if needed
echo [1/4] Checking dependencies...
REM Core API + uploads + webhooks + metrics + PDF reports + Excel/PDF parsing
pip install -q fastapi uvicorn aiofiles pandas python-multipart httpx prometheus-client reportlab openpyxl pypdf pdfplumber 2>nul

REM Set environment variables
echo [2/4] Configuring environment...
set PYTHONPATH=%cd%
set EVENT_QUEUE_MAX=2000
set ACCESS_LOG_SAMPLE_RATE=0.5
REM Generate a unique API key if not provided
if not defined API_KEYS_JSON (
    for /f "usebackq delims=" %%A in (`python -c "import secrets; print(secrets.token_urlsafe(32))"`) do set API_KEY=%%A
    set API_KEYS_JSON=[{"key":"%API_KEY%","scopes":["*"]}]
    echo INFO: Generated API key for this session: %API_KEY%
)
set ENABLE_CSV_UPLOAD=true
set ECLIPSE_XDR_SHARED_SECRET=dev_secret
set ENV=dev
set APP_ENV=dev
set DEFAULT_FRONTEND=console
set STRICT_API_KEY_ENFORCEMENT=1
set DISABLE_CSP=0
set ALLOWED_ORIGINS=http://localhost:8080,http://127.0.0.1:8080
REM Local development defaults
set LLM_SUMMARIES_ENABLED=1
set TEST_HELPERS_ENABLED=0
set PLATFORM_LITE_INIT=0
set LLM_ALLOW_LOCAL_DETERMINISTIC=1
set LLM_STRICT_PROVIDER=0
set ADAPTIVE_EWMA=1
set ADAPTIVE_EWMA_BASE_ALPHA=0.6
set ADAPTIVE_EWMA_MIN_ALPHA=0.3
set ADAPTIVE_EWMA_MAX_ALPHA=0.85
set PLAYBOOK_TENANT_ALLOW=
REM Enable HopGraph persistence + TTL prune loop for demo reliability
set HOPGRAPH_PERSISTENCE_ENABLED=1
set HOPGRAPH_DB_PATH=%cd%\data\hopgraph.db
set HOPGRAPH_EDGE_TTL_SECONDS=604800
set HOPGRAPH_PRUNE_INTERVAL_SECONDS=60

REM Check if database is needed
echo [3/4] Checking database...
REM For now, run without DB for CSV processing

echo [4/4] Starting server...
echo.
echo ========================================
echo Server will start at: http://localhost:8080
echo Frontend UI (LIVE) at: http://localhost:8080/
echo Direct LIVE route: http://localhost:8080/live
echo API Docs at: http://localhost:8080/docs
echo ========================================
echo Optional helper scripts once the server is listening:
echo   python scripts\prewarm_ollama.py --model llama3:8b
echo   python scripts\verify_loop_closure.py --server http://localhost:8080
echo.
echo Press Ctrl+C to stop the server
echo.

REM Start the simple server (non-interactive for CI/tasks)
python start_simple.py

REM Removed interactive pause to avoid blocking non-interactive shells/tasks
