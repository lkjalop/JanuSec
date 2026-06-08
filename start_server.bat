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
pip install -q fastapi uvicorn aiofiles pandas python-multipart httpx prometheus-client reportlab openpyxl pypdf pdfplumber duckdb 2>nul

REM Set environment variables
echo [2/4] Configuring environment...
set PYTHONPATH=%cd%
set EVENT_QUEUE_MAX=2000
set ACCESS_LOG_SAMPLE_RATE=0.5
REM Local dev API key — auto-generate per session; pre-set API_KEY to override.
if not defined API_KEY (
    for /f "usebackq delims=" %%A in (`python -c "import secrets; print('dev-' + secrets.token_urlsafe(16))"`) do set API_KEY=%%A
)
set API_KEYS_JSON=[{^"key^":^"%API_KEY%^",^"scopes^":[^"*^"]}]
echo INFO: Using local dev API key for this session: %API_KEY%
REM CB-2: Auto-generate secrets if not set — never use hard-coded dev defaults in production
if not defined AUDIT_CHAIN_SECRET (
    for /f "usebackq delims=" %%A in (`python -c "import secrets; print(secrets.token_urlsafe(32))"`) do set AUDIT_CHAIN_SECRET=%%A
    echo INFO: Generated AUDIT_CHAIN_SECRET for this session.
)
if not defined JWT_SECRET (
    for /f "usebackq delims=" %%A in (`python -c "import secrets; print(secrets.token_urlsafe(48))"`) do set JWT_SECRET=%%A
    echo INFO: Generated JWT_SECRET for this session.
)
if not defined ECLIPSE_XDR_SHARED_SECRET (
    for /f "usebackq delims=" %%A in (`python -c "import secrets; print(secrets.token_urlsafe(32))"`) do set ECLIPSE_XDR_SHARED_SECRET=%%A
    echo INFO: Generated ECLIPSE_XDR_SHARED_SECRET for this session.
)
REM CB-2: Warn if known dev placeholder detected in any critical variable
python -c "import os,sys; bad=[k for k,v in os.environ.items() if k in ('AUDIT_CHAIN_SECRET','JWT_SECRET') and v in ('dev_secret','secret','changeme','password','1234')]; [print('SECURITY WARNING: '+k+' is set to a known-weak value!') for k in bad]" 2>nul
set ENABLE_CSV_UPLOAD=true
set ENV=dev
set APP_ENV=dev
set JANUSEC_PROFILE=demo
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
REM Ollama models — narration vs interactive are different workloads
REM T1 narrator (batch, non-thinking): qwen2.5:14b — completes in ~15s/cluster
REM T2 narrator (best prose): qwen3.6:27b — pull first: ollama pull qwen3.6:27b
set OLLAMA_MODEL=qwen3.6:27b
REM Interactive/reasoning model: deepseek-r1:14b for analyst chat
REM Pull first: ollama pull deepseek-r1:14b
if not defined INTERACTIVE_MODEL set INTERACTIVE_MODEL=deepseek-r1:14b
REM Anthropic API (optional) — set ANTHROPIC_API_KEY to enable Claude narration
REM Activation: set ANTHROPIC_API_KEY=sk-ant-... && set LLM_PROVIDER=anthropic && set ANTHROPIC_MODEL=claude-sonnet-4-6
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
