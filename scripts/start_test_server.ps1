# Start the FastAPI test server for Playwright or CI runs
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/start_test_server.ps1

$venv = ".venv\Scripts\Activate.ps1"
if (Test-Path $venv) {
    & $venv
}

# Ensure uvicorn available; prefer to run module from activated venv
$bindHost = "0.0.0.0"
$bindPort = 8080
Write-Host "Starting test server on http://$bindHost`:$bindPort"
# Test/demo-friendly env defaults
if (-not $env:TEST_HELPERS_ENABLED) { $env:TEST_HELPERS_ENABLED = '0' }
$env:PYTHONPATH = Get-Location
if (-not $env:DEFAULT_FRONTEND) { $env:DEFAULT_FRONTEND = 'console' }
$env:ENABLE_CSV_UPLOAD = 'true'
if (-not $env:FAST_TEST_MODE) { $env:FAST_TEST_MODE = '0' }
# Disable rate limiting during Playwright / test runs to prevent 429s
$env:TENANT_RATE_LIMIT_ENABLED = '0'
$env:RATE_LIMIT_ENABLED = '0'
# Ensure daily metrics collector cadence is set (24h)
$env:METRICS_DAILY_INTERVAL_SECONDS = '86400'
# Default tenant for local runs
$env:DEFAULT_TENANT = $env:DEFAULT_TENANT -or 'default'
# Enable debug diagnostics for richer tracebacks in logs
$env:DEBUG_DIAGNOSTICS = '1'
# Determine whether to enable autoreload. For diagnostics we prefer a stable server (no reload)
$reloadFlag = ''
if (-not $env:DEBUG_DIAGNOSTICS -or $env:DEBUG_DIAGNOSTICS -eq '0') {
    $reloadFlag = '--reload'
}

# Try to start uvicorn pointing to the ASGI app object if available, else use create_app factory
try {
    if ($reloadFlag -ne '') {
        python -m uvicorn src.api.app:app --host $bindHost --port $bindPort $reloadFlag
    } else {
        python -m uvicorn src.api.app:app --host $bindHost --port $bindPort
    }
} catch {
    Write-Host "Failed to start uvicorn with app object; trying create_app factory"
    if ($reloadFlag -ne '') {
        python -m uvicorn src.api.app:create_app --host $bindHost --port $bindPort $reloadFlag
    } else {
        python -m uvicorn src.api.app:create_app --host $bindHost --port $bindPort
    }
}
