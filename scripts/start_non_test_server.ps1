# Start FastAPI server without test helpers and with Ollama LLM configured
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/start_non_test_server.ps1

$venv = ".venv\Scripts\Activate.ps1"
if (Test-Path $venv) {
    & $venv
}

# Non-test env
$env:TEST_HELPERS_ENABLED = '0'
$env:FAST_TEST_MODE = '0'
$env:DEFAULT_FRONTEND = $env:DEFAULT_FRONTEND -or 'console'
$env:PYTHONPATH = Get-Location

# LLM provider: Ollama
$env:LLM_PROVIDER = $env:LLM_PROVIDER -or 'ollama'
$env:OLLAMA_HOST = $env:OLLAMA_HOST -or 'http://127.0.0.1:11434'
$env:OLLAMA_MODEL = $env:OLLAMA_MODEL -or 'llama3:8b'

# Bind
$bindHost = "127.0.0.1"
$bindPort = 8090
Write-Host "Starting non-test server on http://$bindHost`:$bindPort (LLM=$env:LLM_PROVIDER $env:OLLAMA_MODEL)"

# Start uvicorn
python -m uvicorn src.api.app:app --host $bindHost --port $bindPort