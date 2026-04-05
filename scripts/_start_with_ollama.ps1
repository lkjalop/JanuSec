param()

$env:OLLAMA_HOST = 'http://127.0.0.1:11434'
$env:LLM_PROVIDER = 'ollama'

Write-Output "Starting test server with OLLAMA_HOST=$env:OLLAMA_HOST and LLM_PROVIDER=$env:LLM_PROVIDER"
& powershell -NoProfile -ExecutionPolicy Bypass -File "scripts/start_test_server.ps1"
