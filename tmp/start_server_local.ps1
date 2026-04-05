Set-Location 'D:\AI\Threat_thy_sniffer'
$env:TEST_HELPERS_ENABLED = '1'
$env:PYTHONPATH = 'D:\AI\Threat_thy_sniffer'
$env:DEFAULT_FRONTEND = 'console'
$env:ENABLE_CSV_UPLOAD = 'true'
$env:DEBUG_DIAGNOSTICS = '1'
python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8080
