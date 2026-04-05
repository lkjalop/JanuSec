$env:TEST_HELPERS_ENABLED = '1'
$env:FAST_TEST_MODE = '1'
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
# Start the server with the repository root as working directory so local imports resolve
Start-Process -NoNewWindow -FilePath .\.venv\Scripts\python.exe -ArgumentList 'scripts/run_fast_test_server.py' -WorkingDirectory $root -PassThru
