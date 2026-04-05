param(
  [switch]$NoReload
)

# Set env and start server
if ($NoReload) { $env:UVICORN_RELOAD = '0' } else { $env:UVICORN_RELOAD = '1' }

# Demo & test-friendly default envs for local development
$env:PYTHONPATH = Get-Location
$env:DEFAULT_FRONTEND = 'console'
$env:TEST_HELPERS_ENABLED = '1'
$env:ENABLE_CSV_UPLOAD = 'true'

$p = Start-Process -FilePath python -ArgumentList '.\\start_simple.py' -PassThru -WindowStyle Hidden
"$($p.Id)" | Out-File -FilePath '.server.pid' -Encoding ascii
Start-Sleep -Seconds 2
Write-Output "Started server PID $($p.Id)"
