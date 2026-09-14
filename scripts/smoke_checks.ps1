param(
  [string]$ServiceUrl = 'http://localhost:8080'
)

$ErrorActionPreference = 'Stop'
Write-Host "Running smoke checks against $ServiceUrl" -ForegroundColor Cyan

function Test-SmokeUrl {
  param([string]$Url)
  try{
    $r = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 5
    if($r.StatusCode -ne 200){ Write-Error "$(Get-Date -Format o) FAIL: $Url returned $($r.StatusCode)"; exit 2 }
    Write-Host "OK: $Url" -ForegroundColor Green
  }catch{
    Write-Error "$(Get-Date -Format o) ERROR: $Url -> $($_.Exception.Message)"; exit 2
  }
}

Test-SmokeUrl "$ServiceUrl/health"
Test-SmokeUrl "$ServiceUrl/api/v1/temporal/stats"

# Basic scoring endpoint: POST small artifact batch
try{
  $body = @{ items = @(@{ id = 'smoke-1'; raw = @{ message = 'smoke' } }) } | ConvertTo-Json
  $r = Invoke-RestMethod -Uri "$ServiceUrl/api/v1/artifacts/analyze_batch" -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10
  Write-Host "OK: /api/v1/artifacts/analyze_batch -> response keys: $($r.PSObject.Properties.Name -join ', ')" -ForegroundColor Green
}catch{
  Write-Error "FAIL: artifact/analyze_batch -> $($_.Exception.Message)"; exit 2
}

Write-Host "Smoke checks passed" -ForegroundColor Green
exit 0
