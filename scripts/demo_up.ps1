param(
  [switch]$Rebuild
)

$ErrorActionPreference = 'Stop'
Write-Host "Bringing up JanuSec demo stack (API + Prometheus + Grafana)..." -ForegroundColor Green

$composeArgs = @('up','-d')
if($Rebuild){ $composeArgs = @('up','-d','--build') }

docker compose @composeArgs

Write-Host "Waiting for API to be ready at http://localhost:8080 ..."
$max = 40
for($i=0;$i -lt $max;$i++){
  try{
    $r = Invoke-WebRequest -UseBasicParsing http://localhost:8080/api/v1/health -TimeoutSec 3
    if($r.StatusCode -eq 200){ break }
  }catch{ Start-Sleep -Seconds 1 }
}
if($i -ge $max){ Write-Error "API did not become ready. Check 'docker compose logs app'"; exit 1 }

Write-Host "API ready. Posting sample events..." -ForegroundColor Green
# Ensure demo/test-friendly env defaults for local runs
$env:TEST_HELPERS_ENABLED = '1'
$env:PYTHONPATH = Get-Location
$env:DEFAULT_FRONTEND = 'console'
$env:ENABLE_CSV_UPLOAD = 'true'

powershell -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot/ingest_sample.ps1"

Write-Host "Opening React UI and Grafana..." -ForegroundColor Green
Start-Process "http://localhost:8080/" | Out-Null
Start-Process "http://localhost:3000/" | Out-Null

Write-Host "Tip: Grafana login is admin/admin (password set to 'admin')." -ForegroundColor Yellow
Write-Host "Dashboards are pre-provisioned under 'General'."
