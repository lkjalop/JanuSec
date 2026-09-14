<#
One-command GRC / Control-Assurance demo (Windows).

  1. seeds the demo-vesper audit pack to disk (no Ollama, deterministic)
  2. starts the API in LITE mode (skips heavy init) in the background
  3. waits for health, then opens the two-surface landing in the browser

Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start_grc_demo.ps1
Stop:   Get-Content scripts\logs\grc_demo.pid | ForEach-Object { Stop-Process -Id $_ }

This is the GRC-pivot demo. The legacy scripts\start_demo.ps1 seeds the OLD graph
surface and is kept only for back-compat.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$LogDir   = Join-Path $RepoRoot 'scripts\logs'
$Port     = if ($env:PORT) { $env:PORT } else { '8080' }
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

# Lite mode: no Ollama, no heavy subsystem init — the demo pack is pre-built.
$env:PYTHONPATH        = $RepoRoot
$env:PLATFORM_LITE_INIT = '1'
$env:PORT               = $Port
$env:API_KEYS_JSON      = '[{"key":"devkey123","scopes":["*"]}]'

Write-Host '[1/3] Seeding demo-vesper audit pack...'
& python (Join-Path $RepoRoot 'scripts\seed_grc_demo.py') --id demo-vesper
if ($LASTEXITCODE -ne 0) { Write-Host 'Seed failed — aborting.' -ForegroundColor Red; exit 1 }

Write-Host "[2/3] Starting API (lite) on port $Port..."
$log = Join-Path $LogDir 'grc_demo.log'
$pidFile = Join-Path $LogDir 'grc_demo.pid'
$wrapper = Join-Path $RepoRoot 'scripts\run_uvicorn_wrapper.py'
$proc = Start-Process -FilePath 'python' -ArgumentList @('-u', $wrapper) `
          -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru
$proc.Id | Out-File -FilePath $pidFile -Encoding ASCII
Write-Host "      pid=$($proc.Id)  log=$log"

Write-Host '[3/3] Waiting for health...'
$landing = "http://localhost:$Port/static/assessment.html?aid=demo-vesper"
$ok = $false
for ($i = 0; $i -lt 40 -and -not $ok; $i++) {
  try {
    $r = Invoke-WebRequest -Uri "http://localhost:$Port/health" -UseBasicParsing -TimeoutSec 2
    if ($r.StatusCode -eq 200) { $ok = $true; break }
  } catch { Start-Sleep -Seconds 1 }
}
if (-not $ok) {
  Write-Host "Server did not become healthy. Tail: Get-Content '$log' -Wait" -ForegroundColor Red
  exit 1
}

Write-Host "Ready. Opening $landing" -ForegroundColor Green
Start-Process $landing
Write-Host ''
Write-Host 'Landing        : ' $landing
Write-Host 'Audit report   :' "http://localhost:$Port/api/v1/assessments/demo-vesper/report.html"
Write-Host 'Control page   :' "http://localhost:$Port/api/v1/assessments/demo-vesper/audit-pack.html"
Write-Host "Stop           : Get-Content '$pidFile' | ForEach-Object { Stop-Process -Id `$_ }"
