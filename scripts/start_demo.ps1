<#
Starts the demo server (wrapper) and seeds demo data. Writes logs to scripts/logs.
Usage: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start_demo.ps1
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$LogDir = Join-Path $RepoRoot 'scripts\logs'
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

Write-Host 'Starting demo server (wrapper)...'
$env:PYTHONPATH = "$RepoRoot"
$env:EVENT_QUEUE_MAX = '2000'
$env:API_KEYS_JSON = '[{"key":"devkey123","scopes":["*"]}]'
$env:ENABLE_CSV_UPLOAD = 'true'
$env:DEFAULT_FRONTEND = 'console'

$logFile = Join-Path $LogDir 'uvicorn_wrapper.log'
$pidFile = Join-Path $LogDir 'uvicorn_wrapper.pid'
Write-Host "Log file: $logFile"

# Start wrapper in background and redirect output to log file so failures are captured
$null = New-Item -ItemType File -Path $logFile -Force
$absLog = (Resolve-Path $logFile).ProviderPath
# Use cmd.exe to redirect both stdout and stderr to the same file (PowerShell Start-Process has limitations)
$scriptPath = (Join-Path $RepoRoot 'scripts\run_uvicorn_wrapper.py')
$cmd = "python -u '$scriptPath' > '$absLog' 2>&1"
 # Use a small batch wrapper that redirects stdout/stderr into the log reliably on Windows
 $bat = Join-Path $RepoRoot 'scripts\run_wrapper.bat'
 if(-not (Test-Path $bat)){ Write-Host 'Wrapper launcher not found:' $bat }
 $proc = Start-Process -FilePath $bat -PassThru
Start-Sleep -Milliseconds 500
if($proc -and $proc.Id){
  $proc.Id | Out-File -FilePath $pidFile -Encoding ASCII
  Write-Host "Started wrapper pid=$($proc.Id)"
} else {
  Write-Host 'Failed to start wrapper'
}

# Background job to wait for process exit and optionally stream logs
Start-Job -ScriptBlock {
  param($ProcId)
  try{
    while(Get-Process -Id $ProcId -ErrorAction SilentlyContinue){ Start-Sleep -Milliseconds 200 }
  }catch{}
} -ArgumentList $proc.Id | Out-Null

# Wait for health: poll root URL
$maxWait = 40
$ok = $false
$urls = @('http://localhost:8080/api/v1/health','http://localhost:8080/health','http://localhost:8080/')
for($i=0;$i -lt $maxWait -and -not $ok;$i++){
  foreach($u in $urls){
    try{
      $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 2
      if($r.StatusCode -eq 200){ $ok = $true; break }
    }catch{}
  }
  if(-not $ok){ Start-Sleep -Seconds 1 }
}
if(-not $ok){
  Write-Host 'Server did not become healthy in time. Check logs in scripts\logs.'
} else {
  Write-Host 'Server healthy. Running seeder...'
  & python (Join-Path $RepoRoot 'scripts\seed_demo.py')
}

Write-Host 'Start script finished. Tail logs with: Get-Content -Path scripts\logs\uvicorn_wrapper.log -Wait'
