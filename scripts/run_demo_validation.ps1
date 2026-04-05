param(
  [string]$Api = "http://localhost:8080",
  [int]$Scenarios = 4,
  [int]$Events = 12,
  [switch]$StartServer
)

# Optional: start server
$serverPid = $null
if($StartServer){
  Write-Host "Starting server..."
  $env:PYTHONPATH = (Resolve-Path ".\src").Path
  $p = Start-Process -FilePath python -ArgumentList "start_simple.py" -PassThru
  $serverPid = $p.Id
  Start-Sleep -Seconds 3
}

try{
  Write-Host "Running demo validation against $Api"
  python scripts/validate_demo.py --api $Api --scenarios $Scenarios --events $Events
  if($LASTEXITCODE -ne 0){
    Write-Error "Demo validation failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
  }
  Write-Host "Demo validation passed"
} finally {
  if($serverPid){
    Write-Host "Stopping server PID=$serverPid"
    try{ Stop-Process -Id $serverPid -Force } catch { }
  }
}
