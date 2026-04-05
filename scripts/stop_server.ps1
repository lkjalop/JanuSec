# Gracefully stop the demo server started by start_simple.ps1 / start_server scripts
# Reads .server.pid in the repo root and attempts to stop the process by PID.
Param()
Set-StrictMode -Version Latest
if(-not (Test-Path -Path '.server.pid')){
    Write-Host ".server.pid not found in current directory. Try running from repository root." -ForegroundColor Yellow
    exit 1
}
$pidValue = Get-Content -Path '.server.pid' -ErrorAction SilentlyContinue | Select-Object -First 1
if(-not $pidValue){ Write-Host 'No PID found in .server.pid' -ForegroundColor Yellow; exit 1 }
try{
    $pidValue = [int]$pidValue
}catch{
    Write-Host 'PID in .server.pid is not a number:' $pidValue -ForegroundColor Red; exit 1
}
try{
    $proc = Get-Process -Id $pidValue -ErrorAction Stop
    Write-Host "Stopping process id $pidValue ($($proc.ProcessName))..."
    # Attempt to close main window politely first if present
    try{ if($proc.MainWindowHandle -ne 0){ $proc.CloseMainWindow() | Out-Null; Start-Sleep -Seconds 2 } }catch{}
    # Then stop process
    Stop-Process -Id $pidValue -Force -ErrorAction Stop
    Write-Host 'Process stopped.' -ForegroundColor Green
    Remove-Item -Path '.server.pid' -ErrorAction SilentlyContinue
    exit 0
}catch{
    Write-Host 'Failed to stop process or process not found. Removing .server.pid if present.' -ForegroundColor Yellow
    try{ Remove-Item -Path '.server.pid' -ErrorAction SilentlyContinue }catch{}
    exit 1
}
