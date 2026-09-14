# PowerShell helper to install a Windows service for the temporal worker
param(
    [string]$ServiceName = 'JanusecTemporalWorker',
    [string]$PythonExe = "$PSScriptRoot\..\.venv-1\Scripts\python.exe",
    [string]$WorkDir = "$PSScriptRoot\.."
)

$exe = $PythonExe
$args = "-m src.workers.temporal_worker"

Write-Output "Registering service $ServiceName"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Output "Service already exists. Stopping and removing old service"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
}

$svcCmd = "sc.exe create $ServiceName binPath= \"$exe $args\" start= auto"
Write-Output $svcCmd
Invoke-Expression $svcCmd
Start-Sleep -Seconds 1
Start-Service -Name $ServiceName
Write-Output "Service installed and started. Configure environment vars in the service registry or wrapper script."
