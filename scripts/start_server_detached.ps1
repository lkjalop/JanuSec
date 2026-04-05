# Start the FastAPI demo server in a detached PowerShell process
param(
  [string]$BindHost = '127.0.0.1',
  [int]$Port = 8080
)

$python = "python"
$script = Join-Path $PSScriptRoot '..\start_simple.py'
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $python
$psi.Arguments = "`"$script`" --no-reload --host $BindHost --port $Port --log-level info"
$psi.WorkingDirectory = (Convert-Path "..")
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

$proc = [System.Diagnostics.Process]::Start($psi)
Start-Sleep -Seconds 1
Write-Output "Started process id $($proc.Id)"
Write-Output "To stop: Stop-Process -Id $($proc.Id)"