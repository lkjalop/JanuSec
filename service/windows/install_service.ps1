param(
    [string]$ServiceName = 'JanusecRunner',
    [string]$PythonPath = "$PSScriptRoot\..\..\.venv-1\Scripts\python.exe"
)

Write-Host "Registering service $ServiceName"

# Use sc.exe to create service (simpler) - update paths as needed
$exe = $PythonPath
$args = '-m service.janusec_runner'
sc.exe create $ServiceName binPath= "`"$exe $args`"" start= auto
Write-Host "Service created. Start it with: Start-Service $ServiceName"
