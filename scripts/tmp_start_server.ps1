$cwd = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $cwd
$env:API_KEYS_JSON='[{"key":"devkey123","scopes":["*"]}]'
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','cd /d "' + $PWD.Path + '" && start_server.bat > start_server.log 2>&1' -WindowStyle Hidden -WorkingDirectory $PWD.Path
Write-Host "Started server (check start_server.log)"