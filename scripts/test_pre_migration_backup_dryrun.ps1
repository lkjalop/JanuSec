# Simple dry-run test for pre_migration_backup_enhanced.ps1
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script = Join-Path $here 'pre_migration_backup_enhanced.ps1'
$temp = Join-Path $here 'tmp_backups'
if(-not (Test-Path $temp)){ New-Item -ItemType Directory -Path $temp | Out-Null }
# call script in DryRun mode; set DSN to local fake DB
& powershell -NoProfile -ExecutionPolicy Bypass -File $script -dsn 'postgresql://user:pass@localhost:5432/fakedb' -outdir $temp -DryRun -Sign -KeepLogs 5
Write-Host "Dry-run completed. Log contents:" 
Get-Content (Join-Path $temp 'migration_backup.log') | Select-Object -Last 50 | ForEach-Object { Write-Host $_ }
