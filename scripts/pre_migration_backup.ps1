param(
  [string]$dsn = "postgresql://test:test@localhost:5433/testdb",
  [string]$outdir = "backups"
)
# Simple pre-migration backup script using pg_dump. Best-effort: if pg_dump not found, skip with a warning.
Write-Host "Preparing pre-migration backup for $dsn"
# create output dir
if(-not (Test-Path $outdir)) { New-Item -ItemType Directory -Path $outdir | Out-Null }
# parse DSN
try{
    $uri = [uri]$dsn
    $user = $uri.UserInfo.Split(':')[0]
    $pass = $uri.UserInfo.Split(':')[1]
    $host = $uri.Host
    $port = $uri.Port
    $db = $uri.AbsolutePath.TrimStart('/')
} catch{
    Write-Warning "Failed to parse DSN; skipping backup"
    exit 0
}
$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$outfile = Join-Path $outdir "migration_backup_$db`_$ts.sql"
# If pg_dump is not on PATH, warn and skip
$pgdump = Get-Command pg_dump -ErrorAction SilentlyContinue
if(-not $pgdump){
    Write-Warning "pg_dump not found in PATH. Skipping backup. To enable backups, install PostgreSQL client tools and ensure pg_dump is on PATH."
    exit 0
}
# Build pg_dump command
$env:PGPASSWORD = $pass
$cmd = "pg_dump -h $host -p $port -U $user -F p -f `"$outfile`" $db"
Write-Host "Running: $cmd"
Invoke-Expression $cmd
if($LASTEXITCODE -ne 0){
    Write-Warning "pg_dump exited with code $LASTEXITCODE. Backup may have failed."
    exit 1
}
Write-Host "Backup written to $outfile"
exit 0
