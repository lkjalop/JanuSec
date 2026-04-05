param(
  [string]$dsn = "postgresql://test:test@localhost:5433/testdb"
)
Write-Host "Waiting for Postgres at $dsn..."
$max = 60
for($i=0;$i -lt $max;$i++){
  try{
    $env:APP_DB_DSN = $dsn
    python - <<'PY'
import os,sys
import time
import psycopg2
from urllib.parse import urlparse
u = urlparse(os.environ.get('APP_DB_DSN'))
for _ in range(30):
    try:
        conn = psycopg2.connect(dbname=u.path.lstrip('/'), user=u.username, password=u.password, host=u.hostname, port=u.port)
        conn.close()
        print('db ready')
        break
    except Exception:
        time.sleep(1)
else:
    print('db not ready', file=sys.stderr); sys.exit(2)
PY
    break
  } catch {
    Start-Sleep -Seconds 1
  }
}
Write-Host "Running migrations via scripts/run_migrations.py"
# attempt a pre-migration backup if possible
try{
  Write-Host "Attempting pre-migration backup (best-effort)"
  if(Test-Path scripts/pre_migration_backup_enhanced.ps1){
    & powershell -ExecutionPolicy Bypass -File scripts/pre_migration_backup_enhanced.ps1 -dsn $dsn -s3uri $env:BACKUP_S3_URI -keep 5
  } else {
    & powershell -ExecutionPolicy Bypass -File scripts/pre_migration_backup.ps1 -dsn $dsn
  }
} catch {
  Write-Warning "Pre-migration backup failed or skipped"
}
python scripts/run_migrations.py
