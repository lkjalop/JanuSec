# Orchestrate integration tests: bring up docker-compose, wait for DB, run migrations, run pytest integration, then tear down
param(
  [string]$composeFile = 'docker-compose.test.yml',
  [string]$migrateScript = 'scripts/wait_and_migrate.ps1'
)
Write-Host "Starting integration test environment using $composeFile"
# Start compose
docker compose -f $composeFile up -d
if($LASTEXITCODE -ne 0){ Write-Error "docker compose up failed"; exit 2 }
# Wait and migrate
Write-Host "Waiting for DB and running migrations"
& powershell -ExecutionPolicy Bypass -File $migrateScript
if($LASTEXITCODE -ne 0){ Write-Error "migrations failed"; docker compose -f $composeFile down; exit 3 }
# Run pytest for integration tests
$env:APP_DB_DSN = 'postgresql://test:test@localhost:5433/testdb'
Write-Host "Running pytest integration tests..."
python -m pytest -q tests/integration -k sessions -q
$rc = $LASTEXITCODE
Write-Host "Tearing down docker-compose"
docker compose -f $composeFile down -v
exit $rc
