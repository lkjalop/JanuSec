#!/usr/bin/env bash
set -euo pipefail

# Bring up local Postgres and run migrations
COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.dev.yml}

echo "Starting Postgres via docker-compose (${COMPOSE_FILE})"
docker compose -f "$COMPOSE_FILE" up -d

echo "Waiting for Postgres to be healthy..."
# Simple wait loop
for i in {1..30}; do
  if docker compose -f "$COMPOSE_FILE" ps --services --filter "status=running" | grep -q postgres; then
    echo "Postgres container running"
    break
  fi
  sleep 1
done

echo "Running migrations (dry-run first)"
python scripts/run_migrations.py --dry-run

echo "Applying migrations"
python scripts/run_migrations.py

echo "Done."
