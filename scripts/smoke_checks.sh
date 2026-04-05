#!/usr/bin/env bash
set -euo pipefail
HOST=${1:-http://localhost:8080}

echo "Running smoke checks against $HOST"

function check_url(){
  local url="$1"
  http_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" || true)
  if [ "$http_status" != "200" ]; then
    echo "FAIL: $url returned $http_status" >&2
    exit 2
  fi
  echo "OK: $url"
}

check_url "$HOST/health"
check_url "$HOST/api/v1/temporal/stats"

# Basic scoring endpoint
body='{"items":[{"id":"smoke-1","raw":{"message":"smoke"}}]}'
resp=$(curl -s -X POST -H "Content-Type: application/json" -d "$body" --max-time 10 "$HOST/api/v1/artifacts/analyze_batch" || true)
if [ -z "$resp" ]; then
  echo "FAIL: /api/v1/artifact/analyze_batch returned empty response" >&2
  exit 2
fi

echo "Smoke checks passed"
exit 0
