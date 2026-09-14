#!/usr/bin/env bash
# One-command GRC / Control-Assurance demo (Linux/macOS).
#   1. seeds the demo-vesper audit pack to disk (no Ollama, deterministic)
#   2. starts the API in LITE mode in the background
#   3. waits for health, then opens the two-surface landing
#
# Usage:  bash scripts/start_grc_demo.sh
# Stop:   kill "$(cat scripts/logs/grc_demo.pid)"
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$REPO_ROOT/scripts/logs"
PORT="${PORT:-8080}"
mkdir -p "$LOG_DIR"

# Lite mode: no Ollama, no heavy subsystem init — the demo pack is pre-built.
export PYTHONPATH="$REPO_ROOT"
export PLATFORM_LITE_INIT=1
export PORT
export API_KEYS_JSON='[{"key":"devkey123","scopes":["*"]}]'

echo "[1/3] Seeding demo-vesper audit pack..."
python "$REPO_ROOT/scripts/seed_grc_demo.py" --id demo-vesper

echo "[2/3] Starting API (lite) on port $PORT..."
LOG="$LOG_DIR/grc_demo.log"
python -u "$REPO_ROOT/scripts/run_uvicorn_wrapper.py" >"$LOG" 2>&1 &
SRV_PID=$!
echo "$SRV_PID" >"$LOG_DIR/grc_demo.pid"
echo "      pid=$SRV_PID  log=$LOG"

echo "[3/3] Waiting for health..."
LANDING="http://localhost:$PORT/static/assessment.html?aid=demo-vesper"
ok=""
for _ in $(seq 1 40); do
  if curl -sf -m 2 "http://localhost:$PORT/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
if [ -z "$ok" ]; then
  echo "Server did not become healthy. Tail: tail -f '$LOG'" >&2
  exit 1
fi

echo "Ready. Opening $LANDING"
( xdg-open "$LANDING" 2>/dev/null || open "$LANDING" 2>/dev/null || true ) &
echo
echo "Landing      : $LANDING"
echo "Audit report : http://localhost:$PORT/api/v1/assessments/demo-vesper/report.html"
echo "Control page : http://localhost:$PORT/api/v1/assessments/demo-vesper/audit-pack.html"
echo "Stop         : kill \$(cat '$LOG_DIR/grc_demo.pid')"
