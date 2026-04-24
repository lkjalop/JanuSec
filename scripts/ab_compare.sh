#!/usr/bin/env bash
# ab_compare.sh — Sequential A/B quality vs latency comparison for qwen3:14b vs qwen3:30b
#
# SAFETY: Runs models sequentially with a 60-second cooling pause between calls.
# Monitor GPU temp before starting: nvidia-smi -q -d TEMPERATURE
# Do NOT run this while Playwright tests or other LLM inference is in progress.
#
# Usage:
#   ASSESSMENT_ID=a_XXXX CLUSTER_ID=cluster_001 bash scripts/ab_compare.sh
#   Or: bash scripts/ab_compare.sh a_XXXX cluster_001
#
# Output: prints a side-by-side quality/latency report.

set -euo pipefail

BASE="${PLAYWRIGHT_BASE_URL:-http://127.0.0.1:8000}"
AID="${1:-${ASSESSMENT_ID:-}}"
CID="${2:-${CLUSTER_ID:-}}"
COOL_SECS=60

if [[ -z "$AID" || -z "$CID" ]]; then
  echo "Usage: $0 <assessment_id> <cluster_id>"
  echo "       or set ASSESSMENT_ID and CLUSTER_ID env vars"
  exit 1
fi

check_gpu_temp() {
  local temp
  temp=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits 2>/dev/null || echo "N/A")
  echo "$temp"
}

run_tier1() {
  local model="$1"
  local t_start t_end latency
  t_start=$(date +%s%3N)
  local resp
  resp=$(curl -sf -X POST \
    -H "Content-Type: application/json" \
    -H "x-tenant-id: default" \
    -d "{\"model\":\"${model}\",\"force\":true}" \
    "${BASE}/api/v1/assessments/${AID}/clusters/${CID}/tier1-summary" 2>&1) || {
    echo "  ERROR: curl failed for $model"
    return 1
  }
  t_end=$(date +%s%3N)
  latency=$((t_end - t_start))

  local incident headline actions mitre verdict words
  incident=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); p=d.get('tier1_prefill',{}); print(p.get('incident_name',''))" 2>/dev/null || echo "parse_error")
  headline=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); p=d.get('tier1_prefill',{}); print(p.get('headline_subtitle','')[:100])" 2>/dev/null || echo "")
  actions=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); p=d.get('tier1_prefill',{}); print(len(p.get('top_actions',[])))" 2>/dev/null || echo "0")
  mitre=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); p=d.get('tier1_prefill',{}); ts=p.get('mitre_techniques',[]); print(len(ts))" 2>/dev/null || echo "0")
  verdict=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); p=d.get('tier1_prefill',{}); print('yes' if p.get('verdict_reasoning') else 'no')" 2>/dev/null || echo "no")
  words=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); p=d.get('tier1_prefill',{}); narr=p.get('short_narrative',''); print(len(narr.split()))" 2>/dev/null || echo "0")

  echo "  incident_name:     $incident"
  echo "  headline (100c):   $headline"
  echo "  top_actions count: $actions"
  echo "  MITRE count:       $mitre"
  echo "  narrative words:   $words"
  echo "  verdict_reasoning: $verdict"
  echo "  latency:           ${latency}ms"

  # Store for comparison
  eval "${model//[:.]/_}_latency=$latency"
  eval "${model//[:.]/_}_mitre=$mitre"
  eval "${model//[:.]/_}_words=$words"
  eval "${model//[:.]/_}_actions=$actions"
}

echo "═══════════════════════════════════════════════════════════"
echo "  JanuSec A/B: qwen3:14b vs qwen3:30b"
echo "  Assessment: $AID | Cluster: $CID"
echo "═══════════════════════════════════════════════════════════"

gpu_temp=$(check_gpu_temp)
echo "  GPU temp before start: ${gpu_temp}°C"
if [[ "$gpu_temp" != "N/A" ]] && [[ "$gpu_temp" -gt 85 ]]; then
  echo "  ⚠ GPU temp > 85°C — waiting 120s for cooling before proceeding"
  sleep 120
fi

echo ""
echo "── qwen3:14b ───────────────────────────────────────────────"
run_tier1 "qwen3:14b"

echo ""
echo "── Cooling pause: ${COOL_SECS}s (GPU recovery) ────────────"
gpu_temp=$(check_gpu_temp)
echo "  GPU temp: ${gpu_temp}°C"
sleep "$COOL_SECS"
gpu_temp=$(check_gpu_temp)
echo "  GPU temp after pause: ${gpu_temp}°C"

echo ""
echo "── qwen3:30b ───────────────────────────────────────────────"
run_tier1 "qwen3:30b"

echo ""
echo "── COMPARISON SUMMARY ──────────────────────────────────────"
printf "  %-22s %-14s %-14s\n" "Metric" "qwen3:14b" "qwen3:30b"
printf "  %-22s %-14s %-14s\n" "Latency (ms)"    "${qwen3_14b_latency:-?}" "${qwen3_30b_latency:-?}"
printf "  %-22s %-14s %-14s\n" "Narrative words"  "${qwen3_14b_words:-?}"   "${qwen3_30b_words:-?}"
printf "  %-22s %-14s %-14s\n" "MITRE count"      "${qwen3_14b_mitre:-?}"   "${qwen3_30b_mitre:-?}"
printf "  %-22s %-14s %-14s\n" "Actions count"    "${qwen3_14b_actions:-?}" "${qwen3_30b_actions:-?}"
echo "═══════════════════════════════════════════════════════════"
gpu_temp=$(check_gpu_temp)
echo "  GPU temp at end: ${gpu_temp}°C"
