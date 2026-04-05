#!/usr/bin/env bash
set -euo pipefail

echo "=== Testing Compliance Features ==="
API_KEY="${API_KEY:-devkey123}"
BASE_URL="${BASE_URL:-http://localhost:8000}"

echo "Test 1: List frameworks..."
curl -s -H "x-api-key: $API_KEY" "$BASE_URL/api/v1/compliance/frameworks" | jq . >/dev/null
echo "✅ Frameworks endpoint"

echo "Test 2: Get ISO27001 controls..."
CONTROL_COUNT=$(curl -s -H "x-api-key: $API_KEY" "$BASE_URL/api/v1/compliance/controls?framework=ISO27001" | jq '.controls | length')
echo "ISO27001 controls: $CONTROL_COUNT"

echo "Test 3: Upload evidence..."
TMPFILE=$(mktemp)
echo "Sample policy document" > "$TMPFILE"
curl -s -X POST \
  -H "x-api-key: $API_KEY" \
  -H "X-Tenant-ID: test-tenant" \
  -H "X-Actor: test-user@janusec.com" \
  -F "control_id=A.5.1" \
  -F "description=Information security policy" \
  -F "file=@$TMPFILE" \
  "$BASE_URL/api/v1/compliance/evidence/upload" | jq . >/dev/null
echo "✅ Evidence upload"

echo "Test 4: List evidence..."
curl -s -H "x-api-key: $API_KEY" -H "X-Tenant-ID: test-tenant" \
  "$BASE_URL/api/v1/compliance/evidence/list?control_id=A.5.1" | jq . >/dev/null
echo "✅ Evidence list"

echo "Test 5: Create remediation..."
curl -s -X POST \
  -H "x-api-key: $API_KEY" \
  -H "X-Tenant-ID: test-tenant" \
  -H "Content-Type: application/json" \
  -d '{
    "control_id": "A.9.2",
    "remediation_plan": "Implement MFA for all admin users",
    "assigned_to": "security-team@janusec.com",
    "due_date": "2025-12-01"
  }' \
  "$BASE_URL/api/v1/compliance/remediation/create" | jq . >/dev/null
echo "✅ Remediation create"

echo "Test 6: List remediations..."
curl -s -H "x-api-key: $API_KEY" -H "X-Tenant-ID: test-tenant" \
  "$BASE_URL/api/v1/compliance/remediation/list?status=open" | jq . >/dev/null
echo "✅ Remediation list"

echo "Test 7: Audit trail..."
curl -s -H "x-api-key: $API_KEY" -H "X-Tenant-ID: test-tenant" \
  "$BASE_URL/api/v1/compliance/audit/trail" | jq '.items | length' >/dev/null
echo "✅ Audit trail"

echo "Test 8: Assessment (single file)..."
curl -s -X POST \
  -H "x-api-key: $API_KEY" \
  -H "X-Tenant-ID: test-tenant" \
  -F "files=@$TMPFILE" \
  "$BASE_URL/api/v1/compliance/assess/files?framework=ISO27001" | jq . >/dev/null
echo "✅ Assessment"

rm -f "$TMPFILE"
echo "\n=== All Tests Completed ==="

