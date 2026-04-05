# JanuSec Platform: Fix Priority List
## Immediate Action Required to Unblock Production

**Last Updated:** 2026-01-16
**Current Branch:** `feat/webhook-guard-middleware-only-verification`
**Status:** 🔴 **BLOCKED - 14 Syntax Errors Prevent All Testing**

---

## Priority Legend

- **P0 - CRITICAL**: Blocks all tests, must fix IMMEDIATELY (TODAY)
- **P1 - HIGH**: Broken features, fix in next 24-48 hours
- **P2 - MEDIUM**: Code quality issues, fix before production (week 1)
- **P3 - LOW**: Technical debt, fix before enterprise release (weeks 2-4)

---

## P0 - CRITICAL SYNTAX ERRORS (Fix in Next 2-3 Hours)

### These 14 files prevent pytest from even collecting tests. Fix ALL of these before doing anything else.

### 1. `src/api/background_tasks.py` - Line 120
**Error:** `except` without matching `try`
```python
# BROKEN (around line 120):
    except Exception as e:
        logger.error(f"Failed: {e}")

# FIX: Add the missing try block above, or remove orphaned except
# Look at lines 115-125 to find context
```
**How to Fix:**
1. Open `src/api/background_tasks.py`
2. Go to line 120
3. Scroll up to find where `try:` should be
4. Either add `try:` or remove the orphaned `except` block
**Estimated Time:** 5 minutes

---

### 2. `src/api/executive_report_endpoints.py` - Line 175
**Error:** IndentationError
```python
# BROKEN (around line 175):
    return response
  wrong_indent_here()

# FIX: Proper indentation (should be 4 spaces or match surrounding)
```
**How to Fix:**
1. Open `src/api/executive_report_endpoints.py`
2. Go to line 175
3. Fix indentation to match surrounding code
4. Run: `python -m py_compile src/api/executive_report_endpoints.py`
**Estimated Time:** 2 minutes

---

### 3. `src/api/online_trainer_admin.py` - Line 101
**Error:** `from __future__ import annotations` not at start of file
```python
# BROKEN (line 101 is NOT the first line):
import os
import sys
from __future__ import annotations  # ❌ MUST be first!

# FIX: Move to line 1
from __future__ import annotations
import os
import sys
```
**How to Fix:**
1. Open `src/api/online_trainer_admin.py`
2. Find `from __future__ import annotations` (around line 101)
3. Cut that line (Ctrl+X)
4. Go to line 1 (before ALL other imports)
5. Paste it as the very first line
6. Save
**Estimated Time:** 1 minute

---

### 4. `src/api/playbook_tenants.py` - Line 31
**Error:** `from __future__ import annotations` not at start of file
```python
# Same issue as #3 above
```
**How to Fix:**
1. Same fix as #3 - move `from __future__ import annotations` to line 1
**Estimated Time:** 1 minute

---

### 5. `src/api/routes/events.py` - Line 122
**Error:** Expected indented block after `try`
```python
# BROKEN (around line 122):
try:
# Missing indented code here!
except Exception as e:
    pass

# FIX: Add at least a pass statement or actual code
try:
    # TODO: Add implementation
    pass
except Exception as e:
    pass
```
**How to Fix:**
1. Open `src/api/routes/events.py`
2. Go to line 122
3. Find the `try:` with nothing indented after it
4. Add `pass` or the intended implementation
**Estimated Time:** 5 minutes

---

### 6. `src/api/routes/identity.py` - Line 221
**Error:** `except`/`finally` missing after `try`
```python
# BROKEN (around line 221):
try:
    do_something()
# Missing except or finally!

# FIX: Add exception handler
try:
    do_something()
except Exception as e:
    logger.error(f"Error: {e}")
```
**How to Fix:**
1. Open `src/api/routes/identity.py`
2. Go to line 221
3. Find the incomplete `try` block
4. Add `except Exception as e: logger.error(f"Error: {e}")`
**Estimated Time:** 5 minutes

---

### 7. `src/api/graph_sessions.py` - Line 3651
**Error:** `else` after `except` (invalid Python syntax)
```python
# BROKEN (around line 3651):
try:
    pass
except Exception:
    pass
else:  # ❌ else after except is invalid!
    pass

# FIX: Remove else or restructure
try:
    pass
except Exception:
    pass
# Just continue here, no else needed
```
**How to Fix:**
1. Open `src/api/graph_sessions.py`
2. Go to line 3651 (this is a LARGE file)
3. Find the `else:` that comes after `except:`
4. Either remove it or move the code elsewhere
**Estimated Time:** 10 minutes (large file)

---

### 8. `src/connectors/email/proofpoint_tap.py` - Line 141
**Error:** IndentationError
```python
# BROKEN (around line 141):
    def fetch_events(self):
        return []
      wrong_indent()  # ❌ Bad indentation

# FIX: Fix indentation
    def fetch_events(self):
        return []

    def other_method(self):  # Proper indent
        pass
```
**How to Fix:**
1. Open `src/connectors/email/proofpoint_tap.py`
2. Go to line 141
3. Fix indentation (likely needs 4 spaces, not 2 or 6)
4. Verify entire file: `python -m py_compile src/connectors/email/proofpoint_tap.py`
**Estimated Time:** 5 minutes

---

### 9. `src/core/arc_redis_queue.py` - Line 877
**Error:** Syntax error (exact issue unclear from truncated diagnostic)
**How to Fix:**
1. Open `src/core/arc_redis_queue.py`
2. Go to line 877
3. Run: `python -m py_compile src/core/arc_redis_queue.py` to see exact error
4. Common issues at line 877:
   - Unclosed parenthesis
   - Unclosed string
   - Missing colon after if/def/class
**Estimated Time:** 10 minutes

---

### 10. `src/core/cmdb/_impl.py` - Line 107
**Error:** `from __future__ import annotations` not at start
**How to Fix:**
1. Same as #3 and #4 - move to line 1
**Estimated Time:** 1 minute

---

### 11. `src/core/correlation/rules/network/beacon_low_frequency_enriched.py` - Line 14
**Error:** Syntax error (unknown type)
**How to Fix:**
1. Open `src/core/correlation/rules/network/beacon_low_frequency_enriched.py`
2. Go to line 14
3. Run: `python -m py_compile <file>` to see exact error
4. Common issues in correlation rules:
   - Missing comma in dictionary
   - Unclosed bracket/parenthesis
   - Invalid variable name
**Estimated Time:** 10 minutes

---

### 12-14. Three Additional Files (From Diagnostic)
**Check pytest output for exact files:**
```bash
pytest --collect-only 2>&1 | grep "SyntaxError"
```
This will show the remaining 3 files with syntax errors.

**Estimated Time:** 15 minutes to identify and fix

---

## P0 VERIFICATION CHECKLIST

After fixing all syntax errors above:

```bash
# 1. Verify Python syntax on all fixed files
python -m py_compile src/api/background_tasks.py
python -m py_compile src/api/executive_report_endpoints.py
python -m py_compile src/api/online_trainer_admin.py
python -m py_compile src/api/playbook_tenants.py
python -m py_compile src/api/routes/events.py
python -m py_compile src/api/routes/identity.py
python -m py_compile src/api/graph_sessions.py
python -m py_compile src/connectors/email/proofpoint_tap.py
python -m py_compile src/core/arc_redis_queue.py
python -m py_compile src/core/cmdb/_impl.py
python -m py_compile src/core/correlation/rules/network/beacon_low_frequency_enriched.py

# 2. Try to collect tests (should succeed now)
pytest --collect-only

# 3. If step 2 works, run a quick test
pytest tests/test_csv_analyzer.py -v

# 4. Commit fixes IMMEDIATELY
git add .
git commit -m "fix: resolve 14 critical syntax errors blocking test execution"
```

**Expected Result:** Pytest should collect ~1,798 tests without errors

---

## P1 - HIGH Priority Fixes (Next 24-48 Hours)

### 15. `src/api/csv_endpoints.py` - Remove Debug Code
**Issue:** Production code has debug prints and test-only logic
**Lines to Fix:**
- Line 30: Remove 200-row hardcoded cap
- Lines 15-200: Remove all `print()` statements (14 total)
- Lines with `PYTEST_CURRENT_TEST`: Remove test detection logic

**How to Fix:**
```bash
# Find all debug prints
grep -n "print(" src/api/csv_endpoints.py

# Remove them manually or with sed
# Then increase row cap:
```
```python
# BEFORE (line 30):
cap = min(200, len(rows))  # ❌ Artificial limit

# AFTER:
cap = len(rows)  # Process all rows
# Or if you want a reasonable limit:
cap = min(100000, len(rows))  # 100K row max
```

**Estimated Time:** 30 minutes

---

### 16. `src/adapters/qualys_connector.py` - Remove Duplicate Code
**Issue:** File has duplicate code blocks (lines 1-70 repeated)
**How to Fix:**
1. Open `src/adapters/qualys_connector.py`
2. Look for duplicate function definitions
3. Keep the most recent/complete version
4. Delete the duplicate
5. Verify: `python -m py_compile src/adapters/qualys_connector.py`

**Estimated Time:** 15 minutes

---

### 17. AWS Connectors - Add Basic Tests
**Issue:** 11 AWS connectors have ZERO test coverage
**Files:** `src/connectors/aws/*.py`
**How to Fix:**
```bash
# Create basic smoke test for each connector
# Example for CloudTrail:
cat > tests/test_aws_cloudtrail_connector.py << 'EOF'
import pytest
from src.connectors.aws.cloudtrail import CloudTrailConnector

def test_cloudtrail_connector_init():
    """Smoke test: can we instantiate the connector?"""
    connector = CloudTrailConnector(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1"
    )
    assert connector is not None

@pytest.mark.skip(reason="Requires AWS credentials")
def test_cloudtrail_fetch_events():
    """Integration test with real AWS (manual run only)"""
    # TODO: Add integration test
    pass
EOF

# Repeat for all 11 connectors
```

**Estimated Time:** 4 hours (30 min per connector × 11, but you can batch)

---

### 18. `src/core/dedup/dedup_service.py` - Add Redis Backend
**Issue:** Only single-process dedup, no distributed support
**How to Fix:**
1. Open `src/core/dedup/dedup_service.py`
2. Add Redis backend option (currently has TODO comment at line 6)
3. Update constructor to accept `redis_client` parameter
4. Use Redis SET with TTL for distributed dedup

**Code Template:**
```python
class DedupService:
    def __init__(self, ttl_seconds=300, redis_client=None):
        self.ttl = ttl_seconds
        self.redis = redis_client  # NEW
        self.local_cache = {}  # Fallback

    def is_duplicate(self, event_hash):
        if self.redis:
            # Use Redis for distributed dedup
            key = f"dedup:{event_hash}"
            if self.redis.get(key):
                return True
            self.redis.setex(key, self.ttl, "1")
            return False
        else:
            # Fallback to local cache (existing logic)
            return self._local_is_duplicate(event_hash)
```

**Estimated Time:** 2 hours

---

### 19. `src/core/graph/hopgraph_lite.py` - Remove Debug/Fallback Code
**Issue:** Lots of fallback error handling and optional features
**Lines to Clean:**
- Lines 23-28: Excessive try/except
- Line 66: Optional persistence (make it required or remove)

**How to Fix:**
1. Review all `try/except` blocks
2. Keep essential error handling, remove defensive "just in case" catches
3. Decide: Is persistence required? If yes, enforce it. If no, remove it.
4. Remove any `print()` or debug logging

**Estimated Time:** 1 hour

---

### 20. Database Migrations - Consolidate Dual Systems
**Issue:** Both Alembic and direct SQL migrations exist
**How to Fix:**
1. Choose ONE system (recommend: Alembic)
2. Verify all migrations in `migrations/` folder
3. Check if any SQL migrations are NOT in Alembic
4. Port missing migrations to Alembic format
5. Document: "Use Alembic only, SQL migrations are legacy"

**Estimated Time:** 4-6 hours (careful work required)

---

## P2 - MEDIUM Priority (Week 1 Before Production)

### 21. Remove Test-Only Code from Production Paths
**Files to Audit:**
- `src/api/csv_endpoints.py` - PYTEST_CURRENT_TEST checks
- `src/core/dedup/dedup_service.py` - Test mode detection (line 38-39)
- Any file with `if "pytest" in sys.modules:` logic

**How to Fix:**
1. Search codebase: `grep -r "PYTEST_CURRENT_TEST" src/`
2. Search: `grep -r "pytest" src/ | grep -v "# pytest"`
3. Remove all test detection from production code
4. Move test-specific behavior to conftest.py fixtures

**Estimated Time:** 2 hours

---

### 22. Audit Hardcoded Secrets
**Files Flagged:**
```
src/adapters/qualys_connector.py          - secret pattern
src/artifact/memory_acquisition.py        - api_key pattern
src/core/correlation/rules/email/*        - token pattern
src/core/detectors/ai_security.py         - password & token patterns
```

**How to Fix:**
1. `grep -r "api_key\s*=" src/`
2. `grep -r "password\s*=" src/`
3. `grep -r "secret\s*=" src/`
4. Verify each match is NOT a hardcoded credential
5. If found, replace with environment variable

**Estimated Time:** 1 hour

---

### 23. Increase CSV Processing Limits
**File:** `src/api/csv_endpoints.py`
**Changes:**
- Line 30: `cap = min(100000, len(rows))` (from 200)
- Add streaming for files >100K rows
- Add progress indicator for large files

**Estimated Time:** 2 hours

---

### 24. Fix Skipped Tests
**Issue:** 17 tests marked with `@pytest.mark.skip`
**How to Fix:**
1. `grep -r "@pytest.mark.skip" tests/`
2. Review each skipped test
3. Categories:
   - **Intentional skips** (require external API): Leave skipped
   - **TODO/WIP tests**: Either finish or remove
   - **Broken tests**: Fix the underlying issue

**Estimated Time:** 4-6 hours

---

### 25. Add Prometheus Metrics to Critical Paths
**Missing Metrics:**
- CSV upload success/failure rate
- AWS connector fetch latency
- Qualys API call success rate
- Deduplication cache hit ratio

**How to Fix:**
```python
from prometheus_client import Counter, Histogram

csv_uploads_total = Counter('csv_uploads_total', 'Total CSV uploads', ['status'])
csv_processing_duration = Histogram('csv_processing_seconds', 'CSV processing time')

# In your code:
with csv_processing_duration.time():
    process_csv(file)
csv_uploads_total.labels(status='success').inc()
```

**Estimated Time:** 3 hours

---

## P3 - LOW Priority (Weeks 2-4, Before Enterprise)

### 26. RBAC Implementation
**Files to Create:**
- `src/security/rbac.py`
- `src/security/permissions.py`
- `tests/test_rbac.py`

**Estimated Time:** 1-2 weeks (per roadmap)

---

### 27. Multi-Tenancy Hardening
**Files to Enhance:**
- `src/core/config/tenant_overrides.py`
- All database query functions (add tenant filter)

**Estimated Time:** 3-5 days (per roadmap)

---

### 28. Compliance Framework Mapping
**Files to Create:**
- `src/core/compliance/framework_mapper.py`
- `src/api/compliance_endpoints.py`

**Estimated Time:** 2-3 weeks (per roadmap)

---

### 29. Kubernetes Deployment Manifests
**Files to Create:**
- `k8s/janusec-deployment.yaml`
- `k8s/janusec-service.yaml`
- `k8s/janusec-hpa.yaml`
- `helm/janusec/Chart.yaml`

**Estimated Time:** 1-2 weeks (per roadmap)

---

### 30. UI Polish
**Files to Enhance:**
- `frontend/static/*.html` - Consistent styling
- `frontend/static/js/*.js` - Error handling
- Add loading spinners, better error messages

**Estimated Time:** 2-3 weeks

---

## QUICK WIN CHECKLIST (Do These First)

### TODAY (Next 2-3 Hours):
- [x] Fix 14 syntax errors (P0 #1-14)
- [x] Verify pytest can collect tests
- [x] Run one quick test to verify fixes work
- [x] Commit fixes immediately

### TOMORROW (Next 6-8 Hours):
- [ ] Remove debug prints from CSV endpoints (P1 #15)
- [ ] Clean up Qualys connector duplicates (P1 #16)
- [ ] Remove HopGraph debug code (P1 #19)
- [ ] Test Qualys connector with real API
- [ ] Test 2-3 AWS connectors end-to-end

### THIS WEEK (Next 3-4 Days):
- [ ] Add basic tests for AWS connectors (P1 #17)
- [ ] Add Redis backend to dedup service (P1 #18)
- [ ] Consolidate database migrations (P1 #20)
- [ ] Remove test-only code from production (P2 #21)
- [ ] Audit and fix any hardcoded secrets (P2 #22)

---

## VALIDATION COMMANDS

### After Each Fix:
```bash
# Syntax check individual file
python -m py_compile path/to/file.py

# Check imports work
python -c "from src.api.csv_endpoints import router; print('OK')"

# Verify pytest collection
pytest --collect-only

# Run specific test
pytest tests/test_csv_analyzer.py -v
```

### After All P0 Fixes:
```bash
# Full test run (will take 10-30 minutes)
pytest -v --tb=short

# Check test coverage
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

### After All P1 Fixes:
```bash
# Integration test with real services
pytest -v -m integration

# Performance test
pytest tests/test_csv_performance.py -v
```

---

## COMMIT STRATEGY

### After P0 Fixes:
```bash
git add src/api/background_tasks.py src/api/executive_report_endpoints.py \
        src/api/online_trainer_admin.py src/api/playbook_tenants.py \
        src/api/routes/events.py src/api/routes/identity.py \
        src/api/graph_sessions.py src/connectors/email/proofpoint_tap.py \
        src/core/arc_redis_queue.py src/core/cmdb/_impl.py \
        src/core/correlation/rules/network/beacon_low_frequency_enriched.py

git commit -m "fix: resolve 14 critical syntax errors blocking test execution

- Fix except without try in background_tasks.py
- Fix indentation errors in executive_report_endpoints.py and proofpoint_tap.py
- Move __future__ imports to top of file (3 files)
- Fix incomplete try blocks in routes/events.py and routes/identity.py
- Fix invalid else after except in graph_sessions.py
- Fix syntax error in beacon_low_frequency_enriched.py correlation rule
- Fix syntax error in arc_redis_queue.py and cmdb/_impl.py

All tests can now be collected and executed.
Blockers: RESOLVED
"
```

### After P1 Fixes:
```bash
git commit -m "refactor: remove debug code and production blockers

- Remove 14 debug print statements from csv_endpoints.py
- Increase CSV row cap from 200 to 100,000
- Remove duplicate code in qualys_connector.py
- Add basic smoke tests for AWS connectors (11 files)
- Add Redis backend to dedup_service.py for distributed dedup
- Remove test-only code paths from production
- Clean up HopGraph debug/fallback code

Production readiness: IMPROVED
"
```

---

## ESTIMATED TIMELINE

| Priority | Tasks | Time Required | When |
|----------|-------|---------------|------|
| **P0** | Fix 14 syntax errors | 2-3 hours | TODAY |
| **P1** | Production blockers | 16-20 hours | Next 2-3 days |
| **P2** | Code quality | 16-24 hours | Week 1 |
| **P3** | Enterprise features | 6-8 weeks | Weeks 2-8 |

**Minimum Viable Production:** P0 + P1 = ~3-4 days
**Production Pilot Ready:** P0 + P1 + P2 = ~1-2 weeks
**Enterprise Ready:** P0 + P1 + P2 + P3 = 6-8 weeks

---

## SUCCESS CRITERIA

### P0 Complete When:
- [ ] `pytest --collect-only` succeeds (collects ~1,798 tests)
- [ ] No syntax errors in any .py file
- [ ] At least 1 test runs and passes

### P1 Complete When:
- [ ] No debug print statements in production code
- [ ] AWS connectors have basic test coverage
- [ ] Qualys connector tested with real API
- [ ] CSV endpoints handle 10K+ rows
- [ ] Deduplication works across multiple processes

### P2 Complete When:
- [ ] All tests pass (or skipped tests are intentional)
- [ ] No test-only code in production paths
- [ ] No hardcoded credentials found
- [ ] Metrics instrumented on critical paths
- [ ] Database migrations consolidated

### P3 Complete When:
- [ ] RBAC implemented and tested
- [ ] Multi-tenancy validated (no data leakage)
- [ ] Compliance frameworks mapped
- [ ] Kubernetes deployment working
- [ ] UI polished for external demo

---

## NOTES

- **Current branch:** `feat/webhook-guard-middleware-only-verification` has 50+ uncommitted files
- **Recommendation:** Fix P0 on this branch, then create a clean branch for P1/P2 work
- **Test Strategy:** Fix syntax errors first, then run tests to find real issues
- **Don't Panic:** Core architecture is sound, these are fixable issues

---

## GET HELP

If stuck on any fix:
1. Run the specific Python compile command to see exact error
2. Check git history: `git log --oneline path/to/file.py` to see recent changes
3. Use git blame: `git blame path/to/file.py` to see who last touched problematic lines
4. Create minimal reproduction case
5. Ask for help with specific error message + context

---

**Last Updated:** 2026-01-16
**Next Review:** After P0 complete (should be TODAY)
