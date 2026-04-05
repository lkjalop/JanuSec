PR Preview: test-harness changes
=================================

This file documents the preview branch `pr/test-harness-preview` contents and verification steps you can run locally before opening the PR.

Files changed in this preview:
- .github/workflows/pytest-lite.yml  (runs lite suite on push/PR; schedule weekly full run)
- .github/workflows/pytest-full.yml  (nightly/dispatch full matrix)
- TEST_HARNESS.md                    (test harness notes)
- README.md                          (added CI badges)
- src/api/app.py                      (reverted temporary import guard; integrations router restored)

Local verification steps (PowerShell):

```powershell
# 1. Create preview branch
git checkout -b pr/test-harness-preview

# 2. Stage and commit the changes (if not already committed locally)
git add .github/workflows/pytest-lite.yml .github/workflows/pytest-full.yml TEST_HARNESS.md README.md src/api/app.py

git commit -m "chore(test): add lite/full CI workflows and document test harness"

# 3. Run lint (optionally)
python -m pip install --upgrade pip
if (Test-Path .\requirements.txt) { pip install -r requirements.txt }
# run your linter if available, e.g., ruff or flake8
# ruff check .

# 4. Run the lite test suite locally
$env:PLATFORM_LITE_INIT='1'
python -m pytest -q tests/test_webhook_guard.py tests/test_zeek_adapter.py tests/test_dread_scorer.py tests/test_intel_sync.py tests/test_bgp_network_wiring.py tests/test_ebpf_smoke.py tests/test_identity_snapshot.py tests/test_bgp_metadata_edges.py

# 5. Run the full test suite (optional, longer)
python -m pytest -q

# 6. If satisfied, push the preview branch and open a PR
git push origin pr/test-harness-preview
# create PR via GitHub UI or gh cli:
# gh pr create --base main --head pr/test-harness-preview --title "test(harness): ..." --body-file PR_PREVIEW.md
```

Notes:
- The `tests/conftest.py` file provides lightweight stubs for `psycopg2` and cloud SDKs so pytest collection does not fail when those optional drivers are not installed.
- CI workflows run the lite test suite on push/PR and the full test matrix on schedule or by manual dispatch.
