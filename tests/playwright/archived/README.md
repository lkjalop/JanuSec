# Archived Playwright Tests

These tests were archived because they reference UI elements or APIs that no longer exist.

## Files

- **llm_panels.spec.ts** — Referenced `#llmSummaryPanel`, `#ransomwareInsightsPanel`, `#btnRunLlmTriage`. These panels were planned but not built in the current console/home page.
- **test_admin_panel.spec.js** / **test_admin_thresholds.spec.ts** — Tested an admin threshold tuning panel UI (`adminKey`-gated) that no longer exists in the console page.
- **test_sbom_upload.spec.js** / **test_sbom_upload.spec.ts** — Referenced `#setDemoKey` button (now hidden) and `#test_ready` element (never added to sbom.html).
- **admin_factors.spec.ts** — Admin factors feedback endpoint changed signature (now requires `fn` query param).

## Restore

Move back to `tests/playwright/` if the referenced features are rebuilt.
