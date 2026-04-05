Batch 3 Plan — Nov 2025

Goals
- Improve offline-first UX and progressive enhancement.
- Introduce lazy-loaded heavy bundles and code-splitting for charts and graph viewers.
- Implement a small telemetry ping to collect frontend error rates and SW activation metrics (local-only, no external telemetry).
- Add feature flags + rollout toggle in `layout_loader.js` using `localStorage` toggle.

Milestones
1. Wallet: Asset prefetching and SW optimization (smoother caching, resource prioritization).
2. Lazy-load: Move charts and graph libraries to dynamically loaded bundles.
3. Telemetry: Add `frontend/static/js/telemetry.js` with a lightweight queue and POST backoff.
4. Flags: Add basics of feature flag UI and runtime gating.
5. Tests: Add Playwright end-to-end tests for lazy-loading and flag gating.

Deliverables
- `frontend/static/js/telemetry.js`
- `frontend/static/js/lazy_loader.js` (already present as `lazy_load.js`; extend as needed)
- Playwright tests

Notes
- Continue conservative approach: never change upload endpoints, minimize inline HTML diff size.
