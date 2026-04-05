CEO Demo Runbook (7-day UI/D3 focus)

Overview:
- Goal: Showcase cohesive platform to CEO with polished UI, interactive factors visualization, and an attack graph demo.
- Duration: 12-15 minute walkthrough.

Order of Operations (scripted):
1. Start server (local dev) with dev key:

```powershell
$env:PLATFORM_LITE_INIT="1"; $env:API_KEY="devkey123"; $env:DEFAULT_FRONTEND="console"; python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8080
```

2. Open Live Console: `http://127.0.0.1:8080/` (displays unified nav)
3. Navigate to "Executive Overview" (sidebar) — show KPIs and Risk Drivers
   - If live data missing, note "sample mode" and point to top factors panel.
4. Open "Factors Top-20" — demonstrate search, domain filter, keyboard navigation (Tab + Enter), open modal and copy JSON.
5. Open "Attack Graph (Interactive)" (`/static/graph_explain_v2.html`) — drag nodes, zoom/pan, export PNG.
6. If any API endpoint fails, switch to cached data: show in console that cached data is used and continue.
7. End demo: highlight roadmap and planned A11y & testing improvements.

Playbook for Failures:
- If backend unreachable: show `authProbeBanner` demo key actions (copy demo key; set demo key) and reload.
- If graphs heavy: switch to static sample graph (preloaded fallback) and continue.

Smoke Tests (local):
- Run Playwright smoke test (Node + Playwright installed):

```powershell
npx playwright test tests/e2e/playwright/smoke_factors.spec.js --headed
```

Notes:
- Keep demo crisp: 12–15 minutes. Focus on outcomes, not implementation details.
- Have a brief note for each slide (KPIs, Risk Drivers, Factors, Attack Graph) to guide conversation.

