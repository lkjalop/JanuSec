# CEO Demo Flow (5–7 Minutes)

Purpose: Show ingestion -> detection -> triage -> incident -> report -> cost & risk insights with minimal clicks, emphasizing autonomy and analyst acceleration.

## 0. Prep (Before Meeting)
1. Run seeding & start script:
   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start_demo.ps1
2. Verify:
   - /api/v1/hunt/overview returns JSON.
   - Console root loads (http://localhost:8080/).
   - CSV Analyzer shows XLSX banner (proves offline parsing fallback).

## 1. Ingestion & Live Console (1 min)
Screen: `janusec-platform-complete-LIVE.html` (root)
Talking Points:
- Unified autonomous pipeline (events → factors → decisions) displayed in real-time.
- Offline-capable XLSX / CSV client parsing reduces dependency risk.
Actions:
1. Briefly scroll recent decisions.
2. Click “Export Investigation Report” (shows HTML detail proving narrative traceability). Close tab.

## 2. Threat Triage (CSV/XLSX Upload) (1.5 min)
Screen: `csv_analyzer.html`
Talking Points:
- Local SheetJS fallback ensures XLSX works without CDN.
- Filters (Threats/All/Benign) accelerate analyst focus.
- Per-row “Mark Malicious / Mark Good” future supports feedback loop (undo coming Day 2).
Actions:
1. Upload sample XLSX (fixture). Observe row count + flagged reasons.
2. Apply “Threats” filter.
3. Open “Why Flagged” (if modal wired) or highlight factors column.

## 3. Network Hunt Snapshot (1 min)
Screen: `hunt_network.html`
Talking Points:
- Hunt Overview card (seeded metrics) – demonstrates birds-eye view.
- Client-side filtering for speed (JA3/JA4, domain, DoH detection factors).
Actions:
1. Show overview counts (Incidents, Decisions, Open Triage).
2. Type a quick filter (e.g., partial IP) → Apply.

## 4. Incident & Explain (1 min)
Screen: Back to LIVE console or Incident list (if implemented). If not, simulate:
Talking Points:
- Each decision retains explainability via stored factors & model introspection.
Actions:
1. Trigger “Create Incident From Recent” (demo action calls incident POST).
2. Immediately click one decision “Explain” (if UI path) or use `/api/v1/decisions/{id}/explain` in a new tab to show JSON factors.

## 5. Reporting & Risk / FinOps (1 min)
Screen: Exported report (already opened earlier) and optional Metrics or FinOps page.
Talking Points:
- Report includes model + scenarios (transparent governance).
- FinOps view (if seeded) demonstrates cost vs detection efficiency.
Actions:
1. Reopen the previously exported report (browser history) or export again.
2. (Optional) Open metrics page for cost summary.

## 6. Wrap: Differentiators (30–45 sec)
Bullet Wrap:
- Offline parsing resilience (CDN & dependency loss tolerant).
- Explainable decisions (factor taxonomy + audit trail).
- Seeded hunting lens (network + endpoint extensibility) – platform surfaces patterns not just alerts.
- Fast analyst path: upload → filter → disposition → incident → report within minutes.
- Modular seeding / file-based bootstrap = frictionless POC.

## Appendix
### Fallback Talking Points (If Something Stalls)
- “Health endpoint delay”: Emphasize decoupled initialization safeguards.
- “No live incidents”: Use seeding script again; highlight idempotent design.

### Suggested Screenshot List
1. LIVE console (recent decisions panel).
2. CSV Analyzer after XLSX upload (Threats filter active).
3. Hunt Network page showing Overview card + filtered table.
4. Incident creation toast / confirmation (if visible).
5. Exported Investigation Report header section.

### Contingency Quick Commands
Regenerate seed:
  python scripts/seed_demo.py
Check health:
  (Invoke-WebRequest http://localhost:8080/api/v1/health).StatusCode

---
Revision: v1 (initial draft). Enhance with undo/disposition UX & guardrail trigger after Day 2 tasks.
