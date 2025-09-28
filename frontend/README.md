# JanuSec Artifact Intelligence UI (Static MVP)

This folder contains a lightweight static integration UI served by FastAPI at `/ui/`.

## Features Implemented
- Fetch latest artifact report (`GET /api/v1/artifacts/latest_report`).
- Optional business summary toggle (`?business=1`).
- Dynamic artifact table (top risky items).
- Detail panel (risk, factors, cluster, rarity placeholder, hash placeholder).
- Override verdict (basic prompt + POST to `/api/v1/artifacts/feedback`).
- Markdown export (fetch `?format=markdown`).
- Search & simple filter chips (High/Malicious, Rare, Multi-Host).
- Detachable detail pop-out window.
- NLP query placeholder (disabled until backend LLM API added).

## Running
Start API (example):
```bash
uvicorn src.api.server:app --reload
```
Open: http://localhost:8000/ui/

If authentication required, set a global token in browser console before refresh:
```js
window.API_TOKEN = 'Bearer YOURTOKEN';
```

## File Structure
- `index.html` – Base layout + placeholders.
- `app.js` – Fetching, rendering, overrides, filters.

## Extending
1. Add real factor numeric contributions: extend backend to include `factor_details` per artifact.
2. Populate `rarity`, `host_count`, `sha256` (partial placeholders already added in serializer).
3. Add cluster list view (fetch `/api/v1/artifacts/clusters`).
4. Implement Upload: parse CSV/XLSX in-browser (SheetJS) → convert to items → POST `/api/v1/artifacts/analyze_batch`.
5. Accessibility pass: add ARIA roles, keyboard focus styling.

## NLP Integration Placeholder
Add endpoint (future) `/api/v1/artifacts/nlp_query` with payload:
```json
{ "query": "Summarize rare artifacts" }
```
Return JSON `{ "answer": "..." }` and enable textarea submit.

## Known Limitations
- Table currently uses only `top_risky` subset.
- No pagination or full artifact list.
- Host count & rarity depend on pipeline enrichment not fully surfaced yet.

---
