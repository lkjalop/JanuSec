Canonical Frontend & API

- React source: `frontend/react`
- Build output: `frontend/react/dist`
- API mounts React at `/react` and uses it for `/` when `dist` exists.
- React API base: `VITE_API_BASE` (Vite env) or `window.location.origin`.
- Detachable side panel: `/sidepanel` (Live, Dashboards, Metrics, Notify)

Build:

```
cd frontend/react && npm ci && npm run build
```

Run API:

```
uvicorn src.api.app:app --host 0.0.0.0 --port 8000
```

