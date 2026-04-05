Sultry Dashboards — samples folder

This folder contains example artifacts for quick demos.

Files:
- `grafana/sultry_overview.json` — importable Grafana dashboard stub (overview panels)
- `prometheus/sample_metrics.py` — tiny Flask app exposing example metrics at `/metrics`

How to run the sample metrics (requires Python and Flask):

```powershell
& .\.venv-1\Scripts\Activate.ps1
pip install flask
python sultry_prd/dashboards/prometheus/sample_metrics.py
# then visit http://127.0.0.1:8000/metrics
```

Notes:
- These are minimal stubs intended for local demos only. Replace metric labels and values with real pipeline exports.
- If you want, I can generate a richer Grafana JSON (with templating variables) or a Kibana saved-object export next.
