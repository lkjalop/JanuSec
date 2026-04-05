# CEO Demo Quick Start

This guide gets you from zero to a working demo in ~5 minutes using the LIVE console and CSV multi-source uploads. It uses simulated streaming (1 Hz) to showcase end-to-end factors and HopGraph correlation.

## Prerequisites
- Python 3.10+
- `pip install -r requirements.txt`
- API runs at `http://localhost:8080` (run `python run_platform.py`)

## Steps
1) Start the API
   - `python run_platform.py`
2) Open the LIVE Console
   - Browser: `http://localhost:8080/`
   - Explore `/static/csv_multi_analyzer.html` from the left sidebar
3) Run the demo uploader (new terminal)
   - `python -m scripts.demo_ceo tests/fixtures/api_gateway_sample.csv tests/fixtures/database_query_sample.csv tests/fixtures/vpn_access_sample.csv tests/fixtures/rdp_sessions_sample.csv`
4) Observe
   - Factors in right panel
   - API Security summary panel
   - Data access summary panel
   - Remote access edges and flags
   
   Screenshots (replace with your runs):
   - ![Dashboard Panels](images/ceo_demo_dashboard_panels.png)
   - ![CSV Multi-Source Upload](images/ceo_demo_csv_multi_upload.png)
   - ![API Security Summary](images/ceo_demo_api_summary.png)
   - ![Data Access Summary](images/ceo_demo_data_summary.png)
   - ![Remote Access Edges](images/ceo_demo_remote_edges.png)

## What’s under the hood
- Unified HopGraph architecture:
  - Core: `src/core/graph/hopgraph_core.py` (prod-grade, durable, final-stage)
  - Lite: `src/core/graph/hopgraph_lite.py` (early-stage cache/time-window)
  - Light (compat): `src/core/hunt/hopgraph_light.py` (late-stage tracker; slated for consolidation)
- CSV Multi Upload auto-detects file kind and forwards to appropriate endpoints.
- Ensure x-api-key is set (defaults to `devkey123`).

Images live under `docs/images/`. If not present yet, capture from your run and drop PNGs with the names above.

## Next
- Real streaming: CloudWatch webhook, Azure Event Hub, GCP Logging, Okta system log polling (Week 2 plan)
- Add screenshots of the panels in the LIVE console for the slide deck.
