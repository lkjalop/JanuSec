SultryTAI — starter package

This package is a starting point for building the Sultry Triage/AI components. It contains a small API stub, a catalog loader for the factors catalog, and a demo runner.

Structure
- `sultrytai/api.py` — FastAPI app stub (exposes `/health` and `/factors` endpoints)
- `sultrytai/catalog.py` — loader for `sultry_prd/factors_catalog/full/factors_catalog_full.json` with basic validation
- `run_demo.py` — small runner to start the demo API

Next steps
- Add authentication, OpenAPI descriptions, and endpoints for scoring and correlation.
- Integrate with the rest of the Janusec platform as needed.
