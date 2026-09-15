Qualys Integration Test Guide
=============================

This document explains how to record VCR-style cassettes for the Qualys
connector and how to run cassette-based integration tests without real
credentials.

Recording cassettes (live Qualys account required)
-------------------------------------------------

- Install test deps (requests, pytest, vcrpy, tenacity)
  ```bash
  python -m pip install -r requirements-dev.txt
  pip install vcrpy
  ```
- Create a small recording script that uses `requests` to hit the real
  Qualys endpoints and write responses to `tests/integration/cassettes/` as
  JSON. The simplest approach is to run the `src/adapters/run_qualys_ingest.py`
  with real credentials and capture outputs, or use `vcrpy` to record HTTP
  interactions.
- Set environment variables:
  - `QUALYS_CLIENT_ID`
  - `QUALYS_CLIENT_SECRET`

- Run tests that exercise live endpoints and save responses to files under
  `tests/integration/cassettes/`. Avoid committing credentials. Sanitize
  any sensitive fields before committing cassettes.

Using cassette-based tests in CI
-------------------------------

- The repository includes a sample cassette `sample_qualys_vulns.json`. The
  test `tests/test_qualys_connector_with_cassette.py` reads JSON from
  `tests/integration/cassettes/` and verifies mapping behavior.
- The GitHub Actions workflow `qualys-integration.yml` runs the cassette unit
  test unconditionally and only runs live integration tests when
  `QUALYS_CLIENT_ID`/`QUALYS_CLIENT_SECRET` secrets are provided.

Wiring the bridge into the ingestion pipeline
--------------------------------------------

The helper `src/adapters/bridge.py` exposes `ingest_vulns_from_connector(name, **kwargs)`.
To wire this into your pipeline:

- Locate the ingestion worker or scheduler entry point in the codebase (e.g.
  in `src/tasks/` or `src/ingest/`).
- Add a scheduled job that calls the bridge and forwards each mapped artifact
  into your existing ingestion API or database.

Example (pseudo-code):

```py
from src.adapters.bridge import ingest_vulns_from_connector

for artifact in ingest_vulns_from_connector('qualys', client_id=..., client_secret=..., api_base=...):
    push_to_pipeline(artifact)
```

Prometheus metrics
------------------

If `prometheus_client` is installed, the connector and telemetry module will
expose Prometheus counters. Ensure your application exposes `/metrics` via
`prometheus_client`'s `make_wsgi_app()` or similar so a Prometheus server
can scrape the metrics.
Qualys integration tests
=======================

How to run
----------

1. Set the following environment variables with a Qualys service account:

   - `QUALYS_CLIENT_ID`
   - `QUALYS_CLIENT_SECRET`

2. To record VCR cassettes for offline playback, run the integration test with a VCR library (e.g., `pytest-vcr`) enabled and commit the recorded cassette files under `tests/integration/cassettes/`.

CI
--

The GitHub Actions workflow `.github/workflows/qualys-integration.yml` will skip live tests when secrets are not available.