# Next steps & how to use these modules

Quick start

1. Generate threat dimensions mapping:

```powershell
python sultry-dump\generate_threat_dimensions.py
```

2. Use `weights_loader` to hot-reload weights in a running service (call `reload_weights()` periodically or run `watch_forever()` in a side thread).

3. After running factor extraction for a batch of artifacts (list of dicts), call:

```python
from sultry-dump.coverage_service import get_coverage_report
report = get_coverage_report(list_of_artifact_dicts)
print(report)
```

4. Observe telemetry during extraction:

```python
from sultry-dump.telemetry import observe_factors, observe_risk_components, observe_extraction_latency, telemetry_snapshot
observe_factors(['lolbin_misuse','fresh_download'])
...
print(telemetry_snapshot())
```

5. Blend heuristic and ML:

```python
from sultry-dump.scoring_blender import blend
res = blend(heuristic_score=0.56, ml_predictor=my_model.predict, obs=artifact_dict)
```

Files created
- `factors.weights.json` – factor→weight table
- `weights_loader.py` – hot-reload loader
- `generate_threat_dimensions.py` – generator script
- `threat_dimensions.json` – created after running the generator
- `coverage_service.py` – coverage report helpers
- `telemetry.py` – collectors
- `scoring_blender.py` – blending logic

New helpers added
- `hopgraph_lite_min.py` – minimal contextual features: `rare_prevalence`, `multi_host_emergence`, `summarize_context`
- `adaptive_ewma.py` – EWMA utilities and `adaptive_alpha_from_counts` for deriving alpha from volatility
- `isolation_forest_adaptive.py` – lightweight wrapper around sklearn's `IsolationForest` with a fallback heuristic
- `hopgraph_attack_reconstruction.py` – adapter to `src.graph.reconstruction` with compact return shape (stub if missing)

Testing & validation
- I recommend wiring these into a small runner that consumes a JanaSec artifact batch and prints coverage + telemetry. I can add that runner next if you want.

Quick usage examples

```python
# hopgraph lite contextual summary
from sultry_dump import hopgraph_lite_min as hop
records = [{'host':'h1','file_hash':'abc'},{'host':'h2','file_hash':'abc'},{'host':'h2','file_hash':'def'}]
print(hop.summarize_context(records))

# adaptive isolation forest (fallback if sklearn missing)
from sultry_dump import isolation_forest_adaptive as ifa
features = [[0.1,0.2],[0.5,0.9],[0.0,0.05]]
model = ifa.fit_iforest(features)
print(ifa.score_samples(model, features))
```

Network & Endpoint helpers

```python
from sultry_dump.network_features import summarize_network
from sultry_dump.endpoint_features import summarize_endpoints, correlate_with_network

net_summary = summarize_network(network_records)
ep_summary = summarize_endpoints(endpoint_records)
signals = correlate_with_network(ep_summary, net_summary)
print(net_summary, ep_summary, signals)
```

Integration with the Correlation Engine

- Where to plug-in: call `summarize_context()` and the network/endpoint summarizers after ingestion/enrichment and before factor scoring so the contextual features can be consumed by factor extractors and the scoring blender.
- Example integration points:
	- In the ingestion pipeline, after parsing and canonical mapping, call the endpoint/network summarizers to produce temporal signals tied to the batch/session id.
	- Provide `signals` to factor extractors as part of the `context` argument (`{'hopgraph': {...}, 'network': {...}, 'endpoint': {...}}`).
	- When building graph sessions, pass the `context` so factors like `multi_host_emergence` and `nxdomain_rate` are available for co-occurrence scoring and EWMA smoothing.

- Minimal contract for factor extractors:
	- Accept `artifact` (dict) and `context` (dict) and return a list of factor names and scores.
	- Example: `def extract(artifact, context): return [{'factor':'multi_host_emergence','score':context['hopgraph']['rare_prevalence']}, ...]`

Security & performance notes

- These helpers are intentionally dependency-light. For production integration, replace heuristics with the project's robust implementations (e.g., full HopGraph, sklearn for isolation forest, or a persistent EWMA store).
- If you enable hot-reload for `factors.weights.json` in a running service, ensure reload operations are serialized with a short lock to prevent mid-batch inconsistencies.

Next actions I can take

- Add a small demo runner that: ingests sample network+endpoint+artifact batches, runs the summarizers, runs factor extraction, and prints coverage + telemetry + blended scores.
- Add unit tests for each new helper.

