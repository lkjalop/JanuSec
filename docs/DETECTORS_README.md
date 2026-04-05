Detector architecture and environment variables
=============================================

This file documents the key detector behavior, confidence scaling, and relevant
environment variables used to tune detection for demo and trials.

Env vars
--------
- `DNS_CDN_WHITELIST` - comma-separated domain suffixes to treat as CDN/allowlist.
  Default: `cloudfront.net,cloudflare.com,amazonaws.com,akamai.net,googleusercontent.com`
- `CDN_ALLOWLIST_PATH` - path to a file with one domain suffix per line to extend
  the allowlist. Lines beginning with `#` are ignored.
- `FILE_HASH_HISTORY_MAXLEN` - maximum number of timestamp entries kept per file
  hash in runtime history (default 200). This bounds memory growth.
- `FILE_HASH_HISTORY_MAX_KEYS` - maximum distinct file hash keys retained (default 5000). Smallest histories pruned when exceeded.
- `FILE_HASH_HISTORY_TTL_SECONDS` - prune per-hash timestamps older than TTL (default 604800 seconds / 7d).
- `FILE_HASH_DECAY_SECONDS` - exponential decay tau for rarity effective counts (0 disables). Effective count = sum(exp(-(age/tau))).
- `NX_TRACKER_MAX_PRODUCERS` - cap on distinct NXDOMAIN producers tracked (default 200); smallest sample sets pruned beyond cap.
- `FACTOR_CONFIDENCE_WEIGHTS` / `FACTOR_CONFIDENCE_WEIGHTS_PATH` - JSON/YAML factor->weight mapping for weighted confidence aggregation (supports fallback `*`).
- `FACTOR_LABELS_PATH` - persistence path for `/api/v1/factors/label` false-positive annotation storage.

Detector architecture
---------------------
Detectors are lightweight, synchronous functions that observe runtime trackers
or event attributes and return factor objects with at least `factor` and
`score` keys. Example detectors:

- `dns_exfil_factors(runtime, ...)` — inspects `runtime.nx_rate_tracker` and
  optional `runtime.dns_query_samples` to compute NXDOMAIN ratios and
  subdomain entropy. Uses CDN allowlist to reduce false positives.
  Enhancements: TXT/CNAME ratio weighting (`txt_ratio`, `cname_ratio`) and pattern hint (`nxdomain_then_cname_chain`).
- `file_hash_rarity_factors(runtime, files, ...)` — computes rarity of file
  hashes relative to historical counts stored in `runtime.file_hash_factors`.
  History is stored as bounded deques of timestamps for each hash.
  Supports decay via `FILE_HASH_DECAY_SECONDS` and prunes distinct keys with `FILE_HASH_HISTORY_MAX_KEYS`.

Detectors append their factor objects (with `score`) to the session factor
list. A shared scoring helper (`src/core/scoring/confidence.py`) provides
`combine_scores(scores, method)` to merge multiple detector scores into an
overall confidence uplift.

Confidence scaling
-----------------
- Individual detectors should emit calibrated scores in `[0.0, 1.0]`.
- The session builder collects detector scores and applies `combine_scores`
  (default `prod` method) and scales the result (e.g. `* 0.6`) before adding
  an uplift to the session confidence. This multiplicative approach models
  the probability that at least one detector is accurate while limiting
  runaway confidence from many weak signals.

Operational notes
-----------------
- Tune `FILE_HASH_HISTORY_MAXLEN` and TTL cleanup frequency for your
  environment to balance memory and sensitivity.
- If you expect many legitimate high-entropy DNS subdomains (CDNs), populate
  `CDN_ALLOWLIST_PATH` with known suffixes to reduce noise.
- Use weighted confidence (factor -> weight) to emphasize critical signals. The `chain_explanation` block in session summaries lists top contributors and applied weights.
- Label false positives via `/api/v1/factors/label` to suppress noisy factors and build governance history.
- Replay historical custody events with `/api/v1/replay?from=&to=&reprocess=1` after detector improvements.

For more details see `DETECTOR_TAXONOMY.md` and the code under
`src/core/detectors`.
