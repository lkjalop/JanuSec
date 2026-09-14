## TF-IDF CI Gating

- Purpose: ensure TF-IDF model quality before merge/deploy.
- Metrics: precision (primary), recall (secondary). Default gates: precision >= 0.6, recall >= 0.35.
- Implementation: `scripts/build_tfidf_from_shadow.py` produces `data/tfidf_metrics.json`. CI runs `scripts/check_tfidf_metrics.py` which fails when metrics below thresholds.
- How to override thresholds: set `TFIDF_MIN_PRECISION` and `TFIDF_MIN_RECALL` env vars in CI.
