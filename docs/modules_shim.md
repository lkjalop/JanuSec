# `modules` shim and optional analyzers

This project historically exposes analyzer implementations under imports like
`from modules.certificate_analysis import CertificateAnalysis`.

Recent changes:

- A lightweight compatibility shim `modules/__init__.py` was added which maps
  `modules` to the repository's `src/modules` directory to preserve existing
  imports during local/demo runs.
- The event pipeline now lazy-loads heavy/optional analyzers at stage runtime
  instead of import time. Missing analyzers will cause a non-fatal stage
  result and a debug log will be emitted under the `pipeline.stages` logger.

Recommended production approach:

1. Prefer installing analyzer dependencies explicitly instead of relying on
   the shim. Document optional analyzer extras in `pyproject.toml` or
   `requirements.txt` (e.g., `pip install .[analyzers]`).
2. For demo or CI lightweight runs, use the shim or set `PLATFORM_LITE_INIT=1`
   and disable heavy stages via pipeline config if available.
3. Monitor `pipeline.stages` debug logs to detect missing optional analyzers.
