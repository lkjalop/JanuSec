Smoke test notes

- Use `session_ids` with names starting with `batch-overlap-` to trigger deterministic synthetic batches from the server when fixtures are not present.
- Example payload:

  {
    "session_ids": ["batch-overlap-1", "batch-overlap-2"],
    "correlate": true,
    "ewma": true,
    "ewma_alpha": 0.6
  }

- This avoids needing to upload or persist sessions for quick local exploration.
- Run the quick smoke script: `python .\\.tmp_smoke_test.py`