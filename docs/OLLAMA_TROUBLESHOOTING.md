Ollama Troubleshooting & Performance Tips

Summary
- Large local models (e.g. llama3:8b) on CPU can take a long time to cold-start and may return 500s while spinning up.
- The service supports configuring longer timeouts and batching; prefer smaller models for fast interactive Tier-1/Tier-2 summaries.

Recommended env vars
- OLLAMA_HOST: http://127.0.0.1:11434
- OLLAMA_MODEL: llama3:8b (or change to llama3:4b, ggml-model, etc.)
- OLLAMA_TIMEOUT_SECONDS: 120  # increase to allow cold-starts
- LLM_TIMEOUT_SECONDS: 120
- LLM_WORKER_BATCH: 8  # increase how many rows processed per worker loop
- LLM_WORKER_INTERVAL_SECONDS: 0.5  # reduce polling latency in dev
- LLM_GEN_PER_ASSESS_PER_MIN: 10  # allow more generation per-minute for heavy analyses

Quick fixes for triage responsiveness
- Use a smaller model for interactive Tier-1 requests (set OLLAMA_MODEL to a lower-parameter model).
- Disable Auto-LLM in the Deep Analyze modal to run faster and queue LLM work in background.
- Enable background worker tuning in env and set LLM_WORKER_BATCH larger to process more rows.

Server-side improvements implemented
- LLM client now increases Ollama timeouts automatically for models that look large (e.g. ":8b").
- Per-attempt timeout increased so occasional slow responses are retried with a longer final attempt.

Operational checklist
1. If you see repeated 500s, check the Ollama server logs and ensure the model was loaded successfully.
2. If running on CPU, expect 30-120s cold starts for 8B models; prefer a GPU host or smaller model for interactive use.
3. To force the app to use OpenAI/Anthropic instead of Ollama, set `LLM_PROVIDER=openai` and add `OPENAI_API_KEY`.

If you'd like, I can:
- Add a feature flag to auto-fallback to a deterministic/local summary when Ollama responds with repeated 5xx errors.
- Implement batching of prompts into multi-row prompts to amortize model latency.

