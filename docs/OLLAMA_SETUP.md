# Local Ollama Setup (quick-start)

This project supports a local Ollama model for low-latency LLM inference. The following is a minimal setup guide and recommended environment variables to run local Ollama with the application.

Prerequisites:
- Install Ollama: https://ollama.com/docs
- Download or use an existing Ollama-compatible model (e.g., `llama2` or other Ollama-supported models).

Environment variables (example):

```
# Host where Ollama is reachable (default: http://localhost:11434)
OLLAMA_HOST=http://localhost:11434

# Model name configured in Ollama (example: llama2)
OLLAMA_MODEL=llama2

# Optionally point the integrated LLM client to use local Ollama by default
LLM_PROVIDER=ollama

# Developer convenience: enable LLM mock (set to 0 to use real model)
LLM_MOCK=0

# Circuit breaker / tenant budget (optional tuning)
LLM_TENANT_BUDGET_USD=5.00
LLM_CIRCUIT_BREAKER_ENABLED=1
```

Quick test (after starting `ollama serve` and loading a model):

1. Start the backend server from the repository Python environment, then trigger a deep analyze via the UI or an API client to `/api/v1/csv/deep_analyze`.

Notes:
- If using Ollama in production, ensure proper resource limits and monitoring. The repo includes a circuit-breaker and tenant budget snapshot feature — configure `LLM_TENANT_BUDGET_USD` to avoid runaway costs.
- For local development and deterministic runs, keep `LLM_MOCK=1` to use canned summaries.
