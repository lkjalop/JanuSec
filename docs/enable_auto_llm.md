# Enabling Auto-LLM Narrative Generation

Overview
- The platform has hooks for generating Tier-2 narratives and incident summaries via an LLM backend (`src/integrations/llm_client.py` and UI toggles). This doc explains how to enable and wire an LLM provider.

Prerequisites
- An LLM endpoint (local or cloud) reachable from the runtime. This can be Ollama, OpenAI, a local LLM server, or any model-serving endpoint that accepts JSON prompts.
- API key or access credentials if required.

Steps
1. Choose an LLM provider and note its base URL and API key.
2. Configure env vars used by the project (check `src/integrations/llm_client.py` for exact variable names). Common vars: `LLM_PROVIDER_URL`, `LLM_API_KEY`, `LLM_DEFAULT_MODEL`.
3. Enable Auto-LLM in the admin config: `/api/v1/admin/autogen/toggle` or set `AUTO_LLM_ENABLED=1` if present.
4. Restart the server and exercise the UI toggle in the LIVE console (right rail). Trigger a sample incident and request an autogen narrative.

Notes
- For local testing with Ollama, install and run Ollama and set `LLM_PROVIDER_URL` accordingly. For OpenAI-compatible endpoints, ensure rate limits and tokens are managed.
