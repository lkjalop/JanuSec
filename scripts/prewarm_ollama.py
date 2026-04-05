"""Warm up the local Ollama model by issuing a quick prompt.

Typical usage:
    python scripts/prewarm_ollama.py --model llama3:8b --prompt "ready check"

If --ollama-host is not provided, the script inspects /api/v1/llm/health on the
running backend (requires --server and --api-key) to discover the configured
host/model before issuing a direct /api/generate call to the Ollama daemon.
"""
from __future__ import annotations

import argparse
import json
from typing import Optional

import requests


def discover_ollama(server: str, api_key: str) -> tuple[Optional[str], Optional[str]]:
    """Read /api/v1/llm/health to find the configured Ollama host/model."""
    url = f"{server.rstrip('/')}/api/v1/llm/health"
    headers = {'x-api-key': api_key} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if not resp.ok:
            print(f"llm/health returned {resp.status_code}: {resp.text}")
            return None, None
        data = resp.json()
        ollama = data.get('ollama') or {}
        host = ollama.get('host') or ollama.get('base_url')
        model = ollama.get('model')
        return host, model
    except Exception as exc:
        print(f"Failed to query {url}: {exc}")
        return None, None


def prewarm(host: str, model: str, prompt: str, timeout: int = 90) -> dict:
    """Send a blocking /api/generate request to load the model into memory."""
    payload = {
        'model': model,
        'prompt': prompt,
        'stream': False,
    }
    resp = requests.post(
        f"{host.rstrip('/')}/api/generate",
        json=payload,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="Preload Ollama model via /api/generate.")
    parser.add_argument('--server', default='http://localhost:8080', help='Backend base URL used to query /api/v1/llm/health')
    parser.add_argument('--api-key', default='devkey123', help='API key for the backend health check')
    parser.add_argument('--ollama-host', default=None, help='Explicit Ollama host (e.g., http://127.0.0.1:11434)')
    parser.add_argument('--model', default=None, help='Model name to warm (defaults to value reported by /api/v1/llm/health)')
    parser.add_argument('--prompt', default='Preparedness check from prewarm script.', help='Brief prompt used for the warm-up generate call')
    parser.add_argument('--timeout', type=int, default=90, help='Timeout (seconds) for the generate request')
    args = parser.parse_args()

    host = args.ollama_host
    model = args.model

    if not host or not model:
        discovered_host, discovered_model = discover_ollama(args.server, args.api_key)
        host = host or discovered_host
        model = model or discovered_model

    if not host:
        raise SystemExit("Unable to determine Ollama host. Pass --ollama-host or configure /api/v1/llm/settings.")
    if not model:
        raise SystemExit("Unable to determine Ollama model. Pass --model or update /api/v1/llm/settings.")

    print(f"Prewarming Ollama model '{model}' at {host} ...")
    result = prewarm(host, model, args.prompt, timeout=args.timeout)
    print("Warm-up response:")
    print(json.dumps({
        'model': result.get('model'),
        'created_at': result.get('created_at'),
        'response_excerpt': (result.get('response') or '')[:160],
    }, indent=2))
    print("Ollama warm-up complete.")


if __name__ == '__main__':
    main()
