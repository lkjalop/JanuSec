#!/usr/bin/env python3
"""
Send a streaming-aware generate request to a local Ollama server and retry until a
non-empty response is produced or a max wait is reached.

Usage:
  python scripts/ollama_stream_and_retry.py

This will read OLLAMA_HOST from the environment or default to http://127.0.0.1:11434
and attempt POST /api/generate (and a few alternate paths) with long timeouts and
SSE/chunk handling. Successful output is written to data/ollama_success.json.
"""
import os
import sys
import time
import json
import signal
from typing import Optional

import requests


OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "llama3:8b")
TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "300"))
RETRY_INTERVAL = float(os.environ.get("OLLAMA_RETRY_INTERVAL", "5"))
MAX_TOTAL_SECONDS = int(os.environ.get("OLLAMA_MAX_TOTAL_SECONDS", "600"))

OUT_PATH = os.path.join("data", "ollama_success.json")


def try_paths():
    # common endpoint shapes observed in various Ollama builds
    yield f"{OLLAMA_HOST}/api/generate"
    yield f"{OLLAMA_HOST}/v1/generate"
    yield f"{OLLAMA_HOST}/v1/predictions"
    # model-specific
    yield f"{OLLAMA_HOST}/v1/models/{MODEL}/generate"
    yield f"{OLLAMA_HOST}/api/models/{MODEL}/generate"


def build_payload(prompt: str):
    # Ollama variants accept `prompt` as a string, not a list. Add a common wrapper.
    return {
        "model": MODEL,
        "prompt": prompt,
        "max_tokens": 512,
        "temperature": 0.2,
        "top_p": 0.95,
    }


def save_success(resp_json: dict):
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(resp_json, f, indent=2, ensure_ascii=False)
    print(f"Saved successful response to {OUT_PATH}")


def stream_request(url: str, payload: dict, timeout: int) -> Optional[dict]:
    print(f"POST {url} with timeout={timeout}s")
    headers = {"Content-Type": "application/json"}
    try:
        with requests.post(url, json=payload, headers=headers, stream=True, timeout=timeout) as r:
            print(f"Status: {r.status_code}")
            if r.status_code >= 400:
                try:
                    return {"error_status": r.status_code, "error_body": r.text}
                except Exception:
                    return {"error_status": r.status_code}

            # Some Ollama builds stream via chunked responses; collect incrementally.
            collected = ""
            done_reason = None
            # Try to parse full body if not streaming
            try:
                text = r.text
                if text:
                    try:
                        j = json.loads(text)
                        # If the service returned structured JSON, return it
                        return j
                    except Exception:
                        # Not JSON; treat as raw text
                        collected += text
                # If we got here and no JSON, also try iter_lines for streaming
            except requests.exceptions.ReadTimeout:
                print("Read timeout while reading text()")

            for chunk in r.iter_content(chunk_size=None):
                if not chunk:
                    continue
                try:
                    part = chunk.decode("utf-8")
                except Exception:
                    part = str(chunk)
                collected += part
                # Try to keep a lightweight heartbeat print
                sys.stdout.write(".")
                sys.stdout.flush()

            if collected:
                # attempt to parse JSON blob inside collected
                try:
                    j = json.loads(collected)
                    return j
                except Exception:
                    # Fallback: return as text wrapper
                    return {"model": MODEL, "response": collected, "done": True}

            return None
    except requests.exceptions.ReadTimeout:
        print("Request timed out")
        return {"error": "timeout"}
    except Exception as e:
        print(f"Request exception: {e}")
        return {"error": str(e)}


def main():
    prompt = (
        "Summarize the following security alert in one short paragraph and give a concise triage note:\n"
        "Event: sample Tier1 test\nDetails: This is a test to drive model loading and streaming behavior."
    )

    start = time.time()
    tried_urls = []
    for url in try_paths():
        tried_urls.append(url)

    print("Trying urls:")
    for u in tried_urls:
        print(" -", u)

    while True:
        elapsed = time.time() - start
        if elapsed > MAX_TOTAL_SECONDS:
            print(f"Exceeded max total wait {MAX_TOTAL_SECONDS}s, aborting")
            return 2

        for url in tried_urls:
            payload = build_payload(prompt)
            result = stream_request(url, payload, timeout=TIMEOUT)
            print("\nResult type:", type(result))
            if not result:
                print("No result (empty). Will retry after sleep.")
                time.sleep(RETRY_INTERVAL)
                continue

            # handle various response shapes
            if isinstance(result, dict):
                # Errors
                if result.get("error") or result.get("error_status"):
                    print("Error response:", result)
                    # If server indicates model loading behavior, keep waiting
                    if isinstance(result.get("error_body"), str) and "load" in result.get("error_body", ""):
                        print("Model appears to be loading based on error body. Retrying...")
                        time.sleep(RETRY_INTERVAL)
                        continue
                    # otherwise try next URL
                    continue

                # Ollama shape: {model, created_at, response, done, done_reason}
                if "response" in result:
                    resp_text = result.get("response") or ""
                    done_reason = result.get("done_reason")
                    if resp_text.strip():
                        print("Received non-empty response from Ollama")
                        save_success(result)
                        return 0
                    else:
                        print(f"Empty response; done_reason={done_reason}. Retrying...")
                        if done_reason == "load":
                            time.sleep(RETRY_INTERVAL)
                            continue
                        else:
                            time.sleep(RETRY_INTERVAL)
                            continue

                # OpenAI-like or prediction shapes
                if "choices" in result:
                    text = "".join(c.get("text", "") or c.get("message", {}).get("content", "") for c in result.get("choices", []))
                    if text.strip():
                        save_success({"model": MODEL, "response": text, "source": url})
                        return 0

                # If result contains 'outputs' array (some APIs)
                if "outputs" in result:
                    outs = result.get("outputs")
                    if isinstance(outs, list) and outs:
                        txt = "".join(o.get("content", "") if isinstance(o, dict) else str(o) for o in outs)
                        if txt.strip():
                            save_success({"model": MODEL, "response": txt, "source": url})
                            return 0

            # fallback wait
            time.sleep(RETRY_INTERVAL)

        # sleep before full cycle retry
        print(f"Cycle complete; sleeping {RETRY_INTERVAL}s before retrying")
        time.sleep(RETRY_INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
