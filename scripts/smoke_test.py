#!/usr/bin/env python3
import json
import time
from urllib import request, error


def get(url: str):
    try:
        with request.urlopen(url, timeout=5) as resp:
            body = resp.read()
            status = resp.status
            return status, body
    except Exception as e:
        return None, str(e).encode()


def main():
    base = "http://localhost:8080"
    # small wait in case server is still warming up
    time.sleep(1.0)
    results = {}
    for name, path in (
        ("health", "/api/v1/health"),
        ("supported_formats", "/api/v1/upload/supported-formats"),
        ("console", "/console"),
        ("docs", "/docs"),
    ):
        status, body = get(base + path)
        ok = status == 200
        # attempt to parse json when appropriate
        payload = None
        if ok and name in {"health", "supported_formats"}:
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                payload = None
        results[name] = {"status": status, "ok": ok, "sample": (body[:120].decode(errors="ignore") if isinstance(body, (bytes, bytearray)) else str(body))}
        if payload is not None:
            results[name]["json_keys"] = list(payload.keys())
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
