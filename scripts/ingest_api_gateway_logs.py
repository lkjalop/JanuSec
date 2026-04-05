import json
import os
import sys
import urllib.request

from src.integrations.api_gateway_adapter import load_gateway_logs, normalize_gateway_batch


def _post_json(url: str, payload: dict, api_key: str | None) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("x-api-key", api_key)
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/ingest_api_gateway_logs.py <path> [base_url]")
        sys.exit(1)
    path = sys.argv[1]
    base_url = sys.argv[2] if len(sys.argv) > 2 else os.getenv("API_BASE_URL", "http://localhost:8080")
    api_key = os.getenv("API_KEY", "devkey123")
    records = load_gateway_logs(path)
    if not records:
        print("No gateway logs found.")
        sys.exit(1)
    normalized = normalize_gateway_batch(records)
    payload = {"events": normalized}
    url = base_url.rstrip("/") + "/api/v1/api_security/gateway_logs"
    out = _post_json(url, payload, api_key)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
