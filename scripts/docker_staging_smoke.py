from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def _docker_exec_request(method: str, path: str, headers: dict[str, str], payload: dict | None = None) -> str:
    cmd = ["docker", "compose", "exec", "-T", "app", "curl", "-fsS", "-X", method]
    for key, value in headers.items():
        cmd.extend(["-H", f"{key}: {value}"])
    if payload is not None:
        cmd.extend(["-d", json.dumps(payload)])
    cmd.append(f"http://127.0.0.1:8080{path}")
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout


def _headers(api_key: str, tenant_id: str) -> dict[str, str]:
    return {
        "x-api-key": api_key,
        "X-Tenant-ID": tenant_id,
        "Content-Type": "application/json",
    }


def _request_json(method: str, url: str, headers: dict[str, str], payload: dict | None = None, timeout: float = 15.0, transport: str = "docker-exec"):
    if transport == "docker-exec":
        parsed = urllib.parse.urlparse(url)
        body = _docker_exec_request(method, parsed.path + (f"?{parsed.query}" if parsed.query else ""), headers, payload)
        return json.loads(body) if body else {}
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}


def _request_text(method: str, url: str, headers: dict[str, str], payload: dict | None = None, timeout: float = 20.0, transport: str = "docker-exec") -> str:
    if transport == "docker-exec":
        parsed = urllib.parse.urlparse(url)
        return _docker_exec_request(method, parsed.path + (f"?{parsed.query}" if parsed.query else ""), headers, payload)
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def _wait_ready(base_url: str, timeout: float, transport: str = "docker-exec") -> dict:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            payload = _request_json("GET", f"{base_url}/ready", {}, timeout=5, transport=transport)
            if payload.get("status") == "ready":
                return payload
            last_error = payload
        except Exception as exc:
            last_error = str(exc)
        time.sleep(2)
    raise RuntimeError(f"/ready did not become healthy: {last_error}")


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _run_compose_recreate() -> None:
    subprocess.run(["docker", "compose", "up", "-d", "--force-recreate", "app", "worker"], check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test truthful staging Docker stack")
    parser.add_argument("--base-url", default=os.getenv("JANUSEC_BASE_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--api-key", default=os.getenv("JANUSEC_API_KEY") or os.getenv("API_KEY") or "janusec-staging-local-20260324")
    parser.add_argument("--tenant-id", default=os.getenv("JANUSEC_TENANT_ID", "default"))
    parser.add_argument("--recreate", action="store_true")
    parser.add_argument("--transport", choices=("docker-exec", "host"), default=os.getenv("JANUSEC_SMOKE_TRANSPORT", "docker-exec"))
    parser.add_argument("--ready-timeout", type=float, default=90.0)
    args = parser.parse_args()

    headers = _headers(args.api_key, args.tenant_id)
    ready = _wait_ready(args.base_url, args.ready_timeout, transport=args.transport)
    _assert(ready.get("database", {}).get("connected") is True, "database not connected")
    _assert(ready.get("redis", {}).get("connected") is True, "redis not connected")
    _assert(ready.get("worker", {}).get("connected") is True, "worker not connected")

    llm_health = _request_json("GET", f"{args.base_url}/api/v1/llm/health", headers, transport=args.transport)
    _assert(llm_health.get("provider") in {"ollama", "openai", "anthropic", "local-deterministic", "unavailable"}, "missing llm provider")
    _assert(llm_health.get("fallback_active") is False, "llm fallback unexpectedly active")

    tier2_body = {
        "assessment_id": f"smoke-{int(time.time())}",
        "org": args.tenant_id,
        "rows": [
            {
                "host": "wkstn-01",
                "user": "alice",
                "process_name": "powershell.exe",
                "command_line": "powershell -enc SQBFAFgA",
                "src_ip": "10.0.0.10",
                "dst_ip": "8.8.8.8"
            }
        ]
    }
    sse_text = _request_text("POST", f"{args.base_url}/api/v1/csv/tier2_sse", headers, tier2_body, timeout=30.0, transport=args.transport)
    _assert("data:" in sse_text, "tier2 SSE did not stream any frames")
    _assert('"provider": "ollama"' in sse_text or '"provider":"ollama"' in sse_text, "tier2 SSE not using ollama")

    session_payload = {
        "session_ids": ["smoke-a", "smoke-b"],
        "sessions": [
            {"id": "smoke-a", "data": [{"user": "alice", "host": "wkstn-01", "sha256": "a" * 64, "domain": "example.com"}]},
            {"id": "smoke-b", "data": [{"user": "alice", "host": "wkstn-02", "sha256": "a" * 64, "domain": "example.com"}]}
        ],
        "correlate": True,
        "ewma": True,
        "mapping": {"user": "user", "host": "host", "sha256": "file_hash", "domain": "domain"}
    }
    build = _request_json("POST", f"{args.base_url}/api/v1/graph/session/build", headers, session_payload, timeout=30.0, transport=args.transport)
    session_id = build.get("session_id")
    _assert(bool(session_id), "graph build did not return session_id")
    _assert(bool(build.get("graph_snapshot_ref")), "graph build did not return graph_snapshot_ref")
    _assert(bool(build.get("status")), "graph build did not return persistence status")

    load = _request_json("GET", f"{args.base_url}/api/v1/graph/session/{urllib.parse.quote(session_id)}", headers, transport=args.transport)
    paths = _request_json("GET", f"{args.base_url}/api/v1/graph/session/{urllib.parse.quote(session_id)}/paths", headers, transport=args.transport)
    replay = _request_json("POST", f"{args.base_url}/api/v1/graph/session/{urllib.parse.quote(session_id)}/replay", headers, {}, transport=args.transport)
    _assert(load.get("session_id") == session_id, "graph load mismatch")
    _assert(paths.get("session_id") == session_id, "graph paths mismatch")
    _assert(replay.get("session_id") == session_id, "graph replay mismatch")

    if args.recreate:
        _run_compose_recreate()
        _wait_ready(args.base_url, args.ready_timeout, transport=args.transport)
        replayed = _request_json("GET", f"{args.base_url}/api/v1/graph/session/{urllib.parse.quote(session_id)}", headers, transport=args.transport)
        _assert(replayed.get("session_id") == session_id, "graph session missing after recreate")

    print(json.dumps({
        "ready": ready,
        "llm_health": llm_health,
        "graph_session_id": session_id,
        "graph_snapshot_ref": build.get("graph_snapshot_ref"),
        "recreate_checked": bool(args.recreate)
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError, urllib.error.URLError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
