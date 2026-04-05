"""Unified Run Script for JanuSec Platform

Provides a single entrypoint to:
 1. Launch the FastAPI service (normal or FAST_LIVE_MODE)
 2. Generate demo / synthetic events against the running server
 3. Run the audit runner after (or without) server startup
 4. Combined mode: start server, wait for readiness, feed events, run audit

Subcommands:
  server      Start only the API server
  demo        Generate demo events (requires an already running server)
  audit       Run scripts/audit_runner.py (best-effort)
  all         Start server -> feed demo events -> run audit (optional) -> stay running

Examples (PowerShell):
  python scripts/unified_run.py server --host 0.0.0.0 --port 8080 --fast-live
  python scripts/unified_run.py demo --count 200 --rate 40 --url http://localhost:8080
  python scripts/unified_run.py all --count 100 --fast-live --audit --metrics-url http://localhost:8080/metrics

Notes:
 - If uvicorn is not installed, will attempt to fallback to hypercorn or fail cleanly.
 - Demo generator uses only stdlib (http.client) unless 'requests' is installed.
 - Graceful shutdown via Ctrl+C.
"""
from __future__ import annotations
import argparse, os, sys, time, json, random, threading, signal
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

LOG_FORMAT = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"), format=LOG_FORMAT)
logger = logging.getLogger("unified")

ROOT = Path(__file__).resolve().parent.parent


def _import_app():
    """Import FastAPI app lazily to allow subcommands that don't need deps."""
    sys.path.insert(0, str(ROOT / 'src'))
    try:
        from api.server import app  # type: ignore
        return app
    except Exception as e:
        logger.error("Failed to import FastAPI app: %s", e)
        raise


def run_server(host: str, port: int, fast_live: bool, reload: bool):
    if fast_live:
        os.environ['FAST_LIVE_MODE'] = '1'
    app = _import_app()
    # Try uvicorn first
    try:
        import uvicorn  # type: ignore
        logger.info("Starting server via uvicorn (fast_live=%s) on %s:%d", fast_live, host, port)
        uvicorn.run(app, host=host, port=port, reload=reload, log_level="info")
        return
    except ImportError:
        logger.warning("uvicorn not installed; attempting hypercorn")
    except Exception as e:
        logger.error("uvicorn failed: %s", e)
    try:
        from hypercorn.asyncio import serve  # type: ignore
        from hypercorn.config import Config  # type: ignore
        import asyncio
        cfg = Config()
        cfg.bind = [f"{host}:{port}"]
        logger.info("Starting server via hypercorn (fast_live=%s) on %s:%d", fast_live, host, port)
        asyncio.run(serve(app, cfg))
    except ImportError:
        logger.error("Neither uvicorn nor hypercorn installed. Please install uvicorn.")
    except Exception as e:
        logger.error("hypercorn failed: %s", e)


def _http_post(url: str, payload: Dict[str, Any], timeout: float = 2.0) -> int:
    """Minimal POST helper using stdlib; returns status code or -1"""
    try:
        from urllib.parse import urlparse
        import http.client, ssl
        parsed = urlparse(url)
        conn_cls = http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection
        ctx = None
        if parsed.scheme == 'https':
            ctx = ssl.create_default_context()
        conn = conn_cls(parsed.hostname, parsed.port or (443 if parsed.scheme=='https' else 80), timeout=timeout, context=ctx)  # type: ignore[arg-type]
        path = parsed.path or '/'
        body = json.dumps(payload).encode('utf-8')
        conn.request('POST', path, body, headers={'Content-Type':'application/json'})
        resp = conn.getresponse()
        _ = resp.read()
        return resp.status
    except Exception:
        return -1


def generate_demo_events(count: int, rate: int, base_url: str, sources: Optional[List[str]] = None):
    if not sources:
        sources = ['api','sim','demo']
    ingest_url = base_url.rstrip('/') + '/api/v1/events'
    logger.info("Generating %d demo events -> %s (rate=%d/sec)", count, ingest_url, rate)
    interval = 1.0 / max(rate,1)
    sent = 0
    errors = 0
    start = time.time()
    while sent < count:
        ev_id = f"demo-{int(time.time()*1000)}-{sent}"
        payload = {
            'id': ev_id,
            'source': random.choice(sources),
            'severity': random.choice(['low','medium','high']),
            'event_type': random.choice(['proc','net','file','auth']),
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'details': {
                'cmd': random.choice(['whoami','curl example.com','powershell Invoke-WebRequest','/usr/bin/python script.py']),
                'user': random.choice(['svc_app','root','analyst','system']),
                'host': random.choice(['host1','host2','host3']),
            }
        }
        status = _http_post(ingest_url, payload)
        if status not in (200,202):
            errors += 1
        sent += 1
        # pace
        time.sleep(interval)
    dur = time.time() - start
    logger.info("Demo complete: sent=%d errors=%d duration=%.2fs eps=%.1f", sent, errors, dur, sent / max(dur,0.001))
    return {'sent': sent, 'errors': errors, 'duration_sec': dur}


def wait_ready(base_url: str, timeout: float = 20.0) -> bool:
    url = base_url.rstrip('/') + '/ready'
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _http_post(url.replace('/ready','/health'), {'ping':'pong'}) in (404,405):
            # server reachable (health is GET; POST returns 404/405) treat as up
            return True
        time.sleep(0.5)
    return False


def run_audit(metrics_url: Optional[str], strict: bool):
    cmd = [sys.executable, str(ROOT / 'scripts' / 'audit_runner.py'), '--output', 'audit_results.json']
    if metrics_url:
        cmd += ['--metrics-url', metrics_url]
    if strict:
        cmd += ['--strict']
    logger.info("Running audit runner: %s", ' '.join(cmd))
    import subprocess
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        logger.warning("Audit runner exited with code %s", proc.returncode)
    (ROOT / 'audit_runner_stdout.log').write_text(proc.stdout + '\n' + proc.stderr, encoding='utf-8')
    logger.info("Audit runner finished (stdout+stderr captured)")


def _thread(target, *a, **k):
    t = threading.Thread(target=target, args=a, kwargs=k, daemon=True)
    t.start()
    return t


def handle_all(args):
    # Start server in background thread
    def _serve():
        run_server(args.host, args.port, args.fast_live, args.reload)
    _thread(_serve)
    base_url = f"http://{args.host}:{args.port}"
    if not wait_ready(base_url, timeout=30):
        logger.error("Server did not become ready; aborting")
        return 2
    logger.info("Server is up")
    if args.count > 0:
        generate_demo_events(args.count, args.rate, base_url)
    if args.audit:
        run_audit(base_url + '/metrics', strict=args.strict)
    logger.info("All mode running. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    return 0


def parse_args():
    ap = argparse.ArgumentParser(description="Unified run / dev harness")
    sub = ap.add_subparsers(dest='cmd', required=True)

    ap_server = sub.add_parser('server', help='Run only the API server')
    ap_server.add_argument('--host', default='127.0.0.1')
    ap_server.add_argument('--port', type=int, default=8080)
    ap_server.add_argument('--fast-live', action='store_true', help='Enable FAST_LIVE_MODE lighter startup')
    ap_server.add_argument('--reload', action='store_true', help='Enable auto-reload (uvicorn only)')

    ap_demo = sub.add_parser('demo', help='Generate demo events against existing server')
    ap_demo.add_argument('--url', default='http://127.0.0.1:8080')
    ap_demo.add_argument('--count', type=int, default=50)
    ap_demo.add_argument('--rate', type=int, default=25, help='Events per second target')

    ap_audit = sub.add_parser('audit', help='Run audit runner only')
    ap_audit.add_argument('--metrics-url', help='Metrics endpoint for reachability')
    ap_audit.add_argument('--strict', action='store_true')

    ap_all = sub.add_parser('all', help='Server + demo + optional audit (stays running)')
    ap_all.add_argument('--host', default='127.0.0.1')
    ap_all.add_argument('--port', type=int, default=8080)
    ap_all.add_argument('--fast-live', action='store_true')
    ap_all.add_argument('--reload', action='store_true')
    ap_all.add_argument('--count', type=int, default=100)
    ap_all.add_argument('--rate', type=int, default=40)
    ap_all.add_argument('--audit', action='store_true', help='Run audit after feeding demo events')
    ap_all.add_argument('--strict', action='store_true', help='Strict audit mode')

    return ap.parse_args()


def main():
    args = parse_args()
    if args.cmd == 'server':
        run_server(args.host, args.port, args.fast_live, args.reload)
    elif args.cmd == 'demo':
        generate_demo_events(args.count, args.rate, args.url)
    elif args.cmd == 'audit':
        run_audit(args.metrics_url, strict=args.strict)
    elif args.cmd == 'all':
        code = handle_all(args)
        if code:
            sys.exit(code)
    else:  # pragma: no cover - defensive
        print('Unknown command')
        sys.exit(2)


if __name__ == '__main__':
    # Allow clean Ctrl+C on Windows
    try:
        signal.signal(signal.SIGINT, lambda s,f: sys.exit(0))
    except Exception:
        pass
    main()
