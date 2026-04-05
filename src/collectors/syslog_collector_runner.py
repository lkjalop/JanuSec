import asyncio
import os
import signal
import ssl
import logging
import structlog
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter
from aiohttp import web
from prometheus_client import start_http_server

from .syslog_collector import SyslogCollector

logging.basicConfig(level=logging.INFO)
structlog.configure(
    processors=[
        structlog.processors.KeyValueRenderer(key_order=["event", "ts"])
    ]
)

# initialize simple OpenTelemetry tracer (Console exporter for local debugging)
provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer(__name__)


async def _start_admin_server(redis_producer, host="127.0.0.1", port=9000):
    app = web.Application()

    async def _rate_limits(request):
        q = request.query.get("key")
        if not q:
            return web.json_response({"error": "missing key param"}, status=400)
        data = await redis_producer.get_token_bucket(q)
        return web.json_response({"key": q, "bucket": data})

    app.router.add_get("/admin/rate_limits", _rate_limits)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    return runner


async def _watch_and_reload_tls(collector: SyslogCollector, cert_path: str, key_path: str, interval: int = 5):
    last_cert_mtime = None
    last_key_mtime = None
    while True:
        try:
            cert_m = os.path.getmtime(cert_path)
            key_m = os.path.getmtime(key_path)
            if last_cert_mtime is None:
                last_cert_mtime = cert_m
                last_key_mtime = key_m
            elif cert_m != last_cert_mtime or key_m != last_key_mtime:
                # rebuild ssl context and restart TCP server with TLS
                ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
                await collector.stop()
                await collector.start(tls=True, tls_context=ctx)
                last_cert_mtime = cert_m
                last_key_mtime = key_m
        except Exception:
            pass
        await asyncio.sleep(interval)


async def main():
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    udp_port = int(os.environ.get("SYSLOG_UDP_PORT", "5140"))
    tcp_port = int(os.environ.get("SYSLOG_TCP_PORT", "5141"))
    device_map_path = os.environ.get("DEVICE_MAP_PATH")
    rate_limit_path = os.environ.get("RATE_LIMIT_CONFIG")
    cert_path = os.environ.get("TLS_CERT_PATH")
    key_path = os.environ.get("TLS_KEY_PATH")

    # start prometheus metrics endpoint
    start_http_server(8000)

    collector = SyslogCollector(redis_url=redis_url)
    if device_map_path:
        collector.load_device_map(device_map_path)
    if rate_limit_path:
        collector.load_rate_limit_config(rate_limit_path)

    tls_ctx = None
    if cert_path and key_path:
        try:
            tls_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            tls_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        except Exception:
            tls_ctx = None

    await collector.start(udp_port=udp_port, tcp_port=tcp_port, tls=bool(tls_ctx), tls_context=tls_ctx, device_map_path=device_map_path)

    # start admin http server
    admin_runner = await _start_admin_server(collector.redis)

    # optionally watch certs and reload
    watchers = []
    if cert_path and key_path:
        watchers.append(asyncio.create_task(_watch_and_reload_tls(collector, cert_path, key_path)))

    loop = asyncio.get_event_loop()

    stop = asyncio.Future()

    def _on_signal(*_):
        if not stop.done():
            stop.set_result(True)

    loop.add_signal_handler(signal.SIGINT, _on_signal)
    loop.add_signal_handler(signal.SIGTERM, _on_signal)

    await stop

    for w in watchers:
        w.cancel()

    await admin_runner.cleanup()
    await collector.stop()


if __name__ == "__main__":
    asyncio.run(main())
