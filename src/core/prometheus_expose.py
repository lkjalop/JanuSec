"""Small helper to expose Prometheus metrics via WSGI for simple servers.

Usage (WSGI):
    from prometheus_client import make_wsgi_app
    app.mount('/metrics', make_wsgi_app())

If your app is FastAPI you can use the Prometheus ASGI middleware or expose
an endpoint that returns `generate_latest()`.
"""
try:
    from prometheus_client import make_wsgi_app
    PROM_AVAILABLE = True
except Exception:
    make_wsgi_app = None
    PROM_AVAILABLE = False


def get_metrics_wsgi_app():
    if not PROM_AVAILABLE:
        raise RuntimeError('prometheus_client not available')
    return make_wsgi_app()
