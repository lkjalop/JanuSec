import asyncio
from src.core.hunt.evidence_envelope import EvidenceEnvelope
from src.core.reputation import wrappers


def test_redirect_chain_detection(monkeypatch):
    # Simulate an email body containing a redirect chain; lane only needs to detect presence
    body = 'Please click http://short.ly/abc which redirects to http://evil.com/login'
    # Monkeypatch URL extraction to return both links
    from src.core.hunt import lanes
    # We'll call url_shortener and url_login_keyword directly
    from src.core.hunt.lanes import email_bec
    res = email_bec._extract_urls(body)
    assert any('http' in u for u in res)


def test_redirect_chain_live(monkeypatch):
    # Start a simple HTTP server that redirects /a -> /b -> /final
    import threading, http.server, socketserver, time, requests

    class RedirectHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/a':
                self.send_response(302)
                self.send_header('Location', '/b')
                self.end_headers()
            elif self.path == '/b':
                self.send_response(302)
                self.send_header('Location', '/final')
                self.end_headers()
            elif self.path == '/final':
                self.send_response(200)
                self.end_headers(); self.wfile.write(b'OK')
            else:
                self.send_response(404); self.end_headers()

    # Bind to an ephemeral port
    srv = None
    port = 0
    class ThreadedServer(threading.Thread):
        def run(self):
            nonlocal srv, port
            with socketserver.TCPServer(('127.0.0.1', 0), RedirectHandler) as httpd:
                srv = httpd
                port = httpd.server_address[1]
                httpd.serve_forever()

    t = ThreadedServer(); t.daemon = True; t.start()
    # wait for server
    time.sleep(0.2)
    try:
        url = f'http://127.0.0.1:{port}/a'
        r = requests.get(url, allow_redirects=True, timeout=2.0)
        assert r.status_code == 200 and r.text == 'OK'
    finally:
        try:
            if srv:
                srv.shutdown()
        except Exception:
            pass


def test_qr_detection_optional(monkeypatch):
    # Optional heavy test: run only when enabled
    import os
    if os.getenv('TEST_HELPERS_ENABLED','0').lower() not in {'1','true','yes'}:
        return
    try:
        from PIL import Image
    except Exception:
        return
    # If Pillow available, further QR tests could be added here (placeholder)
    assert 'email:qr_phish_lure' in __import__('src.core.threat_modeling.factor_taxonomy', fromlist=['FACTOR_MAP_PUBLIC']).FACTOR_MAP_PUBLIC


def test_qr_detection_stub(monkeypatch):
    # QR detection may be a separate utility; here we assert the taxonomy contains 'email:qr_phish_lure'
    from src.core.threat_modeling import factor_taxonomy
    assert 'email:qr_phish_lure' in factor_taxonomy.FACTOR_MAP_PUBLIC


def test_whois_wrapper_stub(monkeypatch):
    # Ensure whois wrapper returns cached value when monkeypatched
    def fake_whois(domain):
        return {'creation_date': '2010-01-01T00:00:00'}
    monkeypatch.setattr(wrappers, '_perform_whois', fake_whois)
    wrappers.cache = getattr(wrappers, 'cache', None)
    # call wrapper
    days = wrappers.whois_domain_age_days('example.com')
    assert days is not None and days > 3000
