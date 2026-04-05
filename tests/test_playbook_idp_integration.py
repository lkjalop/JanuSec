import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import asyncio

from src.soar.connectors import http_post, get_registry


class SimpleHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('content-length', 0))
        data = self.rfile.read(length) if length else b''
        try:
            payload = json.loads(data.decode('utf-8'))
        except Exception:
            payload = {}
        # Simple check: if action is revoke_sessions return success
        resp = {'status': 'ok', 'received': payload}
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode('utf-8'))


def run_server(server):
    try:
        server.serve_forever()
    except Exception:
        pass


def test_http_idp_connector():
    server = HTTPServer(('127.0.0.1', 0), SimpleHandler)
    port = server.server_address[1]
    thr = threading.Thread(target=run_server, args=(server,), daemon=True)
    thr.start()
    time.sleep(0.05)

    url = f'http://127.0.0.1:{port}/revoke'
    # call http_post helper directly
    res = asyncio.get_event_loop().run_until_complete(http_post(url, {'action': 'revoke_sessions', 'user': 'bob'}))
    assert res.get('status') == 'ok'

    # test connector via registry
    reg = get_registry()
    async def call_connector():
        conn = reg.get('idp.revoke_sessions')
        out = await conn({'user': 'bob', 'api_url': url})
        return out

    out = asyncio.get_event_loop().run_until_complete(call_connector())
    assert out.get('status') == 'ok' or out.get('revoked') is True

    server.shutdown()
