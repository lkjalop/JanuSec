import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import os
import asyncio

from src.soar.connectors import http_post


class HeaderCaptureHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # capture headers and echo them back
        headers = dict(self.headers)
        length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(length) if length else b''
        try:
            payload = json.loads(body.decode('utf-8'))
        except Exception:
            payload = {}
        resp = {'status': 'ok', 'headers': headers, 'payload': payload}
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode('utf-8'))


def run_server(server):
    try:
        server.serve_forever()
    except Exception:
        pass


def test_api_key_and_bearer_env():
    server = HTTPServer(('127.0.0.1', 0), HeaderCaptureHandler)
    port = server.server_address[1]
    thr = threading.Thread(target=run_server, args=(server,), daemon=True)
    thr.start()
    time.sleep(0.05)
    url = f'http://127.0.0.1:{port}/revoke'

    # test api_key in payload
    res = asyncio.get_event_loop().run_until_complete(http_post(url, {'action': 'x', 'api_key': 'secret123'}))
    assert res.get('status') == 'ok'

    # test bearer_env propagation
    os.environ['TEST_BEARER_TOKEN'] = 'tok-xyz'
    res2 = asyncio.get_event_loop().run_until_complete(http_post(url, {'action': 'x', 'bearer_env': 'TEST_BEARER_TOKEN'}))
    assert res2.get('status') == 'ok'

    server.shutdown()
