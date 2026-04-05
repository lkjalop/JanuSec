"""
Simple local telemetry collector for Batch 3 development.
Run with: python scripts/telemetry_collector.py
Receives POSTs to /telemetry/ingest and logs to stdout.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from urllib.parse import urlparse

# in-memory latest payload (helps tests regardless of working directory)
LAST_PAYLOAD = None

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/telemetry/ingest':
            self.send_response(404); self.end_headers(); return
        length = int(self.headers.get('content-length',0))
        data = self.rfile.read(length) if length else b''
        try:
            j = json.loads(data.decode('utf-8'))
        except Exception as e:
            j = data.decode('utf-8')
        print('TELEMETRY INGEST:', j)
        global LAST_PAYLOAD
        LAST_PAYLOAD = j
        # persist to data/telemetry.log for offline inspection
        try:
            os.makedirs('data', exist_ok=True)
            with open(os.path.join('data','telemetry.log'), 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(j, ensure_ascii=False) + '\n')
            # also write latest for quick GET read
            with open(os.path.join('data','telemetry.latest.json'), 'w', encoding='utf-8') as fh2:
                json.dump(j, fh2, ensure_ascii=False)
        except Exception:
            pass
        # respond with CORS so browser-based fetches succeed
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Methods','POST,GET,OPTIONS')
        self.send_header('Access-Control-Allow-Headers','Content-Type')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/telemetry/latest':
            # prefer in-memory payload if available
            try:
                global LAST_PAYLOAD
                if LAST_PAYLOAD is not None:
                    body = json.dumps(LAST_PAYLOAD, ensure_ascii=False)
                    self.send_response(200)
                    self.send_header('Content-Type','application/json')
                    self.send_header('Access-Control-Allow-Origin','*')
                    self.end_headers()
                    self.wfile.write(body.encode('utf-8'))
                    return
                # fallback to persisted file
                with open(os.path.join('data','telemetry.latest.json'), 'r', encoding='utf-8') as fh:
                    body = fh.read()
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Access-Control-Allow-Origin','*')
                self.end_headers()
                self.wfile.write(body.encode('utf-8'))
                return
            except Exception:
                self.send_response(404); self.end_headers(); return
        self.send_response(404); self.end_headers();

    def do_OPTIONS(self):
        # Reply to preflight CORS requests
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Methods','POST,GET,OPTIONS')
        self.send_header('Access-Control-Allow-Headers','Content-Type')
        self.end_headers()

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 5001), Handler)
    print('Telemetry collector listening on http://0.0.0.0:5001')
    server.serve_forever()
