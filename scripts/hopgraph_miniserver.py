"""Minimal HTTP server using builtin http.server to expose snapshot/restore.

This avoids FastAPI/uvicorn/pydantic startup overhead for quick process-level tests.
"""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import sys


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        data = json.dumps(obj).encode('utf8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length else b''
        try:
            data = json.loads(body.decode('utf8')) if body else {}
        except Exception:
            data = {}
        try:
            # import here to pick up env settings in the subprocess
            from src.core.graph import hopgraph_lite
            g = hopgraph_lite.get_graph()
        except Exception as e:
            self._send_json({'error': 'hopgraph_import_failed', 'detail': str(e)}, code=500)
            return

        if parsed.path in ('/snapshot', '/api/v1/hopgraph/snapshot'):
            try:
                if getattr(g, 'backend', None):
                    snap = g.backend.load_graph()
                else:
                    snap = {'nodes': {}, 'edges': []}
                self._send_json({'ok': True, 'snapshot': snap}, code=200)
                return
            if parsed.path in ('/observe', '/api/v1/hopgraph/observe'):
                try:
                    # Expect JSON event in body
                    ev = data or {}
                    g.observe(ev)
                    self._send_json({'ok': True}, code=200)
                    return
                except Exception as e:
                    self._send_json({'error': 'observe_failed', 'detail': str(e)}, code=500)
                    return
            except Exception as e:
                self._send_json({'error': 'snapshot_failed', 'detail': str(e)}, code=500)
                return
        if parsed.path in ('/restore', '/api/v1/hopgraph/restore'):
            try:
                snap = data.get('snapshot') or data
                if getattr(g, 'backend', None):
                    be = g.backend
                    for nid, n in (snap.get('nodes') or {}).items():
                        be.save_node(nid, n.get('type', 'unknown'), n.get('metadata', {}))
                    for e in snap.get('edges', []):
                        be.save_edge(e.get('src'), e.get('dst'), e.get('etype', 'link'), e.get('weight', 1.0), e.get('metadata', {}))
                    self._send_json({'ok': True}, code=200)
                    return
                else:
                    self._send_json({'error': 'no_backend'}, code=500)
                    return
            except Exception as e:
                self._send_json({'error': 'restore_failed', 'detail': str(e)}, code=500)
                return

        self._send_json({'error': 'not_found'}, code=404)


def run(port: int = 8082):
    server = HTTPServer(('0.0.0.0', port), Handler)
    print(f'Starting hopgraph_miniserver on port {port}', file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--port', type=int, default=8082)
    args = p.parse_args()
    run(args.port)
