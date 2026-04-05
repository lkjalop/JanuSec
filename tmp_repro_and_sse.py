# Repro loop: call /api/v1/decisions/recent with tenant variations and fetch /api/v1/debug/last-errors
# Then open SSE connection to /api/v1/decisions/stream and post seed to verify events
import requests
import time
import threading

BASE = 'http://localhost:8080'
HEADERS = {'x-api-key': 'devkey123'}


def call_recent(tenant=None):
    url = BASE + '/api/v1/decisions/recent'
    headers = dict(HEADERS)
    if tenant:
        headers['X-Tenant-ID'] = tenant
    try:
        r = requests.get(url, headers=headers, timeout=5)
        print(f'GET /decisions/recent tenant={tenant} ->', r.status_code)
    except Exception as e:
        print('GET /decisions/recent EXC', e)


def fetch_errors():
    try:
        r = requests.get(BASE + '/api/v1/debug/last-errors', headers=HEADERS, timeout=5)
        print('DEBUG LAST-ERRORS', r.status_code)
        print(r.text)
    except Exception as e:
        print('DEBUG LAST-ERRORS EXC', e)


# SSE reader

def sse_reader(stop_event, out_list):
    import sseclient
    try:
        url = BASE + '/api/v1/decisions/stream'
        resp = requests.get(url, headers=HEADERS, stream=True, timeout=10)
        client = sseclient.SSEClient(resp)
        for ev in client.events():
            print('SSE event:', ev.event, ev.data)
            out_list.append((ev.event, ev.data))
            if stop_event.is_set():
                break
    except Exception as e:
        print('SSE reader exception', e)


if __name__ == '__main__':
    # 1. Repro loop: perform multiple GETs with/without tenant header
    for i in range(5):
        call_recent(None)
        call_recent('demo')
        call_recent('tenant-A')
        time.sleep(0.5)

    # fetch diagnostics
    fetch_errors()

    # 2. SSE verification: start reader thread
    stop_ev = threading.Event()
    events = []
    try:
        import sseclient
    except Exception:
        print('sseclient not installed; skipping SSE test')
        sse_ok = False
    else:
        t = threading.Thread(target=sse_reader, args=(stop_ev, events), daemon=True)
        t.start()
        # give it a moment to connect
        time.sleep(1)
        # post a seed
        try:
            payload = {"count": 2, "prefix": "seed", "tenant_id": "demo"}
            r = requests.post(BASE + '/api/v1/dev/seed_decisions', json=payload, headers=HEADERS, timeout=5)
            print('POST seed ->', r.status_code)
            print(r.text)
        except Exception as e:
            print('POST seed EXC', e)
        # wait a bit to capture SSEs
        time.sleep(3)
        stop_ev.set()
        time.sleep(0.5)
        print('Captured SSE events:', events)

    # 3. final diagnostics
    fetch_errors()
