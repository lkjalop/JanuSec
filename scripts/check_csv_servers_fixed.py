import urllib.request, re

def fetch(u):
    try:
        req = urllib.request.Request(u, headers={'User-Agent':'cli-check/1.0','Accept':'text/html'})
        with urllib.request.urlopen(req, timeout=5) as r:
            ct = r.headers.get('Content-Type')
            body = r.read().decode('utf-8', errors='replace')
            count = len(re.findall('<!DOCTYPE', body, flags=re.IGNORECASE))
            preview = body[:400]
            print(f"URL: {u}")
            print(f"Status: {r.status}")
            print(f"Content-Type: {ct}")
            print(f"Length: {len(body)}")
            print(f"<!DOCTYPE count: {count}")
            print('Preview:')
            print(preview)
            print('-'*60)
    except Exception as e:
        print(f"URL: {u} ERROR: {e}")

if __name__ == '__main__':
    urls = [
        'http://127.0.0.1:8080/static/csv_analyzer.html',
        'http://localhost:9090/csv_analyzer.html'
    ]
    for u in urls:
        fetch(u)
