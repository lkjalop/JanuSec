import urllib.request, json

sessions = ['758ebd2d97134dbfadd989e05f2d760e', 'sess-1775273340592']
headers = {'x-api-key': 'devkey123', 'X-Tenant-ID': 'default'}

for sess in sessions:
    url = f'http://localhost:8090/api/v1/report/ingestion?format=json&persona=executive&session_ids={sess}'
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read())
            alerts = len(d.get('flagged_events') or d.get('alerts') or [])
            print(f'Session {sess[:12]}: alerts={alerts}')
            print('  verdict_stats:', d.get('verdict_stats'))
            print('  tier1_summary:', str(d.get('tier1_summary') or d.get('llm_summary') or '')[:200])
            print('  top keys:', list(d.keys())[:15])
    except urllib.error.HTTPError as e:
        print(f'Session {sess[:12]}: HTTP {e.code}', e.read().decode()[:300])
    except Exception as ex:
        print(f'Session {sess[:12]}: ERROR {ex}')
