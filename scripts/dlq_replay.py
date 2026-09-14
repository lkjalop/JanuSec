import os
import json
import sys
import requests

API_BASE = os.getenv('PLATFORM_API_BASE', 'http://localhost:8080')
API_KEY = os.getenv('PLATFORM_API_KEY', os.getenv('AZURE_DEF_SCHED_API_KEY', 'devkey123'))
TENANT_ID = os.getenv('TENANT_ID')
DLQ_PATH = os.getenv('DLQ_PATH', os.path.join(os.getcwd(), 'artifacts', 'dlq', 'azure_defender.jsonl'))


def replay(path: str):
    items = []
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    items.append(obj)
            except Exception:
                continue
    if not items:
        print('No items to replay')
        return
    payload = {'findings': []}
    # Assume items are raw defender events; normalize lightly here if needed
    for it in items:
        # pass through if already normalized
        if all(k in it for k in ('id','type','resource','severity')):
            payload['findings'].append(it)
        else:
            from azure.functions.defender_eventhub.mapper import normalize_defender_event  # type: ignore
            payload['findings'].append(normalize_defender_event(it))
    url = f"{API_BASE.rstrip('/')}/api/v1/compliance/posture"
    headers = {'x-api-key': API_KEY, 'Content-Type': 'application/json'}
    if TENANT_ID:
        headers['X-Tenant-ID'] = TENANT_ID
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    r.raise_for_status()
    print(f"Replayed {len(payload['findings'])} items")


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else DLQ_PATH
    replay(path)
