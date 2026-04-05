import requests, json, sys
host='http://127.0.0.1:11434'
print('Host:', host)
try:
    r = requests.get(f'{host}/', timeout=3)
    print('/ ->', r.status_code, repr(r.text[:200]))
except Exception as e:
    print('/ -> ERROR', type(e).__name__, e)

try:
    r = requests.get(f'{host}/api/version', timeout=3)
    print('/api/version ->', r.status_code, r.text)
except Exception as e:
    print('/api/version -> ERROR', type(e).__name__, e)

try:
    r = requests.get(f'{host}/v1/models', timeout=3)
    print('/v1/models ->', r.status_code)
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print('models body preview:', repr(r.text[:400]))
except Exception as e:
    print('/v1/models -> ERROR', type(e).__name__, e)

payload={'model':'llama3:8b','prompt':'Hello from diag','stream':False,'options':{'num_predict':32}}
# Try short POST
try:
    r = requests.post(f'{host}/api/generate', json=payload, timeout=5)
    print('/api/generate ->', r.status_code)
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print('body preview:', repr(r.text[:400]))
except Exception as e:
    print('/api/generate -> ERROR', type(e).__name__, e)

# Try POST to /v1/generate
try:
    r = requests.post(f'{host}/v1/generate', json=payload, timeout=5)
    print('/v1/generate ->', r.status_code)
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print('body preview:', repr(r.text[:400]))
except Exception as e:
    print('/v1/generate -> ERROR', type(e).__name__, e)

# If /api/version worked, print elapsed
sys.exit(0)
