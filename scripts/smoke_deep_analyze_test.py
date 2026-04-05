import requests, json, os

API = os.getenv('API_URL', 'http://127.0.0.1:8080')
KEY = os.getenv('API_KEY', 'devkey123')
url = API + '/api/v1/assessments/deep_analyze'
headers = {'Content-Type':'application/json','x-api-key':KEY}
payload = {
    'rows': [ { 'row_index': 0, 'raw': {'process_name':'rundll32','file_path':'C:\\Windows\\System32\\rundll32.exe','sha256':'deadbeef','host':'host1'} } ],
    'options': {'auto_llm': True},
    'org': 'local'
}
print('Posting to', url)
resp = requests.post(url, headers=headers, data=json.dumps(payload))
print('Status', resp.status_code)
try:
    print(json.dumps(resp.json(), indent=2))
except Exception:
    print(resp.text)
