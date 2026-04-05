from src.api.app import create_app
from fastapi.testclient import TestClient
app = create_app()
# show matching routes info
matches = [r for r in app.router.routes if getattr(r,'path',None) in ('/api/v1/playbook/reload','/api/v1/playbook/{mitre_id}', '/api/v1/playbook/TTEST')]
for r in matches:
    try:
        print('PATH:', r.path, 'METHODS:', getattr(r,'methods',None), 'ENDPOINT:', getattr(r,'endpoint',None))
    except Exception as e:
        print('ERR', e)
client = TestClient(app)
resp_get = client.get('/api/v1/playbook/TTEST')
print('GET /api/v1/playbook/TTEST:', resp_get.status_code, resp_get.text)
resp_post = client.post('/api/v1/playbook/reload')
print('POST /api/v1/playbook/reload:', resp_post.status_code, resp_post.text)
