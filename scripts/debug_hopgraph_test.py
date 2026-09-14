import os, sys
sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
import src.api.app as appmod
from src.graph.hopgraph import HopGraph
hg = HopGraph()
appmod.app.GLOBAL_HOPGRAPH = hg
client = TestClient(appmod.app)
# Post remote_access
ra = {'src_ip':'198.51.100.23','user':'finance','dest_host':'vpn.corp.example.com','protocol':'vpn','timestamp':'2025-11-04T10:00:00Z'}
r1 = client.post('/api/v1/remote_access/ingest', json=ra)
print('remote_access status', r1.status_code)
print('after remote_access nodes:', list(hg.nodes.keys()))
# Post email
p={'from':'ceo@paypa¶2.com','to':'finance@example.com','subject':'Urgent wire','raw':{'body':'Please click https://bit.ly/xyz'}}
r2 = client.post('/api/v1/email/ingest', json=p)
print('email status', r2.status_code)
print('email resp', r2.json())
print('after email nodes:', list(hg.nodes.keys()))
