import os
import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.incidents.aggregator import GLOBAL_INCIDENTS

client = TestClient(app)

def test_incident_recommendation_toggle():
    os.environ['ALLOW_DEV_API_KEY'] = '1'
    headers = {'x-api-key':'devkey123'}
    # Seed an incident with a recommendation action
    inc_id = 'inc-test-1'
    GLOBAL_INCIDENTS.incidents[inc_id] = {
        'id': inc_id,
        'factors': ['auth_failed'],
        'recommendation_actions': {
            'network|block_ip': {
                'id':'network|block_ip','domain':'network','action':'block_ip','status':'pending','updated_ts':0
            }
        }
    }
    r = client.post(f'/api/v1/incidents/{inc_id}/recommendations/act', json={'action_id':'network|block_ip','status':'completed'}, headers=headers)
    assert r.status_code == 200
    j = r.json()
    assert j['action']['status'] == 'completed'
