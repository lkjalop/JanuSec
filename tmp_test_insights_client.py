from fastapi.testclient import TestClient
from src.api.app import app
import json

client = TestClient(app)

def post_tier1():
    url = '/api/v1/insights/generate'
    payload = {
        'insight_type':'tier1',
        'row':{
            'process_name':'bad.exe',
            'host':'host-01',
            'verdict':'suspicious',
            'factors':['process_injection','unsigned_binary'],
            'row_index': 5
        },
        'pipeline_context':{
            'request_id':'test-tier1-004',
            'overrides':{
                'ollama_host':'http://127.0.0.1:11434',
                'ollama_model':'llama3:8b',
                'ollama_generate_path':'/api/generate'
            }
        }
    }
    r = client.post(url, json=payload, headers={'x-api-key':'devkey123'})
    print('Tier1 status', r.status_code)
    print(json.dumps(r.json(), indent=2))


def post_tier2():
    url = '/api/v1/insights/generate'
    payload = {
        'insight_type':'tier2',
        'row':{
            'process_name':'weird.exe',
            'host':'host-02',
            'verdict':'unknown',
            'factors':['suspicious_network'],
            'row_index': 6
        },
        'pipeline_context':{
            'request_id':'test-tier2-004',
            'overrides':{
                'ollama_host':'http://127.0.0.1:11434',
                'ollama_model':'llama3:8b',
                'ollama_generate_path':'/api/generate'
            }
        }
    }
    r = client.post(url, json=payload, headers={'x-api-key':'devkey123'})
    print('Tier2 status', r.status_code)
    print(json.dumps(r.json(), indent=2))

if __name__ == '__main__':
    post_tier1()
    post_tier2()
