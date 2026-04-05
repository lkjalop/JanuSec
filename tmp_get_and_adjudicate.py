import requestsimport requests







    print('adjudicated',cid, r.status_code, r.text)    r = requests.post(f'http://127.0.0.1:8080/api/v1/llm/tier1/claims/{cid}/adjudicate', json={'is_correct': True}, timeout=5)    cid = pending['pending'][0]['id']if pending.get('pending'):print('pending_count=', len(pending.get('pending',[])))pending = requests.get('http://127.0.0.1:8080/api/v1/llm/tier1/claims/pending',timeout=5).json()pending = requests.get('http://127.0.0.1:8080/api/v1/llm/tier1/claims/pending',timeout=5).json()
print('pending_count=', len(pending.get('pending',[])))
if pending.get('pending'):
    cid = pending['pending'][0]['id']
    r = requests.post(f'http://127.0.0.1:8080/api/v1/llm/tier1/claims/{cid}/adjudicate', json={'is_correct': True}, timeout=5)
    print('adjudicated',cid, r.status_code, r.text)
