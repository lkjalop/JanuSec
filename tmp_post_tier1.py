import os, requests, json
os.environ['FAST_TEST_MODE']='1'
url='http://127.0.0.1:8080/api/v1/llm/tier1/summarize'
payload={"decision_id":"test-dec-3","top_factors":[{"id":"fX","name":"weird_exec","contribution":0.85}],"related_events":[{"id":"evX","event_id":"evX","summary":"Weird exec seen"}]}
r=requests.post(url,json=payload,timeout=5)
print(r.status_code)
print(r.text)
