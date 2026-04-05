import sys, time, os, json
sys.path.insert(0, r'd:\AI\Threat_thy_sniffer')
from src.pipeline.deep_analyze_pipeline import DEFAULT_WORKER
session_id='test-session-debug'
payload={'assessment_id':'assessment-debug-001','org':'unittest','rows':[{'process_name':'a','sha256':'00'*32}],'options':{'auto_llm':True}}
print('starting session')
DEFAULT_WORKER.start_session(session_id, payload)
for i in range(60):
    s=DEFAULT_WORKER.status(session_id)
    print(i, s.get('status') if s else None)
    if s and s.get('status') in ('completed','failed'):
        break
    time.sleep(0.1)
print('final status:', DEFAULT_WORKER.status(session_id))
base=os.environ.get('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(),'data','assessments')
print('base:', base)
datepart=time.strftime('%Y-%m-%d', time.gmtime(time.time()))
path=os.path.join(base,'unittest',datepart,'assessment-debug-001.json')
print('expected path:', path)
print('exists:', os.path.exists(path))
if os.path.exists(path):
    print('file content:', open(path).read())
else:
    for root,dirs,files in os.walk(base):
        print('walk root:', root)
        print('dirs:', dirs)
        print('files:', files)
