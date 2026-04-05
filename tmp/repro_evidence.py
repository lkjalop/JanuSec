import os, time, sys
from importlib import reload
from pathlib import Path
# ensure repo root on path
p = Path(r'd:\AI\Threat_thy_sniffer\tmp')
sys.path.insert(0, r'd:\AI\Threat_thy_sniffer')
# simulate module imported earlier with defaults
import src.live.evidence_store as evidence_store
print('initial MAX_BYTES:', getattr(evidence_store, '_MAX_BYTES', None))
# now set env and reload to mimic test behavior
os.environ['EVIDENCE_FILE_PATH'] = r'd:\AI\Threat_thy_sniffer\tmp\evidence_test.jsonl'
os.environ['EVIDENCE_MAX_BYTES'] = '150'
reload(evidence_store)
print('reloaded MAX_BYTES:', getattr(evidence_store, '_MAX_BYTES', None))
for i in range(25):
    evidence_store.append({'event_id': f'id{i}','ts': time.time(), 'evidence': [{'score':i}]})
p = Path(r'd:\AI\Threat_thy_sniffer\tmp')
files = [str(x) for x in p.iterdir() if 'evidence_test' in x.name]
print('files:', files)
print('current size:', Path(r'd:\AI\Threat_thy_sniffer\tmp\evidence_test.jsonl').stat().st_size)
