import sys, os
sys.path.insert(0, 'd:/AI/Threat_thy_sniffer')
from src.analysis.playbook_db import get_playbook_for_mitre, list_mitre_ids
from src.api.evidence_provenance import sign_evidence_metadata
print('Known MITRE IDs:', list_mitre_ids())
print('T1059.001 playbook excerpt:', get_playbook_for_mitre('T1059.001').get('playbook',{}).get('required_logs'))
# create sample file
p = 'tmp_sample_evidence.bin'
with open(p,'wb') as fh:
    fh.write(b'hello-evidence')
meta = sign_evidence_metadata(p, 'analyst@example.com', 'manual_upload', 'TICKET-123')
print('Signed metadata keys:', list(meta.keys()))
print('Meta path exists?', os.path.exists(p + '.meta.json'))
