from pathlib import Path
p=Path('d:/AI/Threat_thy_sniffer/src/api/feedback_endpoints.py')
s=p.read_text()
for i,line in enumerate(s.splitlines(),1):
    print(f"{i:04}: {line}")
print('\nLEN', len(s.splitlines()))
