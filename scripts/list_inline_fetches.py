from pathlib import Path
import re
p = Path('frontend/static')
pat = re.compile(r"\bfetch\s*\(")
for f in p.glob('*.html'):
    s=f.read_text(encoding='utf-8')
    for i,line in enumerate(s.splitlines(),1):
        if pat.search(line):
            print(f"{f.name}:{i}: {line.strip()}")
