"""
Simple migration script to inject notifications.js include into frontend static HTML pages
that reference user-facing flows but don't include the notifications helper.

Usage: python scripts/migrate_add_notifications.py
It will scan frontend/static/*.html and insert a script tag before the closing </body>
if the file doesn't already include /static/js/notifications.js
"""
import glob
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAT = ROOT / 'frontend' / 'static' / '*.html'

INCLUDE = '<script src="/static/js/notifications.js"></script>'

if __name__ == '__main__':
    changed = []
    for p in glob.glob(str(PAT)):
        fp = Path(p)
        txt = fp.read_text(encoding='utf-8')
        if '/static/js/notifications.js' in txt:
            continue
        # insert before closing </body>
        if '</body>' in txt:
            new = txt.replace('</body>', f'  {INCLUDE}\n</body>')
            fp.write_text(new, encoding='utf-8')
            changed.append(fp.name)
    if changed:
        print('Injected notifications include into:', ', '.join(changed))
    else:
        print('No files changed; all static pages already include notifications.js or had no </body> tag.')
