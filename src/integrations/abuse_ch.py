from __future__ import annotations

import csv
import io
import os
import time
from typing import Dict, List


class AbuseCH:
    def __init__(self):
        self.enabled = os.getenv('ABUSECH_ENABLED','0').lower() in {'1','true','yes'}
        self.cache: Dict[str, List[Dict[str,str]]] = {'malware_urls': [], 'ts': 0}

    def refresh(self) -> int:
        if not self.enabled:
            return 0
        url = os.getenv('ABUSECH_MALWARE_URLS_CSV', 'https://urlhaus.abuse.ch/downloads/csv_recent/')
        try:
            import requests  # type: ignore
            resp = requests.get(url, timeout=20)
            if resp.status_code != 200:
                return 0
            text = resp.text
            # CSV contains comments starting with '#'
            lines = [ln for ln in text.splitlines() if ln and not ln.startswith('#')]
            buf = io.StringIO('\n'.join(lines))
            reader = csv.DictReader(buf)
            rows: List[Dict[str,str]] = []
            for i, row in enumerate(reader):
                rows.append({k: (row.get(k) or '') for k in reader.fieldnames or []})
                if i >= 20000:
                    break
            self.cache = {'malware_urls': rows, 'ts': time.time()}
            # Persist to disk
            path = os.getenv('ABUSECH_CACHE_PATH', os.path.join('data','ti','abusech_urls.json'))
            try:
                import json, pathlib
                pathlib.Path(os.path.dirname(path)).mkdir(parents=True, exist_ok=True)
                with open(path, 'w', encoding='utf-8') as fh:
                    json.dump(rows, fh)
            except Exception:
                pass
            return len(rows)
        except Exception:
            return 0


CLIENT = AbuseCH()
