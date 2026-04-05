#!/usr/bin/env python3
"""POST a sample analyze_row payload to the running API and print the JSON response.
Uses only Python stdlib so it works in the venv without extra deps.
"""
import json
import urllib.request
import urllib.error

URL = "http://127.0.0.1:8080/api/v1/csv/analyze_row"
payload = {
    "row": {
        "process_name": "powershell.exe",
        "file_path": "C:\\Users\\Alice\\AppData\\Local\\Temp\\mal.ps1",
        "hash": "0000deadbeefcafebabe",
        "command_line": "powershell -e SGVsbG8=",
        "user": "alice",
        "host": "host-alice",
        "factors": ["powershell_execution", "encoded_command", "temp_directory_execution"],
        "verdict": "MALICIOUS",
        "confidence": 0.7
    },
    "options": {"threshold": 0.5}
}

data = json.dumps(payload).encode('utf-8')
req = urllib.request.Request(URL, data=data, headers={'Content-Type': 'application/json'})

try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode('utf-8', errors='replace')
        try:
            parsed = json.loads(body)
            print(json.dumps(parsed, indent=2))
        except Exception:
            print(body)
except urllib.error.HTTPError as e:
    print(f"HTTP Error: {e.code} {e.reason}")
    try:
        print(e.read().decode('utf-8', errors='replace'))
    except Exception:
        pass
except Exception as e:
    print(f"Request failed: {e}")
