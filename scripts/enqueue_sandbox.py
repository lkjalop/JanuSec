"""Enqueue a file for static analysis / sandbox processing.

Usage: python -m scripts.enqueue_sandbox <file_path>
"""
import sys
import json
import time
import uuid
import os

def enqueue(path: str, db_path: str = 'data/app.db'):
    import sqlite3
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, 'rb') as fh:
        b = fh.read()
    payload = {'filename': os.path.basename(path), 'size': len(b)}
    payload_json = json.dumps(payload)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS sandbox_queue (id TEXT PRIMARY KEY, created_ts INTEGER, payload_json TEXT, status TEXT DEFAULT "pending")')
    id = str(uuid.uuid4())
    cur.execute('INSERT INTO sandbox_queue(id,created_ts,payload_json,status) VALUES (?,?,?,?)', (id, int(time.time()), payload_json, 'pending'))
    conn.commit(); conn.close()
    print('enqueued', id)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: enqueue_sandbox.py <file>')
        sys.exit(2)
    enqueue(sys.argv[1])
