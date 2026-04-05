"""Compact / VACUUM hopgraph sqlite DB file.
Usage: python scripts/compact_hopgraph_db.py ./data/test_hopgraph.db
"""
import sqlite3
import sys

def main():
    if len(sys.argv) < 2:
        print('Usage: python compact_hopgraph_db.py <path-to-db>')
        return
    path = sys.argv[1]
    conn = sqlite3.connect(path)
    try:
        conn.execute('VACUUM')
        conn.commit()
        print('VACUUM completed')
    finally:
        conn.close()

if __name__ == '__main__':
    main()
