"""Migration helper: export approval_events and approvals from SQLite to a SQL file
that can be loaded into Postgres. This script is a helper and operators should
review the output before applying to production Postgres.
"""
import sqlite3
import os
import json
import argparse


def dump_sqlite(sqlite_path, out_sql):
    conn = sqlite3.connect(sqlite_path)
    cur = conn.cursor()
    tables = ['approval_events', 'approvals', 'approval_policies']
    with open(out_sql, 'w', encoding='utf-8') as fh:
        for t in tables:
            try:
                rows = cur.execute(f'SELECT * FROM {t}').fetchall()
            except Exception:
                continue
            for r in rows:
                vals = []
                for v in r:
                    if v is None:
                        vals.append('NULL')
                    else:
                        vals.append("'" + str(v).replace("'", "''") + "'")
                fh.write(f'INSERT INTO {t} VALUES ({",".join(vals)});\n')
    conn.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('sqlite')
    p.add_argument('--out', default='approvals_dump.sql')
    args = p.parse_args()
    dump_sqlite(args.sqlite, args.out)


if __name__ == '__main__':
    main()
