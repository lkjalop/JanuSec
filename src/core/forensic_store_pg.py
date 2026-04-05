import os
import psycopg2
import json
from typing import Optional


class ForensicStorePG:
    def __init__(self, dsn: Optional[str] = None):
        self.dsn = dsn or os.getenv('FORENSIC_PG_DSN')

    def insert_artifact(self, s3_url: str, collector: str, collected_at: int, sha256: str, meta: Optional[dict] = None):
        with psycopg2.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO forensic_artifacts (s3_url, collector, collected_at, sha256, meta) VALUES (%s,%s,%s,%s,%s)',
                            (s3_url, collector, collected_at, sha256, json.dumps(meta or {})))
