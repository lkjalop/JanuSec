"""Durable, customer-scoped Entra delivery receipts and replay input."""
import json
import os
from pathlib import Path
import sqlite3
import time

from src.core.evidence_contract.records import canonical_hash


def _db():
    path = Path(os.getenv("JANUSEC_CONNECTOR_RECEIPTS_DB") or
                str(Path(os.getenv("SESSION_PERSIST_DIR", "data/sessions")) / "connector_receipts.sqlite"))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    conn.execute("""CREATE TABLE IF NOT EXISTS connector_deliveries (
        tenant TEXT NOT NULL, connector TEXT NOT NULL, fingerprint TEXT NOT NULL,
        received_at REAL NOT NULL, payload TEXT NOT NULL,
        PRIMARY KEY (tenant, connector, fingerprint))""")
    return conn


def fingerprint(event):
    return canonical_hash([event.get("provider_record_id") or event.get("id"),
                           event.get("raw_receipt_hash") or event.get("raw") or event.get("id") or event])


def known(tenant, connector):
    conn = _db()
    try:
        return {row[0] for row in conn.execute("SELECT fingerprint FROM connector_deliveries WHERE tenant=? AND connector=?", (tenant, connector))}
    finally:
        conn.close()


def deliver(tenant, connector, events):
    if any(event.get("tenant_id") != tenant for event in events):
        raise ValueError("connector_delivery_tenant_mismatch")
    conn = _db()
    try:
        with conn:
            conn.executemany("INSERT OR IGNORE INTO connector_deliveries VALUES (?, ?, ?, ?, ?)",
                             [(tenant, connector, fingerprint(event), time.time(), json.dumps(event)) for event in events])
    finally:
        conn.close()


def recent(tenant, limit=5000):
    conn = _db()
    try:
        return [json.loads(row[0]) for row in conn.execute("SELECT payload FROM connector_deliveries WHERE tenant=? ORDER BY received_at DESC LIMIT ?", (tenant, limit))]
    finally:
        conn.close()
