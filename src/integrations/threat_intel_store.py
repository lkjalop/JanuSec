"""Persistent threat intel store + simple sync helpers.

Provides a lightweight sqlite-backed store for IPs/domains/ja3/certfp and a
sync helper for Abuse.ch (URLhaus) as a starting point. Designed to be
extended with MISP/OpenCTI fetchers.
"""
from __future__ import annotations
import sqlite3
import threading
import time
from typing import Iterable
import os
import requests
from .misp_client import fetch_attributes, MispAuthError
try:
    from prometheus_client import Counter  # type: ignore
except Exception:
    Counter = None  # type: ignore

DB_PATH = os.getenv('THREAT_INTEL_DB_PATH', 'data/threat_intel.sqlite')
_LOCK = threading.RLock()

if Counter:
    TI_SYNC_SUCCESS = Counter('threat_intel_sync_success_total','Threat intel sync success', ['source'])  # type: ignore
    TI_SYNC_FAILURE = Counter('threat_intel_sync_failure_total','Threat intel sync failure', ['source'])  # type: ignore
else:
    TI_SYNC_SUCCESS = None  # type: ignore
    TI_SYNC_FAILURE = None  # type: ignore


def _ensure_db(db_path: str = DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS ips (value TEXT PRIMARY KEY, updated INTEGER)
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS domains (value TEXT PRIMARY KEY, updated INTEGER)
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS ja3 (value TEXT PRIMARY KEY, updated INTEGER)
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS certfp (value TEXT PRIMARY KEY, updated INTEGER)
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS issuer_rep (issuer TEXT PRIMARY KEY, count INTEGER, updated INTEGER)
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS cert_checks (certfp TEXT PRIMARY KEY, status TEXT, last_checked INTEGER, details TEXT)
    ''')
    conn.commit(); conn.close()


class ThreatIntelStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        _ensure_db(self.db_path)

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def upsert_ips(self, ips: Iterable[str]):
        now = int(time.time())
        with _LOCK:
            conn = self._conn()
            cur = conn.cursor()
            cur.executemany('INSERT OR REPLACE INTO ips(value,updated) VALUES(?,?)', [(i,now) for i in ips])
            conn.commit(); conn.close()

    def upsert_domains(self, domains: Iterable[str]):
        now = int(time.time())
        with _LOCK:
            conn = self._conn()
            cur = conn.cursor()
            cur.executemany('INSERT OR REPLACE INTO domains(value,updated) VALUES(?,?)', [(d.lower(),now) for d in domains])
            conn.commit(); conn.close()

    def upsert_ja3(self, ja3s: Iterable[str]):
        now = int(time.time())
        with _LOCK:
            conn = self._conn(); cur = conn.cursor()
            cur.executemany('INSERT OR REPLACE INTO ja3(value,updated) VALUES(?,?)', [(j,now) for j in ja3s])
            conn.commit(); conn.close()

    def upsert_certfp(self, fps: Iterable[str]):
        now = int(time.time())
        with _LOCK:
            conn = self._conn(); cur = conn.cursor()
            cur.executemany('INSERT OR REPLACE INTO certfp(value,updated) VALUES(?,?)', [(f,now) for f in fps])
            conn.commit(); conn.close()

    def list_domains(self):
        with _LOCK:
            conn = self._conn(); cur = conn.cursor()
            cur.execute('SELECT value FROM domains'); rows = [r[0] for r in cur.fetchall()]; conn.close(); return set(rows)

    def list_ips(self):
        with _LOCK:
            conn = self._conn(); cur = conn.cursor()
            cur.execute('SELECT value FROM ips'); rows = [r[0] for r in cur.fetchall()]; conn.close(); return set(rows)

    def incr_issuer(self, issuer: str):
        now = int(time.time())
        with _LOCK:
            conn = self._conn(); cur = conn.cursor()
            cur.execute('SELECT count FROM issuer_rep WHERE issuer=?', (issuer,))
            row = cur.fetchone()
            if row:
                cur.execute('UPDATE issuer_rep SET count=count+1, updated=? WHERE issuer=?', (now,issuer))
            else:
                cur.execute('INSERT INTO issuer_rep(issuer,count,updated) VALUES(?,?,?)', (issuer,1,now))
            conn.commit(); conn.close()

    def get_issuer_count(self, issuer: str) -> int:
        with _LOCK:
            conn = self._conn(); cur = conn.cursor(); cur.execute('SELECT count FROM issuer_rep WHERE issuer=?', (issuer,)); r = cur.fetchone(); conn.close(); return int(r[0]) if r else 0


STORE = ThreatIntelStore()


def sync_abusech_urlhaus_csv(url: str = 'https://urlhaus.abuse.ch/downloads/csv/') -> dict:
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        text = r.text
        domains = set()
        for line in text.splitlines():
            if not line or line.startswith('#'):
                continue
            parts = line.split(',')
            if len(parts) < 2:
                continue
            url_field = parts[0].strip().strip('"')
            try:
                from urllib.parse import urlparse
                p = urlparse(url_field)
                host = (p.hostname or '').lower()
                if host:
                    domains.add(host)
            except Exception:
                continue
        if domains:
            STORE.upsert_domains(domains)
            # optional webhook for new domains
            webhook = os.getenv('THREAT_INTEL_WEBHOOK_URL')
            if webhook:
                try:
                    requests.post(webhook, json={'source':'abusech','new_domains': list(sorted(domains))}, timeout=5)
                except Exception:
                    pass
        if TI_SYNC_SUCCESS:
            try: TI_SYNC_SUCCESS.labels(source='abusech').inc()  # type: ignore
            except Exception: pass
        return {'added_domains': len(domains)}
    except Exception as exc:
        if TI_SYNC_FAILURE:
            try: TI_SYNC_FAILURE.labels(source='abusech').inc()  # type: ignore
            except Exception: pass
        return {'error': str(exc)}


def sync_misp(api_url: str = None, api_key: str = None) -> dict:
    """Simple MISP fetcher (placeholder).

    If MISP API details are provided via env, this will call /events/index or /attributes
    to fetch IoCs. For now this is a placeholder that reads env vars and returns 0 when
    not configured.
    """
    if not api_url or not api_key:
        api_url = os.getenv('MISP_API_URL')
        api_key = os.getenv('MISP_API_KEY')
    if not api_url or not api_key:
        return {'skipped': 'misp_not_configured'}

    ips, domains, ja3s, fps = set(), set(), set(), set()
    added = {'ips': 0, 'domains': 0, 'ja3': 0, 'certfp': 0}
    try:
        # Use the resilient iterator which handles pagination and retries
        for a in fetch_attributes(api_url, api_key, page_size=200, retries=3):
            try:
                val = a.get('value') or ''
                atype = (a.get('type') or '').lower()
                if atype in ('ip-src', 'ip-dst', 'ip'):
                    ips.add(val)
                elif atype in ('domain', 'hostname'):
                    domains.add(val.lower())
                elif atype == 'ja3':
                    ja3s.add(val)
                elif atype in ('certfp', 'sha1'):
                    fps.add(val)
            except Exception:
                # defensive: skip malformed attribute
                continue

        if ips:
            STORE.upsert_ips(ips); added['ips'] = len(ips)
        if domains:
            STORE.upsert_domains(domains); added['domains'] = len(domains)
        if ja3s:
            STORE.upsert_ja3(ja3s); added['ja3'] = len(ja3s)
        if fps:
            STORE.upsert_certfp(fps); added['certfp'] = len(fps)

        if TI_SYNC_SUCCESS:
            try: TI_SYNC_SUCCESS.labels(source='misp').inc()  # type: ignore
            except Exception: pass
        return {'added': added}
    except MispAuthError as mae:
        if TI_SYNC_FAILURE:
            try: TI_SYNC_FAILURE.labels(source='misp').inc()  # type: ignore
            except Exception: pass
        return {'error': str(mae), 'auth': True}
    except Exception as exc:
        if TI_SYNC_FAILURE:
            try: TI_SYNC_FAILURE.labels(source='misp').inc()  # type: ignore
            except Exception: pass
        return {'error': str(exc)}


def sync_opencti(api_url: str = None, api_token: str = None) -> dict:
    if not api_url or not api_token:
        api_url = os.getenv('OPENCTI_API_URL')
        api_token = os.getenv('OPENCTI_API_TOKEN')
    if not api_url or not api_token:
        return {'skipped': 'opencti_not_configured'}

    try:
        from .opencti_client import fetch_observables, OpenCTIAuthError
    except Exception:
        return {'error': 'opencti_client_unavailable'}

    ips, domains = set(), set()
    try:
        for o in fetch_observables(api_url, api_token, page_size=200, retries=3):
            try:
                val = o.get('observable_value') or o.get('value') or ''
                itype = (o.get('entity_type') or o.get('type') or '').lower()
                if itype in ('ipv4-addr', 'ipv4'):
                    ips.add(val)
                elif itype in ('domain-name', 'hostname', 'domain'):
                    domains.add(val.lower())
            except Exception:
                continue

        if ips: STORE.upsert_ips(ips)
        if domains: STORE.upsert_domains(domains)

        if TI_SYNC_SUCCESS:
            try: TI_SYNC_SUCCESS.labels(source='opencti').inc()  # type: ignore
            except Exception: pass
        return {'added': {'ips': len(ips), 'domains': len(domains)}}
    except OpenCTIAuthError as oae:
        if TI_SYNC_FAILURE:
            try: TI_SYNC_FAILURE.labels(source='opencti').inc()  # type: ignore
            except Exception: pass
        return {'error': str(oae), 'auth': True}
    except Exception as exc:
        if TI_SYNC_FAILURE:
            try: TI_SYNC_FAILURE.labels(source='opencti').inc()  # type: ignore
            except Exception: pass
        return {'error': str(exc)}


def sync_all():
    out = {}
    out['abusech'] = sync_abusech_urlhaus_csv()
    out['misp'] = sync_misp()
    out['opencti'] = sync_opencti()
    return out


def last_sync_status():
    """Return simple status summary: counts from DB and last updated times."""
    try:
        return {
            'domains': len(STORE.list_domains()),
            'ips': len(STORE.list_ips()),
        }
    except Exception:
        return {}


__all__ = ['STORE','sync_abusech_urlhaus_csv','sync_misp','sync_opencti','sync_all']
