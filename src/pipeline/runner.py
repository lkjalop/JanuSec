from __future__ import annotations
import os, time, json
import psycopg2
from typing import List, Dict, Any

from src.collectors.iam_okta_adapter import OktaIAMCollector
from src.collectors.api_gateway_adapter import APIGatewayCollector
from src.pipeline.normalizer import normalize_okta_event, normalize_apigw_event, normalize_o365_event
from src.enrichment.email_enrichment import enrich_email
from src.live.event_models import EmailEvent

DB_DSN = os.getenv('JNS_DB_DSN', 'postgresql://postgres:postgres@localhost:5432/janusec')


def _get_conn():
    return psycopg2.connect(DB_DSN)


def insert_event(conn, event: Dict[str, Any]):
    # Minimal upsert
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO events(event_id, tenant_id, ts, domain, ingest_source, raw, factors, tags)
            VALUES (%s,%s,to_timestamp(%s),%s,%s,%s,%s,%s)
            ON CONFLICT (event_id) DO UPDATE SET raw = EXCLUDED.raw
            """,
            (event['event_id'], event.get('tenant_id','default'), event.get('ts', time.time()), event.get('domain'), event.get('ingest_source'), json.dumps(event.get('raw') or {}), event.get('factors') or [], event.get('tags') or [])
        )
    conn.commit()


def enqueue_enrichment(conn, event_id: str, tenant_id: str):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO enrichment_queue(event_id, tenant_id) VALUES (%s,%s)", (event_id, tenant_id))
    conn.commit()


def run_once():
    # Poll collectors
    okta = OktaIAMCollector()
    apigw = APIGatewayCollector()
    events: List[Dict[str, Any]] = []
    now = time.time()
    events.extend(okta.fetch_events(now - 3600))
    events.extend(apigw.fetch_events(now - 3600))

    conn = _get_conn()
    for raw in events:
        try:
            if raw.get('eventType') or raw.get('changeType'):
                ev = normalize_okta_event(raw)
            elif raw.get('methodsSequence'):
                ev = normalize_apigw_event(raw)
            else:
                # Try O365/Gmail specific normalizers based on source hint
                src = (raw.get('source') or '').lower()
                if src in ('gmail', 'gmail_api'):
                    from src.pipeline.normalizer import normalize_gmail_event
                    ev = normalize_gmail_event(raw)
                else:
                    ev = normalize_o365_event(raw)
                # If email domain, run enrichment synchronously to attach early factors
                try:
                    if ev.get('domain') == 'email':
                        # Build EmailEvent model
                        email_model = EmailEvent(
                            timestamp=ev.get('ts'),
                            tenant_id=ev.get('tenant_id'),
                            source=ev.get('ingest_source'),
                            sender=(ev.get('email') or {}).get('from'),
                            sender_display_name=None,
                            recipients=(ev.get('email') or {}).get('to') or [],
                            subject=(ev.get('email') or {}).get('subject'),
                            has_attachments=(ev.get('email') or {}).get('has_attachments', False),
                            headers=ev.get('headers') or {},
                            body_preview=ev.get('body_preview') or (ev.get('raw') or {}).get('bodyPreview'),
                            message_id=(ev.get('raw') or {}).get('id') or ev.get('event_id'),
                            raw_event=ev.get('raw') or {}
                        )
                        enrichment = enrich_email(email_model)
                        # Merge enrichment into raw and append any signals to factors
                        try:
                            ev.setdefault('raw', {})
                            ev['raw']['enrichment'] = enrichment
                            signals = (enrichment.get('email_enrichment') or {}).get('signals') or []
                            if signals:
                                ev.setdefault('factors', [])
                                ev['factors'].extend(signals)
                        except Exception:
                            pass
                except Exception:
                    pass
            insert_event(conn, ev)
            enqueue_enrichment(conn, ev['event_id'], ev.get('tenant_id','default'))
        except Exception as e:
            print('insert error', e)
    conn.close()


if __name__ == '__main__':
    run_once()
