"""Background job to label false negatives by comparing incidents to prior decisions."""
import asyncio
import os
import time
from datetime import datetime, timedelta

async def _fn_loop(app):
    interval = int(os.getenv('FN_DETECT_INTERVAL_SECONDS','600') or 600)
    while True:
        try:
            # Best-effort: list recent incidents and cross-check decisions
            try:
                from src.repositories import incidents_repo, decisions_repo, decision_labels_repo
            except Exception:
                await asyncio.sleep(max(5, interval))
                continue
            incs = await incidents_repo.list_incidents(limit=200)
            for inc in incs:
                artifact = inc.get('artifact_id') or inc.get('id')
                tenant = inc.get('tenant_id')
                # If artifact looks like an event_id, check decision
                if not artifact:
                    continue
                try:
                    dec = await decisions_repo.get_decision(artifact, tenant)
                except Exception:
                    dec = None
                # If no decision or decision indicates benign/low_conf, mark FN
                mark_fn = False
                if dec is None:
                    mark_fn = True
                else:
                    verdict = dec.get('verdict')
                    confidence = dec.get('confidence') or 0.0
                    if verdict in ('benign','allow','clean') or float(confidence) < 0.4:
                        mark_fn = True
                if mark_fn:
                    try:
                        await decision_labels_repo.insert_label(artifact, dec.get('event_id') if dec else None, 'false_negative', tenant, None, None)
                    except Exception:
                        pass
        except Exception:
            pass
        await asyncio.sleep(max(5, interval))


def register_fn_detector(app):
    interval = int(os.getenv('FN_DETECT_INTERVAL_SECONDS','0') or 0)
    if interval <= 0:
        return
    async def _start():
        await asyncio.sleep(5)
        asyncio.create_task(_fn_loop(app))
    app.add_event_handler('startup', lambda: asyncio.create_task(_start()))
