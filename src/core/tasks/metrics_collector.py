from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, date
import logging

from src.repositories.decision_labels_repo import aggregate_daily
from src.repositories.precision_metrics_repo import PrecisionMetricsRepo

logger = logging.getLogger(__name__)

# Use same SQLite path as precision metrics repo; production should point to Postgres
_repo = PrecisionMetricsRepo(db_path='data/precision_metrics.db')


def register_metrics_collector(app, interval_seconds: int = 60*60*24):
    """Register a background task that runs daily to aggregate decision labels
    into the precision_metrics table. interval_seconds default to 24h for daily runs.
    """
    async def _collector_loop():
        while True:
            try:
                # For each tenant in runtime state we could iterate; for now run global default tenant
                tenants = [None]
                now = datetime.utcnow()
                # compute yesterday window (UTC day)
                yesterday = (now - timedelta(days=1)).date()
                start_ts = datetime(yesterday.year, yesterday.month, yesterday.day).isoformat() + 'Z'
                end_ts_dt = datetime(yesterday.year, yesterday.month, yesterday.day) + timedelta(days=1)
                end_ts = end_ts_dt.isoformat() + 'Z'
                for t in tenants:
                    try:
                        rows = await aggregate_daily(t, start_ts, end_ts)
                        for r in rows:
                            # r contains day,tp,fp,fn
                            try:
                                d = date.fromisoformat(r['day'].split('T')[0])
                            except Exception:
                                d = yesterday
                            tp = int(r.get('tp', 0) or 0)
                            fp = int(r.get('fp', 0) or 0)
                            fn = int(r.get('fn', 0) or 0)
                            tenant_id = t or 'default'
                            _repo.insert_daily_metrics(d, tenant_id, tp, fp, fn)
                    except Exception as exc:
                        logger.exception('metrics_collector: per-tenant aggregate failed: %s', exc)
            except Exception as exc:
                logger.exception('metrics_collector loop error: %s', exc)
            await asyncio.sleep(interval_seconds)

    # schedule on app startup
    app.add_event_handler('startup', lambda: asyncio.create_task(_collector_loop()))
"""Background task to aggregate daily precision metrics from feedback and decision logs.

This is a lightweight stub: it demonstrates where to implement aggregation logic.
It looks for env var METRICS_DAILY_INTERVAL_SECONDS to schedule runs.
"""
import asyncio
import os
import time
from datetime import datetime, date, timedelta
from typing import Optional

from src.repositories.precision_metrics_repo import PrecisionMetricsRepo
from src.repositories import decision_labels_repo
import asyncio
from src.api import metrics_init


_DB_PATH = os.getenv('JANUSEC_SQLITE_PATH', 'data/janusec.db')
_repo = PrecisionMetricsRepo(_DB_PATH)


async def _daily_metrics_loop():
    # Run at configured interval (default 24h)
    interval = int(os.getenv('METRICS_DAILY_INTERVAL_SECONDS', str(24 * 3600)) or (24 * 3600))
    while True:
        try:
            # Compute yesterday's date and aggregate TP/FP/FN counts from decision_labels
            target_day = (datetime.utcnow().date() - timedelta(days=1))
            start_ts = datetime.combine(target_day, datetime.min.time()).isoformat() + 'Z'
            end_ts = (datetime.combine(target_day + timedelta(days=1), datetime.min.time()).isoformat() + 'Z')
            tenant_id = os.getenv('DEFAULT_TENANT', 'default')
            tp = fp = fn = 0
            try:
                # decision_labels_repo.aggregate_daily expects timestamps and tenant
                rows = await decision_labels_repo.aggregate_daily(tenant_id, start_ts, end_ts)
                # rows are list of dicts with day,tp,fp,fn
                for r in rows:
                    tp += int(r.get('tp') or 0)
                    fp += int(r.get('fp') or 0)
                    fn += int(r.get('fn') or 0)
            except Exception:
                # If DB not available or error, fallback to in-memory feedback store if present
                try:
                    from src.feedback.store import GLOBAL_FEEDBACK_STORE
                    stats = GLOBAL_FEEDBACK_STORE.stats()
                    tp = stats.get('by_classification', {}).get('tp', 0) or stats.get('by_classification', {}).get('true_positive', 0) or 0
                    fp = stats.get('by_classification', {}).get('fp', 0) or stats.get('by_classification', {}).get('false_positive', 0) or 0
                    fn = 0
                except Exception:
                    tp = fp = fn = 0
            try:
                _repo.insert_daily_metrics(target_day, tenant_id, int(tp), int(fp), int(fn))
            except Exception:
                pass
            # Export to Prometheus gauges (precision / recall per tenant/day)
            try:
                try:
                    metrics_init.ensure_metrics()
                except Exception:
                    pass
                # Lazily create gauges on the metrics_init module so tests/other
                # code paths reuse the same objects.
                if not hasattr(metrics_init, 'precision_daily_gauge'):
                    try:
                        metrics_init.precision_daily_gauge = metrics_init._safe_gauge(
                            'janusec_precision_daily','Daily precision per tenant',['tenant_id','day']
                        )
                    except Exception:
                        metrics_init.precision_daily_gauge = None
                if not hasattr(metrics_init, 'recall_daily_gauge'):
                    try:
                        metrics_init.recall_daily_gauge = metrics_init._safe_gauge(
                            'janusec_recall_daily','Daily recall per tenant',['tenant_id','day']
                        )
                    except Exception:
                        metrics_init.recall_daily_gauge = None
                # Compute precision & recall and set gauges
                precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
                recall = (tp / (tp + fn)) if (tp + fn) > 0 else None
                try:
                    if getattr(metrics_init, 'precision_daily_gauge', None) is not None and precision is not None:
                        metrics_init.precision_daily_gauge.labels(tenant_id=tenant_id, day=str(target_day)).set(float(precision))
                except Exception:
                    pass
                try:
                    if getattr(metrics_init, 'recall_daily_gauge', None) is not None and recall is not None:
                        metrics_init.recall_daily_gauge.labels(tenant_id=tenant_id, day=str(target_day)).set(float(recall))
                except Exception:
                    pass
                try:
                    if getattr(metrics_init, 'metrics_scrape_ts', None) is not None:
                        try:
                            metrics_init.metrics_scrape_ts.labels().set(time.time())
                        except Exception:
                            try:
                                metrics_init.metrics_scrape_ts.set(time.time())
                            except Exception:
                                pass
                except Exception:
                    pass
            except Exception:
                pass
            # Simple anomaly detection: precision below threshold
            try:
                precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
                thresh = float(os.getenv('METRICS_PRECISION_ALERT_THRESHOLD','0.6'))
                if precision is not None and precision < thresh:
                    try:
                        from src.api.server import audit_emit
                        audit_emit('metrics_precision_anomaly', None, {'tenant_id': tenant_id, 'day': str(target_day), 'precision': precision, 'tp': tp, 'fp': fp})
                    except Exception:
                        pass
            except Exception:
                pass
            # Per-variant AB precision gauges (for active experiments)
            try:
                try:
                    from src.repositories import ab_test_repo
                    tests = []
                    try:
                        tests = asyncio.run(ab_test_repo.list_active()) if hasattr(ab_test_repo, 'list_active') else []
                    except Exception:
                        try:
                            tests = ab_test_repo.list_active()
                        except Exception:
                            tests = []
                    for t in (tests or []):
                        test_id = t.get('id') or t.get('test_id') or t.get('name')
                        if not test_id:
                            continue
                        try:
                            rows = await decision_labels_repo.ab_test_daily(tenant_id, test_id, start_ts, end_ts)
                        except Exception:
                            continue
                        # rows: list of {day, variant, tp, fp, fn}
                        # ensure gauge exists
                        gauge_name = 'janusec_precision_daily_variant'
                        if not hasattr(metrics_init, 'precision_daily_variant_gauge'):
                            try:
                                metrics_init.precision_daily_variant_gauge = metrics_init._safe_gauge(gauge_name, 'Daily precision per tenant and variant', ['tenant_id','test_id','variant','day'])
                            except Exception:
                                metrics_init.precision_daily_variant_gauge = None
                        for r in rows:
                            var = r.get('variant') or 'unknown'
                            day = r.get('day')
                            tp_v = int(r.get('tp') or 0)
                            fp_v = int(r.get('fp') or 0)
                            prec_v = (tp_v / (tp_v + fp_v)) if (tp_v + fp_v) > 0 else None
                            try:
                                if getattr(metrics_init, 'precision_daily_variant_gauge', None) is not None and prec_v is not None:
                                    metrics_init.precision_daily_variant_gauge.labels(tenant_id=tenant_id, test_id=test_id, variant=var, day=str(day)).set(float(prec_v))
                            except Exception:
                                pass
                except Exception:
                    pass
            except Exception:
                pass
        except Exception:
            pass
        await asyncio.sleep(max(30, interval))


def register_metrics_collector(app):
    interval = int(os.getenv('METRICS_DAILY_INTERVAL_SECONDS', '0') or 0)
    if interval <= 0:
        return

    async def _start():
        await asyncio.sleep(5)
        asyncio.create_task(_daily_metrics_loop())

    app.add_event_handler('startup', lambda: asyncio.create_task(_start()))
