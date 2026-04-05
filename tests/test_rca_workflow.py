import os
import shutil
from datetime import datetime, timedelta
from src.core.heartbeat import record_ingest, get_actual_volume_last_hour, get_baseline_hourly, detect_missing_sources
from src.core.collector_telemetry import ingest_collector_telemetry, read_last_collector_status
from src.core.rca import analyze_root_causes


def setup_function(fn):
    # clean data dir
    d = "data"
    if os.path.exists(d):
        shutil.rmtree(d)


def test_heartbeat_and_baseline_and_detect():
    tenant = "t1"
    src = "aws_cloudtrail"
    # record 24 hourly buckets of 100 events to build baseline
    now = datetime.utcnow()
    for i in range(24):
        # record hours 2..25 (exclude the most recent hour) so last hour is empty
        ts = now - timedelta(hours=(i+2))
        record_ingest(tenant, src, ts=ts, count=100)

    baseline = get_baseline_hourly(tenant, src, days=1)
    assert baseline > 0

    # no recent ingest -> detect anomaly
    anomalies = detect_missing_sources(tenant, [src], days_baseline=1)
    assert src in anomalies
    assert anomalies[src]["status"] == "no_logs"


def test_collector_telemetry_and_rca():
    tenant = "t2"
    src = "okta_system_log"
    # create baseline then no logs
    now = datetime.utcnow()
    for i in range(24):
        # exclude most recent hour
        record_ingest(tenant, src, ts=now - timedelta(hours=(i+2)), count=50)

    # no logs in last hour -> anomaly
    # inject collector telemetry showing auth failure
    ingest_collector_telemetry(src, {"status": "auth_failed", "error": "401"})

    results = analyze_root_causes(tenant, [src])
    assert len(results) == 1
    r = results[0]
    assert r["source"] == src
    # top hypothesis should likely be authentication_issue or similar
    assert r["confidence"] > 0.1
