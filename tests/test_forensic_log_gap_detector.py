import asyncio
import pytest
from datetime import datetime, timedelta

from src.monitoring.forensic_log_gap_detector import ForensicLogGapDetector


class DummyConn:
    def __init__(self, rows):
        self._rows = rows

    async def fetchrow(self, *_args, **_kwargs):
        return self._rows[0] if self._rows else None


class DummyDB:
    def __init__(self, last_seen_map):
        self.last_seen_map = last_seen_map

    def get_connection(self):
        class Ctx:
            def __init__(self, rows):
                self.rows = rows

            async def __aenter__(self):
                return DummyConn(self.rows)

            async def __aexit__(self, exc_type, exc, tb):
                return False

        # Build rows based on expected query args in codepath
        # For tests we'll map event_type -> timestamp
        rows = []
        return Ctx(rows)


class DummyAlertManager:
    def __init__(self):
        self.sent = []

    async def send_alert(self, alert):
        self.sent.append(alert)


@pytest.mark.asyncio
async def test_detect_log_gaps_never_seen(monkeypatch):
    # DB that returns no rows - simulation of never seen
    class DB:
        def get_connection(self):
            class Ctx:
                async def __aenter__(self_inner):
                    class R:
                        async def fetchrow(self_inner2, *args, **kwargs):
                            return None

                    return R()

                async def __aexit__(self_inner, *args):
                    return False

            return Ctx()

    db = DB()
    alert_mgr = DummyAlertManager()

    detector = ForensicLogGapDetector(db=db, alert_manager=alert_mgr, check_interval_seconds=1)

    tenants = []

    async def fake_get_active_tenants():
        return ['tenant-a']

    monkeypatch.setattr(detector, '_get_active_tenants', fake_get_active_tenants)

    # Run one check
    await detector.check_all_tenants()

    # Expect at least one alert for missing firewall_logs (critical)
    assert any('Missing Essential Log Sources' in a['title'] or a['title'].startswith('CRITICAL') for a in alert_mgr.sent)
