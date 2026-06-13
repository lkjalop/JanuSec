"""Tests for the operator sanctioned-context channel."""
from __future__ import annotations

from datetime import datetime, timezone

from src.core.operator_context import OperatorContext

_IN_WINDOW = datetime(2026, 2, 15, tzinfo=timezone.utc).timestamp()   # inside Feb 2026
_BEFORE_WINDOW = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()  # before window


CTX = {
    "authorized_pentest": {
        "accounts": ["pentest-readonly-feb2026"],
        "cidrs": ["203.0.113.0/24"],
        "window_start": "2026-02-01T00:00:00Z", "window_end": "2026-02-28T23:59:59Z",
    },
    "crown_jewels": {"hosts": ["SVR-DB-01"], "accounts": ["svc_sql"]},
    "sanctioned_destinations": ["acmevesper.sharepoint.com"],
}


class TestEmptyContext:
    def test_empty_is_noop(self):
        c = OperatorContext({})
        assert c.is_empty
        assert not c.is_authorized_pentest(user="anyone")
        assert c.touches_crown_jewel({"shared_hosts": ["x"]}) == []
        assert not c.is_sanctioned_destination("evil.com")


class TestPentestSuppression:
    def setup_method(self):
        self.c = OperatorContext(CTX)

    def test_account_in_window(self):
        ts = _IN_WINDOW
        assert self.c.is_authorized_pentest(user="pentest-readonly-feb2026", ts=ts)

    def test_cidr_match(self):
        ts = _IN_WINDOW
        assert self.c.is_authorized_pentest(ip="203.0.113.50", ts=ts)
        assert not self.c.is_authorized_pentest(ip="45.133.193.10", ts=ts)

    def test_outside_window_not_authorized(self):
        ts_jan = _BEFORE_WINDOW
        assert not self.c.is_authorized_pentest(user="pentest-readonly-feb2026", ts=ts_jan)

    def test_unknown_account_not_authorized(self):
        assert not self.c.is_authorized_pentest(user="aaron.blackwood", ts=_IN_WINDOW)

    def test_cluster_all_pentest_suppressed(self):
        cl = {"shared_users": ["pentest-readonly-feb2026"], "shared_ips": ["203.0.113.7"]}
        assert self.c.cluster_is_authorized_pentest(cl)

    def test_cluster_mixed_actors_NOT_suppressed(self):
        # A real breach that also touches a pentest account must NOT be suppressed.
        cl = {"shared_users": ["pentest-readonly-feb2026", "aaron.blackwood"]}
        assert not self.c.cluster_is_authorized_pentest(cl)


class TestCrownJewelAndDestinations:
    def setup_method(self):
        self.c = OperatorContext(CTX)

    def test_crown_jewel_host(self):
        assert self.c.touches_crown_jewel({"shared_hosts": ["SVR-DB-01"]}) == ["SVR-DB-01"]

    def test_crown_jewel_account(self):
        assert self.c.touches_crown_jewel({"shared_users": ["svc_sql"]}) == ["svc_sql"]

    def test_sanctioned_destination(self):
        assert self.c.is_sanctioned_destination("acmevesper.sharepoint.com")
        assert not self.c.is_sanctioned_destination("martin-chen.sharepoint.com")
