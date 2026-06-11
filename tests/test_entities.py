"""Tests for the canonical entity extractor (src/core/entities.py)."""
from __future__ import annotations

from src.core import entities as E


class TestFlatExtraction:
    def test_users_ips_hosts(self):
        row = {"user_canonical": "Martin.Chen", "src_ip": "10.0.0.5",
               "hostname": "WS-MARTIN-01", "dst_ip": "10.0.0.9"}
        got = E.extract_entities(row)
        assert "martin.chen" in got
        assert "10.0.0.5" in got and "10.0.0.9" in got
        assert "ws-martin-01" in got

    def test_fqdn_adds_short_host(self):
        row = {"hostname": "dc-01.corp.local"}
        got = E.extract_entities(row)
        assert "dc-01.corp.local" in got and "dc-01" in got

    def test_ip_not_split_into_short(self):
        row = {"src_ip": "10.42.1.10"}
        got = E.extract_entities(row)
        assert got == {"10.42.1.10"}  # no spurious "10" short token

    def test_stopwords_and_short_tokens_dropped(self):
        row = {"user": "-", "hostname": "ok", "src_ip": "0.0.0.0", "account_name": "system"}
        got = E.extract_entities(row)
        assert got == set()  # all filtered (ok is len 2, -, 0.0.0.0, system are stopwords)

    def test_spn_and_service_name_are_users(self):
        row = {"spn": "MSSQLSvc/db01", "service_name": "krbtgt"}
        got = E.extract_entities(row)
        assert "mssqlsvc/db01" in got and "krbtgt" in got


class TestTypedExtraction:
    def test_canonical_preferred_one_per_row(self):
        rows = [{"user_canonical": "alice", "user": "alice@corp"},
                {"user": "bob", "src_ip": "10.0.0.2", "hostname": "h2"}]
        users, ips, hosts = E.extract_typed(rows)
        assert users == ["alice", "bob"]   # canonical wins for row 1, no double-count
        assert ips == ["10.0.0.2"]
        assert hosts == ["h2"]

    def test_dedup_and_sorted(self):
        rows = [{"user": "carol"}, {"user_canonical": "carol"}, {"user": "abe"}]
        users, _, _ = E.extract_typed(rows)
        assert users == ["abe", "carol"]


class TestPrimary:
    def test_primary_user_priority(self):
        assert E.primary_user({"user_canonical": "a", "user": "b"}) == "a"
        assert E.primary_user({"user": "b"}) == "b"
        assert E.primary_user({"user": "-"}) == ""

    def test_parity_with_prior_narrator_behavior(self):
        # The IOC-grounding guardrail depends on this exact behavior.
        row = {"user_canonical": "martin.chen", "src_ip": "10.42.4.91", "hostname": "ws-martin-01"}
        got = E.extract_entities(row)
        assert {"martin.chen", "10.42.4.91", "ws-martin-01"} <= got
