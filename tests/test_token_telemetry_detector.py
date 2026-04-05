from __future__ import annotations

from src.core.detectors import api_security
from src.core.detectors.token_theft import TokenTelemetryAnalyzer


def iso(ts: str) -> str:
    return ts


def test_token_usage_after_revocation_triggers_factor():
    analyzer = TokenTelemetryAnalyzer(ttl_seconds=3600, hijack_window=300)
    analyzer.analyze({"token_id": "tok-1", "timestamp": iso("2026-01-01T00:00:00"), "user": "alice", "ip": "1.1.1.1"})
    analyzer.analyze({"token_id": "tok-1", "timestamp": iso("2026-01-01T00:05:00"), "revoked": True})
    result = analyzer.analyze({"token_id": "tok-1", "timestamp": iso("2026-01-01T00:06:00"), "ip": "2.2.2.2"})
    assert "iam:token_usage_after_revocation" in result.factors


def test_session_hijack_detects_new_ip_in_window():
    analyzer = TokenTelemetryAnalyzer(ttl_seconds=3600, hijack_window=600)
    analyzer.analyze({"token_id": "tok-2", "timestamp": iso("2026-01-01T01:00:00"), "user": "bob", "ip": "3.3.3.3", "user_agent": "ua1"})
    result = analyzer.analyze({"token_id": "tok-2", "timestamp": iso("2026-01-01T01:05:00"), "ip": "4.4.4.4", "user_agent": "ua2"})
    assert "iam:session_hijack" in result.factors


def test_usage_anomaly_leverages_shared_baseline():
    analyzer = TokenTelemetryAnalyzer(ttl_seconds=3600, hijack_window=600)
    stats = api_security._TOKEN_USAGE_BASELINE["token:tok-3"]
    stats["count"] = 20
    stats["mean"] = 5.0
    stats["m2"] = 1.0
    result = analyzer.analyze({"token_id": "tok-3", "timestamp": iso("2026-01-01T02:00:00"), "token_usage": 100})
    assert "iam:token_usage_anomaly" in result.factors


def test_geo_anomaly_detects_new_location():
    analyzer = TokenTelemetryAnalyzer(ttl_seconds=3600, hijack_window=600)
    analyzer.analyze({"token_id": "tok-geo", "timestamp": iso("2026-01-01T03:00:00"), "geo": {"country": "US"}})
    result = analyzer.analyze({"token_id": "tok-geo", "timestamp": iso("2026-01-01T03:05:00"), "geo": {"country": "DE"}})
    assert "iam:token_geo_anomaly" in result.factors


def test_oauth_token_theft_fires_on_ip_switch():
    analyzer = TokenTelemetryAnalyzer(ttl_seconds=3600, hijack_window=600)
    analyzer.analyze({"token_id": "tok-oauth", "timestamp": iso("2026-01-01T04:00:00"), "ip": "1.1.1.1"})
    result = analyzer.analyze(
        {
            "token_id": "tok-oauth",
            "timestamp": iso("2026-01-01T04:05:00"),
            "ip": "8.8.8.8",
            "oauth_client_id": "app-1",
            "oauth_scope": "mail.read",
        }
    )
    assert "iam:oauth_token_theft" in result.factors
