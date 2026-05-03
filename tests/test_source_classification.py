"""Tests for streaming_ingest.classify_source and normalize_row source_type routing.

Covers:
- Janusec v1.x file naming patterns (janusec_ep_endpoint, janusec_net_c2_bgp, ...)
- Sheet name routing for XLSX files via _sheet hint
- Regression guard: existing vendor aliases still work
"""
from src.pipeline.streaming_ingest import (
    classify_source,
    normalize_row,
    SOURCE_CLOUD,
    SOURCE_ENDPOINT,
    SOURCE_IAM,
    SOURCE_EMAIL,
    SOURCE_NETWORK,
    SOURCE_REMOTE,
    SOURCE_UNKNOWN,
)


# ── classify_source ───────────────────────────────────────────────────────────

class TestClassifySourceFilenames:
    def test_janusec_ep_endpoint_xlsx(self):
        assert classify_source("janusec_ep_endpoint.v1.1.xlsx") == SOURCE_ENDPOINT

    def test_janusec_net_c2_bgp_csv(self):
        assert classify_source("janusec_net_c2_bgp.v1.1.csv") == SOURCE_NETWORK

    def test_janusec_okta_m365_events_json(self):
        assert classify_source("janusec_okta_m365_events.v1.1.json") == SOURCE_IAM

    def test_crowdstrike_filename(self):
        assert classify_source("crowdstrike_events.ndjson") == SOURCE_ENDPOINT

    def test_network_csv(self):
        assert classify_source("network_flow.csv") == SOURCE_NETWORK

    def test_zeek_log(self):
        assert classify_source("zeek_conn.log") == SOURCE_NETWORK


class TestClassifySourceSheetNames:
    """XLSX sheet names used by Janusec workbooks."""

    def test_endpoint_sheet(self):
        assert classify_source("endpoint") == SOURCE_ENDPOINT

    def test_network_sheet(self):
        assert classify_source("network") == SOURCE_NETWORK

    def test_cloud_sheet(self):
        assert classify_source("cloud") == SOURCE_CLOUD

    def test_email_sheet(self):
        assert classify_source("email") == SOURCE_EMAIL

    def test_identity_sheet(self):
        assert classify_source("identity") == SOURCE_IAM

    def test_bgp_token(self):
        assert classify_source("bgp") == SOURCE_NETWORK


class TestClassifySourceVendorRegression:
    """Existing vendor aliases must still resolve correctly."""

    def test_aws_cloudtrail(self):
        assert classify_source("cloudtrail") == SOURCE_CLOUD

    def test_okta(self):
        assert classify_source("okta") == SOURCE_IAM

    def test_m365(self):
        assert classify_source("m365") == SOURCE_EMAIL

    def test_crowdstrike(self):
        assert classify_source("crowdstrike") == SOURCE_ENDPOINT

    def test_vpn(self):
        assert classify_source("vpn") == SOURCE_REMOTE

    def test_unknown(self):
        assert classify_source("random_app_log.csv") == SOURCE_UNKNOWN


# ── normalize_row _sheet hint ─────────────────────────────────────────────────

class TestNormalizeRowSheetHint:
    """Rows from XLSX files carry _sheet; normalize_row must use it when
    the filename alone doesn't classify."""

    def test_xlsx_endpoint_sheet_sets_source_type(self):
        row = {
            "_source": "janusec_ep_endpoint.v1.1.xlsx",
            "_sheet": "endpoint",
            "hostname": "ws-001",
            "event_type": "process_create",
        }
        r = normalize_row(row)
        assert r["_source_type"] == SOURCE_ENDPOINT

    def test_xlsx_network_sheet_sets_source_type(self):
        row = {
            "_source": "some_network_logs.xlsx",
            "_sheet": "network",
            "src_ip": "10.0.0.1",
        }
        r = normalize_row(row)
        assert r["_source_type"] == SOURCE_NETWORK

    def test_xlsx_identity_sheet_sets_source_type(self):
        row = {
            "_source": "corp_data_dump.xlsx",
            "_sheet": "identity",
            "userPrincipalName": "alice@corp.com",
        }
        r = normalize_row(row)
        assert r["_source_type"] == SOURCE_IAM

    def test_section_hint_still_works(self):
        """Existing _section routing (for JSON bundles) must not regress.
        Use a filename that has no alias match of its own so the _section
        hint is the sole classifier."""
        row = {
            "_source": "acmecorp_export_2026.json",
            "_section": "cloud",
            "userIdentity": {"userName": "alice"},
        }
        r = normalize_row(row)
        assert r["_source_type"] == SOURCE_CLOUD

    def test_bgp_csv_filename_direct_classify(self):
        """BGP CSV files should resolve without needing a sheet hint."""
        row = {
            "_source": "janusec_net_c2_bgp.v1.1.csv",
            "src_ip": "10.0.0.1",
            "dst_ip": "1.2.3.4",
        }
        r = normalize_row(row)
        assert r["_source_type"] == SOURCE_NETWORK
