"""Canonical ChronoGraph metric name constants.

All code that writes to or reads from ChronoGraph must import metric names
from here rather than using inline strings. This prevents typo-driven
z-score misses and makes refactoring safe.

Usage:
    from src.core.chrono.metric_names import M
    chrono.increment("user", user, M.EVENTS, 1.0, ts=ts)
    z = chrono.z_score("user", user, M.BYTES_OUT, window_seconds=...)
"""
from __future__ import annotations


class M:
    """Metric name constants. Prefix indicates the source domain."""

    # ── Generic per-entity volume ───────────────────────────────────────────
    EVENTS           = "events"
    BYTES_OUT        = "bytes_out"
    CLOUD_BYTES_OUT  = "cloud_bytes_out"

    # ── Recon / off-hours (endpoint + IAM) ─────────────────────────────────
    RECON_EVENTS          = "recon_events"
    OFF_HOURS_EVENTS      = "off_hours_events"
    OFF_HOURS_RECON       = "off_hours_recon_events"

    # ── First-seen host access (per-user) ──────────────────────────────────
    @staticmethod
    def HOST_ACCESS(host: str) -> str:
        return f"host_access:{host}"

    # ── IAM / Kerberos ─────────────────────────────────────────────────────
    IAM_RC4_COUNT        = "iam:rc4_count"
    IAM_TICKET_VOLUME    = "iam:ticket_volume"
    IAM_PRE_AUTH_FAILS   = "iam:pre_auth_fail_count"
    IAM_FAILED_LOGINS    = "iam:failed_login_count"

    # ── Cloud / Azure AD ───────────────────────────────────────────────────
    CLOUD_FOREIGN_ASN    = "cloud:foreign_asn_count"
    CLOUD_CA_BYPASS      = "cloud:ca_bypass_count"
    CLOUD_CONSENT_GRANTS = "cloud:consent_grant_count"
    CLOUD_RISKY_SIGNINS  = "cloud:risky_signin_count"

    # ── Endpoint (Sysmon / EDR) ────────────────────────────────────────────
    ENDPOINT_LOLBIN          = "endpoint:lolbin_count"
    ENDPOINT_ENCODED_PS      = "endpoint:encoded_ps_count"
    ENDPOINT_WMI_EXEC        = "endpoint:wmi_exec_count"
    ENDPOINT_NEW_PROC_PARENT = "endpoint:new_parent_process_count"

    # ── Network ────────────────────────────────────────────────────────────
    NETWORK_UNIQUE_DESTS   = "network:unique_dest_count"
    NETWORK_CONN_BURST     = "network:connection_burst"
    NETWORK_DNS_QUERIES    = "network:dns_query_count"

    # ── Email ──────────────────────────────────────────────────────────────
    EMAIL_EXTERNAL_SENDS   = "email:external_send_count"
    EMAIL_ATTACH_BYTES     = "email:attachment_bytes"
    EMAIL_EXTERNAL_RATIO   = "email:external_ratio"

    # ── ML-derived (written by MLSignalAggregator.to_chrono_metrics) ───────
    ML_ISO_ANOM_COUNT  = "ml:iso_anom_count"
    ML_ENSEMBLE_PEAK   = "ml:ensemble_peak"
