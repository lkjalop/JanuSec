"""Regression tests for cluster_merge.transitive_merge_clusters.

Uses a synthetic fixture that mirrors the Santos three-file shape:
  - real intrusion phases (LSASS, K8s escape, Snowflake unload, Rclone exfil,
    DNS beaconing) sharing pivot keys across 22 days
  - authorized pentest engagement RH-ENG-2026-041
  - change-managed maintenance CHG-2026-0184 and CHG-2026-0229
  - BAU Snowflake queries that must NOT enter the breach
  - Feb 22 escalation row that bridges from pentest into the campaign

Each test corresponds to one of T1–T9 from the architectural review.

Run:
    python -m pytest test_cluster_merge.py -v
"""
from __future__ import annotations

import datetime
from typing import Any

import pytest

from src.core.ingest.cluster_merge import transitive_merge_clusters


# ── Fixture builder ──────────────────────────────────────────────────────────

def _ts(day: int, hour: int = 12, minute: int = 0) -> str:
    """Return ISO timestamp for Feb 2026, day=day."""
    return datetime.datetime(2026, 2, day, hour, minute, 0).isoformat()


def _row(idx: int, **kw: Any) -> dict:
    """Helper to build a normalized row with sensible defaults."""
    base: dict[str, Any] = {
        "row_index": idx,
        "_source_type": "unknown",
        "_lane": "telemetry_evidence",
        "_engagement_refs": [],
        "_change_refs": [],
    }
    base.update(kw)
    return base


def santos_synthetic_rows() -> list[dict]:
    """Return rows approximating the Santos three-file shape.

    Pivots are built downstream by ``cluster_merge.build_scope_qualified_pivots``;
    the fixture supplies only the row fields that pivot construction reads.
    """
    rows: list[dict] = []

    def add(**kw: Any) -> dict:
        idx = len(rows)
        r = _row(idx, **kw)
        rows.append(r)
        return r

    # ── REAL INTRUSION ──────────────────────────────────────────────────────

    # Feb 7 — recon attempt (PREVENTED) on javier.santos's host
    add(timestamp=_ts(7, 11, 34),
        user_canonical="javier.santos",
        hostname="sfl-lt-0599",
        src_ip="10.12.220.50",
        _source_type="endpoint",
        event="mso365-update.hta SUSPICIOUS_HTA_EXECUTION",
        notes="ML prevention — credential dumping precursor")

    # Feb 9 — DNS beacon kicks off on dispatch_vlan host
    for h in (9, 10, 11, 12, 14, 16, 18, 20, 22):
        add(timestamp=_ts(h, 3, 14),
            hostname="sfl-lt-0399",
            src_ip="10.12.230.180",
            src_ip_cidr24="10.12.230.0",
            _source_type="network",
            event="DNS Query low-reputation .link",
            event_signature="dns:nrd_lowrep",
            notes="newly-registered domain beacon")

    # Feb 11–22 — second beacon stream from dev_vlan (same /24 as rclone src).
    # This is the cross-day bridge that ties the beacon component to the
    # rclone exfil component via cidr24:10.12.50.0.
    for h in (11, 13, 15, 17, 19, 21):
        add(timestamp=_ts(h, 4, 22),
            hostname="sfl-lt-0521",
            src_ip="10.12.50.180",
            src_ip_cidr24="10.12.50.0",
            _source_type="network",
            event="DNS Query low-reputation .top",
            event_signature="dns:nrd_lowrep",
            notes="newly-registered domain beacon")

    # Feb 10 03:04 — Okta admin app session theft
    add(timestamp=_ts(10, 3, 4),
        user_canonical="rachel.nakamura",
        src_ip="45.133.193.118",
        src_ip_cidr24="45.133.193.0",
        _source_type="iam",
        event="user.session.access_admin_app",
        notes="Geo claims Sydney — session.access_admin_app")

    # Feb 10 03:10 — certutil download (network) from same /24 different IP
    add(timestamp=_ts(10, 3, 10),
        hostname="sfl-lt-0442",
        src_ip="10.12.230.180",
        src_ip_cidr24="10.12.230.0",
        dst_ip="45.133.193.42",
        dst_ip_cidr24="45.133.193.0",
        _source_type="network",
        event="certutil.exe URL cache",
        notes="Stage 2 download")

    # Feb 10 03:45 — LSASS dump exfil, same /24 destination
    add(timestamp=_ts(10, 3, 45),
        hostname="sfl-lt-0442",
        user_canonical="rachel.nakamura",
        src_ip="10.12.200.120",
        dst_ip="45.133.193.42",
        src_ip_cidr24="10.12.200.0",
        dst_ip_cidr24="45.133.193.0",
        _source_type="network",
        event="possible LSASS dump exfiltration 100MB",
        notes="lsass credential dump comsvcs.dll aaron.blackwood credentials extracted")

    # Feb 16 01:25 — AWS Secret access from attacker IP
    # NOTE: hostname=sfl-lt-0522 is the assessment-overlay attribution
    # ("AWS principal aaron.blackwood last seen on workstation sfl-lt-0522").
    # This is the cross-day bridge to Feb 20-22 rclone+escalation via host pivot.
    add(timestamp=_ts(16, 1, 25),
        user_canonical="aaron.blackwood",
        hostname="sfl-lt-0522",
        src_ip="91.240.118.7",
        _source_type="cloud",
        event="GetSecretValue",
        notes="AWS GetSecretValue from off-host IP, then sts:AssumeRole")

    # Feb 16 01:21 — K8s privileged DaemonSet
    add(timestamp=_ts(16, 1, 21),
        src_ip="91.240.118.7",
        hostname="eks-prod-node-04",
        _source_type="cloud",
        event="create DaemonSet privileged-ds-node-probe",
        notes="privileged container hostpath /host-root mount kubelet token")

    # Feb 16 01:26 — Falco runtime alert
    add(timestamp=_ts(16, 1, 26),
        src_ip="91.240.118.7",
        hostname="eks-prod-node-04",
        _source_type="endpoint",
        event="falco hostpath_mount privileged_pod_exec",
        notes="falco privileged kubelet host-root")

    # Feb 16 02:02 — Snowflake recon SHOW DATABASES (BAU verb-less; should NOT
    # phase-trigger by itself, but unifies via shared IP)
    add(timestamp=_ts(16, 2, 2),
        user_canonical="svc_sfl_analytics_fed",
        src_ip="91.240.118.7",
        _source_type="cloud",
        event="SHOW DATABASES",
        notes="snowflake recon")

    # Feb 16 02:23 — Snowflake CREATE STAGE + COPY INTO
    add(timestamp=_ts(16, 2, 23),
        user_canonical="svc_sfl_analytics_fed",
        src_ip="91.240.118.7",
        _source_type="cloud",
        event="CREATE STAGE / COPY INTO external stage s3://attacker-bucket/",
        rows_produced=1_410_000,
        notes="snowflake unload external stage")

    # Feb 20 14:35 — Snowflake exfil 1.86GB to attacker S3
    add(timestamp=_ts(20, 14, 35),
        user_canonical="svc_sfl_analytics_fed",
        src_ip="91.240.118.7",
        _source_type="cloud",
        event="COPY INTO @ext_stage_attacker FROM PORT_SCHEDULING_MASTER",
        rows_produced=1_860_000,
        notes="snowflake unload external stage 1.86GB")

    # Feb 20–22 — bulk network exfil to Hetzner sink
    for d, h in [(20, 14), (21, 9), (21, 14), (22, 10), (22, 16)]:
        add(timestamp=_ts(d, h, 51),
            hostname="sfl-lt-0522",
            src_ip="10.12.50.30",
            src_ip_cidr24="10.12.50.0",
            dst_ip="31.216.148.17",
            _source_type="network",
            event="rclone copy → mega.nz over WireGuard tunnel",
            notes="rclone bulk transfer >1.5GB Hetzner AS24940")

    # Feb 22 14:30 — IR declaration accelerates exfil (operator-aware)
    add(timestamp=_ts(22, 14, 30),
        hostname="sfl-lt-0522",
        _source_type="endpoint",
        event="IR declared accelerated exfil",
        notes="bandwidth note")

    # Feb 22 escalation — pentest operator finds OneDriveUpdate scheduled task
    # on Blackwood's host. KEY ROW: has _engagement_refs but ALSO has phase
    # signature. Should bridge from pentest engagement INTO campaign.
    add(timestamp=_ts(22, 18, 5),
        hostname="sfl-lt-0522",
        user_canonical="abdul.mohammadi",
        src_ip="198.51.100.42",   # pentest TEST-NET-2 source
        src_ip_cidr24="198.51.100.0",
        _source_type="endpoint",
        _engagement_refs=["RH-ENG-2026-041"],
        event="ESCALATION — non-engagement artifact found",
        notes="OneDriveUpdate task ctflogger.dll discovered on Blackwood host — does NOT match RH playbook — credential dump artifact")

    # Feb 23 — RTR containment of Blackwood + Nakamura hosts
    add(timestamp=_ts(23, 9, 0),
        hostname="sfl-lt-0522",
        _source_type="endpoint",
        event="RTR contain quarantine",
        notes="killed OneDriveUpdate task ctflogger.dll quarantine archive_001.7z")
    add(timestamp=_ts(23, 9, 30),
        hostname="sfl-lt-0442",
        _source_type="endpoint",
        event="RTR contain quarantine",
        notes="contain Nakamura host")

    # ── AUTHORIZED PENTEST RH-ENG-2026-041 ──────────────────────────────────
    # Nuclei perimeter scans Feb 19 — should NOT phase-trigger
    for h in range(0, 24, 2):
        add(timestamp=_ts(19, h, 0),
            src_ip="198.51.100.10",
            src_ip_cidr24="198.51.100.0",
            _source_type="network",
            _engagement_refs=["RH-ENG-2026-041"],
            event="Nuclei perimeter scan",
            notes="Authorized — RH-ENG-2026-041 perimeter probe")

    # SSH brute, SQLi, VPC reach probes Feb 20-22 — engagement-tagged
    for d, h in [(20, 9), (20, 14), (21, 10), (21, 15), (22, 8), (22, 13)]:
        add(timestamp=_ts(d, h, 0),
            src_ip="198.51.100.10",
            src_ip_cidr24="198.51.100.0",
            _source_type="network",
            _engagement_refs=["RH-ENG-2026-041"],
            event="SSH brute force bastion-vault-01",
            notes="Authorized — RH-ENG-2026-041 vault DMZ probe")
        add(timestamp=_ts(d, h, 5),
            src_ip="198.51.100.10",
            src_ip_cidr24="198.51.100.0",
            user_canonical="pentest-readonly-feb2026",
            _source_type="cloud",
            _engagement_refs=["RH-ENG-2026-041"],
            event="AccessDenied AssumeRole",
            notes="Authorized — RH-ENG-2026-041 IAM probe")

    # ── CHANGE-MANAGED OPS ──────────────────────────────────────────────────
    # CHG-2026-0184 — CrowdStrike sensor upgrade Feb 6, six hosts
    for host in ("sfl-lt-0118", "sfl-lt-0305", "sfl-lt-0442",
                 "sfl-lt-0448", "sfl-lt-0451", "sfl-lt-0453"):
        add(timestamp=_ts(6, 2, 14),
            hostname=host,
            _source_type="endpoint",
            _change_refs=["CHG-2026-0184"],
            event="CrowdStrike sensor 7.19.18714 → 7.20.19102",
            notes="CHG-2026-0184 sensor upgrade")

    # CHG-2026-0229 — EKS control plane upgrade Feb 18
    for h in (3, 3, 4, 4):
        add(timestamp=_ts(18, h, 55),
            hostname="eks-control-plane",
            _source_type="cloud",
            _change_refs=["CHG-2026-0229"],
            event="EKS control plane upgrade audit-sample",
            notes="CHG-2026-0229 EKS upgrade")

    # ── BAU SNOWFLAKE — must NOT enter campaign ────────────────────────────
    for d in (3, 4, 5, 11, 12, 13, 17, 24, 25):
        for user in ("sophie.reid", "kenji.watanabe", "analytics_service"):
            add(timestamp=_ts(d, 10, 0),
                user_canonical=user,
                src_ip="10.11.5.42",
                src_ip_cidr24="10.11.5.0",
                _source_type="cloud",
                event="SHOW TABLES",
                notes="snowflake BAU analytics query SnowSQL 1.3.1")

    # Aaron's BAU on Feb 16 morning (before compromise window) —
    # should NOT bridge to attacker activity at 01:21 because they share
    # user_canonical but the time gap (~6h) is at boundary. Adjusted to
    # 9 hours apart so the user-window does NOT bridge them.
    add(timestamp=_ts(16, 11, 0),
        user_canonical="aaron.blackwood",
        src_ip="10.11.5.50",
        src_ip_cidr24="10.11.5.0",
        _source_type="cloud",
        event="SHOW TABLES",
        notes="snowflake BAU query routine")

    return rows


# ── Tests ────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def fixture():
    rows = santos_synthetic_rows()
    clusters = transitive_merge_clusters(None, rows)
    return rows, clusters


def _by_kind(clusters: list[dict], kind: str) -> list[dict]:
    return [c for c in clusters if c.get("cluster_kind") == kind]


def test_t1_one_or_two_campaigns_covering_all_phases(fixture):
    """T1 — at most two VALIDATED_BREACH campaign components, jointly covering
    all five expected phase types. One is the ideal; two is acceptable when
    the data has a long inactive gap that even permissive infrastructure
    pivots can't bridge."""
    _, clusters = fixture
    campaigns = _by_kind(clusters, "campaign")
    assert 1 <= len(campaigns) <= 2, (
        f"Expected 1-2 campaigns, got {len(campaigns)}. "
        f"Phase ids per campaign: {[[p['phase_id'] for p in c['phases']] for c in campaigns]}"
    )
    for c in campaigns:
        assert c["verdict"] == "VALIDATED_BREACH"
    all_phase_ids: set[str] = set()
    for c in campaigns:
        all_phase_ids.update(p["phase_id"] for p in c["phases"])
    expected = {
        "credential_theft",
        "data_exfiltration_snowflake",
        "data_exfiltration_rclone",
        "privilege_escalation_k8s",
        "c2_dns_beacon",
    }
    missing = expected - all_phase_ids
    assert not missing, f"Missing expected phases across all campaigns: {missing}"


def test_t2_pentest_cluster_bound_to_engagement_ref(fixture):
    """T2 — pentest cluster has engagement_ref and BENIGN_EXPECTED verdict."""
    _, clusters = fixture
    pentests = _by_kind(clusters, "pentest")
    assert len(pentests) == 1
    p = pentests[0]
    assert p["verdict"] == "BENIGN_EXPECTED"
    assert "RH-ENG-2026-041" in p["engagement_refs"]
    assert p["row_count"] >= 18


def test_t3_escalation_row_in_campaign_not_pentest(fixture):
    """T3 — Feb 22 escalation row bridges into the campaign, not the pentest.

    This is the bridge the architectural review called out as critical:
    a pentest-tagged row that ALSO carries phase signatures must drag its
    component into the campaign bucket, not remain inside the pentest scope.
    """
    rows, clusters = fixture
    escalation = next(
        r for r in rows
        if "ESCALATION" in str(r.get("event", "")) and "OneDriveUpdate" in str(r.get("notes", ""))
    )
    eidx = escalation["row_index"]

    campaign = _by_kind(clusters, "campaign")[0]
    pentest  = _by_kind(clusters, "pentest")[0]

    # Escalation row must appear in SOME campaign cluster (there may be 1 or 2)
    all_campaign_refs = set()
    all_campaign_eng_refs = set()
    for c in _by_kind(clusters, "campaign"):
        all_campaign_refs.update(c["row_refs"])
        all_campaign_eng_refs.update(c.get("engagement_refs", []))

    assert eidx in all_campaign_refs, "Escalation row must be in the campaign."
    assert eidx not in pentest["row_refs"], "Escalation row must NOT be in the pentest scope."
    # Sanity: the engagement_ref should still be carried as evidence inside the
    # campaign so analysts see the bridge context.
    assert "RH-ENG-2026-041" in all_campaign_eng_refs


def test_t4_change_refs_collapse_into_ops(fixture):
    """T4 — change_refs each produce one ops cluster (or merge into one)."""
    _, clusters = fixture
    ops = _by_kind(clusters, "ops")
    refs = {r for c in ops for r in c["change_refs"]}
    assert {"CHG-2026-0184", "CHG-2026-0229"} <= refs
    # Each change ref should appear in exactly one ops cluster (no fragmenting)
    for ref in ("CHG-2026-0184", "CHG-2026-0229"):
        owners = [c for c in ops if ref in c["change_refs"]]
        assert len(owners) == 1, f"{ref} fragmented across {len(owners)} clusters"


def test_t5_canonical_user_joins_across_sources(fixture):
    """T5 — Aaron's canonical user spans cloud and other sources in the campaign."""
    rows, clusters = fixture
    campaigns = _by_kind(clusters, "campaign")
    rows_by_idx = {r["row_index"]: r for r in rows}
    # Aaron should be in some campaign cluster (may be campaign[0] or [1])
    all_campaign_refs = set()
    for c in campaigns:
        all_campaign_refs.update(c["row_refs"])
    src_for_aaron = {
        rows_by_idx[i].get("_source_type")
        for i in all_campaign_refs
        if rows_by_idx[i].get("user_canonical") == "aaron.blackwood"
        and not rows_by_idx[i].get("notes", "").startswith("snowflake BAU")
    }
    assert "cloud" in src_for_aaron
    # And the Aaron BAU row from 9h after compromise must NOT be in any campaign
    aaron_bau_idx = next(
        r["row_index"] for r in rows
        if r.get("user_canonical") == "aaron.blackwood"
        and "BAU" in str(r.get("notes", ""))
    )
    assert aaron_bau_idx not in all_campaign_refs, \
        "Aaron BAU 9h after compromise leaked into campaign (USER_WINDOW too wide)"


def test_t6_cidr24_joins_45_133_193(fixture):
    """T6 — /24 CIDR pivot joins 45.133.193.42 and 45.133.193.118."""
    rows, clusters = fixture
    campaign = _by_kind(clusters, "campaign")[0]
    rows_by_idx = {r["row_index"]: r for r in rows}
    dst_ips_in_campaign = {
        rows_by_idx[i].get("dst_ip")
        for i in campaign["row_refs"]
        if rows_by_idx[i].get("dst_ip")
    }
    src_ips_in_campaign = {
        rows_by_idx[i].get("src_ip")
        for i in campaign["row_refs"]
        if rows_by_idx[i].get("src_ip")
    }
    all_ips_seen = dst_ips_in_campaign | src_ips_in_campaign
    assert "45.133.193.42" in all_ips_seen
    assert "45.133.193.118" in all_ips_seen


def test_t7_snowflake_bau_does_not_enter_campaign(fixture):
    """T7 — BAU Snowflake users (SOPHIE.REID etc.) do NOT enter the campaign."""
    rows, clusters = fixture
    campaign = _by_kind(clusters, "campaign")[0]
    rows_by_idx = {r["row_index"]: r for r in rows}
    bau_users = {"sophie.reid", "kenji.watanabe", "analytics_service"}
    leaked = [
        i for i in campaign["row_refs"]
        if rows_by_idx[i].get("user_canonical") in bau_users
    ]
    assert not leaked, (
        f"BAU Snowflake users leaked into campaign. "
        f"Leaked rows: {[(i, rows_by_idx[i].get('user_canonical'), rows_by_idx[i].get('event')) for i in leaked]}"
    )


def test_t8_dns_beacon_collapses_by_signature(fixture):
    """T8 — DNS beacon rows collapse into one phase, not many cases."""
    _, clusters = fixture
    campaign = _by_kind(clusters, "campaign")[0]
    beacon_phase = next(p for p in campaign["phases"] if p["phase_id"] == "c2_dns_beacon")
    assert beacon_phase["row_count"] >= 7, "DNS beacon rows should aggregate into one phase"


def test_t9_top_card_count_bounded(fixture):
    """T9 — top-card count is bounded; raw audit detail is preserved separately.

    cluster_merge produces analysis_clusters; the count of CAMPAIGN+PENTEST+OPS
    components is what the user sees on the page. UNCLASSIFIED components stay
    as a single rolled-up bucket downstream in threat_case_builder.
    """
    rows, clusters = fixture
    surfaced = [c for c in clusters
                if c["cluster_kind"] in ("campaign", "pentest", "ops")]
    assert len(surfaced) <= 6, f"Too many surfaced clusters: {len(surfaced)}"
    # Audit trail: the scope-qualified pivot inventory is preserved
    from src.core.ingest.cluster_merge import build_scope_qualified_pivots
    pivots = build_scope_qualified_pivots(rows)
    assert len(pivots) >= 20, "Pivot inventory should be substantial"


def test_t10_provenance_phase_row_refs_resolve(fixture):
    """T10 — every phase's row_refs resolve to telemetry-evidence rows."""
    rows, clusters = fixture
    rows_by_idx = {r["row_index"]: r for r in rows}
    campaign = _by_kind(clusters, "campaign")[0]
    for phase in campaign["phases"]:
        assert phase["row_count"] > 0
        for ref in phase["row_refs"]:
            assert isinstance(ref, int)
            row = rows_by_idx[ref]
            assert row.get("_lane", "telemetry_evidence") == "telemetry_evidence"


def test_unclassified_bucket_exists(fixture):
    """Sanity: BAU activity becomes unclassified components, not noise dropped."""
    _, clusters = fixture
    unc = _by_kind(clusters, "unclassified")
    # BAU Snowflake rows form unclassified components; sophie/kenji/analytics
    # should each form their own (or a merged one via shared 10.11.5.0/24).
    assert unc, "BAU activity should produce unclassified components, not be dropped"


def test_severity_ordering(fixture):
    """Sanity: the campaign sorts above pentest and ops."""
    _, clusters = fixture
    surfaced = [c for c in clusters if c["cluster_kind"] != "unclassified"]
    if len(surfaced) >= 2:
        assert surfaced[0]["cluster_kind"] == "campaign", \
            f"Campaign should sort first; got {surfaced[0]['cluster_kind']}"
