"""Transitive merge of raw pivot groups into campaign / pentest / ops / unclassified
analysis clusters.

Replaces the per-pivot one-cluster-each loop in
``assessment_worker.run_assessment_pipeline`` with evidence-bound, time-windowed
transitive merging using union-find over row indices.

Design notes
------------

The previous active path materialised one cluster per pivot key from
``store.entity_pivot_groups`` (capped at 200). That fragments multi-domain
intrusions whose phases share *different* pivot keys (an attacker's external
IP is distinct from the asset they touched, which is distinct from the user
whose key they abused), and produces N near-identical "shared pivot X" rows
for benign change-management activity.

This module is the missing transitive-merge step. Inputs are evidence-only —
``_lane`` blocked rows must be filtered upstream by ``threat_case_builder`` —
so any merge here is auditable back to telemetry.

Merge rules (applied in order, all evidence-bound)
--------------------------------------------------

R1  Same canonical user across rows within ``USER_WINDOW``.
    Tight window (6h) deliberately avoids merging a user's BAU activity on
    Day N+1 with their compromised activity on Day N. Cross-day persistence
    of the same actor is bridged through R2 (external IP) or R7 (signature).

R2  Same external IP across rows within ``IP_WINDOW``.
    Permissive window (60d) — an external attacker IP touching multiple
    things over weeks is the same actor.

R3  Same /24 CIDR across rows within ``CIDR_WINDOW``.
    Tighter window (24h) because CIDRs include CGN ranges that should not
    bridge a month of unrelated activity.

R4  Cross-domain shared external IP (same IP appears in cloud, k8s, snowflake)
    within ``CROSS_DOMAIN_IP_WINDOW`` (2h). This is the specific Santos
    Feb 16 burst signature.

R5  Same engagement_ref. Unbounded window — engagements are bounded by
    their own ref. ``RH-ENG-2026-041`` rows union into one pentest cluster
    regardless of when they fire.

R6  Same change_ref. Unbounded window. ``CHG-2026-0184`` rows union into
    one ops cluster.

R7  Same ``event_signature`` (e.g. ``dns:nrd_lowrep``) within ``SIG_WINDOW``
    (14d). Collapses 78 individual DNS-beacon alerts into one.

Component classification
------------------------

After unioning, each component is tagged ``cluster_kind``:

  ``campaign``     — at least one phase detector fires on any member row.
                     Verdict: VALIDATED_BREACH.
  ``pentest``      — every member row carries an ``engagement_ref`` AND no
                     phase detector fires. Verdict: BENIGN_EXPECTED.
  ``ops``          — every member row carries a ``change_ref`` AND no phase
                     detector fires. Verdict: BENIGN_EXPECTED.
  ``unclassified`` — anything else. Verdict: NO_VALIDATED_BREACH.

The pentest classification deliberately requires *no* phase detector hit,
which is the bridge case that a pure pentest-allowlist would suppress.
A row tagged with both ``RH-ENG-2026-041`` AND an LSASS/Rclone/K8s phase
will pull its component into the campaign bucket, taking the engagement
context with it as evidence.

Phase detectors are tightened versions of the previous
``threat_case_builder._MATERIAL_PATTERNS``. The single biggest tightening:
``data_exfiltration_snowflake`` no longer fires on the bare term
``"snowflake"`` — it requires UNLOAD verbs co-occurring with an external
destination, OR a large ``rows_produced`` value with co-occurring verbs.
This is what stops ~3,300 BAU Snowflake queries showing up as VALIDATED_BREACH
evidence.
"""
from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)


# Bump when merge logic changes so assessment_worker can detect stale cluster outputs.
_CLUSTER_MERGE_VERSION = "1.5"

# ── Time windows (seconds) per pivot type ────────────────────────────────────
USER_WINDOW             = 6 * 3600          # 6h burst
USER_CAMPAIGN_WINDOW    = 30 * 86_400       # 30d — same user across multi-phase campaign
IP_WINDOW               = 60 * 86_400       # ~unbounded within an assessment
CIDR_WINDOW             = 24 * 3600         # 24h
CROSS_DOMAIN_IP_WINDOW  = 2 * 3600          # 2h (cloud/k8s/sf shared-IP burst)
HOST_WINDOW             = 14 * 86_400       # 14d (compromised host stays compromised)
SIG_WINDOW              = 14 * 86_400       # 14d (DNS beacon campaign span)
ENG_WINDOW              = 365 * 86_400      # unbounded — engagements own their boundary
CHG_WINDOW              = 365 * 86_400      # unbounded — change tickets own their boundary
SESSION_WINDOW          = 6 * 3600          # 6h


# ── Phase detectors ──────────────────────────────────────────────────────────
@dataclass
class PhaseDetector:
    phase_id: str
    name: str
    case_role: str
    severity: str   # critical | high | medium | low
    matcher: Callable[[dict, str], bool]


def _det_lsass(_row: dict, text: str) -> bool:
    return any(t in text for t in (
        "lsass", "comsvcs", "mimikatz", "procdump", "ntds.dit",
        "credential dump", "credential dumping",
    ))


def _det_sf_unload(row: dict, text: str) -> bool:
    """Snowflake bulk unload — requires UNLOAD verb AND external destination,
    OR a large rows_produced value with co-occurring verb. Bare "snowflake"
    no longer fires."""
    has_verb = ("copy into" in text) or ("unload" in text)
    has_external = any(s in text for s in (
        "external stage", "s3://", "azure://", "azure-blob", "gcs://",
        "@~/", "stage_url", "external_stage",
    ))
    if has_verb and has_external:
        return True
    rp = row.get("rows_produced") or row.get("bytes_scanned") or row.get("rows") or 0
    try:
        if float(rp) > 1_000_000 and has_verb:   # 1M rows produced + verb
            return True
    except (TypeError, ValueError):
        pass
    return False


def _det_rclone(_row: dict, text: str) -> bool:
    return any(t in text for t in (
        "rclone", "mega.nz", "backblaze", "b2.backblazeb2", "wasabi",
        "rclone copy", "rclone sync",
    ))


def _det_k8s_escape(_row: dict, text: str) -> bool:
    if "hostpath" in text or "hostpid" in text or "host-root" in text:
        return True
    if "privileged" in text and any(t in text for t in ("container", "daemonset", "pod", "exec")):
        return True
    if "falco" in text and ("priv" in text or "escape" in text or "kubelet" in text):
        return True
    return False


def _det_dns_beacon(_row: dict, text: str) -> bool:
    return any(t in text for t in (
        "low reputation", "low-reputation", "newly registered", "newly-registered",
        "nrd ", "nrd<", "dns beacon", "periodic dns", "c2 beacon",
        "command-and-control", "command and control",
    ))


def _det_session_theft(_row: dict, text: str) -> bool:
    return any(t in text for t in (
        "impossible travel", "session.access_admin_app", "admin app access",
        "access_admin_app", "token replay", "token theft", "session hijack",
    ))


def _det_secret_access(_row: dict, text: str) -> bool:
    return any(t in text for t in (
        "getsecretvalue", "secretsmanager:getsecret", "sts:assumerole",
        "assume role from", "assumerolewithsaml", "sts:getfederationtoken",
    ))


def _det_payload_blocked_but_followed(row: dict, text: str) -> bool:
    """Recon attempt that was prevented but produced a follow-on success.
    Currently a placeholder — the actual signal is row.triage_score >= 0.65 + tag."""
    return False


def _det_pentest_escalation(row: dict, text: str) -> bool:
    """Pentest operator escalation — human intel signal that engagement-tagged
    artifacts are actually non-engagement (real threat).  The Feb 22 Santos case:
    action_taken=ESCALATED + description naming non-playbook artifacts."""
    action = str(row.get('action_taken') or row.get('action') or '').lower()
    if action == 'escalated':
        return True
    return any(t in text for t in (
        'action_taken": "escalated', 'action_taken":"escalated',
        'escalated to soc', 'escalated to ir', 'not matching', 'pre-existing intrusion',
    ))


def _det_email_inbox_rule(row: dict, text: str) -> bool:
    """T1114.003 / T1564.008 — inbox forwarding rule or inbox-rule creation."""
    op = str(row.get('Operation') or row.get('operation') or row.get('event_name') or '').lower()
    if op in ('new-inboxrule', 'set-inboxrule', 'newinboxrule', 'setinboxrule',
              'add-mailboxpermission', 'set-mailboxautoreply'):
        return True
    return any(t in text for t in (
        'new-inboxrule', 'forwardto', 'forwardingaddress', 'redirectto',
        'forwarding_smtp', 'newinboxrule',
    ))


def _det_email_external_exfil(row: dict, text: str) -> bool:
    """T1567.002 — email with attachments sent to an external recipient domain."""
    if row.get('external_recipient_domain'):
        att = row.get('AttachmentCount') or row.get('attachment_count') or 0
        try:
            att = int(att)
        except (TypeError, ValueError):
            att = 0
        if att > 0:
            return True
    return any(t in text for t in (
        'externalaccess', 'external_recipient_domain', 'sinobiz', 'ccp-exfil',
    ))


def _det_bulk_sensitive_download(row: dict, text: str) -> bool:
    """T1213.002 — bulk download of SharePoint/OneDrive sensitive files."""
    _SENSITIVE_TOKENS = (
        'payroll', 'acquisition', 'merger', 'novabridge', 'ip-schedule',
        'infra-map', 'capex', 'q1-projections', 'merger-ip', 'sensitive_document_bulk_download',
    )
    if row.get('_sensitivity') == 'high':
        return True
    return any(t in text for t in _SENSITIVE_TOKENS)


def _det_bastion_rdp(row: dict, text: str) -> bool:
    """T1021.001 — mstsc.exe / port 3389 lateral movement."""
    proc = str(row.get('process_name') or row.get('process') or '').lower()
    if 'mstsc' in proc:
        return True
    try:
        port = int(row.get('dst_port') or row.get('port') or 0)
        if port == 3389:
            return True
    except (TypeError, ValueError):
        pass
    return any(t in text for t in ('mstsc', 'mstsc.exe', 'remote desktop', ':3389'))


def _det_identity_ip_anomaly(row: dict, text: str) -> bool:
    """Pre-tagged _anomaly=user_ip_drift OR _cluster seeded with known exfil label."""
    if str(row.get('_anomaly') or '').lower() == 'user_ip_drift':
        return True
    cluster_tag = str(row.get('_cluster') or '').lower()
    return 'exfil' in cluster_tag or 'anomaly' in cluster_tag


PHASE_DETECTORS: list[PhaseDetector] = [
    PhaseDetector("credential_theft",          "Credential Theft (LSASS)",        "credential_theft",     "critical", _det_lsass),
    PhaseDetector("data_exfiltration_snowflake","Snowflake Bulk Unload",          "data_exfiltration",    "critical", _det_sf_unload),
    PhaseDetector("data_exfiltration_rclone",  "Rclone Cloud Exfiltration",       "data_exfiltration",    "critical", _det_rclone),
    PhaseDetector("privilege_escalation_k8s",  "K8s Privileged Container Escape", "privilege_escalation", "critical", _det_k8s_escape),
    PhaseDetector("c2_dns_beacon",             "Low-Reputation DNS Beaconing",    "c2_communication",     "high",     _det_dns_beacon),
    PhaseDetector("session_theft",             "Session Theft / Token Replay",    "initial_access",       "high",     _det_session_theft),
    PhaseDetector("secret_access",             "AWS Secret / STS Abuse",          "privilege_escalation", "high",     _det_secret_access),
    PhaseDetector("pentest_escalation",        "Pentest Operator Escalation",     "escalation_bridge",    "high",     _det_pentest_escalation),
    PhaseDetector("email_inbox_rule_abuse",    "Email Inbox Rule Abuse (T1114.003)","persistence",         "high",     _det_email_inbox_rule),
    PhaseDetector("email_external_exfil",      "Email External Exfiltration",     "exfiltration",         "critical", _det_email_external_exfil),
    PhaseDetector("sharepoint_bulk_download",  "SharePoint Bulk Sensitive Download","collection",          "high",     _det_bulk_sensitive_download),
    PhaseDetector("bastion_rdp_lateral",       "Bastion RDP Lateral Movement",    "lateral_movement",     "high",     _det_bastion_rdp),
    PhaseDetector("identity_ip_anomaly",       "Identity IP Anomaly (user_ip_drift)","initial_access",     "high",     _det_identity_ip_anomaly),
]


def detect_row_phase_tags(row: dict) -> set[str]:
    """Return the set of phase_ids that fire on a single row."""
    text = _row_text(row)
    hits: set[str] = set()
    for det in PHASE_DETECTORS:
        try:
            if det.matcher(row, text):
                hits.add(det.phase_id)
        except Exception:   # noqa: BLE001
            continue
    return hits


def _row_scope_suffix(row: dict, phase_tags: set[str]) -> str:
    """Compute the scope qualification suffix for a row's pivot keys.

    Returns:
        "" — unqualified. Used for: phase-tagged (campaign) rows AND
             unscoped/noise rows. These can union freely.
        "|eng:<refs>" — pentest scope. Only unions with same-engagement rows.
        "|chg:<refs>" — ops scope. Only unions with same-change rows.

    Phase-tagged rows are intentionally promoted to unqualified scope even if
    they carry engagement_ref — this is the Feb-22-escalation bridge case.
    The engagement_ref is preserved on the row for evidence display, but
    pivot membership uses unqualified keys so the row joins the campaign.
    """
    if phase_tags:
        return ""
    refs_e = row.get("_engagement_refs") or row.get("engagement_refs") or []
    if refs_e:
        return "|eng:" + ",".join(sorted(str(r).upper() for r in refs_e))
    refs_c = row.get("_change_refs") or row.get("change_refs") or []
    if refs_c:
        return "|chg:" + ",".join(sorted(str(r).upper() for r in refs_c))
    return ""


def build_scope_qualified_pivots(rows: list[dict]) -> dict[str, list[int]]:
    """Build pivot_groups from rows with scope qualification.

    This is the canonical pivot construction for cluster_merge. The
    SQL-side ``store.entity_pivot_groups`` is preserved for the audit-trail
    raw_correlation_clusters output, but the actual transitive merge runs on
    these scope-qualified pivots so that engagement-bound activity does NOT
    bridge into the campaign through shared infrastructure pivots (CIDR,
    host, etc.).

    Pivot dimensions emitted (per row, all scope-suffixed except as noted):
        canon_user:<user_canonical>
        ip:<src_ip>
        ip:<dst_ip>            (outbound-attacker IP exposure)
        cidr24:<src_ip_cidr24>
        cidr24:<dst_ip_cidr24>
        host:<hostname>
        sig:<event_signature>

    Plus unsuffixed scope-anchor pivots:
        engagement:<ref>       (only emitted by pentest-scope rows)
        change:<ref>           (only emitted by ops-scope rows)
    """
    out: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        try:
            idx = int(r.get("row_index"))
        except (TypeError, ValueError):
            continue
        phase_tags = detect_row_phase_tags(r)
        suffix = _row_scope_suffix(r, phase_tags)

        u = _lower(r.get("user_canonical") or r.get("user"))
        if u and u not in ("-", "n/a", "system", "root"):
            out[f"canon_user:{u}{suffix}"].append(idx)
            # Phase-tagged rows also get a wide-window campaign pivot so the same
            # user bridges across multi-phase attacks that span days (e.g. Feb 10
            # session theft → Feb 16 AWS abuse → Feb 22 exfil, same user, different IPs).
            if phase_tags:
                out[f"canon_user_breach:{u}"].append(idx)

        for fld in ("src_ip", "dst_ip"):
            ip = _str(r.get(fld))
            if ip and ip not in ("-", "0.0.0.0"):
                out[f"ip:{ip}{suffix}"].append(idx)

        for fld in ("src_ip_cidr24", "dst_ip_cidr24"):
            cidr = _str(r.get(fld))
            # Only use CIDR pivots for public IPs — RFC1918 subnets link every
            # internal host in the same /24, creating massive noise clusters.
            if cidr and _is_public_ip(cidr):
                out[f"cidr24:{cidr}{suffix}"].append(idx)

        host = _lower(r.get("hostname") or r.get("host"))
        if host:
            out[f"host:{host}{suffix}"].append(idx)

        sig = _str(r.get("event_signature"))
        if sig:
            out[f"sig:{sig}{suffix}"].append(idx)

        # Attacker-zone pivot: network rows classified as attacker infrastructure
        # (e.g. zone_dst: "attacker_c2") share a pivot so that C2 rotation across
        # different IP ranges still merges into one campaign.  Uses SIG_WINDOW (14d).
        for zone_fld in ("zone_dst", "zone_src"):
            zone = _lower(r.get(zone_fld))
            if zone and zone.startswith("attacker"):
                out[f"attacker_zone:{zone}{suffix}"].append(idx)

        # Scope-anchor pivots — emitted ONLY when scope matches.
        # An engagement-tagged-only row's engagement: pivot unions it with
        # other pentest-scope rows that share the same engagement.
        # A campaign-scope row that ALSO carries engagement_ref does NOT
        # emit engagement: pivot — its engagement context travels with the
        # row for display, but doesn't pull it into the pentest cluster.
        if not phase_tags:
            for ref in (r.get("_engagement_refs") or r.get("engagement_refs") or []):
                out[f"engagement:{str(ref).upper()}"].append(idx)
            for ref in (r.get("_change_refs") or r.get("change_refs") or []):
                out[f"change:{str(ref).upper()}"].append(idx)

        # ── IAM operation pivot (24h burst window) ──────────────────────────
        # Groups rows sharing the same suspicious IAM operation within 24h.
        # Skips BAU operations that fire hundreds of times a day.
        _BAU_OPS = frozenset({
            'mailitemsaccessed', 'filedownloaded', 'pageviewed', 'filesyncdownloaded',
            'searchqueryperformed', 'signin', 'userloggedin', 'userloggedout',
        })
        for _op_fld in ('Operation', 'operation', 'event_name'):
            _op = _lower(r.get(_op_fld))
            if _op and _op not in _BAU_OPS and len(_op) >= 4:
                out[f"iam_op:{_op}{suffix}"].append(idx)
                break

        # ── External recipient domain pivot (7d exfil channel) ──────────────
        # Correlates all rows that sent to the same external domain within 7d.
        _ext_dom = _lower(r.get('external_recipient_domain') or r.get('ForwardingSmtpAddress'))
        if _ext_dom and '@' not in _ext_dom and '.' in _ext_dom and len(_ext_dom) >= 4:
            # Strip leading '@' that might appear in forwarding address fields
            _ext_dom = _ext_dom.lstrip('@').split('@')[-1]
            out[f"recipient_domain:{_ext_dom}"].append(idx)

        # ── Pre-tagged seed pivot (7d campaign window) ─────────────────────
        # Ground-truth labels (_cluster / _anomaly) from test fixtures or SIEM
        # pre-enrichment bridge all rows with the same label into one cluster.
        for _seed_fld in ('_cluster', '_anomaly'):
            _seed_val = _lower(r.get(_seed_fld))
            if _seed_val and len(_seed_val) >= 4 and _seed_val not in ('n/a', 'none', 'unknown'):
                out[f"seed:{_seed_val}"].append(idx)

    return dict(out)

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── Union-find ───────────────────────────────────────────────────────────────
class _UF:
    __slots__ = ("parent", "rank")

    def __init__(self) -> None:
        self.parent: dict[int, int] = {}
        self.rank: dict[int, int] = {}

    def find(self, x: int) -> int:
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0
            return x
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        # Path compression
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: int, b: int) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1
        return True


# ── Timestamp parsing ────────────────────────────────────────────────────────
_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)


def _epoch(ts: Any) -> float:
    """Best-effort epoch extraction. Returns 0.0 if unparseable."""
    if ts is None or ts == "":
        return 0.0
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts).strip()
    if not s:
        return 0.0
    # ISO with timezone
    try:
        # Python 3.11+ handles most ISO variants natively
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, OSError):
        pass
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s, fmt).timestamp()
        except (ValueError, OSError):
            continue
    try:
        return float(s)
    except (TypeError, ValueError):
        return 0.0


# ── Pivot-key window registry ────────────────────────────────────────────────
_PREFIX_WINDOW: list[tuple[str, float]] = [
    # Specific prefixes first (longest-match)
    ("canon_user_breach:", USER_CAMPAIGN_WINDOW),  # phase-tagged rows: 30d bridge
    ("canon_user:",  USER_WINDOW),
    ("engagement:",  ENG_WINDOW),
    ("change:",      CHG_WINDOW),
    ("session:",     SESSION_WINDOW),
    ("cross_ip:",    CROSS_DOMAIN_IP_WINDOW),
    ("attacker_zone:", SIG_WINDOW),       # C2 rotation bridge: 14d
    ("cidr24:",      CIDR_WINDOW),
    ("sig:",         SIG_WINDOW),
    ("host:",        HOST_WINDOW),
    ("h2:",          HOST_WINDOW),     # legacy from streaming_ingest
    ("usr:",         USER_WINDOW),     # legacy
    ("user:",        USER_WINDOW),     # legacy from store.entity_pivot_groups
    ("ip:",          IP_WINDOW),
    # IAM / email exfiltration pivots (Sprint 1 — 2025)
    ("recipient_domain:", 7 * 86_400),   # 7d: external exfil channel correlation
    ("iam_op:",      24 * 3600),         # 24h: burst of same IAM operation
    ("seed:",        7 * 86_400),        # 7d: pre-tagged _cluster/_anomaly ground truth
]


def _window_for(pivot_key: str) -> float:
    for prefix, window in _PREFIX_WINDOW:
        if pivot_key.startswith(prefix):
            return window
    return IP_WINDOW   # default permissive


# ── Public entrypoint ────────────────────────────────────────────────────────
def transitive_merge_clusters(
    pivot_groups: dict[str, list[int]] | None,
    rows: list[dict],
    *,
    min_component_size: int = 2,
    pivot_keys_per_cluster_cap: int = 50,
    use_scope_qualified_pivots: bool = True,
    diagnostics_out: dict | None = None,
) -> list[dict]:
    """Merge pivot groups into components via union-find with time-windowed unions.

    Args:
        pivot_groups: from ``store.entity_pivot_groups`` —
            ``{pivot_key: [row_index, ...]}``. May be ``None`` or empty; when
            ``use_scope_qualified_pivots`` is True (default), pivots are
            re-derived from rows with scope qualification (recommended path).
            The SQL-side pivots are still useful as raw_correlation_clusters
            audit output but should not drive the merge directly because
            they lack engagement/change scope qualification.
        rows: list of normalized rows. Required fields: ``row_index``,
            ``timestamp`` (or ``_ts_epoch``). Recommended fields:
            ``user_canonical``, ``src_ip``, ``src_ip_cidr24``, ``dst_ip``,
            ``dst_ip_cidr24``, ``_source_type``, ``_engagement_refs``,
            ``_change_refs``, ``event_signature``.
        min_component_size: drop components smaller than this from the
            output. Singleton rows still appear in the upstream
            ``raw_correlation_clusters`` for audit; this only affects what
            shows up in analysis_clusters.
        pivot_keys_per_cluster_cap: cap on pivot keys reported per component
            (avoid 5MB JSON payloads when a CGN /24 unifies thousands).
        use_scope_qualified_pivots: when True (default), ignore the supplied
            ``pivot_groups`` and rebuild from rows using
            ``build_scope_qualified_pivots``. Set False only for backwards
            compatibility with callers that have already qualified pivots.

    Returns:
        list of analysis_cluster dicts, sorted by severity then row count.
        Each cluster has ``cluster_kind``, ``verdict``, ``phases`` (campaigns
        only), ``engagement_refs``, ``change_refs``, ``row_refs``, and entity
        rollups.
    """
    if not rows:
        if diagnostics_out is not None:
            diagnostics_out.update({"pivot_count": 0, "component_count": 0, "singleton_drop_count": 0, "phase_hit_count": 0, "stale_rows": 0})
        return []

    # Count stale rows (stored before normalizer produced canonical fields).
    stale_row_count = sum(
        1 for r in rows
        if not r.get('user_canonical') and not r.get('src_ip') and not r.get('hostname')
    )

    if use_scope_qualified_pivots or not pivot_groups:
        pivot_groups = build_scope_qualified_pivots(rows)
    if not pivot_groups:
        if diagnostics_out is not None:
            diagnostics_out.update({"pivot_count": 0, "component_count": 0, "singleton_drop_count": len(rows), "phase_hit_count": 0, "stale_rows": stale_row_count})
        return []

    row_by_idx: dict[int, dict] = {}
    for r in rows:
        try:
            row_by_idx[int(r.get("row_index"))] = r
        except (TypeError, ValueError):
            continue
    if not row_by_idx:
        return []

    ts_by_idx: dict[int, float] = {}
    for idx, r in row_by_idx.items():
        ts = r.get("_ts_epoch")
        if ts is None:
            ts = _epoch(r.get("timestamp"))
        ts_by_idx[idx] = float(ts) if ts else 0.0

    uf = _UF()
    # Pre-touch every row so isolated rows form singleton components.
    for idx in row_by_idx:
        uf.find(idx)

    # ── Pass 1: window-bounded chain unioning per pivot key ──────────────────
    # For each pivot key, sort members by timestamp and walk a sliding-window
    # chain. Two members union iff they are within the pivot's window of *each
    # other*. Transitive closure across pivots is implicit through union-find.
    for pivot_key, member_idxs in pivot_groups.items():
        window = _window_for(pivot_key)
        members = [i for i in member_idxs if i in row_by_idx]
        if len(members) < 2:
            continue
        members.sort(key=lambda i: ts_by_idx.get(i, 0.0))
        # Sliding-window: union each member with the previous one if within
        # window; otherwise, this member starts a new sub-chain. The chain
        # acts as the transitive bridge for that pivot.
        # Epoch-zero means the timestamp was not parsed — treat as unknown
        # and allow the merge rather than blocking on a bogus 1970 offset.
        prev_idx = members[0]
        for cur_idx in members[1:]:
            t_prev = ts_by_idx.get(prev_idx, 0.0)
            t_cur = ts_by_idx.get(cur_idx, 0.0)
            if t_prev == 0.0 or t_cur == 0.0 or (t_cur - t_prev) <= window:
                uf.union(prev_idx, cur_idx)
            prev_idx = cur_idx

    # ── Pass 2: collect components ───────────────────────────────────────────
    comp_members: dict[int, list[int]] = defaultdict(list)
    for idx in row_by_idx:
        comp_members[uf.find(idx)].append(idx)

    # Build a reverse index: which pivot keys touched each component.
    # A pivot key "touches" a component if any of its row indices is in it.
    pivot_index: dict[int, set[str]] = defaultdict(set)
    for pivot_key, member_idxs in pivot_groups.items():
        roots_seen: set[int] = set()
        for idx in member_idxs:
            if idx in row_by_idx:
                roots_seen.add(uf.find(idx))
        for root in roots_seen:
            pivot_index[root].add(pivot_key)

    # ── Pass 3: classify each component ──────────────────────────────────────
    out: list[dict] = []
    isolated: list[dict] = []
    for root, member_idxs in comp_members.items():
        if len(member_idxs) < min_component_size:
            continue
        cluster = _classify_component(
            root,
            member_idxs,
            row_by_idx,
            ts_by_idx,
            pivot_keys_used=sorted(pivot_index.get(root, set()))[:pivot_keys_per_cluster_cap],
            pivot_key_total=len(pivot_index.get(root, set())),
        )
        # Unclassified single-source components are BAU activity groups, not
        # cross-domain intrusion signals. Bucket them as isolated telemetry so
        # they don't pad the cluster count with noise cards.
        if (
            cluster.get("cluster_kind") == "unclassified"
            and len(cluster.get("sources", [])) < 2
        ):
            cluster["_isolated"] = True
            isolated.append(cluster)
        else:
            out.append(cluster)

    out.sort(key=lambda c: (
        _SEV_ORDER.get(str(c.get("severity", "low")), 9),
        -int(c.get("row_count", 0)),
    ))

    if diagnostics_out is not None:
        singleton_drops = sum(1 for members in comp_members.values() if len(members) < min_component_size)
        phase_hits = sum(1 for c in out if c.get("phases"))
        diagnostics_out.update({
            "pivot_count": len(pivot_groups),
            "component_count": len(out),
            "isolated_count": len(isolated),
            "singleton_drop_count": singleton_drops,
            "phase_hit_count": phase_hits,
            "stale_rows": stale_row_count,
            "cluster_merge_version": _CLUSTER_MERGE_VERSION,
        })

    # Append isolated clusters at the end with a sentinel so callers can
    # split them out for the isolated_count header without losing audit data.
    return out + isolated


def _classify_component(
    root: int,
    member_idxs: list[int],
    row_by_idx: dict[int, dict],
    ts_by_idx: dict[int, float],
    *,
    pivot_keys_used: list[str],
    pivot_key_total: int,
) -> dict:
    member_rows = [row_by_idx[i] for i in member_idxs]

    # ── Phase detection ──
    phase_hits: dict[str, list[int]] = defaultdict(list)
    for r in member_rows:
        text = _row_text(r)
        for det in PHASE_DETECTORS:
            try:
                if det.matcher(r, text):
                    phase_hits[det.phase_id].append(int(r.get("row_index")))
            except Exception:   # noqa: BLE001 — detector errors must not fail clustering
                logger.debug("phase detector %s raised on row %s", det.phase_id, r.get("row_index"), exc_info=True)
                continue

    has_phase = bool(phase_hits)

    # ── Engagement / change ref aggregation ──
    engagement_refs: set[str] = set()
    change_refs: set[str] = set()
    rows_with_engagement = 0
    rows_with_change = 0
    for r in member_rows:
        ers = r.get("_engagement_refs") or r.get("engagement_refs") or []
        crs = r.get("_change_refs") or r.get("change_refs") or []
        if ers:
            rows_with_engagement += 1
            for ref in ers:
                engagement_refs.add(str(ref).upper())
        if crs:
            rows_with_change += 1
            for ref in crs:
                change_refs.add(str(ref).upper())

    n = len(member_rows)
    all_have_engagement = engagement_refs and rows_with_engagement == n
    all_have_change     = change_refs    and rows_with_change    == n

    # ── Decide cluster_kind ──
    if has_phase:
        kind = "campaign"
        verdict = "VALIDATED_BREACH"
        analysis_classification = "confirmed_breach"
        firing = [d for d in PHASE_DETECTORS if d.phase_id in phase_hits]
        severity = min(
            (_SEV_ORDER.get(d.severity, 9) for d in firing),
            default=_SEV_ORDER["high"],
        )
        severity_label = next((k for k, v in _SEV_ORDER.items() if v == severity), "high")
    elif all_have_engagement:
        kind = "pentest"
        verdict = "BENIGN_EXPECTED"
        analysis_classification = "authorized_activity"
        severity_label = "low"
    elif all_have_change:
        kind = "ops"
        verdict = "BENIGN_EXPECTED"
        analysis_classification = "authorized_change"
        severity_label = "low"
    else:
        kind = "unclassified"
        verdict = "NO_VALIDATED_BREACH"
        analysis_classification = "unclassified"
        severity_label = "info"

    # ── Entity rollups ──
    users   = sorted({_lower(r.get("user_canonical") or r.get("user")) for r in member_rows})
    users   = [u for u in users if u]
    ips     = sorted({_str(r.get("src_ip"))       for r in member_rows if r.get("src_ip")})
    cidrs   = sorted({_str(r.get("src_ip_cidr24"))for r in member_rows if r.get("src_ip_cidr24")})
    hosts   = sorted({_lower(r.get("hostname") or r.get("host")) for r in member_rows
                      if r.get("hostname") or r.get("host")})
    hosts   = [h for h in hosts if h]
    sources = sorted({_str(r.get("_source_type") or r.get("source_type") or "unknown")
                      for r in member_rows})

    times = [t for t in (ts_by_idx.get(int(r.get("row_index")), 0.0) for r in member_rows) if t > 0]

    # ── Phases payload (only meaningful for campaigns) ──
    phases: list[dict] = []
    if kind == "campaign":
        for det in PHASE_DETECTORS:
            if det.phase_id not in phase_hits:
                continue
            phase_row_refs = sorted(set(phase_hits[det.phase_id]))
            phases.append({
                "phase_id": det.phase_id,
                "name":     det.name,
                "case_role":det.case_role,
                "severity": det.severity,
                "row_refs": phase_row_refs,
                "row_count":len(phase_row_refs),
            })
        # Order phases by kill-chain rough position
        _PHASE_ORDER = {
            "session_theft": 0,
            "credential_theft": 1,
            "secret_access": 2,
            "privilege_escalation_k8s": 3,
            "c2_dns_beacon": 4,
            "data_exfiltration_snowflake": 5,
            "data_exfiltration_rclone": 6,
            "pentest_escalation": 7,
        }
        phases.sort(key=lambda p: _PHASE_ORDER.get(p["phase_id"], 99))

    # ── Lead description ──
    public_ips = [ip for ip in ips if _is_public_ip(ip)]
    if kind == "campaign":
        lead = (
            f"Multi-phase intrusion · {len(phases)} phase(s) · {n} rows "
            f"· {len(sources)} telemetry source(s)"
        )
        if public_ips:
            lead += f" · external infra: {', '.join(public_ips[:3])}"
    elif kind == "pentest":
        lead = (
            f"Authorized engagement {', '.join(sorted(engagement_refs))} · {n} rows"
        )
    elif kind == "ops":
        lead = (
            f"Change-managed activity {', '.join(sorted(change_refs))} · {n} rows"
        )
    else:
        lead = f"Unclassified component · {n} rows · {len(sources)} source(s)"

    confidence = min(0.95, 0.40 + (n / 200.0))
    if kind == "campaign":
        confidence = max(confidence, 0.85)
    elif kind in ("pentest", "ops"):
        confidence = 0.92   # high — explicit ref attestation

    return {
        "cluster_id": f"analysis-{root}",
        "cluster_kind": kind,
        "verdict": verdict,
        "final_verdict": verdict,
        "analysis_classification": analysis_classification,
        "severity": severity_label,
        "confidence": round(confidence, 3),
        "confidence_calibration": "uncalibrated",
        "lead_description": lead,
        "reason_summary": lead,
        "phases": phases,
        "phase_count": len(phases),
        "phase_anchor_row_count": sum(p["row_count"] for p in phases) if phases else 0,
        "engagement_refs": sorted(engagement_refs),
        "change_refs": sorted(change_refs),
        "pivot_keys_used": pivot_keys_used,
        "pivot_key_count": pivot_key_total,
        "row_refs": sorted(member_idxs),
        "row_count": n,
        "shared_users": users[:8],
        "shared_ips": ips[:8],
        "shared_cidrs": cidrs[:8],
        "shared_hosts": hosts[:8],
        "sources": sources,
        "time_window": {
            "start": min(times) if times else None,
            "end":   max(times) if times else None,
            "span_seconds": (max(times) - min(times)) if len(times) >= 2 else 0,
        },
    }


# ── Helpers ──────────────────────────────────────────────────────────────────

def _is_public_ip(ip: str) -> bool:
    """Return True only for routable public IPv4/IPv6 addresses."""
    if not ip:
        return False
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _row_text(row: dict) -> str:
    """Lower-cased flat text from a row for term matching."""
    parts: list[str] = []
    for v in row.values():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            parts.append(str(v))
        elif isinstance(v, (list, tuple)):
            for item in v:
                parts.append(str(item))
        elif isinstance(v, dict):
            for sub in v.values():
                parts.append(str(sub))
    return " ".join(parts).lower()


def _str(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _lower(v: Any) -> str:
    return _str(v).lower()
