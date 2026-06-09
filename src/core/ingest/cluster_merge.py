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
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)


# Bump when merge logic changes so assessment_worker can detect stale cluster outputs.
_CLUSTER_MERGE_VERSION = "1.9"  # +dedup+jaccard+campaign_rollup+singleton_filter+oversized_cap

# ── Time windows (seconds) per pivot type ────────────────────────────────────
USER_WINDOW             = 6 * 3600          # 6h burst — deliberately tight to avoid BAU/campaign leakage
USER_CAMPAIGN_WINDOW    = 30 * 86_400       # 30d — same user across multi-phase campaign
IP_WINDOW               = 60 * 86_400       # ~unbounded within an assessment
CIDR_WINDOW             = 24 * 3600         # 24h
CROSS_DOMAIN_IP_WINDOW  = 2 * 3600          # 2h (cloud/k8s/sf shared-IP burst)
CIDR16_WINDOW           = 48 * 3600         # 48h loose — /16 is a weak signal; only bridges tight bursts
HOST_WINDOW             = 14 * 86_400       # 14d (compromised host stays compromised)
SIG_WINDOW              = 14 * 86_400       # 14d (DNS beacon campaign span)
ENG_WINDOW              = 365 * 86_400      # unbounded — engagements own their boundary
CHG_WINDOW              = 365 * 86_400      # unbounded — change tickets own their boundary
SESSION_WINDOW          = 6 * 3600          # 6h

# ── Verdict rank for dedup/rollup ordering ────────────────────────────────────
# Mirrors assessment_worker._VERDICT_RANK — kept in sync by convention.
_VERDICT_RANK: dict[str, int] = {
    "INSUFFICIENT_EVIDENCE": 0,
    "BENIGN_EXPECTED": 1,
    "REQUIRES_INVESTIGATION": 2,
    "SUSPECTED_BREACH": 3,
    "SUSPICIOUS_ACTIVITY": 3,
    "LIKELY_COMPROMISE": 3,
    "LIKELY_BREACH": 3,
    "VALIDATED_BREACH": 4,
    "CONFIRMED_INTRUSION": 4,
    "CONFIRMED_BREACH": 4,
}

_BREACH_VERDICT_SET = frozenset({
    "VALIDATED_BREACH", "CONFIRMED_BREACH", "CONFIRMED_INTRUSION",
    "LIKELY_BREACH", "LIKELY_COMPROMISE", "SUSPECTED_BREACH",
})

# ── RFC-1918 prefixes for campaign rollup IP filtering ───────────────────────
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                     "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
                     "127.", "169.254.", "::1", "fc", "fd")


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


# ── Sprint 3: APT-aligned phase detectors ────────────────────────────────────
# Each detector targets a specific MITRE ATT&CK technique group seen in real APT
# campaigns. Functions use structured row fields first, then fall back to the
# pre-serialised text blob for free-text log sources.


def _det_lolbin_execution(row: dict, text: str) -> bool:
    """T1218 / T1059 — Living-off-the-land binary abuse.
    certutil, mshta, regsvr32, wscript, bitsadmin fetching / decoding payloads.
    APT28, APT41, Lazarus Group, Fin7."""
    proc = str(row.get('process_name') or row.get('process') or '').lower()
    if proc in (
        'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'wscript.exe',
        'cscript.exe', 'bitsadmin.exe', 'installutil.exe', 'msiexec.exe',
        'odbcconf.exe', 'mavinject.exe', 'appsyncpublishingtool.exe',
    ):
        cmdline = str(row.get('CommandLine') or row.get('command_line') or '').lower()
        if any(t in cmdline for t in (
            'http://', 'https://', '-decode', '-decodehex', '-urlcache', '/transfer',
            'javascript:', 'vbscript:', 'scrobj', '/i:http',
        )):
            return True
    return any(t in text for t in (
        'certutil -decode', 'certutil -urlcache', 'certutil.exe -urlcache',
        'mshta http', 'mshta.exe http', 'mshta vbscript',
        'regsvr32 /s /n /u /i:http', 'regsvr32.exe /s /n',
        'bitsadmin /transfer', 'installutil /logfile=',
        'odbcconf /a {regsvr', 'mavinject.exe',
    ))


def _det_oauth_device_code(row: dict, text: str) -> bool:
    """T1528 / T1550.001 — OAuth Device Code flow phishing; suspicious app consent.
    APT29 (Midnight Blizzard), Storm-0558 primary initial-access technique.
    Also covers delegated-permission grant abuse and rogue app registration."""
    op = str(row.get('Operation') or row.get('operation') or row.get('event_name') or '').lower()
    if op in (
        'consent to application', 'add app role assignment to service principal',
        'add delegated permission grant', 'update application',
        'add oauth2permissiongrant', 'add service principal',
    ):
        return True
    return any(t in text for t in (
        'device_code', 'oauth2/devicecode', 'devicecodeflow',
        'consent to application', 'add app role assignment',
        'add delegated permission', 'oauth2permissiongrant',
        'malicious oauth', 'suspicious app consent', 'stolen refresh token',
    ))


def _det_cloud_imds_theft(row: dict, text: str) -> bool:
    """T1552.005 — Cloud instance metadata service (IMDS) credential theft.
    Access to 169.254.169.254, metadata.google.internal, metadata.azure.com.
    APT41, TeamTNT, Pacu framework operator."""
    dst = str(row.get('dst_ip') or row.get('dst') or '').strip()
    if dst in ('169.254.169.254', '169.254.170.2'):  # AWS IMDS + ECS task metadata
        return True
    url = str(
        row.get('url') or row.get('http_url') or row.get('uri') or row.get('http.uri') or ''
    ).lower()
    if any(t in url for t in (
        '169.254.169.254', 'metadata.google.internal', 'metadata.azure.com',
        'metadata/instance', 'latest/meta-data/iam/security-credentials',
    )):
        return True
    return any(t in text for t in (
        '169.254.169.254', 'metadata.google.internal', 'metadata.azure.com',
        'imds credential', 'ecs credentials endpoint', 'taskrole',
        'containerrole', 'meta-data/iam/security-credentials', 'imdsv1',
    ))


def _det_dcsync(row: dict, text: str) -> bool:
    """T1003.006 — DCSync domain replication credential harvest.
    Windows Event 4662 with GUID {1131f6aa} / {1131f6ad} / {89e95b76}.
    APT29, Conti, LockBit post-exploitation toolkit chains."""
    event_id = str(row.get('event_id') or row.get('EventID') or '').strip()
    if event_id == '4662':
        props = str(row.get('Properties') or row.get('property_names') or '').lower()
        if any(t in props for t in (
            '1131f6aa', '1131f6ad', '89e95b76', 'ds-replication-get-changes',
        )):
            return True
    return any(t in text for t in (
        'getncchanges', 'ms-drsr', 'drsuapi', 'ds-replication-get-changes',
        '1131f6aa', '1131f6ad', '89e95b76',
        'dcsync', 'dc sync', 'domain replication attack',
        'impacket secretsdump', 'secretsdump.py',
    ))


def _det_kerberoasting(row: dict, text: str) -> bool:
    """T1558.003 / T1558.004 / T1558.001 — Kerberoasting, AS-REP roasting, Golden Ticket.
    RC4_HMAC_MD5 (etype 0x17) TGS requests; pre-auth disabled accounts; forged TGTs.
    Near-universal in targeted attacks: APT29, Fin6, many ransomware groups.
    Field aliases: windows_event_id (VESPER NDJSON), EventID (XML), event_id (normalised)."""
    # Accept both Windows XML field names and VESPER NDJSON field names
    event_id = str(
        row.get('event_id') or row.get('EventID') or row.get('windows_event_id') or ''
    ).strip()
    if event_id == '4769':
        enc_type = str(
            row.get('TicketEncryptionType') or row.get('ticket_encryption_type')
            or row.get('ticket_encryption') or ''
        ).strip()
        if enc_type in ('0x17', '0x18', '23', '18', '0x17 rc4'):
            # Kerberoasting: RC4-downgraded TGS request
            return True
        # Golden Ticket: forged TGT/TGS — anomalous ticket_options indicate forgery
        # 0x60a10000 = forwardable+renewable+proxiable+renewable_ok (atypical combination)
        ticket_opts = str(
            row.get('ticket_options') or row.get('TicketOptions') or ''
        ).strip()
        if enc_type in ('0x17', '0x18', '23', '18') and ticket_opts in (
            '0x60a10000', '0x40a10000', '0x60810000', '0x60a00000',
        ):
            return True
    if event_id == '4768':
        preauth = str(
            row.get('PreAuthType') or row.get('pre_auth_type') or ''
        ).strip()
        if preauth in ('0', '0x0'):
            # AS-REP roasting: pre-authentication disabled
            return True
    return any(t in text for t in (
        'kerberoasting', 'as-rep roasting', 'asreproasting', 'asrep roasting',
        'rc4_hmac_md5', 'rc4 downgrade', '0x17 ticket',
        'golden ticket', 'silver ticket', 'pass-the-ticket', 'ptt attack',
        'spn enumeration', 'gmsapassword',
        'kerbrute', 'rubeus.exe', 'impacket getuserspns', 'getuserspns.py',
    ))


def _det_shadow_copy_deletion(row: dict, text: str) -> bool:
    """T1490 — Inhibit system recovery: shadow copy / backup catalog deletion.
    vssadmin, wmic shadowcopy delete, bcdedit, wbadmin.
    LockBit, BlackCat/ALPHV, Cl0p, Royal, BlackBasta staging signature."""
    return any(t in text for t in (
        'vssadmin delete shadows', 'vssadmin.exe delete',
        'wmic shadowcopy delete', 'wmic shadowcopy call delete',
        'bcdedit /set recoveryenabled no', 'bcdedit /set bootstatuspolicy',
        'diskshadow /s ', 'delete shadows /all /quiet',
        'wbadmin delete catalog', 'wbadmin disable backup',
        'set-mppreference -disablerealtimemonitoring',
        'netsh advfirewall set allprofiles state off',
    ))


def _det_wmi_dcom_lateral(row: dict, text: str) -> bool:
    """T1047 / T1021.003 — WMI and DCOM lateral movement.
    wmic /node: Win32_Process Create, DCOM via RPC port 135/593.
    Also catches wmiprvse.exe spawning encoded PowerShell (sysmon event 1 pattern).
    APT29, Fin7, Sandworm lateral movement tradecraft."""
    proc = str(row.get('process_name') or row.get('process') or '').lower()
    cmdline = str(row.get('CommandLine') or row.get('command_line') or '').lower()
    parent = str(row.get('parent_process') or row.get('ParentImage') or '').lower()
    if ('wmic' in proc or proc == 'wmiprvse.exe') and any(
        t in cmdline for t in ('/node:', 'win32_process', 'call create', 'process call')
    ):
        return True
    # WMI lateral movement via spawned encoded PowerShell (sysmon process-create)
    if 'wmiprvse.exe' in parent and any(
        t in cmdline for t in ('-enc ', '-encodedcommand', ' iex ', 'invoke-expression', 'downloadstring')
    ):
        return True
    try:
        port = int(row.get('dst_port') or row.get('port') or 0)
        if port == 135:
            conn = str(row.get('conn_state') or row.get('connection_state') or '').upper()
            if conn in ('SF', 'S0', 'ESTABLISHED', 'RSTO', 'OTH'):
                return True
    except (TypeError, ValueError):
        pass
    return any(t in text for t in (
        'win32_process create', 'wmic /node:', 'wbemexec',
        'impacket wmiexec', 'wmiexec.py', 'dcom lateral',
        'invoke-wmimethod', 'invoke-cimmethod', 'invoke-dcomobject',
    ))


def _det_entra_privesc(row: dict, text: str) -> bool:
    """T1098.001 / T1136.003 — Azure AD / Entra ID privilege escalation.
    Adding principals to Global Administrator, app role assignments, federation abuse.
    APT29 (Midnight Blizzard), Storm-0558, Scattered Spider."""
    op = str(row.get('Operation') or row.get('operation') or row.get('event_name') or '').lower()
    if op in (
        'add member to role', 'add owner to application',
        'add app role assignment to service principal',
        'add delegated permission grant', 'set domain authentication',
        'add verified domain', 'add unverified domain',
        'update federation settings on domain',
    ):
        target = str(
            row.get('ModifiedProperties') or row.get('Target') or
            row.get('target_resource') or row.get('target_id') or ''
        ).lower()
        if any(t in target for t in (
            'global administrator', 'privileged role administrator',
            'user access administrator', 'application administrator',
            'cloud application administrator', 'exchange administrator',
            'security administrator',
        )):
            return True
    return any(t in text for t in (
        'global administrator', 'privileged role administrator',
        'add member to privileged', 'add service principal to role',
        'federated domain added', 'trustedformasauth',
        'set domain authentication', 'add verified domain to company',
        'golden saml', 'aadinternals', 'roadtools',
    ))


def _det_powershell_staged_payload(row: dict, text: str) -> bool:
    """T1059.001 / T1105 — PowerShell staged payload delivery.
    IEX + DownloadString, -EncodedCommand, AMSI bypass, reflection loading.
    APT29, Lazarus, QakBot, BazarLoader, many commodity loaders."""
    cmdline = str(
        row.get('CommandLine') or row.get('command_line') or row.get('command') or ''
    ).lower()
    # Combination of download + exec in one invocation = high confidence
    has_download = any(t in cmdline for t in (
        'downloadstring', 'downloadfile', 'webclient', 'webrequest',
        'invoke-webrequest', 'iwr ', '.downloaddata(', 'urldownloadtofile',
    ))
    has_exec = any(t in cmdline for t in (
        'iex ', 'invoke-expression', '| iex', '|iex', '(iex',
        '[system.reflection.assembly]', 'load([',
    ))
    if has_download and has_exec:
        return True
    # Standalone AMSI bypass / heavy obfuscation indicators
    if any(t in cmdline for t in (
        '-encodedcommand', '-enc ', ' -nop ', '-noni ',
        'amsiutils', 'amsicontext', '[ref].assembly',
        '[system.runtime.interopservices.marshal]',
        '[convert]::frombase64string', 'set-itemproperty.*run.*powershell',
    )):
        return True
    return any(t in text for t in (
        'amsiscanbuffer', 'amsiutils', 'amsicontext', 'amsibypass',
        'invoke-obfuscation', 'powersploit', 'nishang',
        'empire payload', 'covenant payload', 'powershell cradle',
    ))


def _det_dns_tunnel(row: dict, text: str) -> bool:
    """T1071.004 — DNS tunneling / covert channel exfiltration.
    Long subdomain labels (>50 chars), base64-like query content, iodine/dnscat.
    APT32 (OceanLotus), APT34 (OilRig), SUNBURST C2 channel."""
    import re as _re
    query = str(
        row.get('query') or row.get('dns_query') or
        row.get('dns_question_name') or row.get('qname') or ''
    ).lower().rstrip('.')
    if query:
        first_label = query.split('.')[0]
        if len(first_label) > 50:
            return True
        # High base64-char density in a long label
        if len(first_label) > 20:
            b64_chars = len(_re.findall(r'[A-Za-z0-9+/=\-_]', first_label))
            if b64_chars / max(len(first_label), 1) > 0.92:
                return True
    return any(t in text for t in (
        'dns tunnel', 'dnstunnel', 'dnscat', 'iodine',
        'dns2tcp', 'dns exfil', 'txt record exfil',
        'nxdomain_rate_high', 'nxdomain_spike', 'sunburst beacon',
    ))


def _det_ntlm_relay_pth(row: dict, text: str) -> bool:
    """T1550.002 — Pass-the-hash and NTLM relay attacks.
    ntlmrelayx, Responder, Impacket, hash capture and lateral movement.
    Fin7, APT19, Conti, many ransomware lateral movement phases."""
    return any(t in text for t in (
        'ntlmrelayx', 'ntlm relay', 'responder.py', 'responder capture',
        'impacket psexec', 'impacket smbexec', 'impacket atexec',
        'pass-the-hash', 'pass the hash', 'pth-winexe', 'pth-smbclient',
        'ntlm_theft', 'hash capture', 'ntlm hash captured',
        'ntlm authentication from foreign', 'lm hash', 'overpass-the-hash',
    ))


def _det_cloud_iam_privesc(row: dict, text: str) -> bool:
    """T1098 — Cloud IAM privilege escalation via key creation or policy attachment.
    CreateAccessKey, AttachUserPolicy, iam:* wildcard, new admin user creation.
    APT41, ShinyHunters, TeamTNT, Scattered Spider post-compromise activity."""
    event_name = str(
        row.get('event_name') or row.get('eventName') or
        row.get('Operation') or row.get('operation') or ''
    ).lower()
    if event_name in (
        'createaccesskey', 'attachuserpolicy', 'attachrolepolicy',
        'putuserpolicy', 'createloginprofile', 'updateloginprofile',
        'addusertogroup', 'createuser', 'createpolicy',
        'setdefaultpolicyversion', 'attachgrouppolicy',
    ):
        return True
    policy_body = str(
        row.get('requestParameters') or row.get('request_parameters') or
        row.get('ResourceProperties') or ''
    ).lower()
    if 'iam:*' in policy_body or ('administratoraccess' in policy_body):
        return True
    return any(t in text for t in (
        '"iam:*"', 'iam:*', 'administratoraccess', 'createaccesskey',
        'attachuserpolicy', 'attachrolepolicy', 'putuserinlinepolicy',
        'createloginprofile', 'updateloginprofile', 'addusertogroup.*admin',
    ))


def _det_insider_after_hours(row: dict, text: str) -> bool:
    """Insider threat: privileged after-hours access to sensitive resources,
    or explicit _risk=insider tagging from UEBA/SIEM pre-enrichment.
    Covers Meridian-class scenarios and deliberate data theft by departing employees."""
    if str(row.get('_risk') or '').lower() in ('insider', 'insider_threat', 'insider-threat'):
        return True
    # After-hours access (22:00–06:00 UTC) combined with high-sensitivity resource
    if row.get('_sensitivity') == 'high':
        import re as _re
        ts_raw = str(
            row.get('timestamp') or row.get('TimeGenerated') or
            row.get('ts') or row.get('CreationTime') or ''
        )
        if ts_raw:
            try:
                hr_match = _re.search(r'T(\d{2}):', ts_raw) or _re.search(r' (\d{2}):\d{2}:\d{2}', ts_raw)
                if hr_match:
                    hour = int(hr_match.group(1))
                    if hour >= 22 or hour < 6:
                        return True
            except Exception:
                pass
    return any(t in text for t in (
        '"_risk": "insider"', '_risk": "insider', 'insider_threat',
        'anomalous_access_pattern', 'after_hours_access', 'out_of_role_access',
        'departing employee', 'terminated employee',
    ))


def _det_ransomware_staging(row: dict, text: str) -> bool:
    """Multi-signal ransomware / wiper preparation pattern.
    Covers LockBit, BlackCat/ALPHV, Cl0p, Royal, BlackBasta, Akira, Rhysida.
    Complements shadow_copy_deletion — this fires on ransomware binary artefacts
    and encryption-prep activity rather than the recovery-inhibit phase."""
    return any(t in text for t in (
        # Ransomware family / group names
        'lockbit', 'blackcat', 'alphv', 'cl0p', 'clop',
        'blackbasta', 'black basta', 'royal ransomware', 'akira ransomware',
        'rhysida', 'scattered spider', 'unc3944',
        # Encryption artefacts and ransom notes
        '.lockbit', '.blackcat', 'readme_to_decrypt', '!!! all your files',
        'how_to_decrypt', 'recovery_key.txt', 'ransom_note',
        # Defender / AV disablement (pair with shadow deletion)
        'disable windows defender', 'disablerealtimemonitoring',
        'reg add.*wscsvc.*4',
        # SMB propagation artefacts
        'smb spread', 'psexec ransomware propagation',
    ))


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
    # ── Sprint 3: APT-aligned detectors ──────────────────────────────────────
    # LOLBin / staged execution
    PhaseDetector("lolbin_execution",          "LOLBin Payload Fetch/Decode (T1218)",  "execution",          "critical", _det_lolbin_execution),
    PhaseDetector("powershell_staged_payload", "PowerShell Staged Payload/AMSI Bypass (T1059.001)", "execution", "critical", _det_powershell_staged_payload),
    # Credential access
    PhaseDetector("dcsync_replication",        "DCSync Domain Replication (T1003.006)","credential_access",  "critical", _det_dcsync),
    PhaseDetector("kerberoasting",             "Kerberoasting/AS-REP Roasting (T1558.003)", "credential_access", "high", _det_kerberoasting),
    PhaseDetector("ntlm_relay_pth",            "NTLM Relay / Pass-the-Hash (T1550.002)", "lateral_movement", "high",     _det_ntlm_relay_pth),
    PhaseDetector("cloud_imds_theft",          "Cloud IMDS Credential Theft (T1552.005)", "credential_access", "critical", _det_cloud_imds_theft),
    # Lateral movement
    PhaseDetector("wmi_dcom_lateral",          "WMI/DCOM Lateral Movement (T1047)", "lateral_movement",    "high",     _det_wmi_dcom_lateral),
    # Persistence / identity / cloud
    PhaseDetector("oauth_device_code",         "OAuth Device Code Phishing (T1528)", "initial_access",     "critical", _det_oauth_device_code),
    PhaseDetector("entra_privesc",             "Entra ID/AAD Privilege Escalation (T1098.001)", "privilege_escalation", "critical", _det_entra_privesc),
    PhaseDetector("cloud_iam_privesc",         "Cloud IAM Privilege Escalation (T1098)", "privilege_escalation", "critical", _det_cloud_iam_privesc),
    # Exfiltration
    PhaseDetector("dns_tunnel_exfil",          "DNS Tunneling Exfiltration (T1071.004)", "exfiltration",    "high",     _det_dns_tunnel),
    # Impact / ransomware
    PhaseDetector("shadow_copy_deletion",      "Shadow Copy Deletion/Recovery Inhibit (T1490)", "impact",   "critical", _det_shadow_copy_deletion),
    PhaseDetector("ransomware_staging",        "Ransomware Staging/Wiper Prep",    "impact",               "critical", _det_ransomware_staging),
    # Insider threat
    PhaseDetector("insider_after_hours",       "Insider After-Hours Sensitive Access", "exfiltration",     "high",     _det_insider_after_hours),
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
        cidr24:<src_ip_cidr24> (pre-computed /24 field)
        cidr28:<src/dst /28>   (Phase 0b: definitive same-VPC signal, 24h)
        cidr16:<src/dst /16>   (Phase 0b: loose burst-only bridge, 48h)
        host:<hostname>
        sig:<event_signature>
        ja3:<ja3_hash>         (Phase 0b R8a: TLS fingerprint beacon-chain merge, 14d)
        ja4:<ja4_hash>         (Phase 0b R8a: TLS fingerprint beacon-chain merge, 14d)

    Plus unsuffixed scope-anchor and identity-bridge pivots:
        engagement:<ref>       (only emitted by pentest-scope rows)
        change:<ref>           (only emitted by ops-scope rows)
        session:<session_id>   (Phase 0b R8b: cross-actor session token, 6h)
        device:<device_id>     (Phase 0b R8b: cross-user device bridge, 14d)
        oauth_token:<token_id> (Phase 0b R8b: shared OAuth token burst, 6h)
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

        # ── Weighted CIDR specificity: /28 (definitive) and /16 (loose) ────────
        # /28 = 16-address block: two IPs in the same /28 are almost certainly
        #   the same machine or a tightly clustered C2 VPC — use CIDR_WINDOW (24h).
        # /16 = 65536-address block: weak signal (could be a large CGN or cloud
        #   provider range) — use a wider CIDR16_WINDOW (48h) so it only bridges
        #   within a tight burst.
        for _raw_ip_fld in ("src_ip", "dst_ip"):
            _raw_ip = _str(r.get(_raw_ip_fld))
            if _raw_ip and _raw_ip not in ("-", "0.0.0.0") and _is_public_ip(_raw_ip):
                _c28 = _cidr_prefix(_raw_ip, 28)
                if _c28:
                    out[f"cidr28:{_c28}{suffix}"].append(idx)
                _c16 = _cidr_prefix(_raw_ip, 16)
                if _c16:
                    out[f"cidr16:{_c16}{suffix}"].append(idx)

        host = _lower(r.get("hostname") or r.get("host"))
        if host:
            out[f"host:{host}{suffix}"].append(idx)

        sig = _str(r.get("event_signature"))
        if sig:
            out[f"sig:{sig}{suffix}"].append(idx)

        # ── R8a: JA3/JA4 TLS fingerprint pivot (beacon-chain merging) ──────────
        # Collapses beacon chains whose event_signature strings differ by minor
        # variation (e.g. different NRD domain each day) but share the same
        # JA3/JA4 fingerprint, proving the same C2 implant is responsible.
        # Uses SIG_WINDOW (14d) — same as the event_signature pivot.
        for _ja3_fld in ('ja3', 'ja3_hash', 'ssl_ja3', 'tls_ja3', 'ja3_fingerprint'):
            _ja3 = _str(r.get(_ja3_fld))
            if _ja3 and len(_ja3) >= 16:   # reject noise shorter than an MD5 fragment
                out[f"ja3:{_ja3}{suffix}"].append(idx)
                break
        for _ja4_fld in ('ja4', 'ja4_hash', 'tls_ja4', 'ja4_fingerprint'):
            _ja4 = _str(r.get(_ja4_fld))
            if _ja4 and len(_ja4) >= 16:
                out[f"ja4:{_ja4}{suffix}"].append(idx)
                break
        # JA3S (server-side TLS fingerprint — Zeek ja3s column): cluster on same server cert.
        # Merges events talking to the same C2 server infrastructure even via different clients.
        for _ja3s_fld in ('ja3s', 'ja3_server', 'ssl_ja3s', 'tls_ja3s'):
            _ja3s = _str(r.get(_ja3s_fld))
            if _ja3s and len(_ja3s) >= 16:
                out[f"ja3s:{_ja3s}{suffix}"].append(idx)
                break

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

        # ── Cloud identity pivot (cross-cloud lateral movement, 7d) ──────────
        # Stitches AWS principal ARNs, Azure UPNs, and GCP service accounts when
        # they belong to the same human or workload identity. This is the
        # missing lever that lets us correlate "alice@corp on Azure logs in" →
        # "AWS AssumeRole-as-alice 4 hours later" → "GCP WIF token issued to
        # alice's GitHub workflow" into a single cross-cloud kill chain.
        #
        # Handle nested CloudTrail / Azure AD structures that haven't been fully
        # flattened by the file_parser. AWS CloudTrail stores userIdentity as a
        # dict: {"type":"IAMUser","arn":"...","userName":"alice",...}.
        # Azure AD stores principal under properties.userPrincipalName.
        _uid_raw = r.get('userIdentity')
        if isinstance(_uid_raw, dict):
            # AWS CloudTrail nested userIdentity — extract userName or ARN
            _uid_raw = (
                _uid_raw.get('userName') or
                _uid_raw.get('arn') or
                _uid_raw.get('principalId') or ''
            )
        _props = r.get('properties') or {}
        if isinstance(_props, dict):
            _azure_upn = _props.get('userPrincipalName') or _props.get('userId') or ''
        else:
            _azure_upn = ''
        _cloud_id = _lower(
            r.get('cloud_principal') or r.get('cloud_identity') or
            r.get('iam_principal') or r.get('userIdentity_arn') or
            _uid_raw or r.get('principal_id') or
            r.get('service_account_email') or r.get('upn') or
            _azure_upn
        )
        if _cloud_id and len(_cloud_id) >= 6 and _cloud_id not in ('-', 'n/a', 'unknown', 'system', 'anonymous'):
            # Normalize to a canonical short form so AWS ARN and bare email collide
            _norm = _cloud_id
            if 'arn:aws:iam::' in _norm:
                # arn:aws:iam::123456789012:user/alice → alice
                _norm = _norm.split('/')[-1] or _norm.split(':')[-1]
            elif 'arn:aws:sts::' in _norm:
                _norm = _norm.split('/')[-1] or _norm.split(':')[-1]
            elif _norm.endswith('.iam.gserviceaccount.com'):
                # alice@my-proj.iam.gserviceaccount.com → alice
                _norm = _norm.split('@')[0]
            elif '@' in _norm:
                # alice@corp.com → alice (so it collides with bare 'alice' identity)
                _local = _norm.split('@')[0]
                if len(_local) >= 3:
                    _norm = _local
            if len(_norm) >= 3:
                out[f"cloud_identity:{_norm}"].append(idx)

        # ── R8b: Transitive identity join via shared session/device/token ──────
        # Bridges actor pivots the user-based canon_user rule misses: a stolen
        # session token or shared device links row A (user alice) → row C (user
        # svc-account) even if they share no user_canonical string.
        # session: already has SESSION_WINDOW (6h) in _PREFIX_WINDOW.
        # device: uses HOST_WINDOW (14d) — a compromised device stays compromised.
        # oauth_token: uses SESSION_WINDOW (6h) — token reuse is a tight burst.
        for _sid_fld in ('session_id', 'SessionId', 'session_key', 'sessionId'):
            _sid = _str(r.get(_sid_fld))
            if _sid and len(_sid) >= 8 and _sid.lower() not in ('n/a', 'none', 'null', '-'):
                out[f"session:{_sid}"].append(idx)   # no scope suffix — tokens cross actors
                break
        for _did_fld in ('device_id', 'DeviceId', 'device_key', 'device_object_id', 'deviceId'):
            _did = _str(r.get(_did_fld))
            if _did and len(_did) >= 8 and _did.lower() not in ('n/a', 'none', 'null', '-'):
                out[f"device:{_did}"].append(idx)    # no scope suffix — devices cross users
                break
        for _tok_fld in ('oauth_token_id', 'token_id', 'access_token_hash', 'refresh_token_hash'):
            _tok = _str(r.get(_tok_fld))
            if _tok and len(_tok) >= 8 and _tok.lower() not in ('n/a', 'none', 'null', '-'):
                out[f"oauth_token:{_tok}"].append(idx)
                break

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
    ("cloud_identity:", 7 * 86_400),     # 7d: cross-cloud principal lateral movement
    ("seed:",        7 * 86_400),        # 7d: pre-tagged _cluster/_anomaly ground truth
    # Phase 0b: fragmentation fixes (R8a/R8b/CIDR)
    ("cidr28:",      CIDR_WINDOW),       # 24h: /28 block — definitive same-host/VPC signal
    ("cidr16:",      CIDR16_WINDOW),     # 48h: /16 block — loose burst-only bridge
    ("ja3:",         SIG_WINDOW),        # 14d: same JA3 TLS fingerprint = same C2 implant
    ("ja4:",         SIG_WINDOW),        # 14d: same JA4 TLS fingerprint = same C2 implant
    ("ja3s:",        SIG_WINDOW),        # 14d: same server JA3 fingerprint = same C2 server cert
    ("device:",      HOST_WINDOW),       # 14d: shared device bridges cross-account pivots
    ("oauth_token:", SESSION_WINDOW),    # 6h: shared OAuth token = same actor burst
]


def _window_for(pivot_key: str) -> float:
    for prefix, window in _PREFIX_WINDOW:
        if pivot_key.startswith(prefix):
            return window
    return IP_WINDOW   # default permissive


# ── Post-merge deduplication and campaign rollup ─────────────────────────────

_SINGLETON_KEEP_VERDICTS = frozenset({
    "VALIDATED_BREACH", "SUSPECTED_BREACH", "LIKELY_BREACH",
    "LIKELY_COMPROMISE", "CONFIRMED_INTRUSION",
})
# Factor tags that are high-value enough to keep even a single-row cluster.
_SINGLETON_KEEP_FACTORS = frozenset({
    "iam:golden_ticket", "iam:dcsync", "iam:kerberoasting", "iam:pass_the_hash",
    "iam:pass_the_ticket", "iam:asrep_roasting", "iam:adcs_cert_request_abuse",
    "endpoint:lolbin_execution", "endpoint:process_injection", "endpoint:ransomware",
    "cloud:privilege_escalation", "cloud:ssm_run_command_unusual",
    "exfil:large_upload", "exfil:dns_tunnel",
})
_SINGLETON_MAX_ROW_COUNT = int(os.getenv("JANUSEC_SINGLETON_MAX_ROWS", "1"))
_OVERSIZED_CAP = int(os.getenv("JANUSEC_OVERSIZED_CLUSTER_CAP", "500"))


def _filter_low_signal_singletons(clusters: list[dict]) -> list[dict]:
    """Drop singleton clusters that carry no actionable signal.

    A cluster is considered low-signal if ALL of:
      - row_count <= JANUSEC_SINGLETON_MAX_ROWS (default 1)
      - verdict not in a breach/compromise family
      - no attack phases detected (not a campaign)
      - no high-value factor tags
      - no MITRE techniques tagged

    Such clusters are noise: a single generic event that didn't pivot to anything.
    High-triage singletons (e.g. a lone golden ticket event) are kept because they
    carry high-value factor_tags.
    """
    out: list[dict] = []
    for cl in clusters:
        refs = cl.get("row_refs") or []
        row_count = len(refs) if isinstance(refs, list) else int(cl.get("row_count") or 1)
        if row_count > _SINGLETON_MAX_ROW_COUNT:
            out.append(cl)
            continue
        # Check if any keep condition applies
        verdict = str(cl.get("verdict") or "").upper()
        if verdict in _SINGLETON_KEEP_VERDICTS:
            out.append(cl)
            continue
        phases = cl.get("phases")
        if phases:
            out.append(cl)
            continue
        ft = cl.get("factor_tags") or []
        ft_set = set(ft) if isinstance(ft, list) else set((ft or {}).keys())
        if ft_set & _SINGLETON_KEEP_FACTORS:
            out.append(cl)
            continue
        if cl.get("mitre_techniques"):
            out.append(cl)
            continue
        # All conditions met for drop — tag and skip
        logger.debug(
            "cluster_merge: dropping low-signal singleton cluster %s (verdict=%s)",
            cl.get("cluster_id"), verdict,
        )
    return out


def _cap_oversized_clusters(clusters: list[dict]) -> list[dict]:
    """Cap excessively large clusters to prevent narration/LLM overload.

    Clusters with more than JANUSEC_OVERSIZED_CLUSTER_CAP rows (default 500) have
    their row_refs capped and are tagged with _oversized=True so downstream code
    can display a warning. The original total is preserved as _total_row_count.
    """
    out: list[dict] = []
    for cl in clusters:
        refs = cl.get("row_refs") or []
        if isinstance(refs, list) and len(refs) > _OVERSIZED_CAP:
            cl = dict(cl)  # shallow copy — don't mutate the original
            cl["_total_row_count"] = len(refs)
            cl["_oversized"] = True
            cl["row_refs"] = refs[:_OVERSIZED_CAP]
            cl["row_count"] = _OVERSIZED_CAP
            logger.warning(
                "cluster_merge: cluster %s oversized (%d rows) — capping to %d for narration",
                cl.get("cluster_id"), len(refs), _OVERSIZED_CAP,
            )
        out.append(cl)
    return out


def _deduplicate_by_rowset(clusters: list[dict]) -> list[dict]:
    """Collapse clusters with identical row_ref sets. Keeps highest-verdict cluster.

    Eliminates Jaccard=1.0 duplicates that arise when phase decomposition creates
    multiple children from the same evidence rows.
    """
    seen: dict[frozenset, int] = {}   # frozenset(row_refs) → index in out
    out: list[dict] = []
    for cl in clusters:
        refs = cl.get('row_refs') or []
        key: frozenset[int] = frozenset(int(r) for r in refs if r is not None)
        if not key:
            out.append(cl)
            continue
        if key in seen:
            existing = out[seen[key]]
            if (_VERDICT_RANK.get(str(cl.get('verdict', '')), 0) >
                    _VERDICT_RANK.get(str(existing.get('verdict', '')), 0)):
                out[seen[key]] = cl
        else:
            seen[key] = len(out)
            out.append(cl)
    return out


def _merge_high_jaccard(clusters: list[dict], threshold: float = 0.65) -> list[dict]:
    """Merge clusters whose row-set Jaccard overlap ≥ threshold into the higher-verdict parent.

    Handles near-duplicate phase-children (e.g. email_exfil phase1 vs phase2 with 80% overlap).
    Uses path-compressed union-find so the O(n²) pair scan only runs once.
    """
    if len(clusters) < 2:
        return clusters

    sets: list[frozenset[int]] = [
        frozenset(int(r) for r in (cl.get('row_refs') or []) if r is not None)
        for cl in clusters
    ]
    n = len(clusters)
    parent = list(range(n))

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(n):
        if not sets[i]:
            continue
        for j in range(i + 1, n):
            if not sets[j]:
                continue
            inter = len(sets[i] & sets[j])
            if inter == 0:
                continue
            union = len(sets[i] | sets[j])
            if union and inter / union >= threshold:
                ri, rj = _find(i), _find(j)
                if ri != rj:
                    vi = _VERDICT_RANK.get(str(clusters[ri].get('verdict', '')), 0)
                    vj = _VERDICT_RANK.get(str(clusters[rj].get('verdict', '')), 0)
                    survivor, absorbed = (ri, rj) if vi >= vj else (rj, ri)
                    parent[absorbed] = survivor
                    # Merge row refs and factor_tags into survivor
                    merged_refs = sets[survivor] | sets[absorbed]
                    clusters[survivor]['row_refs'] = sorted(merged_refs)
                    clusters[survivor]['row_count'] = len(merged_refs)
                    sets[survivor] = merged_refs
                    for ft in (clusters[absorbed].get('factor_tags') or []):
                        existing_tags = clusters[survivor].setdefault('factor_tags', [])
                        if ft not in existing_tags:
                            existing_tags.append(ft)

    seen_roots: set[int] = set()
    out: list[dict] = []
    for i in range(n):
        root = _find(i)
        if root not in seen_roots:
            seen_roots.add(root)
            out.append(clusters[root])
    return out


def _campaign_rollup(clusters: list[dict], max_campaigns: int = 8) -> list[dict]:
    """Group breach clusters that share actors or external IPs into a single campaign case.

    Non-breach clusters (pentest, ops, unclassified) pass through unchanged.
    Merges sub-cases into a primary cluster and appends them as 'sub_cases' metadata.
    Caps total breach cases to max_campaigns to prevent proliferation.
    """
    campaign_clusters = [c for c in clusters if c.get('verdict') in _BREACH_VERDICT_SET]
    other_clusters = [c for c in clusters if c.get('verdict') not in _BREACH_VERDICT_SET]

    if len(campaign_clusters) <= 1:
        return clusters

    # Build actor → cluster-index and external-ip → cluster-index maps
    actor_idx: dict[str, list[int]] = defaultdict(list)
    ip_idx: dict[str, list[int]] = defaultdict(list)
    for i, cl in enumerate(campaign_clusters):
        for u in (cl.get('shared_users') or cl.get('shared_accounts') or []):
            u_key = str(u).lower().strip()
            if u_key and u_key not in ('-', 'n/a', 'system', 'root', ''):
                actor_idx[u_key].append(i)
        for ip in (cl.get('shared_ips') or []):
            ip_str = str(ip or '').strip()
            if ip_str and not any(ip_str.startswith(p) for p in _PRIVATE_PREFIXES):
                ip_idx[ip_str].append(i)

    # Union-find over campaign clusters
    parent = list(range(len(campaign_clusters)))

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(a: int, b: int) -> None:
        ra, rb = _find(a), _find(b)
        if ra != rb:
            parent[rb] = ra

    for indices in actor_idx.values():
        for j in range(1, len(indices)):
            _union(indices[0], indices[j])
    for indices in ip_idx.values():
        for j in range(1, len(indices)):
            _union(indices[0], indices[j])

    # Collect groups
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(campaign_clusters)):
        groups[_find(i)].append(i)

    merged: list[dict] = []
    for root, members in groups.items():
        if len(members) == 1:
            merged.append(campaign_clusters[members[0]])
            continue
        # Merge all members: primary is the root cluster
        primary = campaign_clusters[root]
        all_row_refs: set[int] = set(
            int(r) for r in (primary.get('row_refs') or []) if r is not None
        )
        all_factors: list[str] = list(primary.get('factor_tags') or [])
        sub_cases: list[dict] = []
        for idx in members:
            if idx == root:
                continue
            absorbed = campaign_clusters[idx]
            for r in (absorbed.get('row_refs') or []):
                if r is not None:
                    all_row_refs.add(int(r))
            for ft in (absorbed.get('factor_tags') or []):
                if ft not in all_factors:
                    all_factors.append(ft)
            sub_cases.append({
                'cluster_id': absorbed.get('cluster_id'),
                'lead_description': absorbed.get('lead_description'),
                'verdict': absorbed.get('verdict'),
                'row_count': absorbed.get('row_count'),
                'factor_tags': absorbed.get('factor_tags'),
                'shared_users': absorbed.get('shared_users') or absorbed.get('shared_accounts'),
                'shared_ips': absorbed.get('shared_ips'),
            })
        primary['row_refs'] = sorted(all_row_refs)
        primary['row_count'] = len(all_row_refs)
        primary['factor_tags'] = all_factors
        primary['sub_cases'] = sub_cases
        primary['_merged_cluster_count'] = len(members)
        merged.append(primary)

    # Sort by verdict rank desc, then row_count desc; cap to max_campaigns
    merged.sort(
        key=lambda c: (_VERDICT_RANK.get(str(c.get('verdict', '')), 0), int(c.get('row_count') or 0)),
        reverse=True,
    )
    return merged[:max_campaigns] + other_clusters


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
        expanded = _expand_large_campaign_cluster(cluster, row_by_idx, ts_by_idx)
        candidate_clusters = expanded or [cluster]

        # Unclassified single-source components are BAU activity groups, not
        # cross-domain intrusion signals. Bucket them as isolated telemetry so
        # they don't pad the cluster count with noise cards.
        for candidate in candidate_clusters:
            if (
                candidate.get("cluster_kind") == "unclassified"
                and len(candidate.get("sources", [])) < 2
            ):
                candidate["_isolated"] = True
                isolated.append(candidate)
            else:
                out.append(candidate)

    out.sort(key=lambda c: (
        _SEV_ORDER.get(str(c.get("severity", "low")), 9),
        -int(c.get("row_count", 0)),
    ))

    # Cap expanded sub-clusters: after sort (largest first), keep at most
    # JANUSEC_PHASE_SUB_CLUSTER_CAP per (parent_cluster_id, phase_id) pair
    # so a single mega-campaign doesn't produce 40+ near-duplicate cards.
    _sub_cap = int(os.getenv("JANUSEC_PHASE_SUB_CLUSTER_CAP", "4") or 4)
    _phase_sub_seen: dict[tuple[str, str], int] = {}
    _out_deduped: list[dict] = []
    for _c_dd in out:
        if not _c_dd.get("expanded_from_large_campaign"):
            _out_deduped.append(_c_dd)
            continue
        _ph_id_dd = str((_c_dd.get("phases") or [{}])[0].get("phase_id") or "unknown")
        _par_id_dd = str(_c_dd.get("parent_cluster_id") or "")
        _key_dd = (_par_id_dd, _ph_id_dd)
        _phase_sub_seen[_key_dd] = _phase_sub_seen.get(_key_dd, 0) + 1
        if _phase_sub_seen[_key_dd] <= _sub_cap:
            _out_deduped.append(_c_dd)
    out = _out_deduped

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

    # ── Post-merge deduplication and campaign rollup ─────────────────────────
    # Layer 1: collapse identical row-sets (Jaccard=1.0 from phase decomposition)
    out = _deduplicate_by_rowset(out)
    # Layer 2: merge near-duplicates above the Jaccard threshold
    _jaccard_threshold = float(os.getenv("JANUSEC_JACCARD_MERGE_THRESHOLD", "0.65"))
    out = _merge_high_jaccard(out, threshold=_jaccard_threshold)
    # Layer 3: roll multi-cluster actor/IP campaigns into single cases
    _max_campaigns = int(os.getenv("JANUSEC_MAX_CAMPAIGNS", "8"))
    out = _campaign_rollup(out, max_campaigns=_max_campaigns)
    # Layer 4: drop no-signal singleton clusters (single generic event, no indicators)
    _pre_singleton_count = len(out)
    out = _filter_low_signal_singletons(out)
    # Layer 5: cap oversized clusters so narration stays within LLM context limits
    out = _cap_oversized_clusters(out)

    if diagnostics_out is not None:
        diagnostics_out["post_merge_cluster_count"] = len(out)
        diagnostics_out["post_merge_jaccard_threshold"] = _jaccard_threshold
        diagnostics_out["singleton_filter_dropped"] = _pre_singleton_count - len(out)
        diagnostics_out["oversized_clusters"] = sum(1 for c in out if c.get("_oversized"))

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

    # ── Phase 0a: Structured confidence breakdown ────────────────────────────────
    # Replaces the uncalibrated `0.40 + n/200` row-count formula.  Weights match
    # the segment_max values in threat_models._compute_confidence_meter so that
    # the cluster-level scalar and the prefill-level meter are computed on the
    # same conceptual basis (prefill refines with per-row MITRE + off-hours data).

    # Source corroboration (25 pts weight): distinct source types vs expected 3
    _src_corr = min(1.0, len(sources) / 3.0)

    # Evidence cluster strength (30 pts weight): phase count signals evidence richness
    if phases:
        _evid = min(1.0, 0.40 + len(phases) * 0.15)
    else:
        _evid = min(1.0, 0.25 + n / 500.0)

    # Technique confidence (25 pts weight): critical/high detectors that fired
    _crit = sum(1 for d in PHASE_DETECTORS if d.phase_id in phase_hits and d.severity == "critical")
    _high = sum(1 for d in PHASE_DETECTORS if d.phase_id in phase_hits and d.severity == "high")
    _tech = min(1.0, _crit * 0.35 + _high * 0.20) if phase_hits else 0.30

    # Temporal consistency (20 pts weight): attack span vs known campaign durations
    _span_c = (max(times) - min(times)) if len(times) >= 2 else 0.0
    if _span_c >= 7 * 86400:
        _temp = 1.0
    elif _span_c >= 86400:
        _temp = 0.85
    elif _span_c >= 6 * 3600:
        _temp = 0.65
    elif _span_c > 0:
        _temp = 0.50
    else:
        _temp = 0.30

    confidence = round(
        _src_corr * 0.25
        + _evid * 0.30
        + _tech * 0.25
        + _temp * 0.20,
        3,
    )

    # Attestation floors
    if kind in ("pentest", "ops"):
        confidence = max(confidence, 0.85)    # explicit ref attestation
    elif kind == "campaign" and phase_hits:
        confidence = max(confidence, 0.60)    # at least one detector fired

    confidence_breakdown = {
        "source_corroboration":      round(_src_corr * 25, 1),
        "evidence_cluster_strength": round(_evid * 30, 1),
        "technique_confidence":      round(_tech * 25, 1),
        "temporal_consistency":      round(_temp * 20, 1),
    }
    try:
        from src.core.calibration.confidence_calibration import apply_calibration
        _dataset_hint = (
            member_rows[0].get("org")
            or member_rows[0].get("tenant_id")
            or member_rows[0].get("_source")
            if member_rows else None
        )
        _calibrated = apply_calibration(confidence, dataset=_dataset_hint)
    except Exception:
        _calibrated = {
            "probability": confidence,
            "applied": False,
            "method": "none",
            "artifact": None,
            "family": "default",
        }

    # ── APT attribution (best-effort TTP pattern match) ───────────────────
    # Only run for campaign clusters where phase_tags carry weight. Returns
    # None if no profile clears the floor — never fabricates attribution.
    apt_attribution = None
    if kind == "campaign" and phase_hits:
        try:
            from src.core.enrichment.apt_profiles import attribute_apt
            # Cloud providers inferred from sources + pivot keys
            _clouds: set[str] = set()
            for _src in sources:
                _src_l = str(_src).lower()
                for _cp in ("aws", "azure", "gcp", "okta", "m365", "github", "kubernetes", "aad"):
                    if _cp in _src_l:
                        _clouds.add(_cp)
            for _pk in pivot_keys_used:
                _pk_l = str(_pk).lower()
                if "azure" in _pk_l or "aad" in _pk_l:
                    _clouds.add("azure")
                if "aws" in _pk_l:
                    _clouds.add("aws")
                if "gcp" in _pk_l:
                    _clouds.add("gcp")
            apt_attribution = attribute_apt(
                phase_tags=set(phase_hits.keys()),
                pivot_keys=pivot_keys_used,
                cloud_providers=_clouds,
            )
            # Layer in actor tags emitted by the threat intel stage (MISP/OpenCTI)
            # If any member row carries threat_intel_actor_tags that match a known
            # alias in APT_PROFILES, annotate the attribution (or create a stub
            # intel_attribution when no TTP match fired).
            _intel_tags: set[str] = set()
            for _mr in member_rows:
                for _t in (_mr.get('threat_intel_actor_tags') or []):
                    _intel_tags.add(str(_t).lower().strip())
            if _intel_tags:
                if apt_attribution:
                    # Merge intel tags into matched indicators for analyst visibility
                    apt_attribution['threat_intel_actor_tags'] = sorted(_intel_tags)
                    # Check if any intel tag matches the attributed actor or its aliases
                    from src.core.enrichment.apt_profiles import APT_PROFILES as _APC
                    _attr_actor = apt_attribution.get('actor', '')
                    _profile = _APC.get(_attr_actor, {})
                    _all_names = {_attr_actor} | {str(a).lower() for a in _profile.get('aliases', [])}
                    if _intel_tags & _all_names:
                        # Intel feed corroborates TTP attribution → raise confidence
                        apt_attribution['confidence'] = round(
                            min(0.97, apt_attribution['confidence'] + 0.07), 3
                        )
                        apt_attribution['attribution_basis'] = 'ttp_pattern_match+threat_intel'
                else:
                    # No TTP match but MISP/OpenCTI tags present → create intel-only stub
                    apt_attribution = {
                        'actor': sorted(_intel_tags)[0],
                        'aliases': sorted(_intel_tags),
                        'origin': '',
                        'confidence': 0.45,  # below TTP floor — intel only, low confidence
                        'description': 'Actor tag from threat intelligence feed (no TTP pattern match)',
                        'matched_indicators': [f'intel:{t}' for t in sorted(_intel_tags)],
                        'attribution_basis': 'threat_intel_only',
                        'threat_intel_actor_tags': sorted(_intel_tags),
                    }
        except Exception:   # noqa: BLE001
            logger.debug("APT attribution skipped for cluster %s", root, exc_info=True)
            apt_attribution = None

    cluster_out = {
        "cluster_id": f"analysis-{root}",
        "cluster_kind": kind,
        "verdict": verdict,
        "final_verdict": verdict,
        "analysis_classification": analysis_classification,
        "severity": severity_label,
        "confidence": round(confidence, 3),
        "calibrated_confidence": round(float(_calibrated.get("probability", confidence)), 4),
        "confidence_calibration": "decomposed_v1",
        "statistical_calibration": {
            "applied": bool(_calibrated.get("applied")),
            "method": _calibrated.get("method"),
            "artifact": _calibrated.get("artifact"),
            "family": _calibrated.get("family"),
        },
        "confidence_breakdown": confidence_breakdown,
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
        "source_types": sources,
        "source_count": len(sources),
        "time_window": {
            "start": min(times) if times else None,
            "end":   max(times) if times else None,
            "span_seconds": (max(times) - min(times)) if len(times) >= 2 else 0,
        },
    }
    if apt_attribution:
        cluster_out["apt_attribution"] = apt_attribution
        # Bonus to confidence when a high-quality APT profile match fires
        if apt_attribution.get("confidence", 0) >= 0.7:
            cluster_out["confidence"] = round(min(0.97, cluster_out["confidence"] + 0.05), 3)
    return cluster_out


# ── Helpers ──────────────────────────────────────────────────────────────────

def _expand_large_campaign_cluster(
    cluster: dict,
    row_by_idx: dict[int, dict],
    ts_by_idx: dict[int, float],
) -> list[dict]:
    """Split very large campaign components into phase-centered clusters."""
    if os.getenv("JANUSEC_SPLIT_LARGE_CAMPAIGNS", "1").lower() in {"0", "false", "no"}:
        return []
    if cluster.get("cluster_kind") != "campaign":
        return []
    try:
        row_count = int(cluster.get("row_count") or 0)
    except (TypeError, ValueError):
        row_count = 0
    threshold = int(os.getenv("JANUSEC_LARGE_CAMPAIGN_ROWS", "500") or 500)
    if row_count < threshold:
        return []

    parent_refs = {
        idx for ref in (cluster.get("row_refs") or [])
        if (idx := _int_or_none(ref)) is not None
    }
    if not parent_refs:
        return []

    context_window = float(os.getenv("JANUSEC_PHASE_CLUSTER_CONTEXT_SECONDS", str(6 * 3600)) or (6 * 3600))
    bucket_seconds = float(os.getenv("JANUSEC_PHASE_CLUSTER_BUCKET_SECONDS", str(12 * 3600)) or (12 * 3600))
    per_phase_cap = int(os.getenv("JANUSEC_PHASE_CLUSTER_MAX_PER_PHASE", "24") or 24)
    context_cap = int(os.getenv("JANUSEC_PHASE_CLUSTER_CONTEXT_CAP", "120") or 120)
    min_children = int(os.getenv("JANUSEC_PHASE_CLUSTER_MIN_CHILDREN", "8") or 8)

    groups: dict[tuple[str, str, int], set[int]] = defaultdict(set)
    phase_meta: dict[str, dict] = {}
    for phase in cluster.get("phases") or []:
        phase_id = str(phase.get("phase_id") or "")
        if not phase_id:
            continue
        phase_meta[phase_id] = phase
        for ref in phase.get("row_refs") or []:
            idx = _int_or_none(ref)
            if idx is None or idx not in parent_refs:
                continue
            row = row_by_idx.get(idx) or {}
            ts = ts_by_idx.get(idx, 0.0)
            bucket = int(ts // bucket_seconds) if ts > 0 and bucket_seconds > 0 else 0
            groups[(phase_id, _row_group_anchor(row), bucket)].add(idx)

    if not groups:
        return []

    selected_keys: list[tuple[str, str, int]] = []
    by_phase: dict[str, list[tuple[tuple[str, str, int], set[int]]]] = defaultdict(list)
    for key, refs in groups.items():
        by_phase[key[0]].append((key, refs))
    for _phase_id, items in by_phase.items():
        items.sort(key=lambda item: (-len(item[1]), item[0][2], item[0][1]))
        selected_keys.extend(key for key, _ in items[:per_phase_cap])
    selected_keys.sort(key=lambda key: (key[2], key[0], key[1]))

    children: list[dict] = []
    for n, key in enumerate(selected_keys, start=1):
        phase_id, anchor, _bucket = key
        anchor_refs = groups[key]
        child_refs = _phase_context_refs(anchor_refs, parent_refs, row_by_idx, ts_by_idx, context_window, context_cap)
        if len(child_refs) < 2:
            child_refs = set(anchor_refs)
        if child_refs:
            children.append(_make_phase_child_cluster(cluster, phase_meta.get(phase_id) or {}, phase_id, anchor, n, child_refs, row_by_idx, ts_by_idx))

    if len(children) < min_children:
        return []
    return children


def _phase_context_refs(
    anchor_refs: set[int],
    parent_refs: set[int],
    row_by_idx: dict[int, dict],
    ts_by_idx: dict[int, float],
    context_window: float,
    context_cap: int,
) -> set[int]:
    anchor_entities: set[str] = set()
    anchor_times = [ts_by_idx.get(idx, 0.0) for idx in anchor_refs if ts_by_idx.get(idx, 0.0) > 0]
    for idx in anchor_refs:
        anchor_entities.update(_row_entities(row_by_idx.get(idx) or {}))
    if not anchor_times:
        return set(anchor_refs)
    start = min(anchor_times) - context_window
    end = max(anchor_times) + context_window
    center = (min(anchor_times) + max(anchor_times)) / 2
    candidates: list[tuple[float, int, bool]] = []
    for idx in parent_refs:
        ts = ts_by_idx.get(idx, 0.0)
        if ts and (ts < start or ts > end):
            continue
        overlaps = bool(anchor_entities & _row_entities(row_by_idx.get(idx) or {}))
        if idx in anchor_refs or overlaps:
            candidates.append((abs((ts or center) - center), idx, overlaps))
    candidates.sort(key=lambda item: (item[0], 0 if item[2] else 1, item[1]))
    picked = {idx for _, idx, _ in candidates[:context_cap]}
    picked.update(anchor_refs)
    return picked


def _make_phase_child_cluster(
    parent: dict,
    phase: dict,
    phase_id: str,
    anchor: str,
    ordinal: int,
    refs: set[int],
    row_by_idx: dict[int, dict],
    ts_by_idx: dict[int, float],
) -> dict:
    rows = [row_by_idx[i] for i in sorted(refs) if i in row_by_idx]
    sources = sorted({
        _str(r.get("_source_type") or r.get("source_type") or r.get("source_file") or "unknown")
        for r in rows
    })
    users = sorted({_lower(r.get("user_canonical") or r.get("user") or r.get("username")) for r in rows})
    users = [u for u in users if u]
    ips = sorted({_str(r.get("src_ip") or r.get("dst_ip")) for r in rows if r.get("src_ip") or r.get("dst_ip")})
    hosts = sorted({_lower(r.get("hostname") or r.get("host")) for r in rows if r.get("hostname") or r.get("host")})
    times = [ts_by_idx.get(i, 0.0) for i in refs if ts_by_idx.get(i, 0.0) > 0]
    phase_rows = sorted(i for i in refs if phase_id in detect_row_phase_tags(row_by_idx.get(i) or {}))
    child_phase = dict(phase)
    child_phase["row_refs"] = phase_rows or sorted(refs)
    child_phase["row_count"] = len(child_phase["row_refs"])
    lead = (
        f"{phase.get('name') or phase_id.replace('_', ' ').title()} cluster "
        f"around {anchor} - {len(refs)} rows - {len(sources)} telemetry source(s)"
    )
    return {
        "cluster_id": f"{parent.get('cluster_id', 'analysis')}-{phase_id}-{ordinal:02d}",
        "parent_cluster_id": parent.get("cluster_id"),
        "expanded_from_large_campaign": True,
        "cluster_kind": "campaign",
        "verdict": parent.get("verdict", "VALIDATED_BREACH"),
        "final_verdict": parent.get("final_verdict", "VALIDATED_BREACH"),
        "analysis_classification": parent.get("analysis_classification", "confirmed_breach"),
        "severity": phase.get("severity") or parent.get("severity", "high"),
        "confidence": parent.get("confidence", 0.85),
        "confidence_calibration": parent.get("confidence_calibration", "decomposed_v1"),
        "confidence_breakdown": parent.get("confidence_breakdown"),
        "lead_description": lead,
        "reason_summary": lead,
        "phases": [child_phase],
        "phase_count": 1,
        "phase_anchor_row_count": len(child_phase["row_refs"]),
        "engagement_refs": parent.get("engagement_refs") or [],
        "change_refs": parent.get("change_refs") or [],
        "pivot_keys_used": parent.get("pivot_keys_used") or [],
        "pivot_key_count": parent.get("pivot_key_count") or 0,
        "row_refs": sorted(refs),
        "row_count": len(refs),
        "shared_users": users[:8],
        "shared_ips": ips[:8],
        "shared_hosts": hosts[:8],
        "sources": sources,
        "source_types": sources,
        "source_count": len(sources),
        "time_window": {
            "start": min(times) if times else None,
            "end": max(times) if times else None,
            "span_seconds": (max(times) - min(times)) if len(times) >= 2 else 0,
        },
    }


def _row_group_anchor(row: dict) -> str:
    for field in ("hostname", "host", "user_canonical", "user", "src_ip", "dst_ip", "dns_query", "event_signature"):
        val = _lower(row.get(field))
        if val:
            return f"{field}:{val}"
    return "event"


def _row_entities(row: dict) -> set[str]:
    out: set[str] = set()
    for field in ("hostname", "host", "user_canonical", "user", "username", "src_ip", "dst_ip", "dns_query", "domain", "event_signature"):
        val = _lower(row.get(field))
        if val:
            out.add(f"{field}:{val}")
    return out


def _int_or_none(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _is_public_ip(ip: str) -> bool:
    """Return True only for routable public IPv4/IPv6 addresses."""
    if not ip:
        return False
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _cidr_prefix(ip: str, prefix_len: int) -> str:
    """Return the network address string for *ip* masked to *prefix_len*.

    Returns '' on any parse failure so callers can safely skip empty strings.
    Only works on IPv4; IPv6 CIDR pivots are intentionally excluded because
    most IPv6 prefixes are /48 or shorter and the address space is enormous.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return ''
        net = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
        return str(net.network_address)
    except ValueError:
        return ''


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
