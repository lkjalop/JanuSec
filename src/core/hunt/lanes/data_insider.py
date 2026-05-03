from __future__ import annotations

import asyncio
import re
from typing import Any

from ..evidence_envelope import EvidenceEnvelope

# Thresholds — tunable via env or future config API
_DB_EXPORT_ROLES = frozenset({'db_admin', 'dba', 'data_engineer', 'etl_service'})
_BULK_ROW_THRESHOLD = 50_000          # rows in a single export
_LARGE_TRANSFER_BYTES = 5_000_000     # bytes via scheduled task
_SYNC_RATIO_THRESHOLD = 2.5           # host→cloud sync ratio anomaly
_OFF_HOURS_START = 22                 # 10 PM local
_OFF_HOURS_END = 6                    # 6 AM local
_MULTI_SAAS_WINDOW_SECONDS = 14_400   # 4h multi-SaaS window
_STAGING_HOP_THRESHOLD = 2            # cloud provider hops for multi-cloud staging
_BULK_GIT_CLONE_THRESHOLD = 10        # repos cloned in a short window
_PRIVILEGED_SAAS_EXPORTS = frozenset({
    'sharepoint_bulk_download', 'onedrive_bulk_download',
    'googledrive_bulk_export', 'confluence_space_export',
    'snowflake_unload', 'tableau_data_export',
    'salesforce_bulk_export', 's3_getobject_burst',
})

# ── Varonis DatAdvantage: File sensitivity classification at rest ────────────
# Classify file paths / names into sensitivity tiers so that even a single
# FileDownloaded on a payroll or M&A file triggers a DLP signal independent
# of volume threshold — matching what Varonis does natively.

_SENS_PAYROLL = re.compile(
    r'(?i)(payroll|salary|compensation|bonus|w.?2\b|1099|merit|raise'
    r'|stock.option|equity.grant|severance)',
)
_SENS_MA = re.compile(
    r'(?i)(m.?(?:and|&).?a|merger|acquisition|deal.sheet|loi|term.sheet'
    r'|due.diligence|project.[ _]?[a-z]{3,12}(?=[ _.])|target.company'
    r'|synergy|carve.out)',
)
_SENS_LEGAL = re.compile(
    r'(?i)(nda|non.disclosure|settlement|litigation|outside.counsel'
    r'|privileged|attorney.client|work.product|legal.hold|regulatory)',
)
_SENS_PII = re.compile(
    r'(?i)(ssn|social.security|passport|dob|date.of.birth|tax.id'
    r'|national.id|drivers.license|credit.card|ccpan|medical|hipaa'
    r'|phi\b|health.record)',
)
_SENS_SECRETS = re.compile(
    r'(?i)(password|passwd|credentials?|secret|api.?key|private.?key'
    r'|\.pem\b|\.p12\b|\.pfx\b|\.key\b|vault|kms|hsm)',
)


def classify_file_sensitivity(file_path: str | None,
                               data_classification: str | None = None) -> list[str]:
    """Return sensitivity tier tags for a file path (Varonis DatAdvantage equivalent).

    Inputs:
      file_path        — full path or filename string
      data_classification — pre-existing label from DLP/MDM (optional)

    Returns list of factor strings like 'data:sensitive_file_payroll',
    'data:sensitive_file_ma', etc.  Empty list means unclassified / benign.
    """
    tags: list[str] = []
    try:
        # Honour existing upstream classification first
        dc = (data_classification or '').lower()
        if dc in ('confidential', 'restricted', 'secret', 'top_secret', 'pii'):
            tags.append('data:sensitive_file_classified_label')

        combined = f'{file_path or ""} {data_classification or ""}'
        if _SENS_PAYROLL.search(combined):
            tags.append('data:sensitive_file_payroll')
        if _SENS_MA.search(combined):
            tags.append('data:sensitive_file_ma')
        if _SENS_LEGAL.search(combined):
            tags.append('data:sensitive_file_legal')
        if _SENS_PII.search(combined):
            tags.append('data:sensitive_file_pii')
        if _SENS_SECRETS.search(combined):
            tags.append('data:sensitive_file_secrets')
    except Exception:
        pass
    return tags


class DataInsiderLane:
    """Insider / data-theft detection lane.

    Signal catalogue (10 active detectors):
      1. privileged_db_export — DBA/ETL role executing a bulk export
      2. scheduled_task_data_exfil — cron/scheduled task with large byte transfer
      3. host_to_cloud_sync_ratio_anomaly — unusually high host→cloud sync rate
      4. multi_cloud_staging — same user copies data across ≥2 cloud providers
      5. off_hours_sensitive_access — access to sensitive assets outside business hours
      6. multi_saas_access_burst — ≥3 different SaaS targets in a 4h window
      7. offboarding_precursor — bulk git clone or SaaS export within 30d of HR event
      8. iam_self_escalation — user repeatedly assumes elevated roles they created/modified
      9. bulk_saas_export — known bulk-export operation on a privileged SaaS target
     10. unusual_resource_combo — access to ≥3 distinct sensitive resource types in one session
    """

    name = 'data_insider'

    async def run(self, envelope: EvidenceEnvelope, ctx) -> None:
        ev = getattr(envelope, 'event', {}) or {}
        factors: list[str] = []

        # ── 1. Privileged database export ────────────────────────────────────
        role = str(ev.get('user_role') or ev.get('role') or '').lower()
        if role in _DB_EXPORT_ROLES and ev.get('db_export'):
            factors.append('data:privileged_db_export')
            # Bulk row count escalates severity
            rows_exported = int(ev.get('rows_exported') or ev.get('row_count') or 0)
            if rows_exported >= _BULK_ROW_THRESHOLD:
                factors.append('data:privileged_db_export_bulk')

        # ── 2. Scheduled task large file transfer ────────────────────────────
        if ev.get('scheduled_task') and (ev.get('transfer_size') or 0) > _LARGE_TRANSFER_BYTES:
            factors.append('data:scheduled_task_data_exfil')

        # ── 3. Host→cloud sync ratio anomaly ────────────────────────────────
        host_sync = ev.get('host_cloud_sync_ratio') or 0.0
        if isinstance(host_sync, (int, float)) and host_sync > _SYNC_RATIO_THRESHOLD:
            factors.append('data:host_to_cloud_sync_ratio_anomaly')

        # ── 4. Multi-cloud data staging ──────────────────────────────────────
        # Detect "copy AWS → GCP → personal account" low-slow pattern.
        # Requires the upstream enrichment to populate cloud_staging_hops
        # (list of cloud provider names visited in order) or cloud_provider_count.
        cloud_hops = ev.get('cloud_staging_hops') or []
        cloud_provider_count = ev.get('cloud_provider_count') or len(set(cloud_hops))
        if cloud_provider_count >= _STAGING_HOP_THRESHOLD:
            factors.append('data:multi_cloud_staging')
        # Cross-provider copy (e.g. aws→gcp same session)
        if isinstance(cloud_hops, list) and len(cloud_hops) >= 2:
            unique_providers = {str(h).lower().split(':')[0] for h in cloud_hops}
            if len(unique_providers) >= 2 and any(
                p in unique_providers for p in ('personal', 'b2', 'mega', 'dropbox', 'gdrive')
            ):
                factors.append('data:multi_cloud_personal_copy')

        # ── 5. Off-hours sensitive asset access ──────────────────────────────
        # Check hour from event timestamp or hour field
        hour = None
        try:
            ts_raw = ev.get('timestamp') or ev.get('ts') or ''
            if ts_raw:
                import re as _re
                m = _re.search(r'T(\d{2}):', str(ts_raw))
                if m:
                    hour = int(m.group(1))
        except Exception:
            pass
        if hour is None:
            hour = ev.get('hour')
        if hour is not None:
            in_off_hours = (hour >= _OFF_HOURS_START) or (hour < _OFF_HOURS_END)
            is_sensitive = ev.get('sensitive_resource') or ev.get('data_classification') in (
                'confidential', 'restricted', 'pii', 'secret', 'top_secret',
            )
            if in_off_hours and is_sensitive:
                factors.append('data:off_hours_sensitive_access')

        # ── 6. Multi-SaaS access burst (≥3 distinct SaaS targets in 4h) ─────
        saas_targets = ev.get('saas_targets_4h') or ev.get('distinct_saas_count') or 0
        if isinstance(saas_targets, (list, tuple)):
            saas_targets = len(saas_targets)
        if isinstance(saas_targets, (int, float)) and saas_targets >= 3:
            factors.append('data:multi_saas_access_burst')

        # ── 7. Offboarding precursor ─────────────────────────────────────────
        # User is flagged as "pre-departure" (days_until_offboard ≤ 30 or
        # hr_departure_flag set) AND performs a bulk clone/export.
        offboarding = ev.get('hr_departure_flag') or (
            isinstance(ev.get('days_until_offboard'), (int, float)) and
            0 < (ev.get('days_until_offboard') or 9999) <= 30
        )
        if offboarding:
            git_clones = int(ev.get('git_clone_count') or 0)
            if git_clones >= _BULK_GIT_CLONE_THRESHOLD:
                factors.append('data:offboarding_bulk_git_clone')
            saas_export = str(ev.get('operation') or ev.get('event_name') or '').lower()
            if saas_export in _PRIVILEGED_SAAS_EXPORTS or ev.get('bulk_saas_export'):
                factors.append('data:offboarding_saas_export')

        # ── 8. IAM self-escalation ────────────────────────────────────────────
        # User repeatedly assumes a role they own or recently created/modified.
        # Requires iam_self_role_assumption field from CloudTrail enrichment.
        if ev.get('iam_self_role_assumption'):
            factors.append('data:iam_self_escalation')
        # Also catch repeated AssumeRole bursts toward sensitive roles
        assume_role_burst = ev.get('assume_role_burst_count') or 0
        if isinstance(assume_role_burst, (int, float)) and assume_role_burst >= 5:
            role_name = str(ev.get('assumed_role_name') or ev.get('roleArn') or '').lower()
            if any(k in role_name for k in ('admin', 'root', 'power', 'security', 'break_glass')):
                factors.append('data:iam_privileged_role_burst')

        # ── 9. Bulk SaaS export from known high-value operations ─────────────
        op = str(ev.get('Operation') or ev.get('operation') or ev.get('event_name') or '').lower()
        if op in _PRIVILEGED_SAAS_EXPORTS:
            factors.append('data:bulk_saas_export')
            # Extra signal: destination is a personal/external domain
            dest = str(ev.get('destination') or ev.get('external_recipient_domain') or '').lower()
            if dest and not dest.endswith((
                '.corp', '.internal', '.local', 'company.com', '.sharepoint.com',
            )):
                factors.append('data:bulk_saas_export_external_dest')

        # ── 10. Unusual sensitive resource combo in one session ───────────────
        # ≥3 distinct sensitive resource types accessed in a single session
        # (e.g. S3 + Snowflake + Confluence = broad crown-jewels sweep).
        resource_types = ev.get('session_sensitive_resource_types') or []
        if isinstance(resource_types, (list, tuple)) and len(set(resource_types)) >= 3:
            factors.append('data:unusual_sensitive_resource_combo')
        # Alternatively, a scalar count field
        resource_type_count = ev.get('distinct_sensitive_resource_count') or 0
        if isinstance(resource_type_count, (int, float)) and resource_type_count >= 3:
            if 'data:unusual_sensitive_resource_combo' not in factors:
                factors.append('data:unusual_sensitive_resource_combo')

        # ── 11. File sensitivity tagging (Varonis DatAdvantage equivalent) ───
        # Classify individual file access events by sensitivity — a single
        # FileDownloaded on a payroll/M&A file triggers DLP signal regardless
        # of volume, matching what Varonis does with classified content at rest.
        file_path = ev.get('file_path') or ev.get('file_name') or ev.get('ObjectId') or ''
        file_dc = ev.get('data_classification') or ev.get('sensitivity_label') or ''
        sensitivity_tags = classify_file_sensitivity(file_path, file_dc)
        if sensitivity_tags:
            factors.extend(sensitivity_tags)
            # Compound: sensitive file + external destination = high-confidence exfil
            dest = str(ev.get('destination') or ev.get('external_recipient_domain') or '').lower()
            if dest and not dest.endswith(('.corp', '.internal', '.local', '.sharepoint.com')):
                factors.append('data:sensitive_file_external_dest')
            # Compound: sensitive file + offboarding user = insider theft signal
            if offboarding:
                factors.append('data:sensitive_file_access_offboarding_user')

        if factors:
            envelope.add_emission(self.name, factors, notes='auto-detect-batch4', latency_ms=ctx.elapsed_ms())
        await asyncio.sleep(0)


LANE = DataInsiderLane()

