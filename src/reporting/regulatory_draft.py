"""Regulatory notification draft generator.

Supported action types:
  - ndb          : Australian Privacy Act 1988 (Cth) Part IIIC — Notifiable Data Breaches
  - gdpr         : EU GDPR Art. 33/34 — Supervisory authority + individual notification
  - forensic     : Forensic preservation order (internal chain-of-custody notice)
  - sec_8k       : US SEC Form 8-K material cybersecurity incident disclosure
  - asx          : ASX Listing Rule 3.1 continuous disclosure

Usage::

    from src.reporting.regulatory_draft import build_regulatory_draft
    draft = build_regulatory_draft('ndb', assessment)
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any


def _today_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%d')


def _now_dt() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def _extract_subjects(assessment: dict) -> tuple[int, list[str]]:
    """Best-effort count and sample list of affected individuals from rows."""
    rows: list[dict] = (
        assessment.get('normalized_rows')
        or assessment.get('evidence_rows')
        or assessment.get('rows') or []
    )
    users: set[str] = set()
    for row in rows:
        for field in ('user', 'username', 'email', 'subject', 'upn', 'actor'):
            v = str(row.get(field) or '').strip()
            if v and v.lower() not in ('', '-', 'n/a', 'none', 'unknown'):
                users.add(v)
    return len(users), sorted(users)[:10]


def _mitre_list(assessment: dict) -> list[str]:
    techniques: set[str] = set()
    for cluster in (assessment.get('clusters') or []):
        p = cluster.get('tier1_prefill') or {}
        for t in (p.get('mitre_techniques') or []):
            tid = str(t).upper()[:7].replace(' ', '').split('-')[0]
            if tid.startswith('T'):
                techniques.add(tid)
    return sorted(techniques)


def _verdict(assessment: dict) -> str:
    return str(assessment.get('verdict') or 'SUSPECTED BREACH').upper()


def _headline(assessment: dict) -> str:
    for cluster in (assessment.get('clusters') or []):
        p = cluster.get('tier1_prefill') or {}
        h = p.get('incident_name') or p.get('headline_subtitle') or ''
        if h:
            return h
    return 'Unauthorised Access / Data Exfiltration Incident'


# ── NDB draft ────────────────────────────────────────────────────────────────

def _build_ndb(assessment: dict, meta: dict) -> dict:
    n_subjects, sample_users = _extract_subjects(assessment)
    techniques = _mitre_list(assessment)
    headline = _headline(assessment)
    org = meta.get('organisation', '[ORGANISATION NAME]')
    assessor = meta.get('assessor', '[ASSESSOR NAME AND TITLE]')

    body = f"""NOTIFIABLE DATA BREACH — STATEMENT OF NOTIFICATION
Prepared under the Privacy Act 1988 (Cth) Part IIIC — NDB Scheme

Date:       {_today_iso()}
Prepared by: {assessor}
Reference:  {assessment.get('assessment_id', '[ASSESSMENT-ID]')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ENTITY

Organisation: {org}
ABN: [INSERT ABN]
Contact for queries: privacy@[domain.com]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DESCRIPTION OF THE ELIGIBLE DATA BREACH

Nature of the breach: {headline}
Suspected cause:       Credential theft / unauthorised authentication followed by data exfiltration
Attack techniques:     {', '.join(techniques) or '[Pending forensic analysis]'}
Assessment verdict:    {_verdict(assessment)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KINDS OF INFORMATION INVOLVED

[ ] Full names              [ ] Email addresses        [ ] Physical addresses
[ ] Phone numbers           [ ] Date of birth          [ ] Government identifiers (TFN, Medicare, Passport)
[ ] Financial account info  [ ] Health information     [ ] Passwords / credentials
[ ] Other: [INSERT DESCRIPTION]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INDIVIDUALS AFFECTED

Estimated count:  {n_subjects if n_subjects else '[PENDING — FORENSIC REVIEW REQUIRED]'}
{"Sample identities (internal reference only, not for public release):" if sample_users else ""}
{chr(10).join("  - " + u for u in sample_users) if sample_users else ""}

NOTE: Affected individual count requires forensic confirmation.
If exact count is unavailable within the 72-hour window, provide
a reasonable estimate and confirm the basis for that estimate.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEPS TAKEN IN RESPONSE

1. Immediate containment — [INSERT: e.g. revoked compromised credentials, blocked malicious IP ranges]
2. Evidence preservation — [INSERT: e.g. mailbox legal hold applied, SIEM logs archived]
3. Forensic investigation — [INSERT: current status, retained firm if applicable]
4. Enhanced monitoring — [INSERT: additional detection rules, EDR containment]
5. Notification — This statement to OAIC; direct notification to affected individuals to follow.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NOTIFICATION TO OAIC

This statement is submitted to the Office of the Australian Information Commissioner (OAIC)
at notifybreach@oaic.gov.au in accordance with s. 26WK of the Privacy Act 1988 (Cth).

Deadline: 72 hours from the time the organisation first became aware of the eligible data
breach, or as soon as practicable thereafter (APP 1.2 / s. 26WH).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SIGNED

{assessor}
{_today_iso()}
[SIGNATURE]
"""
    return {
        'type': 'ndb',
        'title': 'NDB Notification — Privacy Act 1988 (Cth) Part IIIC',
        'body': body,
        'submit_to': 'notifybreach@oaic.gov.au',
        'deadline_hours': 72,
        'generated_at': _now_dt(),
    }


# ── GDPR draft ───────────────────────────────────────────────────────────────

def _build_gdpr(assessment: dict, meta: dict) -> dict:
    n_subjects, sample_users = _extract_subjects(assessment)
    techniques = _mitre_list(assessment)
    headline = _headline(assessment)
    org = meta.get('organisation', '[ORGANISATION NAME]')
    dpo = meta.get('dpo', '[DATA PROTECTION OFFICER NAME]')
    sa = meta.get('supervisory_authority', '[SUPERVISORY AUTHORITY — e.g. ICO, CNIL, BfDI]')

    body = f"""PERSONAL DATA BREACH NOTIFICATION
Prepared under GDPR Art. 33 (Notification to Supervisory Authority)

Date:         {_today_iso()}
Controller:   {org}
DPO Contact:  {dpo}
Reference:    {assessment.get('assessment_id', '[ASSESSMENT-ID]')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUPERVISORY AUTHORITY

{sa}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ART. 33(3) REQUIRED INFORMATION

(a) NATURE OF THE BREACH
    Type:          {headline}
    Attack chain:  {', '.join(techniques) or '[Pending analysis]'}
    Approximate date / period of breach: [INSERT DATE RANGE]
    Date discovered: {_today_iso()}

(b) DATA PROCESSOR INVOLVED (if applicable)
    Name / contact: [INSERT OR STATE NONE]

(c) CATEGORIES AND APPROXIMATE NUMBER OF INDIVIDUALS CONCERNED
    Categories: [e.g. employees, customers, users]
    Approximate number of individuals: {n_subjects if n_subjects else '[PENDING — forensic review]'}

(d) CATEGORIES AND APPROXIMATE NUMBER OF PERSONAL DATA RECORDS CONCERNED
    Data categories: [e.g. email addresses, login credentials, financial data]
    Approximate number of records: [INSERT OR STATE PENDING]

(e) LIKELY CONSEQUENCES OF THE BREACH
    Risk to rights and freedoms: [e.g. identity theft, financial loss, reputational harm]
    Assess whether Art. 34 notification to affected individuals is required.

(f) MEASURES TAKEN OR PROPOSED
    1. [INSERT: e.g. account suspension, credential reset]
    2. [INSERT: e.g. forensic investigation engaged]
    3. [INSERT: e.g. DLP controls tightened]
    4. [INSERT: e.g. law enforcement notification if applicable]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TIMELINE

This notification is submitted within 72 hours of becoming aware as required by GDPR Art. 33(1).
[ ] Notification is within 72 hours  [ ] Notification is delayed — reason: [INSERT]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ART. 34 — COMMUNICATION TO INDIVIDUALS

Assessment: [ ] Required — high risk to rights/freedoms
            [ ] Not required — risk is low / mitigated
Reason: [INSERT ASSESSMENT]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SIGNED

{dpo}
{org}
{_today_iso()}
[SIGNATURE]
"""
    return {
        'type': 'gdpr',
        'title': 'GDPR Art. 33 Supervisory Authority Notification',
        'body': body,
        'submit_to': f'{sa} (national DPA portal or email)',
        'deadline_hours': 72,
        'generated_at': _now_dt(),
    }


# ── Forensic Preservation Order ───────────────────────────────────────────────

def _build_forensic(assessment: dict, meta: dict) -> dict:
    techniques = _mitre_list(assessment)
    headline = _headline(assessment)
    org = meta.get('organisation', '[ORGANISATION NAME]')
    requestor = meta.get('assessor', '[REQUESTOR NAME AND TITLE]')

    body = f"""FORENSIC EVIDENCE PRESERVATION ORDER
Internal Chain-of-Custody Notice

Date:           {_today_iso()}
Organisation:   {org}
Incident Ref:   {assessment.get('assessment_id', '[ASSESSMENT-ID]')}
Requestor:      {requestor}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SCOPE OF INCIDENT

Incident:    {headline}
Techniques:  {', '.join(techniques) or '[Pending analysis]'}
Verdict:     {_verdict(assessment)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRESERVATION REQUIREMENTS

All personnel with access to the systems identified below MUST NOT:
  - Delete, modify, overwrite, or defragment any data
  - Apply system updates or patches without forensic approval
  - Power off systems without forensic approval (unless emergency)
  - Share credentials, artefacts, or incident details outside the
    incident response team without written approval

The following artefacts MUST be preserved and their integrity hash recorded:

[ ] Mail server message-trace logs (last 90 days)
[ ] Mailbox content of affected accounts (legal hold applied: [Y/N])
[ ] Authentication/SSO logs (Okta / Azure AD / ADFS)
[ ] DNS query logs (resolver, NDR)
[ ] Network flow logs (NSG / VPC flow / firewall)
[ ] Endpoint EDR telemetry for affected hosts
[ ] Cloud storage access logs (SharePoint, OneDrive, S3, GCS)
[ ] Identity directory snapshots (AD export, group membership)
[ ] SIEM raw event exports for the window: [INSERT DATE RANGE]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHAIN OF CUSTODY

Custodian:        [INSERT NAME AND ROLE]
Storage location: [INSERT SECURE PATH / EVIDENCE VAULT]
Hash algorithm:   SHA-256
Access log:       [INSERT LOCATION OF EVIDENCE ACCESS LOG]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LEGAL HOLD NOTICE

Automated data retention schedules that would purge relevant data
MUST be suspended immediately for the period: [INSERT HOLD PERIOD].

Systems affected: [INSERT SYSTEMS]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AUTHORISED BY

{requestor}
{_today_iso()}
[SIGNATURE]
"""
    return {
        'type': 'forensic',
        'title': 'Forensic Preservation Order — Chain of Custody Notice',
        'body': body,
        'generated_at': _now_dt(),
    }


# ── SEC Form 8-K stub ─────────────────────────────────────────────────────────

def _build_sec_8k(assessment: dict, meta: dict) -> dict:
    headline = _headline(assessment)
    org = meta.get('organisation', '[REGISTRANT NAME]')
    body = f"""UNITED STATES SECURITIES AND EXCHANGE COMMISSION
FORM 8-K — CURRENT REPORT
Pursuant to Section 13 or 15(d) of the Securities Exchange Act of 1934

Date of Report (Date of earliest event reported): {_today_iso()}
Registrant: {org}
[SEC File Number: INSERT]  [IRS Employer Identification No.: INSERT]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ITEM 1.05 — MATERIAL CYBERSECURITY INCIDENT

On or about {_today_iso()}, {org} became aware of a cybersecurity
incident involving {headline}.

The incident is assessed as: {_verdict(assessment)}

[INSERT: Brief description of the nature, scope, and timing of the incident.]
[INSERT: Whether any information was stolen, altered, or accessed without authorisation.]
[INSERT: Impact on operations, financial condition, or results of operations, if known.]
[INSERT: Status of remediation efforts.]

This disclosure is made pursuant to SEC Rule 10b-5 and the SEC's cybersecurity
disclosure requirements (effective December 2023, Release No. 33-11216).

NOTE: Do NOT disclose information that would impair ongoing law enforcement
investigations or national security. Consult legal counsel before filing.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Signature block per registrant requirements]
Generated: {_now_dt()}
Incident Ref: {assessment.get('assessment_id', '[ASSESSMENT-ID]')}
"""
    return {
        'type': 'sec_8k',
        'title': 'SEC Form 8-K — Item 1.05 Material Cybersecurity Incident',
        'body': body,
        'deadline_note': 'File within 4 business days of determining materiality (SEC Rule 10b-5)',
        'generated_at': _now_dt(),
    }


# ── ASX continuous disclosure ─────────────────────────────────────────────────

def _build_asx(assessment: dict, meta: dict) -> dict:
    headline = _headline(assessment)
    org = meta.get('organisation', '[ENTITY NAME]')
    body = f"""ASX LISTING RULE 3.1 — CONTINUOUS DISCLOSURE ANNOUNCEMENT

ENTITY:     {org}
ASX CODE:   [INSERT]
DATE:       {_today_iso()}

CYBERSECURITY INCIDENT — {headline.upper()}

{org} advises that it has detected a cybersecurity incident assessed as:
{_verdict(assessment)}

[INSERT: 2–4 sentences describing the incident in clear, factual terms without
disclosing attacker TTPs that would compromise the investigation or national security.]

The Company is undertaking a full forensic investigation with [INSERT: internal/external
incident response team]. Notification obligations to regulatory bodies are being assessed.

The Company will provide further updates as material information becomes available.
This announcement is authorised for release by the Board/CEO/CFO.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
For further information:

[INSERT: Company Secretary or Investor Relations contact]

Generated: {_now_dt()}
Incident Ref: {assessment.get('assessment_id', '[ASSESSMENT-ID]')}
"""
    return {
        'type': 'asx',
        'title': 'ASX Listing Rule 3.1 Continuous Disclosure Announcement',
        'body': body,
        'deadline_note': 'Immediately upon becoming aware of material information',
        'generated_at': _now_dt(),
    }


# ── Dispatcher ───────────────────────────────────────────────────────────────

_BUILDERS = {
    'ndb': _build_ndb,
    'gdpr': _build_gdpr,
    'forensic': _build_forensic,
    'sec_8k': _build_sec_8k,
    'asx': _build_asx,
}


def build_regulatory_draft(
    action_type: str,
    assessment: dict,
    meta: dict | None = None,
) -> dict:
    """Build a regulatory notification draft for the given action_type.

    Parameters
    ----------
    action_type : str
        One of: ndb, gdpr, forensic, sec_8k, asx
    assessment : dict
        Assessment data from REPORT_STORE / assessment_store.
    meta : dict, optional
        Overrides for organisation, assessor, dpo, supervisory_authority.

    Returns
    -------
    dict with keys: type, title, body, generated_at, [submit_to], [deadline_hours]
    """
    if meta is None:
        meta = {}
    builder = _BUILDERS.get((action_type or '').lower().replace('-', '_'))
    if builder is None:
        supported = sorted(_BUILDERS.keys())
        return {
            'error': f'Unknown action_type: {action_type!r}. Supported: {supported}',
            'supported': supported,
        }
    return builder(assessment, meta)
