"""Per-cluster control-witness ledger.

For every row in a cluster, record which compliance controls it triggers and
via which MITRE technique.  The output is a transparent evidence index that
lets the UI / regulator see *exactly* which row supports each control claim.

Schema:

    cluster['control_witnesses'] = {
        'AC-2': {
            'control_id':   'AC-2',
            'control_name': 'Account management',
            'framework':    'NIST 800-53',
            'rows':         [14, 22, 47],            # 0-based row indices
            'mitre':        ['T1078.004'],
            'sources':      ['CloudTrail', 'Okta'],  # distinct source sheets
            'witness_count':3,
            'derivation':   'mitre_mapping',
        },
        ...
    }

Why this matters
----------------
JanuSec's differentiator is multi-source narrative stitching.  When the
compliance tab claims AC-2 failed, the analyst (and the regulator) needs to
see *which rows from which sources* support that claim.  Without this
ledger, the persona dispatch payload contains controls whose rationale lives
only in the LLM's head — undefensible.
"""
from __future__ import annotations

import logging
from typing import Iterable

from src.prefill.compliance_tags import (
    _MITRE_TO_CONTROLS,
    _expand_technique,
    _normalise_technique,
)

logger = logging.getLogger(__name__)


_HVR_DOWNGRADE_FIELDS = (
    'approved_change',
    'change_ticket',
)


def _row_techniques(row: dict) -> list[str]:
    """Best-effort extraction of MITRE technique IDs from a normalised row.

    Mirrors the field aliases used elsewhere in the codebase
    (prefill_engine._infer_mitre_techniques, breach_endpoints lines 2295/1284).
    Falls back to keyword inference from event/process/description fields when
    no explicit technique IDs are present.
    """
    out: list[str] = []
    for f in ('mitre_technique', 'technique_id', 'mitre_id'):
        v = row.get(f)
        if v:
            out.append(str(v))
    for f in ('mitre', 'mitre_techniques', 'mitre_tags'):
        v = row.get(f)
        if isinstance(v, list):
            out.extend(str(x) for x in v if x)
        elif v:
            out.append(str(v))
    if not out:
        out.extend(_infer_techniques_from_keywords(row))
    return out


# Keyword → MITRE technique inference for rows that don't carry explicit IDs.
# Covers the most common Santos event patterns (cloud_identity, endpoint_k8s,
# network) so control_witnesses populates even without upstream MITRE tagging.
_KEYWORD_TECHNIQUE_MAP: list[tuple[tuple[str, ...], str]] = [
    # Credential access
    (('comsvcs', 'lsass', 'minidump'), 'T1003.001'),
    (('mimikatz', 'sekurlsa', 'wce'), 'T1003.001'),
    (('kerberoast', 'kerberoasting', 'spn'), 'T1558.003'),
    (('golden ticket', 'forged ticket', 'pass-the-ticket'), 'T1550.003'),
    (('pass-the-hash', 'pass the hash', 'pth'), 'T1550.002'),
    # Exfiltration
    (('rclone', 'backblaze b2', 'mega.nz'), 'T1567.002'),
    (('copy into s3', 'unload to s3', 'aws s3'), 'T1537'),
    (('snowflake copy', 'unload', 'copy into'), 'T1530'),
    # Persistence / payload delivery
    (('certutil', 'certutil.exe'), 'T1105'),
    (('scheduled task', 'schtasks'), 'T1053.005'),
    # Privilege escalation / container escape
    (('hostpid', 'hostnetwork', 'daemonset', 'privileged container'), 'T1611'),
    (('assumerole', 'sts:assumerole'), 'T1548.001'),
    (('eks', 'eks-integration'), 'T1548.001'),
    # Discovery
    (('getsecretvalue', 'secretsmanager'), 'T1555.006'),
    (('list-buckets', 's3:listbuckets'), 'T1619'),
    # Initial access
    (('phish', 'spear-phish', 'malicious attachment'), 'T1566.001'),
    # Defense evasion
    (('msiexec /quiet', 'msi silent'), 'T1218.007'),
    (('certutil -decode', 'certutil decode'), 'T1140'),
    # Lateral movement
    (('psexec', 'wmiexec', 'rdp login'), 'T1021.001'),
    # C2
    (('beacon', 'c2', 'command-and-control', 'dns tunnel'), 'T1071.004'),
    (('ja3', 'cobalt strike', 'cobaltstrike'), 'T1071.001'),
]


def _infer_techniques_from_keywords(row: dict) -> list[str]:
    """Infer MITRE technique IDs from event/process/description keywords."""
    # Build a lower-cased search corpus from common text fields
    corpus_parts = []
    for f in ('event_name', 'event_simpleName', 'process_name', 'cmdline',
              'command_line', 'description', 'technique', 'event_type',
              '_raw', 'message', 'dns_query', 'resource', 'action'):
        v = row.get(f)
        if v and isinstance(v, str):
            corpus_parts.append(v.lower())
    if not corpus_parts:
        return []
    corpus = ' '.join(corpus_parts)
    techniques: list[str] = []
    for keywords, tid in _KEYWORD_TECHNIQUE_MAP:
        if any(kw in corpus for kw in keywords):
            techniques.append(tid)
    return techniques


def _row_source(row: dict) -> str:
    return str(
        row.get('_sheet')
        or row.get('source_sheet')
        or row.get('source')
        or row.get('sheet')
        or 'unknown'
    )


def _row_is_approved_change(row: dict) -> bool:
    if (row.get('policy_change_context') or {}).get('approved_change'):
        return True
    return any(bool(row.get(k)) for k in _HVR_DOWNGRADE_FIELDS)


def attach_control_witnesses(cluster: dict, rows: Iterable[dict]) -> dict:
    """Compute and attach per-control witness ledger to ``cluster``.

    ``rows`` should be the rows that belong to ``cluster``; callers usually
    derive this from ``cluster['row_refs']`` against the assessment's
    normalised row list.

    Returns the witness dict (also stored under ``cluster['control_witnesses']``).
    """
    witnesses: dict[str, dict] = {}

    for idx, row in enumerate(rows or []):
        if not isinstance(row, dict):
            continue
        techniques = _row_techniques(row)
        if not techniques:
            continue

        approved = _row_is_approved_change(row)
        source = _row_source(row)
        # Prefer the assessment-level row index if the row carries one.
        row_id = row.get('_row_id')
        if not isinstance(row_id, int):
            row_id = idx

        for raw_tid in techniques:
            norm_tid = _normalise_technique(raw_tid)
            if not norm_tid:
                continue
            for tid in _expand_technique(norm_tid):
                for fw, cid, name in _MITRE_TO_CONTROLS.get(tid, []):
                    entry = witnesses.get(cid)
                    if entry is None:
                        entry = {
                            'control_id':    cid,
                            'control_name':  name,
                            'framework':     fw,
                            'rows':          [],
                            'mitre':         [],
                            'sources':       [],
                            'witness_count': 0,
                            'downgraded':    False,
                            'derivation':    'mitre_mapping',
                        }
                        witnesses[cid] = entry
                    if row_id not in entry['rows']:
                        entry['rows'].append(row_id)
                    if norm_tid not in entry['mitre']:
                        entry['mitre'].append(norm_tid)
                    if source not in entry['sources']:
                        entry['sources'].append(source)
                    entry['witness_count'] = len(entry['rows'])
                    if approved:
                        entry['downgraded'] = True

    # ── Cluster-level fallback ────────────────────────────────────────────
    # When row scanning yields nothing (e.g. rows not available in-memory
    # after restart), synthesise witnesses from MITRE techniques already
    # stored at the cluster level by the ingest/narrator pipeline.
    if not witnesses:
        cluster_techniques: list[str] = []
        for key in ('mitre_techniques', 'top_mitre', 'mitre_tags'):
            v = cluster.get(key) or []
            if isinstance(v, list):
                cluster_techniques.extend(str(x) for x in v if x)
        prefill = cluster.get('tier1_prefill') or {}
        for key in ('mitre_techniques', 'top_techniques'):
            v = prefill.get(key) or []
            if isinstance(v, list):
                cluster_techniques.extend(str(x) for x in v if x)
        for raw_tid in cluster_techniques:
            norm_tid = _normalise_technique(raw_tid)
            if not norm_tid:
                continue
            for tid in _expand_technique(norm_tid):
                for fw, cid, name in _MITRE_TO_CONTROLS.get(tid, []):
                    entry = witnesses.get(cid)
                    if entry is None:
                        entry = {
                            'control_id':    cid,
                            'control_name':  name,
                            'framework':     fw,
                            'rows':          [],
                            'mitre':         [],
                            'sources':       ['cluster_level'],
                            'witness_count': 1,
                            'downgraded':    False,
                            'derivation':    'cluster_mitre_fallback',
                        }
                        witnesses[cid] = entry
                    if norm_tid not in entry['mitre']:
                        entry['mitre'].append(norm_tid)

    cluster['control_witnesses'] = witnesses
    return witnesses


def witnesses_to_control_failures(
    witnesses: dict[str, dict],
    *,
    min_witness_count: int = 1,
) -> list[dict]:
    """Reshape ``control_witnesses`` into the ``control_failures`` array
    breach.js (compliance persona tab) expects.

    Severity heuristic:
        witness_count >= 3 and sources >= 2  → 'high'
        witness_count >= 2                   → 'medium'
        otherwise                            → 'low'

    Downgraded entries (approved-change witnessed) drop one tier.
    """
    out: list[dict] = []
    for entry in witnesses.values():
        wc = int(entry.get('witness_count') or 0)
        if wc < min_witness_count:
            continue
        sources = entry.get('sources') or []
        if wc >= 3 and len(sources) >= 2:
            sev = 'high'
        elif wc >= 2:
            sev = 'medium'
        else:
            sev = 'low'
        if entry.get('downgraded'):
            sev = {'high': 'medium', 'medium': 'low', 'low': 'low'}[sev]
        out.append({
            'control_id':       entry['control_id'],
            'control_name':     entry.get('control_name') or entry['control_id'],
            'framework':        entry.get('framework') or '',
            'failure':          entry.get('control_name') or entry['control_id'],
            'severity':         sev,
            'evidence_row_ids': list(entry.get('rows') or []),
            'triggered_by':     list(entry.get('mitre') or []),
            'sources':          list(sources),
            'witness_count':    wc,
            'remediation_priority': 'P1' if sev == 'high' else ('P2' if sev == 'medium' else 'P3'),
        })
    # Stable order: high severity first, then by witness count desc, then control id
    sev_rank = {'high': 0, 'medium': 1, 'low': 2}
    out.sort(key=lambda e: (sev_rank.get(e['severity'], 9), -e['witness_count'], e['control_id']))
    return out


def witnesses_to_cross_framework(witnesses: dict[str, dict]) -> dict[str, dict]:
    """Group witnesses by ISO 27001 control id, surfacing parallel framework
    coverage.  Used by the cross_framework_evidence table in the UI.
    """
    iso_index: dict[str, dict] = {}
    other_by_mitre: dict[str, list[dict]] = {}

    for entry in witnesses.values():
        if entry.get('framework') == 'ISO 27001:2022':
            iso_index[entry['control_id']] = entry
        else:
            for tid in entry.get('mitre') or []:
                other_by_mitre.setdefault(tid, []).append(entry)

    out: dict[str, dict] = {}
    for iso_id, iso_entry in iso_index.items():
        crosswalk = {
            'iso_27001':       iso_id,
            'iso_27001_name':  iso_entry.get('control_name') or '',
            'nist_csf':        '',
            'essential_eight': '',
            'nist_800_53':     '',
            'evidence_reuse_pct': 0,
        }
        related = []
        for tid in iso_entry.get('mitre') or []:
            related.extend(other_by_mitre.get(tid, []))
        rows_iso = set(iso_entry.get('rows') or [])
        reused = 0
        for rel in related:
            fw = rel.get('framework') or ''
            cid = rel.get('control_id') or ''
            if fw == 'NIST CSF 2.0' and not crosswalk['nist_csf']:
                crosswalk['nist_csf'] = cid
            elif fw == 'Essential Eight' and not crosswalk['essential_eight']:
                crosswalk['essential_eight'] = cid
            elif fw == 'NIST 800-53' and not crosswalk['nist_800_53']:
                crosswalk['nist_800_53'] = cid
            shared = rows_iso & set(rel.get('rows') or [])
            if rows_iso:
                reused = max(reused, int(round(100 * len(shared) / max(1, len(rows_iso)))))
        crosswalk['evidence_reuse_pct'] = reused
        out[iso_id] = crosswalk
    return out
