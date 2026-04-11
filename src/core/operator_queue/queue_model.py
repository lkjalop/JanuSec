"""Assessment-local operator queue — data model and state machine.

Design
──────
Every cluster produced by the deep_analyze pipeline becomes a QueueItem.
Isolated rows (not in any cluster) become lower-priority QueueItems if their
triage_score exceeds the ISOLATED_ROW_THRESHOLD.

State machine
─────────────
           ┌─────────────────────────────────────────────┐
           │                  NEW EVIDENCE               │
           │                (corroboration delta)        │
           ▼                                             │
    ┌─────────────┐   analyst      ┌───────────────────┐ │
    │   Active    │──────────────► │    Escalated      │ │
    └──────┬──────┘   escalate     └───────────────────┘ │
           │                                              │
           │ analyst               ┌───────────────────┐  │
           │ deny/clear ──────────►│    Cleared        │  │
           │                       └───────────────────┘  │
           │                                              │
           │ analyst               ┌───────────────────┐  │
           │ defer     ──────────► │    Deferred       │──┘
           │                       └────────┬──────────┘
           │                                │ reopen_condition met
           │                                ▼
           │                       ┌───────────────────┐
           │                       │    Remainder      │
           │                       └───────────────────┘
           │   highest priority
           └──────────────────────────────────────────────

Active:    The single highest-priority open item for the current persona.
           Auto-computed; not stored — derived on read from Remainder.
Remainder: Open backlog items, sorted by priority_score descending.
Cleared:   Analyst confirmed benign / resolved with evidence refs.
Escalated: Requires IR, forensics, legal/GRC, or customer action.
Deferred:  Waiting for telemetry, connector freshness, sandbox result,
           owner response, or corroboration count to reach threshold.

Corroboration delta (Approach A)
─────────────────────────────────
New rows added to an assessment carry entity tags (IPs, users, hosts, hashes).
If a Deferred/Remainder item shares ≥ CORROBORATION_THRESHOLD distinct
entities with the new rows, its corroboration_count increments and its
priority_score is recalculated:
  priority_score = base_risk × (1 + 0.1 × corroboration_count)
Items in state Deferred are automatically returned to Remainder once
either:
  (a) corroboration_count hits the item's reopen_threshold, or
  (b) wall-clock time passes reopen_at.

Human-confirmed transitions (Approach B)
─────────────────────────────────────────
Every analyst action creates a QueueAction record with:
  actor, action, timestamp, evidence_refs, rationale
These are immutable and form the chain-of-custody ledger for the item.
A human-Escalated item cannot be auto-cleared by new evidence — it can
only receive a "new_evidence_available" flag and an incremented counter.

TTL-gated re-evaluation (Approach C)
─────────────────────────────────────
Deferred items carry reopen_at (epoch) and reopen_conditions (list).
On each queue read, expired Deferred items return to Remainder with the
cumulative evidence delta attached as a transition record.
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any


# ── Constants ────────────────────────────────────────────────────────────────

ISOLATED_ROW_THRESHOLD = 55          # min triage_score for a standalone-row queue item
CORROBORATION_THRESHOLD = 2          # new shared entities needed to promote
DEFAULT_REOPEN_TTL = 7 * 24 * 3600  # 7 days default Deferred re-evaluation window


# ── Enums ────────────────────────────────────────────────────────────────────

class QueueState(str, Enum):
    REMAINDER = 'remainder'
    CLEARED = 'cleared'
    ESCALATED = 'escalated'
    DEFERRED = 'deferred'


class QueueAction(str, Enum):
    """Analyst-driven or system-driven state transitions."""
    CONFIRM = 'confirm'          # analyst confirms threat is real → may stay Remainder/go Active
    DENY = 'deny'                # analyst denies → Cleared
    DEFER = 'defer'              # analyst defers → Deferred with reopen condition
    ESCALATE = 'escalate'        # analyst escalates → Escalated
    REOPEN = 'reopen'            # system/analyst reopens a Cleared/Deferred item
    ADD_EVIDENCE = 'add_evidence' # new evidence attached (no state change — flags new_evidence_available)
    CORROBORATE = 'corroborate'  # system: corroboration delta pushed item back to Remainder


# ── Data classes (plain dicts for JSON-serializable storage) ─────────────────

def _now() -> float:
    return time.time()


def make_queue_item(
    *,
    cluster: dict[str, Any] | None = None,
    row: dict[str, Any] | None = None,
    assessment_id: str,
    persona: str = 'soc_analyst',
) -> dict[str, Any]:
    """Create a new QueueItem dict from a cluster or an isolated row.

    Priority score formula:
      base_risk × (1 + 0.1 × corroboration_count)
    where base_risk comes from the severity label:
      critical=1.0, high=0.75, medium=0.5, low=0.2
    """
    _sev_base = {'critical': 1.0, 'high': 0.75, 'medium': 0.5, 'low': 0.2, 'unknown': 0.1}
    item_id = str(uuid.uuid4())

    if cluster:
        sev = (cluster.get('severity') or 'unknown').lower()
        base_risk = _sev_base.get(sev, 0.1)
        confidence = float(cluster.get('confidence') or 0.5)
        row_count = len(cluster.get('row_refs') or [])
        shared_entity_count = (
            len(cluster.get('shared_accounts') or []) +
            len(cluster.get('shared_hosts') or []) +
            len(cluster.get('shared_external_ips') or [])
        )
        # More entities = more lateral movement evidence = higher priority
        entity_bonus = min(0.3, shared_entity_count * 0.05)
        priority_score = round(base_risk * confidence * (1 + entity_bonus), 4)

        return {
            'item_id': item_id,
            'assessment_id': assessment_id,
            'source': 'cluster',
            'cluster_id': cluster.get('cluster_id'),
            'row_refs': cluster.get('row_refs') or [],
            'evidence_refs': cluster.get('evidence_refs') or [],
            'severity': sev,
            'confidence': confidence,
            'base_risk': base_risk,
            'entity_bonus': entity_bonus,
            'priority_score': priority_score,
            'state': QueueState.REMAINDER,
            'persona_focus': persona,
            'title': _cluster_title(cluster),
            'summary': cluster.get('reason_summary') or cluster.get('lead_description') or '',
            'shared_accounts': cluster.get('shared_accounts') or [],
            'shared_hosts': cluster.get('shared_hosts') or [],
            'shared_ips': cluster.get('shared_external_ips') or [],
            'top_mitre': cluster.get('top_mitre') or [],
            'source_sheets': cluster.get('source_sheets') or [],
            'time_window': cluster.get('time_window') or {},
            # Evidence management
            'corroboration_count': 0,
            'requires_human_validation': False,
            'new_evidence_available': False,
            'evidence_delta': [],        # new entity overlaps since last analyst review
            # Deferred fields (populated on defer action)
            'reopen_at': None,
            'reopen_conditions': [],
            'reopen_threshold': CORROBORATION_THRESHOLD,
            # Audit trail (QueueActionRecord list)
            'actions': [],
            'created_at': _now(),
            'updated_at': _now(),
        }

    elif row:
        sev = (row.get('severity') or 'unknown').lower()
        base_risk = _sev_base.get(sev, 0.1)
        triage = float(row.get('triage_score') or 0.0) / 100.0
        priority_score = round(base_risk * max(triage, 0.1), 4)
        entity_bonus = 0.0  # isolated rows have no multi-entity corroboration bonus

        return {
            'item_id': item_id,
            'assessment_id': assessment_id,
            'source': 'isolated_row',
            'cluster_id': None,
            'row_refs': [int(row.get('row_index') or 0)],
            'evidence_refs': [f"R{int(row.get('row_index') or 0)}"],
            'severity': sev,
            'confidence': triage,
            'base_risk': base_risk,
            'entity_bonus': entity_bonus,
            'priority_score': priority_score,
            'state': QueueState.REMAINDER,
            'persona_focus': persona,
            'title': _row_title(row),
            'summary': row.get('llm_summary') or row.get('description') or '',
            'shared_accounts': [str(row.get('user') or row.get('account') or '')] if (row.get('user') or row.get('account')) else [],
            'shared_hosts': [str(row.get('host') or '')] if row.get('host') else [],
            'shared_ips': [str(row.get('dst_ip') or '')] if row.get('dst_ip') else [],
            'top_mitre': row.get('mitre') or [],
            'source_sheets': [str(row.get('_sheet') or row.get('source_sheet') or '')],
            'time_window': {},
            'corroboration_count': 0,
            'requires_human_validation': False,
            'new_evidence_available': False,
            'evidence_delta': [],
            'reopen_at': None,
            'reopen_conditions': [],
            'reopen_threshold': CORROBORATION_THRESHOLD,
            'actions': [],
            'created_at': _now(),
            'updated_at': _now(),
        }
    else:
        raise ValueError('Either cluster or row must be provided')


def _cluster_title(cluster: dict[str, Any]) -> str:
    sev = (cluster.get('severity') or 'Unknown').title()
    sheets = ', '.join(cluster.get('source_sheets') or [])
    accounts = cluster.get('shared_accounts') or []
    ips = cluster.get('shared_external_ips') or []
    mitre = cluster.get('top_mitre') or []
    if accounts:
        pivot = accounts[0]
    elif ips:
        pivot = ips[0]
    else:
        pivot = ''
    technique = mitre[0] if mitre else ''
    parts = [sev + ' cluster']
    if pivot:
        parts.append(f'pivot={pivot}')
    if sheets:
        parts.append(sheets)
    if technique:
        parts.append(technique)
    return ' · '.join(parts)


def _row_title(row: dict[str, Any]) -> str:
    sev = (row.get('severity') or 'Unknown').title()
    event_type = row.get('event_type') or row.get('action') or ''
    host = row.get('host') or row.get('hostname') or ''
    user = row.get('user') or row.get('account') or ''
    pivot = host or user or ''
    parts = [sev]
    if event_type:
        parts.append(event_type)
    if pivot:
        parts.append(pivot)
    return ' · '.join(parts)


# ── Action execution ─────────────────────────────────────────────────────────

def apply_action(
    item: dict[str, Any],
    action: QueueAction | str,
    *,
    actor: str = 'analyst',
    evidence_refs: list[str] | None = None,
    rationale: str = '',
    reopen_at: float | None = None,
    reopen_conditions: list[str] | None = None,
) -> dict[str, Any]:
    """Apply an analyst or system action to a QueueItem, returning the modified item.

    Every application creates an immutable QueueActionRecord and appends it to
    item['actions'].  Human-escalated items cannot be auto-cleared — they can
    only receive ADD_EVIDENCE annotations.  Deferred items carry reopen_at /
    reopen_conditions for Approach C TTL re-evaluation.
    """
    action = QueueAction(action) if isinstance(action, str) else action
    record = {
        'action': action,
        'actor': actor,
        'timestamp': _now(),
        'evidence_refs': evidence_refs or [],
        'rationale': rationale,
        'prior_state': item['state'],
    }

    if action == QueueAction.DENY:
        item['state'] = QueueState.CLEARED
    elif action == QueueAction.CONFIRM:
        # Confirm keeps in Remainder (Active is derived on read); just registers evidence
        item['state'] = QueueState.REMAINDER
        if evidence_refs:
            item['evidence_refs'] = sorted(set((item.get('evidence_refs') or []) + evidence_refs))
    elif action == QueueAction.ESCALATE:
        item['state'] = QueueState.ESCALATED
    elif action == QueueAction.DEFER:
        item['state'] = QueueState.DEFERRED
        item['reopen_at'] = reopen_at or (_now() + DEFAULT_REOPEN_TTL)
        item['reopen_conditions'] = reopen_conditions or []
        item['reopen_threshold'] = max(item.get('reopen_threshold', CORROBORATION_THRESHOLD),
                                       CORROBORATION_THRESHOLD)
    elif action == QueueAction.REOPEN:
        item['state'] = QueueState.REMAINDER
        item['new_evidence_available'] = False
        item['reopen_at'] = None
        item['reopen_conditions'] = []
    elif action == QueueAction.ADD_EVIDENCE:
        # Never changes state for human-Escalated items — only annotates
        if evidence_refs:
            item['evidence_refs'] = sorted(set((item.get('evidence_refs') or []) + evidence_refs))
        item['new_evidence_available'] = True
    elif action == QueueAction.CORROBORATE:
        item['corroboration_count'] = item.get('corroboration_count', 0) + 1
        # Recalculate priority with corroboration multiplier
        item['priority_score'] = round(
              item['base_risk'] * item['confidence'] * (1 + item.get('entity_bonus', 0.0) + 0.1 * item['corroboration_count']),
              4,
          )
        if item['state'] == QueueState.DEFERRED:
            if item['corroboration_count'] >= item.get('reopen_threshold', CORROBORATION_THRESHOLD):
                item['state'] = QueueState.REMAINDER
                record['note'] = 'Auto-promoted: corroboration threshold reached'
        item['new_evidence_available'] = True

    item['actions'].append(record)
    item['updated_at'] = _now()
    return item


# ── TTL re-evaluation (Approach C) ───────────────────────────────────────────

def reopen_expired_deferred(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return items list with any TTL-expired Deferred items moved to Remainder.

    Called on every queue read so Deferred items never silently die.
    """
    now = _now()
    for item in items:
        if item.get('state') != QueueState.DEFERRED:
            continue
        reopen_at = item.get('reopen_at')
        if reopen_at and now >= reopen_at:
            apply_action(
                item,
                QueueAction.REOPEN,
                actor='system:ttl',
                rationale=f'Deferred TTL expired at {reopen_at:.0f}',
            )
    return items


# ── Corroboration delta (Approach A) ─────────────────────────────────────────

def apply_new_evidence(
    items: list[dict[str, Any]],
    new_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Push new evidence entities into existing queue items, corroborating or denying.

    For each item, extract the entity sets it already knows about.
    For each new_row, extract its entity set.
    If the overlap reaches CORROBORATION_THRESHOLD distinct entities, apply
    a CORROBORATE action.  If a new_row carries disposition='benign'/'cleared'
    and its entities match a Remainder/Deferred item, add an ADD_EVIDENCE
    note so analysts see contradicting evidence.

    Human-Escalated items are never auto-changed — only annotated.
    """
    _IP_FIELDS = ('src_ip', 'dst_ip', 'ip', 'source_ip', 'destination_ip',
                  'remote_ip', 'ip_address')
    _USER_FIELDS = ('user', 'username', 'user_principal_name', 'account',
                    'principal', 'actor')
    _HOST_FIELDS = ('host', 'hostname', 'computer', 'device', 'machine')
    _HASH_FIELDS = ('sha256', 'md5', 'sha1', 'file_hash', 'hash')

    def _entity_set(row: dict) -> set[str]:
        entities: set[str] = set()
        for fields in (_IP_FIELDS, _USER_FIELDS, _HOST_FIELDS, _HASH_FIELDS):
            for f in fields:
                v = str(row.get(f) or '').strip()
                if v and v.lower() not in ('none', 'null', '-', ''):
                    entities.add(v.lower())
        return entities

    for item in items:
        # Build known entity set for this item
        item_entities: set[str] = set()
        for ip in (item.get('shared_ips') or []):
            item_entities.add(str(ip).lower())
        for u in (item.get('shared_accounts') or []):
            item_entities.add(str(u).lower())
        for h in (item.get('shared_hosts') or []):
            item_entities.add(str(h).lower())

        if not item_entities:
            continue

        # Already-Cleared items do not receive corroboration
        if item.get('state') == QueueState.CLEARED:
            continue

        matching_rows: list[dict] = []
        denying_rows: list[dict] = []
        for row in new_rows:
            row_entities = _entity_set(row)
            overlap = item_entities & row_entities
            if not overlap:
                continue
            disp = str(row.get('disposition') or row.get('review_state') or '').lower()
            if any(d in disp for d in ('benign', 'false_positive', 'cleared', 'allow')):
                denying_rows.append(row)
            else:
                matching_rows.append(row)

        # Corroboration
        if len(matching_rows) >= CORROBORATION_THRESHOLD:
            new_refs = [f"R{int(r.get('row_index') or 0)}" for r in matching_rows]
            delta = item.get('evidence_delta') or []
            delta.extend(new_refs)
            item['evidence_delta'] = delta[-20:]  # keep last 20 only
            apply_action(
                item,
                QueueAction.CORROBORATE,
                actor='system:corroboration',
                evidence_refs=new_refs,
                rationale=f'{len(matching_rows)} new row(s) share entities with this item',
            )

        # Denial/contradiction evidence (Approach B: annotate only)
        if denying_rows:
            deny_refs = [f"R{int(r.get('row_index') or 0)}" for r in denying_rows]
            apply_action(
                item,
                QueueAction.ADD_EVIDENCE,
                actor='system:contradiction',
                evidence_refs=deny_refs,
                rationale=(
                    f'{len(denying_rows)} new row(s) with benign/cleared disposition '
                    'share entities — analyst review required to determine if they '
                    'deny this threat or represent parallel benign activity.'
                ),
            )

    return items


# ── Queue derivation from assessment ─────────────────────────────────────────

def build_queue_from_assessment(
    assessment: dict[str, Any],
    persona: str = 'soc_analyst',
) -> list[dict[str, Any]]:
    """Derive a fresh queue from an assessment's clusters and isolated rows.

    Cluster items are always created first (higher priority).
    Isolated rows above ISOLATED_ROW_THRESHOLD are appended after.
    Returns items sorted by priority_score descending (Remainder first).
    """
    assessment_id = str(assessment.get('assessment_id') or '')
    items: list[dict[str, Any]] = []

    # From clusters
    for cluster in (assessment.get('clusters') or []):
        item = make_queue_item(
            cluster=cluster,
            assessment_id=assessment_id,
            persona=persona,
        )
        items.append(item)

    # From isolated rows (triage_score ≥ threshold)
    llm_rows = assessment.get('llm_rows') or []
    findings = assessment.get('findings') or []
    ev_rows = llm_rows if llm_rows else findings
    cluster_row_refs = {
        ref
        for item in items
        for ref in (item.get('row_refs') or [])
    }
    for row in ev_rows:
        idx = int(row.get('row_index') or 0)
        if idx in cluster_row_refs:
            continue
        score = float(row.get('triage_score') or 0.0)
        if score < ISOLATED_ROW_THRESHOLD:
            continue
        item = make_queue_item(
            row=row,
            assessment_id=assessment_id,
            persona=persona,
        )
        items.append(item)

    # Sort: Remainder/Escalated by priority desc; Cleared/Deferred after
    def _sort_key(it: dict) -> tuple:
        state_order = {
            QueueState.REMAINDER: 0,
            QueueState.ESCALATED: 1,
            QueueState.DEFERRED: 2,
            QueueState.CLEARED: 3,
        }
        return (state_order.get(it.get('state'), 4), -it.get('priority_score', 0))

    items.sort(key=_sort_key)
    return items


def get_active_item(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the single highest-priority Remainder item (the 'Active' item).

    Active is not a stored state — it is computed from the Remainder list.
    This keeps the state machine simple and prevents stale Active flags.
    """
    remainder = [it for it in items if it.get('state') == QueueState.REMAINDER]
    if not remainder:
        return None
    return max(remainder, key=lambda it: it.get('priority_score', 0))


def get_queue_view(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a structured queue view with Active, Remainder, Escalated,
    Deferred, and Cleared buckets for UI rendering."""
    # Run TTL re-evaluation first
    items = reopen_expired_deferred(items)

    active = get_active_item(items)
    active_id = active['item_id'] if active else None

    remainder = sorted(
        [it for it in items
         if it.get('state') == QueueState.REMAINDER and it['item_id'] != active_id],
        key=lambda it: -it.get('priority_score', 0),
    )
    escalated = [it for it in items if it.get('state') == QueueState.ESCALATED]
    deferred = [it for it in items if it.get('state') == QueueState.DEFERRED]
    cleared = [it for it in items if it.get('state') == QueueState.CLEARED]

    return {
        'active': active,
        'remainder': remainder,
        'escalated': escalated,
        'deferred': deferred,
        'cleared': cleared,
        'counts': {
            'active': 1 if active else 0,
            'remainder': len(remainder),
            'escalated': len(escalated),
            'deferred': len(deferred),
            'cleared': len(cleared),
            'total': len(items),
        },
    }
