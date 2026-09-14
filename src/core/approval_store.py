from __future__ import annotations
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

APPROVALS_DIR = os.environ.get('APPROVAL_STORE_DIR', 'data/approvals')
os.makedirs(APPROVALS_DIR, exist_ok=True)
APPROVALS_FILE = os.path.join(APPROVALS_DIR, 'approvals.jsonl')

# Optional DB-backed repo (resolved dynamically to honor env updates in tests)
USE_DB = False
_DB_READY = False
try:
    from src.core import approval_repo as _approval_repo  # type: ignore
except Exception:
    _approval_repo = None  # type: ignore


def _use_db() -> bool:
    """Return True when DB-backed approvals should be used (env-driven, lazy init)."""
    global USE_DB, _DB_READY
    enabled = os.environ.get('USE_APPROVAL_DB', '0').lower() in {'1', 'true', 'yes'}
    if not enabled:
        return False
    if _approval_repo is None:
        return False
    if not USE_DB:
        USE_DB = True
    try:
        db_path = _approval_repo._db_path()  # type: ignore[attr-defined]
    except Exception:
        db_path = None
    if db_path and not os.path.exists(db_path):
        _DB_READY = False
    if USE_DB and not _DB_READY:
        try:
            _approval_repo.init_db()
        except Exception:
            USE_DB = False
            return False
        _DB_READY = True
    return USE_DB


def _append_record(record: Dict[str, Any]):
    if _use_db():
        try:
            # translate event record into DB calls
            ev = record.get('event')
            token = record.get('token')
            if ev == 'request':
                payload = record.copy()
                _approval_repo.save_request(token, payload.get('request') or {}, payload.get('expires_at'))
                return
            if ev == 'approve':
                _approval_repo.save_approve(token, record.get('approver'), record.get('note'))
                return
            if ev == 'revoke':
                _approval_repo.save_revoke(token, record.get('revoked_by'), record.get('reason'))
                return
            return
        except Exception:
            # fallback to file
            pass
    # Ensure directory exists (defensive: tests may run with different cwd)
    try:
        os.makedirs(APPROVALS_DIR, exist_ok=True)
    except Exception:
        pass
    with open(APPROVALS_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record) + "\n")


def create_request(token: str, request_data: Dict[str, Any], expiry_seconds: Optional[int] = None):
    now = datetime.utcnow()
    rec = {
        'token': token,
        'requested_at': now.isoformat() + 'Z',
        'request': request_data,
        'status': 'requested',
        'revoked': False,
    }
    if expiry_seconds is not None:
        rec['expires_at'] = (now + timedelta(seconds=expiry_seconds)).isoformat() + 'Z'
    if _use_db():
        _approval_repo.save_request(token, request_data, rec.get('expires_at'))
        return rec
    _append_record({'event': 'request', **rec})
    return rec


def approve_token(token: str, approver: str, note: Optional[str] = None):
    now = datetime.utcnow()
    rec = {
        'token': token,
        'approved_at': now.isoformat() + 'Z',
        'approver': approver,
        'status': 'approved'
    }
    if note:
        rec['note'] = note
    if _use_db():
        _approval_repo.save_approve(token, approver, note)
        return rec
    _append_record({'event': 'approve', **rec})
    return rec


def revoke_token(token: str, revoked_by: str, reason: Optional[str] = None):
    now = datetime.utcnow()
    rec = {
        'token': token,
        'revoked_at': now.isoformat() + 'Z',
        'revoked_by': revoked_by,
        'status': 'revoked'
    }
    if reason:
        rec['reason'] = reason
    if _use_db():
        _approval_repo.save_revoke(token, revoked_by, reason)
        return rec
    _append_record({'event': 'revoke', **rec})
    return rec


def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception:
        return None


def is_approved(token: str) -> bool:
    # DB-backed check
    if _use_db():
        st = _approval_repo.get_status(token)
        if not st:
            return False
        # revoked wins
        if st.get('status') == 'revoked':
            return False
        # check expiry
        exp = st.get('expires_at')
        if exp:
            exp_dt = _parse_iso(exp)
            if exp_dt and datetime.utcnow() > exp_dt:
                return False
        # Multi-approver: consult policy matching this request's action when available
        try:
            # st may include parsed request
            action = None
            if st.get('request') and isinstance(st.get('request'), dict):
                action = st.get('request', {}).get('action')
            policy = None
            if action:
                policy = _approval_repo.find_policy_for_action(action)
            if policy:
                n = int(policy.get('n_required') or 1)
                m = int(policy.get('m_total') or 0)
                pool = policy.get('approver_pool') or []
                # collect unique approvers from events
                approvers = _approval_repo.get_approvers_for_token(token)
                # if approver pool defined, filter
                if pool:
                    approvers = [a for a in approvers if a in pool]
                cnt = len(set(approvers))
                # if m_total is set and pool provided, ensure pool size >= m
                if m and pool and len(pool) < m:
                    # invalid policy config -> treat as not approved
                    return False
                return cnt >= n
            # fallback: env variable APPROVAL_N_OF_M allows 'n:m' default None
            n_of_m = os.getenv('APPROVAL_N_OF_M')
            if n_of_m:
                try:
                    parts = n_of_m.split(':')
                    n = int(parts[0]); m = int(parts[1])
                    cnt = _approval_repo.count_approvals(token)
                    return cnt >= n
                except Exception:
                    pass
        except Exception:
            pass
        # legacy single-approve semantics
        if st.get('status') == 'approved':
            return True
        return False
    # file-based fallback
    if not os.path.exists(APPROVALS_FILE):
        return False
    status = None
    expires_at = None
    revoked = False
    with open(APPROVALS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get('token') != token:
                continue
            ev = r.get('event')
            if ev == 'request' and r.get('expires_at'):
                expires_at = _parse_iso(r['expires_at'])
            if ev == 'approve':
                status = 'approved'
            if ev == 'revoke':
                revoked = True
                status = 'revoked'
    if revoked:
        return False
    if status == 'approved':
        if expires_at is None:
            return True
        return datetime.utcnow() <= expires_at
    return False


def list_requests() -> List[Dict[str, Any]]:
    if _use_db():
        return _approval_repo.list_all()

    out: Dict[str, Dict[str, Any]] = {}
    if not os.path.exists(APPROVALS_FILE):
        return []
    with open(APPROVALS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            t = r.get('token')
            if not t:
                continue
            rec = out.get(t, {'token': t, 'events': [], 'status': 'unknown'})
            rec['events'].append(r)
            # inspect events to set status
            ev = r.get('event')
            if ev == 'request':
                rec['status'] = r.get('status', rec['status'])
                if r.get('expires_at'):
                    rec['expires_at'] = r['expires_at']
                rec['requested_at'] = r.get('requested_at')
                rec['requested_by'] = r.get('request', {}).get('requested_by')
            elif ev == 'approve':
                rec['status'] = 'approved'
                rec['approved_at'] = r.get('approved_at')
                rec['approver'] = r.get('approver')
            elif ev == 'revoke':
                rec['status'] = 'revoked'
                rec['revoked_at'] = r.get('revoked_at')
                rec['revoked_by'] = r.get('revoked_by')
            out[t] = rec
    return list(out.values())
