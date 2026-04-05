from __future__ import annotations

import glob
import json
import os
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional

# Optional Jinja2 support for richer templating
try:
    import jinja2  # type: ignore
    _HAS_JINJA = True
except Exception:
    _HAS_JINJA = False


def _playbook_files(dir_path: Optional[str] = None) -> List[str]:
    base = dir_path or os.getenv('PLAYBOOK_DIR', 'src/data/playbooks')
    return sorted(glob.glob(os.path.join(base, '*.json')))


def load_playbooks(dir_path: Optional[str] = None) -> List[Dict[str, Any]]:
    files = _playbook_files(dir_path)
    out: List[Dict[str, Any]] = []
    for p in files:
        try:
            with open(p, 'r', encoding='utf8') as fh:
                data = json.load(fh)
                if isinstance(data, dict):
                    data['_src_path'] = str(Path(p))
                    out.append(data)
        except Exception:
            # skip bad files silently for loader resilience
            continue
    return out


def build_index(playbooks: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Return mapping factor -> list of playbooks. Handles 'factor' and 'factor_any'."""
    idx: Dict[str, List[Dict[str, Any]]] = {}
    for pb in playbooks:
        trig = pb.get('trigger') or {}
        # single factor
        f = trig.get('factor')
        if f:
            idx.setdefault(f, []).append(pb)
        # any-of list
        fa = trig.get('factor_any') or []
        if isinstance(fa, list):
            for ff in fa:
                idx.setdefault(ff, []).append(pb)
        # optionally support prefix matcher 'factor_prefix'
        fp = trig.get('factor_prefix')
        if fp:
            # store under a pseudo-key to denote prefixes
            idx.setdefault(f'prefix::{fp}', []).append(pb)
    return idx


def resolve_for_factor(factor: str, dir_path: Optional[str] = None) -> List[Dict[str, Any]]:
    pbs = load_playbooks(dir_path)
    idx = build_index(pbs)
    matches: List[Dict[str, Any]] = []
    # exact matches
    matches.extend(idx.get(factor, []))
    # prefix matches
    for k, v in idx.items():
        if k.startswith('prefix::'):
            pref = k.split('::', 1)[1]
            if factor.startswith(pref):
                matches.extend(v)
    # dedupe by src path
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for m in matches:
        sp = m.get('_src_path')
        if sp and sp not in seen:
            seen.add(sp)
            deduped.append(m)
    return deduped


def render_playbook(playbook: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return a deep-copied playbook with Template-substituted params (supports ${var})."""
    ctx = context or {}
    def render_value(v: Any) -> Any:
        if isinstance(v, str):
            # Prefer Jinja2 when available (richer expressions); fall back to string.Template
            if _HAS_JINJA:
                try:
                    tpl = jinja2.Template(v)
                    jres = tpl.render(**{k: vv for k, vv in ctx.items() if vv is not None})
                    # If Jinja didn't substitute Template-style ($var) placeholders, fall back
                    if isinstance(jres, str) and ('$' in jres and '${' in jres):
                        # fall through to Template below
                        pass
                    else:
                        return jres
                except Exception:
                    # fallback to simple Template
                    pass
            try:
                return Template(v).substitute(**{k: str(vv) for k, vv in ctx.items() if vv is not None})
            except Exception:
                # leave placeholder intact if missing or other errors
                return v
        if isinstance(v, list):
            return [render_value(x) for x in v]
        if isinstance(v, dict):
            return {kk: render_value(vv) for kk, vv in v.items()}
        return v

    out = {}
    for k, val in playbook.items():
        if k == 'steps' and isinstance(val, list):
            out['steps'] = []
            for step in val:
                if isinstance(step, dict):
                    s = {kk: render_value(vv) for kk, vv in step.items()}
                    out['steps'].append(s)
                else:
                    out['steps'].append(step)
        else:
            out[k] = render_value(val)
    return out


def extract_context_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Derive common templating context keys from an event dict.

    Returns keys: user, host, ip, file_hash
    """
    # Look into nested enrichment fields commonly used
    user = event.get('user') or event.get('username') or event.get('uid')
    if not user:
        # enrichment -> identity -> user
        try:
            user = event.get('enrichment', {}).get('identity', {}).get('user')
        except Exception:
            user = user
    host = event.get('host') or event.get('hostname') or event.get('agent_host')
    ip = event.get('dest_ip') or event.get('ip') or event.get('src_ip') or event.get('client_ip')
    file_hash = event.get('file_hash') or event.get('sha256') or event.get('hash') or event.get('file', {}).get('sha256')
    return {'user': user, 'host': host, 'ip': ip, 'file_hash': file_hash}


__all__ = ['load_playbooks', 'build_index', 'resolve_for_factor', 'render_playbook']
