from __future__ import annotations

import os
import json
import time
from typing import Any, Dict, List, Optional
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi import Query
from fastapi import Depends
from pydantic import BaseModel
from src.core.configuration import get_scoring_config as _load_scoring_config

try:
    from src.security.auth import require_api_key
except Exception:
    try:
        from security.auth import require_api_key
    except Exception:
        require_api_key = None  # type: ignore

router = APIRouter(prefix="/api/v1/graph/session", tags=["GraphSession"])


# Persistence and TTL settings
SESSION_PERSIST_DIR = Path(os.getenv("SESSION_PERSIST_DIR", "data/sessions"))
SESSION_PERSIST_DIR.mkdir(parents=True, exist_ok=True)
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "86400"))
SESSION_CLEAN_INTERVAL_SECONDS = int(os.getenv("SESSION_CLEAN_INTERVAL_SECONDS", "0"))
EWMA_HISTORY_PATH = Path(os.getenv("EWMA_HISTORY_PATH", str(SESSION_PERSIST_DIR / "ewma_history.json")))
EWMA_HISTORY_TTL_SECONDS = int(os.getenv("EWMA_HISTORY_TTL_SECONDS", "604800"))

# Adaptive EWMA settings
ADAPTIVE_EWMA = str(os.getenv("ADAPTIVE_EWMA", "0")).lower() in ("1","true","yes","on")
ADAPTIVE_EWMA_BASE_ALPHA = float(os.getenv("ADAPTIVE_EWMA_BASE_ALPHA", "0.6"))
ADAPTIVE_EWMA_MIN_ALPHA = float(os.getenv("ADAPTIVE_EWMA_MIN_ALPHA", "0.3"))
ADAPTIVE_EWMA_MAX_ALPHA = float(os.getenv("ADAPTIVE_EWMA_MAX_ALPHA", "0.85"))
ADAPTIVE_EWMA_VOL_SCALE = float(os.getenv("ADAPTIVE_EWMA_VOL_SCALE", "0.4"))

# Scoring weights (shared config)
try:
    _SCORING_CFG = _load_scoring_config()
except Exception:
    _SCORING_CFG = {'weights': {}, 'adaptive_ewma': {}}
SCORING_WEIGHTS_JSON = dict(_SCORING_CFG.get('weights', {}))
SCORING_DIVERSITY_WEIGHT = float(SCORING_WEIGHTS_JSON.get("diversity", 0.0))
SCORING_MAPPING_WEIGHT = float(SCORING_WEIGHTS_JSON.get("mapping", 0.0))


def _safe_write(path: Path, obj: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False)
    except Exception:
        pass


def _safe_read(path: Path) -> dict:
    try:
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _prune_sessions_now() -> None:
    try:
        now = time.time()
        for p in SESSION_PERSIST_DIR.glob("session_*.json"):
            try:
                data = _safe_read(p)
                ts = float(data.get("ts", 0))
                if ts and now - ts > SESSION_TTL_SECONDS:
                    p.unlink(missing_ok=True)
            except Exception:
                continue
        # prune ewma history
        hist = _safe_read(EWMA_HISTORY_PATH)
        changed = False
        for k,v in list(hist.items()):
            try:
                t = float(v[1] if isinstance(v, list) else (v.get("t") if isinstance(v, dict) else 0))
            except Exception:
                t = 0
            if t and now - t > EWMA_HISTORY_TTL_SECONDS:
                hist.pop(k, None)
                changed = True
        if changed:
            _safe_write(EWMA_HISTORY_PATH, hist)
    except Exception:
        pass


class BuildPayload(BaseModel):
    session_id: Optional[str] = None
    session_ids: List[str]
    correlate: bool = True
    ewma: bool = True
    ewma_alpha: Optional[float] = None
    mapping: Dict[str, str] = {}
    batches: Optional[List[dict]] = None


def _derive_alpha(counts: List[int]) -> float:
    if not ADAPTIVE_EWMA or not counts:
        return ADAPTIVE_EWMA_BASE_ALPHA
    # volatility = variance/mean of non-zero counts
    nz = [c for c in counts if c > 0]
    if not nz:
        return ADAPTIVE_EWMA_BASE_ALPHA
    mean = sum(nz) / len(nz)
    var = sum((c-mean)**2 for c in nz) / len(nz)
    vol = (var/mean) if mean > 0 else 0.0
    # higher volatility -> lower alpha
    alpha = ADAPTIVE_EWMA_BASE_ALPHA - ADAPTIVE_EWMA_VOL_SCALE * vol
    alpha = max(ADAPTIVE_EWMA_MIN_ALPHA, min(ADAPTIVE_EWMA_MAX_ALPHA, alpha))
    return alpha


def _overlap_counts(batches: List[dict], mapping: Dict[str,str]) -> Dict[str, Dict[str,int]]:
    names = [b.get("name") or b.get("id") or f"batch-{i}" for i,b in enumerate(batches)]
    # Build canonical value sets per batch
    canon_keys = ["user","host","process","file_hash","domain","ip","ip_dst"]
    sets: List[Dict[str,set]] = []
    for b in batches:
        rows = b.get("rows") or []
        s: Dict[str,set] = {k:set() for k in canon_keys}
        for r in rows:
            for k in canon_keys:
                src = mapping.get(k) or k
                v = r.get(src)
                if v:
                    s[k].add(str(v))
        sets.append(s)
    mat: Dict[str, Dict[str,int]] = {}
    for i,a in enumerate(names):
        mat[a] = {}
        for j,bn in enumerate(names):
            if i==j:
                mat[a][bn] = 0
                continue
            cnt = 0
            for k in canon_keys:
                cnt += len(sets[i][k].intersection(sets[j][k]))
            mat[a][bn] = cnt
    return mat


def _ewma_matrix(mat: Dict[str, Dict[str,int]], alpha: float) -> Dict[str, Dict[str,float]]:
    hist = _safe_read(EWMA_HISTORY_PATH)
    now = time.time()
    out: Dict[str, Dict[str,float]] = {}
    for a, row in mat.items():
        out[a] = {}
        for b, val in row.items():
            key = f"{a}::{b}"
            prev_entry = hist.get(key)
            prev = float(prev_entry[0] if isinstance(prev_entry, list) else (prev_entry.get("v") if isinstance(prev_entry, dict) else 0.0))
            sm = alpha * float(val) + (1.0 - alpha) * prev
            out[a][b] = sm
            hist[key] = [sm, now]
    _safe_write(EWMA_HISTORY_PATH, hist)
    return out


def _allow_demo_graph_fallbacks() -> bool:
    """Return True if demo/stub fallbacks are acceptable (e.g. in dev/test mode).
    Monkeypatch to ``lambda: False`` in production-mode tests."""
    return os.getenv('JANUSEC_LIVE_MODE', '0').lower() not in ('1', 'true', 'yes')


def _mapping_stats(mapping: Dict[str,str]) -> Dict[str,int]:
    stats: Dict[str,int] = {}
    for k,v in mapping.items():
        stats[v] = stats.get(v,0) + 1
    return stats


def _factor_tags(mat: Dict[str, Dict[str,int]], mapping: Dict[str,str]) -> List[dict]:
    factors: List[dict] = []
    # correlation factor
    try:
        total_pairs = sum(int(v) for a in mat.values() for v in a.values())
        if total_pairs > 0:
            factors.append({"factor":"multi_source_correlation","score": min(1.0, total_pairs/100.0), "reason": f"overlap_total={total_pairs}"})
    except Exception:
        pass
    # mapping semantics factor
    try:
        high_value = ["user","host","process","file_hash","domain"]
        hv_present = len([k for k in high_value if (mapping.get(k) or "")])
        bonus = 0.0
        if hv_present >= 4:
            bonus = 0.15
        elif hv_present >= 3:
            bonus = 0.07
        if bonus>0:
            factors.append({"factor":"mapping_semantics_rich","score": bonus, "reason": f"high_value_fields={hv_present}"})
    except Exception:
        pass
    # ASN rarity demo tag (expanded) — skipped in live/production mode
    if _allow_demo_graph_fallbacks():
        factors.append({"factor":"asn_rare","tags":["CVSS:AV:N","KEV:CANDIDATE"],"reason":"demo tag","weight":0.03})
    # NXDOMAIN spike
    try:
        threshold = float(os.getenv("ZEEK_NXDOMAIN_RATE_THRESHOLD", "0.35"))
        # placeholder: if any domain overlaps present, mark high
        dom_pairs = sum(int(v) for a in mat.values() for v in a.values())
        if dom_pairs > 10:
            factors.append({"factor":"nxdomain_rate_high","score":0.05,"reason":f"rate>=threshold:{threshold}","tag":"nxdomain_rate_high"})
    except Exception:
        pass
    return factors


def _lolbins_factors(batches: List[dict]) -> List[dict]:
    macos = ["osascript","launchctl","security","dscl","curl","bash"]
    linux = ["curl","wget","nc","socat","cron","systemctl","iptables","ssh"]
    suspicious = []
    for b in batches or []:
        rows = b.get("rows") or []
        for r in rows:
            proc = str(r.get("process") or r.get("cmd") or "").lower()
            parent = str(r.get("parent") or r.get("ppid_name") or "").lower()
            if not proc:
                continue
            tag = None
            if any(p in proc for p in macos):
                tag = "macos_lolbin"
            if any(p in proc for p in linux):
                tag = (tag or "") + " linux_lolbin"
            if tag:
                sev = 0.2
                if parent and any(x in parent for x in ["browser","chrome","safari","firefox"]):
                    sev += 0.15  # lineage-aware browser->osascript
                if "cron" in proc and ("/tmp" in (r.get("path") or "") or "tmp" in (r.get("args") or "")):
                    sev += 0.1  # cron -> tmp scripts
                suspicious.append({"factor":"lolbin_usage","process":proc,"parent":parent,"score":round(min(1.0,sev),3),"tags":[tag.strip(),"MITRE:T1059","MITRE:T1547"]})
    return suspicious


def _supply_chain_factors(batches: List[dict]) -> List[dict]:
    out = []
    exfil_tlds = [".zip",".tk",".xyz",".top"]
    for b in batches or []:
        pkg = b.get("package") or {}
        name = str(pkg.get("name") or "")
        repo = str(pkg.get("repo") or "")
        deps = pkg.get("deps") or []
        if name and pkg.get("typosquat"):
            out.append({"factor":"supply_chain:typosquat","package":name,"score":0.35,"tags":["npm","pypi","maven","rubygems","docker"]})
        if pkg.get("script_abuse"):
            out.append({"factor":"supply_chain:script_abuse","package":name,"score":0.25})
        if any(str(repo).lower().endswith(t) for t in exfil_tlds):
            out.append({"factor":"supply_chain:exfil_tld","repo":repo,"score":0.2})
        new_rare = [d for d in deps if (d.get("new") or d.get("rare"))]
        if new_rare:
            out.append({"factor":"supply_chain:new_rare_dependencies","count":len(new_rare),"score":min(0.4,0.1*len(new_rare))})
    return out


def _iam_factors(batches: List[dict]) -> List[dict]:
    out = []
    for b in batches or []:
        events = b.get("events") or []
        for e in events:
            act = str(e.get("action") or "").lower()
            if any(x in act for x in ["assume_role","attach_policy","add_user_to_group","create_access_key"]):
                score = 0.3
                if e.get("off_hours"):
                    score += 0.1
                if e.get("source_ip_novel"):
                    score += 0.1
                out.append({"factor":"iam_priv_escalation","action":act,"score":round(min(1.0,score),3),"tags":["MITRE:T1098"]})
    return out


def _email_factors(batches: List[dict]) -> List[dict]:
    out = []
    for b in batches or []:
        mails = b.get("emails") or []
        for m in mails:
            att = m.get("attachment") or {}
            flags = att.get("flags") or []
            if flags:
                out.append({"factor":"email_attachment_risk","flags":flags,"score":0.25})
            if m.get("bec"):
                out.append({"factor":"email_bec","score":0.35,"tags":["impersonation","payment","mailbox_rules","login_anomaly"]})
    return out


def _binary_factors(batches: List[dict]) -> List[dict]:
    out = []
    for b in batches or []:
        bins = b.get("binaries") or []
        for bi in bins:
            static = bi.get("static") or {}
            dyn = bi.get("dynamic") or {}
            mem = bi.get("memory") or {}
            score = 0.0
            if static.get("suspicious_imports") or static.get("rwx_sections") or static.get("unusual_sections"):
                score += 0.3
            if dyn.get("network") or dyn.get("registry") or dyn.get("anti_analysis"):
                score += 0.25
            if mem.get("lsass") or mem.get("injected_code") or mem.get("hidden_procs"):
                score += 0.25
            if bi.get("fuzzy_similarity"):
                score += 0.1
            if score>0:
                out.append({"factor":"binary_analysis","score":round(min(1.0,score),3),"tags":["PE","ELF","MITRE"]})
    return out


def _diversity_score(domain_taxonomy: Dict[str, List[str]]) -> float:
    target = 6.0
    distinct = len([k for k,v in domain_taxonomy.items() if v])
    s = min(1.0, distinct / target)
    w = SCORING_WEIGHTS_JSON.get("diversity", SCORING_DIVERSITY_WEIGHT)
    return s * float(w)


def _mapping_semantics_score(mapping: Dict[str,str]) -> float:
    high_value = {"user","host","process","file_hash","domain"}
    hv_count = sum(1 for k in high_value if mapping.get(k))
    bonus = 0.0
    if hv_count >= 4:
        bonus = 0.15
    elif hv_count >= 3:
        bonus = 0.07
    w = SCORING_WEIGHTS_JSON.get("mapping", SCORING_MAPPING_WEIGHT)
    return bonus * float(w)


def _verdict_and_confidence(mat: Dict[str, Dict[str,int]], diversity: float, mapping_sem: float) -> Dict[str, Any]:
    total = sum(int(v) for a in mat.values() for v in a.values())
    base = min(1.0, total/50.0)
    confidence = max(0.0, min(1.0, base + diversity + mapping_sem))
    verdict = "benign"
    if confidence >= 0.75:
        verdict = "escalate"
    elif confidence >= 0.4:
        verdict = "watch"
    return {"verdict": verdict, "confidence": confidence, "confidence_breakdown": {"base": base, "diversity_weight": diversity, "mapping_weight": mapping_sem}}


# Lightweight 21-step pipeline scoring
_PIPELINE_STEPS = [
    'Reconnaissance','Resource Development','Initial Access','Execution','Persistence','Privilege Escalation',
    'Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Command and Control',
    'Exfiltration','Impact','Cleanup','Evidence Corroboration','Identity Linkage','Endpoint Linkage',
    'Network Linkage','Artifact Linkage','Timeline Synthesis'
]

def _pipeline_scoring(mapping_stats: Dict[str,int], factors: List[dict]) -> Dict[str, Any]:
    stage_scores: List[Dict[str, Any]] = []
    # Simple heuristics: use presence of canonical fields to boost certain stages
    boosts = {
        'Identity Linkage': 0.1 if (mapping_stats.get('user',0)>0) else 0.0,
        'Endpoint Linkage': 0.1 if (mapping_stats.get('host',0)>0 or mapping_stats.get('process',0)>0) else 0.0,
        'Network Linkage': 0.1 if (mapping_stats.get('ip',0)>0 or mapping_stats.get('domain',0)>0) else 0.0,
        'Artifact Linkage': 0.1 if (mapping_stats.get('file_hash',0)>0) else 0.0,
        'Evidence Corroboration': 0.05 if any(f.get('factor')=='multi_source_correlation' for f in factors) else 0.0,
        'Timeline Synthesis': 0.05
    }
    # Context multipliers from domain-specific factors
    try:
        if any(f.get('factor')=='lolbin_usage' for f in factors):
            boosts['Execution'] = max(boosts.get('Execution',0.0), 0.15)
            boosts['Persistence'] = max(boosts.get('Persistence',0.0), 0.1)
        if any(str(f.get('factor','')).startswith('supply_chain:') for f in factors):
            boosts['Resource Development'] = max(boosts.get('Resource Development',0.0), 0.12)
            boosts['Impact'] = max(boosts.get('Impact',0.0), 0.08)
        if any(f.get('factor')=='iam_priv_escalation' for f in factors):
            boosts['Privilege Escalation'] = max(boosts.get('Privilege Escalation',0.0), 0.15)
            boosts['Defense Evasion'] = max(boosts.get('Defense Evasion',0.0), 0.08)
        if any(f.get('factor')=='email_bec' for f in factors):
            boosts['Initial Access'] = max(boosts.get('Initial Access',0.0), 0.12)
            boosts['Command and Control'] = max(boosts.get('Command and Control',0.0), 0.08)
        if any(f.get('factor')=='binary_analysis' for f in factors):
            boosts['Execution'] = max(boosts.get('Execution',0.0), 0.12)
            boosts['Collection'] = max(boosts.get('Collection',0.0), 0.08)
    except Exception:
        pass
    coverage_hits = 0
    for name in _PIPELINE_STEPS:
        base = 0.3  # baseline visibility
        delta = boosts.get(name, 0.0)
        score = max(0.0, min(1.0, base + delta))
        if delta > 0:
            coverage_hits += 1
        stage_scores.append({'stage': name, 'score': round(score,3), 'delta': round(delta,3)})
    coverage = coverage_hits / float(len(_PIPELINE_STEPS))
    overall = round(sum(s['score'] for s in stage_scores) / len(stage_scores), 3)
    return {'overall': overall, 'coverage': round(coverage,3), 'stages': stage_scores}


@router.post("/build")
async def build_session(payload: BuildPayload, request: Request, auth=Depends(require_api_key), args: Optional[List[str]] = None, kwargs: Optional[str] = None) -> Dict[str, Any]:
    if not payload.session_ids or len(payload.session_ids) < 2:
        raise HTTPException(status_code=400, detail="need_at_least_two_sessions")
    sid = payload.session_id or f"sess-{int(time.time()*1000)}"
    batches = payload.batches or []
    # compute overlaps
    mat = _overlap_counts(batches, payload.mapping or {})
    counts = [int(v) for a in mat.values() for v in a.values()]
    alpha = payload.ewma_alpha
    if payload.ewma and (alpha is None) and ADAPTIVE_EWMA:
        alpha = _derive_alpha(counts)
    # Validate alpha when provided
    if payload.ewma and alpha is not None:
        try:
            a = float(alpha)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid_alpha")
        if not (0.0 <= a <= 1.0):
            raise HTTPException(status_code=400, detail="invalid_alpha")
        smoothed = _ewma_matrix(mat, float(alpha))
    else:
        smoothed = None
    # domain taxonomy (simple demo): infer from mapping keys present
    domain_taxonomy = {
        "identity": ["user"], "endpoint": ["host","process"], "network": ["ip","ip_dst"],
        "data": ["db"], "email": ["email"], "cloud": ["cloud"], "remote": ["role"], "api_app": ["service"],
    }
    diversity_score = _diversity_score(domain_taxonomy)
    mapping_score = _mapping_semantics_score(payload.mapping or {})
    vc = _verdict_and_confidence(mat, diversity_score, mapping_score)
    factors = _factor_tags(mat, payload.mapping or {})
    # Extend with domain-specific factors
    try:
        factors.extend(_lolbins_factors(batches))
        factors.extend(_supply_chain_factors(batches))
        factors.extend(_iam_factors(batches))
        factors.extend(_email_factors(batches))
        factors.extend(_binary_factors(batches))
    except Exception:
        pass
    summary = {
        "session_id": sid,
        "session_ids": payload.session_ids,
        "correlation": mat,
        "correlation_smoothed": smoothed,
        "ewma_alpha": alpha,
        "mapping_stats": _mapping_stats(payload.mapping or {}),
        "factors": factors,
        "pipeline_summary": _pipeline_scoring(_mapping_stats(payload.mapping or {}), factors),
        "verdict": vc["verdict"],
        "confidence": vc["confidence"],
        "confidence_breakdown": vc["confidence_breakdown"],
        "domain_taxonomy": domain_taxonomy,
        "domain_diversity_score": diversity_score,
        "mapping_semantics_score": mapping_score,
        "graph_summary": {"note": "demo graph summary"},
    }
    # persist
    data = {"ts": time.time(), "summary": summary}
    _safe_write(SESSION_PERSIST_DIR / f"session_{sid}.json", data)
    if SESSION_CLEAN_INTERVAL_SECONDS > 0:
        _prune_sessions_now()
    # Tiered LLM summaries (stubbed, driven by factors)
    try:
        tier1 = {
            "summary": "High-level correlation overview with key factors.",
            "top_factors": sorted([{"factor": f.get("factor"), "score": f.get("score", 0.0)} for f in factors], key=lambda x: x["score"], reverse=True)[:5]
        }
        tier2 = {
            "summary": "Detailed 21-step pipeline context and recommended triage.",
            "pipeline": summary.get("pipeline_summary"),
            "recommendations": [
                "Collect EDR and DNS logs to bridge gaps",
                "Verify IAM changes against baseline and off-hours",
                "Inspect LOLBin execution lineage and persistence markers"
            ]
        }
        summary["llm_summaries"] = {"tier1": tier1, "tier2": tier2}
    except Exception:
        pass
    return summary


@router.get("/{sid}")
async def get_session(sid: str, request: Request, auth=Depends(require_api_key)) -> Dict[str, Any]:
    path = SESSION_PERSIST_DIR / f"session_{sid}.json"
    data = _safe_read(path)
    if not data:
        raise HTTPException(status_code=404, detail="session_not_found")
    return data


@router.get("/{sid}/explain")
async def explain_session(sid: str, request: Request, auth=Depends(require_api_key)) -> Dict[str, Any]:
    # simple volatility explanation using last matrix counts
    path = SESSION_PERSIST_DIR / f"session_{sid}.json"
    data = _safe_read(path)
    summary = data.get("summary") or {}
    mat = summary.get("correlation") or {}
    counts = [int(v) for a in mat.values() for v in a.values()]
    nz = [c for c in counts if c>0]
    if not nz:
        return {"volatility": 0.0}
    mean = sum(nz)/len(nz)
    var = sum((c-mean)**2 for c in nz)/len(nz)
    return {"volatility": (var/mean) if mean>0 else 0.0}


__all__ = ["router"]
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Tuple
import os, time, json, math, statistics

router = APIRouter(prefix="/api/v1/graph", tags=["GraphSession"])

SESSION_PERSIST_DIR = os.getenv('SESSION_PERSIST_DIR', os.path.join('data','sessions'))
os.makedirs(SESSION_PERSIST_DIR, exist_ok=True)
EWMA_HISTORY_PATH = os.getenv('EWMA_HISTORY_PATH', os.path.join(SESSION_PERSIST_DIR, 'ewma_history.json'))
os.makedirs(os.path.dirname(EWMA_HISTORY_PATH), exist_ok=True)

ADAPTIVE_EWMA = os.getenv('ADAPTIVE_EWMA','0').lower() in {'1','true','yes'}
ADAPTIVE_EWMA_BASE_ALPHA = float(os.getenv('ADAPTIVE_EWMA_BASE_ALPHA','0.6'))
ADAPTIVE_EWMA_MIN_ALPHA = float(os.getenv('ADAPTIVE_EWMA_MIN_ALPHA','0.3'))
ADAPTIVE_EWMA_MAX_ALPHA = float(os.getenv('ADAPTIVE_EWMA_MAX_ALPHA','0.85'))
ADAPTIVE_EWMA_VOL_SCALE = float(os.getenv('ADAPTIVE_EWMA_VOL_SCALE','0.4'))


class BuildSessionRequest(BaseModel):
    session_ids: Optional[List[str]] = None
    sessions: Optional[List[Dict[str, Any]]] = None
    correlate: Optional[bool] = True
    ewma: Optional[bool] = True
    ewma_alpha: Optional[float] = None
    mapping: Optional[Dict[str,str]] = None


def _session_path(sid: str) -> str:
    safe = sid.replace('/', '_').replace('..', '_')
    return os.path.join(SESSION_PERSIST_DIR, f"{safe}.json")


def persist_session(sid: str, data: Dict[str, Any]) -> None:
    try:
        with open(_session_path(sid), 'w', encoding='utf-8') as fh:
            json.dump({'id': sid, 'ts': time.time(), 'data': data}, fh)
    except Exception:
        pass


def load_session(sid: str) -> Optional[Dict[str, Any]]:
    p = _session_path(sid)
    if not os.path.exists(p):
        return None
    try:
        with open(p,'r',encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return None


def _load_ewma_history() -> Dict[str, Dict[str, Any]]:
    try:
        if os.path.exists(EWMA_HISTORY_PATH):
            with open(EWMA_HISTORY_PATH,'r',encoding='utf-8') as fh:
                return json.load(fh)
    except Exception:
        pass
    return {}


def _save_ewma_history(h: Dict[str, Dict[str, Any]]) -> None:
    try:
        with open(EWMA_HISTORY_PATH,'w',encoding='utf-8') as fh:
            json.dump(h, fh)
    except Exception:
        pass


def _pair_key(a: str, b: str) -> str:
    return f"{a}|||{b}"


def _canonical_sets(session_obj: Dict[str, Any]) -> Dict[str, set]:
    # Expect session_obj to possibly contain an object like {'data': {'entities': {...}}}
    entities = None
    if not isinstance(session_obj, dict):
        return {}
    # Try common wrapper shapes
    if 'data' in session_obj and isinstance(session_obj['data'], dict):
        data = session_obj['data']
        if 'entities' in data and isinstance(data['entities'], dict):
            entities = data['entities']
        else:
            entities = data
    elif 'entities' in session_obj and isinstance(session_obj['entities'], dict):
        entities = session_obj['entities']
    elif 'events' in session_obj and isinstance(session_obj['events'], dict):
        entities = session_obj['events']
    else:
        # Fallback: maybe session_obj itself is an entities dict
        entities = session_obj

    # Expand canonical fields to cover 9 domains: identity, endpoint, network, data, domain, email, cloud, process, service
    can_keys = ['user', 'host', 'file_hash', 'ip', 'domain', 'email', 'cloud', 'process', 'service']
    out = {k: set() for k in can_keys}

    if not isinstance(entities, dict):
        return out

    for k, v in entities.items():
        if v is None:
            continue
        lk = k.lower()
        # Direct canonical matches
        if lk in out:
            try:
                items = v if isinstance(v, (list, set, tuple)) else [v]
                out[lk].update([str(x).strip().lower() for x in items if x is not None and str(x).strip()])
            except Exception:
                pass
        else:
            # Heuristics: classify common field names into canonical keys
            sval = str(v).strip().lower() if not isinstance(v, (list, set, tuple)) else None
            if any(sub in lk for sub in ('email', 'mail')):
                vals = v if isinstance(v, (list, tuple, set)) else [v]
                out['email'].update([str(x).strip().lower() for x in vals if x])
            elif any(sub in lk for sub in ('sha256', 'sha1', 'md5', 'hash')):
                vals = v if isinstance(v, (list, tuple, set)) else [v]
                out['file_hash'].update([str(x).strip().lower() for x in vals if x])
            elif any(sub in lk for sub in ('ip', 'addr', 'hostip')):
                vals = v if isinstance(v, (list, tuple, set)) else [v]
                out['ip'].update([str(x).strip().lower() for x in vals if x])
            elif any(sub in lk for sub in ('domain', 'fqdn', 'url', 'host')):
                vals = v if isinstance(v, (list, tuple, set)) else [v]
                out['domain'].update([str(x).strip().lower() for x in vals if x])
            elif any(sub in lk for sub in ('proc', 'process', 'cmd')):
                vals = v if isinstance(v, (list, tuple, set)) else [v]
                out['process'].update([str(x).strip().lower() for x in vals if x])
            elif any(sub in lk for sub in ('service', 'api', 'app', 'svc')):
                vals = v if isinstance(v, (list, tuple, set)) else [v]
                out['service'].update([str(x).strip().lower() for x in vals if x])
            elif any(sub in lk for sub in ('cloud', 'azure', 'aws', 'gcp', 'tenant')):
                vals = v if isinstance(v, (list, tuple, set)) else [v]
                out['cloud'].update([str(x).strip().lower() for x in vals if x])
            elif any(sub in lk for sub in ('user', 'account', 'uid')):
                vals = v if isinstance(v, (list, tuple, set)) else [v]
                out['user'].update([str(x).strip().lower() for x in vals if x])
            else:
                # Try to detect emails / ips / hashes from string values
                try:
                    vals = v if isinstance(v, (list, tuple, set)) else [v]
                    for x in vals:
                        if x is None:
                            continue
                        sx = str(x).strip().lower()
                        if '@' in sx and '.' in sx:
                            out['email'].add(sx)
                        elif sx.replace('.', '').isdigit() and sx.count('.') in (1,3):
                            out['ip'].add(sx)
                        elif len(sx) in (32,40,64) and all(c in '0123456789abcdef' for c in sx):
                            out['file_hash'].add(sx)
                        elif '.' in sx:
                            out['domain'].add(sx)
                        else:
                            out['service'].add(sx)
                except Exception:
                    pass

    return out


def _compute_overlap_matrix(sessions: List[Tuple[str, Dict[str, Any]]]) -> Tuple[List[List[int]], Dict[str, int]]:
    n = len(sessions)
    mat = [[0]*n for _ in range(n)]
    mapping_stats = {k:0 for k in ['user','host','file_hash','ip','domain','process','email','cloud','service']}
    sets = [ _canonical_sets(s[1]) for s in sessions ]
    for idx, s in enumerate(sets):
        for k in mapping_stats.keys():
            mapping_stats[k] += len(s.get(k, set()))
    for i in range(n):
        for j in range(n):
            if i==j:
                # self-count: total distinct canonical entities
                mat[i][j] = sum(len(sets[i].get(k, set())) for k in mapping_stats.keys())
            else:
                # sum intersections across canonical keys
                overlap = 0
                for k in mapping_stats.keys():
                    try:
                        overlap += len(sets[i].get(k, set()) & sets[j].get(k, set()))
                    except Exception:
                        pass
                mat[i][j] = overlap
    return mat, mapping_stats


def _suggest_missing_logs(mapping_stats: Dict[str, int], ids: List[str], sets: List[Dict[str, set]], corr: List[List[int]]) -> List[Dict[str, object]]:
    """Return a small list of suggested log types to collect when coverage is low.

    Heuristic rules:
    - If canonical counts for a field are zero or very low, suggest logs that provide that coverage.
    - If overall overlap and entity counts are very small, suggest broader sources (EDR, NetFlow, DNS, Auth).
    """
    suggestions: list[Dict[str, object]] = []
    total_entities = sum(mapping_stats.get(k, 0) for k in mapping_stats.keys())
    # Per-field suggestions
    field_rules = {
        'user': ('Authentication / Identity logs', 'Collect IdP / AD / MFA logs to provide user identity linkage (e.g. Windows Security events, Okta, AzureAD).'),
        'host': ('Endpoint telemetry (EDR)', 'Collect EDR / sysmon / host telemetry to map hosts and process context.'),
        'file_hash': ('Endpoint file/process events', 'Collect EDR file events or file-hash telemetry to link artifacts across hosts.'),
        'ip': ('Network flow / DNS / Proxy logs', 'Collect NetFlow, Zeek, firewall or DNS/Proxy logs to connect network activity between sessions.'),
        'domain': ('DNS / Proxy / HTTP logs', 'Collect DNS, Proxy or HTTP logs to enrich domain activity and referral chains.'),
    }

    for field, (name, reason) in field_rules.items():
        cnt = int(mapping_stats.get(field, 0) or 0)
        if cnt == 0:
            suggestions.append({'log_type': name, 'reason': reason, 'priority': 'high', 'missing_field': field})
        elif cnt < 3:
            suggestions.append({'log_type': name, 'reason': reason, 'priority': 'medium', 'missing_field': field, 'current_count': cnt})

    # If total entities are very low relative to sessions, suggest broader sources
    avg_per_session = float(total_entities) / max(1.0, len(ids))
    if avg_per_session < 2.0:
        suggestions.append({'log_type': 'Broader telemetry', 'reason': 'Low entity coverage across ingested sessions — consider adding EDR, cloud audit, firewall, or email headers to increase correlation signal.', 'priority': 'high'})

    # If there are zero overlaps between sessions, suggest looking for bridging logs
    total_overlap = sum(sum(row) for row in corr) - sum(corr[i][i] for i in range(len(corr)))
    if total_overlap == 0:
        suggestions.append({'log_type': 'Bridging logs (DNS/Netflow/Authentication)', 'reason': 'No overlap found between batches — collecting bridging logs such as DNS, NetFlow or identity logs often reveals links.', 'priority': 'high'})

    # Deduplicate by log_type while keeping priority
    seen = {}
    out = []
    for s in suggestions:
        lt = s.get('log_type')
        if lt in seen:
            # upgrade priority if needed
            prev = seen[lt]
            if prev.get('priority') == 'medium' and s.get('priority') == 'high':
                prev['priority'] = 'high'
        else:
            seen[lt] = s
            out.append(s)

    return out


def _load_latest_assessment_meta(org_hint: str | None = None) -> dict:
    """Best-effort: load the most recent metadata JSON under data/assessments.

    If org_hint is provided, prefer that org folder; otherwise scan all orgs
    and return the most recent metadata file found.
    """
    try:
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        base = os.path.join(repo_root, 'data', 'assessments')
        if not os.path.exists(base):
            return {}
        orgs = [org_hint] if org_hint else os.listdir(base)
        latest = (0, None)
        best = None
        for org in orgs:
            if not org:
                continue
            org_dir = os.path.join(base, org)
            if not os.path.isdir(org_dir):
                continue
            for datepart in sorted(os.listdir(org_dir), reverse=True):
                day_dir = os.path.join(org_dir, datepart)
                if not os.path.isdir(day_dir):
                    continue
                for f in os.listdir(day_dir):
                    if not f.lower().endswith('.json'):
                        continue
                    p = os.path.join(day_dir, f)
                    try:
                        mtime = os.path.getmtime(p)
                    except Exception:
                        mtime = 0
                    if mtime > latest[0]:
                        latest = (mtime, p)
                        best = p
                if best:
                    break
        if best:
            try:
                with open(best, 'r', encoding='utf-8') as fh:
                    return json.load(fh)
            except Exception:
                return {}
    except Exception:
        return {}
    return {}


def _apply_ewma(current: List[List[int]], prev_hist: Dict[str, Dict[str, Any]], ids: List[str], alpha: float) -> List[List[float]]:
    n = len(current)
    smoothed = [[0.0]*n for _ in range(n)]
    now = time.time()
    for i in range(n):
        for j in range(n):
            key = _pair_key(ids[i], ids[j])
            prev = prev_hist.get(key, {}).get('value', 0.0)
            cur = float(current[i][j])
            s = alpha * cur + (1.0 - alpha) * float(prev)
            smoothed[i][j] = s
            prev_hist[key] = {'value': s, 'ts': now}
    return smoothed


@router.post('/session/build')
async def build_session(req: Request, args: Optional[List[str]] = None, kwargs: Optional[str] = None): 
    start_ts = time.time()
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    try:
        payload = BuildSessionRequest.model_validate(body)
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))

    sessions_input: List[Tuple[str, Dict[str, Any]]] = []
    # Persist inline sessions if provided
    if payload.sessions:
        for s in payload.sessions:
            sid = s.get('id') or f"inline-{int(time.time()*1000)}-{len(sessions_input)}"
            persist_session(sid, s)
            sessions_input.append((sid, s))

    # Load session_ids from disk
    if payload.session_ids:
        for sid in payload.session_ids:
            rec = load_session(sid)
            if rec and isinstance(rec, dict) and rec.get('data') is not None:
                sessions_input.append((sid, rec.get('data')))
            else:
                # If no persisted session found, treat as error
                raise HTTPException(status_code=404, detail=f'session_not_found:{sid}')

    if not sessions_input:
        raise HTTPException(status_code=400, detail='no sessions provided')

    ids = [s[0] for s in sessions_input]
    # Compute overlap matrix and mapping stats
    corr, mapping_stats = _compute_overlap_matrix(sessions_input)

    # Compute adaptive alpha if requested
    ewma_alpha = payload.ewma_alpha
    if ewma_alpha is None and ADAPTIVE_EWMA:
        # compute volatility: variance/mean of non-zero pairwise counts (off-diagonal)
        vals = []
        n = len(corr)
        for i in range(n):
            for j in range(n):
                if i==j: continue
                v = corr[i][j]
                if v>0: vals.append(float(v))
        if vals:
            mean = statistics.mean(vals)
            var = statistics.pvariance(vals) if mean>0 else 0.0
            vol = var/mean if mean>0 else 0.0
            # higher volatility -> lower alpha
            ewma_alpha = max(ADAPTIVE_EWMA_MIN_ALPHA, min(ADAPTIVE_EWMA_MAX_ALPHA, ADAPTIVE_EWMA_BASE_ALPHA - vol * ADAPTIVE_EWMA_VOL_SCALE))
        else:
            ewma_alpha = ADAPTIVE_EWMA_BASE_ALPHA
    if ewma_alpha is None:
        ewma_alpha = float(payload.ewma_alpha or ADAPTIVE_EWMA_BASE_ALPHA)

    prev_hist = _load_ewma_history() if payload.ewma else {}
    smoothed = _apply_ewma(corr, prev_hist, ids, ewma_alpha) if payload.ewma else None
    if payload.ewma:
        _save_ewma_history(prev_hist)

    # Build node/edge graph for UI: session nodes + entity nodes + membership edges + session-session edges for overlaps
    nodes: list[Dict[str, Any]] = []
    edges: list[Dict[str, Any]] = []
    import hashlib as _hashlib
    def _stable_node_id(etype: str, val: str) -> str:
        h = _hashlib.sha1(f"{etype}:{val}".encode('utf-8')).hexdigest()[:12]
        return f'entity:{etype}:{h}'

    entity_index: Dict[Tuple[str,str], str] = {}

    # Add session nodes
    for sid in ids:
        nodes.append({'id': f'session:{sid}', 'label': sid, 'type': 'session'})

    # Add entity nodes and membership edges
    sets = [ _canonical_sets(s[1]) for s in sessions_input ]
    for si, ssets in enumerate(sets):
        sid = ids[si]
        for etype, vals in ssets.items():
            for val in vals:
                key = (etype, val)
                if key not in entity_index:
                    node_id = _stable_node_id(etype, val)
                    entity_index[key] = node_id
                    nodes.append({'id': node_id, 'label': val, 'type': etype, 'value': val})
                else:
                    node_id = entity_index[key]
                # membership edge from session -> entity; include evidence (which session-file caused it)
                edges.append({'source': f'session:{sid}', 'target': node_id, 'type': 'has', 'etype': etype, 'evidence': [{'session': sid, 'value': val}]})
                # increment evidence count on node (aggregate)
                try:
                    for n in nodes:
                        if n.get('id') == node_id:
                            n.setdefault('evidence_count', 0)
                            n['evidence_count'] += 1
                            samples = n.setdefault('evidence_samples', [])
                            if len(samples) < 3:
                                samples.append({'session': sid, 'value': val})
                            break
                except Exception:
                    pass

    # Add session-session edges for overlaps with weight
    for i in range(len(ids)):
        for j in range(len(ids)):
            if i == j:
                continue
            w = corr[i][j]
            if w and w > 0:
                # collect evidence: overlapping entity values between i and j
                evs = []
                ssets_i = sets[i]
                ssets_j = sets[j]
                for etype in ssets_i.keys():
                    try:
                        inter = list(ssets_i.get(etype, set()) & ssets_j.get(etype, set()))
                        for v in inter:
                            evs.append({'etype': etype, 'value': v})
                    except Exception:
                        pass
                edges.append({'source': f'session:{ids[i]}', 'target': f'session:{ids[j]}', 'type': 'overlap', 'weight': w, 'evidence': evs})

    resp = {
        'session_ids': ids,
        'correlation': corr,
        'correlation_smoothed': smoothed,
        'ewma_alpha': ewma_alpha,
        'mapping_stats': mapping_stats,
        'factors': [],
        'verdict': 'info',
        'confidence': min(1.0, sum(sum(r) for r in corr) / max(1.0, float(len(ids)*10))),
        'overlap_summary': {
            'total_overlap': int(sum(sum(r) for r in corr) - sum(corr[i][i] for i in range(len(corr)))),
            'avg_overlap_per_pair': float(
                (sum(sum(r) for r in corr) - sum(corr[i][i] for i in range(len(corr))))
                / max(1, (len(corr)*len(corr) - len(corr)))
            ),
            'nonzero_pairs': int(sum(1 for i in range(len(corr)) for j in range(len(corr)) if i!=j and corr[i][j] > 0))
        },
        'graph_summary': {
            'nodes': len(nodes),
            'edges': len(edges),
            'entity_types': list(mapping_stats.keys())
        },
        'graph': {
            'nodes': nodes,
            'edges': edges
        },
        'pivot_points': [
            # entities that connect to >=2 sessions
            {
                'etype': et,
                'value': val,
                'degree': deg
            }
            for (et, val), deg in (
                (lambda idx, eds: [
                    (
                        etype,
                        value,
                        sum(1 for e in eds if e.get('target') == nid and e.get('type') == 'has')
                    )
                    for ((etype, value), nid) in idx.items()
                ])(entity_index, edges)
            ) if deg >= 2
        ],
        'entity_centrality': {
            # simple degree centrality for entity nodes
            (n.get('type')+':'+str(n.get('value'))): sum(1 for e in edges if (e.get('source') == n.get('id') or e.get('target') == n.get('id')))
            for n in nodes if n.get('id','').startswith('entity:')
        }
    }
    # Attach the most recent assessment metadata if available (best-effort)
    try:
        # Try to infer org from session ids (simple heuristic: org- prefixed ids)
        org_hint = None
        for s in ids:
            if '-' in s:
                maybe = s.split('-')[0]
                if maybe and len(maybe) > 1:
                    org_hint = maybe
                    break
        meta = _load_latest_assessment_meta(org_hint)
        if meta:
            resp['assessment_meta'] = meta
    except Exception:
        pass
    # Suggest missing logs to improve correlation / attack reconstruction
    try:
        resp['suggested_missing_logs'] = _suggest_missing_logs(mapping_stats, ids, sets, corr)
    except Exception:
        resp['suggested_missing_logs'] = []

    # Demo fallback: if no suggestions and this is a demo/force session, inject friendly examples
    try:
        if (not resp.get('suggested_missing_logs')) or len(resp.get('suggested_missing_logs') or []) == 0:
            if any(str(s).lower().startswith(('force','demo')) for s in ids):
                resp['suggested_missing_logs'] = [
                    {
                        'log_type': 'Endpoint telemetry (EDR)',
                        'reason': 'No host/user/file_hash coverage detected; EDR provides process and file-hash linkage across hosts.',
                        'priority': 'high',
                        'missing_field': 'host',
                        'example': {'fields': ['host','process','sha256'], 'example_row': {'host':'host-123','process':'cmd.exe','sha256':'abcdef...'}}
                    },
                    {
                        'log_type': 'Authentication / Identity logs',
                        'reason': 'No user/identity linkage observed; IdP/AD logs enable mapping user sessions to hosts.',
                        'priority': 'high',
                        'missing_field': 'user',
                        'example': {'fields': ['user','event','src_ip'], 'example_row': {'user':'alice','event':'login','src_ip':'10.0.0.5'}}
                    },
                    {
                        'log_type': 'Network/DNS (NetFlow/DNS/Proxy)',
                        'reason': 'No bridging network logs found; DNS/NetFlow often reveal pivot traffic and domain lookups.',
                        'priority': 'medium',
                        'missing_field': 'ip',
                        'example': {'fields': ['src_ip','dst_ip','domain'], 'example_row': {'src_ip':'10.0.0.5','dst_ip':'8.8.8.8','domain':'malicious.example'}}
                    }
                ]
    except Exception:
        pass
    # Observability: timings and counters
    try:
        resp['observability'] = {
            'duration_ms': int((time.time() - start_ts) * 1000),
            'nodes': resp.get('graph_summary', {}).get('nodes', 0),
            'edges': resp.get('graph_summary', {}).get('edges', 0),
            'nonzero_pairs': resp.get('overlap_summary', {}).get('nonzero_pairs', 0)
        }
    except Exception:
        pass
    return resp


def build_session_response(sessions_input: List[Tuple[str, Dict[str, Any]]], payload_opts: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Reusable session build logic returning the same response as the /session/build endpoint.

    This extracts the core behavior to allow other endpoints (attack candidate builder)
    to reuse the computed graph, mapping stats, and correlation matrices.
    """
    payload_opts = payload_opts or {}
    ids = [s[0] for s in sessions_input]
    corr, mapping_stats = _compute_overlap_matrix(sessions_input)
    ewma_alpha = payload_opts.get('ewma_alpha', ADAPTIVE_EWMA_BASE_ALPHA)
    if ewma_alpha is None:
        ewma_alpha = ADAPTIVE_EWMA_BASE_ALPHA
    ewma_alpha = float(ewma_alpha)
    prev_hist = _load_ewma_history() if payload_opts.get('ewma', True) else {}
    smoothed = _apply_ewma(corr, prev_hist, ids, ewma_alpha) if payload_opts.get('ewma', True) else None
    if payload_opts.get('ewma', True):
        _save_ewma_history(prev_hist)

    # Build graph nodes/edges (same as build_session)
    nodes = []
    edges = []
    import hashlib as _hashlib
    def _stable_node_id(etype: str, val: str) -> str:
        h = _hashlib.sha1(f"{etype}:{val}".encode('utf-8')).hexdigest()[:12]
        return f'entity:{etype}:{h}'

    for sid in ids:
        nodes.append({'id': f'session:{sid}', 'label': sid, 'type': 'session'})
    entity_index = {}
    sets = [ _canonical_sets(s[1]) for s in sessions_input ]
    for si, ssets in enumerate(sets):
        sid = ids[si]
        for etype, vals in ssets.items():
            for val in vals:
                key = (etype, val)
                if key not in entity_index:
                    node_id = _stable_node_id(etype, val)
                    entity_index[key] = node_id
                    nodes.append({'id': node_id, 'label': val, 'type': etype, 'value': val})
                else:
                    node_id = entity_index[key]
                edges.append({'source': f'session:{sid}', 'target': node_id, 'type': 'has', 'etype': etype, 'evidence': [{'session': sid, 'value': val}]})

    for i in range(len(ids)):
        for j in range(len(ids)):
            if i == j:
                continue
            w = corr[i][j]
            if w and w > 0:
                evs = []
                ssets_i = sets[i]
                ssets_j = sets[j]
                for etype in ssets_i.keys():
                    try:
                        inter = list(ssets_i.get(etype, set()) & ssets_j.get(etype, set()))
                        for v in inter:
                            evs.append({'etype': etype, 'value': v})
                    except Exception:
                        pass
                edges.append({'source': f'session:{ids[i]}', 'target': f'session:{ids[j]}', 'type': 'overlap', 'weight': w, 'evidence': evs})

    resp = {
        'session_ids': ids,
        'correlation': corr,
        'correlation_smoothed': smoothed,
        'ewma_alpha': ewma_alpha,
        'mapping_stats': mapping_stats,
        'overlap_summary': {
            'total_overlap': int(sum(sum(r) for r in corr) - sum(corr[i][i] for i in range(len(corr)))),
            'avg_overlap_per_pair': float(
                (sum(sum(r) for r in corr) - sum(corr[i][i] for i in range(len(corr))))
                / max(1, (len(corr)*len(corr) - len(corr)))
            ),
            'nonzero_pairs': int(sum(1 for i in range(len(corr)) for j in range(len(corr)) if i!=j and corr[i][j] > 0))
        },
        'graph_summary': {'nodes': len(nodes), 'edges': len(edges), 'entity_types': list(mapping_stats.keys())},
        'graph': {'nodes': nodes, 'edges': edges},
        'pivot_points': [
            {
                'etype': et,
                'value': val,
                'degree': deg
            }
            for (et, val), deg in (
                (lambda idx, eds: [
                    (
                        etype,
                        value,
                        sum(1 for e in eds if e.get('target') == nid and e.get('type') == 'has')
                    )
                    for ((etype, value), nid) in idx.items()
                ])(entity_index, edges)
            ) if deg >= 2
        ],
        'entity_centrality': {
            (n.get('type')+':'+str(n.get('value'))): sum(1 for e in edges if (e.get('source') == n.get('id') or e.get('target') == n.get('id')))
            for n in nodes if n.get('id','').startswith('entity:')
        }
    }
    try:
        resp['observability'] = {
            'nodes': resp.get('graph_summary', {}).get('nodes', 0),
            'edges': resp.get('graph_summary', {}).get('edges', 0),
            'nonzero_pairs': resp.get('overlap_summary', {}).get('nonzero_pairs', 0)
        }
    except Exception:
        pass
    return resp


def _extract_entity_first_seen(built_graph: Dict[str, Any]) -> Dict[str, float]:
    """Return approximate first-seen timestamp per entity value using evidence samples when available.

    Falls back to None when timestamps are not present.
    """
    first_seen = {}
    try:
        nodes = built_graph.get('graph', {}).get('nodes', [])
        for n in nodes:
            val = n.get('value') or n.get('label')
            if not val:
                continue
            # evidence_samples may include session and optionally ts
            samples = n.get('evidence_samples') or []
            best = None
            for s in samples:
                # s could be dict with ts or session-level timestamp
                ts = None
                if isinstance(s, dict):
                    ts = s.get('ts') or s.get('timestamp')
                # parse numeric strings
                try:
                    if isinstance(ts, str) and ts.isdigit():
                        ts = int(ts)
                except Exception:
                    pass
                if isinstance(ts, (int, float)):
                    if best is None or ts < best:
                        best = float(ts)
            if best is not None:
                first_seen[val] = best
    except Exception:
        pass
    return first_seen


@router.post('/attack_candidates')
async def attack_candidates(req: Request):
    """Build attack-pattern candidates from provided sessions.

    Accepts the same payload as `/session/build` (session_ids or sessions).
    Returns a list of candidate kill-chains with confidence and missing-link hints.
    """
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    try:
        payload = BuildSessionRequest.model_validate(body)
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))

    sessions_input: List[Tuple[str, Dict[str, Any]]] = []
    if payload.sessions:
        for s in payload.sessions:
            sid = s.get('id') or f"inline-{int(time.time()*1000)}-{len(sessions_input)}"
            persist_session(sid, s)
            sessions_input.append((sid, s))
    if payload.session_ids:
        for sid in payload.session_ids:
            rec = load_session(sid)
            if rec and isinstance(rec, dict) and rec.get('data') is not None:
                sessions_input.append((sid, rec.get('data')))
            else:
                raise HTTPException(status_code=404, detail=f'session_not_found:{sid}')
    if not sessions_input:
        raise HTTPException(status_code=400, detail='no sessions provided')

    # Reuse session build logic
    built = build_session_response(sessions_input, {'ewma': payload.ewma, 'ewma_alpha': payload.ewma_alpha})

    # Heuristic candidate synthesis:
    # - For each entity type that commonly chains (process -> network domain/ip -> file_hash), attempt to form chains
    # - Use overlap edges and entity evidence to order steps
    candidates = []
    graph = built.get('graph', {})
    nodes = graph.get('nodes', [])
    edges = graph.get('edges', [])

    # Index nodes by type/value
    by_type = {}
    for n in nodes:
        t = n.get('type')
        val = n.get('value') or n.get('label')
        if not t or not val: continue
        by_type.setdefault(t, []).append(n)

    # Simple rule-based chain builder
    # Attempt patterns: user -> host -> process -> file_hash -> domain/ip
    def assemble_chain(user, host, process, file_hash, domain):
        chain = []
        if user: chain.append({'step':'user', 'value': user})
        if host: chain.append({'step':'host', 'value': host})
        if process: chain.append({'step':'process', 'value': process})
        if file_hash: chain.append({'step':'file_hash', 'value': file_hash})
        if domain: chain.append({'step':'domain', 'value': domain})
        return chain

    # Gather representative values from mapping stats / node lists
    users = [n['value'] for n in by_type.get('user', [])]
    hosts = [n['value'] for n in by_type.get('host', [])]
    procs = [n['value'] for n in by_type.get('process', [])]
    files = [n['value'] for n in by_type.get('file_hash', [])]
    domains = [n['value'] for n in by_type.get('domain', [])]

    # Build candidate permutations prioritizing observed overlaps
    max_candidates = 12
    seen_chains = set()
    def chain_key(c): return '->'.join([f"{s['step']}:{s['value']}" for s in c])

    # scoring helper: give higher score when entities appear in same session edges
    def score_chain(chain):
        score = 0.0
        # base length factor
        score += len(chain) * 0.1
        # add overlap evidence: if chain elements co-occur in edges, boost score
        vals = [s['value'] for s in chain]
        for e in edges:
            if e.get('type') == 'overlap' and e.get('evidence'):
                for ev in e['evidence']:
                    if ev.get('value') in vals:
                        score += 0.2
        return min(1.0, score)

    # Try combinations with heuristics (greedy)
    for u in (users[:3] or [None]):
        for h in (hosts[:3] or [None]):
            for p in (procs[:3] or [None]):
                for f in (files[:2] or [None]):
                    for d in (domains[:2] or [None]):
                        c = assemble_chain(u, h, p, f, d)
                        if not c: continue
                        k = chain_key(c)
                        if k in seen_chains: continue
                        seen_chains.add(k)
                        conf = score_chain(c)
                        # missing links detection: look for expected intermediate types missing in mapping_stats
                        missing = []
                        built_mapping = built.get('mapping_stats', {}) if isinstance(built, dict) else {}
                        if u and not hosts and built_mapping.get('host', 0) == 0:
                            missing.append({'expected': 'host', 'reason': 'No host coverage to tie user to endpoint'})
                        if p and not files and built_mapping.get('file_hash', 0) == 0:
                            missing.append({'expected': 'file_hash', 'reason': 'No file hash telemetry to link process to artifact'})
                        candidates.append({'chain': c, 'confidence': round(conf,3), 'missing_links': missing})
                        if len(candidates) >= max_candidates:
                            break
                    if len(candidates) >= max_candidates: break
                if len(candidates) >= max_candidates: break
            if len(candidates) >= max_candidates: break
        if len(candidates) >= max_candidates: break

    # Sort by confidence desc
    candidates.sort(key=lambda x: x.get('confidence',0), reverse=True)

    return {'session_ids': built.get('session_ids','[]'), 'candidates': candidates, 'graph_summary': built.get('graph_summary'), 'mapping_stats': built.get('mapping_stats')}


# Simple in-memory store for persisted candidates (demo)
_candidates_store = {}
_candidate_counter = 0


@router.post('/attack_candidates/persist')
async def persist_candidates(payload: dict):
    """Persist candidate list for review. Returns an id for retrieval."""
    global _candidate_counter
    try:
        candidates = payload.get('candidates')
        meta = payload.get('meta') or {}
        if not candidates or not isinstance(candidates, list):
            raise ValueError('candidates list required')
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_payload')
    cid = f'cand-{int(time.time()*1000)}-{_candidate_counter}'
    _candidate_counter += 1
    _candidates_store[cid] = {'id': cid, 'ts': time.time(), 'candidates': candidates, 'meta': meta}
    return {'id': cid, 'stored': True}


@router.get('/attack_candidates/{cid}')
async def get_persisted_candidates(cid: str):
    rec = _candidates_store.get(cid)
    if not rec:
        raise HTTPException(status_code=404, detail='not_found')
    return rec


# Phase 4: Lightweight LLM gated enrichment queue (in-memory demo)
ENRICHMENT_QUEUE = []
ENRICHMENT_RESULTS = {}
LLM_ENABLED = os.getenv('LLM_ENABLED','0').lower() in {'1','true','yes'}


@router.post('/enrich/queue')
async def enqueue_enrichment(payload: dict):
    """Enqueue an enrichment request. Returns job id."""
    item = {
        'id': f'job-{int(time.time()*1000)}-{len(ENRICHMENT_QUEUE)}',
        'payload': payload,
        'status': 'queued',
        'ts': time.time()
    }
    ENRICHMENT_QUEUE.append(item)
    # If LLM disabled, fail hard in live mode; stub in dev/demo mode
    if not LLM_ENABLED:
        if not _allow_demo_graph_fallbacks():
            ENRICHMENT_QUEUE.pop()
            raise HTTPException(status_code=503, detail='llm_enrichment_unavailable')
        ENRICHMENT_RESULTS[item['id']] = {'id': item['id'], 'status': 'done', 'result': {'note': 'LLM_DISABLED', 'summary': None}}
        item['status'] = 'done'
    return {'job_id': item['id'], 'status': item['status']}


@router.get('/enrich/status/{job_id}')
async def get_enrich_status(job_id: str):
    if job_id in ENRICHMENT_RESULTS:
        return ENRICHMENT_RESULTS[job_id]
    for it in ENRICHMENT_QUEUE:
        if it['id'] == job_id:
            return {'id': it['id'], 'status': it['status']}
    raise HTTPException(status_code=404, detail='job_not_found')
