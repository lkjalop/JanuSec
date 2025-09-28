"""Heuristic rules engine (minimal) for FAST_LIVE_MODE.

Focus: quick pattern detection in normalized events without full ML stack.
Each rule returns a RuleHit describing reason and weight contribution.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any, List
import os
from . import rules_config
from . import asn_stats, dns_agg, domain_baseline

# --- Metrics registration (guarded) ---
try:  # pragma: no cover
    from prometheus_client import Counter as _PromCounter  # type: ignore
    if '_rule_hits_counter' not in globals():
        try:
            _rule_hits_counter = _PromCounter('rule_hits_total','Generic rule hits',['rule'])  # type: ignore
        except ValueError:
            class _StubR:  # pragma: no cover
                def labels(self,*a,**k): return self
                def inc(self,*a,**k): return None
            _rule_hits_counter = _StubR()
    if '_asn_rarity_hits_counter' not in globals():
        try:
            _asn_rarity_hits_counter = _PromCounter('asn_rarity_hits_total','ASN rarity rule hits',['asn'])  # type: ignore
        except ValueError:
            class _Stub:  # pragma: no cover
                def labels(self,*a,**k): return self
                def inc(self,*a,**k): return None
            _asn_rarity_hits_counter = _Stub()
    if '_nx_domain_rate_events_counter' not in globals():
        try:
            _nx_domain_rate_events_counter = _PromCounter('nx_domain_rate_events_total','Events triggering NXDOMAIN rate rule',['host'])  # type: ignore
        except ValueError:
            class _Stub2:  # pragma: no cover
                def labels(self,*a,**k): return self
                def inc(self,*a,**k): return None
            _nx_domain_rate_events_counter = _Stub2()
except Exception:  # pragma: no cover
    _asn_rarity_hits_counter = None  # type: ignore
    _nx_domain_rate_events_counter = None  # type: ignore
from typing import Tuple


@dataclass
class RuleHit:
    rule: str
    weight: float
    detail: str | None = None


LOL_BINS = { 'powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe','plink.exe' }
SUSPICIOUS_PARENTS = { 'winword.exe','excel.exe','outlook.exe','powerpnt.exe' }
SUSPICIOUS_PORTS = {4444,1337,8082}

# Zeek heuristics thresholds
_DEFAULT_NXDOMAIN_RATE_THRESHOLD = float(os.getenv('ZEEK_NXDOMAIN_RATE_THRESHOLD','0.35'))
_LOW_VOL_LONG_DUR_THRESHOLD = float(os.getenv('ZEEK_LOW_VOL_LONG_DUR_THRESHOLD','300'))  # seconds
_LOW_VOL_BYTES_MAX = int(os.getenv('ZEEK_LOW_VOL_BYTES_MAX','5000'))

def _zeek_dns_context(ev: Dict[str,Any]) -> Tuple[int,int]:
    # expected fields: zeek dns events would be tagged differently (future expansion)
    # placeholder returns (nxdomain_count,total_queries) from correlated factors if present
    nxd = ev.get('zeek_dns_nxdomain',0)
    total = ev.get('zeek_dns_total',0)
    return nxd, total

def _zeek_conn_low_volume(ev: Dict[str,Any]) -> bool:
    if 'tags' in ev and 'zeek' in ev['tags'] and 'conn' in ev['tags']:
        dur = ev.get('duration') or ev.get('zeek_duration')
        if isinstance(dur,(int,float)) and dur >= _LOW_VOL_LONG_DUR_THRESHOLD:
            total_bytes = (ev.get('orig_bytes') or 0) + (ev.get('resp_bytes') or 0)
            if isinstance(total_bytes,(int,float)) and total_bytes <= _LOW_VOL_BYTES_MAX:
                return True
    return False

def evaluate_event(ev: Dict[str, Any]) -> List[RuleHit]:
    hits: List[RuleHit] = []
    pn = (ev.get('proc_name') or '').lower()
    parent = (ev.get('parent_proc') or '').lower()
    dest_port = ev.get('dest_port')
    weights = rules_config.get_weights() or {}
    w_lol = weights.get('lolbin_misuse', 0.55)
    w_port = weights.get('suspicious_outbound_port', 0.50)
    w_lineage = weights.get('lineage_anomaly', 0.45)
    if pn in LOL_BINS and parent in SUSPICIOUS_PARENTS:
        hits.append(RuleHit('lolbin_misuse', w_lol, f"{pn} from {parent}"))
        try: _rule_hits_counter.labels(rule='lolbin_misuse').inc()  # type: ignore
        except Exception: pass
    if isinstance(dest_port, int) and dest_port in SUSPICIOUS_PORTS:
        hits.append(RuleHit('suspicious_outbound_port', w_port, f"port {dest_port}"))
        try: _rule_hits_counter.labels(rule='suspicious_outbound_port').inc()  # type: ignore
        except Exception: pass
    if pn in LOL_BINS and not parent:
        hits.append(RuleHit('lineage_anomaly', w_lineage, 'missing_parent'))
        try: _rule_hits_counter.labels(rule='lineage_anomaly').inc()  # type: ignore
        except Exception: pass
    # Zeek: low volume long duration session
    if _zeek_conn_low_volume(ev):
        hits.append(RuleHit('zeek_low_volume_long_duration', weights.get('zeek_low_volume_long_duration',0.55), 'low_vol_session'))
        try: _rule_hits_counter.labels(rule='zeek_low_volume_long_duration').inc()  # type: ignore
        except Exception: pass
    # Zeek: NXDOMAIN rate (pull from event or aggregator)
    nxd, total = _zeek_dns_context(ev)
    if not total:
        # Try aggregator by host
        nxd, total = dns_agg.get(ev.get('host'))
    threshold = float(os.getenv('ZEEK_NXDOMAIN_RATE_THRESHOLD', str(_DEFAULT_NXDOMAIN_RATE_THRESHOLD)))
    if total and total >= 10 and (nxd/total) > threshold:
        hits.append(RuleHit('zeek_high_nxdomain_rate', weights.get('zeek_high_nxdomain_rate',0.60), f"{nxd}/{total}"))
        try: _rule_hits_counter.labels(rule='zeek_high_nxdomain_rate').inc()  # type: ignore
        except Exception: pass
        if _nx_domain_rate_events_counter:
            try:
                _nx_domain_rate_events_counter.labels(host=ev.get('host') or 'unknown').inc()  # type: ignore
            except Exception:
                pass
    # ASN rarity rule
    asn = ev.get('asn') or (ev.get('enrich') or {}).get('asn')
    if asn:
        rarity = asn_stats.rarity(asn)
        if rarity >= float(os.getenv('ASN_RARITY_THRESHOLD','0.95')):
            hits.append(RuleHit('asn_rare_outbound', weights.get('asn_rare_outbound',0.58), f"rarity={rarity:.2f}"))
            try: _rule_hits_counter.labels(rule='asn_rare_outbound').inc()  # type: ignore
            except Exception: pass
            if _asn_rarity_hits_counter:
                try:
                    _asn_rarity_hits_counter.labels(asn=asn).inc()  # type: ignore
                except Exception:
                    pass
    # Domain reputation rules (if dest_domain present)
    dest_domain = ev.get('dest_domain')
    if dest_domain:
        domain_baseline.record(dest_domain)
        count, freq, suspicious_tld = domain_baseline.stats(dest_domain)
        if suspicious_tld:
            hits.append(RuleHit('suspicious_domain_tld', weights.get('suspicious_domain_tld',0.50), dest_domain.split('.')[-1]))
            try: _rule_hits_counter.labels(rule='suspicious_domain_tld').inc()  # type: ignore
            except Exception: pass
        if count >= 3 and freq < 0.0005:
            hits.append(RuleHit('rare_domain', weights.get('rare_domain',0.52), f"freq={freq:.6f}"))
            try: _rule_hits_counter.labels(rule='rare_domain').inc()  # type: ignore
            except Exception: pass
    return hits

def rule_weight_summary(hits: List[RuleHit]) -> float:
    return max((h.weight for h in hits), default=0.0)

ALERT_THRESHOLD = float(os.getenv('FAST_ALERT_THRESHOLD','0.75'))
AMBIG_LOW = float(os.getenv('FAST_AMBIG_LOW','0.45'))
AMBIG_HIGH = float(os.getenv('FAST_AMBIG_HIGH','0.60'))

def score_and_classify(hits: List[RuleHit], artifact_risk: float | None = None) -> dict:
    base = rule_weight_summary(hits)
    ar = (artifact_risk or 0.0) * 0.4
    score = min(1.0, base + ar)
    if AMBIG_LOW <= score < AMBIG_HIGH:
        verdict = 'OBSERVE'
        ambiguity = round(((AMBIG_HIGH - score)/(AMBIG_HIGH - AMBIG_LOW)),3)
    elif score >= ALERT_THRESHOLD:
        verdict = 'ALERT'
        ambiguity = 0.0
    else:
        verdict = 'IGNORE'
        ambiguity = 0.0
    return {
        'score': round(score,3),
        'verdict': verdict,
        'ambiguity': ambiguity,
        'artifact_risk': artifact_risk
    }
