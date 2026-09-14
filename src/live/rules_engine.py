"""Heuristic rules engine (minimal) for FAST_LIVE_MODE.

Focus: quick pattern detection in normalized events without full ML stack.
Each rule returns a RuleHit describing reason and weight contribution.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from . import asn_stats, dns_agg, domain_baseline, rules_config

if TYPE_CHECKING:
    from prometheus_client import CollectorRegistry

logger = logging.getLogger(__name__)
ADAPTIVE_TUNER_ENABLED = os.getenv('ADAPTIVE_TUNER_ENABLED','0').lower() in {'1','true','yes'}

_rule_hits_counter: Any = None  # will be bound by register_metrics
_asn_rarity_hits_counter: Any = None
_nx_domain_rate_events_counter: Any = None

def register_metrics(registry: Optional['CollectorRegistry'] = None) -> None:
    """Register counters explicitly into provided registry (no global side effects).

    Recreates counters if they are not bound to the target registry. Always uses
    the prometheus_client constructors with an explicit registry argument.
    """
    global _rule_hits_counter, _asn_rarity_hits_counter, _nx_domain_rate_events_counter
    try:
        from prometheus_client import Counter

        from src.api.metrics_init import REGISTRY as DEFAULT_REG, ensure_metrics
        ensure_metrics()
        reg = registry or DEFAULT_REG
        # (Re)create each counter with explicit registry binding
        _rule_hits_counter = Counter('rule_hits_total', 'Generic rule hits', ['rule'], registry=reg)
        _asn_rarity_hits_counter = Counter('asn_rarity_hits_total', 'ASN rarity rule hits', ['asn'], registry=reg)
        _nx_domain_rate_events_counter = Counter('nx_domain_rate_events_total', 'Events triggering NXDOMAIN rate rule', ['host'], registry=reg)
        logger.debug('rules_engine metrics registered (explicit registry)')
    except Exception as exc:
        logger.debug('rules_engine metrics registration failed: %s', exc)
        class _Stub:
            def labels(self, *a: Any, **k: Any) -> "_Stub":
                return self
            def inc(self, *a: Any, **k: Any) -> None:
                return None
        if _rule_hits_counter is None: _rule_hits_counter = _Stub()
        if _asn_rarity_hits_counter is None: _asn_rarity_hits_counter = _Stub()
        if _nx_domain_rate_events_counter is None: _nx_domain_rate_events_counter = _Stub()
from typing import Tuple

# Module import debug (helps diagnose whether this module is actually loaded)
try:
    _mod_registry = getattr(globals().get('_rule_hits_counter', None), 'registry', None)
    logger.debug('live.rules_engine imported, rule counter registry=%s', _mod_registry)
except Exception:
    logger.debug('live.rules_engine imported')
try:
    from src.api.metrics_init import REGISTRY as _MI_REG
    try:
        names = [f.name for f in (_MI_REG.collect() or [])]
    except Exception:
        names = []
    logger.debug('metrics_init.REGISTRY contains: %s', names)
except Exception:
    logger.debug('metrics_init not available at import')


@dataclass
class RuleHit:
    rule: str
    weight: float
    detail: str | None = None


LOL_BINS = { 'powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe','plink.exe' }
SUSPICIOUS_PARENTS = { 'winword.exe','excel.exe','outlook.exe','powerpnt.exe' }
SUSPICIOUS_PORTS = {4444,1337,8082}
SUSPICIOUS_CMD_FLAGS = [' -enc ', ' -encodedcommand', ' -nop ', ' -w hidden', ' /bypass', ' -exec bypass']

# Zeek heuristics thresholds
_DEFAULT_NXDOMAIN_RATE_THRESHOLD = float(os.getenv('ZEEK_NXDOMAIN_RATE_THRESHOLD','0.35'))
_LOW_VOL_LONG_DUR_THRESHOLD = float(os.getenv('ZEEK_LOW_VOL_LONG_DUR_THRESHOLD','300'))  # seconds
_LOW_VOL_BYTES_MAX = int(os.getenv('ZEEK_LOW_VOL_BYTES_MAX','5000'))

def _zeek_dns_context(ev: dict[str,Any]) -> tuple[int,int]:
    # expected fields: zeek dns events would be tagged differently (future expansion)
    # placeholder returns (nxdomain_count,total_queries) from correlated factors if present
    nxd = ev.get('zeek_dns_nxdomain',0)
    total = ev.get('zeek_dns_total',0)
    return nxd, total

def _zeek_conn_low_volume(ev: dict[str,Any]) -> bool:
    if 'tags' in ev and 'zeek' in ev['tags'] and 'conn' in ev['tags']:
        dur = ev.get('duration') or ev.get('zeek_duration')
        if isinstance(dur,(int,float)) and dur >= _LOW_VOL_LONG_DUR_THRESHOLD:
            total_bytes = (ev.get('orig_bytes') or 0) + (ev.get('resp_bytes') or 0)
            if isinstance(total_bytes,(int,float)) and total_bytes <= _LOW_VOL_BYTES_MAX:
                return True
    return False

def evaluate_event(ev: dict[str, Any]) -> list[RuleHit]:
    # Entry debug: log that evaluate_event was invoked and a short event summary
    try:
        if ADAPTIVE_TUNER_ENABLED:
            logger.debug('evaluate_event called; event_keys=%s', list(ev.keys())[:12])
    except Exception:
        if ADAPTIVE_TUNER_ENABLED:
            logger.debug('evaluate_event called')
    hits: list[RuleHit] = []
    # Defensive: ensure metrics are registered if startup didn't run register_metrics yet.
    try:
        if getattr(_rule_hits_counter, 'registry', None) is None:
            try:
                from src.api.metrics_init import REGISTRY as _REG
                register_metrics(_REG)
            except Exception:
                try:
                    register_metrics()
                except Exception:
                    pass
    except Exception:
        # If any of the introspection fails, continue without blocking evaluation
        pass
    pn = (ev.get('proc_name') or '').lower()
    parent = (ev.get('parent_proc') or '').lower()
    dest_port = ev.get('dest_port')
    cmd = (ev.get('command_line') or '').lower()
    weights: dict[str, Any] = rules_config.get_weights() or {}
    # Default weights tuned to ensure strong signal for well-known abuse patterns
    # These can still be overridden via rules_config external file.
    w_lol = weights.get('lolbin_misuse', 0.70)
    w_port = weights.get('suspicious_outbound_port', 0.50)
    w_lineage = weights.get('lineage_anomaly', 0.45)
    w_cmd = weights.get('suspicious_cmdline_flags', 0.72)
    if pn in LOL_BINS and parent in SUSPICIOUS_PARENTS:
        hits.append(RuleHit('lolbin_misuse', w_lol, f"{pn} from {parent}"))
        logger.debug('lolbin_misuse hit, registry=%s', getattr(_rule_hits_counter, 'registry', None))
        try:
            _rule_hits_counter.labels(rule='lolbin_misuse').inc()
        except Exception as e:
            logger.debug('inc failed: %s', e)
        try:
            # Check label integrity
            if not getattr(_rule_hits_counter, '_labelnames', None):
                logger.debug('rule_hits_counter missing labelnames attribute at runtime')
        except Exception:
            pass
    if isinstance(dest_port, int) and dest_port in SUSPICIOUS_PORTS:
        hits.append(RuleHit('suspicious_outbound_port', w_port, f"port {dest_port}"))
        try:
            _rule_hits_counter.labels(rule='suspicious_outbound_port').inc()
        except Exception:
            pass
    if pn in LOL_BINS and not parent:
        hits.append(RuleHit('lineage_anomaly', w_lineage, 'missing_parent'))
    # Suspicious command line flags
    try:
        if cmd and any(flag in cmd for flag in SUSPICIOUS_CMD_FLAGS):
            hits.append(RuleHit('suspicious_cmdline_flags', w_cmd, 'cmdline_flags'))
            try: _rule_hits_counter.labels(rule='suspicious_cmdline_flags').inc()
            except Exception: pass
    except Exception:
        pass
        try:
            _rule_hits_counter.labels(rule='lineage_anomaly').inc()
        except Exception:
            pass
    # Zeek: low volume long duration session
    if _zeek_conn_low_volume(ev):
        hits.append(RuleHit('zeek_low_volume_long_duration', weights.get('zeek_low_volume_long_duration',0.55), 'low_vol_session'))
        try:
            _rule_hits_counter.labels(rule='zeek_low_volume_long_duration').inc()
        except Exception:
            pass
    # Zeek: NXDOMAIN rate (pull from event or aggregator)
    nxd, total = _zeek_dns_context(ev)
    if not total:
        # Try aggregator by host
        nxd, total = dns_agg.get(ev.get('host'))
    threshold = float(os.getenv('ZEEK_NXDOMAIN_RATE_THRESHOLD', str(_DEFAULT_NXDOMAIN_RATE_THRESHOLD)))
    # Boundary: tests expect rule NOT to fire when rate exactly equals threshold but fire when above; keep '>'
    # However ensure division safe and cached threshold respected even if env changed post-import.
    if total and total >= 10 and (nxd/total) > threshold:
        hits.append(RuleHit('zeek_high_nxdomain_rate', weights.get('zeek_high_nxdomain_rate',0.60), f"{nxd}/{total}"))
        try:
            _rule_hits_counter.labels(rule='zeek_high_nxdomain_rate').inc()
        except Exception:
            pass
        if _nx_domain_rate_events_counter:
            try:
                _nx_domain_rate_events_counter.labels(host=ev.get('host') or 'unknown').inc()
            except Exception:
                pass
    # ASN rarity rule
    asn = ev.get('asn') or (ev.get('enrich') or {}).get('asn')
    if asn:
        rarity = asn_stats.rarity(asn)
        # Boundary: fire only when rarity strictly exceeds threshold to allow precise under/over test control.
        if rarity > float(os.getenv('ASN_RARITY_THRESHOLD','0.95')):
            hits.append(RuleHit('asn_rare_outbound', weights.get('asn_rare_outbound',0.58), f"rarity={rarity:.2f}"))
            try:
                _rule_hits_counter.labels(rule='asn_rare_outbound').inc()
            except Exception:
                pass
            if _asn_rarity_hits_counter:
                try:
                    _asn_rarity_hits_counter.labels(asn=asn).inc()
                except Exception:
                    pass
    # Domain reputation rules (if dest_domain present)
    dest_domain = ev.get('dest_domain')
    if dest_domain:
        domain_baseline.record(dest_domain)
        count, freq, suspicious_tld = domain_baseline.stats(dest_domain)
        if suspicious_tld:
            hits.append(RuleHit('suspicious_domain_tld', weights.get('suspicious_domain_tld',0.50), dest_domain.split('.')[-1]))
            try: _rule_hits_counter.labels(rule='suspicious_domain_tld').inc()
            except Exception: pass
        if count >= 3 and freq < 0.0005:
            hits.append(RuleHit('rare_domain', weights.get('rare_domain',0.52), f"freq={freq:.6f}"))
            try: _rule_hits_counter.labels(rule='rare_domain').inc()
            except Exception: pass
    return hits

def rule_weight_summary(hits: list[RuleHit]) -> float:
    return max((h.weight for h in hits), default=0.0)

ALERT_THRESHOLD = float(os.getenv('FAST_ALERT_THRESHOLD','0.75'))
AMBIG_LOW = float(os.getenv('FAST_AMBIG_LOW','0.45'))
AMBIG_HIGH = float(os.getenv('FAST_AMBIG_HIGH','0.60'))

def score_and_classify(hits: list[RuleHit], artifact_risk: float | None = None) -> dict[str, Any]:
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
