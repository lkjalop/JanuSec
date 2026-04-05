"""Detector for DNS exfil patterns using NXDOMAIN rates and subdomain entropy."""
from __future__ import annotations

from typing import Dict, Any, List
import math, os, time


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    l = float(len(s))
    for _, c in freq.items():
        p = c / l
        ent -= p * math.log2(p)
    return ent


def dns_exfil_factors(runtime: Any, min_samples: int = 10, nx_threshold: float = 0.35) -> List[Dict[str, Any]]:
    """Inspect runtime.nx_rate_tracker and return dns_exfil related factors.

    runtime: expected to have .nx_rate_tracker mapping of producer -> deque[bool]
    """
    out = []
    if runtime is None:
        return out
    nx_tracker = getattr(runtime, 'nx_rate_tracker', None)
    if not nx_tracker:
        return out
    # CDN whitelist (common legitimate providers) - allowlist domains
    cdn_whitelist = set([d.strip().lower() for d in (os.getenv('DNS_CDN_WHITELIST','cloudfront.net,cloudflare.com,amazonaws.com,akamai.net,googleusercontent.com').split(',')) if d.strip()])
    # Optional file-based allowlist for enterprise tuning
    allowlist_path = os.getenv('CDN_ALLOWLIST_PATH')
    if allowlist_path and os.path.exists(allowlist_path):
        try:
            with open(allowlist_path,'r',encoding='utf8') as fh:
                for line in fh:
                    l = line.strip().lower()
                    if l and not l.startswith('#'):
                        cdn_whitelist.add(l)
        except Exception:
            pass
    # Examine each producer for NXDOMAIN ratio and approximate subdomain entropy
    # Optional rcode counts tracker: runtime may expose dns_rcode_counts mapping producer -> {'NXDOMAIN': n, 'NOERROR': m, 'TXT': x, 'CNAME': y}
    rcode_counts = getattr(runtime, 'dns_rcode_counts', {}) if hasattr(runtime, 'dns_rcode_counts') else {}
    for producer, dq in list(nx_tracker.items()):
        try:
            vals = list(dq)
            if len(vals) < min_samples:
                continue
            rate = sum(1 for v in vals if v) / max(1, len(vals))
            if rate < nx_threshold:
                continue
            # Try to compute entropy from available DNS samples if present on runtime.
            samples = None
            for attr in ('dns_samples', 'dns_query_samples', 'dns_query_examples'):
                samples = getattr(runtime, attr, None)
                if samples is not None:
                    break
            entropy_val = 0.0
            sample_count = 0
            if isinstance(samples, dict):
                # expect mapping producer -> list[str]
                s_list = samples.get(producer) or []
            else:
                s_list = []
            # If samples exist, compute entropy across concatenated left labels
            if s_list and isinstance(s_list, (list, tuple)):
                buf = []
                for q in s_list[:min(len(s_list), 64)]:
                    try:
                        left = str(q).split('.')[:-2]
                        if left:
                            buf.append('.'.join(left))
                    except Exception:
                        continue
                concat = '.'.join(buf)
                entropy_val = _shannon_entropy(concat) if concat else 0.0
                sample_count = len(buf)
            else:
                # fallback: use producer label as proxy
                entropy_val = _shannon_entropy(producer.split(':')[-1])
            # If producer domain is a known CDN, skip
            try:
                domain_part = producer.split(':')[-1].lower()
                if any(domain_part.endswith(d) for d in cdn_whitelist):
                    continue
            except Exception:
                pass

            score = 0.5
            reason = f'nx_rate {rate:.2f} >= {nx_threshold:.2f} for {producer}'
            # Incorporate rcode mix weighting: high TXT/CNAME proportion can indicate tunneling
            mix = rcode_counts.get(producer, {}) if isinstance(rcode_counts, dict) else {}
            txt_count = int(mix.get('TXT', 0) or 0)
            cname_count = int(mix.get('CNAME', 0) or 0)
            nxd_count = int(mix.get('NXDOMAIN', 0) or 0)
            total_rcodes = sum(int(v or 0) for v in mix.values()) or 0
            txt_ratio = (txt_count / total_rcodes) if total_rcodes > 0 else 0.0
            cname_ratio = (cname_count / total_rcodes) if total_rcodes > 0 else 0.0
            # Heuristic boosts
            if txt_ratio >= 0.15:
                score += 0.1
                reason += f' TXT_ratio={txt_ratio:.2f}'
            if cname_ratio >= 0.2:
                score += 0.07
                reason += f' CNAME_ratio={cname_ratio:.2f}'
            # Response pattern heuristics: rapid NXDOMAIN bursts followed by CNAME chain pivot
            try:
                pattern_hint = None
                if nxd_count >= 10 and cname_ratio > 0.15 and rate > (nx_threshold + 0.1):
                    pattern_hint = 'nxdomain_then_cname_chain'
                    score += 0.05
                    reason += ' pattern=nxdomain_then_cname_chain'
            except Exception:
                pattern_hint = None
            if entropy_val and entropy_val >= 3.5:
                score = 0.85 if sample_count >= 5 else 0.7
                reason += f' and entropy {entropy_val:.2f} high'
            # Boost if sample_count and high rate
            if sample_count >= 10 and rate >= (nx_threshold + 0.15):
                score = min(0.95, score + 0.05)
            out.append({'producer': producer, 'factor': 'dns_exfil', 'nx_rate': round(rate, 3), 'entropy': round(entropy_val, 3), 'reason': reason, 'score': round(score, 3), 'txt_ratio': round(txt_ratio,3), 'cname_ratio': round(cname_ratio,3)})
        except Exception:
            continue
    return out
