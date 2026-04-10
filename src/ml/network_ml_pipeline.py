"""Network ML Pipeline — composable detectors for C2/exfil/tunnel.

Composes existing primitives (IsolationForest, TF-IDF, EWMA) into a
per-flow feature vector pipeline. Each detector returns factors + scores.
"""
from __future__ import annotations

import math
import os
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Tuple

# --------------- Beacon Analyzer (KS test + periodicity) ---------------

class BeaconAnalyzer:
    """Statistical periodicity detector per (src, dst, port) 5-tuple.

    Emits 'net:beacon_statistical' when coefficient of variation < threshold
    and sample count >= min_samples. Optionally runs a Kolmogorov-Smirnov
    test against uniform interval distribution to catch jittered beacons.
    """

    def __init__(
        self,
        cv_threshold: float = 0.3,
        min_samples: int = 10,
        ks_pvalue: float = 0.05,
        maxlen: int = 128,
    ):
        self.cv_threshold = float(os.getenv('BEACON_CV_THRESHOLD', str(cv_threshold)))
        self.min_samples = int(os.getenv('BEACON_MIN_SAMPLES', str(min_samples)))
        self.ks_pvalue = ks_pvalue
        self.maxlen = maxlen
        self._flows: Dict[Tuple[str, str, int], deque] = defaultdict(
            lambda: deque(maxlen=self.maxlen)
        )

    def observe(self, src_ip: str, dst_ip: str, dst_port: int, ts: float) -> Dict[str, Any]:
        key = (src_ip, dst_ip, dst_port)
        dq = self._flows[key]
        dq.append(ts)
        if len(dq) < self.min_samples + 1:
            return {}
        intervals = [dq[i + 1] - dq[i] for i in range(len(dq) - 1)]
        mean_iv = sum(intervals) / len(intervals)
        if mean_iv <= 0:
            return {}
        var_iv = sum((x - mean_iv) ** 2 for x in intervals) / len(intervals)
        std_iv = math.sqrt(var_iv)
        cv = std_iv / mean_iv

        result: Dict[str, Any] = {
            'cv': round(cv, 4),
            'mean_interval': round(mean_iv, 2),
            'std_interval': round(std_iv, 2),
            'sample_count': len(intervals),
        }

        if cv < self.cv_threshold:
            result['beacon_detected'] = True
            result['confidence'] = round(1.0 - cv, 3)
            result['factor'] = 'net:beacon_statistical'
        else:
            # KS test for jittered beacons
            ks_p = self._ks_uniform_test(intervals)
            result['ks_pvalue'] = round(ks_p, 4) if ks_p is not None else None
            if ks_p is not None and ks_p < self.ks_pvalue:
                result['beacon_detected'] = True
                result['confidence'] = round(min(0.8, 1.0 - ks_p), 3)
                result['factor'] = 'net:beacon_jitter_detected'
            else:
                result['beacon_detected'] = False

        return result

    @staticmethod
    def _ks_uniform_test(intervals: List[float]) -> float | None:
        """KS test: are intervals drawn from a uniform distribution?
        Low p-value => NOT uniform => likely periodic with jitter.
        Returns p-value or None if scipy unavailable.
        """
        try:
            from scipy.stats import kstest  # type: ignore
            if not intervals or len(intervals) < 5:
                return None
            lo, hi = min(intervals), max(intervals)
            if hi <= lo:
                return 0.0
            normalized = [(x - lo) / (hi - lo) for x in intervals]
            stat, pvalue = kstest(normalized, 'uniform')
            return float(pvalue)
        except Exception:
            return None


# --------------- DNS Tunnel Detector ---------------

class DNSTunnelDetector:
    """Per-domain entropy EWMA + query-length tracker.

    Fires 'dns:tunnel_entropy_high' when EWMA of subdomain entropy
    exceeds threshold, even without high QPS (catches slow DNS tunnels).
    """

    def __init__(
        self,
        entropy_threshold: float = 3.5,
        length_threshold: int = 50,
        ewma_alpha: float = 0.3,
    ):
        self.entropy_threshold = float(
            os.getenv('DNS_TUNNEL_ENTROPY_THRESHOLD', str(entropy_threshold))
        )
        self.length_threshold = int(
            os.getenv('DNS_TUNNEL_LENGTH_THRESHOLD', str(length_threshold))
        )
        self.ewma_alpha = ewma_alpha
        self._domain_ewma: Dict[str, float] = {}
        self._domain_count: Dict[str, int] = defaultdict(int)

    def analyze(self, query_name: str) -> Dict[str, Any]:
        if not query_name:
            return {}
        qname = query_name.lower().strip('.')
        labels = qname.split('.')
        if len(labels) < 2:
            return {}
        sld = '.'.join(labels[-2:])
        subdomain_part = '.'.join(labels[:-2])
        ent = _shannon_entropy(subdomain_part)
        qlen = len(subdomain_part)

        # EWMA update
        prev = self._domain_ewma.get(sld, ent)
        ewma_val = self.ewma_alpha * ent + (1.0 - self.ewma_alpha) * prev
        self._domain_ewma[sld] = ewma_val
        self._domain_count[sld] += 1

        result: Dict[str, Any] = {
            'sld': sld,
            'entropy': round(ent, 3),
            'ewma_entropy': round(ewma_val, 3),
            'query_length': qlen,
            'query_count': self._domain_count[sld],
        }

        factors: List[str] = []
        if ewma_val > self.entropy_threshold:
            factors.append('dns:tunnel_entropy_high')
        if qlen > self.length_threshold:
            factors.append('dns:tunnel_long_query')
        if factors:
            result['factors'] = factors
            result['confidence'] = round(min(0.9, ewma_val / 5.0), 3)
        return result


# --------------- Flow Anomaly Detector (Isolation Forest) ---------------

class FlowAnomalyDetector:
    """Per-flow feature vector → Isolation Forest anomaly score.

    Features: (bytes_out, packets, duration_s, interval_cv).
    Wraps the existing IsolationForestDetector.
    """

    def __init__(self, warmup: int = 50):
        self.warmup = warmup
        self._buffer: List[List[float]] = []
        self._fitted = False
        self._detector = None

    def _ensure_detector(self):
        if self._detector is None:
            try:
                from src.core.detect.isolation_forest import IsolationForestDetector
                self._detector = IsolationForestDetector(n_estimators=50)
            except Exception:
                self._detector = None

    def observe(
        self,
        bytes_out: float,
        packets: float,
        duration_s: float,
        interval_cv: float,
    ) -> Dict[str, Any]:
        self._ensure_detector()
        if self._detector is None:
            return {}
        features = [bytes_out, packets, duration_s, interval_cv]
        self._buffer.append(features)

        if not self._fitted:
            if len(self._buffer) >= self.warmup:
                self._detector.fit(self._buffer)
                self._fitted = True
            return {}

        score = self._detector.score(features)
        result: Dict[str, Any] = {
            'anomaly_score': round(score, 4),
            'features': {
                'bytes_out': bytes_out,
                'packets': packets,
                'duration_s': round(duration_s, 2),
                'interval_cv': round(interval_cv, 4),
            },
        }
        if score > 0.7:
            result['factor'] = 'net:flow_anomaly_high'
            result['confidence'] = round(min(0.95, score), 3)
        elif score > 0.5:
            result['factor'] = 'net:flow_anomaly_medium'
            result['confidence'] = round(score, 3)
        return result


# --------------- JA3 SSLBL + TF-IDF Rarity ---------------

class JA3Analyzer:
    """Known-bad JA3 lookup (SSLBL) + TF-IDF rarity scoring."""

    # Curated Cobalt Strike / Metasploit / Sliver JA3 hashes (SSLBL subset)
    KNOWN_BAD_JA3: set = {
        '72a589da586844d7f0818ce684948eea',  # Cobalt Strike default
        'a0e9f5d64349fb13191bc781f81f42e1',  # Cobalt Strike 4.x
        '51c64c77e60f3980eea90869b68c58a8',  # Metasploit Meterpreter
        'b742b407517bac9536a77a7b0fee28e9',  # Sliver C2
        '6734f37431670b3ab4292b8f60f29984',  # Trickbot
        'e7d705a3286e19ea42f587b344ee6865',  # Dridex
        '3b5074b1b5d032e5620f69f9f700ff0e',  # IcedID
        '8a553953cdbb67f29a0b0eef0b1d886c',  # QakBot
    }

    def __init__(self):
        self._tfidf = None
        self._count = 0

    def _ensure_tfidf(self):
        if self._tfidf is None:
            try:
                from src.ml.tfidf_profile import TfidfProfile
                self._tfidf = TfidfProfile()
            except Exception:
                pass

    def analyze(self, ja3_hash: str, sni: str = '') -> Dict[str, Any]:
        if not ja3_hash:
            return {}
        h = ja3_hash.strip().lower()
        result: Dict[str, Any] = {'ja3': h}
        factors: List[str] = []

        # SSLBL lookup
        if h in self.KNOWN_BAD_JA3:
            factors.append('ssl:ja3_sslbl_match')
            result['sslbl_match'] = True
            result['confidence'] = 0.92

        # TF-IDF rarity
        self._ensure_tfidf()
        if self._tfidf:
            tokens = [h]
            if sni:
                tokens.append(sni.lower())
            self._tfidf.add_document(tokens)
            rarity = self._tfidf.get_rarity_score(tokens)
            result['tfidf_rarity'] = round(rarity, 4)
            if rarity > 0.8 and 'ssl:ja3_sslbl_match' not in factors:
                factors.append('ssl:ja3_tfidf_rare')
                result['confidence'] = round(min(0.85, rarity), 3)

        if factors:
            result['factors'] = factors
        return result


# --------------- Composed Pipeline ---------------

class NetworkMLPipeline:
    """Facade that runs all detectors on a flow/event and returns factors."""

    def __init__(self):
        self.beacon = BeaconAnalyzer()
        self.dns_tunnel = DNSTunnelDetector()
        self.flow_anomaly = FlowAnomalyDetector()
        self.ja3 = JA3Analyzer()

    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Run all applicable detectors on a single event dict.

        Returns: {'factors': [...], 'details': {...}}
        """
        factors: List[str] = []
        details: Dict[str, Any] = {}

        # Beacon analysis
        src = event.get('src_ip') or event.get('source_ip') or ''
        dst = event.get('dst_ip') or event.get('destination_ip') or ''
        port = event.get('dst_port') or event.get('destination_port')
        ts = event.get('ts') or event.get('timestamp') or time.time()
        if src and dst and port:
            try:
                beacon_result = self.beacon.observe(str(src), str(dst), int(port), float(ts))
                if beacon_result.get('beacon_detected'):
                    factors.append(beacon_result.get('factor', 'net:beacon_statistical'))
                    details['beacon'] = beacon_result
            except Exception:
                pass

        # DNS tunnel
        qname = event.get('dns_query') or event.get('query_name') or ''
        if qname:
            dns_result = self.dns_tunnel.analyze(qname)
            for f in dns_result.get('factors', []):
                factors.append(f)
            if dns_result.get('factors'):
                details['dns_tunnel'] = dns_result

        # Flow anomaly (when byte counts available)
        bytes_out = event.get('bytes_out') or event.get('resp_bytes') or 0
        packets = event.get('packets') or event.get('pkts') or 0
        duration = event.get('duration') or event.get('duration_s') or 0
        if bytes_out or packets:
            # Use beacon CV if available, else 1.0
            iv_cv = (details.get('beacon', {}).get('cv') or 1.0)
            flow_result = self.flow_anomaly.observe(
                float(bytes_out), float(packets), float(duration), float(iv_cv)
            )
            if flow_result.get('factor'):
                factors.append(flow_result['factor'])
                details['flow_anomaly'] = flow_result

        # JA3 analysis
        ja3 = event.get('ja3') or event.get('ja3_hash') or ''
        sni = event.get('sni') or event.get('server_name') or ''
        if ja3:
            ja3_result = self.ja3.analyze(ja3, sni)
            for f in ja3_result.get('factors', []):
                factors.append(f)
            if ja3_result.get('factors'):
                details['ja3'] = ja3_result

        return {'factors': list(dict.fromkeys(factors)), 'details': details}


# --------------- Utility ---------------

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent
