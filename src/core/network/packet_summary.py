"""Lightweight packet/micro-flow summarizer.

Design Goals:
- No raw packet capture storage; only derived features.
- Operates on optional network metadata in event['details']['network'] list of flow dicts.
- Emits factors for anomalies (dns_tunnel_pattern, beacon_like_30s, unusual_port_cluster, large_outbound_volume).

Expected flow entry keys (if present):
  proto: str (e.g., tcp, udp, dns, http)
  dst_port: int
  bytes: int
  direction: str (outbound|inbound)
  timestamp: float (epoch seconds)
  domain: optional str (for dns)

Configuration via env (optional):
  PACKET_SUMMARY_MAX_FLOWS (default 200)
  PACKET_SUMMARY_BEACON_THRESHOLD_JITTER (default 0.15)
  PACKET_SUMMARY_LARGE_OUTBOUND_BYTES (default 5_000_000)

Returns list of factor strings.
"""
from __future__ import annotations

import math
import os
import statistics
from typing import Any, Dict, List, Tuple


class PacketSummarizer:
    def __init__(self):
        self.max_flows = int(os.getenv('PACKET_SUMMARY_MAX_FLOWS','200'))
        self.beacon_jitter_thresh = float(os.getenv('PACKET_SUMMARY_BEACON_THRESHOLD_JITTER','0.15'))
        self.large_outbound_bytes = int(os.getenv('PACKET_SUMMARY_LARGE_OUTBOUND_BYTES','5000000'))

    def summarize(self, event: dict[str, Any]) -> list[str]:
        details = event.get('details') or {}
        flows: list[dict[str, Any]] = details.get('network') or []
        if not isinstance(flows, list) or not flows:
            return []
        flows = flows[:self.max_flows]
        factors: list[str] = []
        # Basic aggregations
        outbound = [f for f in flows if f.get('direction') == 'outbound']
        total_out = sum(int(f.get('bytes',0)) for f in outbound)
        if total_out >= self.large_outbound_bytes:
            factors.append('exfil_volume_high')
        # Port clustering (simple variance Heuristic)
        ports = [int(f.get('dst_port',0)) for f in outbound if f.get('dst_port')]
        if len(ports) >= 5:
            # If ports all distinct and spread large, might indicate scanning / unusual cluster
            uniq = len(set(ports))
            if uniq/len(ports) > 0.9 and (max(ports)-min(ports) > 40000):
                factors.append('unusual_port_cluster')
        # DNS tunneling heuristic (long labels / volume of queries)
        dns_flows = [f for f in flows if f.get('proto') == 'dns']
        if dns_flows:
            long_label = 0
            for d in dns_flows:
                domain = d.get('domain') or ''
                parts = domain.split('.') if domain else []
                if any(len(p) > 30 for p in parts):
                    long_label += 1
            if long_label and long_label/len(dns_flows) > 0.2:
                factors.append('dns_tunnel_pattern')
        # Beacon detection: even spacing of timestamps in outbound flows
        times = sorted(float(f.get('timestamp')) for f in outbound if f.get('timestamp'))
        if len(times) >= 4:
            intervals = [times[i+1]-times[i] for i in range(len(times)-1)]
            detection_interval = None
            if intervals:
                mean_iv = statistics.mean(intervals)
                if mean_iv > 0:
                    std = statistics.pstdev(intervals)
                    jitter = std / mean_iv if mean_iv else 0.0
                    if jitter < self.beacon_jitter_thresh:
                        detection_interval = mean_iv
                if detection_interval is None:
                    median_iv = statistics.median(intervals)
                    if median_iv > 0:
                        deviations = [abs(iv - median_iv) / median_iv for iv in intervals]
                        stable = [d for d in deviations if d < self.beacon_jitter_thresh]
                        if len(stable) >= max(3, len(intervals) - 2):
                            detection_interval = median_iv
                if detection_interval:
                    label = 'beacon_like_30s' if 20 <= detection_interval <= 40 else 'beacon_pattern'
                    factors.append(label)
        return factors

_default = PacketSummarizer()

def summarize_packet_event(event: dict[str, Any]) -> list[str]:
    try:
        return _default.summarize(event)
    except Exception:
        return []
