from typing import List
from ..canonical_event import CanonicalEvent

try:
    from src.ml.network_ml_pipeline import NetworkMLPipeline as _NMP
    _ml_pipeline = _NMP()
except Exception:
    _ml_pipeline = None

class FactorEmit(dict):
    pass

def extract_network_factors(events: List[CanonicalEvent]) -> List[FactorEmit]:
    out: List[FactorEmit] = []
    # naive grouping for dns_nxdomain_spike & anomalous_tls_ja3 placeholder
    nxdomain_count = 0
    ja3_seen = set()
    flow_by_dst: dict[str, List[float]] = {}
    domain_contact_count: dict[str, int] = {}
    # recon tracking
    src_port_targets: dict[str, dict[int, set[str]]] = {}
    src_dst_ports: dict[str, dict[str, set[int]]] = {}
    src_domain_contacts: dict[str, set[str]] = {}
    for e in events:
        if e.source_type != 'network':
            continue
        if e.domain and e.domain.endswith('.invalid'):
            nxdomain_count += 1
        if e.raw.get('ja3'):
            ja3_seen.add(e.raw.get('ja3'))
        # capture beacon candidate flows: src->dst repeated timestamps
        if e.dst_ip and e.timestamp:
            key = e.dst_ip
            flow_by_dst.setdefault(key, []).append(e.timestamp)
        if e.domain:
            domain_contact_count[e.domain] = domain_contact_count.get(e.domain,0)+1
            if e.src_ip:
                src_domain_contacts.setdefault(e.src_ip, set()).add(e.domain)
        if e.src_ip and e.dst_ip and e.dst_port:
            src_port_targets.setdefault(e.src_ip, {}).setdefault(int(e.dst_port), set()).add(e.dst_ip)
            src_dst_ports.setdefault(e.src_ip, {}).setdefault(e.dst_ip, set()).add(int(e.dst_port))
    if nxdomain_count >= 3:
        out.append(FactorEmit(name='dns_nxdomain_spike', nodes=['aggregate:network'], domain='network', confidence=0.6, ts=events[0].timestamp if events else 0.0))
    if len(ja3_seen) >= 2:
        out.append(FactorEmit(name='anomalous_tls_ja3', nodes=['aggregate:network'], domain='network', confidence=0.55, ts=events[0].timestamp if events else 0.0))
    # lateral_move_edge_sequence (simplified: presence of >1 distinct dst_ip from same src_ip)
    src_to_dst = {}
    for e in events:
        if e.source_type != 'network':
            continue
        if e.src_ip and e.dst_ip:
            src_to_dst.setdefault(e.src_ip, set()).add(e.dst_ip)
    for src_ip, dsts in src_to_dst.items():
        if len(dsts) >= 3:
            out.append(FactorEmit(name='lateral_move_edge_sequence', nodes=[f"ip:{src_ip}"], domain='network', confidence=0.62, ts=events[0].timestamp if events else 0.0))
    # beaconing_interval_regular: low variance intervals
    for dst, times in flow_by_dst.items():
        if len(times) >= 5:
            times.sort()
            intervals = [times[i+1]-times[i] for i in range(len(times)-1)]
            if intervals:
                avg = sum(intervals)/len(intervals)
                var = sum((iv-avg)**2 for iv in intervals)/len(intervals)
                if avg > 0 and var/avg < 0.2:  # simple regularity heuristic
                    out.append(FactorEmit(name='beaconing_interval_regular', nodes=[f"ip:{dst}"], domain='network', confidence=0.66, ts=times[-1]))
    # sudden_c2_domain_contact: domain contacted more than threshold quickly
    for dom, cnt in domain_contact_count.items():
        if cnt >= 8:  # threshold
            out.append(FactorEmit(name='sudden_c2_domain_contact', nodes=[f"domain:{dom}"], domain='network', confidence=0.68, ts=events[-1].timestamp if events else 0.0))
    # Recon: horizontal/vertical scans and domain recon spikes
    for src_ip, port_map in src_port_targets.items():
        for port, dsts in port_map.items():
            if len(dsts) >= 8:
                out.append(FactorEmit(
                    name='port_scan_horizontal',
                    nodes=[f"ip:{src_ip}"],
                    domain='network',
                    confidence=0.62,
                    ts=events[-1].timestamp if events else 0.0
                ))
                break
    for src_ip, dst_map in src_dst_ports.items():
        for dst_ip, ports in dst_map.items():
            if len(ports) >= 8:
                out.append(FactorEmit(
                    name='port_scan_vertical',
                    nodes=[f"ip:{src_ip}", f"ip:{dst_ip}"],
                    domain='network',
                    confidence=0.6,
                    ts=events[-1].timestamp if events else 0.0
                ))
                break
    for src_ip, domains in src_domain_contacts.items():
        if len(domains) >= 10:
            out.append(FactorEmit(
                name='dns_recon_spike',
                nodes=[f"ip:{src_ip}"],
                domain='network',
                confidence=0.58,
                ts=events[-1].timestamp if events else 0.0
            ))
    # --- ML-based detectors (beacon, DNS tunnel, flow anomaly, JA3) ---
    if _ml_pipeline is not None:
        for e in events:
            if e.source_type != 'network':
                continue
            ev = {
                'src_ip': e.src_ip or '',
                'dst_ip': e.dst_ip or '',
                'dst_port': int(e.dst_port) if e.dst_port else 0,
                'timestamp': e.timestamp or 0.0,
                'domain': e.domain or '',
                'dns_query': e.raw.get('dns_query') or e.raw.get('query_name') or e.raw.get('query', ''),
                'ja3': e.raw.get('ja3', ''),
                'sni': e.raw.get('sni') or e.raw.get('server_name') or '',
                'bytes_out': e.raw.get('bytes_out', 0),
                'packets': e.raw.get('packets', 0),
                'duration': e.raw.get('duration', 0),
            }
            try:
                ml_factors = _ml_pipeline.analyze_event(ev)
            except Exception:
                ml_factors = {}
            factor_names = []
            if isinstance(ml_factors, dict):
                factor_names = list(ml_factors.get('factors') or [])
            elif isinstance(ml_factors, list):
                factor_names = list(ml_factors)
            for mf in factor_names:
                out.append(FactorEmit(
                    name=str(mf or 'unknown'),
                    nodes=[f"ip:{ev['src_ip']}"] if ev['src_ip'] else ['aggregate:network'],
                    domain='network',
                    confidence=float(((ml_factors.get('details') or {}).get('beacon') or {}).get('confidence') or 0.5) if isinstance(ml_factors, dict) else 0.5,
                    ts=ev['timestamp'],
                ))
    return out
