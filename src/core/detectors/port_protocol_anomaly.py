"""Detect uncommon ports or sudden shifts in protocol usage."""
from typing import Any, Dict, List

COMMON_PORTS = {80,443,22,53,123,445,3389}

def detect_port_protocol_anomalies(runtime: Any, uncommon_threshold: int = 10) -> List[Dict[str,Any]]:
    results: List[Dict[str,Any]] = []
    if runtime is None:
        return results
    try:
        flows = getattr(runtime, 'flows', None) or []
        port_counts = {}
        proto_counts = {}
        for f in flows:
            try:
                p = int(f.get('dst_port') or f.get('port') or 0)
                proto = f.get('proto') or f.get('protocol') or 'tcp'
                port_counts[p] = port_counts.get(p,0)+1
                proto_counts[proto] = proto_counts.get(proto,0)+1
            except Exception:
                continue
        # Uncommon ports by count
        uncommon = [p for p,c in port_counts.items() if p not in COMMON_PORTS and c >= uncommon_threshold]
        if uncommon:
            results.append({'factor':'port_uncommon_activity','ports':uncommon,'count':len(uncommon),'score':0.5,'reason':'uncommon ports with high counts','metadata':{'mitre':['T1043'],'stride':['repudiation']}})
        # Protocol shift: e.g., sudden jump in udp/tcp ratio. Simple heuristic
        total_proto = sum(proto_counts.values())
        if total_proto:
            udp_ratio = (proto_counts.get('udp',0)/total_proto)
            if udp_ratio > 0.7:
                results.append({'factor':'protocol_shift_udp_high','udp_ratio':round(udp_ratio,3),'score':0.4,'reason':'high UDP ratio observed','metadata':{'mitre':['T1041'],'stride':['data_leak']}})
    except Exception:
        pass
    return results
