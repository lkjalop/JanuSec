from typing import Any, Dict, List, Optional
import time

# Minimal PCAP parser skeleton: in real usage, use scapy or dpkt.
# Here we accept synthetic "packets" as dicts to keep tests hermetic.

def parse_packets(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in packets:
        out.append({
            "ts": p.get("ts") or int(time.time()),
            "src_ip": p.get("src_ip"),
            "dst_ip": p.get("dst_ip"),
            "src_port": p.get("src_port"),
            "dst_port": p.get("dst_port"),
            "proto": p.get("proto") or "TCP",
            "len": p.get("len"),
        })
    return out
