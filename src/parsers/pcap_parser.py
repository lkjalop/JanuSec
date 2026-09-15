from __future__ import annotations

from typing import Any, Dict, List

def parse_pcap_bytes(content: bytes, max_packets: int = 100000) -> dict[str, Any]:
    """Best-effort parser: prefer dpkt for speed, fallback to scapy.
    Returns {flows:[], dns:[], tls:[]} with minimal fields.
    """
    try:
        import dpkt  # type: ignore
        import socket
        flows: list[dict[str, Any]] = []
        dns_rows: list[dict[str, Any]] = []
        tls_rows: list[dict[str, Any]] = []
        n = 0
        for ts, buf in dpkt.pcap.Reader(iter([content])).__iter__():  # type: ignore
            n += 1
            if n > max_packets:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not hasattr(ip, 'p'):
                    continue
                src = socket.inet_ntoa(ip.src) if isinstance(ip.src, (bytes, bytearray)) else ''
                dst = socket.inet_ntoa(ip.dst) if isinstance(ip.dst, (bytes, bytearray)) else ''
                proto = getattr(ip, 'p', 0)
                l4 = ip.data
                sport = getattr(l4, 'sport', None)
                dport = getattr(l4, 'dport', None)
                flows.append({'ts': ts, 'src': src, 'dst': dst, 'sport': sport, 'dport': dport, 'proto': proto})
                # DNS (udp/53)
                if proto == 17 and (sport == 53 or dport == 53):
                    try:
                        import dpkt.dns as _dns  # type: ignore
                        d = _dns.DNS(l4.data)
                        qnames = [q.name for q in d.qd] if getattr(d, 'qd', None) else []
                        dns_rows.append({'ts': ts, 'src': src, 'dst': dst, 'qnames': qnames})
                    except Exception:
                        pass
                # TLS SNI (tcp/443)
                if proto == 6 and (sport == 443 or dport == 443):
                    try:
                        from src.parsers.tls_helpers import parse_tls_client_hello  # type: ignore
                        raw = bytes(l4.data) if hasattr(l4,'data') else (l4.data if isinstance(l4.data, (bytes, bytearray)) else b'')
                        sni, ja3, ja4 = parse_tls_client_hello(raw)
                        if sni or ja3 or ja4:
                            tls_rows.append({'ts': ts, 'src': src, 'dst': dst, 'sni': sni, 'ja3': ja3, 'ja4': ja4})
                    except Exception:
                        pass
            except Exception:
                continue
        return {'flows': flows, 'dns': dns_rows, 'tls': tls_rows}
    except Exception:
        # Fallback to scapy if available
        try:
            from scapy.all import RawPcapReader, TCP, UDP, IP  # type: ignore
            flows: list[dict[str, Any]] = []
            dns_rows: list[dict[str, Any]] = []
            tls_rows: list[dict[str, Any]] = []
            n = 0
            for pkt_data, pkt_meta in RawPcapReader(content):  # type: ignore
                n += 1
                if n > max_packets:
                    break
                try:
                    ip = IP(pkt_data)
                    src = ip.src
                    dst = ip.dst
                    proto = int(ip.proto)
                    sport = getattr(ip.payload, 'sport', None)
                    dport = getattr(ip.payload, 'dport', None)
                    flows.append({'ts': float(pkt_meta.sec)+pkt_meta.usec/1e6 if hasattr(pkt_meta,'sec') else 0.0, 'src': src, 'dst': dst, 'sport': sport, 'dport': dport, 'proto': proto})
                    if UDP in ip and (sport == 53 or dport == 53):
                        # lightweight; full DNS parse omitted here for perf
                        dns_rows.append({'ts': flows[-1]['ts'], 'src': src, 'dst': dst, 'qnames': []})
                    if TCP in ip and (sport == 443 or dport == 443):
                        from .tls_helpers import parse_tls_client_hello  # type: ignore
                        raw = bytes(ip[TCP].payload) if hasattr(ip[TCP],'payload') else b''
                        sni, ja3, ja4 = parse_tls_client_hello(raw)
                        if sni or ja3 or ja4:
                            tls_rows.append({'ts': flows[-1]['ts'], 'src': src, 'dst': dst, 'sni': sni, 'ja3': ja3, 'ja4': ja4})
                except Exception:
                    continue
            return {'flows': flows, 'dns': dns_rows, 'tls': tls_rows}
        except Exception:
            raise
