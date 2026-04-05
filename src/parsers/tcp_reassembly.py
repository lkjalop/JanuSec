"""Lightweight TCP reassembly helper.

Provides best-effort flow grouping from PCAP bytes. Prefers `dpkt` for
performance; falls back to `scapy` if dpkt is not available. Raises
ImportError when no parser is available.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple
import io


@dataclass
class TCPFlow:
    src: str
    sport: int
    dst: str
    dport: int
    proto: str
    packets: List[bytes]


def reassemble_from_pcap_bytes(pcap_bytes: bytes) -> List[TCPFlow]:
    """Lightweight TCP reassembly helper.

    Provides best-effort flow grouping from PCAP bytes. Prefers `dpkt` for
    performance; falls back to `scapy` if dpkt is not available. Returns a
    list of TCPFlow objects containing application payload fragments in order.
    """
    from __future__ import annotations

    from dataclasses import dataclass
    from typing import Dict, List, Tuple
    import io


    @dataclass
    class TCPFlow:
        src: str
        sport: int
        dst: str
        dport: int
        proto: str
        packets: List[bytes]


    def reassemble_from_pcap_bytes(pcap_bytes: bytes) -> List[TCPFlow]:
        """Reassemble TCP streams from raw pcap bytes.

        Tries to use dpkt for speed; falls back to scapy if dpkt is not
        installed. Returns a list of TCPFlow with concatenated payloads per
        4-tuple.
        """
        # Attempt dpkt
        try:
            import dpkt  # type: ignore
            import socket
        except Exception:
            dpkt = None

        flows: Dict[Tuple[str, int, str, int], TCPFlow] = {}

        if dpkt is not None:
            try:
                bio = io.BytesIO(pcap_bytes)
                pcap = dpkt.pcap.Reader(bio)
                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        ip = eth.data
                        if not hasattr(ip, 'p'):
                            continue
                        # IPv4 only for now
                        if getattr(ip, 'p', None) != dpkt.ip.IP_PROTO_TCP:
                            continue
                        tcp = ip.data
                        src = socket.inet_ntoa(getattr(ip, 'src', b'') or b'0.0.0.0')
                        dst = socket.inet_ntoa(getattr(ip, 'dst', b'') or b'0.0.0.0')
                        key = (src, tcp.sport, dst, tcp.dport)
                        data = bytes(getattr(tcp, 'data', b'') or b'')
                        if key not in flows:
                            flows[key] = TCPFlow(src=src, sport=int(tcp.sport), dst=dst, dport=int(tcp.dport), proto='tcp', packets=[])
                        if data:
                            flows[key].packets.append(data)
                    except Exception:
                        continue
                return list(flows.values())
            except Exception:
                # Fall back to scapy
                pass

        # Fallback: scapy-based parsing
        try:
            from scapy.all import RawPcapReader, Ether, IP, TCP  # type: ignore
        except Exception as exc:
            raise ImportError('No pcap parser available (install dpkt or scapy)') from exc

        for pkt_data, meta in RawPcapReader(io.BytesIO(pcap_bytes)):
            try:
                packet = Ether(pkt_data)
                if not packet.haslayer(IP) or not packet.haslayer(TCP):
                    continue
                ip = packet[IP]
                tcp = packet[TCP]
                key = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
                data = bytes(tcp.payload or b'')
                if key not in flows:
                    flows[key] = TCPFlow(src=ip.src, sport=int(tcp.sport), dst=ip.dst, dport=int(tcp.dport), proto='tcp', packets=[])
                if data:
                    flows[key].packets.append(data)
            except Exception:
                continue

        return list(flows.values())