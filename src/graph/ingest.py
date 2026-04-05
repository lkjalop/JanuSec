"""Event -> HopGraph ingestion utility.

Creates lightweight provenance edges for multi-hop tracing:
 - host:<hostname> -> ip:<dst_ip>   (etype: conn)
 - ip:<dst_ip> -> domain:<domain>   (etype: dns / http)
 - proc:<process> -> host:<hostname> (etype: proc_host)

Idempotency: duplicate edges are allowed (kept simple); callers can future-opt dedupe.
"""
from __future__ import annotations
from typing import Dict, Optional
from graph.unified import UG  # type: ignore
import time


def ingest_event(event: Dict, source: str = 'event') -> None:
    try:
        host = (event.get('src_host') or event.get('source_host') or event.get('host') or '').strip().lower()
        dst_ip = (event.get('dst_ip') or event.get('destination_ip') or event.get('server_ip') or '').strip()
        domain = (event.get('domain') or event.get('host') or event.get('hostname') or event.get('sni') or '').strip().lower()
        process = (event.get('process') or event.get('proc_name') or '').strip().lower()
        ts = float(event.get('ts') or time.time())
        if host and dst_ip:
            UG.add_edge(f'host:{host}', f'ip:{dst_ip}', 'conn', source=source, ts=ts)
        if dst_ip and domain and domain not in dst_ip:
            # Domain relation – prefer HTTP host or DNS query semantics
            et = 'http' if event.get('http_method') or event.get('http_headers') else 'dns'
            UG.add_edge(f'ip:{dst_ip}', f'domain:{domain}', et, source=source, ts=ts)
        if process and host:
            UG.add_edge(f'proc:{process}', f'host:{host}', 'proc_host', source=source, ts=ts)
    except Exception:
        # Swallow ingestion issues (non-critical path)
        pass

def ingest_portscan_event(src_ip: str, dst_ip: str, dst_port: int, mode: str = 'unknown', ts: Optional[float] = None, source: str = 'network_hunter') -> None:
    """Create a lightweight PortScanEvent node and temporal PRECEDES edges.

    - Adds `ip:<src_ip>` -> `portscan:<dst_ip>:<dst_port>` with etype `portscan`.
    - Adds `portscan:<dst_ip>:<dst_port>` -> `ip:<dst_ip>` with etype `precedes` (kill-chain ordering).
    - `mode` is one of {'horizontal','vertical','unknown'} and is stored as an attribute.
    """
    try:
        ts = float(ts or time.time())
        scan_node = f"portscan:{dst_ip}:{dst_port}"
        UG.add_edge(f"ip:{src_ip}", scan_node, 'portscan', source=source, ts=ts, attrs={'mode': mode})
        # Temporal ordering and discovery semantics
        UG.add_edge(scan_node, f"ip:{dst_ip}", 'precedes', source=source, ts=ts, attrs={'mode': mode})
        UG.add_edge(scan_node, f"ip:{dst_ip}", 'discovers', source=source, ts=ts, attrs={'mode': mode})
    except Exception:
        # Best-effort only; do not fail caller
        pass

__all__ = ['ingest_event','ingest_portscan_event']
def ingest_recon_event(actor: str, target: str, technique: str, target_type: str = 'ip', ts: Optional[float] = None, source: str = 'recon') -> None:
    """Create a lightweight ReconEvent node and temporal PRECEDES edges.

    - Adds `ip:<actor>` or `host:<actor>` -> `recon:<technique>:<target>` with etype `recon`.
    - Adds `recon:<technique>:<target>` -> `<target_type>:<target>` with etype `precedes` (kill-chain ordering).
    - `target_type` is one of {'ip','domain','host','proc'}.
    """
    try:
        ts = float(ts or time.time())
        recon_node = f"recon:{technique}:{target}"
        # naive actor typing: treat dotted numeric as IP, else host
        actor_key = 'ip' if any(ch.isdigit() for ch in actor) and '.' in actor else 'host'
        UG.add_edge(f"{actor_key}:{actor}", recon_node, 'recon', source=source, ts=ts, attrs={'technique': technique})
        # link to target
        target_key = target_type if target_type in {'ip','domain','host','proc'} else 'ip'
        UG.add_edge(recon_node, f"{target_key}:{target}", 'precedes', source=source, ts=ts, attrs={'technique': technique})
        UG.add_edge(recon_node, f"{target_key}:{target}", 'discovers', source=source, ts=ts, attrs={'technique': technique})
    except Exception:
        # Best-effort only; do not fail caller
        pass

__all__ = ['ingest_event','ingest_portscan_event','ingest_recon_event']
