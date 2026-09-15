from __future__ import annotations

from .base import StageContext, StageResult

async def pcap_session_stage(event: dict, ctx: StageContext) -> StageResult:
    # Expect either raw bytes in 'pcap_blob' or a file path in 'pcap_path'
    pcap_bytes = None
    if event.get('pcap_blob'):
        pcap_bytes = event['pcap_blob']
    elif event.get('pcap_path'):
        try:
            with open(event['pcap_path'], 'rb') as fh:
                pcap_bytes = fh.read()
        except Exception:
            return StageResult(name='pcap_session', factors=[], confidence_delta=0.0, metadata={'error': 'pcap_read_failed'})
    else:
        return StageResult(name='pcap_session', factors=[], confidence_delta=0.0, metadata={'error': 'no_pcap'})

    try:
        from src.parsers.tcp_reassembly import reassemble_from_pcap_bytes
        flows = reassemble_from_pcap_bytes(pcap_bytes)
    except ImportError:
        return StageResult(name='pcap_session', factors=[], confidence_delta=0.0, metadata={'error': 'scapy_missing'})
    except Exception as exc:
        return StageResult(name='pcap_session', factors=[], confidence_delta=0.0, metadata={'error': str(exc)})

    # Publish minimal session nodes to HopGraph if available
    try:
        from core.graph.hopgraph_lite import get_graph
        g = get_graph()
        session_ids = []
        for i, f in enumerate(flows):
            node_id = f'pcap_session:{hash((f.src,f.sport,f.dst,f.dport,i))}'
            g.add_node(node_id, type='pcap_session', src=f.src, dst=f.dst, sport=f.sport, dport=f.dport, packets=len(f.packets))
            session_ids.append(node_id)
        metadata = {'pcap_sessions': session_ids}
    except Exception:
        metadata = {'pcap_sessions_count': len(flows)}

    # Emit a factor if large session or artifact suspected
    factors = []
    if len(flows) > 0:
        factors.append('pcap:session_reconstructed')
    return StageResult(name='pcap_session', factors=factors, confidence_delta=0.05, metadata=metadata)
