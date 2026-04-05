"""Simulate an attack by ingesting CSV artifacts into HopGraph and producing reports.

This script is intentionally deterministic and evidence-based: it reads CSVs under
`dump/` and uses `src.graph.ingest.ingest_event` to create HopGraph edges. It then
queries the HopGraph to build Tier 1 (concise) and Tier 2 (detailed) summaries and
generates persona-based reports for Executive, Analyst, and Threat Hunter personas.

Optional Ollama LLM enrichment: set `OLLAMA_HOST` env var (e.g. http://localhost:11434)
and `USE_OLLAMA=1` to send prompts to an Ollama Llama3:8b model. The script will also
work offline and synthesize Tiered summaries deterministically from extracted facts.
"""
from __future__ import annotations
import os
import csv
import json
import time
from pathlib import Path
from typing import List, Dict, Any

from src.graph.ingest import ingest_event
from src.graph.hopgraph import GLOBAL_HOPGRAPH

ROOT = Path(__file__).resolve().parent.parent
DUMP = ROOT / 'dump'


def load_csv(path: Path) -> List[Dict[str, str]]:
    out = []
    with path.open('r', encoding='utf-8') as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            out.append(r)
    return out


def ingest_all():
    # Network
    net = load_csv(DUMP / 'network.csv')
    for r in net:
        ev = {
            'src_ip': r.get('src_ip'),
            'dst_ip': r.get('dst_ip'),
            'dst_port': int(r.get('dst_port') or 0),
            'ts': float(r.get('ts') or time.time()),
        }
        ingest_event({'src_ip': ev['src_ip'], 'dst_ip': ev['dst_ip'], 'ts': ev['ts']}, source='sim_network')

    # Endpoint
    eps = load_csv(DUMP / 'endpoint.csv')
    for r in eps:
        ev = {
            'host': r.get('host'),
            'process': r.get('process'),
            'ts': float(r.get('ts') or time.time()),
        }
        ingest_event({'host': ev['host'], 'process': ev['process'], 'ts': ev['ts']}, source='sim_endpoint')

    # Email
    emails = load_csv(DUMP / 'email.csv')
    for r in emails:
        body = r.get('body') or ''
        url = None
        for token in body.split():
            if token.startswith('http://') or token.startswith('https://'):
                url = token
                break
        dst_ip = None
        host = None
        if url:
            try:
                host = url.split('://',1)[1].split('/',1)[0]
                if all(c.isdigit() or c=='.' for c in host):
                    dst_ip = host
            except Exception:
                host = None
        ev = {'src_host': r.get('from'), 'domain': host or r.get('from'), 'dst_ip': dst_ip, 'ts': float(r.get('ts') or time.time())}
        ingest_event(ev, source='sim_email')

    # EDR
    edrs = load_csv(DUMP / 'edr.csv')
    for r in edrs:
        ev = {
            'host': r.get('host'),
            'process': r.get('process'),
            'ts': float(r.get('ts') or time.time()),
            'file_hash': r.get('file_sha256')
        }
        ingest_event(ev, source='sim_edr')

    # C2 beacons
    c2s = load_csv(DUMP / 'c2.csv')
    for r in c2s:
        ev = {'src_ip': r.get('src_ip'), 'dst_ip': r.get('dst_ip'), 'ts': float(r.get('ts') or time.time())}
        ingest_event(ev, source='sim_c2')


def gather_evidence(start_node: str) -> Dict[str, Any]:
    # Use HopGraph explain_chain to build recon evidence
    chains = GLOBAL_HOPGRAPH.explain_chain(start_node, max_depth=4, top_k=5, beam_width=6)
    return chains


def format_tier1(evidence: Dict[str, Any]) -> str:
    # Short, high-level summary with verdict and recommended action
    chains = evidence.get('chains', [])
    if not chains:
        return 'No high-confidence chains found from start node.'
    top = chains[0]
    score = top.get('score', 0.0)
    length = top.get('length', 0)
    summary = f"Verdict: Likely compromise path found (score={score:.2f}, hops={length})."
    hints = []
    for hop in top.get('hops', [])[:3]:
        hints.append(f"{hop.get('src')} -> {hop.get('dst')} ({hop.get('etype')})")
    summary += '\nEvidence snippets: ' + '; '.join(hints)
    summary += '\nImmediate actions: Isolate host, block outbound to observed IPs, collect full EDR snapshot.'
    return summary


def format_tier2(evidence: Dict[str, Any]) -> str:
    # Detailed analyst-facing narrative with edge-level details and timestamps
    lines = []
    for ch in evidence.get('chains', []):
        lines.append(f"Chain score={ch.get('score',0):.3f}, hops={ch.get('length')}")
        for hop in ch.get('hops', []):
            lines.append(json.dumps({
                'src': hop.get('src'), 'dst': hop.get('dst'), 'etype': hop.get('etype'), 'ts': hop.get('timestamp'), 'weight': hop.get('weight')
            }))
        lines.append('')
    return '\n'.join(lines)


def persona_reports(tier1: str, tier2: str) -> Dict[str, str]:
    # Executive, Threat Hunter, Forensic Analyst
    exec_rep = f"Executive Summary:\n{tier1}\nKey Rationale: evidence-based chain scoring from HopGraph."
    hunter = f"Threat Hunter Brief:\n{tier2}\nHunt Next: pivot on host/process hashes and network egress to suspect IPs."
    forensic = f"Forensic Analyst Report:\n{tier2}\nArtifacts: request EDR, memory, file hashes. Timeline: reconstructed via HopGraph edges."
    return {'executive': exec_rep, 'hunter': hunter, 'forensic': forensic}


def maybe_ollama_prompt(prompt: str) -> str:
    use = os.getenv('USE_OLLAMA','0').lower() in {'1','true','yes'}
    host = os.getenv('OLLAMA_HOST')
    model = os.getenv('OLLAMA_MODEL','llama3:8b')
    if not use or not host:
        return prompt
    try:
        import requests
        endpoints = [
            '/api/generate',
            '/v1/generate',
            '/generate'
        ]
        headers = {'Content-Type': 'application/json'}
        body = {'model': model, 'prompt': prompt, 'max_tokens': 512}
        # Try non-stream first with reasonable timeout
        for ep in endpoints:
            url = host.rstrip('/') + ep
            try:
                r = requests.post(url, json=body, timeout=15)
                if r.status_code == 200:
                    # Try typical shapes
                    try:
                        j = r.json()
                        # Common: {'text': '...'} or {'result':'...'} or {'choices':[{'text':...}]}
                        if isinstance(j, dict):
                            if 'text' in j and j['text']:
                                return j['text']
                            if 'result' in j and j['result']:
                                return j['result']
                            if 'choices' in j and isinstance(j['choices'], list) and j['choices']:
                                c = j['choices'][0]
                                if isinstance(c, dict) and 'text' in c:
                                    return c['text']
                        # Fallback to raw text
                        return r.text or prompt
                    except Exception:
                        return r.text or prompt
                # 404 or other code => try next
            except requests.exceptions.ReadTimeout:
                # Server may be streaming; try streaming mode
                try:
                    rs = requests.post(url, json=body, stream=True, timeout=(3,60))
                    collected = []
                    try:
                        for chunk in rs.iter_content(decode_unicode=True, chunk_size=1024):
                            if not chunk:
                                continue
                            collected.append(chunk)
                            text = ''.join(collected)
                            # Try to extract JSON chunk with text
                            try:
                                import re
                                # find JSON objects in stream
                                objs = re.findall(r"\{.*?\}", text, flags=re.S)
                                for o in objs[::-1]:
                                    try:
                                        jj = json.loads(o)
                                        if isinstance(jj, dict) and 'text' in jj:
                                            return jj['text']
                                    except Exception:
                                        continue
                            except Exception:
                                pass
                        # If stream ended, return concatenated
                        return ''.join(collected) or prompt
                    finally:
                        try: rs.close()
                        except Exception: pass
                except Exception:
                    pass
        # If all endpoints fail, return original
    except Exception:
        pass
    return prompt


def main():
    ingest_all()

    # Choose a start node likely to be compromised: prefer 'proc:' (ingest_event uses 'proc:'), fall back to 'process:'
    candidates = ['proc:evilproc', 'process:evilproc', 'process:evilproc:4321']
    start = None
    for c in candidates:
        if c in GLOBAL_HOPGRAPH.nodes:
            start = c; break
    if start is None:
        # fallback: pick any process-like node
        for n in GLOBAL_HOPGRAPH.nodes.keys():
            if isinstance(n, str) and n.startswith('proc:'):
                start = n; break
    if start is None:
        start = 'proc:evilproc'
    evidence = gather_evidence(start)

    tier1 = format_tier1(evidence)
    tier2 = format_tier2(evidence)

    # Optionally refine with Ollama
    tier1_refined = maybe_ollama_prompt(tier1)
    tier2_refined = maybe_ollama_prompt(tier2)

    reports = persona_reports(tier1_refined, tier2_refined)

    outdir = ROOT / 'sim_reports'
    outdir.mkdir(exist_ok=True)
    (outdir / 'tier1.txt').write_text(tier1_refined, encoding='utf-8')
    (outdir / 'tier2.txt').write_text(tier2_refined, encoding='utf-8')
    (outdir / 'executive.txt').write_text(reports['executive'], encoding='utf-8')
    (outdir / 'hunter.txt').write_text(reports['hunter'], encoding='utf-8')
    (outdir / 'forensic.txt').write_text(reports['forensic'], encoding='utf-8')

    print('Reports written to', outdir)


if __name__ == '__main__':
    main()
