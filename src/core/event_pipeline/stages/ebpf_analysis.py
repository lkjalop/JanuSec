from __future__ import annotations

from typing import Any
import time
from pathlib import Path
import yaml

from .base import StageContext, StageResult, timed_stage
from src.integrations.bgp_client import CLIENT as BGP_CLIENT
from src.integrations.sbom import GLOBAL_SBOM
from src.core.graph.hopgraph_lite import get_graph
import hashlib
import os
import collections
import json


@timed_stage('ebpf_analysis')
async def ebpf_analysis_stage(event: dict[str, Any], ctx: StageContext) -> StageResult:
    """Analyze eBPF (Falco) container runtime events and emit factors.

    This stage is no-op for non-eBPF events.
    """
    # quick no-op for non-falco events
    if (event.get('source') or '') != 'falco_ebpf':
        return StageResult(name='ebpf_analysis', factors=[])

    factors: list[str] = []
    enrichment: dict[str, Any] = {}

    # Container escape heuristics
    cmd = (event.get('command') or event.get('cmdline') or '')
    if isinstance(cmd, str) and any(x in cmd.lower() for x in ('nsenter', 'unshare', 'mount ', '/proc/', 'cap_sys_admin')):
        factors.append('ebpf:container_escape')
    if isinstance(cmd, str) and any(x in cmd.lower() for x in ('/etc/passwd', '/etc/shadow', 'useradd', 'adduser', 'crontab', 'systemctl', 'authorized_keys')):
        factors.append('ebpf:priv_escalation')

    # Syscall anomaly and histograms with decaying baseline
    cid = event.get('container_id') or ''
    sc = event.get('syscall') or ''
    now_ts = time.time()
    if cid and sc:
        # maintain a dict of syscall -> last_seen timestamp per container
        tstore: dict[str, dict[str, float]] = ctx.state.setdefault('_ebpf_syscall_last_seen', {})  # type: ignore[assignment]
        last_seen = tstore.setdefault(str(cid), {})
        # decay window (seconds) - older entries become less trusted
        DECAY_HALF_LIFE = 60.0 * 60.0  # 1 hour half-life by default
        anomaly = False
        if sc not in last_seen and len(last_seen) > 0:
            anomaly = True
        else:
            # if seen long ago (>> half-life) treat as new
            prev = last_seen.get(sc)
            if prev is None:
                anomaly = False
            else:
                # if last seen older than 24h, consider anomaly
                if now_ts - float(prev) > 24 * 3600:
                    anomaly = True
        # update last seen
        last_seen[sc] = now_ts
        if anomaly:
            factors.append('ebpf:syscall_anomaly')
        # maintain histogram counters as before
        hstore: dict[str, collections.Counter] = ctx.state.setdefault('_ebpf_syscall_hist', {})  # type: ignore[assignment]
        hist: collections.Counter = hstore.setdefault(str(cid), collections.Counter())
        hist[sc] += 1

    # Enrichment: provenance and process metadata
    enrichment['collector_timestamp'] = event.get('time') or event.get('ts') or None
    enrichment['host_id'] = event.get('host') or event.get('hostname') or event.get('agent_host')
    enrichment['pid'] = event.get('pid') or event.get('process_pid')
    enrichment['ppid'] = event.get('ppid') or event.get('process_ppid')
    enrichment['process_name'] = event.get('process_name') or event.get('proc_name')
    enrichment['cmdline'] = cmd
    exe_path = event.get('exe') or event.get('process_path') or event.get('proc_path')
    enrichment['exe_path'] = exe_path
    # binary sha256 if local file exists
    if exe_path and os.path.exists(exe_path):
        try:
            h = hashlib.sha256()
            with open(exe_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            enrichment['binary_sha256'] = h.hexdigest()
        except Exception:
            enrichment['binary_sha256'] = None

    ancestry = ctx.state.get('_proc_ancestry', {}) if ctx and hasattr(ctx, 'state') else {}
    enrichment['parent_chain'] = ancestry.get(enrichment.get('pid')) if ancestry else None

    enrichment['local_ip'] = event.get('local_ip') or event.get('src_ip') or event.get('local')
    enrichment['remote_ip'] = event.get('remote_ip') or event.get('dst_ip') or event.get('remote')
    enrichment['container_id'] = cid
    enrichment['container_image'] = event.get('container_image') or event.get('image')
    enrichment['kubernetes_pod'] = event.get('k8s_pod') or event.get('pod_name')
    enrichment['kubernetes_namespace'] = event.get('k8s_ns') or event.get('pod_ns')

    # BGP enrich for remote
    rip = enrichment.get('remote_ip')
    if rip:
        try:
            enrichment['remote_asn'] = BGP_CLIENT.get_asn(rip)
            enrichment['remote_prefix'] = BGP_CLIENT.get_prefix_for_ip(rip)
        except Exception:
            enrichment['remote_asn'] = None
            enrichment['remote_prefix'] = None

    # TLS / DNS
    tls = event.get('tls') or {}
    if isinstance(tls, dict):
        enrichment['tls_server_name'] = tls.get('server_name') or tls.get('sni')
        if tls.get('fingerprint'):
            enrichment['tls_fingerprint'] = tls.get('fingerprint')
    dns = event.get('dns') or {}
    if isinstance(dns, dict):
        enrichment['dns_qname'] = dns.get('query') or dns.get('qname')
        enrichment['dns_answers'] = dns.get('answers')

    # attach syscall hist snapshot
    hstore = ctx.state.get('_ebpf_syscall_hist', {}) if ctx and hasattr(ctx, 'state') else {}
    if cid and hstore.get(str(cid)):
        enrichment['syscall_histogram'] = dict(hstore.get(str(cid)).most_common(10))

    # SBOM lookup
    bhash = enrichment.get('binary_sha256')
    if bhash:
        try:
            sb = GLOBAL_SBOM.lookup_binary(bhash)
            enrichment['sbom_components'] = sb.get('components', [])
            enrichment['sbom_cves'] = sb.get('cves', [])
            enrichment['cve_summary'] = []
            for c in enrichment['sbom_cves']:
                try:
                    enrichment['cve_summary'].append({
                        'cve': c.get('cve'),
                        'cvss': float(c.get('cvss')) if c.get('cvss') is not None else None,
                        'kev': bool(c.get('kev')) if c.get('kev') is not None else False,
                        'epss': float(c.get('epss')) if c.get('epss') is not None else None,
                    })
                except Exception:
                    pass
        except Exception:
            pass

    # Map Falco rule to technique tags if present, using mapping file
    rule = (event.get('rule_name') or '')
    if isinstance(rule, str) and rule:
        safe_rule = rule.replace(' ', '_')[:64]
        factors.append(f"falco_event:{safe_rule}")
        # keep backward-compatible factor name expected by tests/UI
        factors.append(f"falco_rule:{safe_rule}")
        try:
            # load mapping once
            _MAP_PATH = Path(__file__).resolve().parents[3] / 'data' / 'falco_to_mitre.yaml'
            if _MAP_PATH.exists():
                mapping = yaml.safe_load(_MAP_PATH.read_text(encoding='utf-8')) or {}
                rl = rule.lower()
                for k, v in mapping.items():
                    for frag in v.get('match', []):
                        if frag in rl:
                            for f in v.get('factors', []):
                                if f not in factors:
                                    factors.append(f)
                            for m in v.get('mitre', []):
                                if m and not any(x.startswith('mitre:') for x in factors):
                                    factors.append(f'mitre:{m}')
        except Exception:
            # best-effort fallback to simple heuristics
            rl = rule.lower()
            if 'shell' in rl or 'spawn' in rl or 'exec' in rl:
                factors.append('mitre:T1059')
            if 'sensitive file' in rl or '/etc/passwd' in rl:
                factors.append('mitre:T1555')

    # attach process ancestry from shared state if available (proc_ancestry or _proc_ancestry)
    ancestry = ctx.state.get('proc_ancestry') or ctx.state.get('_proc_ancestry') or {}
    if ancestry and enrichment.get('pid') and enrichment.get('pid') in ancestry:
        enrichment['parent_chain'] = ancestry.get(enrichment.get('pid'))

    # Best-effort: persist lightweight graph nodes/edges into HopGraph-lite
    try:
        graph_evt: dict[str, object] = {}
        host_id = enrichment.get('host_id') or enrichment.get('hostname') or ''
        if host_id:
            graph_evt['host'] = host_id
        # use process name or cmdline as proc identifier
        proc = enrichment.get('process_name') or enrichment.get('proc_name') or enrichment.get('cmdline') or enrichment.get('exe_path')
        if proc:
            graph_evt['proc'] = proc
        # container id is useful as an infrastructure node when host missing
        cid = enrichment.get('container_id') or enrichment.get('container_image') or ''
        if cid and not host_id:
            graph_evt['host'] = f'container:{cid}'
        # annotate edge type when we have network vs proc clues
        graph_evt['edge_type'] = 'proc'
        # include user if present on event
        if event.get('user'):
            graph_evt['user'] = event.get('user')
        # push into hopgraph (will persist via backend if enabled)
        try:
            get_graph().observe(graph_evt)
        except Exception:
            # non-fatal; HopGraph optional persistence
            pass
    except Exception:
        pass

    return StageResult(name='ebpf_analysis', factors=factors, metadata=enrichment)
