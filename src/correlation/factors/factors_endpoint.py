from typing import List
from ..canonical_event import CanonicalEvent

try:
    from src.ml.endpoint_email_ml_pipeline import EndpointEmailMLPipeline as _EEMPL
    _endpoint_pipeline = _EEMPL()
except Exception:
    _endpoint_pipeline = None

try:
    from src.ml.endpoint_email_ml_pipeline import EndpointEmailMLPipeline as _EEMPL
    _endpoint_pipeline = _EEMPL()
except Exception:
    _endpoint_pipeline = None

class FactorEmit(dict):
    pass

def extract_endpoint_factors(events: List[CanonicalEvent]) -> List[FactorEmit]:
    out: List[FactorEmit] = []
    by_host = {}
    for e in events:
        if e.source_type != 'endpoint':
            continue
        by_host.setdefault(e.host or 'unknown', []).append(e)
    for host, lst in by_host.items():
        lst.sort(key=lambda x: x.timestamp)
        proc_counts = {}
        parent_anomaly = False
        persistence_hits = 0
        autorun_new = False
        for ev in lst:
            if ev.process:
                proc_counts[ev.process] = proc_counts.get(ev.process, 0) + 1
            if ev.raw.get('parent_process') and ev.raw.get('parent_process') in {'cmd.exe','powershell.exe'} and ev.process and ev.process.lower() in {'rundll32.exe','regsvr32.exe'}:
                parent_anomaly = True
            # persistence_registry_change heuristic: raw contains registry_change + run key markers
            if any(k in str(ev.raw).lower() for k in ['run\\', 'runonce', 'startup']) and 'registry_change' in str(ev.raw).lower():
                persistence_hits += 1
            # new_autorun_entry: raw contains autorun flag
            if 'autorun_entry' in str(ev.raw).lower():
                autorun_new = True
        if parent_anomaly:
            out.append(FactorEmit(name='unusual_parent_process', nodes=[f"host:{host}"], domain='endpoint', confidence=0.6, ts=lst[-1].timestamp))
        high_freq = [p for p,c in proc_counts.items() if c >= 5]
        if high_freq:
            out.append(FactorEmit(name='unsigned_binary_exec_high_freq', nodes=[f"host:{host}"], domain='endpoint', confidence=0.55, ts=lst[-1].timestamp))
        # living_off_the_land_tool_use simplistic: process name matches LOL tool list
        lol_tools = {'powershell.exe','wmic.exe','certutil.exe'}
        # ML-based endpoint detectors (process tree, persistence, advanced threats)
        if _endpoint_pipeline is not None:
            for ev in lst:
                ev_dict = {
                    'process': ev.process or '',
                    'parent_process': ev.raw.get('parent_process', '') if ev.raw else '',
                    'cmdline': ev.raw.get('cmdline') or ev.raw.get('command_line') or ev.raw.get('CommandLine', '') if ev.raw else '',
                    'process_depth': int(ev.raw.get('process_depth', 1)) if ev.raw else 1,
                    'time_since_boot': float(ev.raw.get('time_since_boot', 3600.0)) if ev.raw else 3600.0,
                    'persistence_mechanism': ev.raw.get('persistence_mechanism', '') if ev.raw else '',
                    'persistence_key': ev.raw.get('persistence_key', '') if ev.raw else '',
                    'host': host,
                    'ts': ev.timestamp,
                    'raw': ev.raw or {},
                }
                try:
                    ml_factors = _endpoint_pipeline.analyze_endpoint_event(ev_dict)
                except Exception:
                    ml_factors = []
                for mf in ml_factors:
                    out.append(FactorEmit(
                        name=mf.get('factor', 'unknown'),
                        nodes=[f"host:{host}"],
                        domain='endpoint',
                        confidence=mf.get('confidence', 0.5),
                        ts=ev.timestamp,
                    ))
        if any(ev.process and ev.process.lower() in lol_tools for ev in lst):
            out.append(FactorEmit(name='living_off_the_land_tool_use', nodes=[f"host:{host}"], domain='endpoint', confidence=0.58, ts=lst[-1].timestamp))
        if persistence_hits >= 1:
            out.append(FactorEmit(name='persistence_registry_change', nodes=[f"host:{host}"], domain='endpoint', confidence=0.62, ts=lst[-1].timestamp))
        if autorun_new:
            out.append(FactorEmit(name='new_autorun_entry', nodes=[f"host:{host}"], domain='endpoint', confidence=0.63, ts=lst[-1].timestamp))
        # ML-based endpoint detectors (process tree, persistence, advanced threats)
        if _endpoint_pipeline is not None:
            for ev in lst:
                ev_dict = {
                    'process': ev.process or '',
                    'parent_process': ev.raw.get('parent_process', '') if ev.raw else '',
                    'cmdline': ev.raw.get('cmdline') or ev.raw.get('command_line') or ev.raw.get('CommandLine', '') if ev.raw else '',
                    'process_depth': int(ev.raw.get('process_depth', 1)) if ev.raw else 1,
                    'time_since_boot': float(ev.raw.get('time_since_boot', 3600.0)) if ev.raw else 3600.0,
                    'persistence_mechanism': ev.raw.get('persistence_mechanism', '') if ev.raw else '',
                    'persistence_key': ev.raw.get('persistence_key', '') if ev.raw else '',
                    'host': host,
                    'ts': ev.timestamp,
                    'raw': ev.raw or {},
                }
                try:
                    ml_factors = _endpoint_pipeline.analyze_endpoint_event(ev_dict)
                except Exception:
                    ml_factors = []
                for mf in ml_factors:
                    out.append(FactorEmit(
                        name=mf.get('factor', 'unknown'),
                        nodes=[f"host:{host}"],
                        domain='endpoint',
                        confidence=mf.get('confidence', 0.5),
                        ts=ev.timestamp,
                    ))
    return out
