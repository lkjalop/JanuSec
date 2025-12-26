from __future__ import annotations

import math
import re
import time
from typing import Any, Dict, List

from .models import ArtifactObservation, FactorCategory

# Simple pattern libraries
LOLBINS = ['certutil','mshta','bitsadmin','wmic','rundll32','regsvr32','powershell','powershell_ise','installutil','plink']
TUNNEL_TOKENS = ['plink','ngrok','socat','stunnel','chisel']
MACRO_EXT = {'.docm','.xlsm','.pptm'}
SUSPICIOUS_DIRS = ['\\temp\\','/tmp/','\\appdata\\local\\temp','\\users\\public\\']
PACK_SECTION_NAMES = ['.upx','.aspack','.themida']

FACTOR_WEIGHTS = {
    'unsigned_binary': (FactorCategory.STATIC, 0.18, 'Unsigned executable or driver'),
    'compile_time_recent': (FactorCategory.STATIC, 0.08, 'Recent compile timestamp anomaly'),
    'high_entropy_section': (FactorCategory.STATIC, 0.10, 'Packed or encrypted section detected'),
    'macro_autoexec': (FactorCategory.MACRO, 0.16, 'Auto-executing macro present'),
    'macro_obfuscated': (FactorCategory.MACRO, 0.10, 'Obfuscated macro strings'),
    'pdf_embedded_js': (FactorCategory.MACRO, 0.14, 'PDF embedded JavaScript'),
    'script_encoded_block': (FactorCategory.SCRIPT, 0.14, 'Encoded command or block detected'),
    'script_obfuscation_high': (FactorCategory.SCRIPT, 0.12, 'High obfuscation score'),
    'lolbin_misuse': (FactorCategory.LOLBIN, 0.20, 'Living-off-the-land binary suspicious usage'),
    'tunneling_utility': (FactorCategory.LOLBIN, 0.18, 'Potential tunneling tool usage'),
    'fresh_download': (FactorCategory.ORIGIN, 0.12, 'Recently downloaded from internet zone'),
    'rapid_multi_host_appearance': (FactorCategory.TEMPORAL, 0.10, 'Propagated across hosts quickly'),
    'persistence_registry': (FactorCategory.PERSISTENCE, 0.12, 'Registry-based persistence attempt'),
    'scheduled_task_hidden': (FactorCategory.PERSISTENCE, 0.14, 'Hidden or anomalous scheduled task'),
    'wmi_persistence_consumer': (FactorCategory.PERSISTENCE, 0.14, 'WMI event consumer persistence'),
    'malicious_neighbor': (FactorCategory.RELATIONAL, 0.08, 'Adjacent to known malicious artifact'),
    'cluster_malicious_density_high': (FactorCategory.RELATIONAL, 0.06, 'Cluster has high malicious density'),
    'seen_good_stable': (FactorCategory.RELATIONAL, -0.08, 'Well-established benign history'),
    'rare_prevalence': (FactorCategory.TEMPORAL, 0.06, 'Artifact name extremely rare across fleet'),
    'emerging_multi_host': (FactorCategory.TEMPORAL, 0.08, 'Rapid emergent presence across hosts'),
    'vt_ratio_mid': (FactorCategory.REPUTATION, 0.12, 'Moderate VT positives'),
    'vt_ratio_high': (FactorCategory.REPUTATION, 0.25, 'High VT positives'),
    'reputation_unavailable': (FactorCategory.REPUTATION, 0.00, 'Reputation source unavailable'),
}

BASE64_RE = re.compile(r"(?i)(?:-enc\s+|encodedcommand\s+)?[A-Za-z0-9+/]{60,}={0,2}")
OBFUSCATION_TOKENS = ['`','^','%','${','||',';','&&']


def extract_static(obs: ArtifactObservation, meta: dict[str, Any]):
    (obs.path or '').lower()
    if obs.artifact_type in ('executable','driver'):
        if not meta.get('signed', True):
            add_factor(obs, 'unsigned_binary')
        if meta.get('compile_recent_anomaly'):
            add_factor(obs, 'compile_time_recent')
        if meta.get('entropy_high_section'):
            add_factor(obs, 'high_entropy_section')
    if obs.artifact_type == 'document':
        ext = (obs.path or '').lower()[-5:]
        if ext and any(obs.path.lower().endswith(m) for m in MACRO_EXT) and meta.get('macro_autoexec'):
            add_factor(obs,'macro_autoexec')
        if meta.get('macro_obfuscated'): add_factor(obs,'macro_obfuscated')
        if meta.get('pdf_embedded_js'): add_factor(obs,'pdf_embedded_js')


def extract_script(obs: ArtifactObservation, meta: dict[str, Any]):
    if obs.artifact_type == 'script' or (obs.path and any(obs.path.lower().endswith(e) for e in ['.ps1','.vbs','.js','.bat','.cmd'])):
        cmd = meta.get('command_line','') or ''
        if BASE64_RE.search(cmd):
            add_factor(obs,'script_encoded_block')
        # simple obfuscation score
        score = sum(cmd.count(t) for t in OBFUSCATION_TOKENS)
        if score >= 6:
            add_factor(obs,'script_obfuscation_high')


def extract_lolbin(obs: ArtifactObservation, meta: dict[str, Any]):
    name_l = (obs.name or '').lower()
    cmd = (meta.get('command_line') or '').lower()
    if any(lb in name_l for lb in LOLBINS) or any(lb in cmd for lb in LOLBINS):
        add_factor(obs,'lolbin_misuse')
    if any(t in cmd for t in TUNNEL_TOKENS):
        add_factor(obs,'tunneling_utility')


def extract_origin(obs: ArtifactObservation, meta: dict[str, Any]):
    if meta.get('zone_id') in (3,'3','internet') or meta.get('download_origin'):
        # fresh download if age < 24h
        age = time.time() - obs.first_seen
        if age < 86400:
            add_factor(obs,'fresh_download')


def extract_persistence(obs: ArtifactObservation, meta: dict[str, Any]):
    if meta.get('registry_autorun'): add_factor(obs,'persistence_registry')
    if meta.get('scheduled_task_hidden'): add_factor(obs,'scheduled_task_hidden')
    if meta.get('wmi_consumer'): add_factor(obs,'wmi_persistence_consumer')


def extract_relational(obs: ArtifactObservation):
    graph = obs.graph_context or {}
    if graph.get('malicious_neighbor'): add_factor(obs,'malicious_neighbor')
    if graph.get('cluster_malicious_density_high'): add_factor(obs,'cluster_malicious_density_high')
    if graph.get('seen_good_stable'): add_factor(obs,'seen_good_stable')
    if graph.get('rapid_multi_host_appearance'): add_factor(obs,'rapid_multi_host_appearance')
    if graph.get('rare_name'): add_factor(obs,'rare_prevalence')
    if graph.get('emerging_multi_host'): add_factor(obs,'emerging_multi_host')


def extract_reputation(obs: ArtifactObservation):
    rep = obs.reputation or {}
    ratio = rep.get('vt_ratio')
    if ratio is None and rep.get('unavailable'): add_factor(obs,'reputation_unavailable')
    if isinstance(ratio,(int,float)):
        if ratio >= 0.4 and ratio < 0.7: add_factor(obs,'vt_ratio_mid')
        if ratio >= 0.7: add_factor(obs,'vt_ratio_high')


def add_factor(obs: ArtifactObservation, name: str, details: dict[str, Any] | None = None):
    if name not in obs.factors:
        obs.factors.append(name)
        obs.factor_details[name] = details or {}


def compute_weighted_base(obs: ArtifactObservation) -> float:
    total = 0.0
    for f in obs.factors:
        meta = FACTOR_WEIGHTS.get(f)
        if not meta: continue
        total += meta[1]
    # clamp
    return min(1.0, max(0.0, total))


def run_all(obs: ArtifactObservation, meta: dict[str, Any]):
    extract_static(obs, meta)
    extract_script(obs, meta)
    extract_lolbin(obs, meta)
    extract_origin(obs, meta)
    extract_persistence(obs, meta)
    extract_relational(obs)
    extract_reputation(obs)
    obs.base_risk = compute_weighted_base(obs)
    return obs
