"""Normalization utilities for multi-source events.

Functions here canonicalize field values before HopGraph ingestion.
"""
from __future__ import annotations
import re

_PROC_SUFFIX_RE = re.compile(r"(_[0-9]+)+$")

def normalize_process(name: str | None) -> str | None:
    if not name:
        return None
    base = name.strip().lower()
    # strip synthetic suffixes added by generators (e.g. cmd.exe_1_2)
    base = _PROC_SUFFIX_RE.sub("", base)
    return base

def normalize_host(host: str | None) -> str | None:
    if not host:
        return None
    return host.strip().lower()

def normalize_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    d = domain.strip().lower()
    # collapse www.
    if d.startswith("www."):
        d = d[4:]
    return d

def normalize_hash(h: str | None) -> str | None:
    if not h:
        return None
    return h.strip().lower()

def normalize_event(ev: dict) -> dict:
    # mutate copy
    out = dict(ev)
    if 'process' in out:
        out['process'] = normalize_process(out.get('process'))
    if 'host' in out:
        out['host'] = normalize_host(out.get('host'))
    if 'qname' in out:
        out['qname'] = normalize_domain(out.get('qname'))
    if 'dst_domain' in out:
        out['dst_domain'] = normalize_domain(out.get('dst_domain'))
    if 'sha256' in out:
        out['file_hash'] = normalize_hash(out.get('sha256'))
    if 'file_hash' in out:
        out['file_hash'] = normalize_hash(out.get('file_hash'))
    return out
