"""Detect files where content signature mismatches reported metadata or known signature DB.

This detector inspects runtime file analysis entries (each file dict should include
`sha256`, `reported_name`, `pe_info.signature` etc.). For demo, we flag when
`reported_name` extension doesn't match PE magic or when declared signer missing but strong heuristics.
"""
from typing import Any, Dict, List
import binascii

def detect_file_signature_mismatch(runtime: Any, files: List[Dict[str,Any]] = None) -> List[Dict[str,Any]]:
    results: List[Dict[str,Any]] = []
    if files is None:
        # try runtime-provided file analysis
        try:
            files = getattr(runtime, 'recent_files', None) or []
        except Exception:
            files = []
    for f in (files or []):
        try:
            sha = str(f.get('sha256') or f.get('sha1') or f.get('md5') or '')
            name = str(f.get('reported_name') or f.get('name') or '')
            pe = f.get('pe_info') or {}
            # heuristics: if reported name endswith .exe but pe_info.maybe_pe is false -> mismatch
            maybe_pe = bool(pe.get('is_pe'))
            if name.lower().endswith('.exe') and not maybe_pe:
                results.append({'factor':'file_signature_mismatch','sha256':sha,'reported_name':name,'score':0.8,'reason':'filename suggests PE but content not PE','metadata':{'mitre':['T1036'],'stride':['tampering']}})
            # if pe signature present but signer empty -> suspicious
            signer = pe.get('signer')
            if maybe_pe and (signer is None or signer == '' ): 
                results.append({'factor':'file_unsigned_suspicious','sha256':sha,'reported_name':name,'score':0.45,'reason':'PE binary unsigned or missing signer','metadata':{'mitre':['T1553'],'stride':['tampering']}})
        except Exception:
            pass
    return results
