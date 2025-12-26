"""SBOM Execution Mapping Repository

Links observed process image hashes to SBOM components and detects hash drift.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from typing import Dict, Optional, Tuple


@dataclass
class ExecComponentLink:
    component_key: str
    sbom_hashes: dict[str,str]
    first_seen: float
    last_seen: float
    drift: bool = False

class SBOMExecutionRepository:
    def __init__(self, persist_path: str = 'artifacts/state/sbom_exec.json'):
        self._lock = threading.Lock()
        # (tenant, file_hash_sha256) -> ExecComponentLink
        self._hash_map: dict[tuple[str,str], ExecComponentLink] = {}
        # component_key -> known canonical hashes (union over SBOM)
        self._component_hash_index: dict[str, dict[str,str]] = {}
        self._persist_path = persist_path
        self._dirty = False
        self._load()

    def register_sbom_component(self, tenant: str, name: str, version: str | None, hashes: dict[str,str]):
        name_norm = (name or '').lower()
        version_norm = (version or 'unknown').lower()
        key = f"{name_norm}:{version_norm}"
        with self._lock:
            entry = self._component_hash_index.setdefault(key, {})
            for alg, h in hashes.items():
                if alg not in entry:
                    entry[alg] = h
            self._dirty = True

    def _resolve_component_key(self, image_name: str | None, component_guess: str | None) -> str | None:
        if component_guess:
            return component_guess.lower()
        if not image_name:
            return None
        name_norm = image_name.lower()
        base = name_norm.rsplit('.', 1)[0] if '.' in name_norm else name_norm
        for candidate in (f"{name_norm}:unknown", f"{base}:unknown"):
            hashes = self._component_hash_index.get(candidate)
            if hashes:
                return candidate
        preferred = None
        for candidate in self._component_hash_index.keys():
            if candidate.startswith(f"{base}:") and self._component_hash_index.get(candidate):
                return candidate
            if candidate.startswith(f"{base}:") and preferred is None:
                preferred = candidate
            if candidate.startswith(f"{name_norm}:") and self._component_hash_index.get(candidate):
                return candidate
            if candidate.startswith(f"{name_norm}:") and preferred is None:
                preferred = candidate
        if preferred:
            return preferred
        return f"{base}:unknown"

    def observe_execution(self, tenant: str, file_hash: str, image_name: str, component_guess: str | None = None) -> dict[str,object]:
        now = time.time()
        key = (tenant, file_hash)
        drift = False
        with self._lock:
            comp_key = self._resolve_component_key(image_name, component_guess)
            if comp_key:
                self._component_hash_index.setdefault(comp_key, {})
            link = self._hash_map.get(key)
            if not link:
                hashes = self._component_hash_index.get(comp_key or '', {})
                link = ExecComponentLink(component_key=comp_key or 'unknown', sbom_hashes=hashes, first_seen=now, last_seen=now)
                self._hash_map[key] = link
            else:
                link.last_seen = now
                if comp_key and link.component_key != comp_key:
                    link.component_key = comp_key
            if comp_key and self._component_hash_index.get(comp_key):
                expected_hashes = self._component_hash_index[comp_key]
                expected_sha256 = expected_hashes.get('sha-256') or expected_hashes.get('sha256')
                if expected_sha256 and expected_sha256.lower() != file_hash.lower():
                    link.drift = True
                    drift = True
            self._dirty = True
        return {
            'component_key': link.component_key,
            'drift': drift,
            'first_seen': link.first_seen,
            'last_seen': link.last_seen
        }

    def _load(self):
        try:
            if not os.path.exists(self._persist_path):
                return
            with open(self._persist_path,encoding='utf-8') as f:
                wrapper = json.load(f)
            data = wrapper.get('payload', wrapper)
            expected = wrapper.get('sha256')
            try:
                import hashlib
                import json as _json
                calc = hashlib.sha256(json.dumps(data, sort_keys=True).encode('utf-8')).hexdigest()
                if expected and calc != expected:
                    return  # integrity failure; skip load silently
            except Exception:
                pass
            comps = data.get('component_hash_index',{})
            hashes = data.get('hash_map',{})
            for k,v in comps.items():
                self._component_hash_index[k] = v
            for k,v in hashes.items():
                tenant, file_hash = k.split('|||',1)
                self._hash_map[(tenant,file_hash)] = ExecComponentLink(**v)
        except Exception:
            pass

    def _save(self):
        if not self._dirty:
            return
        try:
            os.makedirs(os.path.dirname(self._persist_path), exist_ok=True)
            serial_hash_map = { f"{t}|||{h}": asdict(v) for (t,h),v in self._hash_map.items() }
            blob = {
                'component_hash_index': self._component_hash_index,
                'hash_map': serial_hash_map,
                'saved_at': time.time()
            }
            raw = json.dumps(blob, sort_keys=True).encode('utf-8')
            digest = hashlib.sha256(raw).hexdigest()
            wrapper = {'payload': blob, 'sha256': digest}
            with open(self._persist_path,'w',encoding='utf-8') as f:
                json.dump(wrapper, f)
            self._dirty = False
        except Exception:
            pass

    def flush(self):
        with self._lock:
            self._save()

_sbom_exec_singleton: SBOMExecutionRepository | None = None

def get_sbom_exec_repo() -> SBOMExecutionRepository:
    global _sbom_exec_singleton
    if _sbom_exec_singleton is None:
        _sbom_exec_singleton = SBOMExecutionRepository()
    return _sbom_exec_singleton
