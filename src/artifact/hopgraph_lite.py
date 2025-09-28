from __future__ import annotations
from typing import Dict, Set, Tuple, Any, List
import time, threading, math
from .models import ArtifactObservation

class HopGraphLite:
    def __init__(self, retention_seconds: int = 86400, benign_stable_ratio: float = 0.9, malicious_density_threshold: float = 0.25):
        self.retention = retention_seconds
        self.benign_stable_ratio = benign_stable_ratio
        self.malicious_density_threshold = malicious_density_threshold
        self._lock = threading.RLock()
        self.hash_history: Dict[str, Dict[str, int]] = {}
        self.hash_last_seen: Dict[str, float] = {}
        self.cluster_hist: Dict[str, Dict[str, int]] = {}
        self.host_artifacts_window: Dict[str, List[Tuple[float,str]]] = {}
        # Name prevalence + host spread tracking
        self.name_hosts: Dict[str, Dict[str, float]] = {}  # name -> host -> last_seen_ts
        self.name_total: Dict[str, int] = {}  # observation counts
        self.window_recent_seconds = 1800  # for rapid propagation heuristic
        # Persistence
        self._persist_path = 'dump/artifact_prevalence.json'
        self._loaded = False
        self._ensure_loaded()

    def evict(self):
        cutoff = time.time() - self.retention
        remove = [h for h,t in self.hash_last_seen.items() if t < cutoff]
        for h in remove:
            self.hash_last_seen.pop(h, None)
            self.hash_history.pop(h, None)
        # host windows
        for host, arr in list(self.host_artifacts_window.items()):
            filtered = [x for x in arr if x[0] >= cutoff]
            if filtered:
                self.host_artifacts_window[host] = filtered
            else:
                self.host_artifacts_window.pop(host, None)

    def update(self, obs: ArtifactObservation):
        with self._lock:
            self.hash_last_seen[obs.artifact_id] = time.time()
            hist = self.hash_history.setdefault(obs.artifact_id, {})
            hist[obs.verdict.value] = hist.get(obs.verdict.value, 0) + 1
            if obs.cluster_id:
                ch = self.cluster_hist.setdefault(obs.cluster_id, {})
                ch[obs.verdict.value] = ch.get(obs.verdict.value, 0) + 1
            # host propagation tracking
            if obs.host:
                arr = self.host_artifacts_window.setdefault(obs.host, [])
                arr.append((time.time(), obs.artifact_id))
            # name prevalence
            name = (obs.name or '').lower()
            if name:
                nh = self.name_hosts.setdefault(name, {})
                nh[obs.host or 'unknown'] = time.time()
                self.name_total[name] = self.name_total.get(name,0)+1
            if len(self.hash_last_seen) % 500 == 0:
                self.evict()
                self._persist_async()

    def context(self, obs: ArtifactObservation, recent_window: int = 1800, propagation_threshold: int = 5) -> Dict[str, Any]:
        now = time.time()
        ctx: Dict[str, Any] = {}
        with self._lock:
            hist = self.hash_history.get(obs.artifact_id, {})
            total = sum(hist.values())
            good_cnt = hist.get('GOOD',0)
            mal_cnt = hist.get('MALICIOUS',0)
            if total > 0 and good_cnt / total >= self.benign_stable_ratio:
                ctx['seen_good_stable'] = True
            if mal_cnt > 0:
                ctx['malicious_neighbor'] = True  # simplified for Lite; could refine with adjacency in future
            # cluster density
            if obs.cluster_id:
                ch = self.cluster_hist.get(obs.cluster_id, {})
                ctot = sum(ch.values())
                if ctot > 0 and ch.get('MALICIOUS',0)/ctot >= self.malicious_density_threshold:
                    ctx['cluster_malicious_density_high'] = True
            # Rapid propagation & rarity
            name = (obs.name or '').lower()
            if name and name in self.name_hosts:
                hosts_map = self.name_hosts[name]
                # Distinct hosts recent window
                recent_hosts = [h for h, ts in hosts_map.items() if now - ts <= recent_window]
                if len(recent_hosts) >= propagation_threshold:
                    ctx['rapid_multi_host_appearance'] = len(recent_hosts)
                # rarity: total observations small but multi-host indicates emerging
                total_name = self.name_total.get(name,0)
                if total_name < 3 and len(recent_hosts) >= 2:
                    ctx['emerging_multi_host'] = True
                # overall rarity (global) compared to simple heuristic threshold
                if total_name == 1:
                    ctx['rare_name'] = True
        return ctx

    # ---------------- Persistence -----------------
    def _ensure_loaded(self):
        if self._loaded:
            return
        try:
            import json, os
            if os.path.exists(self._persist_path):
                with open(self._persist_path,'r',encoding='utf-8') as f:
                    data = json.load(f)
                self.name_hosts = {k:{hk:float(ts) for hk,ts in v.items()} for k,v in data.get('name_hosts',{}).items()}
                self.name_total = {k:int(v) for k,v in data.get('name_total',{}).items()}
        except Exception:
            pass
        self._loaded = True

    def _persist_async(self):
        # fire-and-forget thread to persist small JSON snapshot
        import threading
        def _do():
            try:
                import json, os
                os.makedirs('dump', exist_ok=True)
                snap = {
                    'name_hosts': self.name_hosts,
                    'name_total': self.name_total,
                    'ts': time.time()
                }
                with open(self._persist_path,'w',encoding='utf-8') as f:
                    json.dump(snap,f)
            except Exception:
                pass
        threading.Thread(target=_do, daemon=True).start()
