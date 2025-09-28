from __future__ import annotations
from typing import Optional, Dict, Any
import threading, queue, time, os, json

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

class VTWorker(threading.Thread):
    def __init__(self, api_key: str, in_q: queue.Queue, out_q: queue.Queue, rate_limit_per_min: int = 4):
        super().__init__(daemon=True)
        self.api_key = api_key
        self.in_q = in_q
        self.out_q = out_q
        self.rate_limit_per_min = rate_limit_per_min
        self.last_reset = time.time()
        self.tokens = rate_limit_per_min

    def run(self):
        while True:
            item = self.in_q.get()
            if item is None:
                break
            sha256 = item['sha256']
            if not sha256:
                self.out_q.put({'sha256': None, 'unavailable': True, 'reason':'no_hash'})
                continue
            if httpx is None:
                self.out_q.put({'sha256': sha256, 'unavailable': True, 'reason':'httpx_missing'})
                continue
            self._refill()
            if self.tokens <= 0:
                time.sleep(5)
                self._refill()
            try:
                headers = {"x-apikey": self.api_key}
                url = f"https://www.virustotal.com/api/v3/files/{sha256}"
                resp = httpx.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    stats = data.get('data',{}).get('attributes',{}).get('last_analysis_stats',{})
                    positives = sum(v for k,v in stats.items() if k not in ('harmless','undetected'))
                    total = sum(stats.values()) or 1
                    vt_ratio = positives/total
                    self.out_q.put({'sha256':sha256,'vt_ratio':vt_ratio,'positives':positives,'total':total})
                else:
                    self.out_q.put({'sha256':sha256,'unavailable':True,'reason':f'status_{resp.status_code}'})
            except Exception as e:
                self.out_q.put({'sha256':sha256,'unavailable':True,'reason':str(e)})
            finally:
                self.tokens -= 1
                self.in_q.task_done()

    def _refill(self):
        now = time.time()
        if now - self.last_reset >= 60:
            self.tokens = self.rate_limit_per_min
            self.last_reset = now

class VTQueue:
    def __init__(self):
        self.enabled = bool(os.getenv('ENABLE_VT_REPUTATION')) and os.getenv('VT_API_KEY')
        self.api_key = os.getenv('VT_API_KEY','')
        self.in_q: queue.Queue = queue.Queue()
        self.out_q: queue.Queue = queue.Queue()
        self.worker: Optional[VTWorker] = None
        if self.enabled:
            self.worker = VTWorker(self.api_key, self.in_q, self.out_q)
            self.worker.start()
        self.cache: Dict[str, Dict[str,Any]] = {}

    def submit(self, sha256: str):
        if not self.enabled: return
        if sha256 in self.cache: return
        self.in_q.put({'sha256':sha256})

    def poll_ready(self):
        drained = []
        while True:
            try:
                item = self.out_q.get_nowait()
            except queue.Empty:
                break
            self.cache[item.get('sha256')] = item
            drained.append(item)
        return drained

    def get(self, sha256: str) -> Optional[Dict[str,Any]]:
        return self.cache.get(sha256)
