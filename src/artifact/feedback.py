from __future__ import annotations
from typing import Dict, Any, Optional
import threading, json, os, time
from .models import Verdict

FEEDBACK_PATH = os.path.join('dump','artifact_feedback.json')

class FeedbackStore:
    def __init__(self):
        self._lock = threading.RLock()
        self.overrides: Dict[str, Dict[str,Any]] = {}
        self._load()

    def _load(self):
        if os.path.exists(FEEDBACK_PATH):
            try:
                with open(FEEDBACK_PATH,'r',encoding='utf-8') as fh:
                    self.overrides = json.load(fh)
            except Exception:
                self.overrides = {}

    def _persist(self):
        try:
            with open(FEEDBACK_PATH,'w',encoding='utf-8') as fh:
                json.dump(self.overrides, fh, indent=2)
        except Exception:
            pass

    def apply(self, artifact_id: str, verdict: str, comment: str | None = None):
        with self._lock:
            self.overrides[artifact_id] = {'verdict': verdict, 'comment': comment, 'ts': time.time()}
            self._persist()

    def get(self, artifact_id: str) -> Optional[Dict[str,Any]]:
        return self.overrides.get(artifact_id)
