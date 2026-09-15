"""Weights loader with hot-reload for Sultry dump.
Simple file-watch polling to reload `factors.weights.json` when changed.
"""
from __future__ import annotations
import json, os, time
from typing import Dict

_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), 'factors.weights.json')

class WeightsLoader:
    def __init__(self, path: str | None = None, poll_interval: float = 1.0):
        self.path = path or _DEFAULT_PATH
        self.poll_interval = poll_interval
        self._last_mtime = 0.0
        self.weights: Dict[str, float] = {}
        self.load()

    def load(self):
        try:
            st = os.stat(self.path)
            m = st.st_mtime
            if m != self._last_mtime:
                with open(self.path, 'r', encoding='utf-8') as fh:
                    self.weights = json.load(fh)
                self._last_mtime = m
        except FileNotFoundError:
            self.weights = {}
        except Exception:
            pass

    def watch_forever(self):
        try:
            while True:
                self.load()
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            return

    def get_weight(self, factor: str, default: float = 0.0) -> float:
        return float(self.weights.get(factor, default))

# simple module-level instance for ease of use
_loader = WeightsLoader()
get_weight = _loader.get_weight
reload_weights = _loader.load
