from __future__ import annotations
import json, os
from pathlib import Path
from typing import Dict, List, Optional

_REGISTRY_PATH = os.getenv("FACTOR_REGISTRY_PATH", "src/config/factor_registry.json")

class FactorRegistry:
    def __init__(self, path: str):
        self.path = path
        self.version: int = 0
        self.factors: List[Dict[str, object]] = []
        self.active: List[str] = []
        self.experimental: List[str] = []
        self.weights: Dict[str, float] = {}
        self._load()

    def _load(self) -> None:
        try:
            p = Path(self.path)
            if not p.exists():
                return
            data = json.loads(p.read_text(encoding="utf-8"))
            self.version = int(data.get("version", 1))
            self.factors = list(data.get("factors", []))
            for f in self.factors:
                name = str(f.get("name"))
                status = str(f.get("status", "active"))
                w = float(f.get("weight", 1.0))
                if status == "active":
                    self.active.append(name)
                elif status == "experimental":
                    self.experimental.append(name)
                self.weights[name] = w
        except Exception:
            pass

    def reload(self) -> None:
        self.active.clear(); self.experimental.clear(); self.weights.clear()
        self._load()

    def weight(self, name: str) -> float:
        return self.weights.get(name, 1.0)

FACTOR_REGISTRY: Optional[FactorRegistry] = None
try:
    FACTOR_REGISTRY = FactorRegistry(_REGISTRY_PATH)
except Exception:
    FACTOR_REGISTRY = None

__all__ = ["FactorRegistry", "FACTOR_REGISTRY"]
