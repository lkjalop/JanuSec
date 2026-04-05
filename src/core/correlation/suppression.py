from __future__ import annotations
import json, os, time
from pathlib import Path
from typing import List, Dict, Any
try:  # metrics optional
    from .metrics_correlation import inc_suppression  # type: ignore
except Exception:  # pragma: no cover
    def inc_suppression(*_a, **_k):
        return None
try:
    from .negative_patterns import GLOBAL_NEGATIVE_PATTERNS  # type: ignore
except Exception:  # pragma: no cover
    GLOBAL_NEGATIVE_PATTERNS = None  # type: ignore

_SUPPRESS_PATH = os.getenv("SUPPRESSION_TEMPLATES_PATH", "src/config/suppression_templates.json")

class SuppressionEngine:
    def __init__(self, path: str = _SUPPRESS_PATH):
        self.path = path
        self.templates: List[Dict[str, Any]] = []
        self._load()

    def _load(self):
        try:
            p = Path(self.path)
            if not p.exists():
                return
            data = json.loads(p.read_text(encoding="utf-8"))
            self.templates = list(data.get("templates", []))
        except Exception:
            pass

    def evaluate(self, context: Dict[str, Any], factors: List[str]) -> Dict[str, float]:
        """Return adjustment map {factor: delta} (negative to lower)."""
        adjustments: Dict[str, float] = {}
        hour = time.gmtime().tm_hour
        for tpl in self.templates:
            mf: List[str] = tpl.get("match_factors", [])
            if not any(f in factors for f in mf):
                continue
            cond = tpl.get("conditions", {})
            # basic checks
            hr = cond.get("hour_range")
            if hr and isinstance(hr, list) and len(hr) == 2:
                if not (hr[0] <= hour <= hr[1]):
                    continue
            tag = cond.get("tag")
            if tag and tag != context.get("tag"):
                continue
            role = cond.get("user_role")
            if role and role != context.get("user_role"):
                continue
            if cond.get("deployment_window") and not context.get("deployment_window_active"):
                continue
            if cond.get("tool_whitelist") and not context.get("tool_whitelisted"):
                continue
            action = tpl.get("action")
            if action == "suppress":
                for f in mf:
                    adjustments[f] = -999.0  # sentinel large negative
                try: inc_suppression(str(tpl.get('name','template')), 'suppress')
                except Exception: pass
            elif action == "lower_weight":
                delta = float(tpl.get("delta", -0.2))
                for f in mf:
                    adjustments[f] = delta
                try: inc_suppression(str(tpl.get('name','template')), 'lower_weight')
                except Exception: pass
        return adjustments

    def evaluate_with_negative(self, context: Dict[str, Any], factors: List[str]) -> Dict[str, Any]:
        """Evaluate suppression and also annotate any matching negative (benign) patterns.

        Returns: { 'adjustments': {factor: delta}, 'negative_matches': [pattern_names] }
        """
        res = self.evaluate(context, factors)
        negs = []
        try:
            if GLOBAL_NEGATIVE_PATTERNS is not None:
                negs = GLOBAL_NEGATIVE_PATTERNS.evaluate(factors)
        except Exception:
            negs = []
        return {'adjustments': res, 'negative_matches': negs}

GLOBAL_SUPPRESSION_ENGINE = SuppressionEngine()

__all__ = ["SuppressionEngine", "GLOBAL_SUPPRESSION_ENGINE"]
