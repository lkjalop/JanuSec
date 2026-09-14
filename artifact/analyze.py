# Lightweight shim for ArtifactPipeline used in tests
from typing import Any

class ArtifactPipeline:
    def __init__(self, *args, **kwargs):
        self.enable_embeddings = kwargs.get('enable_embeddings', False)
        # allow init with positional flags
        if len(args) and isinstance(args[0], bool):
            self.enable_embeddings = args[0]
    def run(self, artifact: Any) -> dict:
        # return a minimal expected structure
        return {'result': 'ok', 'artifact': artifact}

    def _ambiguous(self, obs: Any) -> bool:
        # Behavior expected by tests:
        # - if ENABLE_ARTIFACT_LLM env var is not '1', ambiguity band is disabled
        # - otherwise, check ARTIFACT_AMBIGUITY_LOWER and _UPPER bounds
        import os
        enabled = os.getenv('ENABLE_ARTIFACT_LLM','0') == '1'
        if not enabled:
            return False
        try:
            lo = float(os.getenv('ARTIFACT_AMBIGUITY_LOWER','0.4'))
            hi = float(os.getenv('ARTIFACT_AMBIGUITY_UPPER','0.7'))
        except Exception:
            lo, hi = 0.4, 0.7
        v = getattr(obs, 'final_risk', None)
        try:
            v = float(v)
        except Exception:
            return False
        return (v >= lo and v <= hi)

__all__ = ['ArtifactPipeline']
