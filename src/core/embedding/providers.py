"""Pluggable embedding provider abstraction with graceful degradation.

Order of preference (escalation path): SecBERT -> TinyBERT (security-tuned) -> MiniLM -> Hash.
A light complexity scoring heuristic determines whether to ATTEMPT escalation;
if complexity low we skip heavier model for latency/cost savings.

Environment Variables:
  EMBEDDING_FORCE_PROVIDER = one of [secbert, tinybert, minilm, hash]
  EMBEDDING_COMPLEXITY_THRESHOLD = float (default 0.6)
  EMBEDDING_DISABLE_SEC = '1' to skip SecBERT entirely
  EMBEDDING_HASH_DIM = int (default 32)

Metrics (to be optionally registered elsewhere):
  embedding_provider_selection_total{provider}
  embedding_provider_fallback_total{from,reason}

Note: Only minimal imports at module import time; heavy model loads happen lazily.
"""
from __future__ import annotations
import os, hashlib, math, time
from typing import List, Dict, Any, Optional, Protocol

try:
    from prometheus_client import Counter
except Exception:  # fallback dummies
    Counter = lambda *a, **k: None  # type: ignore

_provider_select_counter = None
_fallback_counter = None
try:
    _provider_select_counter = Counter('embedding_provider_selection_total', 'Embedding provider selections', ['provider'])
    _fallback_counter = Counter('embedding_provider_fallback_total', 'Embedding provider fallbacks', ['source','reason'])
except Exception:
    pass

class EmbeddingProvider(Protocol):
    name: str
    async def embed(self, text: str) -> List[float]: ...

class HashProvider:
    name = 'hash'
    def __init__(self, dim: int = 32):
        self.dim = dim
    async def embed(self, text: str) -> List[float]:
        h = hashlib.sha256(text.encode()).digest()
        # repeat if dim > len
        raw = list(h)
        while len(raw) < self.dim:
            raw.extend(raw)
        return [b/255.0 for b in raw[:self.dim]]

class MiniLMProvider:
    name = 'minilm'
    def __init__(self):
        self._loaded = False
    async def _load(self):
        if self._loaded:
            return
        from transformers import AutoTokenizer, AutoModel  # type: ignore
        self._tok = AutoTokenizer.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
        self._model = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
        self._loaded = True
    async def embed(self, text: str) -> List[float]:
        try:
            await self._load()
            toks = self._tok(text, return_tensors='pt', truncation=True)
            import torch  # type: ignore
            with torch.no_grad():
                out = self._model(**toks)
                vec = out.last_hidden_state.mean(dim=1).squeeze().tolist()
                if isinstance(vec, float):
                    vec = [vec]
                return [float(x) for x in vec[:384]]
        except Exception:
            return await HashProvider().embed(text)

class TinyBERTSecProvider:
    name = 'tinybert_sec'
    def __init__(self):
        self._loaded = False
    async def _load(self):
        if self._loaded:
            return
        # Placeholder: using same MiniLM as stand-in unless security-tuned tiny model is downloaded
        # In production, point to a fine-tuned TinyBERT security model artifact.
        from transformers import AutoTokenizer, AutoModel  # type: ignore
        self._tok = AutoTokenizer.from_pretrained('sentence-transformers/paraphrase-MiniLM-L3-v2')
        self._model = AutoModel.from_pretrained('sentence-transformers/paraphrase-MiniLM-L3-v2')
        self._loaded = True
    async def embed(self, text: str) -> List[float]:
        try:
            await self._load()
            toks = self._tok(text, return_tensors='pt', truncation=True)
            import torch  # type: ignore
            with torch.no_grad():
                out = self._model(**toks)
                vec = out.last_hidden_state.mean(dim=1).squeeze().tolist()
                if isinstance(vec, float): vec = [vec]
                return [float(x) for x in vec[:384]]
        except Exception:
            return await HashProvider().embed(text)

class SecBERTProvider:
    name = 'secbert'
    def __init__(self):
        self._loaded = False
    async def _load(self):
        if self._loaded:
            return
        # Placeholder: reuse MiniLM pending security-specific checkpoint integration.
        from transformers import AutoTokenizer, AutoModel  # type: ignore
        self._tok = AutoTokenizer.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
        self._model = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
        self._loaded = True
    async def embed(self, text: str) -> List[float]:
        try:
            await self._load()
            toks = self._tok(text, return_tensors='pt', truncation=True)
            import torch  # type: ignore
            with torch.no_grad():
                out = self._model(**toks)
                vec = out.last_hidden_state.mean(dim=1).squeeze().tolist()
                if isinstance(vec, float): vec = [vec]
                return [float(x) for x in vec[:384]]
        except Exception:
            return await HashProvider().embed(text)

class EmbeddingSelector:
    def __init__(self):
        self.hash_provider = HashProvider(dim=int(os.getenv('EMBEDDING_HASH_DIM','32')))
        self.minilm = MiniLMProvider()
        self.tiny = TinyBERTSecProvider()
        self.sec = None if os.getenv('EMBEDDING_DISABLE_SEC') == '1' else SecBERTProvider()
        self.force = os.getenv('EMBEDDING_FORCE_PROVIDER')
        self.complexity_threshold = float(os.getenv('EMBEDDING_COMPLEXITY_THRESHOLD','0.6'))

    def _score_complexity(self, factors: List[str]) -> float:
        if not factors:
            return 0.0
        roots = set(f.split(':',1)[0] for f in factors)
        diversity = len(roots) / max(10, len(factors))
        security_tokens = sum(1 for f in factors if any(k in f for k in ['lateral','exfil','priv','persistence','credential']))
        score = 0.5*diversity + 0.5*min(1.0, security_tokens/5)
        return min(1.0, score)

    async def select(self, factors: List[str]) -> EmbeddingProvider:
        if self.force:
            return getattr(self, self._force_attr(self.force), self.hash_provider)
        complexity = self._score_complexity(factors)
        # If complexity below threshold, skip heavy providers
        if complexity < self.complexity_threshold:
            return self._record(self.tiny if self.tiny else self.minilm)
        # Try escalation path
        for prov in [self.sec, self.tiny, self.minilm, self.hash_provider]:
            if prov is None: continue
            return self._record(prov)
        return self.hash_provider

    def _force_attr(self, name: str) -> str:
        mapping = {
            'hash': 'hash_provider',
            'minilm': 'minilm',
            'tinybert': 'tiny',
            'tiny': 'tiny',
            'secbert': 'sec',
            'sec': 'sec'
        }
        return mapping.get(name.lower(), 'hash_provider')

    def _record(self, provider: EmbeddingProvider) -> EmbeddingProvider:
        try:
            if _provider_select_counter:
                _provider_select_counter.labels(provider=provider.name).inc()
        except Exception:
            pass
        return provider

async def embed_text(text: str, factors: List[str], selector: Optional[EmbeddingSelector] = None) -> List[float]:
    selector = selector or EmbeddingSelector()
    prov = await selector.select(factors)
    try:
        return await prov.embed(text)
    except Exception as e:
        # fallback
        if _fallback_counter:
            try: _fallback_counter.labels(source=prov.name, reason='exception').inc()
            except Exception: pass
        return await selector.hash_provider.embed(text)
