"""Open-Source Security Models Integration.

Supports Hugging Face transformers (CPU by default) and optional Ollama models
residing under D:\\ by default. Loading is lazy and failures degrade gracefully.
"""
from __future__ import annotations

import asyncio
import logging
import pathlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

try:  # Optional heavy dependencies
    from transformers import (
        AutoModel,
        AutoModelForSequenceClassification,
        AutoTokenizer,
        pipeline,
    )
    import torch
    TRANSFORMERS_AVAILABLE = True
except Exception:  # pragma: no cover - env without transformers/torch
    AutoModel = AutoModelForSequenceClassification = AutoTokenizer = pipeline = None  # type: ignore
    torch = None  # type: ignore
    TRANSFORMERS_AVAILABLE = False


@dataclass
class OSSModelSpec:
    name: str
    task: str  # 'embedding' | 'classification' | 'generation'
    model_id: str
    max_length: int = 512
    trust_remote_code: bool = False
    device_pref: str = 'auto'


class _OllamaClient:
    """Thin wrapper around the Ollama HTTP API (installed on D:\\ by default)."""

    def __init__(self, host: str, root: pathlib.Path, command: Optional[str] = None):
        self.host = host.rstrip('/')
        self.root = root
        self.command = command

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.host}{path}"
        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:  # pragma: no cover - network error paths
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

    def embed(self, model: str, text: str) -> Optional[List[float]]:
        data = self._post('/api/embeddings', {'model': model, 'prompt': text})
        return data.get('embedding')

    def generate(self, model: str, prompt: str, max_new_tokens: int) -> str:
        payload = {
            'model': model,
            'prompt': prompt,
            'stream': False,
            'options': {'num_predict': max_new_tokens},
        }
        data = self._post('/api/generate', payload)
        return data.get('response', '')

    def classification_scores(self, text: str) -> Dict[str, float]:
        """Very light heuristic scoring when Ollama is provider."""
        baseline = {'benign': 0.4, 'suspicious': 0.3, 'malicious': 0.3}
        lowered = text.lower()
        malicious_tokens = ('mimikatz', 'c2', 'ransom', 'payload', 'malware')
        suspicious_tokens = ('suspicious', 'unknown', 'encoded', 'anomaly')
        benign_tokens = ('baseline', 'expected', 'allow', 'whitelist')
        if any(tok in lowered for tok in malicious_tokens):
            baseline['malicious'] += 0.4
        if any(tok in lowered for tok in suspicious_tokens):
            baseline['suspicious'] += 0.3
        if any(tok in lowered for tok in benign_tokens):
            baseline['benign'] += 0.3
        total = sum(baseline.values()) or 1.0
        return {k: v / total for k, v in baseline.items()}


class OpenSourceModelManager:
    """Manages optional open-source models with lazy loading and backend selection."""

    _OLLAMA_LABELS = ['benign', 'suspicious', 'malicious']

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.backend = (self.config.get('backend') or 'transformers').lower()
        self.device_pref = (self.config.get('device') or 'cpu').lower()
        self.enabled = bool(self.config.get('enable') or self.config.get('enable_oss_models'))
        self.models: Dict[str, Any] = {}
        self.model_devices: Dict[str, str] = {}
        self.tokenizers: Dict[str, Any] = {}
        self.model_specs: Dict[str, OSSModelSpec] = {}
        self.health: Dict[str, Dict[str, Any]] = {}

        self.ollama_root = pathlib.Path(self.config.get('ollama_root') or 'D:/Ollama')
        self.ollama_host = self.config.get('ollama_host') or 'http://127.0.0.1:11434'
        self.ollama_client = _OllamaClient(self.ollama_host, self.ollama_root, self.config.get('ollama_cmd'))

        if self.backend == 'transformers' and not TRANSFORMERS_AVAILABLE:
            logger.warning('transformers/torch not available. Disabling OSS transformers backend.')
            self.enabled = False

        self._register_default_models()

    def _register_default_models(self) -> None:
        defaults = [
            OSSModelSpec('roberta_embed', 'embedding', 'sentence-transformers/all-MiniLM-L6-v2', 384),
            OSSModelSpec('roberta_cls', 'classification', 'roberta-base'),
            OSSModelSpec('deberta_cls', 'classification', 'microsoft/deberta-v3-base'),
            OSSModelSpec('mistral_gen', 'generation', 'mistralai/Mistral-7B-Instruct-v0.2', 1024, True),
        ]
        for spec in defaults:
            self.model_specs.setdefault(spec.name, spec)
        for custom in self.config.get('oss_model_specs', []):
            try:
                spec = OSSModelSpec(**custom)
                self.model_specs[spec.name] = spec
            except Exception as exc:  # pragma: no cover - config error paths
                logger.error("Invalid custom OSS model spec %s: %s", custom, exc)

    def list_available(self) -> List[str]:
        if not self.enabled:
            return []
        if self.backend == 'transformers' and not TRANSFORMERS_AVAILABLE:
            return []
        return list(self.model_specs.keys())

    async def ensure_loaded(self, name: str) -> bool:
        if not self.enabled:
            return False
        if name in self.models:
            return True
        if name not in self.model_specs:
            logger.error("Model spec %s not registered", name)
            return False
        spec = self.model_specs[name]

        if self.backend == 'ollama':
            self.models[name] = {'model_id': spec.model_id}
            self.health[name] = {'loaded': True, 'backend': 'ollama', 'error': None}
            return True

        if not TRANSFORMERS_AVAILABLE:
            logger.error("transformers backend unavailable for model %s", name)
            self.health[name] = {'loaded': False, 'error': 'transformers_unavailable'}
            return False

        try:
            chosen_device = spec.device_pref.lower() if spec.device_pref else 'auto'
            if chosen_device == 'auto':
                chosen_device = self.device_pref
            if chosen_device == 'cuda' and not torch.cuda.is_available():  # type: ignore[union-attr]
                logger.warning("CUDA requested for %s but unavailable; falling back to CPU", name)
                chosen_device = 'cpu'
            torch_device = 'cuda' if chosen_device == 'cuda' else 'cpu'
            pipeline_device = 0 if torch_device == 'cuda' else -1

            if spec.task == 'embedding':
                tokenizer = AutoTokenizer.from_pretrained(spec.model_id, trust_remote_code=spec.trust_remote_code)
                model = AutoModel.from_pretrained(spec.model_id, trust_remote_code=spec.trust_remote_code)
                model = model.to(torch_device)
                self.tokenizers[name] = tokenizer
                self.models[name] = model
            elif spec.task == 'classification':
                tokenizer = AutoTokenizer.from_pretrained(spec.model_id, trust_remote_code=spec.trust_remote_code)
                model = AutoModelForSequenceClassification.from_pretrained(spec.model_id, trust_remote_code=spec.trust_remote_code)
                model = model.to(torch_device)
                self.tokenizers[name] = tokenizer
                self.models[name] = model
            elif spec.task == 'generation':
                self.models[name] = pipeline(
                    'text-generation',
                    model=spec.model_id,
                    trust_remote_code=spec.trust_remote_code,
                    device=pipeline_device,
                )
            else:
                logger.error("Unknown task %s for model %s", spec.task, name)
                return False

            self.model_devices[name] = torch_device
            self.health[name] = {'loaded': True, 'backend': self.backend, 'device': torch_device, 'error': None}
            logger.info("Loaded OSS model %s (%s) on %s", name, spec.model_id, torch_device)
            return True
        except Exception as exc:
            self.health[name] = {'loaded': False, 'error': str(exc)}
            logger.error("Failed loading model %s: %s", name, exc)
            return False

    async def embed(self, name: str, text: str) -> Optional[List[float]]:
        if not await self.ensure_loaded(name):
            return None
        spec = self.model_specs[name]
        if spec.task not in ('embedding', 'classification'):
            logger.error("Model %s not suitable for embeddings", name)
            return None
        if self.backend == 'ollama':
            return await asyncio.to_thread(self.ollama_client.embed, spec.model_id, text)
        tokenizer = self.tokenizers[name]
        model = self.models[name]
        device = self.model_devices.get(name, 'cpu')
        inputs = tokenizer(text, truncation=True, max_length=spec.max_length, return_tensors='pt')
        if device == 'cuda':
            inputs = inputs.to('cuda')  # type: ignore[union-attr]
        with torch.no_grad():  # type: ignore[union-attr]
            outputs = model(**inputs)
            if hasattr(outputs, 'last_hidden_state'):
                emb = outputs.last_hidden_state.mean(dim=1).squeeze().cpu().tolist()
            else:
                emb = outputs[0].mean(dim=1).squeeze().cpu().tolist()
        return emb

    async def classify(self, name: str, text: str) -> Optional[Dict[str, Any]]:
        if not await self.ensure_loaded(name):
            return None
        spec = self.model_specs[name]
        if spec.task != 'classification':
            logger.error("Model %s not classification type", name)
            return None
        if self.backend == 'ollama':
            scores = self.ollama_client.classification_scores(text)
            probabilities = [scores[label] for label in self._OLLAMA_LABELS]
            idx = int(max(range(len(probabilities)), key=lambda i: probabilities[i]))
            return {'labels': self._OLLAMA_LABELS, 'probabilities': probabilities, 'predicted_index': idx}
        tokenizer = self.tokenizers[name]
        model = self.models[name]
        device = self.model_devices.get(name, 'cpu')
        inputs = tokenizer(text, truncation=True, max_length=spec.max_length, return_tensors='pt')
        if device == 'cuda':
            inputs = inputs.to('cuda')  # type: ignore[union-attr]
        with torch.no_grad():  # type: ignore[union-attr]
            logits = model(**inputs).logits
            probs = torch.softmax(logits, dim=-1).squeeze().cpu().tolist()  # type: ignore[union-attr]
        return {
            'labels': list(range(len(probs))),
            'probabilities': probs,
            'predicted_index': int(max(range(len(probs)), key=lambda i: probs[i])),
        }

    async def generate(self, name: str, prompt: str, max_new_tokens: int = 128) -> Optional[str]:
        if not await self.ensure_loaded(name):
            return None
        spec = self.model_specs[name]
        if spec.task != 'generation':
            logger.error("Model %s not generation type", name)
            return None
        if self.backend == 'ollama':
            return await asyncio.to_thread(self.ollama_client.generate, spec.model_id, prompt, max_new_tokens)
        pipe = self.models[name]
        out = pipe(prompt, max_new_tokens=max_new_tokens, do_sample=False)
        return out[0]['generated_text'] if out else None

    def get_health(self) -> Dict[str, Any]:
        return {
            'enabled': self.enabled,
            'backend': self.backend,
            'device': self.device_pref,
            'transformers_available': TRANSFORMERS_AVAILABLE,
            'models': self.health,
            'registered': list(self.model_specs.keys()),
            'ollama_root': str(self.ollama_root),
        }
