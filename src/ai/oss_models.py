"""Open-Source Security Models Integration

Provides optional integration with open-source transformer and domain-specific security language models.
Lazy loads models only when requested; degrades gracefully if dependencies missing.

Models supported (config-driven):
- roberta-base / roberta-large
- microsoft/DeBERTa-v3-base (classification)
- sentence-transformers/all-MiniLM-L6-v2 (embeddings lightweight)
- security BERT variants (placeholder names: securebert-base, cybert-base)*
- mistral-7b-instruct (through text-generation pipeline)

(* custom fine-tuned models can be mapped in config)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

try:
    from transformers import AutoTokenizer, AutoModel, AutoModelForSequenceClassification, pipeline
    import torch
    TRANSFORMERS_AVAILABLE = True
except Exception:  # broad: if any import fails we mark unavailable
    TRANSFORMERS_AVAILABLE = False


@dataclass
class OSSModelSpec:
    name: str
    task: str  # 'embedding' | 'classification' | 'generation'
    model_id: str
    max_length: int = 512
    trust_remote_code: bool = False
    device_pref: str = 'auto'


class OpenSourceModelManager:
    """Manages optional open-source models with lazy loading and caching."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.models: Dict[str, Any] = {}
        self.tokenizers: Dict[str, Any] = {}
        self.model_specs: Dict[str, OSSModelSpec] = {}
        self.health: Dict[str, Dict[str, Any]] = {}
        self.enabled = self.config.get('enable_oss_models', False)
        if not TRANSFORMERS_AVAILABLE:
            logger.warning("transformers/torch not installed. OSS models disabled.")

        # Default model registry (can be overridden)
        self._register_default_models()

    def _register_default_models(self):
        defaults = [
            OSSModelSpec('roberta_embed', 'embedding', 'sentence-transformers/all-MiniLM-L6-v2', 384),
            OSSModelSpec('roberta_cls', 'classification', 'roberta-base'),
            OSSModelSpec('deberta_cls', 'classification', 'microsoft/deberta-v3-base'),
            OSSModelSpec('mistral_gen', 'generation', 'mistralai/Mistral-7B-Instruct-v0.2', 1024, True),
        ]
        for spec in defaults:
            self.model_specs[spec.name] = spec

        # Merge user-defined specs
        for custom in self.config.get('oss_model_specs', []):
            try:
                spec = OSSModelSpec(**custom)
                self.model_specs[spec.name] = spec
            except Exception as e:
                logger.error(f"Invalid custom OSS model spec {custom}: {e}")

    def list_available(self) -> List[str]:
        return list(self.model_specs.keys()) if self.enabled and TRANSFORMERS_AVAILABLE else []

    async def ensure_loaded(self, name: str) -> bool:
        if not self.enabled or not TRANSFORMERS_AVAILABLE:
            return False
        if name in self.models:
            return True
        if name not in self.model_specs:
            logger.error(f"Model spec {name} not registered")
            return False
        spec = self.model_specs[name]
        try:
            device = 0 if torch.cuda.is_available() else -1
            if spec.task == 'embedding':
                tok = AutoTokenizer.from_pretrained(spec.model_id, trust_remote_code=spec.trust_remote_code)
                mdl = AutoModel.from_pretrained(spec.model_id, trust_remote_code=spec.trust_remote_code)
                self.tokenizers[name] = tok
                self.models[name] = mdl.to('cuda' if device == 0 else 'cpu')
            elif spec.task == 'classification':
                tok = AutoTokenizer.from_pretrained(spec.model_id, trust_remote_code=spec.trust_remote_code)
                mdl = AutoModelForSequenceClassification.from_pretrained(spec.model_id, trust_remote_code=spec.trust_remote_code)
                self.tokenizers[name] = tok
                self.models[name] = mdl.to('cuda' if device == 0 else 'cpu')
            elif spec.task == 'generation':
                self.models[name] = pipeline(
                    'text-generation',
                    model=spec.model_id,
                    trust_remote_code=spec.trust_remote_code,
                    device=device
                )
            else:
                logger.error(f"Unknown task {spec.task} for {name}")
                return False
            self.health[name] = {'loaded': True, 'error': None}
            logger.info(f"Loaded OSS model {name} ({spec.model_id})")
            return True
        except Exception as e:
            self.health[name] = {'loaded': False, 'error': str(e)}
            logger.error(f"Failed loading model {name}: {e}")
            return False

    async def embed(self, name: str, text: str) -> Optional[List[float]]:
        if not await self.ensure_loaded(name):
            return None
        spec = self.model_specs[name]
        if spec.task not in ('embedding', 'classification'):
            logger.error(f"Model {name} not suitable for embeddings")
            return None
        tokenizer = self.tokenizers[name]
        model = self.models[name]
        inputs = tokenizer(text, truncation=True, max_length=spec.max_length, return_tensors='pt')
        with torch.no_grad():
            outputs = model(**inputs)
            # CLS token or mean pooling
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
            logger.error(f"Model {name} not classification type")
            return None
        tok = self.tokenizers[name]
        mdl = self.models[name]
        inputs = tok(text, truncation=True, max_length=spec.max_length, return_tensors='pt')
        with torch.no_grad():
            logits = mdl(**inputs).logits
            probs = torch.softmax(logits, dim=-1).squeeze().cpu().tolist()
        return {
            'labels': list(range(len(probs))),  # Without label mapping unless config provides
            'probabilities': probs,
            'predicted_index': int(max(range(len(probs)), key=lambda i: probs[i]))
        }

    async def generate(self, name: str, prompt: str, max_new_tokens: int = 128) -> Optional[str]:
        if not await self.ensure_loaded(name):
            return None
        spec = self.model_specs[name]
        if spec.task != 'generation':
            logger.error(f"Model {name} not generation type")
            return None
        pipe = self.models[name]
        out = pipe(prompt, max_new_tokens=max_new_tokens, do_sample=False)
        return out[0]['generated_text'] if out else None

    def get_health(self) -> Dict[str, Any]:
        return {
            'enabled': self.enabled,
            'transformers_available': TRANSFORMERS_AVAILABLE,
            'models': self.health,
            'registered': list(self.model_specs.keys())
        }
