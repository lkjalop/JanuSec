"""Per-tenant LLM provider configuration with encrypted key storage.

Each tenant can bring their own API keys (BYOK) or point to a cloud-native
endpoint (Bedrock, Azure OpenAI, Vertex AI).  If no tenant config exists the
platform falls back to the global DEFAULT_CLIENT (Ollama or env-var keys).

Storage: one JSON file per tenant under  <SESSION_PERSIST_DIR>/tenant_llm/
Encryption: API keys are wrapped with Fernet via src.security.crypto_utils
            (uses INTEGRATIONS_ENCRYPTION_KEY env var).

Schema (stored on disk):
{
  "tenant_id": "acme",
  "provider": "ollama" | "anthropic" | "openai" | "bedrock" | "azure_openai" | "vertex",
  "tier_small_model":    "<model-id>",   # REFINE / low-medium severity
  "tier_large_model":    "<model-id>",   # ACCEPT / high severity
  "tier_critical_model": "<model-id>",   # ACCEPT + critical / escalation
  "ollama_host":   "http://127.0.0.1:11434",
  "api_key_enc":   "<fernet-ciphertext>",  # empty string = IAM-role / no key needed
  "endpoint":      "",   # Azure base URL, SageMaker endpoint ARN, etc.
  "region":        "",   # AWS region for Bedrock / SageMaker
  "enabled":       true,
  "updated_at":    1234567890.0
}
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Defaults per provider ────────────────────────────────────────────────────

_PROVIDER_DEFAULTS: Dict[str, Dict[str, str]] = {
    'ollama': {
        'tier_small_model':    'qwen3:14b',
        'tier_large_model':    'qwen3:14b',
        'tier_critical_model': 'qwen3:14b',
    },
    'anthropic': {
        'tier_small_model':    'claude-haiku-4-5-20251001',
        'tier_large_model':    'claude-sonnet-4-6',
        'tier_critical_model': 'claude-sonnet-4-6',
    },
    'openai': {
        'tier_small_model':    'gpt-4o-mini',
        'tier_large_model':    'gpt-4o',
        'tier_critical_model': 'gpt-4o',
    },
    'bedrock': {
        # Bedrock model IDs — Claude via Amazon Bedrock
        'tier_small_model':    'anthropic.claude-haiku-4-5-20251001-v1:0',
        'tier_large_model':    'anthropic.claude-sonnet-4-6-v1:0',
        'tier_critical_model': 'anthropic.claude-sonnet-4-6-v1:0',
    },
    'azure_openai': {
        'tier_small_model':    'gpt-4o-mini',
        'tier_large_model':    'gpt-4o',
        'tier_critical_model': 'gpt-4o',
    },
    'vertex': {
        'tier_small_model':    'gemini-2.0-flash',
        'tier_large_model':    'gemini-2.5-pro',
        'tier_critical_model': 'gemini-2.5-pro',
    },
}

SUPPORTED_PROVIDERS = set(_PROVIDER_DEFAULTS.keys())


# ── Dataclass ────────────────────────────────────────────────────────────────

@dataclass
class TenantLLMConfig:
    tenant_id: str
    provider: str = 'ollama'
    tier_small_model: str = ''
    tier_large_model: str = ''
    tier_critical_model: str = ''
    ollama_host: str = 'http://127.0.0.1:11434'
    api_key_enc: str = ''           # Fernet-encrypted; empty = use IAM / no key
    endpoint: str = ''              # Azure base URL, SageMaker endpoint, etc.
    region: str = ''                # AWS region
    enabled: bool = True
    updated_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        """Fill model defaults for the chosen provider if caller left them blank."""
        defaults = _PROVIDER_DEFAULTS.get(self.provider, _PROVIDER_DEFAULTS['ollama'])
        if not self.tier_small_model:
            self.tier_small_model = defaults['tier_small_model']
        if not self.tier_large_model:
            self.tier_large_model = defaults['tier_large_model']
        if not self.tier_critical_model:
            self.tier_critical_model = defaults['tier_critical_model']

    # ── Key helpers ───────────────────────────────────────────────────────────

    def set_api_key(self, plaintext: str) -> None:
        """Encrypt and store an API key.  Uses crypto_utils if available."""
        try:
            from src.security.crypto_utils import encrypt_secret
            self.api_key_enc = encrypt_secret(plaintext)
        except Exception:
            # Dev fallback: base64 obfuscation only — NOT secure for production
            import base64
            self.api_key_enc = 'b64:' + base64.b64encode(plaintext.encode()).decode()

    def get_api_key(self) -> str:
        """Decrypt and return the stored API key, or '' if none set."""
        if not self.api_key_enc:
            return ''
        try:
            from src.security.crypto_utils import decrypt_secret
            return decrypt_secret(self.api_key_enc)
        except Exception:
            try:
                import base64
                if self.api_key_enc.startswith('b64:'):
                    return base64.b64decode(self.api_key_enc[4:]).decode()
            except Exception:
                pass
        return ''

    def model_for_tier(self, tier: str) -> str:
        """Return the model ID for 'small' | 'large' | 'critical'."""
        if tier == 'small':
            return self.tier_small_model
        if tier == 'large':
            return self.tier_large_model
        return self.tier_critical_model


# ── Storage ──────────────────────────────────────────────────────────────────

def _store_dir() -> Path:
    base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data')
    p = Path(base) / 'tenant_llm'
    p.mkdir(parents=True, exist_ok=True)
    return p


def _safe(s: str) -> str:
    return ''.join(c if c.isalnum() or c in '-_.' else '_' for c in s)


def load_tenant_llm_config(tenant_id: str) -> Optional[TenantLLMConfig]:
    """Load persisted config for *tenant_id*, or None if not configured."""
    path = _store_dir() / f'{_safe(tenant_id)}.json'
    if not path.exists():
        return None
    try:
        data: Dict[str, Any] = json.loads(path.read_text(encoding='utf-8'))
        cfg = TenantLLMConfig(
            tenant_id=data.get('tenant_id', tenant_id),
            provider=data.get('provider', 'ollama'),
            tier_small_model=data.get('tier_small_model', ''),
            tier_large_model=data.get('tier_large_model', ''),
            tier_critical_model=data.get('tier_critical_model', ''),
            ollama_host=data.get('ollama_host', 'http://127.0.0.1:11434'),
            api_key_enc=data.get('api_key_enc', ''),
            endpoint=data.get('endpoint', ''),
            region=data.get('region', ''),
            enabled=data.get('enabled', True),
            updated_at=data.get('updated_at', 0.0),
        )
        return cfg
    except Exception as exc:
        logger.warning('tenant_llm_config load failed for %s: %s', tenant_id, exc)
        return None


def save_tenant_llm_config(cfg: TenantLLMConfig) -> None:
    """Persist a TenantLLMConfig to disk."""
    cfg.updated_at = time.time()
    path = _store_dir() / f'{_safe(cfg.tenant_id)}.json'
    try:
        path.write_text(json.dumps(asdict(cfg), indent=2, ensure_ascii=False), encoding='utf-8')
    except Exception as exc:
        logger.error('tenant_llm_config save failed for %s: %s', cfg.tenant_id, exc)
        raise


def delete_tenant_llm_config(tenant_id: str) -> bool:
    """Remove tenant config; returns True if it existed."""
    path = _store_dir() / f'{_safe(tenant_id)}.json'
    if path.exists():
        path.unlink()
        return True
    return False


def list_tenant_llm_configs() -> list[str]:
    """Return list of tenant_ids that have a saved LLM config."""
    return [p.stem for p in _store_dir().glob('*.json')]


__all__ = [
    'TenantLLMConfig',
    'SUPPORTED_PROVIDERS',
    'load_tenant_llm_config',
    'save_tenant_llm_config',
    'delete_tenant_llm_config',
    'list_tenant_llm_configs',
]
