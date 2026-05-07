"""Pluggable LLM client abstraction with a deterministic local fallback.

Modules import `DEFAULT_CLIENT` and call `generate`, `stream_generate`,
and `reserve_tenant_budget`. This file provides a simple, fully-local
deterministic client so the application can run without external LLMs
during tests and offline demos.

The implementation is intentionally small and dependency-free.
"""
from __future__ import annotations

import os
import time
import json
import hashlib
import logging
import threading
import re
from typing import Any, Dict, Iterator, Optional

from src.integrations.llm_concurrency import GLOBAL_LLM_LIMITER, llm_concurrency_status

LOGGER = logging.getLogger(__name__)


class BaseLLMClient:
    provider = 'base'

    def generate(self, prompt: str, max_tokens: int = 512, tenant_id: str | None = None, overrides: Dict[str, Any] | None = None, model: str | None = None, **kwargs: Any) -> Dict[str, Any]:
        raise NotImplementedError()

    def stream_generate(self, prompt: str, max_tokens: int = 512, tenant_id: str | None = None) -> Iterator[Dict[str, Any]]:
        # yields fragments {'text': str, 'meta': {...}}
        raise NotImplementedError()

    def generate_batch(self, prompts: list, max_tokens: int | None = None, tenant_id: str | None = None, overrides: Dict[str, Any] | None = None, model: str | None = None) -> list:
        """Serial fallback batch implementation — subclasses may override with concurrency."""
        out = []
        for p in prompts:
            try:
                out.append(self.generate(p, max_tokens=max_tokens or 512, tenant_id=tenant_id, overrides=overrides, model=model))
            except Exception as exc:
                out.append({'error': str(exc)})
        return out

    def reserve_tenant_budget(self, tenant_id: str, cost: float) -> bool:
        # best-effort budget reservation (default allows everything)
        return True


class LocalDeterministicClient(BaseLLMClient):
    provider = 'local-deterministic'

    def __init__(self):
        # simple in-memory tenant budget map for demos/tests
        self._tenant_budget: Dict[str, float] = {}

    def _deterministic_text(self, prompt: str, max_tokens: int) -> str:
        # Return a compact deterministic summary derived from the prompt.
        # When the prompt is for a structured incident assessment (tier1_prefill),
        # return the required JSON schema so downstream parsers don't log warnings.
        h = hashlib.sha256(prompt.encode('utf-8')).hexdigest()[:12]
        snippet = prompt.replace('\n', ' ')[:200]

        # Detect tier1_prefill prompts — they start with /no_think or ask for
        # "structured incident assessment" and expect specific JSON keys.
        is_prefill = (
            prompt.lstrip().startswith('/no_think') or
            'structured incident assessment' in prompt or
            'incident_name' in prompt or
            'headline_subtitle' in prompt or
            'short_narrative' in prompt
        )
        if is_prefill:
            # Extract what we can from the prompt to populate deterministic fields
            import re as _re
            verdict_m = _re.search(r'verdict[:\s=]+([A-Z_\-]+)', prompt, _re.IGNORECASE)
            severity_m = _re.search(r'severity[:\s=]+([a-z]+)', prompt, _re.IGNORECASE)
            verdict = (verdict_m.group(1).lower() if verdict_m else 'confirmed_breach').replace('_', ' ')
            severity = severity_m.group(1) if severity_m else 'high'
            text = json.dumps({
                'incident_name': f'Security Incident {h[:8].upper()}',
                'headline_subtitle': f'{severity.capitalize()}-severity {verdict} detected in monitored environment',
                'short_narrative': (
                    f'Analysis of telemetry data identified a {severity}-severity {verdict}. '
                    f'Evidence from multiple sources was correlated to identify the activity pattern. '
                    f'Immediate investigation and containment is recommended.'
                ),
                'confidence_rationale': (
                    f'Confidence based on correlated indicators across data sources. '
                    f'Deterministic analysis applied (LLM not available).'
                ),
                'top_actions': [
                    'Isolate affected systems and accounts',
                    'Revoke and rotate any compromised credentials',
                    'Preserve forensic artifacts for investigation',
                    'Notify security incident response team',
                    'Review access logs for lateral movement indicators',
                ],
                'mitre_techniques': [],
                'provider': self.provider,
                'summary': f'deterministic-summary-{h}',
                'prompt_snippet': snippet,
                'max_tokens': max_tokens,
                'generated_at': int(time.time()),
            })
        else:
            text = json.dumps({
                'provider': self.provider,
                'summary': f'deterministic-summary-{h}',
                'prompt_snippet': snippet,
                'max_tokens': max_tokens,
                'generated_at': int(time.time()),
            })
        return text

    def generate(self, prompt: str, max_tokens: int = 512, tenant_id: str | None = None, overrides: Dict[str, Any] | None = None, model: str | None = None, **kwargs: Any) -> Dict[str, Any]:
        try:
            text = self._deterministic_text(prompt, max_tokens)
            return {'text': text, 'meta': {'provider': self.provider, 'model': model, 'prompt_hash': hashlib.sha256(prompt.encode()).hexdigest()}}
        except Exception as exc:
            LOGGER.exception('LocalDeterministicClient.generate failed')
            return {'text': 'error', 'meta': {'error': str(exc)}}

    def generate_batch(self, prompts: list, max_tokens: int | None = None, tenant_id: str | None = None, overrides: Dict[str, Any] | None = None, model: str | None = None) -> list:
        """Deterministic batch — returns one result per prompt in input order."""
        return [
            self.generate(p, max_tokens=max_tokens or 512, tenant_id=tenant_id, overrides=overrides, model=model)
            for p in prompts
        ]

    def stream_generate(self, prompt: str, max_tokens: int = 512, tenant_id: str | None = None):
        # yield small chunks deterministically
        text = self._deterministic_text(prompt, max_tokens)
        # split into pseudo-token fragments
        size = 128
        for i in range(0, len(text), size):
            frag = text[i:i+size]
            yield {'text': frag, 'meta': {'provider': self.provider, 'offset': i}}

    def reserve_tenant_budget(self, tenant_id: str, cost: float) -> bool:
        if not tenant_id:
            return True
        # allow unlimited in tests unless explicit env set
        env_key = f'T2_BUDGET_{tenant_id.upper()}'
        forced = os.getenv(env_key)
        if forced is not None:
            try:
                allowed = float(forced)
                if cost > allowed:
                    return False
            except Exception:
                pass
        # otherwise allow and record a naive ledger
        self._tenant_budget[tenant_id] = self._tenant_budget.get(tenant_id, 0.0) - float(cost or 0.0)
        return True


try:
    from src.core.config.llm_settings_store import load_settings
except Exception:
    # Fallback when configuration store module is not present during tests/dev
    def load_settings():
        return {}

try:
    import requests
except Exception:  # pragma: no cover - fallback when requests missing
    requests = None

logger = logging.getLogger(__name__)


class LLMClient(BaseLLMClient):
    """Lightweight LLM client wrapper with timeout, retry, mock and token cap support.

    Configure behavior via env vars:
    - LLM_MOCK=1 -> returns canned responses from tests/fixtures/llm_mock.json
    - LLM_TIMEOUT_SECONDS (default 10)
    - LLM_MAX_TOKENS (default 1024)
    - LLM_RETRIES (default 2)
    """

    def __init__(self, overrides: Optional[Dict[str, Any]] = None):
        self.mock = os.getenv('LLM_MOCK','0').lower() in {'1','true','yes'}
        try:
            self.timeout = int(os.getenv('LLM_TIMEOUT_SECONDS','10') or 10)
        except Exception:
            self.timeout = 10
        try:
            self.max_tokens = int(os.getenv('LLM_MAX_TOKENS','1024') or 1024)
        except Exception:
            self.max_tokens = 1024
        try:
            self.retries = int(os.getenv('LLM_RETRIES','2') or 2)
        except Exception:
            self.retries = 2

        overrides = overrides or {}
        # Preload mock responses if requested
        self._mock_data = None
        if self.mock:
            try:
                base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
                path = os.path.join(base, 'tests', 'fixtures', 'llm_mock.json')
                with open(path, 'r', encoding='utf-8') as fh:
                    self._mock_data = json.load(fh)
            except Exception as e:
                logger.warning('LLM mock enabled but failed to load fixture: %s', e)
        
        try:
            stored_settings = load_settings()
        except Exception:
            stored_settings = {}
        self._stored_settings = stored_settings

        # Provider keys (env first, then persisted settings)
        self.openai_key = os.getenv('OPENAI_API_KEY')
        self.anthropic_key = os.getenv('ANTHROPIC_API_KEY')
        if not self.openai_key and stored_settings.get('openai_api_key'):
            self.openai_key = stored_settings['openai_api_key']
            os.environ.setdefault('OPENAI_API_KEY', self.openai_key)
        if not self.anthropic_key and stored_settings.get('anthropic_api_key'):
            self.anthropic_key = stored_settings['anthropic_api_key']
            os.environ.setdefault('ANTHROPIC_API_KEY', self.anthropic_key)
        
        # Attempt to import provider SDKs (optional)
        try:
            import openai
            self._openai = openai
        except Exception:
            self._openai = None
        try:
            import anthropic
            self._anthropic = anthropic
        except Exception:
            self._anthropic = None
        
        # Cost ledger integration (optional)
        try:
            from src.core.metrics.cost_ledger import CostLedger
            self._cost_ledger = CostLedger.get_instance()
        except Exception:
            # Provide a tiny in-memory fallback ledger for tests/dev
            class _FallbackLedger:
                def __init__(self):
                    self._costs = {}
                def add_cost(self, key, amount):
                    self._costs[key] = self._costs.get(key, 0.0) + float(amount)
                def get_cost(self, key):
                    return self._costs.get(key, 0.0)
            self._cost_ledger = _FallbackLedger()

        # Simple per-tenant circuit-breaker state (in-memory)
        self._tenant_budget = {}  # tenant_id -> consumed_cost
        try:
            self._tenant_budget_limit = float(os.getenv('LLM_TENANT_BUDGET', '100.0'))
        except Exception:
            self._tenant_budget_limit = 100.0
        # breaker state and locks
        self._breaker_state = {}
        self._breaker_lock = threading.Lock()
        try:
            self._breaker_failure_threshold = int(os.getenv('LLM_BREAKER_FAILURE_THRESHOLD', '5'))
        except Exception:
            self._breaker_failure_threshold = 5
        try:
            self._breaker_trip_seconds = float(os.getenv('LLM_BREAKER_TRIP_SECONDS', '60'))
        except Exception:
            self._breaker_trip_seconds = 60.0
        try:
            self._tenant_soft_threshold = float(os.getenv('LLM_TENANT_SOFT_THRESHOLD', '0.9'))
        except Exception:
            self._tenant_soft_threshold = 0.9
        # optional metrics emitter (use cost_tracker if available)
        try:
            from src.artifact.cost_tracker import record_llm_tokens, COST_STATE
            self._record_llm_tokens = record_llm_tokens
            self._metrics_state = COST_STATE
        except Exception:
            self._record_llm_tokens = None
            self._metrics_state = None
        # Optional external metrics backend: prometheus or statsd
        self._metrics_backend = os.getenv('LLM_METRICS_BACKEND','').lower()
        self._metrics_client = None
        if self._metrics_backend == 'statsd':
            try:
                from statsd import StatsClient
                self._metrics_client = StatsClient()
            except Exception:
                self._metrics_client = None
        elif self._metrics_backend == 'prometheus':
            try:
                from prometheus_client import Counter
                # simple counters for warnings/trips
                self._prom_warnings = Counter('llm_warnings_total','LLM warnings')
                self._prom_trips = Counter('llm_trips_total','LLM trips')
                self._metrics_client = True
            except Exception:
                self._metrics_client = None

        # Provider selection logic:
        # - If LLM_PROVIDER set, respect it.
        # - Otherwise prefer Ollama when no managed API keys are present (OpenAI/Anthropic),
        #   or when an Ollama host is configured.
        provider_hint = (os.getenv('LLM_PROVIDER') or '').strip() or None
        if provider_hint:
            base_provider = provider_hint
        else:
            # prefer Ollama if an Ollama host exists or no managed keys are configured
            has_managed_keys = bool(self.openai_key or self.anthropic_key or stored_settings.get('openai_api_key') or stored_settings.get('anthropic_api_key'))
            if stored_settings.get('ollama_base_url') or os.getenv('OLLAMA_HOST') or not has_managed_keys:
                base_provider = 'ollama'
            else:
                base_provider = 'openai'
        self.provider = base_provider.lower()
        # Runtime environment must win over persisted UI settings. In Docker,
        # config/llm_settings.json may contain a host-local 127.0.0.1 URL that
        # is valid on Windows but invalid inside the container.
        raw_ollama_host = os.getenv('OLLAMA_HOST') or os.getenv('OLLAMA_URL') or stored_settings.get('ollama_base_url') or 'http://localhost:11434'
        self.ollama_host = raw_ollama_host.rstrip('/')
        self.ollama_model = os.getenv('OLLAMA_MODEL') or os.getenv('LLM_MODEL') or stored_settings.get('ollama_model') or 'qwen3:14b'
        try:
            # Allow explicit per-provider timeout or fall back to general timeout
            self.ollama_timeout = float(os.getenv('OLLAMA_TIMEOUT_SECONDS') or os.getenv('LLM_TIMEOUT_SECONDS') or self.timeout)
        except Exception:
            self.ollama_timeout = float(self.timeout)
        # Optional interactive-model fallback for fast Tier-1/Tier-2 summaries
        # If set, short prompts will be sent to this smaller model to reduce latency.
        self.interactive_model = stored_settings.get('interactive_model') or os.getenv('INTERACTIVE_MODEL')
        try:
            self.interactive_prompt_token_threshold = int(os.getenv('INTERACTIVE_PROMPT_TOKEN_THRESHOLD', '200') or 200)
        except Exception:
            self.interactive_prompt_token_threshold = 200
        # Scale timeout based on model size: 30b+ → 300s, 14b+ → 180s, any :Nb → 120s
        try:
            if isinstance(self.ollama_model, str) and not (os.getenv('OLLAMA_TIMEOUT_SECONDS') or os.getenv('LLM_TIMEOUT_SECONDS')):
                m = re.search(r':(\d+)b', self.ollama_model)
                if m:
                    gb = int(m.group(1))
                    if gb >= 30:
                        self.ollama_timeout = max(self.ollama_timeout, 300.0)
                    elif gb >= 14:
                        self.ollama_timeout = max(self.ollama_timeout, 180.0)
                    else:
                        self.ollama_timeout = max(self.ollama_timeout, 120.0)
        except Exception:
            pass
        self.ollama_enabled = (self.provider == 'ollama') or bool(os.getenv('OLLAMA_HOST') or stored_settings.get('ollama_base_url'))
        self.ollama_reachable = False
        self._ollama_session = None
        if self.ollama_enabled:
            if requests is None:
                logger.warning('Ollama provider requested but requests library is missing; disabling Ollama mode')
                self.ollama_enabled = False
            else:
                self._ollama_session = requests.Session()
                # Probe models and optionally auto-select a model if the configured one is not available
                if os.getenv('OLLAMA_PROBE_ON_START', '1').lower() in {'1','true','yes'}:
                    try:
                        # quick probe for version and model list
                        ok = self._probe_ollama()
                        self.ollama_reachable = bool(ok)
                        if ok:
                            # fetch available models and auto-select if mismatch
                            try:
                                r = self._ollama_session.get(f"{self.ollama_host}/v1/models", timeout=min(5, max(2, float(self.ollama_timeout))))
                                if r.status_code == 200:
                                    data = r.json()
                                    items = data.get('data') or data.get('models') or []
                                    model_ids = [m.get('id') or m.get('model') for m in items if isinstance(m, dict)]
                                    # If configured model not present, pick the first available model
                                    if model_ids:
                                        if self.ollama_model not in model_ids:
                                            logger.warning('Configured Ollama model "%s" not found in host models; auto-selecting "%s"', self.ollama_model, model_ids[0])
                                            self.ollama_model = model_ids[0]
                                        logger.info('Ollama models available: %s', model_ids)
                                        # Re-run timeout heuristic based on the resolved model name
                                        try:
                                            if isinstance(self.ollama_model, str) and not os.getenv('OLLAMA_TIMEOUT_SECONDS'):
                                                m2 = re.search(r':(\d+)b', self.ollama_model)
                                                if m2:
                                                    gb2 = int(m2.group(1))
                                                    if gb2 >= 30:
                                                        self.ollama_timeout = max(self.ollama_timeout, 300.0)
                                                    elif gb2 >= 14:
                                                        self.ollama_timeout = max(self.ollama_timeout, 180.0)
                                                    else:
                                                        self.ollama_timeout = max(self.ollama_timeout, 120.0)
                                                    logger.info('Adjusted ollama_timeout to %s due to model %s', self.ollama_timeout, self.ollama_model)
                                        except Exception:
                                            pass
                            except Exception as e:
                                logger.warning('Failed to query Ollama models list: %s', e)
                    except Exception:
                        # probe logic already logs warnings inside _probe_ollama
                        pass
                # log resolved provider and model for operators
                logger.info('LLMClient startup: provider=%s ollama_enabled=%s ollama_host=%s ollama_model=%s timeout=%s', self.provider, self.ollama_enabled, self.ollama_host, self.ollama_model, self.ollama_timeout)

    def _enforce_token_cap(self, prompt: str, max_tokens: Optional[int]) -> int:
        # Check prompt input size against MAX_PROMPT_WORDS (default 6000).
        # max_tokens controls OUTPUT length — do NOT compare prompt words against it.
        est = len(prompt.split())
        try:
            prompt_word_limit = int(os.getenv('MAX_PROMPT_WORDS', '6000'))
        except Exception:
            prompt_word_limit = 6000
        if est > prompt_word_limit:
            raise ValueError(f'Prompt size {est} words exceeds context limit {prompt_word_limit}')
        return est

    def reserve_tenant_budget(self, tenant_id: str, amount: float) -> bool:
        """Attempt to reserve budget for a tenant atomically. Returns True on success."""
        try:
            with self._breaker_lock:
                consumed = self._tenant_budget.get(tenant_id, 0.0)
                limit = float(os.getenv('LLM_TENANT_BUDGET', str(self._tenant_budget_limit)))
                if consumed + float(amount) > limit:
                    return False
                # reserve by incrementing consumed amount; caller responsible for finalization
                self._tenant_budget[tenant_id] = consumed + float(amount)
                return True
        except Exception:
            return False

    def release_tenant_budget(self, tenant_id: str, amount: float) -> None:
        """Release previously reserved budget (best-effort)."""
        try:
            with self._breaker_lock:
                consumed = self._tenant_budget.get(tenant_id, 0.0)
                self._tenant_budget[tenant_id] = max(0.0, consumed - float(amount))
        except Exception:
            pass

    def stream_generate(self, prompt: str, max_tokens: Optional[int] = None, tenant_id: str | None = None, overrides: Optional[Dict[str, Any]] = None, model: str = 'gpt-like', **kwargs):
        """Generator that yields streaming token fragments (dicts). For mock mode yields the full mock text as a single token chunk.

        Yields dicts like {'text': 'token fragment', 'meta': {...}}
        """
        if tenant_id is None and kwargs and isinstance(kwargs, dict):
            tenant_id = kwargs.get('tenant_id')
        # For mock mode, return the mock response as a single event for simplicity
        if self.mock:
            resp = self._mock_response(prompt)
            text = resp.get('text') if isinstance(resp, dict) else str(resp)
            # naive chunking: yield slices of 128 chars
            for i in range(0, len(text), 128):
                yield {'text': text[i:i+128], 'meta': {'mock': True}}
            return

        # For Ollama/OpenAI etc. streaming, implement provider-specific streaming here
        # As a fallback, generate a single response and yield it
        resp = self.generate(prompt, max_tokens=max_tokens, tenant_id=tenant_id, overrides=overrides, model=model, **kwargs)
        text = resp.get('text') if isinstance(resp, dict) else str(resp)
        for i in range(0, len(text), 128):
            yield {'text': text[i:i+128], 'meta': resp.get('meta', {})}

    def _mock_response(self, prompt: str) -> Dict[str, Any]:
        if not self._mock_data:
            return {'text': 'mocked response', 'model': 'mock-model', 'meta': {}}
        # simple mapping: find an entry where 'contains' matches prompt
        for entry in self._mock_data.get('responses', []):
            if entry.get('contains') and entry.get('contains') in prompt:
                return entry.get('response')
        return self._mock_data.get('default') or {'text': 'mocked default', 'model': 'mock-model', 'meta': {}}

    def _probe_ollama(self) -> bool:
        if not self._ollama_session:
            self.ollama_reachable = False
            return False
        try:
            resp = self._ollama_session.get(f"{self.ollama_host}/api/version", timeout=self.ollama_timeout)
            resp.raise_for_status()
            self.ollama_reachable = True
            return True
        except Exception as exc:
            logger.warning('Ollama probe failed: %s', exc)
            self.ollama_reachable = False
            return False

    def _ollama_generate(
        self,
        prompt: str,
        max_tokens: Optional[int],
        model_override: Optional[str] = None,
        *,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        if not self._ollama_session:
            raise RuntimeError('ollama_session_unavailable')
        # Disable thinking mode for qwen3/deepseek-r1 when prompt starts with /no_think.
        # This skips the CoT reasoning phase, giving 5-10x faster responses for structured output.
        options: dict = {'num_predict': max_tokens or self.max_tokens}
        selected_model = model_override or self.ollama_model
        # NOTE: format=json is intentionally NOT set here.
        # Ollama's JSON grammar mode combined with think=False causes qwen3/deepseek-r1
        # to emit degenerate {} responses instead of the expected structured payload.
        # _parse_prefill_json already handles robust extraction (think-tag stripping,
        # markdown fence removal, repair, and {.*} fallback regex), so grammar-mode
        # is not needed and causes more failures than it prevents.
        payload = {
            'model': selected_model,
            'prompt': prompt,
            'stream': False,
            'options': options,
        }
        # think=False must be at top level (not inside options) for qwen3/deepseek-r1.
        if prompt.lstrip().startswith('/no_think') or any(m in selected_model for m in ('qwen3', 'deepseek-r1')):
            payload['think'] = False
        request_timeout = float(timeout if timeout is not None else self.ollama_timeout)
        with GLOBAL_LLM_LIMITER.acquire(label='ollama_generate') as gate:
            resp = self._ollama_session.post(f"{self.ollama_host}/api/generate", json=payload, timeout=request_timeout)
        resp.raise_for_status()
        data = resp.json()
        text = data.get('response') or data.get('output') or ''
        return {
            'text': text,
            'model': data.get('model') or selected_model,
            'meta': {
                'provider': 'ollama',
                'requested_model': selected_model,
                'eval_count': data.get('eval_count'),
                'total_duration_ms': data.get('total_duration'),
                'queue_wait_s': gate.get('wait_s'),
                'llm_concurrency_limit': gate.get('limit'),
            },
        }

    def _ollama_generate_with_host(self, host: str, model: Optional[str], prompt: str, max_tokens: Optional[int], generate_path: Optional[str] = None) -> Dict[str, Any]:
        """Call a specific Ollama host (overrides) for a single request.

        Tries multiple candidate endpoints (provided path, then /api/generate, then /v1/generate)
        with short timeouts and logs attempts so failures are visible during debugging.
        """
        if requests is None:
            raise RuntimeError('requests_library_missing')
        host = (host or '').rstrip('/')
        candidates = []
        if generate_path:
            # allow generate_path to be '/api/generate' or 'api/generate' etc.
            p = generate_path if generate_path.startswith('/') else f'/{generate_path}'
            candidates.append(f"{host}{p}")
        candidates.extend([f"{host}/api/generate", f"{host}/v1/generate"])

        payload = {
            'model': model or self.ollama_model,
            'prompt': prompt,
            'stream': False,
            'options': {'num_predict': max_tokens or self.max_tokens},
        }
        # think=False at top level for qwen3/deepseek-r1 to suppress CoT output.
        _m = model or self.ollama_model or ''
        if prompt.lstrip().startswith('/no_think') or any(tok in _m for tok in ('qwen3', 'deepseek-r1')):
            payload['think'] = False
        # short timeout for override attempts to surface failures quickly
        # Allow more generous per-attempt timeouts for larger models and local Ollama instances.
        try:
            base_timeout = float(self.ollama_timeout or 10)
        except Exception:
            base_timeout = 10.0
        attempt_timeout = min(10.0, max(3.0, base_timeout))
        last_exc = None
        saw_timeout_on_api_generate = False
        for url in candidates:
            for attempt in range(1, 3):
                try:
                    logger.info('Ollama override attempt %s -> %s (attempt %d)', prompt[:40].replace('\n',' '), url, attempt)
                    try:
                        with GLOBAL_LLM_LIMITER.acquire(label='ollama_override') as gate:
                            resp = sess.post(url, json=payload, timeout=attempt_timeout)
                    except Exception as e:
                        # detect read timeout specifically for api/generate
                        if url.endswith('/api/generate'):
                            try:
                                if requests and hasattr(requests.exceptions, 'ReadTimeout') and isinstance(e, requests.exceptions.ReadTimeout):
                                    saw_timeout_on_api_generate = True
                            except Exception:
                                pass
                        logger.warning('Ollama override POST to %s failed on attempt %d: %s', url, attempt, e)
                        last_exc = e
                        continue
                    # record response status and content for debugging
                    status = getattr(resp, 'status_code', None)
                    text = ''
                    try:
                        data = resp.json()
                        text = data.get('response') or data.get('output') or ''
                    except Exception:
                        text = (resp.text or '')[:400]
                    logger.info('Ollama override response from %s status=%s body_preview=%s', url, status, str(text)[:200])
                    resp.raise_for_status()
                    data = resp.json()
                    text = data.get('response') or data.get('output') or ''
                    return {
                        'text': text,
                        'model': data.get('model') or (model or self.ollama_model),
                        'meta': {
                            'provider': 'ollama',
                            'eval_count': data.get('eval_count'),
                            'total_duration_ms': data.get('total_duration'),
                            'queue_wait_s': gate.get('wait_s'),
                            'llm_concurrency_limit': gate.get('limit'),
                        },
                    }
                except Exception as exc:
                    # log exception and try next attempt / endpoint
                    logger.exception('Ollama override exception for %s on %s attempt %d: %s', model or self.ollama_model, url, attempt, exc)
                    last_exc = exc
                    continue

        # Last-resort: if we saw timeouts for /api/generate but host root and /api/version are reachable,
        # try a single longer-timeout POST to /api/generate (accounts for cold-start or heavy model load).
        if saw_timeout_on_api_generate:
            try:
                root_ok = False
                ver_ok = False
                try:
                    rroot = sess.get(f"{host}/", timeout=2)
                    root_ok = rroot.status_code == 200
                except Exception:
                    root_ok = False
                try:
                    rver = sess.get(f"{host}/api/version", timeout=2)
                    ver_ok = rver.status_code == 200
                except Exception:
                    ver_ok = False

                logger.info('Ollama override health quick-check root=%s version=%s', root_ok, ver_ok)
                if root_ok or ver_ok:
                    # Final retry with a generous timeout for heavy models / cold starts
                    try:
                        long_timeout = max(120, float(self.ollama_timeout or 60))
                    except Exception:
                        long_timeout = max(120, 60)
                    final_url = f"{host}/api/generate"
                    logger.info('Ollama override final retry to %s with timeout=%s', final_url, long_timeout)
                    with GLOBAL_LLM_LIMITER.acquire(label='ollama_override_final') as gate:
                        resp = sess.post(final_url, json=payload, timeout=long_timeout)
                    resp.raise_for_status()
                    data = resp.json()
                    text = data.get('response') or data.get('output') or ''
                    return {
                        'text': text,
                        'model': data.get('model') or (model or self.ollama_model),
                        'meta': {
                            'provider': 'ollama',
                            'eval_count': data.get('eval_count'),
                            'total_duration_ms': data.get('total_duration'),
                            'queue_wait_s': gate.get('wait_s'),
                            'llm_concurrency_limit': gate.get('limit'),
                        },
                    }
            except Exception as exc:
                logger.exception('Ollama final long-timeout retry failed: %s', exc)
                last_exc = exc

        # if we reach here, all attempts failed
        # Instead of raising, surface a clear error for callers and include a fallback hint
        raise RuntimeError(f'ollama_override_failed: last_exc={last_exc}')

    def generate(self, prompt: str, max_tokens: Optional[int] = None, tenant_id: str | None = None, overrides: Optional[Dict[str, Any]] = None, model: str = 'gpt-like', **kwargs) -> Dict[str, Any]:
        """Generate a text response. Returns dict with keys: text, model, meta (includes timing+tokens).
        May raise ValueError for prompt caps or RuntimeError on repeated failures.
        """
        overrides_dict: Dict[str, Any] = {}
        if kwargs and isinstance(kwargs, dict):
            raw_overrides = kwargs.get('overrides')
            if isinstance(raw_overrides, dict):
                overrides_dict.update(raw_overrides)
        if overrides:
            overrides_dict.update(overrides)
        request_timeout: Optional[float] = None
        if "timeout" in overrides_dict or "ollama_timeout" in overrides_dict:
            try:
                request_timeout = float(overrides_dict.get("ollama_timeout") or overrides_dict.get("timeout"))
            except Exception:
                request_timeout = None
        attempt_count = self.retries + 1
        if "retries" in overrides_dict:
            try:
                attempt_count = max(1, int(overrides_dict.get("retries")) + 1)
            except Exception:
                attempt_count = self.retries + 1
        try:
            if overrides_dict:
                logger.info('LLMClient.generate called with overrides=%s', {k: str(v)[:200] for k, v in overrides_dict.items()})
        except Exception:
            pass
        start = time.time()
        # If caller provided a persona prompt, prefer explicit kwarg, then check overrides.
        try:
            persona_fragment = None
            if isinstance(kwargs, dict) and 'persona_prompt' in kwargs:
                persona_fragment = kwargs.get('persona_prompt')
            elif overrides_dict and 'persona_prompt' in overrides_dict:
                persona_fragment = overrides_dict.get('persona_prompt')
            if persona_fragment:
                try:
                    prompt = f"{persona_fragment}\n\n{prompt}"
                except Exception:
                    # fall back to original prompt if formatting fails
                    pass
        except Exception:
            pass
        self._enforce_token_cap(prompt, max_tokens)

        if tenant_id is None and kwargs and isinstance(kwargs, dict):
            tenant_id = kwargs.get('tenant_id')
        provider_hint = kwargs.get('provider') if kwargs and isinstance(kwargs, dict) else None
        requested_ollama_model = (
            overrides_dict.get('ollama_model')
            or overrides_dict.get('ollama_model_name')
            or (
                model
                if isinstance(model, str)
                and model
                and model != 'gpt-like'
                and not model.lower().startswith('gpt')
                else None
            )
        )

        # Circuit-breaker: if tripped, short-circuit
        if tenant_id:
            with self._breaker_lock:
                state = self._breaker_state.get(tenant_id)
                if state:
                    tr_until = state.get('tripped_until', 0)
                    if tr_until and time.time() < tr_until:
                        return {'error': 'circuit_breaker_tripped', 'tenant_id': tenant_id}
            # check budget threshold and trip if exceeded
            consumed = self._tenant_budget.get(tenant_id, 0.0)
            if consumed >= self._tenant_budget_limit:
                with self._breaker_lock:
                    self._breaker_state[tenant_id] = {
                        'failures': self._breaker_failure_threshold,
                        'tripped_until': time.time() + self._breaker_trip_seconds,
                    }
                return {'error': 'tenant_cost_threshold_exceeded', 'tenant_id': tenant_id}

        last_exc = None
        for attempt in range(attempt_count):
            try:
                if self.mock:
                    resp = self._mock_response(prompt)
                    elapsed = time.time() - start
                    # record estimated cost for mock responses as well
                    try:
                        if self._cost_ledger:
                            est_cost = (len(prompt.split()) + (max_tokens or 0)) * 0.000001
                            # prefer add_cost for global counters
                            if hasattr(self._cost_ledger, 'add_cost'):
                                self._cost_ledger.add_cost('llm_mock', est_cost)
                            if tenant_id:
                                new_budget = self._tenant_budget.get(tenant_id, 0.0) + est_cost
                                self._tenant_budget[tenant_id] = new_budget
                                # persist budget via set_budget if available
                                try:
                                    if hasattr(self._cost_ledger, 'set_budget'):
                                        self._cost_ledger.set_budget(f'tenant_budget:{tenant_id}', new_budget)
                                    elif hasattr(self._cost_ledger, 'add_cost'):
                                        self._cost_ledger.add_cost(f'tenant_budget:{tenant_id}', new_budget)
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    # reset breaker on success
                    if tenant_id:
                        with self._breaker_lock:
                            self._breaker_state.pop(tenant_id, None)
                    return {
                        'text': resp.get('text') if isinstance(resp, dict) else str(resp),
                        'model': resp.get('model', model) if isinstance(resp, dict) else model,
                        'meta': {'mock': True, 'elapsed_s': elapsed, 'prompt_len': len(prompt.split())}
                    }

                # Respect per-request overrides for Ollama host/model even when Ollama not globally enabled
                if overrides_dict:
                    ollama_host = overrides_dict.get('ollama_host') or overrides_dict.get('ollama_base_url')
                    ollama_model = overrides_dict.get('ollama_model') or overrides_dict.get('ollama_model_name')
                    generate_path = overrides_dict.get('ollama_generate_path') or overrides_dict.get('ollama_generate')
                    if ollama_host:
                        # If the override path fails, propagate the exception so callers can handle/report it.
                        resp = self._ollama_generate_with_host(ollama_host, ollama_model or None, prompt, max_tokens or self.max_tokens, generate_path=generate_path)
                        elapsed = time.time() - start
                        meta = resp.get('meta') or {}
                        meta['elapsed_s'] = elapsed
                        resp['meta'] = meta
                        try:
                            if self._cost_ledger:
                                est_cost = (len(prompt.split()) + (max_tokens or 0)) * 0.0000005
                                if hasattr(self._cost_ledger, 'add_cost'):
                                    self._cost_ledger.add_cost('llm_ollama', est_cost)
                        except Exception:
                            pass
                        return resp
                if self.ollama_enabled and (self.provider == 'ollama' or (provider_hint or '').lower() == 'ollama'):
                    # If an interactive fallback model is configured and the prompt is small,
                    # prefer that smaller model to reduce cold-start/latency for interactive flows.
                    try:
                        prompt_len = len(prompt.split())
                    except Exception:
                        prompt_len = 0
                    if self.interactive_model and request_timeout is None and (prompt_len <= int(self.interactive_prompt_token_threshold)) and not requested_ollama_model and not overrides_dict.get('ollama_host'):
                        try:
                            resp = self._ollama_generate_with_host(self.ollama_host, self.interactive_model, prompt, max_tokens or self.max_tokens)
                        except Exception:
                            # fallback to default model if interactive model call fails
                            try:
                                if request_timeout is None:
                                    resp = self._ollama_generate(
                                        prompt,
                                        max_tokens or self.max_tokens,
                                        requested_ollama_model,
                                    )
                                else:
                                    resp = self._ollama_generate(
                                        prompt,
                                        max_tokens or self.max_tokens,
                                        requested_ollama_model,
                                        timeout=request_timeout,
                                    )
                            except Exception as exc_ollama:
                                # Log and mark last exception, then attempt a graceful fallback to deterministic client
                                logger.exception('Ollama generate failed, will attempt deterministic fallback: %s', exc_ollama)
                                # Best-effort deterministic summary so callers (and tests) can continue
                                try:
                                    det = LocalDeterministicClient()
                                    text = det._deterministic_text(prompt, max_tokens or self.max_tokens)
                                    elapsed = time.time() - start
                                    return {'text': text, 'model': det.provider, 'meta': {'provider': det.provider, 'fallback': True, 'elapsed_s': elapsed}}
                                except Exception:
                                    # if fallback also fails, re-raise the original Ollama exception to be handled by outer retry
                                    raise
                    else:
                        if request_timeout is None:
                            resp = self._ollama_generate(
                                prompt,
                                max_tokens or self.max_tokens,
                                requested_ollama_model,
                            )
                        else:
                            resp = self._ollama_generate(
                                prompt,
                                max_tokens or self.max_tokens,
                                requested_ollama_model,
                                timeout=request_timeout,
                            )
                    elapsed = time.time() - start
                    meta = resp.get('meta') or {}
                    meta['elapsed_s'] = elapsed
                    resp['meta'] = meta
                    try:
                        if self._cost_ledger:
                            est_cost = (len(prompt.split()) + (max_tokens or 0)) * 0.0000005
                            if hasattr(self._cost_ledger, 'add_cost'):
                                self._cost_ledger.add_cost('llm_ollama', est_cost)
                            if tenant_id:
                                new_budget = self._tenant_budget.get(tenant_id, 0.0) + est_cost
                                self._tenant_budget[tenant_id] = new_budget
                    except Exception:
                        pass
                    return resp

                # Real client path placeholder: implement provider-specific calls here
                # Provider-specific implementation
                if self.provider != 'ollama' and self._openai and self.openai_key and model.startswith('gpt'):
                    try:
                        self._openai.api_key = self.openai_key
                        resp = self._openai.ChatCompletion.create(model=model, messages=[{"role":"user","content":prompt}], max_tokens=max_tokens or 256, timeout=self.timeout)
                        text = resp.choices[0].message['content'] if hasattr(resp, 'choices') else str(resp)
                        elapsed = time.time() - start
                        # track cost if ledger available (estimate via prompt+resp length)
                        if self._cost_ledger:
                            try:
                                est_cost = (len(prompt.split()) + (max_tokens or 0)) * 0.000001
                                if hasattr(self._cost_ledger, 'add_cost'):
                                    self._cost_ledger.add_cost('llm_openai', est_cost)
                                if tenant_id:
                                    # update tenant budget (in-memory)
                                    new_budget = self._tenant_budget.get(tenant_id, 0.0) + est_cost
                                    self._tenant_budget[tenant_id] = new_budget
                                    # persist tenant budget to ledger if ledger supports it
                                    try:
                                        if hasattr(self._cost_ledger, 'set_budget'):
                                            self._cost_ledger.set_budget(f'tenant_budget:{tenant_id}', new_budget)
                                        elif hasattr(self._cost_ledger, 'add_cost'):
                                            self._cost_ledger.add_cost(f'tenant_budget:{tenant_id}', new_budget)
                                    except Exception:
                                        pass
                                    # if soft-threshold crossed, increment failure/warning counter
                                    try:
                                        limit = self._tenant_budget_limit
                                        if limit > 0 and (new_budget / limit) >= self._tenant_soft_threshold:
                                            state = self._breaker_state.get(tenant_id, {})
                                            state['warnings'] = state.get('warnings', 0) + 1
                                            self._breaker_state[tenant_id] = state
                                            # emit a metric for warnings (internal)
                                            try:
                                                if self._metrics_state is not None:
                                                    self._metrics_state.setdefault('llm_warnings', 0)
                                                    self._metrics_state['llm_warnings'] += 1
                                            except Exception:
                                                pass
                                            # external metrics
                                            try:
                                                if self._metrics_backend == 'statsd' and self._metrics_client:
                                                    self._metrics_client.incr('llm.warnings')
                                                if self._metrics_backend == 'prometheus' and getattr(self, '_prom_warnings', None) is not None:
                                                    self._prom_warnings.inc()
                                            except Exception:
                                                pass
                                            # auto-trip when warnings exceed failure threshold
                                            try:
                                                if state['warnings'] >= self._breaker_failure_threshold:
                                                    self._breaker_state[tenant_id] = {
                                                        'failures': state.get('warnings', 0),
                                                        'tripped_until': time.time() + self._breaker_trip_seconds,
                                                    }
                                                    # emit trip metric (internal)
                                                    try:
                                                        if self._metrics_state is not None:
                                                            self._metrics_state.setdefault('llm_trips', 0)
                                                            self._metrics_state['llm_trips'] += 1
                                                    except Exception:
                                                        pass
                                                    # external trip metrics
                                                    try:
                                                        if self._metrics_backend == 'statsd' and self._metrics_client:
                                                            self._metrics_client.incr('llm.trips')
                                                        if self._metrics_backend == 'prometheus' and getattr(self, '_prom_trips', None) is not None:
                                                            self._prom_trips.inc()
                                                    except Exception:
                                                        pass
                                            except Exception:
                                                pass
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                        # reset failure count on success
                        if tenant_id:
                            with self._breaker_lock:
                                self._breaker_state.pop(tenant_id, None)
                        return {'text': text, 'model': model, 'meta': {'elapsed_s': elapsed, 'prompt_len': len(prompt.split())}}
                    except Exception as e:
                        logger.warning('OpenAI call failed: %s', e)
                        raise
                if self._anthropic and self.anthropic_key and model.startswith('claude'):
                    try:
                        client = self._anthropic.Client(self.anthropic_key)
                        resp = client.completions.create(model=model, prompt=prompt, max_tokens_to_sample=max_tokens or 256)
                        text = getattr(resp, 'completion', str(resp))
                        elapsed = time.time() - start
                        if self._cost_ledger:
                            try:
                                est_cost = (len(prompt.split()) + (max_tokens or 0)) * 0.000001
                                if hasattr(self._cost_ledger, 'add_cost'):
                                    self._cost_ledger.add_cost('llm_anthropic', est_cost)
                                if tenant_id:
                                    new_budget = self._tenant_budget.get(tenant_id, 0.0) + est_cost
                                    self._tenant_budget[tenant_id] = new_budget
                                    try:
                                        if hasattr(self._cost_ledger, 'set_budget'):
                                            self._cost_ledger.set_budget(f'tenant_budget:{tenant_id}', new_budget)
                                        elif hasattr(self._cost_ledger, 'add_cost'):
                                            self._cost_ledger.add_cost(f'tenant_budget:{tenant_id}', new_budget)
                                    except Exception:
                                        pass
                                    try:
                                        limit = self._tenant_budget_limit
                                        if limit > 0 and (new_budget / limit) >= self._tenant_soft_threshold:
                                            state = self._breaker_state.get(tenant_id, {})
                                            state['warnings'] = state.get('warnings', 0) + 1
                                            self._breaker_state[tenant_id] = state
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                        # reset failure count on success
                        if tenant_id:
                            with self._breaker_lock:
                                self._breaker_state.pop(tenant_id, None)
                        return {'text': text, 'model': model, 'meta': {'elapsed_s': elapsed, 'prompt_len': len(prompt.split())}}
                    except Exception as e:
                        logger.warning('Anthropic call failed: %s', e)
                        raise
                
                # Fallback: emulate delay and simple reply
                time.sleep(min(0.05, self.timeout))
                elapsed = time.time() - start
                return {'text': f'Response for prompt (len {len(prompt)}).', 'model': model, 'meta': {'elapsed_s': elapsed, 'prompt_len': len(prompt.split())}}
            except Exception as exc:
                last_exc = exc
                logger.warning('LLM generate attempt %d failed: %s', attempt, exc)
                time.sleep(0.5 * (attempt + 1))
                continue

        raise RuntimeError(f'LLM generate failed after {attempt_count} attempts') from last_exc

    def generate_batch(self, prompts: list, max_tokens: Optional[int] = None, tenant_id: str | None = None, overrides: Optional[Dict[str, Any]] = None, model: str = 'gpt-like') -> list:
        """Concurrent batch wrapper around `generate` for multiple prompts.

        This helper issues multiple `generate` calls in parallel using a
        ThreadPool to avoid serial blocking when the provider can handle
        concurrent requests (e.g. local Ollama). It returns a list of
        response dictionaries in the same order as `prompts`.
        On per-item failure, the returned entry will be a dict with an
        `error` key describing the failure.
        """
        results = [None] * len(prompts)
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
        except Exception:
            # Fallback to serial generation
            out = []
            for p in prompts:
                try:
                    out.append(self.generate(p, max_tokens=max_tokens, tenant_id=tenant_id, overrides=overrides, model=model))
                except Exception as e:
                    out.append({'error': str(e)})
            return out

        # Limit concurrency to a small pool to avoid overwhelming local resources
        pool_size = min(8, max(1, len(prompts)))
        with ThreadPoolExecutor(max_workers=pool_size) as ex:
            future_map = {}
            for idx, p in enumerate(prompts):
                future = ex.submit(self.generate, p, max_tokens, tenant_id, overrides, model)
                future_map[future] = idx
            for fut in as_completed(future_map):
                idx = future_map.get(fut)
                try:
                    res = fut.result()
                    results[idx] = res
                except Exception as e:
                    results[idx] = {'error': str(e)}
        return results


def _select_default_client() -> BaseLLMClient:
    try:
        prov = os.getenv('LLM_PROVIDER', 'ollama').lower()
    except Exception:
        prov = 'local'
    # If test helpers are enabled or running under pytest, prefer deterministic local client
    test_mode = os.getenv('TEST_HELPERS_ENABLED','0').lower() in {'1','true','yes'} or bool(os.getenv('PYTEST_CURRENT_TEST')) or os.getenv('FAST_TEST_MODE','0').lower() in {'1','true','yes'}
    if test_mode:
        logger.info('LLM: test mode active; using LocalDeterministicClient')
        return LocalDeterministicClient()
    if prov in {'local', 'local-deterministic', 'mock'}:
        return LocalDeterministicClient()
    try:
        client = LLMClient()
        logger.info('LLM: initialized client provider=%s', getattr(client, 'provider', 'unknown'))
        return client
    except Exception as exc:
        LOGGER.warning('Failed to initialize LLM provider %s (%s); falling back to deterministic client', prov, exc)
        try:
            return LocalDeterministicClient()
        except Exception:
            # Last resort: raise so import-time failures surface for operator
            raise


# Module-level default client used by application code
DEFAULT_CLIENT: BaseLLMClient = _select_default_client()


def generate_summary(prompt: str, max_tokens: int = 256, tenant_id: str | None = None, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return DEFAULT_CLIENT.generate(prompt, max_tokens=max_tokens, tenant_id=tenant_id, overrides=overrides)


def get_client_status(client: BaseLLMClient | None = None) -> dict:
    c = client or DEFAULT_CLIENT
    provider = getattr(c, 'provider', 'unknown')
    ollama_enabled = bool(getattr(c, 'ollama_enabled', False))
    ollama_reachable = bool(getattr(c, 'ollama_reachable', False))
    openai_configured = bool(getattr(c, 'openai_key', None))
    anthropic_configured = bool(getattr(c, 'anthropic_key', None))
    available = (
        provider == 'local-deterministic'
        or (provider == 'ollama' and ollama_enabled and ollama_reachable)
        or (provider == 'openai' and openai_configured)
        or (provider == 'anthropic' and anthropic_configured)
    )
    return {
        'model': getattr(c, 'model', 'unknown'),
        'backend': type(c).__name__,
        'ready': True,
        'provider': provider,
        'requested_provider': provider,
        'environment': 'local' if provider in {'ollama', 'local-deterministic'} else 'remote',
        'available': available,
        'strict_provider': bool(getattr(c, 'strict_provider', False)),
        'fallback_active': provider == 'local-deterministic',
        'fallback_reason': 'local-deterministic fallback active' if provider == 'local-deterministic' else None,
        'local_deterministic_active': provider == 'local-deterministic',
        'client_class': type(c).__name__,
        'ollama_enabled': ollama_enabled,
        'ollama_host': getattr(c, 'ollama_host', None),
        'ollama_model': getattr(c, 'ollama_model', None),
        'ollama_reachable': ollama_reachable,
        'concurrency': llm_concurrency_status(),
        'openai_configured': openai_configured,
        'anthropic_configured': anthropic_configured,
    }


__all__ = ['DEFAULT_CLIENT', 'generate_summary', 'get_client_status', 'BaseLLMClient', 'LocalDeterministicClient', 'LLMClient']
