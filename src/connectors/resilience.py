from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from src.integrations.polling_state import PollingStateStore


@dataclass
class RetryPolicy:
    attempts: int = 3
    base_sleep: float = 0.25
    max_sleep: float = 3.0
    circuit_failures: int = 3
    circuit_cooldown: int = 60


def _state_provider(provider: str, connector: str) -> str:
    safe_provider = f'{provider}-{connector}-runtime'
    return safe_provider.replace(':', '-').replace('/', '-')


def load_runtime_state(store: PollingStateStore, tenant_id: str, provider: str, connector: str) -> Dict[str, Any]:
    state = store.load_state(tenant_id, _state_provider(provider, connector))
    if not isinstance(state, dict):
        state = {}
    state.setdefault('consecutive_failures', 0)
    state.setdefault('circuit_open_until', 0)
    state.setdefault('last_error', None)
    state.setdefault('last_success_ts', None)
    state.setdefault('last_latency_ms', None)
    state.setdefault('last_duplicate_count', 0)
    return state


def save_runtime_state(store: PollingStateStore, tenant_id: str, provider: str, connector: str, state: Dict[str, Any]) -> None:
    store.save_state(tenant_id, _state_provider(provider, connector), state)


def is_circuit_open(state: Dict[str, Any], now: Optional[float] = None) -> bool:
    now = now or time.time()
    return float(state.get('circuit_open_until') or 0) > now


def execute_with_resilience(
    action: Callable[[], Any],
    *,
    store: PollingStateStore,
    tenant_id: str,
    provider: str,
    connector: str,
    policy: RetryPolicy | None = None,
) -> Any:
    policy = policy or RetryPolicy()
    state = load_runtime_state(store, tenant_id, provider, connector)
    now = time.time()
    if is_circuit_open(state, now):
        raise RuntimeError(f'circuit_open_until:{int(state["circuit_open_until"])}')
    last_error: str | None = None
    for attempt in range(policy.attempts):
        started = time.time()
        try:
            result = action()
            state['consecutive_failures'] = 0
            state['circuit_open_until'] = 0
            state['last_error'] = None
            state['last_success_ts'] = time.time()
            state['last_latency_ms'] = int((time.time() - started) * 1000)
            save_runtime_state(store, tenant_id, provider, connector, state)
            return result
        except Exception as exc:
            last_error = str(exc)
            state['consecutive_failures'] = int(state.get('consecutive_failures') or 0) + 1
            state['last_error'] = last_error
            if state['consecutive_failures'] >= policy.circuit_failures:
                state['circuit_open_until'] = int(time.time() + policy.circuit_cooldown)
            save_runtime_state(store, tenant_id, provider, connector, state)
            if attempt >= policy.attempts - 1:
                break
            sleep_for = min(policy.max_sleep, policy.base_sleep * (2 ** attempt)) + random.random() * 0.05
            time.sleep(sleep_for)
    raise RuntimeError(last_error or 'connector_execution_failed')
