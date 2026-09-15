"""
LLM Prompt Injection Guard (CB-6)
Sanitizes artifact rows and free-text before they are included in LLM prompts.
"""
from __future__ import annotations

import copy
import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

# Counter for Prometheus-style metrics (module-level, incremented on redaction)
INJECTION_ATTEMPTS: int = 0

# Master list of compiled injection patterns (case-insensitive)
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?', re.IGNORECASE),
    re.compile(r'\bact\s+as\b.{0,60}(?:jailbreak|DAN|evil|unrestricted)', re.IGNORECASE),
    re.compile(r'(?:^|\n)\s*SYSTEM\s*:', re.IGNORECASE | re.MULTILINE),
    re.compile(r'override\s+(?:all\s+)?(?:security|safety|content)\s+(?:policy|policies|filter)', re.IGNORECASE),
]

# Max field length allowed in the prompt (characters); longer values are truncated
_MAX_FIELD_LEN = int(os.getenv('LLM_PROMPT_MAX_FIELD_LEN', '4096'))
# Max total row JSON size (characters)
_MAX_ROW_LEN = int(os.getenv('LLM_PROMPT_MAX_ROW_LEN', '12000'))

_REDACT_MARKER = '[REDACTED:injection]'


def sanitize_text_for_llm(text: str, max_len: int = _MAX_FIELD_LEN) -> tuple[str, bool]:
    """Sanitize a single string value intended for inclusion in an LLM prompt.

    Returns:
        (sanitized_text, was_redacted) — was_redacted is True if any pattern fired.
    """
    if not isinstance(text, str):
        return text, False

    redacted = False
    result = text[:max_len]  # hard cap first

    for pattern in _INJECTION_PATTERNS:
        if pattern.search(result):
            result = pattern.sub(_REDACT_MARKER, result)
            redacted = True

    return result, redacted


def _sanitize_value(value: Any) -> tuple[Any, bool]:
    """Recursively sanitize a scalar or nested value."""
    if isinstance(value, str):
        return sanitize_text_for_llm(value)
    if isinstance(value, dict):
        new_dict: dict[str, Any] = {}
        any_redacted = False
        for k, v in value.items():
            sanitized, flag = _sanitize_value(v)
            new_dict[k] = sanitized
            any_redacted = any_redacted or flag
        return new_dict, any_redacted
    if isinstance(value, list):
        new_list: list[Any] = []
        any_redacted = False
        for item in value:
            sanitized, flag = _sanitize_value(item)
            new_list.append(sanitized)
            any_redacted = any_redacted or flag
        return new_list, any_redacted
    return value, False


def sanitize_row_for_llm(row: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy and sanitize all string leaf values in a row dict.

    Tracks globally how many injection attempts have been detected.
    Returns the sanitized copy (original is never mutated).
    """
    global INJECTION_ATTEMPTS

    if not isinstance(row, dict):
        return row

    sanitized, was_redacted = _sanitize_value(copy.deepcopy(row))

    if was_redacted:
        INJECTION_ATTEMPTS += 1
        logger.warning(
            'llm_prompt_guard: injection pattern detected and redacted in row (total_attempts=%d)',
            INJECTION_ATTEMPTS,
        )

    return sanitized  # type: ignore[return-value]


def get_injection_attempt_count() -> int:
    """Return the total number of injection attempts detected this process lifetime."""
    return INJECTION_ATTEMPTS
