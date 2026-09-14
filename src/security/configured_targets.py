"""Resolve request selections to operator-controlled outbound targets."""
import json
import os


def configured_target(requested: str, setting: str) -> str:
    """Never pass a request-supplied URL or CLI target through to a sink.

    The environment contains a JSON array of explicitly approved full targets.
    An empty/malformed configuration denies all real operations.
    """
    try:
        targets = json.loads(os.environ.get(setting, "[]"))
    except (TypeError, ValueError):
        raise ValueError("Invalid outbound target configuration") from None
    if not isinstance(targets, list) or not all(isinstance(v, str) for v in targets):
        raise ValueError("Invalid outbound target configuration")
    for target in targets:
        if requested == target:
            if not target or target.startswith("-") or any(ord(c) < 32 for c in target):
                break
            return target
    raise ValueError("Target is not configured for real operations")


def configured_webhook(requested: str) -> str:
    from src.security.egress_guard import ssrf_check
    target = configured_target(requested, "JANUSEC_APPROVED_WEBHOOK_URLS")
    ok, _ = ssrf_check(target)
    if not ok:
        raise ValueError("Configured webhook violates outbound policy")
    return target
