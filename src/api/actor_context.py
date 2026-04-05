from contextvars import ContextVar
from typing import Optional
from contextlib import contextmanager

# ContextVar to hold the current actor identity for the running request
_actor_var: ContextVar[Optional[str]] = ContextVar('_actor_var', default=None)


def get_current_actor() -> Optional[str]:
    try:
        return _actor_var.get()
    except Exception:
        return None


@contextmanager
def set_current_actor(actor: Optional[str]):
    """Context manager that sets the current actor for the scope and resets it on exit."""
    token = _actor_var.set(actor)
    try:
        yield
    finally:
        try:
            _actor_var.reset(token)
        except Exception:
            pass
