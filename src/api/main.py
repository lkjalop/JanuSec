"""Compatibility shim exposing the FastAPI `app` as src.api.main.app

Some tests import src.api.main; provide a tiny shim that re-exports
the canonical application object from src.api.app.
"""

from src.api.app import app

__all__ = ["app"]
