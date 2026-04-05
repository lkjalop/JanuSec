"""Compatibility shim so imports like `import repositories.foo` resolve to `src/repositories/foo`.

This file adjusts the package __path__ at runtime to include the project's `src/repositories`
folder (if present). It keeps behavior safe when running from installed packages.
"""
from __future__ import annotations

import os
import pathlib

_this_dir = pathlib.Path(__file__).resolve().parent
_src_repos = _this_dir.parent / 'src' / 'repositories'
if _src_repos.exists():
    # Prepend to __path__ so normal imports (e.g., `import repositories.x`) find files
    # under src/repositories during local development and tests.
    __path__.insert(0, str(_src_repos))

__all__ = []
