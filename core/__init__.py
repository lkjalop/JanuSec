"""
Compatibility shim for `core` package pointing to `src/core` so imports
like `import core.xxx` resolve from the repository source tree during tests.
"""
import os
_here = os.path.dirname(__file__)
_src_core = os.path.abspath(os.path.join(_here, '..', 'src', 'core'))
__path__ = [_src_core]
