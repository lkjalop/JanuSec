"""
Compatibility shim for `db` package to point to `src/db` during tests.
"""
import os
_here = os.path.dirname(__file__)
_src_db = os.path.abspath(os.path.join(_here, '..', 'src', 'db'))
__path__ = [_src_db]
