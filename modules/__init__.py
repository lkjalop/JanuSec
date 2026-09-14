"""
Lightweight shim package to expose the repository's `src/modules`
folder as a top-level `modules` package.

This allows existing code that does `from modules.foo import Bar`
to continue working without changing imports across the codebase.

It inserts the repo's `src/modules` directory at the front of this
package's `__path__` so Python will load modules from there.
"""
import os

# Compute the path to the repo root and then to src/modules
_this_dir = os.path.dirname(__file__)
_repo_root = os.path.normpath(os.path.join(_this_dir, '..'))
_src_modules = os.path.normpath(os.path.join(_repo_root, 'src', 'modules'))

if os.path.isdir(_src_modules):
    # Prefer the repo's src/modules directory for imports like `modules.foo`.
    __path__.insert(0, _src_modules)
    # If the src/modules package has an __init__.py, execute it here so
    # symbols defined there (stubs) become available as `modules.X` and
    # `from modules import Y` works during tests and runtime.
    init_file = os.path.join(_src_modules, '__init__.py')
    if os.path.isfile(init_file):
        try:
            with open(init_file, 'r', encoding='utf-8') as fh:
                src = fh.read()
            # Execute the source in our package namespace so names are exported.
            exec(compile(src, init_file, 'exec'), globals())
        except Exception:
            # If execution fails, leave path inserted and rely on import-time
            # resolution via normal package loading.
            pass

__all__ = []
