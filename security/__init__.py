"""
Compatibility shim for the `security` package used throughout the codebase.
This ensures imports like `import security.auth` will resolve to the modules
under `src/security` when running tests from the repository root.
"""
import os

# Use the `src/security` directory as the package path so submodule imports
# are resolved from the source tree rather than requiring an installed package.
_here = os.path.dirname(__file__)
_src_security = os.path.abspath(os.path.join(_here, '..', 'src', 'security'))
__path__ = [ _src_security ]
