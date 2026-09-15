"""Early test-time site customization to avoid repo azure shadowing.

This module executes very early during Python startup in many test runners
and attempts to ensure installed site-packages are preferred over the
repository `azure/` folder.
"""
import sys
import os
import site

try:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    site_paths = []
    try:
        site_paths.extend(site.getsitepackages())
    except Exception:
        pass
    try:
        site_paths.append(site.getusersitepackages())
    except Exception:
        pass

    # Prepend site-packages paths to sys.path so installed azure is found first
    for p in reversed(site_paths):
        if p and os.path.isdir(p) and p not in sys.path:
            sys.path.insert(0, p)

    # Ensure repo root is after site-packages
    try:
        if repo_root in sys.path:
            sys.path.remove(repo_root)
        sys.path.append(repo_root)
    except Exception:
        pass
except Exception:
    pass
