# azure package shim for local test mappings
__all__ = []
"""Local azure package shim to ensure tests import our subpackages.

This file ensures the package is treated as a regular package and helps avoid
namespace package conflicts with installed 'azure' namespace packages.
"""
__path__ = __import__('pkgutil').extend_path(__path__, __name__)
__all__ = []
