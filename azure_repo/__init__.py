"""Local copy of repository-level azure artifacts to avoid colliding with
the installed `azure` distribution. Use `azure_repo.*` to reference code
here and avoid interfering with runtime imports of `azure` packages.
"""
__all__ = ["functions"]
