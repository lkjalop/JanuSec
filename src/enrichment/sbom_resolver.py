"""SBOM (Software Bill of Materials) minimal component resolver.

This module provides a function to resolve a component (by name/version) to a CVE/OSV lookup key for enrichment.
"""
from typing import Dict, Any, Optional

def resolve_component(component: Dict[str, Any]) -> Optional[str]:
    """Given a component dict (with at least 'name' and 'version'), return a lookup key (e.g., purl or cpe) for CVE/OSV enrichment."""
    # Prefer purl if present
    if 'purl' in component:
        return component['purl']
    # Fallback: construct a simple key
    name = component.get('name')
    version = component.get('version')
    if name and version:
        return f"{name}@{version}"
    if name:
        return name
    return None
