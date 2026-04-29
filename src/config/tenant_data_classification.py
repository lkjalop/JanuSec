"""Tenant data classification config loader.

Loads per-tenant sensitivity/class mappings from YAML/JSON config.
Returns a TenantDataClassification instance that enrich_narrative() uses
for table-level sensitivity detection.

Tenant config YAML shape:
    data_classification:
      sensitivity_by_table:
        DB.SCHEMA.TABLE: crown_jewel
      classes_by_table:
        DB.SCHEMA.TABLE: [customer_pii, operational]
      extra_pii_patterns:
        - 'consignment_id'
      extra_restricted_schemas: []
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Lazy import — the schema module is in src/llm/
_TenantDataClassification = None


def _get_class():
    global _TenantDataClassification
    if _TenantDataClassification is None:
        from src.llm.cluster_narrator_v2_schema import TenantDataClassification
        _TenantDataClassification = TenantDataClassification
    return _TenantDataClassification


def _load_tenant_config_dict(tenant_id: str) -> Optional[dict]:
    """Load tenant config from the tenant_configs directory.

    Looks for:
      data/tenant_configs/{tenant_id}.json
      data/tenant_configs/{tenant_id}.yaml
    """
    base_dir = Path(os.getenv('TENANT_CONFIG_DIR', 'data/tenant_configs'))
    for ext in ('.json', '.yaml', '.yml'):
        path = base_dir / f'{tenant_id}{ext}'
        if path.is_file():
            try:
                if ext == '.json':
                    with open(path, 'r', encoding='utf-8') as f:
                        return json.load(f)
                else:
                    try:
                        import yaml
                        with open(path, 'r', encoding='utf-8') as f:
                            return yaml.safe_load(f)
                    except ImportError:
                        logger.debug('PyYAML not installed; skipping %s', path)
            except Exception as exc:
                logger.warning('Failed to load tenant config %s: %s', path, exc)
    return None


def load_for_tenant(tenant_id: str):
    """Load TenantDataClassification for a tenant, or None if not configured."""
    cfg = _load_tenant_config_dict(tenant_id)
    raw = (cfg or {}).get('data_classification')
    if not raw:
        return None
    cls = _get_class()
    return cls(raw)


__all__ = ['load_for_tenant']
