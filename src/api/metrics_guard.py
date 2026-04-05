"""Utilities for safe tenant labeling and metric creation to limit cardinality.

Provides a tenant label mapping that supports whitelisting, sampling, and hashed buckets.
"""
from __future__ import annotations
import os
import hashlib
import random
from typing import Optional


def _parse_csv_env(name: str) -> list[str]:
    raw = os.getenv(name, '') or ''
    return [p.strip() for p in raw.split(',') if p.strip()]


def tenant_label_for(tenant: Optional[str]) -> str:
    """Return a safe tenant label string.

    Behavior order:
      1. If tenant is falsy -> 'default'
      2. If TENANT_METRICS_WHITELIST contains tenant -> return original tenant (safe)
      3. If TENANT_METRICS_SAMPLE_RATE > 0 and random() < sample -> return original tenant (sampled)
      4. If TENANT_METRICS_HASH_BUCKETS > 0 -> return 'b{n}' where n is hash bucket
      5. Else return 'other'

    This keeps the metric label cardinality bounded while letting a small set of tenants
    be recorded verbatim when explicitly whitelisted.
    """
    if not tenant:
        return 'default'
    tenant = str(tenant)
    # Whitelist exact tenants
    whitelist = _parse_csv_env('TENANT_METRICS_WHITELIST')
    if tenant in whitelist:
        # Truncate to reasonable length
        return tenant[:64]

    # Sampling
    try:
        sample = float(os.getenv('TENANT_METRICS_SAMPLE_RATE', '0') or 0.0)
    except Exception:
        sample = 0.0
    if sample > 0.0:
        try:
            r = random.random()
            if r < sample:
                return tenant[:64]
        except Exception:
            pass

    # Hashed buckets
    try:
        buckets = int(os.getenv('TENANT_METRICS_HASH_BUCKETS', '0') or 0)
    except Exception:
        buckets = 0
    if buckets and buckets > 0:
        # stable hash
        h = hashlib.sha1(tenant.encode('utf-8')).hexdigest()
        val = int(h[:8], 16) % buckets
        return f'b{val}'

    # Fallback coarse label
    return 'other'
