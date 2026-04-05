#!/usr/bin/env python
"""Validation script for factor taxonomy mappings.

Usage:
  python scripts/validate_factor_mappings.py

Outputs JSON summary of coverage and missing required keys for each factor.
Exits with non-zero status if issues exceed threshold (default: 0) unless
ALLOW_MISSING_SYNTHETIC=1 set.
"""
from __future__ import annotations
import json, os, sys
from typing import Any
from src.core.threat_modeling.factor_taxonomy import FACTOR_MAP_PUBLIC  # type: ignore
from src.core.threat_modeling.factor_schema import validate_factor_map

THRESHOLD = int(os.getenv('FACTOR_MAPPING_ISSUE_THRESHOLD','0') or 0)
ALLOW_SYNTHETIC = os.getenv('ALLOW_MISSING_SYNTHETIC','0').lower() in {'1','true','yes'}

summary = validate_factor_map(FACTOR_MAP_PUBLIC)
print(json.dumps(summary, indent=2))

issues = summary.get('issues') or []
if ALLOW_SYNTHETIC:
    # Filter out correlation/meta synthetic factors
    issues = [i for i in issues if not str(i.get('factor','')).startswith(('corr_','meta:'))]

if len(issues) > THRESHOLD:
    print(f"Validation failed: {len(issues)} mapping issues (threshold={THRESHOLD})", file=sys.stderr)
    sys.exit(1)
print("Validation passed.")
