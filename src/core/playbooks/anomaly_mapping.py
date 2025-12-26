"""Anomaly (system alert / factor) -> Playbook advisory mapping skeleton.

This is an early stub that returns advisory actions based on alert category.
Future: integrate with a DSL-defined catalog and tenant-specific enablement flags.
"""
from __future__ import annotations

from typing import Any, Dict, List

CATEGORY_PLAYBOOK: dict[str, list[str]] = {
    'queue': ['investigate-ingestion-capacity','scale-consumer-workers'],
    'drift': ['run-replay-sample','review-new-factor-frequency','update-baseline-distribution'],
    'latency': ['profile-hot-stages','check-db-latency','inspect-resource-saturation'],
    'embedding': ['inspect-model-endpoints','validate-provider-availability','consider-cache-layer'],
}

def advisory_for_alert(category: str) -> list[str]:
    return CATEGORY_PLAYBOOK.get(category, ['generic-triage'])

__all__ = ['advisory_for_alert']
