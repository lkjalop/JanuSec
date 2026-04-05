"""Scenario Taxonomy Versioning and Control Mapping.

Provides a stable version identifier for scenario semantics and a mapping from
scenario_id -> related security control references (CIS/NIST/ISO/PCI/SOC2).

This allows reports & APIs to declare which taxonomy version they were built
against, aiding comparability across upgrades.
"""
from __future__ import annotations

from typing import Dict, List

SCENARIO_TAXONOMY_VERSION = "2025.10.0"  # YYYY.MM.revision

# Minimal illustrative mapping; extend as scenarios expand.
SCENARIO_CONTROL_MAP: Dict[str, List[str]] = {
    # id -> list of control references (framework:section)
    'lateral_movement_candidate': ['CIS:6.2','NIST:AC-2','ISO27001:A.12.6','SOC2:CC6.6'],
    'encoded_powershell_execution': ['CIS:8.2','NIST:SI-4','ISO27001:A.12.4','PCI:10.2'],
    'office_spawn_shell': ['CIS:2.8','NIST:SI-3','ISO27001:A.8.7','SOC2:CC7.2','PCI:11.5'],
    'suspicious_temp_directory_execution': ['CIS:2.4','NIST:CM-6','ISO27001:A.12.2'],
}

__all__ = ['SCENARIO_TAXONOMY_VERSION','SCENARIO_CONTROL_MAP']
