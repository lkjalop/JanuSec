"""KEV (Known Exploited Vulnerabilities) and EPSS (Exploit Prediction Scoring System) ingestion and lookup scaffolding.

This module provides minimal interfaces for ingesting KEV and EPSS datasets and performing lookups for enrichment.
"""
import csv
import json
from typing import Dict, Any, Optional

_KEV_DB: Dict[str, Dict[str, Any]] = {}
_EPSS_DB: Dict[str, Dict[str, Any]] = {}

def ingest_kev_csv(path: str) -> int:
    """Ingest CISA KEV CSV file. Returns number of entries loaded."""
    count = 0
    with open(path, 'r', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            cve = row.get('cveID') or row.get('CVE')
            if cve:
                _KEV_DB[cve] = row
                count += 1
    return count

def ingest_epss_csv(path: str) -> int:
    """Ingest EPSS CSV file. Returns number of entries loaded."""
    count = 0
    with open(path, 'r', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            cve = row.get('cve') or row.get('CVE')
            if cve:
                _EPSS_DB[cve] = row
                count += 1
    return count

def kev_lookup(cve: str) -> Optional[Dict[str, Any]]:
    """Return KEV entry for CVE, if present."""
    return _KEV_DB.get(cve)

def epss_lookup(cve: str) -> Optional[Dict[str, Any]]:
    """Return EPSS entry for CVE, if present."""
    return _EPSS_DB.get(cve)
