"""Bridge utilities to run connector ingestion and yield normalized enrichment objects.

This module provides a small helper used by scheduled tasks or ad-hoc runners.
"""
from typing import Iterator
from src.adapters import get as get_connector


def ingest_vulns_from_connector(name: str, **connector_kwargs) -> Iterator[dict]:
    """Instantiate the named connector and yield mapped vulnerability artifacts.

    The connector class is expected to implement `list_vulns()` and
    `map_vuln_to_artifact(vuln)`.
    """
    ConnClass = get_connector(name)
    if ConnClass is None:
        raise RuntimeError(f'Connector not registered: {name}')
    conn = ConnClass(**connector_kwargs)
    for vuln in conn.list_vulns():
        yield conn.map_vuln_to_artifact(vuln)
"""Simple ingestion bridge for vulnerability connectors.

This module shows how to call a connector and produce normalized vulnerability
enrichment payloads that the rest of the ingestion pipeline can consume.
"""
from typing import Iterable, Dict, Any
from . import get


def ingest_vulns_from_connector(connector_name: str) -> Iterable[Dict[str, Any]]:
    conn_cls = get(connector_name)
    if not conn_cls:
        raise RuntimeError(f'Connector not registered: {connector_name}')
    # Expect either a class or a factory returning an instance
    conn = conn_cls if not callable(conn_cls) else conn_cls()
    for vuln in conn.list_vulns():
        mapped = conn.map_vuln_to_artifact(vuln)
        # Transform into pipeline-friendly enrichment object
        yield {
            'source': connector_name,
            'vuln_id': mapped.get('vuln_id'),
            'asset_id': mapped.get('asset_id'),
            'package': mapped.get('package'),
            'severity': mapped.get('severity'),
            'raw': mapped.get('raw'),
        }
