"""Non-related event separation between clusters.

The correlation engine may over-cluster events that share only infrastructure
(same IP, same subnet) but have no shared identity evidence — for example, a
helpdesk ticket touching a web server and an attacker scanning the same IP.

This module computes pairwise cluster similarity and flags cluster pairs that
are likely unrelated, reducing analyst false-positive burden.

Usage::
    from src.core.enrichment.cluster_separation import annotate_cluster_separation
    annotate_cluster_separation(clusters)  # mutates clusters in-place

Mutates each cluster with:
    cluster['separation']  — {cluster_id: {shared_accounts, shared_hosts,
                               shared_ips, only_infra_shared, likely_unrelated}}
    cluster['likely_isolated'] — True if this cluster has no strong binding
                                 to ANY other cluster (pure singleton in context)
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _normalize_set(items: Any) -> frozenset[str]:
    if isinstance(items, (list, tuple, set, frozenset)):
        return frozenset(str(x).lower() for x in items if x)
    return frozenset()


# ── Low-value pivot identifiers that don't constitute "real" correlation ──────
_LOW_VALUE_IPS = frozenset([
    '10.0.0.1', '192.168.0.1', '192.168.1.1', '172.16.0.1',  # default gateways
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',              # public DNS
    '0.0.0.0', '127.0.0.1', '::1',
])

_LOW_VALUE_DOMAINS = frozenset([
    'google.com', 'microsoft.com', 'windows.com', 'windowsupdate.com',
    'office.com', 'amazonaws.com', 'cloudfront.net',
    'ocsp.digicert.com', 'crl.microsoft.com', 'ctldl.windowsupdate.com',
])


def _is_low_value_ip(ip: str) -> bool:
    return ip.lower() in _LOW_VALUE_IPS


def _cluster_identifiers(cluster: dict) -> dict[str, frozenset[str]]:
    return {
        'accounts': _normalize_set(cluster.get('shared_accounts') or []),
        'hosts':    _normalize_set(cluster.get('shared_hosts') or []),
        'ips':      _normalize_set(
            [ip for ip in (cluster.get('shared_external_ips') or []) if not _is_low_value_ip(ip)]
        ),
        'resources': _normalize_set(cluster.get('shared_resources') or []),
        'mitre':    _normalize_set(cluster.get('top_mitre') or []),
    }


def _pair_similarity(a_ids: dict, b_ids: dict) -> dict[str, Any]:
    """Compute overlap between two clusters' identifier sets.

    Returns a dict with shared_* counts, whether only infra is shared (no
    identity), and a likely_unrelated flag.
    """
    shared_accounts  = a_ids['accounts'] & b_ids['accounts']
    shared_hosts     = a_ids['hosts']    & b_ids['hosts']
    shared_ips       = a_ids['ips']      & b_ids['ips']
    shared_resources = a_ids['resources'] & b_ids['resources']
    shared_mitre     = a_ids['mitre']    & b_ids['mitre']

    has_identity_link   = bool(shared_accounts)
    has_host_link       = bool(shared_hosts)
    has_ip_link         = bool(shared_ips)
    has_resource_link   = bool(shared_resources)
    has_mitre_overlap   = len(shared_mitre) >= 2

    # "Only infra shared" = shared IPs/domains but no accounts/hosts/resources
    only_infra_shared = (
        (has_ip_link or has_resource_link)
        and not has_identity_link
        and not has_host_link
    )

    # Likely unrelated: no strong binding at all
    # Strong binding = shared account OR shared host OR 2+ MITRE techniques
    strong_binding = has_identity_link or has_host_link or has_mitre_overlap
    likely_unrelated = not strong_binding

    return {
        'shared_accounts':  sorted(shared_accounts)[:6],
        'shared_hosts':     sorted(shared_hosts)[:6],
        'shared_ips':       sorted(shared_ips)[:6],
        'shared_resources': sorted(shared_resources)[:4],
        'shared_mitre':     sorted(shared_mitre)[:4],
        'only_infra_shared': only_infra_shared,
        'likely_unrelated':  likely_unrelated,
    }


def annotate_cluster_separation(clusters: list[dict]) -> None:
    """Annotate each cluster with pairwise separation metadata.

    For every pair of clusters, computes whether they are likely related or
    merely sharing low-value infrastructure (same firewall/NAT IP, etc.).

    Mutates each cluster:
      ``separation``       — {other_cluster_id: pairwise_similarity_dict}
      ``likely_isolated``  — True when cluster has no strong bindings to any other
    """
    if len(clusters) < 2:
        for cl in clusters:
            cl.setdefault('separation', {})
            cl.setdefault('likely_isolated', True)
        return

    # Pre-compute identifiers once
    id_map: dict[str, dict] = {}
    for cl in clusters:
        cid = str(cl.get('cluster_id') or id(cl))
        id_map[cid] = _cluster_identifiers(cl)

    cluster_ids = [str(cl.get('cluster_id') or id(cl)) for cl in clusters]

    for i, cl in enumerate(clusters):
        cid = cluster_ids[i]
        sep: dict[str, Any] = {}
        has_strong_binding = False

        for j, other_cl in enumerate(clusters):
            if i == j:
                continue
            other_cid = cluster_ids[j]
            sim = _pair_similarity(id_map[cid], id_map[other_cid])
            sep[other_cid] = sim
            if not sim['likely_unrelated']:
                has_strong_binding = True

        cl['separation'] = sep
        cl['likely_isolated'] = not has_strong_binding

    logger.debug(
        'cluster_separation: %d clusters, isolated=%d',
        len(clusters),
        sum(1 for cl in clusters if cl.get('likely_isolated')),
    )


__all__ = ['annotate_cluster_separation']
