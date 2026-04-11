from typing import List, Set, Dict
from ..canonical_event import CanonicalEvent

class FactorEmit(dict):
    pass

def extract_cross_domain_factors(events: List[CanonicalEvent]) -> List[FactorEmit]:
    out: List[FactorEmit] = []
    if not events:
        return out

    last_ts = events[-1].timestamp if events else 0.0

    # --- Grouped entity sets per domain ---
    by_domain: Dict[str, List[CanonicalEvent]] = {}
    for e in events:
        by_domain.setdefault(e.source_type, []).append(e)

    users = {e.user for e in events if e.user}
    data_events = any(e.source_type == 'data' for e in events)
    iam_events  = any(e.source_type == 'iam'  for e in events)
    api_events  = any(e.source_type == 'api'  for e in events)

    if data_events and iam_events and api_events and users:
        out.append(FactorEmit(name='multi_stage_escalation_chain',
                              nodes=[f"user:{next(iter(users))}"],
                              domain='cross', confidence=0.6, ts=last_ts))

    # Data staging / exfil sequencing
    repos = [e.repository for e in events if e.source_type == 'data' and e.repository]
    large_outbound = any(e.source_type == 'data' and e.direction == 'outbound'
                         and (e.data_volume_bytes or 0) > 5_000_000 for e in events)
    if len(set(repos)) >= 2:
        out.append(FactorEmit(name='data_staging_phase',
                              nodes=['aggregate:data'], domain='cross', confidence=0.55, ts=last_ts))
    if len(set(repos)) >= 2 and large_outbound:
        out.append(FactorEmit(name='data_staging_then_exfil',
                              nodes=['aggregate:data'], domain='cross', confidence=0.6, ts=last_ts))
        out.append(FactorEmit(name='exfil_after_staging',
                              nodes=['aggregate:data'], domain='cross', confidence=0.62, ts=last_ts))

    # ------------------------------------------------------------------
    # ENTITY CORRELATION: same entity (user/host/ip) seen across 2+ security domains
    # Determines isolated vs. correlated events
    # ------------------------------------------------------------------
    domain_users: Dict[str, Set[str]] = {}
    domain_hosts: Dict[str, Set[str]] = {}
    domain_ips:   Dict[str, Set[str]] = {}

    for e in events:
        d = e.source_type
        if e.user:
            domain_users.setdefault(d, set()).add(e.user)
        if e.host:
            domain_hosts.setdefault(d, set()).add(e.host)
        for ip in filter(None, [e.src_ip, e.dst_ip]):
            domain_ips.setdefault(d, set()).add(ip)

    domains_seen = list(domain_users.keys() | domain_hosts.keys())

    # Shared user across ≥2 distinct security domains
    for user in users:
        domains_with_user = [d for d, us in domain_users.items() if user in us]
        if len(set(domains_with_user)) >= 2:
            out.append(FactorEmit(
                name='cross_domain_user_pivot',
                nodes=[f"user:{user}"],
                domain='cross',
                confidence=0.68,
                ts=last_ts,
                correlated_domains=sorted(set(domains_with_user)),
                correlation_type='shared_user',
            ))

    # Shared host across ≥2 distinct security domains
    all_hosts = {h for hs in domain_hosts.values() for h in hs}
    for host in all_hosts:
        domains_with_host = [d for d, hs in domain_hosts.items() if host in hs]
        if len(set(domains_with_host)) >= 2:
            out.append(FactorEmit(
                name='cross_domain_host_pivot',
                nodes=[f"host:{host}"],
                domain='cross',
                confidence=0.65,
                ts=last_ts,
                correlated_domains=sorted(set(domains_with_host)),
                correlation_type='shared_host',
            ))

    # Shared IP across ≥2 distinct security domains
    all_ips = {ip for ips in domain_ips.values() for ip in ips}
    for ip in all_ips:
        domains_with_ip = [d for d, ips in domain_ips.items() if ip in ips]
        if len(set(domains_with_ip)) >= 2:
            out.append(FactorEmit(
                name='cross_domain_ip_pivot',
                nodes=[f"ip:{ip}"],
                domain='cross',
                confidence=0.63,
                ts=last_ts,
                correlated_domains=sorted(set(domains_with_ip)),
                correlation_type='shared_ip',
            ))

    # Email → endpoint chain: email event with attachment + endpoint execution shortly after
    email_attach_ts = [e.timestamp for e in events
                       if e.source_type == 'email'
                       and e.attachment_type in {'docm','xlsm','pptm','vbs','exe','bat','ps1','hta'}]
    endpoint_exec_ts = [e.timestamp for e in events
                        if e.source_type == 'endpoint' and e.process]
    if email_attach_ts and endpoint_exec_ts:
        # Check temporal proximity: endpoint exec within 600s after malicious attachment
        for eat in email_attach_ts:
            for eet in endpoint_exec_ts:
                if 0 <= eet - eat <= 600:
                    out.append(FactorEmit(
                        name='email_to_endpoint_chain',
                        nodes=['aggregate:cross'],
                        domain='cross',
                        confidence=0.80,
                        ts=eet,
                        correlation_type='temporal_proximity',
                    ))
                    break

    # Classify events as isolated vs correlated
    correlated_factor_names = {f.get('name') for f in out if 'cross' in str(f.get('domain', ''))}

    # Isolation indicator: only one domain present
    if len(set(e.source_type for e in events)) == 1 and not any(
        f.get('name') in {'cross_domain_user_pivot','cross_domain_host_pivot',
                          'cross_domain_ip_pivot','email_to_endpoint_chain'}
        for f in out
    ):
        out.append(FactorEmit(
            name='event_isolated_single_domain',
            nodes=['aggregate:cross'],
            domain='cross',
            confidence=0.45,
            ts=last_ts,
            correlation_type='isolated',
        ))

    return out
