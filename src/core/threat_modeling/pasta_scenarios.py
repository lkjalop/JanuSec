"""Static PASTA scenario definitions (Phase 1).

Each scenario describes a higher-level attack pathway derived from factor clusters.
This initial set keeps matching logic simple (string presence) and does not rely on
asset inventory. Later iterations can externalize to JSON/YAML.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    description: str
    pasta_stages: list[int]  # stages emphasized (3-6 etc.)
    required_factors: set[str] = field(default_factory=set)
    any_factors: set[str] = field(default_factory=set)
    optional_factors: set[str] = field(default_factory=set)
    exclusions: set[str] = field(default_factory=set)
    risk_adjustments: dict[str, int] = field(default_factory=dict)  # damage,+/- etc.
    mitigation_recs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

# NOTE: Factor keys here must match exactly those emitted by pipeline modules.
SCENARIOS: list[Scenario] = [
    Scenario(
        id="SCN-DNS-EXFIL",
        name="DNS Tunneling Exfiltration",
        description="Potential data exfiltration via DNS tunneling with beaconing characteristics.",
        pasta_stages=[3,4,5,6],
        required_factors={"dns:tunnel_suspected"},
        any_factors={"net:beacon_periodic", "ssl:ja3_known_bad", "ssl:ja3_rare"},
        optional_factors={"net:egress_port_scatter"},
        risk_adjustments={"damage": +1, "discoverability": -1},
        mitigation_recs=[
            "Deploy DNS query length & entropy monitoring",
            "Restrict outbound DNS to approved resolvers",
            "Add DLP inspection for egress channels"
        ],
        tags=["dns","exfiltration","c2"]
    ),
    Scenario(
        id="SCN-BEACON-C2",
        name="Beaconing Command & Control",
        description="Regular periodic outbound connections indicative of C2 beaconing.",
        pasta_stages=[3,5,6],
        required_factors={"net:beacon_periodic"},
        any_factors={"ssl:ja3_known_bad", "ssl:ja3_rare"},
        optional_factors={"domain_novel_observed"},
        risk_adjustments={"damage": +1},
        mitigation_recs=[
            "Cluster beacon intervals to identify infrastructure reuse",
            "Geo / ASN reputation enrichment for beacon endpoints"
        ],
        tags=["c2","beacon"]
    ),
    Scenario(
        id="SCN-LOL-PERSIST",
        name="LOLBin Persistence & Execution",
        description="Living-off-the-land binary used for potential persistence or execution chaining.",
        pasta_stages=[3,4,5],
        required_factors={"endpoint:lolbin_certutil_suspicious", "endpoint:persistence_candidate"},
        any_factors={"endpoint:rare_lineage"},
        optional_factors={"endpoint:signed_mismatch"},
        risk_adjustments={"exploitability": +1},
        mitigation_recs=[
            "Harden application allowlists for known LOLBins",
            "Increase telemetry depth for script-based launches"
        ],
        tags=["persistence","lolbin","execution"]
    ),
    Scenario(
        id="SCN-SUPPLY-CHAIN-INITIAL",
        name="Supply Chain Drift Initial Access",
        description="Component drift plus critical CVE suggests potential exploitation path.",
        pasta_stages=[2,3,4,5],
        required_factors={"sbom:supply_chain_drift"},
        any_factors={"sbom:cve_critical"},
        optional_factors=set(),
        risk_adjustments={"damage": +1, "affected_users": +1},
        mitigation_recs=[
            "Patch or mitigate critical vulnerable component",
            "Add integrity monitoring for high-risk components"
        ],
        tags=["supply_chain","initial_access"]
    ),
    Scenario(
        id="SCN-CREDENTIAL-ACCESS",
        name="Credential Access Pattern",
        description="Suspicious activity potentially targeting credential stores or processes.",
        pasta_stages=[3,5],
        required_factors={"credential_access_pattern"},
        any_factors={"endpoint:exec_burst", "endpoint:rare_lineage"},
        optional_factors={"endpoint:signed_mismatch"},
        risk_adjustments={"damage": +1, "reproducibility": +1},
        mitigation_recs=[
            "Increase monitoring on LSASS and protected processes",
            "Add memory access auditing for credential managers"
        ],
        tags=["credential_access"]
    ),
]

ID_INDEX: dict[str, Scenario] = {s.id: s for s in SCENARIOS}

__all__ = ["Scenario", "SCENARIOS", "ID_INDEX"]
