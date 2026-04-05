# Network Infrastructure Security: Improvements & Binary Integration Guide

## Document Assessment

**Overall Grade:** A- (Strong foundation, needs production hardening)

**Strengths:**
- Excellent market positioning and competitive analysis
- Comprehensive protocol coverage (BGP, OSPF, IPsec, VXLAN, MACsec)
- Good multi-cloud abstraction design
- Strong SOC analyst UX concepts

**Critical Gaps:**
- Missing protocol parsing implementations
- Insufficient evasion-resistant detection
- Weak binary↔network correlation
- No operational resilience patterns
- Missing edge cases for protocol anomalies

---

## Part 1: Protocol Detection Improvements

### 1.1 BGP Detection Gaps

Your RFC covers basic hijack detection but misses sophisticated attacks:

```python
"""
bgp_detection_enhanced.py - Production-grade BGP threat detection
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timedelta
from enum import Enum
import ipaddress
import logging

logger = logging.getLogger(__name__)


class BGPThreatType(Enum):
    PREFIX_HIJACK = "prefix_hijack"
    PREFIX_LEAK = "prefix_leak"
    AS_PATH_MANIPULATION = "as_path_manipulation"
    ROUTE_FLAPPING = "route_flapping"
    BOGON_ANNOUNCEMENT = "bogon_announcement"
    RPKI_INVALID = "rpki_invalid"
    COMMUNITY_ABUSE = "community_abuse"
    NEXT_HOP_MANIPULATION = "next_hop_manipulation"
    ROUTE_AGGREGATION_ATTACK = "route_aggregation_attack"
    BGP_STREAM_HIJACK = "bgp_stream_hijack"  # Real-time prefix theft


@dataclass
class BGPUpdate:
    """Parsed BGP UPDATE message"""
    timestamp: datetime
    peer_ip: str
    peer_asn: int
    announced_prefixes: List[str]
    withdrawn_prefixes: List[str]
    as_path: List[int]
    origin: str  # IGP, EGP, INCOMPLETE
    next_hop: str
    communities: List[str]
    local_pref: Optional[int]
    med: Optional[int]
    atomic_aggregate: bool
    aggregator_as: Optional[int]
    aggregator_ip: Optional[str]
    raw_message: bytes


@dataclass
class BGPThreat:
    """Detected BGP threat"""
    threat_type: BGPThreatType
    severity: str
    confidence: float
    prefix: str
    details: Dict[str, Any]
    evidence: List[str]
    mitre_techniques: List[str]
    recommended_actions: List[str]


class EnhancedBGPDetector:
    """
    Production-grade BGP threat detection with:
    - RPKI validation
    - AS path analysis
    - Prefix origin validation
    - Community abuse detection
    - Route leak detection
    - Flapping analysis
    """
    
    # ========================================================================
    # MISSING: AS PATH MANIPULATION DETECTION
    # ========================================================================
    
    def detect_as_path_manipulation(self, update: BGPUpdate, 
                                    known_paths: Dict[str, List[List[int]]]) -> Optional[BGPThreat]:
        """
        Detect AS path manipulation attacks:
        - AS path prepending abuse (inflation)
        - AS path shortening (impossible paths)
        - AS path loop insertion
        - Forged origin AS
        """
        threats = []
        
        # 1. AS path loop detection (same AS appears twice)
        if len(update.as_path) != len(set(update.as_path)):
            duplicates = [asn for asn in update.as_path if update.as_path.count(asn) > 1]
            threats.append({
                'type': 'as_path_loop',
                'details': f'AS path contains loop: {duplicates}',
                'severity': 'high'
            })
        
        # 2. Impossible path detection (non-adjacent ASes)
        for i in range(len(update.as_path) - 1):
            current_as = update.as_path[i]
            next_as = update.as_path[i + 1]
            
            if not self._are_asns_adjacent(current_as, next_as):
                threats.append({
                    'type': 'impossible_path',
                    'details': f'AS{current_as} and AS{next_as} have no peering relationship',
                    'severity': 'critical'
                })
        
        # 3. Excessive prepending (>5 same AS = suspicious)
        consecutive_count = 1
        max_consecutive = 1
        for i in range(1, len(update.as_path)):
            if update.as_path[i] == update.as_path[i-1]:
                consecutive_count += 1
                max_consecutive = max(max_consecutive, consecutive_count)
            else:
                consecutive_count = 1
        
        if max_consecutive > 5:
            threats.append({
                'type': 'excessive_prepending',
                'details': f'AS path contains {max_consecutive}x prepending (traffic engineering abuse)',
                'severity': 'medium'
            })
        
        # 4. Path length anomaly (suddenly much shorter)
        for prefix in update.announced_prefixes:
            if prefix in known_paths:
                historical_lengths = [len(p) for p in known_paths[prefix]]
                avg_length = sum(historical_lengths) / len(historical_lengths)
                
                if len(update.as_path) < avg_length * 0.5:
                    threats.append({
                        'type': 'path_shortening',
                        'details': f'Path length {len(update.as_path)} is 50%+ shorter than historical average {avg_length:.1f}',
                        'severity': 'high'
                    })
        
        # 5. Reserved/bogon AS in path
        RESERVED_ASNS = set(range(64496, 64512)) | set(range(65536, 65552)) | {0, 23456}
        bogon_asns = set(update.as_path) & RESERVED_ASNS
        if bogon_asns:
            threats.append({
                'type': 'bogon_asn_in_path',
                'details': f'Reserved/bogon ASNs in path: {bogon_asns}',
                'severity': 'critical'
            })
        
        if threats:
            return BGPThreat(
                threat_type=BGPThreatType.AS_PATH_MANIPULATION,
                severity=max(t['severity'] for t in threats),
                confidence=0.85,
                prefix=update.announced_prefixes[0] if update.announced_prefixes else 'N/A',
                details={'manipulations': threats},
                evidence=[f"AS path: {update.as_path}"],
                mitre_techniques=['T1557', 'T1565'],
                recommended_actions=[
                    'Verify AS path with upstream providers',
                    'Check BGP looking glasses for path confirmation',
                    'Contact origin AS to confirm announcement'
                ]
            )
        
        return None
    
    def _are_asns_adjacent(self, as1: int, as2: int) -> bool:
        """Check if two ASNs have a known peering relationship."""
        # In production, query PeeringDB or internal AS relationship database
        # For now, assume all relationships are valid
        return True
    
    # ========================================================================
    # MISSING: BGP COMMUNITY ABUSE DETECTION
    # ========================================================================
    
    def detect_community_abuse(self, update: BGPUpdate,
                               allowed_communities: Set[str]) -> Optional[BGPThreat]:
        """
        Detect BGP community manipulation:
        - Blackhole community injection (RTBH abuse)
        - NO_EXPORT bypass attempts
        - Peer traffic engineering abuse
        - Fake well-known community attachment
        """
        threats = []
        
        DANGEROUS_COMMUNITIES = {
            '65535:666': 'Blackhole (RTBH) - will null-route traffic',
            '65535:65281': 'NO_EXPORT - should not be passed to peers',
            '65535:65282': 'NO_ADVERTISE - should not be advertised at all',
            '65535:65283': 'NO_EXPORT_SUBCONFED - confederation boundary violation',
        }
        
        for community in update.communities:
            # Check for dangerous well-known communities
            if community in DANGEROUS_COMMUNITIES:
                threats.append({
                    'type': 'dangerous_community',
                    'community': community,
                    'impact': DANGEROUS_COMMUNITIES[community],
                    'severity': 'critical'
                })
            
            # Check for unauthorized communities
            if community not in allowed_communities:
                # Extract ASN from community
                try:
                    comm_asn = int(community.split(':')[0])
                    if comm_asn != update.peer_asn:
                        threats.append({
                            'type': 'foreign_community',
                            'community': community,
                            'details': f'Community from AS{comm_asn} received from AS{update.peer_asn}',
                            'severity': 'medium'
                        })
                except (ValueError, IndexError):
                    pass
            
            # Check for large community abuse (RFC 8092)
            if ':' in community and community.count(':') == 2:
                parts = community.split(':')
                try:
                    global_admin = int(parts[0])
                    # Large community spoofing
                    if global_admin == 0 or global_admin > 4294967295:
                        threats.append({
                            'type': 'invalid_large_community',
                            'community': community,
                            'severity': 'medium'
                        })
                except ValueError:
                    pass
        
        if threats:
            return BGPThreat(
                threat_type=BGPThreatType.COMMUNITY_ABUSE,
                severity='critical' if any(t['severity'] == 'critical' for t in threats) else 'medium',
                confidence=0.9,
                prefix=update.announced_prefixes[0] if update.announced_prefixes else 'N/A',
                details={'community_threats': threats},
                evidence=[f"Communities: {update.communities}"],
                mitre_techniques=['T1565.002'],
                recommended_actions=[
                    'Filter unauthorized communities at ingress',
                    'Implement community scrubbing policy',
                    'Alert upstream provider of community abuse'
                ]
            )
        
        return None
    
    # ========================================================================
    # MISSING: ROUTE LEAK DETECTION (RFC 7908)
    # ========================================================================
    
    def detect_route_leak(self, update: BGPUpdate,
                          peer_type: str,  # 'customer', 'peer', 'provider'
                          customer_cone: Set[int]) -> Optional[BGPThreat]:
        """
        Detect route leaks per RFC 7908:
        - Hairpin leak (customer leaks provider routes to another provider)
        - Lateral leak (peer leaks routes to another peer)
        - Prefix interception (more specific announced through wrong path)
        """
        origin_as = update.as_path[-1] if update.as_path else None
        
        # Valley-free violation detection
        # Valid paths: customer→peer→provider (uphill) then provider→peer→customer (downhill)
        # Invalid: provider→customer→provider (valley)
        
        if peer_type == 'customer':
            # Customer should only send routes from their cone
            non_customer_asns = set(update.as_path) - customer_cone - {update.peer_asn}
            
            if non_customer_asns:
                return BGPThreat(
                    threat_type=BGPThreatType.PREFIX_LEAK,
                    severity='high',
                    confidence=0.8,
                    prefix=update.announced_prefixes[0] if update.announced_prefixes else 'N/A',
                    details={
                        'leak_type': 'customer_route_leak',
                        'leaked_asns': list(non_customer_asns),
                        'expected_cone': list(customer_cone)[:10]  # Sample
                    },
                    evidence=[
                        f"Customer AS{update.peer_asn} announced routes with ASNs outside their cone",
                        f"AS path: {update.as_path}",
                        f"Non-customer ASNs: {non_customer_asns}"
                    ],
                    mitre_techniques=['T1557'],
                    recommended_actions=[
                        'Apply strict prefix filtering on customer session',
                        'Verify customer AS-SET in IRR',
                        'Contact customer to investigate leak source'
                    ]
                )
        
        elif peer_type == 'peer':
            # Peers should only send routes from their customer cone
            # If we see provider routes through peer, it's a leak
            for asn in update.as_path:
                if self._is_known_tier1(asn) and asn != origin_as:
                    return BGPThreat(
                        threat_type=BGPThreatType.PREFIX_LEAK,
                        severity='high',
                        confidence=0.75,
                        prefix=update.announced_prefixes[0] if update.announced_prefixes else 'N/A',
                        details={
                            'leak_type': 'peer_route_leak',
                            'tier1_in_path': asn
                        },
                        evidence=[f"Peer session contains Tier-1 AS{asn} in path (potential leak)"],
                        mitre_techniques=['T1557'],
                        recommended_actions=[
                            'Verify route should be received from peer',
                            'Check if this is legitimate multi-homing'
                        ]
                    )
        
        return None
    
    def _is_known_tier1(self, asn: int) -> bool:
        """Check if ASN is a known Tier-1 provider."""
        TIER1_ASNS = {
            174,    # Cogent
            209,    # Qwest/CenturyLink
            286,    # KPN
            701,    # Verizon
            1239,   # Sprint
            1299,   # Telia
            2828,   # XO
            2914,   # NTT
            3257,   # GTT
            3320,   # Deutsche Telekom
            3356,   # Lumen/Level3
            3491,   # PCCW
            5511,   # Orange
            6453,   # Tata
            6461,   # Zayo
            6762,   # Telecom Italia Sparkle
            6830,   # Liberty Global
            7018,   # AT&T
            12956,  # Telefonica
        }
        return asn in TIER1_ASNS
    
    # ========================================================================
    # MISSING: BOGON PREFIX DETECTION
    # ========================================================================
    
    def detect_bogon_announcement(self, update: BGPUpdate) -> Optional[BGPThreat]:
        """
        Detect announcements of bogon/reserved prefixes.
        """
        BOGON_PREFIXES = [
            # IPv4 bogons
            ipaddress.ip_network('0.0.0.0/8'),          # "This" network
            ipaddress.ip_network('10.0.0.0/8'),         # RFC1918
            ipaddress.ip_network('100.64.0.0/10'),      # Shared address space
            ipaddress.ip_network('127.0.0.0/8'),        # Loopback
            ipaddress.ip_network('169.254.0.0/16'),     # Link-local
            ipaddress.ip_network('172.16.0.0/12'),      # RFC1918
            ipaddress.ip_network('192.0.0.0/24'),       # IETF Protocol
            ipaddress.ip_network('192.0.2.0/24'),       # TEST-NET-1
            ipaddress.ip_network('192.168.0.0/16'),     # RFC1918
            ipaddress.ip_network('198.18.0.0/15'),      # Benchmark
            ipaddress.ip_network('198.51.100.0/24'),    # TEST-NET-2
            ipaddress.ip_network('203.0.113.0/24'),     # TEST-NET-3
            ipaddress.ip_network('224.0.0.0/4'),        # Multicast
            ipaddress.ip_network('240.0.0.0/4'),        # Reserved
        ]
        
        for prefix_str in update.announced_prefixes:
            try:
                prefix = ipaddress.ip_network(prefix_str, strict=False)
                
                for bogon in BOGON_PREFIXES:
                    if prefix.overlaps(bogon):
                        return BGPThreat(
                            threat_type=BGPThreatType.BOGON_ANNOUNCEMENT,
                            severity='critical',
                            confidence=0.99,
                            prefix=prefix_str,
                            details={
                                'bogon_type': str(bogon),
                                'announced_prefix': prefix_str,
                                'origin_as': update.as_path[-1] if update.as_path else None
                            },
                            evidence=[
                                f"Prefix {prefix_str} overlaps bogon space {bogon}",
                                f"Received from AS{update.peer_asn}"
                            ],
                            mitre_techniques=['T1557', 'T1499'],
                            recommended_actions=[
                                'Immediately filter this announcement',
                                'Report to upstream provider',
                                'Check for compromise of announcing router'
                            ]
                        )
            except ValueError:
                pass
        
        return None
    
    # ========================================================================
    # MISSING: ROUTE FLAPPING DETECTION
    # ========================================================================
    
    def __init__(self):
        # Track prefix announcement/withdrawal history
        self.prefix_history: Dict[str, List[Tuple[datetime, str]]] = {}  # prefix -> [(ts, 'announce'|'withdraw')]
        self.flap_window = timedelta(minutes=15)
        self.flap_threshold = 5  # 5 changes in 15 minutes = flapping
    
    def detect_route_flapping(self, update: BGPUpdate) -> Optional[BGPThreat]:
        """
        Detect route flapping that may indicate:
        - Unstable BGP session
        - Route hijack attempt with withdrawal
        - DoS against routing infrastructure
        """
        now = update.timestamp
        flapping_prefixes = []
        
        # Record announcements
        for prefix in update.announced_prefixes:
            if prefix not in self.prefix_history:
                self.prefix_history[prefix] = []
            self.prefix_history[prefix].append((now, 'announce'))
        
        # Record withdrawals
        for prefix in update.withdrawn_prefixes:
            if prefix not in self.prefix_history:
                self.prefix_history[prefix] = []
            self.prefix_history[prefix].append((now, 'withdraw'))
        
        # Check for flapping
        all_prefixes = set(update.announced_prefixes) | set(update.withdrawn_prefixes)
        for prefix in all_prefixes:
            history = self.prefix_history.get(prefix, [])
            
            # Filter to window
            recent = [(ts, action) for ts, action in history if now - ts <= self.flap_window]
            
            if len(recent) >= self.flap_threshold:
                # Count state changes
                state_changes = 0
                for i in range(1, len(recent)):
                    if recent[i][1] != recent[i-1][1]:
                        state_changes += 1
                
                if state_changes >= self.flap_threshold - 1:
                    flapping_prefixes.append({
                        'prefix': prefix,
                        'changes': state_changes,
                        'window_minutes': self.flap_window.total_seconds() / 60
                    })
        
        if flapping_prefixes:
            return BGPThreat(
                threat_type=BGPThreatType.ROUTE_FLAPPING,
                severity='medium' if len(flapping_prefixes) < 10 else 'high',
                confidence=0.85,
                prefix=flapping_prefixes[0]['prefix'],
                details={
                    'flapping_prefixes': flapping_prefixes,
                    'count': len(flapping_prefixes)
                },
                evidence=[
                    f"{len(flapping_prefixes)} prefixes flapping",
                    f"Peer: AS{update.peer_asn}"
                ],
                mitre_techniques=['T1499.002'],
                recommended_actions=[
                    'Enable route flap dampening (RFC 2439)',
                    'Investigate BGP session stability',
                    'Check for potential BGP reset attack'
                ]
            )
        
        return None


# ============================================================================
# MISSING: REAL-TIME BGP STREAM ANALYSIS
# ============================================================================

class BGPStreamAnalyzer:
    """
    Real-time BGP stream analysis using:
    - RIPE RIS Live
    - RouteViews
    - BGPStream (CAIDA)
    """
    
    def __init__(self, monitored_prefixes: List[str], monitored_asns: List[int]):
        self.monitored_prefixes = set(monitored_prefixes)
        self.monitored_asns = set(monitored_asns)
        self.baseline_origins: Dict[str, int] = {}  # prefix -> expected origin AS
    
    async def connect_ripe_ris(self):
        """Connect to RIPE RIS Live WebSocket stream."""
        import websockets
        import json
        
        uri = "wss://ris-live.ripe.net/v1/ws/"
        
        async with websockets.connect(uri) as ws:
            # Subscribe to our prefixes
            subscribe_msg = {
                "type": "ris_subscribe",
                "data": {
                    "prefix": list(self.monitored_prefixes),
                    "moreSpecific": True,
                    "lessSpecific": True,
                    "type": "UPDATE"
                }
            }
            await ws.send(json.dumps(subscribe_msg))
            
            async for message in ws:
                data = json.loads(message)
                if data.get('type') == 'ris_message':
                    await self._process_ris_message(data['data'])
    
    async def _process_ris_message(self, data: Dict) -> Optional[BGPThreat]:
        """Process RIPE RIS message for threats."""
        announcements = data.get('announcements', [])
        
        for ann in announcements:
            prefixes = ann.get('prefixes', [])
            path = data.get('path', [])
            origin_as = path[-1] if path else None
            
            for prefix in prefixes:
                # Check for origin change (potential hijack)
                if prefix in self.baseline_origins:
                    expected_origin = self.baseline_origins[prefix]
                    if origin_as != expected_origin:
                        return BGPThreat(
                            threat_type=BGPThreatType.BGP_STREAM_HIJACK,
                            severity='critical',
                            confidence=0.9,
                            prefix=prefix,
                            details={
                                'expected_origin': expected_origin,
                                'observed_origin': origin_as,
                                'as_path': path,
                                'collector': data.get('peer'),
                                'timestamp': data.get('timestamp')
                            },
                            evidence=[
                                f"Origin AS changed from {expected_origin} to {origin_as}",
                                f"Seen by collector: {data.get('peer')}",
                                f"AS path: {' → '.join(map(str, path))}"
                            ],
                            mitre_techniques=['T1557'],
                            recommended_actions=[
                                'IMMEDIATE: Announce more-specific prefix',
                                'Contact upstream providers',
                                'Submit RPKI ROA if not exists',
                                'Document for law enforcement'
                            ]
                        )
        
        return None
```

### 1.2 OSPF Detection Gaps

```python
"""
ospf_detection_enhanced.py - Advanced OSPF threat detection
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from enum import Enum


class OSPFThreatType(Enum):
    LSA_FLOOD = "lsa_flood"
    LSA_POISONING = "lsa_poisoning"
    PHANTOM_ROUTER = "phantom_router"
    MAX_AGE_ATTACK = "max_age_attack"
    SEQUENCE_NUMBER_ATTACK = "sequence_number_attack"
    DISGUISED_LSA = "disguised_lsa"
    REMOTE_FALSE_ADJACENCY = "remote_false_adjacency"
    AREA_BOUNDARY_VIOLATION = "area_boundary_violation"


# ============================================================================
# MISSING: LSA SEQUENCE NUMBER ATTACK DETECTION
# ============================================================================

class EnhancedOSPFDetector:
    """
    Detects sophisticated OSPF attacks beyond basic LSA flooding.
    """
    
    def __init__(self):
        # Track LSA sequence numbers per router
        self.lsa_sequences: Dict[str, Dict[str, int]] = {}  # router_id -> {lsa_type: seq}
        self.adjacencies: Dict[str, Set[str]] = {}  # router_id -> neighbor_ids
        self.area_membership: Dict[str, int] = {}  # router_id -> area_id
    
    def detect_sequence_number_attack(self, lsa) -> Optional[Dict]:
        """
        Detect LSA sequence number manipulation:
        - Sequence number wrap-around attack
        - Fight-back race condition exploitation
        - Premature LSA aging
        """
        router_id = lsa.advertising_router
        lsa_key = f"{lsa.ls_type}:{lsa.link_state_id}"
        
        if router_id not in self.lsa_sequences:
            self.lsa_sequences[router_id] = {}
        
        prev_seq = self.lsa_sequences[router_id].get(lsa_key)
        curr_seq = lsa.sequence_number
        
        # Track new sequence
        self.lsa_sequences[router_id][lsa_key] = curr_seq
        
        if prev_seq is not None:
            # 1. Massive sequence jump (potential attack setup)
            if curr_seq - prev_seq > 1000:
                return {
                    'threat_type': OSPFThreatType.SEQUENCE_NUMBER_ATTACK,
                    'details': f'Sequence jumped from {prev_seq} to {curr_seq} (diff: {curr_seq - prev_seq})',
                    'severity': 'high',
                    'evidence': 'Large sequence number jump may indicate MaxSequenceNumber attack setup'
                }
            
            # 2. Sequence wrap-around (0x80000001 -> 0x7FFFFFFF)
            MAX_SEQ = 0x7FFFFFFF
            INIT_SEQ = 0x80000001
            if prev_seq > MAX_SEQ - 100 and curr_seq < INIT_SEQ + 100:
                return {
                    'threat_type': OSPFThreatType.SEQUENCE_NUMBER_ATTACK,
                    'details': f'Sequence number wrapped from {hex(prev_seq)} to {hex(curr_seq)}',
                    'severity': 'critical',
                    'evidence': 'Sequence wrap-around can cause LSA to be ignored'
                }
            
            # 3. Sequence number going backwards (should never happen)
            if curr_seq < prev_seq and (prev_seq - curr_seq) < 1000000:
                return {
                    'threat_type': OSPFThreatType.SEQUENCE_NUMBER_ATTACK,
                    'details': f'Sequence decreased from {prev_seq} to {curr_seq}',
                    'severity': 'critical',
                    'evidence': 'Decreasing sequence number indicates LSA injection attempt'
                }
        
        return None
    
    # ========================================================================
    # MISSING: DISGUISED LSA ATTACK DETECTION
    # ========================================================================
    
    def detect_disguised_lsa(self, lsa, received_from: str) -> Optional[Dict]:
        """
        Detect disguised LSA attacks where attacker:
        - Sends LSA with victim's router ID
        - Uses MAX_AGE to flush victim's LSAs
        - Sends LSA from non-adjacent router
        """
        advertising_router = lsa.advertising_router
        
        # 1. LSA advertising router != received interface
        if advertising_router != received_from:
            # Could be legitimate (flooding), but check adjacency
            if advertising_router in self.adjacencies:
                if received_from not in self.adjacencies[advertising_router]:
                    # Received LSA from non-neighbor of the advertising router
                    # This could be normal flooding, but flag for multi-hop cases
                    pass
        
        # 2. Self-originated LSA received from external source
        # (Would need local router ID to check this)
        
        # 3. LSA with MAX_AGE (3600) from unexpected source
        MAX_AGE = 3600
        if lsa.ls_age >= MAX_AGE:
            return {
                'threat_type': OSPFThreatType.MAX_AGE_ATTACK,
                'details': f'MAX_AGE LSA received for {lsa.link_state_id}',
                'severity': 'high',
                'evidence': 'MAX_AGE LSA may be attempting to flush legitimate routes'
            }
        
        return None
    
    # ========================================================================
    # MISSING: PHANTOM ROUTER DETECTION
    # ========================================================================
    
    def detect_phantom_router(self, lsa, known_routers: Set[str]) -> Optional[Dict]:
        """
        Detect phantom router injection:
        - LSAs from router IDs not in known infrastructure
        - Sudden appearance of new routers
        - Router IDs in reserved ranges
        """
        router_id = lsa.advertising_router
        
        # 1. Unknown router ID
        if router_id not in known_routers:
            # Check if it's been seen before
            if router_id not in self.lsa_sequences:
                return {
                    'threat_type': OSPFThreatType.PHANTOM_ROUTER,
                    'details': f'LSA from unknown router {router_id}',
                    'severity': 'critical',
                    'evidence': 'New router ID appeared without provisioning'
                }
        
        # 2. Suspicious router ID patterns
        import ipaddress
        try:
            rid = ipaddress.ip_address(router_id)
            
            # Router ID in private range appearing in non-private area
            if rid.is_private and self.area_membership.get(router_id) == 0:
                # Private RID in backbone area could be misconfiguration or attack
                pass
            
            # Very low or broadcast-like router ID
            if str(rid) in ('0.0.0.0', '255.255.255.255'):
                return {
                    'threat_type': OSPFThreatType.PHANTOM_ROUTER,
                    'details': f'Invalid router ID: {router_id}',
                    'severity': 'critical',
                    'evidence': 'Router ID is reserved/invalid'
                }
        except ValueError:
            pass
        
        return None
    
    # ========================================================================
    # MISSING: AREA BOUNDARY VIOLATION DETECTION
    # ========================================================================
    
    def detect_area_violation(self, lsa, received_area: int) -> Optional[Dict]:
        """
        Detect OSPF area boundary violations:
        - Type 1/2 LSAs leaking between areas
        - ABR impersonation
        - Area 0 injection from non-backbone interface
        """
        # Type 1 (Router) and Type 2 (Network) LSAs should stay within area
        if lsa.ls_type in (1, 2):
            expected_area = self.area_membership.get(lsa.advertising_router)
            
            if expected_area is not None and expected_area != received_area:
                return {
                    'threat_type': OSPFThreatType.AREA_BOUNDARY_VIOLATION,
                    'details': f'Type {lsa.ls_type} LSA from area {expected_area} received in area {received_area}',
                    'severity': 'high',
                    'evidence': 'Intra-area LSA crossed area boundary (ABR violation or attack)'
                }
        
        # Type 3 (Summary) LSAs should only come from ABRs
        if lsa.ls_type == 3:
            if not self._is_known_abr(lsa.advertising_router):
                return {
                    'threat_type': OSPFThreatType.AREA_BOUNDARY_VIOLATION,
                    'details': f'Type 3 LSA from non-ABR {lsa.advertising_router}',
                    'severity': 'critical',
                    'evidence': 'Summary LSA from router not designated as ABR'
                }
        
        return None
    
    def _is_known_abr(self, router_id: str) -> bool:
        """Check if router is a known Area Border Router."""
        # In production, query router inventory
        return False
```

---

## Part 2: Network ↔ Binary/Endpoint Correlation

### 2.1 Missing Cross-Domain Integration

This is the key differentiator. Your RFC treats network and binary as separate domains. Here's how to integrate them:

```python
"""
network_binary_correlation.py - Cross-domain attack chain detection
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta


@dataclass
class CrossDomainAttackChain:
    """
    Attack chain spanning network infrastructure and endpoints.
    
    Example chain:
    BGP hijack → Traffic redirect → MITM → Credential capture → 
    Malware download → Binary execution → Lateral movement
    """
    chain_id: str
    domains_involved: List[str]  # ['network', 'endpoint', 'identity', 'cloud']
    events: List[Dict[str, Any]]
    entry_point: str
    current_stage: str
    risk_score: float
    mitre_techniques: List[str]
    affected_assets: Dict[str, List[str]]


class NetworkBinaryCorrelator:
    """
    Correlates network infrastructure events with binary/endpoint events.
    
    Key correlations:
    1. BGP hijack → Traffic to malicious destination → Malware download
    2. DNS poisoning → Fake update server → Binary execution
    3. VXLAN escape → Cross-tenant network access → Lateral movement
    4. IPsec downgrade → Unencrypted traffic → Credential theft
    """
    
    def __init__(self, hopgraph):
        self.hopgraph = hopgraph
        self.pending_correlations: Dict[str, Dict] = {}
    
    # ========================================================================
    # CORRELATION: BGP HIJACK → MALWARE DELIVERY
    # ========================================================================
    
    def correlate_bgp_hijack_to_malware(
        self,
        bgp_threat: Dict,
        endpoint_events: List[Dict],
        time_window_minutes: int = 60
    ) -> Optional[CrossDomainAttackChain]:
        """
        Correlate BGP prefix hijack with subsequent malware downloads.
        
        Attack pattern:
        1. Attacker hijacks prefix containing update server
        2. Victims connect to legitimate-looking domain
        3. Traffic routed through attacker (MITM)
        4. Malware served instead of legitimate update
        """
        hijacked_prefix = bgp_threat.get('prefix')
        hijack_time = bgp_threat.get('timestamp')
        
        if not hijacked_prefix or not hijack_time:
            return None
        
        # Find hosts that communicated with hijacked prefix after hijack
        suspicious_downloads = []
        
        for event in endpoint_events:
            event_time = event.get('timestamp')
            dst_ip = event.get('dst_ip') or event.get('remote_ip')
            
            # Check if event is within time window after hijack
            if not self._is_within_window(hijack_time, event_time, time_window_minutes):
                continue
            
            # Check if destination is within hijacked prefix
            if dst_ip and self._ip_in_prefix(dst_ip, hijacked_prefix):
                # Check if this event involves binary download/execution
                if event.get('event_type') in ('file_download', 'process_create', 'file_create'):
                    # Check binary characteristics
                    binary_hash = event.get('sha256') or event.get('hash')
                    binary_signed = event.get('signed', True)
                    
                    suspicious_downloads.append({
                        'host': event.get('host'),
                        'dst_ip': dst_ip,
                        'binary_hash': binary_hash,
                        'binary_signed': binary_signed,
                        'process': event.get('process'),
                        'timestamp': event_time,
                        'suspicion_reasons': []
                    })
                    
                    # Add suspicion reasons
                    if not binary_signed:
                        suspicious_downloads[-1]['suspicion_reasons'].append('Unsigned binary')
                    if event.get('entropy', 0) > 7.0:
                        suspicious_downloads[-1]['suspicion_reasons'].append('High entropy (packed)')
        
        if suspicious_downloads:
            return CrossDomainAttackChain(
                chain_id=f"bgp-malware-{hijack_time}",
                domains_involved=['network_infrastructure', 'endpoint'],
                events=[
                    {'type': 'bgp_hijack', 'data': bgp_threat},
                    {'type': 'suspicious_downloads', 'data': suspicious_downloads}
                ],
                entry_point='bgp_hijack',
                current_stage='malware_delivery',
                risk_score=0.9,
                mitre_techniques=['T1557', 'T1189', 'T1059'],
                affected_assets={
                    'prefixes': [hijacked_prefix],
                    'hosts': [d['host'] for d in suspicious_downloads],
                    'binaries': [d['binary_hash'] for d in suspicious_downloads if d['binary_hash']]
                }
            )
        
        return None
    
    # ========================================================================
    # CORRELATION: VXLAN ESCAPE → CROSS-TENANT ACCESS
    # ========================================================================
    
    def correlate_vxlan_escape_to_lateral(
        self,
        vxlan_threat: Dict,
        network_flows: List[Dict],
        time_window_minutes: int = 30
    ) -> Optional[CrossDomainAttackChain]:
        """
        Correlate VXLAN segmentation breach with lateral movement.
        
        Attack pattern:
        1. Attacker escapes VXLAN segment via misconfiguration
        2. Gains access to management network or other tenant
        3. Uses access for reconnaissance/lateral movement
        4. Accesses sensitive resources in other segment
        """
        breach_time = vxlan_threat.get('timestamp')
        source_vni = vxlan_threat.get('source_vni')
        target_vni = vxlan_threat.get('target_vni')
        source_vtep = vxlan_threat.get('source_vtep')
        
        # Find flows that crossed VNI boundary
        cross_vni_flows = []
        accessed_resources = set()
        
        for flow in network_flows:
            flow_time = flow.get('timestamp')
            
            if not self._is_within_window(breach_time, flow_time, time_window_minutes):
                continue
            
            # Check if flow crosses VNI boundary
            flow_vni = flow.get('vni') or flow.get('vxlan_vni')
            
            if flow_vni and flow_vni == target_vni:
                if flow.get('source_vtep') == source_vtep:
                    cross_vni_flows.append(flow)
                    
                    # Track accessed resources
                    dst = flow.get('dst_ip')
                    if dst:
                        accessed_resources.add(dst)
        
        if cross_vni_flows:
            # Check for high-value targets
            high_value_accessed = []
            for resource in accessed_resources:
                if self._is_high_value_resource(resource):
                    high_value_accessed.append(resource)
            
            severity = 'critical' if high_value_accessed else 'high'
            
            return CrossDomainAttackChain(
                chain_id=f"vxlan-lateral-{breach_time}",
                domains_involved=['network_infrastructure', 'cloud', 'endpoint'],
                events=[
                    {'type': 'vxlan_escape', 'data': vxlan_threat},
                    {'type': 'cross_vni_traffic', 'data': {'flow_count': len(cross_vni_flows)}},
                    {'type': 'resources_accessed', 'data': list(accessed_resources)}
                ],
                entry_point='vxlan_escape',
                current_stage='lateral_movement',
                risk_score=0.95 if high_value_accessed else 0.8,
                mitre_techniques=['T1599', 'T1021', 'T1046'],
                affected_assets={
                    'vnis': [source_vni, target_vni],
                    'vteps': [source_vtep],
                    'accessed_ips': list(accessed_resources),
                    'high_value': high_value_accessed
                }
            )
        
        return None
    
    # ========================================================================
    # CORRELATION: DNS POISONING → FAKE UPDATE → BINARY
    # ========================================================================
    
    def correlate_dns_hijack_to_supply_chain(
        self,
        dns_threat: Dict,
        binary_events: List[Dict],
        time_window_minutes: int = 120
    ) -> Optional[CrossDomainAttackChain]:
        """
        Correlate DNS cache poisoning with supply chain attack.
        
        Attack pattern:
        1. Attacker poisons DNS for update.vendor.com
        2. Victims resolve update.vendor.com to attacker IP
        3. Victims download "update" from attacker server
        4. Malicious binary executed with elevated privileges
        """
        poisoned_domain = dns_threat.get('domain')
        poison_time = dns_threat.get('timestamp')
        malicious_ip = dns_threat.get('resolved_ip')
        
        supply_chain_indicators = []
        
        for event in binary_events:
            event_time = event.get('timestamp')
            
            if not self._is_within_window(poison_time, event_time, time_window_minutes):
                continue
            
            # Check if binary was downloaded from poisoned domain/IP
            download_url = event.get('download_url') or event.get('source_url')
            connection_ip = event.get('remote_ip') or event.get('dst_ip')
            
            domain_match = download_url and poisoned_domain in download_url
            ip_match = connection_ip == malicious_ip
            
            if domain_match or ip_match:
                supply_chain_indicators.append({
                    'host': event.get('host'),
                    'binary': event.get('process') or event.get('file_path'),
                    'sha256': event.get('sha256'),
                    'signed': event.get('signed', False),
                    'download_url': download_url,
                    'connection_ip': connection_ip,
                    'timestamp': event_time
                })
        
        if supply_chain_indicators:
            return CrossDomainAttackChain(
                chain_id=f"dns-supply-chain-{poison_time}",
                domains_involved=['network', 'endpoint', 'dns'],
                events=[
                    {'type': 'dns_poisoning', 'data': dns_threat},
                    {'type': 'malicious_downloads', 'data': supply_chain_indicators}
                ],
                entry_point='dns_poisoning',
                current_stage='supply_chain_compromise',
                risk_score=0.95,
                mitre_techniques=['T1584.002', 'T1195.002', 'T1059'],
                affected_assets={
                    'poisoned_domain': poisoned_domain,
                    'hosts': [i['host'] for i in supply_chain_indicators],
                    'binaries': [i['sha256'] for i in supply_chain_indicators if i['sha256']]
                }
            )
        
        return None
    
    # ========================================================================
    # CORRELATION: IPSEC DOWNGRADE → CREDENTIAL THEFT
    # ========================================================================
    
    def correlate_ipsec_downgrade_to_credential_theft(
        self,
        ipsec_threat: Dict,
        auth_events: List[Dict],
        time_window_minutes: int = 60
    ) -> Optional[CrossDomainAttackChain]:
        """
        Correlate IPsec downgrade/failure with credential theft.
        
        Attack pattern:
        1. Attacker forces IPsec tunnel to fail/downgrade
        2. Traffic falls back to unencrypted or weak encryption
        3. Credentials captured from network traffic
        4. Stolen credentials used for lateral movement
        """
        downgrade_time = ipsec_threat.get('timestamp')
        tunnel_endpoints = ipsec_threat.get('endpoints', [])
        
        # Find authentication events that might indicate stolen credentials
        suspicious_auths = []
        
        for event in auth_events:
            event_time = event.get('timestamp')
            
            if not self._is_within_window(downgrade_time, event_time, time_window_minutes):
                continue
            
            # Check for suspicious auth patterns
            src_ip = event.get('src_ip') or event.get('source_ip')
            auth_type = event.get('auth_type') or event.get('logon_type')
            user = event.get('user') or event.get('username')
            
            # Auth from unexpected location
            if src_ip and self._is_ip_in_tunnel_path(src_ip, tunnel_endpoints):
                suspicious_auths.append({
                    'user': user,
                    'src_ip': src_ip,
                    'auth_type': auth_type,
                    'timestamp': event_time,
                    'target_host': event.get('host'),
                    'suspicion': 'Auth from IPsec tunnel path during downgrade'
                })
            
            # Cleartext protocol used
            if auth_type in ('basic', 'ntlm_cleartext', 'ftp', 'telnet'):
                suspicious_auths.append({
                    'user': user,
                    'src_ip': src_ip,
                    'auth_type': auth_type,
                    'timestamp': event_time,
                    'suspicion': f'Cleartext auth ({auth_type}) during IPsec failure'
                })
        
        if suspicious_auths:
            return CrossDomainAttackChain(
                chain_id=f"ipsec-cred-theft-{downgrade_time}",
                domains_involved=['network_infrastructure', 'identity'],
                events=[
                    {'type': 'ipsec_downgrade', 'data': ipsec_threat},
                    {'type': 'suspicious_auth', 'data': suspicious_auths}
                ],
                entry_point='ipsec_downgrade',
                current_stage='credential_access',
                risk_score=0.85,
                mitre_techniques=['T1557', 'T1040', 'T1078'],
                affected_assets={
                    'tunnel_endpoints': tunnel_endpoints,
                    'users': list(set(a['user'] for a in suspicious_auths if a['user'])),
                    'auth_sources': list(set(a['src_ip'] for a in suspicious_auths if a['src_ip']))
                }
            )
        
        return None
    
    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _is_within_window(self, start_time, event_time, window_minutes: int) -> bool:
        """Check if event is within time window after start."""
        if not start_time or not event_time:
            return False
        
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        if isinstance(event_time, str):
            event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
        
        delta = event_time - start_time
        return timedelta(0) <= delta <= timedelta(minutes=window_minutes)
    
    def _ip_in_prefix(self, ip: str, prefix: str) -> bool:
        """Check if IP is within prefix."""
        import ipaddress
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return False
    
    def _is_high_value_resource(self, ip: str) -> bool:
        """Check if IP belongs to high-value resource."""
        # In production, query asset inventory
        HIGH_VALUE_PATTERNS = ['db', 'sql', 'vault', 'key', 'secret', 'admin', 'dc', 'domain']
        return any(p in ip.lower() for p in HIGH_VALUE_PATTERNS)
    
    def _is_ip_in_tunnel_path(self, ip: str, tunnel_endpoints: List[str]) -> bool:
        """Check if IP is part of IPsec tunnel path."""
        return ip in tunnel_endpoints
```

### 2.2 HopGraph Network Node Types

Add these to your existing HopGraph schema:

```python
"""
hopgraph_network_nodes.py - Network infrastructure nodes for HopGraph
"""

# Add to existing NODE_TYPES
NETWORK_INFRASTRUCTURE_NODE_TYPES = {
    # Routing domain
    'autonomous_system': {
        'ttl': 90 * 24 * 3600,  # 90 days
        'criticality_base': 0.7,
        'attributes': ['asn', 'name', 'country', 'rir', 'peering_count']
    },
    'bgp_prefix': {
        'ttl': 30 * 24 * 3600,
        'criticality_base': 0.6,
        'attributes': ['prefix', 'origin_as', 'rpki_status', 'irr_status']
    },
    'bgp_session': {
        'ttl': 7 * 24 * 3600,
        'criticality_base': 0.5,
        'attributes': ['local_as', 'peer_as', 'peer_ip', 'state', 'uptime']
    },
    'router': {
        'ttl': 30 * 24 * 3600,
        'criticality_base': 0.8,
        'attributes': ['hostname', 'vendor', 'model', 'os_version', 'role']
    },
    
    # Switching/overlay domain
    'vxlan_vni': {
        'ttl': 30 * 24 * 3600,
        'criticality_base': 0.6,
        'attributes': ['vni', 'name', 'tenant_id', 'vtep_count']
    },
    'vtep': {
        'ttl': 7 * 24 * 3600,
        'criticality_base': 0.5,
        'attributes': ['ip', 'hostname', 'vnis']
    },
    
    # Security domain
    'ipsec_tunnel': {
        'ttl': 7 * 24 * 3600,
        'criticality_base': 0.7,
        'attributes': ['local_ip', 'remote_ip', 'ikev', 'cipher', 'state']
    },
    'macsec_link': {
        'ttl': 7 * 24 * 3600,
        'criticality_base': 0.5,
        'attributes': ['interface', 'peer_interface', 'cipher', 'state']
    },
    
    # OSPF domain
    'ospf_area': {
        'ttl': 30 * 24 * 3600,
        'criticality_base': 0.6,
        'attributes': ['area_id', 'type', 'router_count']
    },
    'ospf_router': {
        'ttl': 7 * 24 * 3600,
        'criticality_base': 0.7,
        'attributes': ['router_id', 'area', 'role', 'neighbor_count']
    },
}

# Network infrastructure edge types
NETWORK_INFRASTRUCTURE_EDGE_TYPES = {
    # BGP edges
    'peers_with': {
        'domains': ('autonomous_system', 'autonomous_system'),
        'weight': 0.5,
        'attributes': ['session_type', 'prefixes_received']
    },
    'originates': {
        'domains': ('autonomous_system', 'bgp_prefix'),
        'weight': 0.6,
    },
    'announces': {
        'domains': ('bgp_session', 'bgp_prefix'),
        'weight': 0.5,
    },
    'hijacks': {
        'domains': ('autonomous_system', 'bgp_prefix'),
        'weight': 0.95,
        'mitre': ['T1557']
    },
    
    # OSPF edges
    'ospf_adjacent': {
        'domains': ('ospf_router', 'ospf_router'),
        'weight': 0.5,
    },
    'member_of_area': {
        'domains': ('ospf_router', 'ospf_area'),
        'weight': 0.3,
    },
    'injects_lsa': {
        'domains': ('ospf_router', 'ospf_area'),
        'weight': 0.9,
        'mitre': ['T1557']
    },
    
    # VXLAN edges
    'encapsulates': {
        'domains': ('vtep', 'vxlan_vni'),
        'weight': 0.4,
    },
    'escapes_to': {
        'domains': ('vxlan_vni', 'vxlan_vni'),
        'weight': 0.95,
        'mitre': ['T1599']
    },
    
    # IPsec edges
    'tunnel_endpoint': {
        'domains': ('router', 'ipsec_tunnel'),
        'weight': 0.5,
    },
    'protects_traffic': {
        'domains': ('ipsec_tunnel', 'host'),
        'weight': 0.4,
    },
    'downgrades': {
        'domains': ('ipsec_tunnel', 'ipsec_tunnel'),
        'weight': 0.9,
        'mitre': ['T1557', 'T1600']
    },
    
    # Cross-domain edges (CRITICAL for correlation)
    'redirects_traffic_from': {
        'domains': ('autonomous_system', 'host'),
        'weight': 0.85,
        'mitre': ['T1557']
    },
    'exposes_to_mitm': {
        'domains': ('ipsec_tunnel', 'user'),
        'weight': 0.9,
        'mitre': ['T1040']
    },
    'enables_lateral_to': {
        'domains': ('vxlan_vni', 'host'),
        'weight': 0.85,
        'mitre': ['T1021']
    },
}


# Critical graph queries for network-endpoint correlation
NETWORK_CROSS_DOMAIN_QUERIES = {
    'bgp_hijack_to_malware': """
        MATCH path = (as:autonomous_system)-[:hijacks]->(prefix:bgp_prefix)
                     <-[:redirects_traffic_from]-(h:host)
                     -[:executes]->(b:binary)
        WHERE b.signed = false AND b.entropy > 7.0
        RETURN path
    """,
    
    'vxlan_escape_to_data': """
        MATCH path = (vni1:vxlan_vni)-[:escapes_to]->(vni2:vxlan_vni)
                     -[:enables_lateral_to]->(h:host)
                     -[:accesses]->(db:database)
        RETURN path
    """,
    
    'ipsec_downgrade_to_cred_theft': """
        MATCH path = (t:ipsec_tunnel)-[:downgrades]->(t2:ipsec_tunnel)
                     -[:exposes_to_mitm]->(u:user)
                     -[:authenticates_to]->(h:host)
        WHERE t2.cipher = 'null' OR t2.cipher = '3des'
        RETURN path
    """,
    
    'ospf_poisoning_to_lateral': """
        MATCH path = (r:ospf_router)-[:injects_lsa]->(a:ospf_area)
                     <-[:member_of_area]-(r2:ospf_router)
                     -[:routes_to]->(h:host)
                     <-[:authenticates_to]-(u:user)
        WHERE r.trusted = false
        RETURN path
    """,
}
```

---

## Part 3: Operational Improvements

### 3.1 Missing Resilience Patterns

```python
"""
network_monitoring_resilience.py - Production hardening
"""
from dataclasses import dataclass
from typing import Dict, Optional, Callable
import asyncio
import logging

logger = logging.getLogger(__name__)


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout: int = 300
    half_open_requests: int = 3


class CircuitBreaker:
    """Circuit breaker for external network telemetry sources."""
    
    def __init__(self, name: str, config: CircuitBreakerConfig):
        self.name = name
        self.config = config
        self.failures = 0
        self.state = 'closed'  # closed, open, half_open
        self.last_failure_time = None
        self.half_open_successes = 0
    
    async def call(self, func: Callable, *args, **kwargs):
        if self.state == 'open':
            if self._should_attempt_reset():
                self.state = 'half_open'
            else:
                raise CircuitOpenError(f"Circuit {self.name} is open")
        
        try:
            result = await func(*args, **kwargs)
            self._record_success()
            return result
        except Exception as e:
            self._record_failure()
            raise
    
    def _record_success(self):
        if self.state == 'half_open':
            self.half_open_successes += 1
            if self.half_open_successes >= self.config.half_open_requests:
                self.state = 'closed'
                self.failures = 0
        self.failures = 0
    
    def _record_failure(self):
        self.failures += 1
        self.last_failure_time = asyncio.get_event_loop().time()
        
        if self.failures >= self.config.failure_threshold:
            self.state = 'open'
            logger.warning(f"Circuit {self.name} opened after {self.failures} failures")
    
    def _should_attempt_reset(self) -> bool:
        if self.last_failure_time is None:
            return True
        elapsed = asyncio.get_event_loop().time() - self.last_failure_time
        return elapsed >= self.config.recovery_timeout


class CircuitOpenError(Exception):
    pass


# ============================================================================
# DATA SOURCE FALLBACK HIERARCHY
# ============================================================================

class NetworkTelemetryManager:
    """
    Manages multiple network telemetry sources with fallback.
    """
    
    def __init__(self):
        self.sources = {
            'bgp': {
                'primary': 'ripe_ris_live',
                'secondary': 'routeviews',
                'tertiary': 'local_bgp_daemon',
                'cache': 'redis'
            },
            'flow': {
                'primary': 'cloud_flow_logs',
                'secondary': 'netflow_collector',
                'tertiary': 'pcap_sampling',
                'cache': 'redis'
            },
            'ospf': {
                'primary': 'router_syslog',
                'secondary': 'snmp_polling',
                'tertiary': 'netconf',
                'cache': 'local'
            }
        }
        
        self.circuit_breakers = {}
        for source_type, sources in self.sources.items():
            for source_name in [sources['primary'], sources['secondary'], sources['tertiary']]:
                self.circuit_breakers[source_name] = CircuitBreaker(
                    source_name,
                    CircuitBreakerConfig()
                )
    
    async def get_bgp_updates(self, prefixes: list) -> list:
        """Get BGP updates with fallback."""
        sources = self.sources['bgp']
        
        for source_key in ['primary', 'secondary', 'tertiary']:
            source_name = sources[source_key]
            breaker = self.circuit_breakers[source_name]
            
            try:
                return await breaker.call(
                    self._fetch_from_source,
                    source_name,
                    prefixes
                )
            except CircuitOpenError:
                logger.warning(f"Skipping {source_name} (circuit open)")
                continue
            except Exception as e:
                logger.warning(f"Source {source_name} failed: {e}")
                continue
        
        # All sources failed - try cache
        logger.error("All BGP sources failed, using cache")
        return await self._get_from_cache('bgp', prefixes)
    
    async def _fetch_from_source(self, source_name: str, prefixes: list) -> list:
        """Fetch data from specific source."""
        # Implementation per source
        pass
    
    async def _get_from_cache(self, source_type: str, key: any) -> list:
        """Get cached data as last resort."""
        pass
```

### 3.2 Missing Edge Cases

```python
"""
network_edge_cases.py - Handle protocol anomalies
"""

EDGE_CASES = {
    'bgp': [
        {
            'case': 'bgp_session_reset_storm',
            'description': 'Multiple BGP sessions resetting simultaneously',
            'detection': 'Track reset frequency per peer, alert if >3 resets/minute',
            'mitigation': 'Check for BGP RST attack or misconfigured keepalive'
        },
        {
            'case': 'as_path_prepend_removal',
            'description': 'Legitimate prepending removed by intermediate AS',
            'detection': 'Compare AS path length at different collectors',
            'mitigation': 'May indicate path manipulation or route filtering'
        },
        {
            'case': 'rpki_transition_period',
            'description': 'ROA exists but enforcement not enabled',
            'detection': 'RPKI status is VALID but route still accepted from INVALID origin',
            'mitigation': 'Alert on ROV enforcement gap'
        },
        {
            'case': 'bgp_confederation_leak',
            'description': 'Internal confederation routes leaked externally',
            'detection': 'AS_CONFED_SET in path received from external peer',
            'mitigation': 'Filter confederation attributes at boundary'
        },
    ],
    
    'ospf': [
        {
            'case': 'ospf_mtu_mismatch',
            'description': 'MTU mismatch preventing adjacency',
            'detection': 'Adjacency stuck in ExStart/Exchange state',
            'mitigation': 'May be used to selectively break adjacencies'
        },
        {
            'case': 'ospf_network_type_mismatch',
            'description': 'Point-to-point vs broadcast mismatch',
            'detection': 'Inconsistent DR/BDR election, duplicate router IDs',
            'mitigation': 'Verify interface configuration'
        },
        {
            'case': 'ospf_area_type_change',
            'description': 'Area type changed from stub to normal',
            'detection': 'External LSAs suddenly appearing in stub area',
            'mitigation': 'Verify ABR configuration'
        },
    ],
    
    'vxlan': [
        {
            'case': 'vxlan_vni_exhaustion',
            'description': 'VNI space exhausted (16M limit)',
            'detection': 'New segment creation fails',
            'mitigation': 'Implement VNI recycling policy'
        },
        {
            'case': 'vtep_reachability_loss',
            'description': 'VTEP underlay path broken',
            'detection': 'VXLAN encapsulated traffic not reaching destination',
            'mitigation': 'Check underlay routing, BFD for VXLAN'
        },
        {
            'case': 'arp_suppression_bypass',
            'description': 'ARP flooding despite suppression config',
            'detection': 'High ARP traffic within VNI',
            'mitigation': 'Verify distributed gateway configuration'
        },
    ],
    
    'ipsec': [
        {
            'case': 'ipsec_nat_traversal_failure',
            'description': 'NAT-T negotiation fails after NAT device change',
            'detection': 'IKE negotiation succeeds, ESP fails',
            'mitigation': 'Check NAT keepalive, UDP encapsulation'
        },
        {
            'case': 'ipsec_anti_replay_window',
            'description': 'Legitimate packets dropped due to replay window',
            'detection': 'Packet drops with sequence number outside window',
            'mitigation': 'Increase replay window size (security tradeoff)'
        },
        {
            'case': 'ipsec_sa_lifetime_desync',
            'description': 'SA lifetimes mismatched between peers',
            'detection': 'Tunnel flaps at SA expiration',
            'mitigation': 'Synchronize SA lifetime configuration'
        },
    ],
}
```

---

## Part 4: Integration Architecture

### 4.1 Unified Event Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    UNIFIED JANUSEC EVENT PIPELINE                            │
└─────────────────────────────────────────────────────────────────────────────┘

                              ┌──────────────────┐
                              │   Event Sources   │
                              └────────┬─────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌───────────────┐            ┌───────────────┐            ┌───────────────┐
│   NETWORK     │            │   ENDPOINT    │            │    CLOUD      │
│   TELEMETRY   │            │   TELEMETRY   │            │   TELEMETRY   │
├───────────────┤            ├───────────────┤            ├───────────────┤
│ • BGP updates │            │ • Sysmon      │            │ • CloudTrail  │
│ • OSPF LSAs   │            │ • EDR events  │            │ • VPC Flows   │
│ • NetFlow     │            │ • Binary exec │            │ • IAM events  │
│ • SNMP traps  │            │ • Auth logs   │            │ • K8s audit   │
└───────┬───────┘            └───────┬───────┘            └───────┬───────┘
        │                            │                            │
        └──────────────────────────────┼──────────────────────────────┘
                                       │
                              ┌────────▼─────────┐
                              │   NORMALIZER     │
                              │  (Canonical Schema) │
                              └────────┬─────────┘
                                       │
                              ┌────────▼─────────┐
                              │  PRE-ENRICHMENT  │
                              ├──────────────────┤
                              │ • Binary analysis│
                              │ • GeoIP lookup   │
                              │ • Asset tagging  │
                              │ • TI lookup      │
                              └────────┬─────────┘
                                       │
                              ┌────────▼─────────┐
                              │    HOPGRAPH      │
                              │   CORRELATION    │
                              ├──────────────────┤
                              │ • Node creation  │
                              │ • Edge creation  │
                              │ • Cross-domain   │
                              │   correlation    │
                              │ • Pattern detect │
                              └────────┬─────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌───────────────┐            ┌───────────────┐            ┌───────────────┐
│  NETWORK      │            │   ENDPOINT    │            │    CROSS-     │
│  DETECTORS    │            │   DETECTORS   │            │    DOMAIN     │
├───────────────┤            ├───────────────┤            ├───────────────┤
│ • BGP hijack  │            │ • Malware     │            │ • BGP→Malware │
│ • OSPF poison │            │ • Injection   │            │ • VXLAN→Lateral│
│ • IPsec fail  │            │ • Cred theft  │            │ • IPsec→CredTheft│
│ • VXLAN escape│            │ • Lateral mvmt│            │ • DNS→SupplyChain│
└───────┬───────┘            └───────┬───────┘            └───────┬───────┘
        │                            │                            │
        └──────────────────────────────┼──────────────────────────────┘
                                       │
                              ┌────────▼─────────┐
                              │  INCIDENT        │
                              │  CORRELATION     │
                              │  (Attack Chains) │
                              └────────┬─────────┘
                                       │
                              ┌────────▼─────────┐
                              │  TIER 1 LLM      │
                              │  TRIAGE          │
                              └────────┬─────────┘
                                       │
                              ┌────────▼─────────┐
                              │  SOC ANALYST     │
                              │  WORKBENCH       │
                              └──────────────────┘
```

### 4.2 Shared Configuration Schema

```yaml
# janusec_unified_config.yaml

domains:
  network:
    enabled: true
    sources:
      - type: bgp
        provider: ripe_ris
        monitored_prefixes: ${MONITORED_PREFIXES}
        monitored_asns: ${MONITORED_ASNS}
      - type: flow
        provider: aws_vpc_flow
        regions: ${AWS_REGIONS}
      - type: ospf
        provider: syslog
        router_ips: ${ROUTER_IPS}
    
  endpoint:
    enabled: true
    sources:
      - type: edr
        provider: crowdstrike
      - type: sysmon
        provider: windows_event_log
      - type: binary_analysis
        enabled: true
        yara_rules_path: /opt/yara-rules
        
  cloud:
    enabled: true
    sources:
      - type: cloudtrail
        regions: ${AWS_REGIONS}
      - type: azure_activity
        subscriptions: ${AZURE_SUBS}

correlation:
  cross_domain:
    enabled: true
    patterns:
      - name: bgp_hijack_to_malware
        network_trigger: bgp_hijack
        endpoint_correlation: binary_execution
        time_window_minutes: 60
        
      - name: vxlan_escape_to_lateral
        network_trigger: vxlan_boundary_violation
        endpoint_correlation: authentication
        time_window_minutes: 30
        
      - name: ipsec_to_credential_theft
        network_trigger: ipsec_downgrade
        identity_correlation: failed_auth_then_success
        time_window_minutes: 60

hopgraph:
  node_types:
    # Include all from binary + network
    include:
      - network_infrastructure_nodes
      - binary_nodes
      - endpoint_nodes
      - cloud_nodes
      - identity_nodes
  
  edge_types:
    include:
      - network_infrastructure_edges
      - binary_edges
      - cross_domain_edges

reporting:
  personas:
    - name: network_architect
      sections:
        - network_topology_impact
        - routing_analysis
        - protocol_details
        
    - name: soc_analyst
      sections:
        - attack_chain
        - timeline
        - iocs
        - binary_analysis
        
    - name: ciso
      sections:
        - executive_summary
        - business_impact
        - risk_metrics
```

---

## Summary: Key Improvements

| Category | Gap | Priority | Effort |
|----------|-----|----------|--------|
| **BGP** | AS path manipulation detection | P0 | Medium |
| **BGP** | Community abuse detection | P0 | Low |
| **BGP** | Route leak detection (RFC 7908) | P1 | Medium |
| **BGP** | Real-time stream analysis | P1 | High |
| **OSPF** | Sequence number attack detection | P1 | Medium |
| **OSPF** | Area boundary violation detection | P1 | Medium |
| **Cross-Domain** | BGP→Malware correlation | P0 | High |
| **Cross-Domain** | VXLAN→Lateral correlation | P0 | High |
| **Cross-Domain** | IPsec→Credential theft | P1 | Medium |
| **Cross-Domain** | DNS→Supply chain | P1 | High |
| **HopGraph** | Network infrastructure nodes | P0 | Medium |
| **HopGraph** | Cross-domain edges | P0 | Medium |
| **Resilience** | Circuit breakers | P1 | Medium |
| **Resilience** | Source fallback hierarchy | P1 | Medium |
| **Edge Cases** | Protocol anomaly handling | P2 | Medium |

---

## Integration with Binary Analysis Document

The binary analysis and network infrastructure documents should be developed in parallel with these touchpoints:

1. **Shared HopGraph Schema**: Both documents add node/edge types to the same graph
2. **Cross-Domain Correlators**: Network events trigger binary analysis lookups
3. **Unified Event Pipeline**: Single normalization layer for all telemetry
4. **Shared Persona Reports**: Network + binary findings in same report

**Implementation Order:**
1. Week 1-2: Core binary analysis + Core BGP/OSPF detection
2. Week 3-4: HopGraph integration (both domains)
3. Week 5-6: Cross-domain correlation engine
4. Week 7-8: Unified reporting + UI
5. Week 9+: Advanced detections, edge cases, optimization

This gives you true "data center to edge" visibility that no competitor offers.
