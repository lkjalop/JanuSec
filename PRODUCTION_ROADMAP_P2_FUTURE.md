# JanuSec Platform - P2 FUTURE Production Roadmap
## Advanced Features for Long-Term Competitive Edge

**Priority Level:** P2 - FUTURE / NICE-TO-HAVE
**Timeline:** 12-20 Weeks
**Business Impact:** MEDIUM - Niche use cases, advanced capabilities
**Dependencies:** P0 and P1 features completed, specialized infrastructure

---

## EXECUTIVE SUMMARY

This roadmap covers **advanced, specialized features** for niche security use cases and cutting-edge threat detection capabilities:

1. **BGP Anomaly Detection** - Network infrastructure threat detection
2. **eBPF Kernel-Level Tracing** - Advanced endpoint monitoring and container security

**Expected Outcome:** Platform differentiation for **infrastructure-focused security teams**, **cloud-native environments**, and **advanced threat research**.

**Business Justification:** These features target **<20% of customers** but command **premium pricing** for infrastructure security and cloud-native workloads.

---

## P2-1: BGP ANOMALY DETECTION

### Current State
- ⚠️ **Endpoints exist:** Basic API structure in `src/api/bgp_endpoints.py`
- ❌ **No BGP feed integration:** No live route data
- ❌ **No hijack detection:** No anomaly analysis

### Business Value
- **Target market:** ISPs, cloud providers, large enterprises with BGP
- **Use cases:** Route hijacking detection, ASN reputation, infrastructure security
- **Market size:** Niche (5-10% of customers)
- **Pricing opportunity:** Premium infrastructure security tier

### What is BGP Anomaly Detection?

**Border Gateway Protocol (BGP)** is the routing protocol of the internet. Attacks include:
- **Route Hijacking:** Malicious AS announces routes for victim IPs
- **Prefix Deaggregation:** Announcing more specific routes to intercept traffic
- **Route Leaks:** Accidental or malicious route propagation
- **AS Path Manipulation:** Forging AS paths for traffic interception

### Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 BGP Monitoring Pipeline                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐       ┌──────────────┐                    │
│  │  ExaBGP      │       │  GoBGP       │                    │
│  │  Listener    │       │  Listener    │                    │
│  └──────┬───────┘       └──────┬───────┘                    │
│         │                       │                            │
│         └───────────┬───────────┘                            │
│                     ▼                                        │
│         ┌────────────────────────┐                          │
│         │  BGP Message Parser    │                          │
│         │  (UPDATE/WITHDRAW)     │                          │
│         └────────────────────────┘                          │
│                     │                                        │
│         ┌───────────┼───────────┐                           │
│         ▼           ▼           ▼                           │
│  ┌──────────┐ ┌─────────┐ ┌──────────┐                     │
│  │ Hijack   │ │  Leak   │ │   ASN    │                     │
│  │ Detector │ │Detector │ │Reputation│                     │
│  └──────────┘ └─────────┘ └──────────┘                     │
│         │           │           │                           │
│         └───────────┼───────────┘                           │
│                     ▼                                        │
│         ┌────────────────────────┐                          │
│         │  BGP Alert Generator   │                          │
│         └────────────────────────┘                          │
│                     │                                        │
│                     ▼                                        │
│         ┌────────────────────────┐                          │
│         │   HopGraph Integration │                          │
│         │   (Network Threats)    │                          │
│         └────────────────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Plan

#### Phase 1: BGP Listener Integration (Week 1-3)

**File: `src/integrations/bgp/exabgp_listener.py`** (NEW)

```python
"""
ExaBGP listener for BGP route updates.
Receives BGP UPDATE and WITHDRAW messages and normalizes for analysis.
"""

import asyncio
import json
from typing import Dict, Any, AsyncIterator, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class ExaBGPListener:
    """
    ExaBGP listener that receives BGP messages via JSON API.

    ExaBGP is configured to send JSON-formatted BGP updates to this listener.
    Configuration in exabgp.conf:
        process json-listener {
            run python /path/to/listener.py;
            encoder json;
        }
    """

    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self._baseline_routes: Dict[str, Dict[str, Any]] = {}

    async def listen(self) -> AsyncIterator[Dict[str, Any]]:
        """Listen for BGP updates from ExaBGP stdin."""

        logger.info(f"Starting ExaBGP listener for tenant {self.tenant_id}")

        # ExaBGP sends JSON messages to stdin
        while True:
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, input
                )

                if not line:
                    continue

                # Parse JSON message
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug(f"Non-JSON line: {line}")
                    continue

                # Process BGP message
                bgp_event = await self._parse_bgp_message(message)

                if bgp_event:
                    yield bgp_event

            except EOFError:
                logger.info("ExaBGP connection closed")
                break
            except Exception as e:
                logger.error(f"ExaBGP listener error: {e}")
                await asyncio.sleep(1)

    async def _parse_bgp_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse ExaBGP JSON message into normalized BGP event."""

        # ExaBGP message types
        msg_type = message.get("type")

        if msg_type == "update":
            return await self._parse_update(message)
        elif msg_type == "withdraw":
            return await self._parse_withdraw(message)
        elif msg_type == "state":
            # Peer state change (up/down)
            return await self._parse_state(message)
        else:
            return None

    async def _parse_update(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Parse BGP UPDATE message."""

        neighbor = message.get("neighbor", {})
        update = message.get("update", {})

        # Extract announced prefixes
        announce = update.get("announce", {})
        ipv4_unicast = announce.get("ipv4 unicast", {})

        events = []

        for next_hop, prefixes in ipv4_unicast.items():
            for prefix_data in prefixes:
                prefix = prefix_data.get("nlri")
                as_path = prefix_data.get("as-path", [])

                # Build BGP event
                bgp_event = {
                    "timestamp": datetime.utcnow(),
                    "tenant_id": self.tenant_id,
                    "event_type": "bgp_route_announce",
                    "peer_address": neighbor.get("address", {}).get("peer"),
                    "peer_asn": neighbor.get("asn", {}).get("peer"),
                    "prefix": prefix,
                    "next_hop": next_hop,
                    "as_path": as_path,
                    "origin_asn": as_path[-1] if as_path else None,
                    "path_length": len(as_path),
                    "raw_message": message
                }

                # Check for anomalies
                await self._detect_anomalies(bgp_event)

                events.append(bgp_event)

        return events[0] if events else None

    async def _parse_withdraw(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Parse BGP WITHDRAW message."""

        neighbor = message.get("neighbor", {})
        withdraw = message.get("withdraw", {})

        # Extract withdrawn prefixes
        ipv4_unicast = withdraw.get("ipv4 unicast", [])

        if ipv4_unicast:
            prefix = ipv4_unicast[0]

            bgp_event = {
                "timestamp": datetime.utcnow(),
                "tenant_id": self.tenant_id,
                "event_type": "bgp_route_withdraw",
                "peer_address": neighbor.get("address", {}).get("peer"),
                "peer_asn": neighbor.get("asn", {}).get("peer"),
                "prefix": prefix,
                "raw_message": message
            }

            return bgp_event

        return None

    async def _parse_state(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Parse BGP peer state change."""

        neighbor = message.get("neighbor", {})
        state = message.get("state")

        bgp_event = {
            "timestamp": datetime.utcnow(),
            "tenant_id": self.tenant_id,
            "event_type": "bgp_peer_state",
            "peer_address": neighbor.get("address", {}).get("peer"),
            "peer_asn": neighbor.get("asn", {}).get("peer"),
            "state": state,  # "up", "down", "connected"
            "raw_message": message
        }

        return bgp_event

    async def _detect_anomalies(self, bgp_event: Dict[str, Any]) -> None:
        """Detect BGP anomalies in route announcement."""

        prefix = bgp_event["prefix"]
        origin_asn = bgp_event.get("origin_asn")
        as_path = bgp_event.get("as_path", [])

        # Check against baseline
        if prefix in self._baseline_routes:
            baseline = self._baseline_routes[prefix]
            baseline_origin = baseline.get("origin_asn")
            baseline_path_len = baseline.get("path_length")

            # Hijack detection: Different origin ASN
            if origin_asn != baseline_origin:
                bgp_event["anomaly"] = "origin_asn_change"
                bgp_event["anomaly_details"] = {
                    "baseline_origin": baseline_origin,
                    "new_origin": origin_asn,
                    "suspicion_score": 0.8
                }
                logger.warning(
                    f"Potential BGP hijack: Prefix {prefix} origin changed "
                    f"from AS{baseline_origin} to AS{origin_asn}"
                )

            # Route leak detection: Unexpected AS in path
            if baseline.get("expected_ases"):
                unexpected_ases = set(as_path) - set(baseline["expected_ases"])
                if unexpected_ases:
                    bgp_event["anomaly"] = "unexpected_as_path"
                    bgp_event["anomaly_details"] = {
                        "unexpected_ases": list(unexpected_ases),
                        "suspicion_score": 0.6
                    }

            # Path length anomaly
            if abs(len(as_path) - baseline_path_len) > 3:
                bgp_event["anomaly"] = "path_length_spike"
                bgp_event["anomaly_details"] = {
                    "baseline_length": baseline_path_len,
                    "new_length": len(as_path),
                    "suspicion_score": 0.5
                }

        else:
            # First time seeing this prefix, add to baseline
            self._baseline_routes[prefix] = {
                "origin_asn": origin_asn,
                "path_length": len(as_path),
                "first_seen": datetime.utcnow(),
                "expected_ases": set(as_path)
            }
```

**File: `src/core/detectors/bgp_hijack.py`** (NEW)

```python
"""
BGP hijack detection using heuristics and threat intelligence.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class BGPHijackDetector:
    """Detects BGP route hijacking and manipulation."""

    def __init__(self):
        # ASN reputation database (simplified)
        self._asn_reputation = {}  # TODO: Integrate with threat intel

    async def analyze_route_change(
        self,
        prefix: str,
        old_origin_asn: int,
        new_origin_asn: int,
        as_path: List[int]
    ) -> Dict[str, Any]:
        """Analyze BGP route change for hijack indicators."""

        findings = {
            "is_hijack": False,
            "confidence": 0.0,
            "indicators": [],
            "mitre_techniques": [],
            "recommended_action": None
        }

        # Indicator 1: ASN reputation check
        if await self._is_malicious_asn(new_origin_asn):
            findings["indicators"].append("new_origin_asn_malicious")
            findings["confidence"] += 0.4

        # Indicator 2: Origin change without history
        if old_origin_asn and new_origin_asn != old_origin_asn:
            findings["indicators"].append("origin_asn_changed")
            findings["confidence"] += 0.3

        # Indicator 3: Suspicious AS path (known hijack ASN in path)
        for asn in as_path:
            if await self._is_malicious_asn(asn):
                findings["indicators"].append(f"suspicious_as{asn}_in_path")
                findings["confidence"] += 0.2

        # Indicator 4: Geolocation inconsistency
        # TODO: Check if new origin ASN is in different country than expected

        # Verdict
        if findings["confidence"] >= 0.7:
            findings["is_hijack"] = True
            findings["mitre_techniques"] = ["T1565.002"]  # Data Manipulation: Transmitted Data
            findings["recommended_action"] = "URGENT: Contact NOC to verify route change. Consider prefix filtering."

        elif findings["confidence"] >= 0.4:
            findings["is_hijack"] = False
            findings["recommended_action"] = "MONITOR: Unusual route change detected. Verify with upstream provider."

        return findings

    async def _is_malicious_asn(self, asn: int) -> bool:
        """Check if ASN is known malicious."""
        # TODO: Integrate with threat intel feeds (Team Cymru, Spamhaus, etc.)
        # For now, simple reputation check
        reputation = self._asn_reputation.get(asn, 0)
        return reputation < -0.5

    async def detect_prefix_deaggregation(
        self,
        new_prefix: str,
        existing_prefixes: List[str]
    ) -> bool:
        """Detect if new prefix is more specific than existing (hijack tactic)."""

        # Convert to IP network objects for comparison
        # TODO: Use ipaddress library to check if new_prefix is subnet of existing

        return False  # Placeholder
```

#### Phase 2: ASN Reputation & Threat Intel (Week 4-6)

**File: `src/integrations/bgp/asn_reputation.py`** (NEW)

```python
"""
ASN reputation integration with Team Cymru and threat intel feeds.
"""

import asyncio
import httpx
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ASNReputationService:
    """ASN reputation lookup and threat intelligence."""

    TEAM_CYMRU_DNS = "asn.cymru.com"
    SPAMHAUS_ASN_DROP = "https://www.spamhaus.org/drop/asndrop.txt"

    def __init__(self):
        self._reputation_cache: Dict[int, Dict[str, Any]] = {}
        self._malicious_asns: set = set()

    async def initialize(self):
        """Load malicious ASN lists."""
        await self._load_spamhaus_asndrop()

    async def get_asn_info(self, asn: int) -> Dict[str, Any]:
        """Get ASN information and reputation."""

        # Check cache
        if asn in self._reputation_cache:
            return self._reputation_cache[asn]

        # Query Team Cymru
        asn_info = await self._query_team_cymru(asn)

        # Add reputation score
        asn_info["is_malicious"] = asn in self._malicious_asns
        asn_info["reputation_score"] = -1.0 if asn_info["is_malicious"] else 0.5

        # Cache result
        self._reputation_cache[asn] = asn_info

        return asn_info

    async def _query_team_cymru(self, asn: int) -> Dict[str, Any]:
        """Query Team Cymru for ASN info."""

        # Team Cymru DNS-based ASN lookup
        # Query: AS<asn>.asn.cymru.com TXT
        # Response: "ASN | Country | Registry | Allocated | AS Name"

        # TODO: Implement DNS query
        # For now, return placeholder

        return {
            "asn": asn,
            "country": "US",  # Placeholder
            "registry": "ARIN",
            "name": f"AS{asn}",
            "allocated": "2000-01-01"
        }

    async def _load_spamhaus_asndrop(self):
        """Load Spamhaus ASN DROP list (malicious ASNs)."""

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.SPAMHAUS_ASN_DROP, timeout=30.0)
                response.raise_for_status()

                lines = response.text.split("\n")

                for line in lines:
                    line = line.strip()

                    # Skip comments
                    if line.startswith(";") or not line:
                        continue

                    # Parse ASN (format: "AS12345 ; comment")
                    if line.startswith("AS"):
                        asn_str = line.split(";")[0].strip()
                        asn = int(asn_str.replace("AS", ""))
                        self._malicious_asns.add(asn)

                logger.info(f"Loaded {len(self._malicious_asns)} malicious ASNs from Spamhaus")

        except Exception as e:
            logger.error(f"Failed to load Spamhaus ASN DROP: {e}")
```

#### Phase 3: Integration & Alerting (Week 7-8)

**File: `src/api/bgp_endpoints.py`** (ENHANCE)

```python
"""
BGP monitoring endpoints (enhanced from stub).
"""

from fastapi import APIRouter, Depends
from typing import List, Dict, Any

from src.integrations.bgp.exabgp_listener import ExaBGPListener
from src.core.detectors.bgp_hijack import BGPHijackDetector

router = APIRouter()


@router.get("/api/v1/bgp/routes")
async def get_bgp_routes(
    tenant_id: str = Depends(get_tenant_id),
    prefix: str = None,
    origin_asn: int = None
):
    """Get current BGP routes."""

    # Query BGP route store
    # TODO: Implement route storage and query

    return {
        "route_count": 0,
        "routes": []
    }


@router.get("/api/v1/bgp/anomalies")
async def get_bgp_anomalies(
    tenant_id: str = Depends(get_tenant_id),
    severity: str = None
):
    """Get BGP anomalies and suspected hijacks."""

    # Query anomaly store
    # TODO: Implement

    return {
        "anomaly_count": 0,
        "anomalies": []
    }


@router.post("/api/v1/bgp/alert-config")
async def configure_bgp_alerts(
    config: Dict[str, Any],
    tenant_id: str = Depends(get_tenant_id)
):
    """Configure BGP alert thresholds and notification."""

    # Store alert configuration
    # Example: alert_on_origin_change, alert_on_path_spike, etc.

    return {"status": "configured"}
```

### Testing & Validation

- [ ] ExaBGP integration tested with simulated BGP feeds
- [ ] Hijack detection validated against known hijack incidents (2008 Pakistan YouTube, 2018 Amazon Route 53)
- [ ] ASN reputation integration with Team Cymru and Spamhaus
- [ ] Alert generation for route changes
- [ ] HopGraph integration (BGP event → network event correlation)

**Timeline:** 8 weeks
**Complexity:** HIGH
**Dependencies:** ExaBGP or GoBGP deployment, BGP peering access

---

## P2-2: eBPF KERNEL-LEVEL TRACING

### Current State
- ⚠️ **Endpoints exist:** Basic API in `src/api/ebpf_endpoints.py`
- ❌ **No eBPF agent:** No kernel module or BPF programs
- ❌ **No container escape detection:** No runtime security

### Business Value
- **Target market:** Cloud-native companies, Kubernetes users, container security
- **Use cases:** Container escape detection, syscall anomalies, kernel-level threats
- **Market size:** Growing (30-40% of cloud customers)
- **Competitive gap:** Advanced capability, few platforms offer eBPF

### What is eBPF?

**Extended Berkeley Packet Filter (eBPF)** enables running sandboxed programs in the Linux kernel without modifying kernel code. Security use cases:
- **Syscall monitoring:** Detect unusual system calls (container escapes)
- **Network monitoring:** Packet-level visibility without tcpdump
- **File access tracking:** Monitor sensitive file access in real-time
- **Process monitoring:** Track all process creation, execution, termination
- **Container security:** Detect container breakouts and privilege escalation

### Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               eBPF Runtime Security Pipeline                 │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                  Linux Kernel Space                     │ │
│  │                                                          │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │ │
│  │  │ Syscall  │  │ Network  │  │  File    │             │ │
│  │  │  Probe   │  │  Probe   │  │  Probe   │             │ │
│  │  │ (BPF)    │  │ (BPF)    │  │ (BPF)    │             │ │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘             │ │
│  │       │             │             │                     │ │
│  │       └─────────────┼─────────────┘                     │ │
│  │                     ▼                                   │ │
│  │           ┌──────────────────┐                          │ │
│  │           │  BPF Ring Buffer │                          │ │
│  │           └──────────────────┘                          │ │
│  └────────────────────┬───────────────────────────────────┘ │
│                       │                                      │
│  ┌────────────────────┼───────────────────────────────────┐ │
│  │              User Space (eBPF Agent)                    │ │
│  │                    ▼                                    │ │
│  │       ┌────────────────────────┐                        │ │
│  │       │  Event Aggregator      │                        │ │
│  │       │  (Batch + Filter)      │                        │ │
│  │       └────────────────────────┘                        │ │
│  │                    │                                    │ │
│  │       ┌────────────┼────────────┐                       │ │
│  │       ▼            ▼            ▼                       │ │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐                │ │
│  │  │Container│ │ Syscall  │ │  File    │                │ │
│  │  │ Escape  │ │ Anomaly  │ │ Access   │                │ │
│  │  │Detector │ │ Detector │ │ Monitor  │                │ │
│  │  └─────────┘ └──────────┘ └──────────┘                │ │
│  │       │            │            │                       │ │
│  │       └────────────┼────────────┘                       │ │
│  │                    ▼                                    │ │
│  │       ┌────────────────────────┐                        │ │
│  │       │  JanuSec API Client    │                        │ │
│  │       │  (Event Forwarder)     │                        │ │
│  │       └────────────────────────┘                        │ │
│  └─────────────────────────────────────────────────────────┘ │
│                       │                                      │
│                       ▼                                      │
│         ┌──────────────────────────┐                        │
│         │  JanuSec Event Pipeline  │                        │
│         │  (Process, Correlate)    │                        │
│         └──────────────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

### Implementation Plan

#### Phase 1: eBPF Agent Development (Week 1-6)

**Technology Stack:**
- **libbpf** - C library for loading eBPF programs
- **bpftrace** - High-level tracing language (for prototyping)
- **Cilium/Tetragon** - Optional: leverage existing eBPF security framework

**File: `agents/ebpf/syscall_monitor.bpf.c`** (NEW - BPF Program)

```c
/*
 * eBPF program to monitor syscalls for container escape detection.
 * Detects suspicious syscalls like mount, unshare, ptrace from containers.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct syscall_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 syscall_nr;
    __u64 timestamp;
    char comm[16];  // Process name
    __u8 in_container;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// List of suspicious syscalls
const __u32 SUSPICIOUS_SYSCALLS[] = {
    165,  // mount
    272,  // unshare
    101,  // ptrace
    175,  // init_module (load kernel module)
    176,  // delete_module
    310,  // process_vm_readv
    311   // process_vm_writev
};

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = pid_tgid;
    __u32 syscall_nr = ctx->id;

    // Filter: only monitor suspicious syscalls
    int is_suspicious = 0;
    for (int i = 0; i < sizeof(SUSPICIOUS_SYSCALLS)/sizeof(__u32); i++) {
        if (syscall_nr == SUSPICIOUS_SYSCALLS[i]) {
            is_suspicious = 1;
            break;
        }
    }

    if (!is_suspicious)
        return 0;

    // Allocate event
    struct syscall_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->tid = tid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->syscall_nr = syscall_nr;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Detect if process is in container (check for cgroup)
    // Simplified: check if pid namespace != init namespace
    event->in_container = (bpf_get_current_task()->nsproxy->pid_ns_for_children->ns.inum != PROC_PID_INIT_INO);

    // Submit event
    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**File: `agents/ebpf/ebpf_agent.py`** (NEW - User Space Agent)

```python
"""
eBPF agent that loads BPF programs and forwards events to JanuSec.
"""

import asyncio
import httpx
from bcc import BPF
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)


class eBPFAgent:
    """eBPF runtime security agent."""

    def __init__(self, janusec_api_url: str, api_key: str, tenant_id: str):
        self.janusec_api_url = janusec_api_url
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.bpf = None

    async def start(self):
        """Load eBPF programs and start monitoring."""

        logger.info("Loading eBPF programs...")

        # Load BPF program from source
        with open("syscall_monitor.bpf.c") as f:
            bpf_source = f.read()

        self.bpf = BPF(text=bpf_source)

        # Attach to tracepoint
        self.bpf.attach_tracepoint(tp="raw_syscalls:sys_enter", fn_name="trace_syscall_enter")

        logger.info("eBPF programs loaded, monitoring started")

        # Poll ring buffer for events
        await self._poll_events()

    async def _poll_events(self):
        """Poll eBPF ring buffer and forward events."""

        def event_callback(cpu, data, size):
            """Callback for eBPF events."""
            event = self.bpf["events"].event(data)

            # Convert to JSON
            event_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "tenant_id": self.tenant_id,
                "event_type": "ebpf_syscall",
                "pid": event.pid,
                "tid": event.tid,
                "uid": event.uid,
                "syscall_nr": event.syscall_nr,
                "syscall_name": self._get_syscall_name(event.syscall_nr),
                "process_name": event.comm.decode("utf-8", errors="replace"),
                "in_container": bool(event.in_container),
                "suspicion_score": self._calculate_suspicion(event)
            }

            # Forward to JanuSec asynchronously
            asyncio.create_task(self._forward_event(event_data))

        # Open ring buffer
        self.bpf["events"].open_ring_buffer(event_callback)

        # Poll loop
        while True:
            try:
                self.bpf.ring_buffer_poll(timeout=100)  # 100ms timeout
            except KeyboardInterrupt:
                logger.info("Shutting down eBPF agent")
                break

    async def _forward_event(self, event_data: dict):
        """Forward eBPF event to JanuSec API."""

        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json"
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.janusec_api_url}/api/v1/events",
                    json=event_data,
                    headers=headers,
                    timeout=5.0
                )

                if response.status_code != 200:
                    logger.warning(f"Failed to forward event: {response.status_code}")

            except Exception as e:
                logger.error(f"Event forwarding error: {e}")

    def _get_syscall_name(self, syscall_nr: int) -> str:
        """Map syscall number to name."""
        syscall_map = {
            165: "mount",
            272: "unshare",
            101: "ptrace",
            175: "init_module",
            176: "delete_module",
            310: "process_vm_readv",
            311: "process_vm_writev"
        }
        return syscall_map.get(syscall_nr, f"syscall_{syscall_nr}")

    def _calculate_suspicion(self, event) -> float:
        """Calculate suspicion score for syscall."""

        score = 0.3  # Base score for suspicious syscall

        # Container escape indicators
        if event.in_container:
            if event.syscall_nr == 165:  # mount from container
                score += 0.5
            elif event.syscall_nr == 272:  # unshare (namespace manipulation)
                score += 0.6
            elif event.syscall_nr == 101:  # ptrace from container
                score += 0.4

        # Root user from container is suspicious
        if event.uid == 0 and event.in_container:
            score += 0.2

        return min(score, 1.0)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 4:
        print("Usage: ebpf_agent.py <janusec_url> <api_key> <tenant_id>")
        sys.exit(1)

    agent = eBPFAgent(
        janusec_api_url=sys.argv[1],
        api_key=sys.argv[2],
        tenant_id=sys.argv[3]
    )

    asyncio.run(agent.start())
```

#### Phase 2: Container Escape Detection (Week 7-10)

**Detection Patterns:**
- Mount syscall from container (score: 0.8)
- Namespace manipulation (unshare, setns) from non-privileged container (score: 0.9)
- Loading kernel modules from container (score: 1.0)
- Access to /proc/sys/kernel from container (score: 0.7)
- cgroup manipulation from container (score: 0.8)

#### Phase 3: Integration & Deployment (Week 11-12)

**Deployment Options:**
1. **DaemonSet** (Kubernetes) - Deploy eBPF agent on every node
2. **Systemd Service** (Linux VMs) - Run as background service
3. **Container Sidecar** (Optional) - Per-pod monitoring

**Testing:**
- Kubernetes deployment with RBAC
- Container escape simulation (CVE-2019-5736 runc breakout)
- Performance impact measurement (<2% CPU overhead target)

**Timeline:** 12 weeks
**Complexity:** VERY HIGH
**Dependencies:** Linux kernel 5.4+, CAP_BPF capability, kernel headers

---

## TOTAL P2 TIMELINE: 12-20 Weeks

**Recommended Approach:**
- **BGP (8 weeks):** For customers with network infrastructure focus
- **eBPF (12 weeks):** For cloud-native customers with Kubernetes

**Business Decision:** Pick ONE based on customer demand, or delay both until P0/P1 complete.

---

## CONCLUSION

P2 features are **advanced, niche capabilities** that differentiate JanuSec for specific market segments. **Recommended approach:** Complete P0 and P1 first, then evaluate customer demand before investing in P2.

**Total Production Roadmap Summary:**
- **P0 (Critical):** 8-10 weeks - Email/IAM live ingestion, LLM enhancements, binary analysis
- **P1 (High Priority):** 8-12 weeks - KAPE forensics, LOLBins expansion, personas, scheduling
- **P2 (Future):** 12-20 weeks - BGP anomaly detection, eBPF tracing

**Estimated Total Time to Full Feature Parity:** 28-42 weeks (7-10 months) with 2-3 dedicated engineers.
