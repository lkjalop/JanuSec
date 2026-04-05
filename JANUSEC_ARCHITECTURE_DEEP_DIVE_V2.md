# JanuSec Architecture Deep Dive v2
## Demand-Driven XDR Triage Platform

**Design Philosophy**: Collect the minimum telemetry required for high-confidence correlation (Network + Endpoint), then intelligently identify gaps and pull additional context on-demand. This is not cost-cutting—it's architecturally sound security engineering.

---

## Table of Contents

1. [Core Architecture: The Demand-Driven Model](#1-core-architecture-the-demand-driven-model)
2. [Why Network + Endpoint Is the Right Foundation](#2-why-network--endpoint-is-the-right-foundation)
3. [The Missing Telemetry Detector](#3-the-missing-telemetry-detector)
4. [Deployment Topologies](#4-deployment-topologies)
5. [Cloud-Native Tool Integration](#5-cloud-native-tool-integration)
6. [Investigation Connectors](#6-investigation-connectors)
7. [False Positive Reduction Strategies](#7-false-positive-reduction-strategies)
8. [Tenant Isolation Models](#8-tenant-isolation-models)
9. [Cost Modeling & FinOps](#9-cost-modeling--finops)
10. [Security & Compliance Considerations](#10-security--compliance-considerations)
11. [Implementation Roadmap](#11-implementation-roadmap)
12. [Further Reading](#12-further-reading)

---

## 1. Core Architecture: The Demand-Driven Model

### The Problem with Traditional XDR/SIEM

Traditional security platforms follow a "collect everything, correlate later" model:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Traditional Model: Collect Everything                                       │
│                                                                             │
│   Endpoint ────┐                                                            │
│   Network ─────┤                                                            │
│   Identity ────┤                                                            │
│   Email ───────┼────► Central Lake ────► Rules/ML ────► Alerts             │
│   Cloud ───────┤      (massive)          (noisy)        (overwhelming)      │
│   API ─────────┤                                                            │
│   CSPM ────────┘                                                            │
│                                                                             │
│   Problems:                                                                 │
│   • 70-90% of collected data never used for detection                       │
│   • Storage costs scale linearly with data sources                          │
│   • More data sources = more false positive combinations                    │
│   • Compliance scope expands with each data type stored                     │
│   • Multi-tenant isolation complexity explodes                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### JanuSec's Demand-Driven Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JanuSec Model: Correlate First, Collect on Demand                           │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                      TIER 0: ALWAYS COLLECTED                       │   │
│   │                      ────────────────────────                       │   │
│   │                                                                     │   │
│   │   ┌─────────────────┐              ┌─────────────────┐              │   │
│   │   │    NETWORK      │              │    ENDPOINT     │              │   │
│   │   │   ───────────   │              │   ───────────   │              │   │
│   │   │ • Flow metadata │              │ • Process exec  │              │   │
│   │   │ • DNS queries   │              │ • File creates  │              │   │
│   │   │ • Connection    │◄────────────►│ • Registry mods │              │   │
│   │   │   patterns      │  Correlation │ • Network conns │              │   │
│   │   │ • TLS metadata  │              │ • Module loads  │              │   │
│   │   └─────────────────┘              └─────────────────┘              │   │
│   │                                                                     │   │
│   │   Coverage: ~70-75% MITRE ATT&CK    Cost: ~25-30% of full stack    │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                    JANUSEC CORRELATION ENGINE                       │   │
│   │                    ──────────────────────────                       │   │
│   │                                                                     │   │
│   │   ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │   │
│   │   │   Entity     │  │   Attack     │  │   Missing Telemetry      │ │   │
│   │   │   Resolution │─►│   Graph      │─►│   Detector               │ │   │
│   │   │              │  │   (HopGraph) │  │                          │ │   │
│   │   │ • User→Host  │  │              │  │ "What's missing to       │ │   │
│   │   │ • IP→Process │  │ • Kill chain │  │  complete this picture?" │ │   │
│   │   │ • Hash→File  │  │ • Temporal   │  │                          │ │   │
│   │   └──────────────┘  └──────────────┘  └────────────┬─────────────┘ │   │
│   │                                                    │               │   │
│   └────────────────────────────────────────────────────┼───────────────┘   │
│                                                        │                    │
│                           ┌────────────────────────────┴────────────────┐   │
│                           │                                             │   │
│                     No Gaps Found                              Gaps Found   │
│                           │                                             │   │
│                           ▼                                             ▼   │
│   ┌─────────────────────────────────┐    ┌──────────────────────────────┐  │
│   │  HIGH-CONFIDENCE ALERT          │    │  ON-DEMAND PULL REQUEST      │  │
│   │  ─────────────────────          │    │  ────────────────────────    │  │
│   │  • Full attack narrative        │    │  Scoped to:                  │  │
│   │  • Entity context complete      │    │  • Specific entity           │  │
│   │  • Recommended response         │    │  • Specific time window      │  │
│   │  • Confidence score: HIGH       │    │  • Specific event types      │  │
│   └─────────────────────────────────┘    │                              │  │
│                                          │  Example:                    │  │
│                                          │  "Pull Proofpoint logs for   │  │
│                                          │   user jsmith@acme.com,      │  │
│                                          │   last 24h, inbound only"    │  │
│                                          └──────────────┬───────────────┘  │
│                                                         │                   │
│                                                         ▼                   │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                    TIER 1: ON-DEMAND CONNECTORS                     │   │
│   │                    ────────────────────────────                     │   │
│   │                                                                     │   │
│   │   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │   │
│   │   │ Identity │ │  Email   │ │  Cloud   │ │   API    │ │   CSPM   │ │   │
│   │   │ ──────── │ │ ──────── │ │ ──────── │ │ ──────── │ │ ──────── │ │   │
│   │   │ • Azure  │ │ • Proof- │ │ • Cloud- │ │ • API GW │ │ • Prisma │ │   │
│   │   │   AD     │ │   point  │ │   Trail  │ │   logs   │ │ • Wiz    │ │   │
│   │   │ • Okta   │ │ • Mime-  │ │ • Azure  │ │ • Kong   │ │ • Orca   │ │   │
│   │   │ • Ping   │ │   cast   │ │   Monitor│ │ • Apigee │ │ • CNAPP  │ │   │
│   │   │ • Entra  │ │ • O365   │ │ • GCP    │ │          │ │          │ │   │
│   │   └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │   │
│   │                                                                     │   │
│   │   Data stays in source until needed │ Query via API, don't bulk ETL │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                    TIER 2: DEEP FORENSICS (RARE)                    │   │
│   │                    ─────────────────────────────                    │   │
│   │                                                                     │   │
│   │   Triggered only for confirmed incidents:                           │   │
│   │   • Full PCAP retrieval          • Memory forensics                 │   │
│   │   • Disk imaging                 • Email body/attachment analysis   │   │
│   │   • Cloud storage enumeration    • Container runtime traces         │   │
│   │                                                                     │   │
│   │   These are IR actions, not detection inputs                        │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why This Works

| Aspect | Traditional Model | JanuSec Demand-Driven |
|--------|-------------------|----------------------|
| **Data Volume** | 3 TB/day (8 domains) | 400 GB/day (2 domains) + on-demand |
| **Storage Cost** | $7,000/mo | $1,500/mo |
| **False Positive Rate** | High (more data = more spurious correlations) | Lower (focused correlation) |
| **Investigation Context** | Often missing anyway | Pulled precisely when needed |
| **Compliance Scope** | All 8 data types in your platform | 2 data types + federated queries |
| **Multi-Tenant Risk** | All tenant data commingled | Minimal data exposure |
| **Time to Value** | Weeks (integrate all sources) | Days (just Network + Endpoint) |

---

## 2. Why Network + Endpoint Is the Right Foundation

### MITRE ATT&CK Coverage Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Detection Coverage by Telemetry Domain                                      │
│                                                                             │
│ Tactic              │ Network │ Endpoint │ Combined │ Identity │ Email     │
│ ────────────────────┼─────────┼──────────┼──────────┼──────────┼───────────│
│ Reconnaissance      │   ●●○   │   ○○○    │   ●●○    │   ○○○    │   ●○○     │
│ Resource Dev.       │   ○○○   │   ○○○    │   ○○○    │   ○○○    │   ○○○     │
│ Initial Access      │   ●●○   │   ●○○    │   ●●●    │   ●●○    │   ●●●     │
│ Execution           │   ○○○   │   ●●●    │   ●●●    │   ○○○    │   ○○○     │
│ Persistence         │   ○○○   │   ●●●    │   ●●●    │   ●○○    │   ○○○     │
│ Priv. Escalation    │   ○○○   │   ●●●    │   ●●●    │   ●●○    │   ○○○     │
│ Defense Evasion     │   ●○○   │   ●●●    │   ●●●    │   ○○○    │   ○○○     │
│ Credential Access   │   ●○○   │   ●●●    │   ●●●    │   ●●○    │   ●○○     │
│ Discovery           │   ●●○   │   ●●●    │   ●●●    │   ●○○    │   ○○○     │
│ Lateral Movement    │   ●●●   │   ●●○    │   ●●●    │   ●●○    │   ○○○     │
│ Collection          │   ●○○   │   ●●●    │   ●●●    │   ○○○    │   ●○○     │
│ C2                  │   ●●●   │   ●●○    │   ●●●    │   ○○○    │   ○○○     │
│ Exfiltration        │   ●●●   │   ●○○    │   ●●●    │   ○○○    │   ○○○     │
│ Impact              │   ●○○   │   ●●●    │   ●●●    │   ○○○    │   ○○○     │
│ ────────────────────┼─────────┼──────────┼──────────┼──────────┼───────────│
│ Coverage Score      │   45%   │   60%    │   75%    │   25%    │   15%     │
│                                                                             │
│ ●●● = Strong coverage   ●●○ = Moderate   ●○○ = Limited   ○○○ = None        │
│                                                                             │
│ Key Insight: Network + Endpoint alone covers 75% of tactics.                │
│ Identity and Email add 10-15% each but cost significantly more.             │
│ The demand-driven model pulls Identity/Email only when the 75%              │
│ correlation suggests they're needed.                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### The Correlation Power of Two Domains

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Example: Detecting Lateral Movement with Network + Endpoint                 │
│                                                                             │
│ NETWORK ALONE sees:                                                         │
│ ┌────────────────────────────────────────────────────────────────────────┐ │
│ │ 10.0.1.50:49152 ──SMB/445──► 10.0.2.100 (DC01)                         │ │
│ │ Action: ALLOWED                                                        │ │
│ │                                                                        │ │
│ │ Verdict: Normal? Admins use SMB to DCs constantly. Low confidence.     │ │
│ └────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ ENDPOINT ALONE sees:                                                        │
│ ┌────────────────────────────────────────────────────────────────────────┐ │
│ │ Host: WORKSTATION-50                                                   │ │
│ │ Process: powershell.exe (PID 4521)                                     │ │
│ │ Parent: explorer.exe                                                   │ │
│ │ Command: Invoke-Command -ComputerName DC01 -ScriptBlock {...}          │ │
│ │                                                                        │ │
│ │ Verdict: Suspicious? PowerShell remoting happens. Medium confidence.   │ │
│ └────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ NETWORK + ENDPOINT CORRELATED:                                              │
│ ┌────────────────────────────────────────────────────────────────────────┐ │
│ │ ┌─────────────────────────────────────────────────────────────────┐    │ │
│ │ │ ENTITY: WORKSTATION-50 (10.0.1.50)                              │    │ │
│ │ │ USER: jsmith (resolved from endpoint logs)                      │    │ │
│ │ │                                                                  │    │ │
│ │ │ ATTACK CHAIN:                                                   │    │ │
│ │ │ 1. [ENDPOINT] 09:14:22 - PowerShell spawned with encoded cmd    │    │ │
│ │ │ 2. [NETWORK]  09:14:23 - SMB connection to DC01 initiated       │    │ │
│ │ │ 3. [ENDPOINT] 09:14:24 - WMI provider loaded (lateral movement) │    │ │
│ │ │ 4. [NETWORK]  09:14:25 - WinRM traffic to 10.0.2.100:5985       │    │ │
│ │ │                                                                  │    │ │
│ │ │ VERDICT: HIGH CONFIDENCE - Lateral movement via PowerShell      │    │ │
│ │ │          remoting from non-admin workstation to domain          │    │ │
│ │ │          controller. Technique: T1021.006 (WinRM)               │    │ │
│ │ │                                                                  │    │ │
│ │ │ MISSING TELEMETRY:                                              │    │ │
│ │ │ • No auth event for jsmith on DC01 → REQUEST: Azure AD logs    │    │ │
│ │ │ • Unknown if jsmith is privileged → REQUEST: AD group membership│    │ │
│ │ └─────────────────────────────────────────────────────────────────┘    │ │
│ └────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ The correlation PROVES the attack. The missing telemetry detector           │
│ identifies what additional context would complete the picture.              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### What Network + Endpoint Cannot See (And That's OK)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Known Blind Spots (Addressed by On-Demand Pulls)                            │
│                                                                             │
│ BLIND SPOT                           │ ON-DEMAND RESOLUTION                 │
│ ─────────────────────────────────────┼──────────────────────────────────────│
│ Initial phishing email               │ Pull Proofpoint/Mimecast when        │
│ (no endpoint/network trace until     │ correlation shows user clicked       │
│ user clicks)                         │ malicious link or opened attachment  │
│                                      │                                      │
│ OAuth token theft                    │ Pull Azure AD sign-in logs when      │
│ (no network trace, legitimate        │ endpoint shows suspicious process    │
│ cloud API calls)                     │ accessing token cache                │
│                                      │                                      │
│ Cloud-only attacks                   │ Pull CloudTrail/Azure Monitor when   │
│ (attacker in cloud control plane,    │ network shows connections to cloud   │
│ no on-prem presence)                 │ APIs without corresponding endpoint  │
│                                      │ activity                             │
│                                      │                                      │
│ Insider data theft via approved      │ Pull DLP/Purview logs when network   │
│ channels (OneDrive, sanctioned SaaS) │ shows large egress to known cloud    │
│                                      │ storage without business justification│
│                                      │                                      │
│ BEC (Business Email Compromise)      │ Pull email logs when network shows   │
│ purely in email, no malware          │ user accessing email from unusual    │
│                                      │ location or device                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The Missing Telemetry Detector

### Core Algorithm

The Missing Telemetry Detector is a key differentiator in JanuSec's 21-stage pipeline. It analyzes attack graphs to identify gaps in the narrative and generates scoped pull requests.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Missing Telemetry Detector: Decision Logic                                  │
│                                                                             │
│                        ┌─────────────────────┐                              │
│                        │   Attack Graph      │                              │
│                        │   Node Analysis     │                              │
│                        └──────────┬──────────┘                              │
│                                   │                                         │
│         ┌─────────────────────────┼─────────────────────────┐               │
│         │                         │                         │               │
│         ▼                         ▼                         ▼               │
│ ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐        │
│ │ User Context      │  │ Network Context   │  │ Temporal Context  │        │
│ │ Analysis          │  │ Analysis          │  │ Analysis          │        │
│ └─────────┬─────────┘  └─────────┬─────────┘  └─────────┬─────────┘        │
│           │                      │                      │                   │
│           ▼                      ▼                      ▼                   │
│ ┌───────────────────────────────────────────────────────────────────────┐  │
│ │ GAP DETECTION RULES                                                   │  │
│ │                                                                       │  │
│ │ IF user_context.present AND NOT auth_event.correlated:               │  │
│ │    GENERATE request(Identity, user, ±1h, [logon, priv_change])       │  │
│ │                                                                       │  │
│ │ IF network.destination IN email_domains AND NOT email_event.present: │  │
│ │    GENERATE request(Email, user, -24h, [delivered, clicked])         │  │
│ │                                                                       │  │
│ │ IF network.destination IN cloud_ranges AND NOT cloud_audit.present:  │  │
│ │    GENERATE request(Cloud, inferred_account, ±30m, [api_call])       │  │
│ │                                                                       │  │
│ │ IF process.accessed_sensitive_file AND NOT dlp_event.present:        │  │
│ │    GENERATE request(DLP, file_hash, ±1h, [classification, access])   │  │
│ │                                                                       │  │
│ │ IF network.dest_geo != user.usual_geo AND NOT travel_approved:       │  │
│ │    GENERATE request(HR/Travel, user, -7d, [travel_bookings])         │  │
│ │                                                                       │  │
│ │ IF process.parent == "outlook.exe" AND attachment.executed:          │  │
│ │    GENERATE request(Email, user, -1h, [attachments, sender_rep])     │  │
│ └───────────────────────────────────────────────────────────────────────┘  │
│                                   │                                         │
│                                   ▼                                         │
│ ┌───────────────────────────────────────────────────────────────────────┐  │
│ │ TELEMETRY REQUEST QUEUE                                               │  │
│ │                                                                       │  │
│ │ Priority │ Domain   │ Entity           │ Window │ Types              │  │
│ │ ─────────┼──────────┼──────────────────┼────────┼────────────────────│  │
│ │ P1       │ Identity │ jsmith@acme.com  │ ±1h    │ logon, priv_change │  │
│ │ P2       │ Email    │ jsmith@acme.com  │ -24h   │ delivered, clicked │  │
│ │ P3       │ Cloud    │ arn:aws:iam::123 │ ±30m   │ api_call           │  │
│ └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Request Prioritization

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Pull Request Priority Matrix                                                │
│                                                                             │
│                           ATTACK CONFIDENCE                                 │
│                    Low          Medium         High                         │
│              ┌─────────────┬─────────────┬─────────────┐                   │
│         High │ P2: Queue   │ P1: Auto    │ P0: Urgent  │                   │
│   CONTEXT    │             │    Pull     │    + Alert  │                   │
│   VALUE      ├─────────────┼─────────────┼─────────────┤                   │
│        Med   │ P3: On      │ P2: Queue   │ P1: Auto    │                   │
│              │    Request  │             │    Pull     │                   │
│              ├─────────────┼─────────────┼─────────────┤                   │
│         Low  │ Ignore      │ P3: On      │ P2: Queue   │                   │
│              │             │    Request  │             │                   │
│              └─────────────┴─────────────┴─────────────┘                   │
│                                                                             │
│ P0: Immediate automated pull + analyst notification                         │
│ P1: Automated pull, results feed back into correlation                      │
│ P2: Queued for batch pull (next 15 min window)                              │
│ P3: Available on analyst request via investigation UI                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Implementation Specification

```python
# Missing Telemetry Detector - Core Logic

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
from datetime import datetime, timedelta

class TelemetryDomain(Enum):
    IDENTITY = "identity"
    EMAIL = "email"
    CLOUD = "cloud"
    DLP = "dlp"
    CSPM = "cspm"
    API_GATEWAY = "api_gateway"

class Priority(Enum):
    P0_URGENT = 0      # Auto-pull + immediate alert
    P1_AUTO = 1        # Auto-pull, feed to correlation
    P2_QUEUED = 2      # Batch pull within 15 min
    P3_ON_REQUEST = 3  # Available via investigation UI

@dataclass
class TelemetryRequest:
    domain: TelemetryDomain
    entity: str                        # User, host, account, etc.
    time_start: datetime
    time_end: datetime
    event_types: List[str]
    priority: Priority
    rationale: str                     # Human-readable explanation
    attack_graph_node_id: str          # Link back to triggering node
    confidence_boost: float            # How much this would increase confidence

class MissingTelemetryDetector:
    
    # Known cloud IP ranges (simplified)
    CLOUD_RANGES = {
        "AWS": ["52.0.0.0/8", "54.0.0.0/8"],
        "Azure": ["13.64.0.0/11", "20.0.0.0/8"],
        "GCP": ["34.0.0.0/8", "35.0.0.0/8"]
    }
    
    # Email-related domains
    EMAIL_INDICATORS = [
        "outlook.office365.com", "smtp.", "imap.", "pop3.",
        "mail.", "mx.", "proofpoint.", "mimecast."
    ]
    
    def analyze(self, attack_graph: AttackGraph) -> List[TelemetryRequest]:
        requests = []
        
        for node in attack_graph.nodes:
            requests.extend(self._check_identity_gap(node, attack_graph))
            requests.extend(self._check_email_gap(node, attack_graph))
            requests.extend(self._check_cloud_gap(node, attack_graph))
            requests.extend(self._check_dlp_gap(node, attack_graph))
        
        return self._deduplicate_and_prioritize(requests)
    
    def _check_identity_gap(self, node, graph) -> List[TelemetryRequest]:
        """
        If we see a user context but no authentication event,
        request identity logs to understand HOW they authenticated.
        """
        if not node.user_context:
            return []
        
        # Check if any node in the graph has auth events for this user
        has_auth = any(
            n.event_type in ["logon", "auth", "session_start"] 
            and n.user == node.user_context
            for n in graph.nodes
        )
        
        if has_auth:
            return []
        
        return [TelemetryRequest(
            domain=TelemetryDomain.IDENTITY,
            entity=node.user_context,
            time_start=node.timestamp - timedelta(hours=1),
            time_end=node.timestamp + timedelta(hours=1),
            event_types=["logon", "logon_failed", "privilege_change", 
                        "group_membership_change", "mfa_result"],
            priority=self._calculate_priority(graph.confidence, 0.15),
            rationale=f"Process '{node.process_name}' executed as '{node.user_context}' "
                     f"but no authentication event found. Identity logs would confirm "
                     f"legitimate access vs credential theft.",
            attack_graph_node_id=node.id,
            confidence_boost=0.15
        )]
    
    def _check_email_gap(self, node, graph) -> List[TelemetryRequest]:
        """
        If network shows email-related activity, or endpoint shows
        attachment execution from email client, request email logs.
        """
        is_email_related = False
        
        # Check network destination
        if node.network_dest:
            is_email_related = any(
                indicator in node.network_dest 
                for indicator in self.EMAIL_INDICATORS
            )
        
        # Check if parent process is email client
        if node.parent_process in ["outlook.exe", "thunderbird.exe", "mail"]:
            is_email_related = True
        
        if not is_email_related:
            return []
        
        return [TelemetryRequest(
            domain=TelemetryDomain.EMAIL,
            entity=node.user_context or graph.primary_user,
            time_start=node.timestamp - timedelta(hours=24),
            time_end=node.timestamp,
            event_types=["message_delivered", "url_clicked", "attachment_opened",
                        "sender_reputation", "threat_verdict"],
            priority=self._calculate_priority(graph.confidence, 0.20),
            rationale=f"{'Attachment executed from email client' if node.parent_process else 'Email-related network activity detected'}. "
                     f"Email logs would reveal initial phishing vector.",
            attack_graph_node_id=node.id,
            confidence_boost=0.20
        )]
    
    def _check_cloud_gap(self, node, graph) -> List[TelemetryRequest]:
        """
        If network shows cloud API endpoints but no corresponding
        cloud audit trail, request cloud logs.
        """
        if not node.network_dest_ip:
            return []
        
        cloud_provider = self._identify_cloud_provider(node.network_dest_ip)
        if not cloud_provider:
            return []
        
        # Check if we have cloud events in the graph
        has_cloud_events = any(
            n.source_type == "cloud_audit" and 
            n.timestamp >= node.timestamp - timedelta(minutes=5) and
            n.timestamp <= node.timestamp + timedelta(minutes=5)
            for n in graph.nodes
        )
        
        if has_cloud_events:
            return []
        
        return [TelemetryRequest(
            domain=TelemetryDomain.CLOUD,
            entity=self._infer_cloud_account(node, cloud_provider),
            time_start=node.timestamp - timedelta(minutes=30),
            time_end=node.timestamp + timedelta(minutes=30),
            event_types=["api_call", "console_login", "assume_role",
                        "resource_access", "policy_change"],
            priority=self._calculate_priority(graph.confidence, 0.25),
            rationale=f"Network connection to {cloud_provider} ({node.network_dest_ip}) "
                     f"without corresponding cloud audit trail. This could indicate "
                     f"cloud-native attack activity.",
            attack_graph_node_id=node.id,
            confidence_boost=0.25
        )]
    
    def _check_dlp_gap(self, node, graph) -> List[TelemetryRequest]:
        """
        If process accessed files that might be sensitive, and we're
        seeing exfiltration indicators, request DLP classification.
        """
        if not node.files_accessed:
            return []
        
        # Check for exfiltration indicators in graph
        has_exfil_indicators = any(
            n.event_type in ["large_upload", "cloud_storage_write", "email_attachment"]
            and n.timestamp > node.timestamp
            for n in graph.nodes
        )
        
        if not has_exfil_indicators:
            return []
        
        return [TelemetryRequest(
            domain=TelemetryDomain.DLP,
            entity=node.files_accessed[0],  # Primary file
            time_start=node.timestamp - timedelta(hours=1),
            time_end=node.timestamp + timedelta(hours=1),
            event_types=["file_classification", "sensitivity_label",
                        "access_audit", "share_event"],
            priority=self._calculate_priority(graph.confidence, 0.30),
            rationale=f"Process accessed files followed by potential exfiltration. "
                     f"DLP logs would confirm data sensitivity and policy violations.",
            attack_graph_node_id=node.id,
            confidence_boost=0.30
        )]
    
    def _calculate_priority(self, current_confidence: float, 
                           context_value: float) -> Priority:
        """Map confidence + context value to priority level."""
        score = current_confidence + context_value
        
        if score > 0.9:
            return Priority.P0_URGENT
        elif score > 0.7:
            return Priority.P1_AUTO
        elif score > 0.5:
            return Priority.P2_QUEUED
        else:
            return Priority.P3_ON_REQUEST
    
    def _deduplicate_and_prioritize(self, 
                                    requests: List[TelemetryRequest]) -> List[TelemetryRequest]:
        """Remove duplicates, keep highest priority for each entity/domain pair."""
        seen = {}
        for req in requests:
            key = (req.domain, req.entity)
            if key not in seen or req.priority.value < seen[key].priority.value:
                seen[key] = req
        
        return sorted(seen.values(), key=lambda r: r.priority.value)
```

---

## 4. Deployment Topologies

### Overview: Where to Deploy What

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JanuSec Deployment Options                                                  │
│                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ OPTION A: EDGE-FIRST (Recommended for Enterprise)                       │ │
│ │                                                                         │ │
│ │ Customer Premises          │         Cloud (Azure/AWS/GCP)              │ │
│ │ ─────────────────          │         ─────────────────────              │ │
│ │                            │                                            │ │
│ │ ┌──────────────────┐       │    ┌──────────────────────────────┐       │ │
│ │ │ JanuSec Edge     │       │    │ JanuSec Cloud Core           │       │ │
│ │ │ Collector        │───────┼───►│                              │       │ │
│ │ │                  │ HTTPS │    │ • Correlation Engine         │       │ │
│ │ │ • Local ingest   │ (443) │    │ • Attack Graph (HopGraph)    │       │ │
│ │ │ • Pre-filter     │       │    │ • Missing Telemetry Detector │       │ │
│ │ │ • Compression    │       │    │ • Alert Management           │       │ │
│ │ │ • Buffering      │       │    │ • Investigation UI           │       │ │
│ │ └──────────────────┘       │    │ • On-Demand Connectors       │       │ │
│ │         ▲                  │    └──────────────────────────────┘       │ │
│ │         │                  │                                            │ │
│ │ ┌───────┴──────────┐       │                                            │ │
│ │ │ Endpoints (EDR)  │       │                                            │ │
│ │ │ Network Sensors  │       │                                            │ │
│ │ │ (Zeek/Suricata)  │       │                                            │ │
│ │ └──────────────────┘       │                                            │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Benefits:                                                                   │
│ • Data reduction at source (send only relevant events)                      │
│ • Works in air-gapped environments with store-and-forward                   │
│ • Reduced egress costs (compress and batch at edge)                         │
│ • Low latency for local network sensors                                     │
│ • Keeps raw data on-prem for compliance                                     │
│                                                                             │
│ Use When:                                                                   │
│ • Large enterprise with significant on-prem infrastructure                  │
│ • Data residency requirements                                               │
│ • Existing investment in network TAPs/SPAN ports                            │
│ • Need to minimize cloud egress costs                                       │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ OPTION B: CLOUD-NATIVE (Recommended for Cloud-First Orgs)                   │
│                                                                             │
│                         Cloud (Azure/AWS/GCP)                               │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │                                                                         │ │
│ │   ┌─────────────────────────────────────────────────────────────────┐  │ │
│ │   │                    JanuSec Cloud Platform                       │  │ │
│ │   │                                                                 │  │ │
│ │   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │  │ │
│ │   │  │ Ingest Layer │  │ Correlation  │  │ Investigation        │  │  │ │
│ │   │  │ (API + Queue)│──│ Engine       │──│ + Connectors         │  │  │ │
│ │   │  └──────────────┘  └──────────────┘  └──────────────────────┘  │  │ │
│ │   └─────────────────────────────────────────────────────────────────┘  │ │
│ │                      ▲                           │                      │ │
│ │                      │                           │                      │ │
│ │   ┌──────────────────┼───────────────────────────┼──────────────────┐  │ │
│ │   │                  │     API Connections       │                  │  │ │
│ │   │                  │                           ▼                  │  │ │
│ │   │  ┌───────────────┴───┐  ┌───────────────────────────────────┐  │  │ │
│ │   │  │ Cloud-Native EDR  │  │ SaaS Integrations                 │  │  │ │
│ │   │  │ ─────────────────  │  │ ─────────────────                 │  │  │ │
│ │   │  │ • CrowdStrike     │  │ • Proofpoint (on-demand)          │  │  │ │
│ │   │  │ • SentinelOne     │  │ • Mimecast (on-demand)            │  │  │ │
│ │   │  │ • Defender ATP    │  │ • Okta (on-demand)                │  │  │ │
│ │   │  │ • Carbon Black    │  │ • Azure AD (on-demand)            │  │  │ │
│ │   │  └───────────────────┘  └───────────────────────────────────┘  │  │ │
│ │   │                                                                 │  │ │
│ │   │  ┌───────────────────────────────────────────────────────────┐ │  │ │
│ │   │  │ VPC Flow Logs / NSG Flow Logs / Cloud Firewall Logs      │ │  │ │
│ │   │  │ (Network telemetry from cloud-native sources)            │ │  │ │
│ │   │  └───────────────────────────────────────────────────────────┘ │  │ │
│ │   └─────────────────────────────────────────────────────────────────┘  │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ Benefits:                                                                   │
│ • No on-prem hardware to manage                                             │
│ • Elastic scaling for ingestion spikes                                      │
│ • Native integration with cloud EDR and logging                             │
│ • Lower operational overhead                                                │
│                                                                             │
│ Use When:                                                                   │
│ • Cloud-native organization (AWS/Azure/GCP workloads)                       │
│ • Using cloud-native EDR (Defender, CrowdStrike Falcon)                     │
│ • Limited on-prem infrastructure                                            │
│ • Startup or SMB without dedicated security hardware                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ OPTION C: HYBRID (Recommended for Transition / Mixed Environments)          │
│                                                                             │
│   Customer DC               │              Cloud                            │
│   ──────────                │              ─────                            │
│                             │                                               │
│   ┌─────────────────────┐   │    ┌──────────────────────────────────────┐  │
│   │ Edge Collector      │   │    │ JanuSec Cloud                        │  │
│   │ (on-prem network    │───┼───►│                                      │  │
│   │  sensors)           │   │    │  ┌────────────────────────────────┐  │  │
│   └─────────────────────┘   │    │  │ Correlation + Investigation   │  │  │
│                             │    │  └────────────────────────────────┘  │  │
│   Cloud Workloads           │    │          ▲           ▲               │  │
│   ───────────────           │    │          │           │               │  │
│   ┌─────────────────────┐   │    │  ┌───────┴───┐  ┌────┴────────────┐  │  │
│   │ Cloud VMs           │   │    │  │ Cloud EDR │  │ On-Demand       │  │  │
│   │ (Defender/Falcon)   │───┼───►│  │ Feed      │  │ Connectors      │  │  │
│   │                     │   │    │  │           │  │ (SaaS APIs)     │  │  │
│   └─────────────────────┘   │    │  └───────────┘  └─────────────────┘  │  │
│                             │    └──────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Cloud-Specific Deployment Patterns

#### Azure Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JanuSec on Azure                                                            │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │ Resource Group: janusec-prod                                        │  │
│   │                                                                     │  │
│   │  ┌─────────────────────────────────────────────────────────────┐   │  │
│   │  │ VNet: janusec-vnet (10.0.0.0/16)                            │   │  │
│   │  │                                                              │   │  │
│   │  │  ┌────────────────┐  ┌────────────────┐  ┌───────────────┐  │   │  │
│   │  │  │ DMZ Subnet     │  │ App Subnet     │  │ Data Subnet   │  │   │  │
│   │  │  │ 10.0.1.0/24    │  │ 10.0.2.0/24    │  │ 10.0.3.0/24   │  │   │  │
│   │  │  │                │  │                │  │               │  │   │  │
│   │  │  │ • App Gateway  │  │ • AKS Cluster  │  │ • PostgreSQL  │  │   │  │
│   │  │  │   (WAF v2)     │  │   (ingestion   │  │   Flexible    │  │   │  │
│   │  │  │                │  │    workers)    │  │               │  │   │  │
│   │  │  │ • Azure Front  │  │                │  │ • Azure Blob  │  │   │  │
│   │  │  │   Door (CDN)   │  │ • Container    │  │   (forensic)  │  │   │  │
│   │  │  │                │  │   Apps (API)   │  │               │  │   │  │
│   │  │  └────────────────┘  └────────────────┘  └───────────────┘  │   │  │
│   │  │                                                              │   │  │
│   │  └─────────────────────────────────────────────────────────────┘   │  │
│   │                                                                     │  │
│   │  ┌─────────────────────────────────────────────────────────────┐   │  │
│   │  │ Shared Services                                              │   │  │
│   │  │ • Key Vault (per-tenant keys)                               │   │  │
│   │  │ • Event Hub (ingest buffer)                                 │   │  │
│   │  │ • Log Analytics (operational logs)                          │   │  │
│   │  │ • Application Insights (APM)                                │   │  │
│   │  └─────────────────────────────────────────────────────────────┘   │  │
│   │                                                                     │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│ Terraform Module Structure:                                                 │
│ ├── modules/                                                                │
│ │   ├── network/          # VNet, subnets, NSGs, Azure Firewall            │
│ │   ├── ingest/           # Event Hub, App Gateway, AKS                    │
│ │   ├── storage/          # Blob storage, lifecycle policies               │
│ │   ├── database/         # PostgreSQL Flexible Server                     │
│ │   ├── security/         # Key Vault, managed identities                  │
│ │   └── monitoring/       # Log Analytics, alerts                          │
│ ├── environments/                                                           │
│ │   ├── dev/                                                                │
│ │   ├── staging/                                                            │
│ │   └── prod/                                                               │
│ └── main.tf                                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### AWS Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JanuSec on AWS                                                              │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │ VPC: janusec-vpc (10.0.0.0/16)                                      │  │
│   │                                                                     │  │
│   │  ┌─────────────────────────────────────────────────────────────┐   │  │
│   │  │ Public Subnets (Multi-AZ)                                   │   │  │
│   │  │ • ALB (Application Load Balancer)                           │   │  │
│   │  │ • NAT Gateway                                               │   │  │
│   │  │ • WAF (Web Application Firewall)                            │   │  │
│   │  └─────────────────────────────────────────────────────────────┘   │  │
│   │                                                                     │  │
│   │  ┌─────────────────────────────────────────────────────────────┐   │  │
│   │  │ Private Subnets - App Tier                                  │   │  │
│   │  │ • EKS Cluster (ingestion + correlation)                     │   │  │
│   │  │ • Lambda (on-demand connector execution)                    │   │  │
│   │  └─────────────────────────────────────────────────────────────┘   │  │
│   │                                                                     │  │
│   │  ┌─────────────────────────────────────────────────────────────┐   │  │
│   │  │ Private Subnets - Data Tier                                 │   │  │
│   │  │ • RDS PostgreSQL (Multi-AZ)                                 │   │  │
│   │  │ • S3 (forensic storage with Object Lock)                    │   │  │
│   │  │ • OpenSearch (if self-hosting search)                       │   │  │
│   │  └─────────────────────────────────────────────────────────────┘   │  │
│   │                                                                     │  │
│   │  ┌─────────────────────────────────────────────────────────────┐   │  │
│   │  │ Shared Services                                              │   │  │
│   │  │ • Secrets Manager / KMS (per-tenant keys)                   │   │  │
│   │  │ • Kinesis Data Streams (ingest buffer)                      │   │  │
│   │  │ • SQS (DLQ, async processing)                               │   │  │
│   │  │ • CloudWatch (operational logs + metrics)                   │   │  │
│   │  └─────────────────────────────────────────────────────────────┘   │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│ Key AWS-Specific Patterns:                                                  │
│ • Use VPC Flow Logs → Kinesis → JanuSec for network telemetry              │
│ • GuardDuty findings as supplementary signal (not primary)                  │
│ • Security Hub for compliance posture (CSPM on-demand)                      │
│ • Lambda for lightweight on-demand API pulls (cost-efficient)               │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### GCP Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JanuSec on GCP                                                              │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │ VPC: janusec-vpc                                                    │  │
│   │                                                                     │  │
│   │  ┌─────────────────────────────────────────────────────────────┐   │  │
│   │  │ Global Layer                                                 │   │  │
│   │  │ • Cloud Load Balancing (HTTPS LB with Cloud Armor/WAF)      │   │  │
│   │  │ • Cloud CDN (optional, for static assets)                   │   │  │
│   │  └─────────────────────────────────────────────────────────────┘   │  │
│   │                                                                     │  │
│   │  ┌─────────────────────────────────────────────────────────────┐   │  │
│   │  │ Regional Subnets                                             │   │  │
│   │  │ • GKE Autopilot (ingestion + correlation)                   │   │  │
│   │  │ • Cloud Run (on-demand connectors, scale to zero)           │   │  │
│   │  └─────────────────────────────────────────────────────────────┘   │  │
│   │                                                                     │  │
│   │  ┌─────────────────────────────────────────────────────────────┐   │  │
│   │  │ Data Layer                                                   │   │  │
│   │  │ • Cloud SQL PostgreSQL                                       │   │  │
│   │  │ • Cloud Storage (forensic, with retention policies)         │   │  │
│   │  │ • BigQuery (optional, for large-scale analytics)            │   │  │
│   │  └─────────────────────────────────────────────────────────────┘   │  │
│   │                                                                     │  │
│   │  ┌─────────────────────────────────────────────────────────────┐   │  │
│   │  │ Shared Services                                              │   │  │
│   │  │ • Secret Manager / Cloud KMS (per-tenant keys, HSM-backed)  │   │  │
│   │  │ • Pub/Sub (ingest buffer, dead-letter topics)               │   │  │
│   │  │ • Cloud Logging + Cloud Monitoring                          │   │  │
│   │  └─────────────────────────────────────────────────────────────┘   │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│ GCP-Specific Patterns:                                                      │
│ • VPC Flow Logs → Pub/Sub → JanuSec for network telemetry                  │
│ • Security Command Center as CSPM signal (on-demand)                        │
│ • Chronicle integration option (if customer uses Chronicle)                 │
│ • Cloud Run for cost-efficient on-demand connector execution                │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Cloud-Native Tool Integration

### The Role of Cloud Monitoring Tools

Cloud-native monitoring tools (Azure Monitor, CloudWatch, GCP Cloud Monitoring) serve a specific role in JanuSec's demand-driven architecture: they're **on-demand enrichment sources**, not primary detection inputs.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Cloud Monitoring Tools: On-Demand Enrichment (Not Primary Ingestion)        │
│                                                                             │
│   PRIMARY DETECTION                    ON-DEMAND ENRICHMENT                 │
│   (Always Collected)                   (Pulled When Needed)                 │
│                                                                             │
│   ┌─────────────────┐                  ┌─────────────────────────────────┐ │
│   │ Network +       │   Correlation    │ Cloud Monitoring Tools          │ │
│   │ Endpoint        │───────────────►  │                                 │ │
│   │ Telemetry       │   triggers       │ • Azure Monitor                 │ │
│   └─────────────────┘   pull of:       │ • CloudWatch                    │ │
│                                        │ • GCP Cloud Monitoring          │ │
│                                        │ • Datadog / New Relic           │ │
│                                        └─────────────────────────────────┘ │
│                                                                             │
│ WHY NOT USE CLOUD MONITORING AS PRIMARY?                                    │
│                                                                             │
│ ❌ Cost: Cloud monitoring data is expensive to export                       │
│    • Azure Monitor egress: $2.30/GB                                         │
│    • CloudWatch Logs export: $0.50/GB + S3 costs                            │
│    • At scale, this exceeds the cost of dedicated sensors                   │
│                                                                             │
│ ❌ Latency: Cloud monitoring aggregates data (1-5 min delay)                │
│    • JanuSec needs sub-second correlation for real-time detection           │
│    • Cloud monitoring is designed for ops, not security                     │
│                                                                             │
│ ❌ Coverage: Cloud monitoring captures what cloud sees                      │
│    • Misses encrypted traffic content                                       │
│    • Misses host-level process activity                                     │
│    • Limited to cloud infrastructure, not endpoints                         │
│                                                                             │
│ ✅ CORRECT USE: Enrichment for cloud-specific context                       │
│    • "What Azure resources did this IP access?"                             │
│    • "What AWS API calls did this role make?"                               │
│    • "What GCP permissions does this service account have?"                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Integration Matrix: Cloud Monitoring Tools

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ Cloud Tool Integration for JanuSec                                                     │
├──────────────────────┬─────────────────┬───────────────────────────┬───────────────────┤
│ Tool                 │ Integration     │ Use Case                  │ Pull Trigger      │
│                      │ Method          │                           │                   │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ Azure Monitor        │ Log Analytics   │ • Azure resource access   │ Network shows     │
│                      │ Query API       │ • NSG flow enrichment     │ Azure IP ranges   │
│                      │                 │ • App Service logs        │                   │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ Azure Sentinel       │ REST API        │ • Incident correlation    │ High-confidence   │
│                      │ (SecurityAlert) │ • Alert deduplication     │ JanuSec alert     │
│                      │                 │ • Hunting query results   │                   │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ Microsoft Purview    │ Graph API       │ • Data classification     │ Exfiltration      │
│ (DLP)                │ Compliance API  │ • Sensitivity labels      │ indicators in     │
│                      │                 │ • DLP policy matches      │ attack graph      │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ Microsoft Defender   │ Security Graph  │ • Threat intelligence     │ Hash/IOC match    │
│ for Endpoint         │ API             │ • Device risk score       │ or endpoint       │
│                      │                 │ • Vulnerability state     │ anomaly           │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ AWS CloudWatch       │ Logs Insights   │ • Lambda execution logs   │ Network shows     │
│                      │ API             │ • API Gateway logs        │ AWS API calls     │
│                      │                 │ • VPC Flow enrichment     │                   │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ AWS CloudTrail       │ Lookup Events   │ • API call history        │ Cloud activity    │
│                      │ API             │ • IAM role usage          │ without endpoint  │
│                      │                 │ • Resource modifications  │ trace             │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ AWS Security Hub     │ GetFindings     │ • Compliance posture      │ CSPM gap in       │
│                      │ API             │ • GuardDuty correlation   │ attack graph      │
│                      │                 │ • Inspector findings      │                   │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ AWS Macie            │ GetFindings     │ • S3 data classification  │ S3 exfiltration   │
│ (DLP)                │ API             │ • Sensitive data location │ indicators        │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ GCP Cloud Logging    │ entries.list    │ • GCE/GKE audit logs      │ Network shows     │
│                      │ API             │ • Cloud Functions logs    │ GCP IP ranges     │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ GCP Security         │ findings.list   │ • Misconfiguration alerts │ CSPM gap in       │
│ Command Center       │ API             │ • Threat detection        │ attack graph      │
│                      │                 │ • Vulnerability findings  │                   │
├──────────────────────┼─────────────────┼───────────────────────────┼───────────────────┤
│ GCP DLP              │ dlp.inspect     │ • Data classification     │ GCS exfiltration  │
│                      │ API             │ • Sensitive content scan  │ indicators        │
└──────────────────────┴─────────────────┴───────────────────────────┴───────────────────┘
```

### DLP Integration Deep Dive

Data Loss Prevention tools are particularly valuable for the demand-driven model because they answer the "so what?" question:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ DLP Integration: Answering "Was This Data Sensitive?"                       │
│                                                                             │
│ SCENARIO: JanuSec detects potential data exfiltration                       │
│                                                                             │
│   Network + Endpoint Correlation Shows:                                     │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │ 1. [ENDPOINT] User opened file: Q4_Financial_Projections.xlsx       │  │
│   │ 2. [ENDPOINT] File copied to: C:\Users\jsmith\Dropbox\               │  │
│   │ 3. [NETWORK]  Large upload to: dropbox.com (500 MB)                  │  │
│   │                                                                      │  │
│   │ Verdict: Possible data exfiltration. But is the file sensitive?     │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│   Missing Telemetry Detector Requests DLP Context:                          │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │ Pull from: Microsoft Purview / Macie / GCP DLP                      │  │
│   │ Query: Classification for "Q4_Financial_Projections.xlsx"           │  │
│   │                                                                      │  │
│   │ Response:                                                            │  │
│   │ {                                                                    │  │
│   │   "file": "Q4_Financial_Projections.xlsx",                          │  │
│   │   "classification": "Confidential",                                  │  │
│   │   "sensitivity_label": "Financial - Internal Only",                 │  │
│   │   "dlp_policy": "Block External Sharing",                           │  │
│   │   "policy_violated": true,                                          │  │
│   │   "sensitive_info_types": ["Financial Data", "Revenue Projections"] │  │
│   │ }                                                                    │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│   FINAL ALERT (Enriched):                                                   │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │ SEVERITY: CRITICAL                                                   │  │
│   │ TITLE: Confirmed Data Exfiltration - Confidential Financial Data    │  │
│   │                                                                      │  │
│   │ User jsmith exfiltrated Q4_Financial_Projections.xlsx to personal   │  │
│   │ Dropbox. File is classified CONFIDENTIAL with DLP policy "Block     │  │
│   │ External Sharing" - policy was violated.                            │  │
│   │                                                                      │  │
│   │ Contains: Financial Data, Revenue Projections                        │  │
│   │                                                                      │  │
│   │ RECOMMENDED ACTIONS:                                                 │  │
│   │ 1. Disable user account (Identity connector)                         │  │
│   │ 2. Revoke Dropbox OAuth token (SaaS connector)                       │  │
│   │ 3. Initiate legal hold on user's mailbox                            │  │
│   │ 4. Generate incident report for CISO                                │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│ Without DLP: "User uploaded a file to Dropbox" (low priority, ignored)     │
│ With DLP:    "User exfiltrated confidential financial data" (CRITICAL)     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Connector Implementation Patterns

```python
# Example: Microsoft Purview DLP Connector

from typing import Optional, List
from datetime import datetime, timedelta
import aiohttp

class PurviewDLPConnector:
    """
    On-demand connector for Microsoft Purview DLP.
    Only called when Missing Telemetry Detector identifies DLP gap.
    """
    
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = "https://graph.microsoft.com/v1.0"
        self._token = None
        self._token_expiry = None
    
    async def get_file_classification(self, file_path: str, 
                                       site_id: Optional[str] = None) -> dict:
        """
        Get sensitivity label and DLP policy matches for a file.
        """
        token = await self._get_token()
        
        # Query Purview for file classification
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {token}"}
            
            # Get sensitivity label
            label_url = f"{self.base_url}/security/informationProtection/sensitivityLabels"
            async with session.get(label_url, headers=headers) as resp:
                labels = await resp.json()
            
            # Get DLP policy matches for file
            dlp_url = f"{self.base_url}/security/dataLossPreventionPolicies"
            async with session.get(dlp_url, headers=headers) as resp:
                policies = await resp.json()
            
            # Check policy violations
            # (Simplified - actual implementation would query file-specific matches)
            return {
                "file": file_path,
                "classification": self._determine_classification(labels, file_path),
                "sensitivity_label": self._get_sensitivity_label(labels, file_path),
                "dlp_policies_matched": self._check_policy_matches(policies, file_path),
                "policy_violated": self._check_violations(policies, file_path)
            }
    
    async def get_dlp_alerts(self, user_principal: str,
                             time_start: datetime,
                             time_end: datetime) -> List[dict]:
        """
        Get DLP alerts for a specific user in a time window.
        """
        token = await self._get_token()
        
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {token}"}
            
            # Query DLP alerts
            filter_str = (
                f"createdDateTime ge {time_start.isoformat()}Z "
                f"and createdDateTime le {time_end.isoformat()}Z "
                f"and userPrincipalName eq '{user_principal}'"
            )
            
            url = f"{self.base_url}/security/alerts?$filter={filter_str}"
            async with session.get(url, headers=headers) as resp:
                alerts = await resp.json()
            
            return [
                {
                    "alert_id": alert["id"],
                    "title": alert["title"],
                    "severity": alert["severity"],
                    "category": alert["category"],
                    "file_evidence": alert.get("fileEvidence", []),
                    "policy_name": alert.get("policyName"),
                    "sensitive_info_types": alert.get("sensitiveInfoTypes", [])
                }
                for alert in alerts.get("value", [])
            ]
    
    async def _get_token(self) -> str:
        """Get OAuth token, refresh if expired."""
        if self._token and self._token_expiry > datetime.utcnow():
            return self._token
        
        async with aiohttp.ClientSession() as session:
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials"
            }
            
            async with session.post(token_url, data=data) as resp:
                result = await resp.json()
                self._token = result["access_token"]
                self._token_expiry = datetime.utcnow() + timedelta(seconds=result["expires_in"] - 60)
                return self._token
```

---

## 6. Investigation Connectors

### Connector Architecture for IR/Forensics/Threat Hunting

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Investigation Connector Framework                                           │
│                                                                             │
│ PERSONAS AND THEIR NEEDS:                                                   │
│                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ SOC ANALYST (Tier 1/2)                                                  ││
│ │ ───────────────────────                                                 ││
│ │ Needs: Quick context to triage alerts                                   ││
│ │ Time budget: 5-10 minutes per alert                                     ││
│ │                                                                         ││
│ │ Connectors Used:                                                        ││
│ │ • Identity (user context, group membership, risk score)                 ││
│ │ • Asset (host criticality, owner, recent patches)                       ││
│ │ • Threat Intel (IOC reputation, campaign association)                   ││
│ │                                                                         ││
│ │ UI: Single-click enrichment, auto-populated context panel               ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ INCIDENT RESPONDER (Tier 3)                                             ││
│ │ ─────────────────────────────                                           ││
│ │ Needs: Complete attack timeline, containment actions                    ││
│ │ Time budget: Hours to days per incident                                 ││
│ │                                                                         ││
│ │ Connectors Used:                                                        ││
│ │ • Email (full message retrieval, attachment analysis)                   ││
│ │ • Cloud (API call history, resource modifications)                      ││
│ │ • EDR (live response, isolation, artifact collection)                   ││
│ │ • Identity (password reset, session revocation)                         ││
│ │ • Network (PCAP retrieval, firewall block)                             ││
│ │                                                                         ││
│ │ UI: Investigation workbench with timeline view, action buttons          ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ THREAT HUNTER                                                           ││
│ │ ─────────────────                                                       ││
│ │ Needs: Broad queries across historical data, hypothesis testing         ││
│ │ Time budget: Days to weeks per hunt                                     ││
│ │                                                                         ││
│ │ Connectors Used:                                                        ││
│ │ • Raw log access (federated query to original sources)                  ││
│ │ • YARA/Sigma rule execution (across retained data)                      ││
│ │ • Threat Intel (bulk IOC matching, campaign patterns)                   ││
│ │ • MITRE ATT&CK mapping (technique prevalence analysis)                  ││
│ │                                                                         ││
│ │ UI: Query interface, Jupyter notebook integration, export to STIX       ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ FORENSIC ANALYST                                                        ││
│ │ ──────────────────                                                      ││
│ │ Needs: Evidence collection, chain of custody, legal holds               ││
│ │ Time budget: Weeks to months per case                                   ││
│ │                                                                         ││
│ │ Connectors Used:                                                        ││
│ │ • Memory (live memory acquisition, volatility analysis)                 ││
│ │ • Disk (forensic image acquisition, timeline extraction)                ││
│ │ • Email (legal hold, eDiscovery export)                                 ││
│ │ • Cloud Storage (point-in-time snapshots, access logs)                  ││
│ │ • DLP (data classification evidence)                                    ││
│ │                                                                         ││
│ │ UI: Evidence locker, hash verification, export with audit trail         ││
│ └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

### Connector Categories and Implementations

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Investigation Connector Catalog                                             │
│                                                                             │
│ CATEGORY: IDENTITY & ACCESS                                                 │
│ ───────────────────────────                                                 │
│ ┌─────────────────┬─────────────────────────────────────────────────────┐  │
│ │ Connector       │ Capabilities                                        │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Azure AD        │ • User profile, group membership                    │  │
│ │ (Entra ID)      │ • Sign-in logs (risky sign-ins, MFA status)        │  │
│ │                 │ • Conditional access policy evaluation              │  │
│ │                 │ • Password reset, session revocation (response)     │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Okta            │ • User profile, app assignments                     │  │
│ │                 │ • Authentication logs, MFA events                   │  │
│ │                 │ • Suspicious activity reports                       │  │
│ │                 │ • Session clear, user suspend (response)            │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ CyberArk /      │ • Privileged session recordings                     │  │
│ │ BeyondTrust     │ • Password checkout logs                            │  │
│ │                 │ • Privilege elevation events                        │  │
│ └─────────────────┴─────────────────────────────────────────────────────┘  │
│                                                                             │
│ CATEGORY: EMAIL SECURITY                                                    │
│ ────────────────────────                                                    │
│ ┌─────────────────┬─────────────────────────────────────────────────────┐  │
│ │ Connector       │ Capabilities                                        │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Proofpoint TAP  │ • Message trace (delivered, blocked, quarantined)  │  │
│ │                 │ • URL click tracking                                │  │
│ │                 │ • Attachment analysis verdicts                      │  │
│ │                 │ • Threat campaign association                       │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Mimecast        │ • Message tracking (inbound/outbound)               │  │
│ │                 │ • URL Protection logs                               │  │
│ │                 │ • Impersonation detection results                   │  │
│ │                 │ • Attachment sandbox verdicts                       │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Microsoft 365   │ • Message trace                                     │  │
│ │ Defender        │ • Safe Links/Safe Attachments verdicts             │  │
│ │                 │ • Threat Explorer queries                          │  │
│ │                 │ • Automated investigation results                   │  │
│ └─────────────────┴─────────────────────────────────────────────────────┘  │
│                                                                             │
│ CATEGORY: CLOUD INFRASTRUCTURE                                              │
│ ──────────────────────────────                                              │
│ ┌─────────────────┬─────────────────────────────────────────────────────┐  │
│ │ Connector       │ Capabilities                                        │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ AWS CloudTrail  │ • API call history (management events)              │  │
│ │                 │ • S3 data events                                    │  │
│ │                 │ • IAM role assumption                               │  │
│ │                 │ • Resource creation/modification                    │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Azure Activity  │ • Control plane operations                          │  │
│ │ Log             │ • Resource provider actions                         │  │
│ │                 │ • RBAC changes                                      │  │
│ │                 │ • Policy violations                                 │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ GCP Cloud Audit │ • Admin activity                                    │  │
│ │ Logs            │ • Data access                                       │  │
│ │                 │ • System events                                     │  │
│ │                 │ • Policy denied                                     │  │
│ └─────────────────┴─────────────────────────────────────────────────────┘  │
│                                                                             │
│ CATEGORY: ENDPOINT DEEP DIVE                                                │
│ ────────────────────────────                                                │
│ ┌─────────────────┬─────────────────────────────────────────────────────┐  │
│ │ Connector       │ Capabilities                                        │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ CrowdStrike     │ • Live Response (remote shell, file retrieval)      │  │
│ │ Falcon          │ • Real Time Response scripts                        │  │
│ │                 │ • Network containment                               │  │
│ │                 │ • IOC search across fleet                           │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Microsoft       │ • Live Response                                     │  │
│ │ Defender ATP    │ • Advanced Hunting queries                          │  │
│ │                 │ • Automated Investigation                           │  │
│ │                 │ • Device isolation                                  │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ SentinelOne     │ • Remote Shell                                      │  │
│ │                 │ • Threat Intelligence enrichment                    │  │
│ │                 │ • Rollback/remediation                              │  │
│ │                 │ • Deep Visibility queries                           │  │
│ └─────────────────┴─────────────────────────────────────────────────────┘  │
│                                                                             │
│ CATEGORY: DATA LOSS PREVENTION                                              │
│ ──────────────────────────────                                              │
│ ┌─────────────────┬─────────────────────────────────────────────────────┐  │
│ │ Connector       │ Capabilities                                        │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Microsoft       │ • Sensitivity labels                                │  │
│ │ Purview         │ • DLP policy matches                                │  │
│ │                 │ • Data classification                               │  │
│ │                 │ • eDiscovery case management                        │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ AWS Macie       │ • S3 bucket classification                          │  │
│ │                 │ • Sensitive data discovery                          │  │
│ │                 │ • Policy findings                                   │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Google DLP      │ • Content inspection                                │  │
│ │                 │ • Info type detection                               │  │
│ │                 │ • De-identification                                 │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Netskope /      │ • Cloud app data classification                     │  │
│ │ Zscaler         │ • CASB policy violations                            │  │
│ │                 │ • Shadow IT detection                               │  │
│ └─────────────────┴─────────────────────────────────────────────────────┘  │
│                                                                             │
│ CATEGORY: NETWORK FORENSICS                                                 │
│ ───────────────────────────                                                 │
│ ┌─────────────────┬─────────────────────────────────────────────────────┐  │
│ │ Connector       │ Capabilities                                        │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Corelight /     │ • PCAP retrieval for specific flows                 │  │
│ │ Zeek            │ • Connection logs                                   │  │
│ │                 │ • File extraction (carved from traffic)             │  │
│ │                 │ • Protocol analysis (DNS, HTTP, TLS)                │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ ExtraHop /      │ • Transaction records                               │  │
│ │ Gigamon         │ • Application layer visibility                      │  │
│ │                 │ • Decryption (with key escrow)                      │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Firewall        │ • Connection logs (Palo Alto, Fortinet, etc.)       │  │
│ │ (Various)       │ • Threat logs                                       │  │
│ │                 │ • URL filtering logs                                │  │
│ │                 │ • Block/allow actions                               │  │
│ └─────────────────┴─────────────────────────────────────────────────────┘  │
│                                                                             │
│ CATEGORY: THREAT INTELLIGENCE                                               │
│ ─────────────────────────────                                               │
│ ┌─────────────────┬─────────────────────────────────────────────────────┐  │
│ │ Connector       │ Capabilities                                        │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ VirusTotal      │ • Hash reputation                                   │  │
│ │                 │ • URL/domain reputation                             │  │
│ │                 │ • Behavior analysis                                 │  │
│ │                 │ • Relationship graphs                               │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ Recorded Future │ • IOC enrichment                                    │  │
│ │ / Mandiant      │ • Threat actor profiles                             │  │
│ │                 │ • Campaign attribution                              │  │
│ │                 │ • Vulnerability intelligence                        │  │
│ ├─────────────────┼─────────────────────────────────────────────────────┤  │
│ │ MISP /          │ • Community IOC feeds                               │  │
│ │ OpenCTI         │ • STIX/TAXII integration                            │  │
│ │                 │ • Correlation with known campaigns                  │  │
│ └─────────────────┴─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Investigation Workflow Example

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Real-World Investigation: BEC Attack                                        │
│                                                                             │
│ INITIAL ALERT (from Network + Endpoint correlation):                        │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ "User CFO@acme.com accessed from unusual IP (Nigeria) and initiated    ││
│ │  large wire transfer request via email"                                 ││
│ │                                                                         ││
│ │ Confidence: MEDIUM (need more context)                                  ││
│ │ Missing Telemetry: Identity (auth details), Email (message content)    ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ INVESTIGATION STEP 1: Identity Connector (Auto-pulled, P1)                  │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ Query: Azure AD sign-in logs for CFO@acme.com, last 24h                ││
│ │                                                                         ││
│ │ Result:                                                                 ││
│ │ {                                                                       ││
│ │   "sign_ins": [                                                        ││
│ │     {                                                                   ││
│ │       "timestamp": "2024-01-15T08:15:00Z",                             ││
│ │       "location": "Lagos, Nigeria",                                    ││
│ │       "ip": "197.210.xx.xx",                                           ││
│ │       "mfa_result": "not_required",    ← RED FLAG                      ││
│ │       "risk_level": "high",                                            ││
│ │       "app": "Office 365 Exchange Online",                             ││
│ │       "device": "Unknown"              ← RED FLAG                      ││
│ │     }                                                                   ││
│ │   ],                                                                    ││
│ │   "usual_locations": ["San Francisco, CA", "New York, NY"]             ││
│ │ }                                                                       ││
│ │                                                                         ││
│ │ Confidence Boost: +0.25 (impossible travel, no MFA)                    ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ INVESTIGATION STEP 2: Email Connector (Auto-pulled, P1)                     │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ Query: Proofpoint messages from CFO@acme.com, last 4h                  ││
│ │                                                                         ││
│ │ Result:                                                                 ││
│ │ {                                                                       ││
│ │   "messages_sent": [                                                   ││
│ │     {                                                                   ││
│ │       "timestamp": "2024-01-15T08:22:00Z",                             ││
│ │       "to": "ap@acme.com",                                             ││
│ │       "subject": "Urgent Wire Transfer - Confidential",                ││
│ │       "sender_ip": "197.210.xx.xx",    ← Same as login                 ││
│ │       "attachments": ["Wire_Instructions.pdf"],                        ││
│ │       "keywords_matched": ["wire transfer", "urgent", "confidential"] ││
│ │     }                                                                   ││
│ │   ],                                                                    ││
│ │   "inbox_rules_created": [                                             ││
│ │     {                                                                   ││
│ │       "rule_name": ".",                ← RED FLAG (hidden rule)        ││
│ │       "action": "move to deleted items",                               ││
│ │       "condition": "from contains 'security'"                          ││
│ │     }                                                                   ││
│ │   ]                                                                     ││
│ │ }                                                                       ││
│ │                                                                         ││
│ │ Confidence Boost: +0.30 (BEC pattern confirmed)                        ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ INVESTIGATION STEP 3: DLP Connector (Analyst-requested)                     │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ Query: Purview - wire transfer attachment analysis                      ││
│ │                                                                         ││
│ │ Result:                                                                 ││
│ │ {                                                                       ││
│ │   "attachment": "Wire_Instructions.pdf",                               ││
│ │   "content_analysis": {                                                ││
│ │     "bank_account_detected": true,                                     ││
│ │     "account_country": "Nigeria",                                      ││
│ │     "amount_detected": "$2,450,000",                                   ││
│ │     "beneficiary": "GlobalTrade Supplies Ltd"  ← Not a known vendor   ││
│ │   },                                                                    ││
│ │   "policy_violations": ["External Wire Transfer - CFO Approval Bypass"]││
│ │ }                                                                       ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ FINAL ALERT (Fully Enriched):                                               │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ SEVERITY: CRITICAL                                                      ││
│ │ CONFIDENCE: 0.95 (HIGH)                                                ││
│ │ ATTACK TYPE: Business Email Compromise (BEC)                           ││
│ │                                                                         ││
│ │ SUMMARY:                                                                ││
│ │ CFO account compromised via credential theft. Attacker logged in       ││
│ │ from Nigeria (impossible travel), bypassed MFA, created hidden         ││
│ │ inbox rule, and sent fraudulent wire transfer request for $2.45M       ││
│ │ to unknown Nigerian beneficiary.                                        ││
│ │                                                                         ││
│ │ AUTOMATED RESPONSE EXECUTED:                                            ││
│ │ ✓ CFO session revoked (Azure AD connector)                             ││
│ │ ✓ Inbox rule deleted (Exchange connector)                              ││
│ │ ✓ AP team alerted to hold wire transfer                                ││
│ │                                                                         ││
│ │ PENDING ANALYST ACTIONS:                                                ││
│ │ □ Password reset for CFO                                               ││
│ │ □ MFA re-enrollment                                                    ││
│ │ □ Review all CFO emails sent in last 24h                               ││
│ │ □ Notify legal for potential regulatory reporting                      ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ INVESTIGATION TIME: 3 minutes (automated) + 15 minutes (analyst review)    │
│ WITHOUT DEMAND-DRIVEN MODEL: Would have required continuous email          │
│ collection, increasing storage 5x and creating GDPR exposure               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. False Positive Reduction Strategies

### The False Positive Problem

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Why Traditional XDR/SIEM Has High False Positive Rates                      │
│                                                                             │
│ ROOT CAUSES:                                                                │
│                                                                             │
│ 1. SINGLE-DOMAIN DETECTION                                                  │
│    ┌─────────────────────────────────────────────────────────────────────┐ │
│    │ Alert: "PowerShell executed encoded command"                        │ │
│    │ Reality: IT admin running legitimate maintenance script             │ │
│    │                                                                      │ │
│    │ Problem: Endpoint alone can't distinguish admin from attacker       │ │
│    └─────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ 2. MISSING CONTEXT                                                          │
│    ┌─────────────────────────────────────────────────────────────────────┐ │
│    │ Alert: "Large data upload to cloud storage"                         │ │
│    │ Reality: Marketing team uploading campaign assets to approved CDN   │ │
│    │                                                                      │ │
│    │ Problem: No business context about what's "normal" for that user    │ │
│    └─────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ 3. STATIC THRESHOLDS                                                        │
│    ┌─────────────────────────────────────────────────────────────────────┐ │
│    │ Alert: "User logged in from new location"                           │ │
│    │ Reality: User is on vacation (approved in HR system)                │ │
│    │                                                                      │ │
│    │ Problem: No integration with HR/travel systems                      │ │
│    └─────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│ 4. RULE EXPLOSION                                                           │
│    ┌─────────────────────────────────────────────────────────────────────┐ │
│    │ 500+ detection rules × 8 data sources = thousands of alert types    │ │
│    │ Each rule has its own FP rate                                        │ │
│    │ Cumulative FP rate becomes overwhelming                              │ │
│    │                                                                      │ │
│    │ Problem: More data sources = more spurious correlations             │ │
│    └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### JanuSec's False Positive Reduction Approach

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ False Positive Reduction in the 21-Stage Pipeline                           │
│                                                                             │
│ STAGE 1-5: INGESTION & NORMALIZATION                                        │
│ ──────────────────────────────────────                                      │
│ • Schema normalization (OCSF) - consistent field names                      │
│ • Entity resolution - same user across systems                              │
│ • Timestamp alignment - accurate event ordering                             │
│                                                                             │
│ STAGE 6-10: BASELINE & ANOMALY DETECTION                                    │
│ ─────────────────────────────────────────                                   │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ BEHAVIORAL BASELINING (Per-Entity)                                      ││
│ │                                                                         ││
│ │ For each user/host/service, learn:                                      ││
│ │ • Typical working hours                                                 ││
│ │ • Normal network destinations                                           ││
│ │ • Expected process trees                                                ││
│ │ • Usual data volumes                                                    ││
│ │                                                                         ││
│ │ Anomaly = deviation from baseline, not static threshold                 ││
│ │                                                                         ││
│ │ Example:                                                                ││
│ │ • "Admin ran PowerShell at 3am" is anomalous for a 9-5 admin           ││
│ │ • "Admin ran PowerShell at 3am" is normal for an on-call SRE          ││
│ │                                                                         ││
│ │ Technique: Isolation Forest, EWMA, Lomb-Scargle for periodicity        ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ STAGE 11-15: CORRELATION & ATTACK GRAPH                                     │
│ ────────────────────────────────────────                                    │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ MULTI-DOMAIN CORRELATION (The Key to FP Reduction)                      ││
│ │                                                                         ││
│ │ Single-domain anomaly:     Confidence: LOW (30-50%)                    ││
│ │ Two-domain correlation:    Confidence: MEDIUM (60-75%)                 ││
│ │ Three+ domain correlation: Confidence: HIGH (80-95%)                   ││
│ │                                                                         ││
│ │ Example:                                                                ││
│ │ • Endpoint: "cmd.exe spawned from Word" (could be macro, FP possible) ││
│ │ • Network:  "Connection to known C2 IP"  (could be sinkhole, FP poss.)││
│ │ • Combined: "cmd.exe from Word + C2 connection" → HIGH confidence     ││
│ │                                                                         ││
│ │ The HopGraph attack reconstruction ensures events are causally linked, ││
│ │ not just temporally coincidental.                                       ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ STAGE 16-18: CONTEXT ENRICHMENT                                             │
│ ────────────────────────────────                                            │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ ON-DEMAND CONTEXT PULL (Resolve Ambiguity)                              ││
│ │                                                                         ││
│ │ When correlation is MEDIUM confidence, pull context to resolve:        ││
│ │                                                                         ││
│ │ • Identity: "Is this user an admin? Are they on-call?"                 ││
│ │ • Asset: "Is this host a dev box or production server?"               ││
│ │ • Business: "Is this activity related to a change window?"            ││
│ │ • Threat Intel: "Is this IOC known-malicious or known-benign?"        ││
│ │                                                                         ││
│ │ Context can INCREASE or DECREASE confidence:                           ││
│ │ • "User is IT admin" → decrease suspicion of PowerShell               ││
│ │ • "User is intern in Finance" → increase suspicion of PowerShell      ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ STAGE 19-21: PRIORITIZATION & ALERT SUPPRESSION                             │
│ ────────────────────────────────────────────────                            │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ INTELLIGENT SUPPRESSION                                                  ││
│ │                                                                         ││
│ │ Don't alert on:                                                         ││
│ │ • Known-benign patterns (with explainability)                          ││
│ │ • Low-confidence without corroboration                                  ││
│ │ • Duplicate alerts for same attack chain                               ││
│ │                                                                         ││
│ │ DO alert on:                                                            ││
│ │ • High-confidence with attack chain                                     ││
│ │ • Medium-confidence with critical asset impact                          ││
│ │ • Any confidence with data exfiltration indicators                      ││
│ │                                                                         ││
│ │ EXPLAINABILITY:                                                         ││
│ │ Every suppressed alert goes to a "Noise Reduction" dashboard with:     ││
│ │ • Why it was suppressed                                                 ││
│ │ • What would have made it alert                                         ││
│ │ • Option for analyst to promote to alert                                ││
│ └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

### Quantifying FP Reduction

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ False Positive Reduction Metrics                                            │
│                                                                             │
│ TRADITIONAL SIEM (8 domains, rule-based):                                   │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ Raw events:           1,000,000/day                                     ││
│ │ Rule matches:         50,000/day                                        ││
│ │ After deduplication:  10,000/day                                        ││
│ │ True positives:       50-100/day (0.5-1%)                              ││
│ │                                                                         ││
│ │ Analyst time wasted:  ~99% on false positives                          ││
│ │ Mean time to triage:  45 minutes per alert                             ││
│ │ Alert fatigue:        SEVERE                                            ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ JANUSEC DEMAND-DRIVEN MODEL (2 domains + on-demand):                        │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ Raw events (Network + Endpoint): 300,000/day                            ││
│ │ After correlation:               500/day                                ││
│ │ After context enrichment:        100/day                                ││
│ │ True positives:                  80-90/day (80-90%)                    ││
│ │                                                                         ││
│ │ Analyst time on FP:   ~10-20%                                          ││
│ │ Mean time to triage:  8 minutes per alert (context pre-populated)      ││
│ │ Alert fatigue:        MINIMAL                                           ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ KEY INSIGHT:                                                                │
│ Reducing from 8 domains to 2 domains for PRIMARY detection actually        │
│ REDUCES false positives because:                                            │
│                                                                             │
│ 1. Fewer spurious cross-domain correlations                                 │
│ 2. Network + Endpoint correlation is high-fidelity                          │
│ 3. Additional context is pulled ONLY when needed to resolve ambiguity       │
│ 4. Context is targeted (specific entity, specific time), not bulk noise     │
│                                                                             │
│ FORMULA:                                                                    │
│ FP_rate = base_rate × (1 - correlation_confidence) × (1 - context_boost)   │
│                                                                             │
│ Single domain:  0.95 × (1 - 0.30) × (1 - 0.00) = 0.665 (66.5% FP)          │
│ Two domains:    0.95 × (1 - 0.70) × (1 - 0.00) = 0.285 (28.5% FP)          │
│ Two + context:  0.95 × (1 - 0.70) × (1 - 0.60) = 0.114 (11.4% FP)          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Suppression Rules with Explainability

```yaml
# Example suppression rules with explainability

suppression_rules:
  - name: "IT Admin PowerShell Usage"
    condition:
      process_name: "powershell.exe"
      user_group_contains: "IT-Admins"
      working_hours: true
      network_destination: "internal_only"
    action: suppress
    explain: |
      PowerShell execution by IT admin during business hours with
      only internal network activity matches normal administrative
      behavior. Would alert if: (1) unusual hours, (2) external
      network connections, (3) encoded commands, (4) LSASS access.
    review_trigger:
      - encoded_command: true
      - lsass_access: true
      - external_c2_pattern: true

  - name: "Known Software Update Beacon"
    condition:
      network_pattern: "periodic_beacon"
      destination_domain_in:
        - "*.microsoft.com"
        - "*.windowsupdate.com"
        - "*.adobe.com"
      tls_valid: true
    action: suppress
    explain: |
      Periodic beaconing to known software update domains with
      valid TLS certificates matches expected update behavior.
      Would alert if: (1) domain spoofing detected, (2) unusual
      payload size, (3) certificate anomaly.
    review_trigger:
      - cert_mismatch: true
      - payload_size_anomaly: true

  - name: "Marketing Cloud Upload"
    condition:
      destination: "*.cloudfront.net"
      source_department: "Marketing"
      file_type_in: ["jpg", "png", "mp4", "pdf"]
      size_within_baseline: true
    action: suppress
    explain: |
      Marketing team uploads to approved CDN (CloudFront) with
      expected file types and normal sizes. Would alert if:
      (1) source code uploaded, (2) size significantly above baseline,
      (3) executable files, (4) outside business hours.
    review_trigger:
      - file_type_in: ["exe", "dll", "ps1", "sh"]
      - size_above_baseline: 5x
      - non_business_hours: true
```

---

## 8. Tenant Isolation Models

### Isolation Options for Multi-Tenant Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Tenant Isolation Spectrum                                                   │
│                                                                             │
│   LOGICAL                                                          PHYSICAL │
│   ISOLATION ◄─────────────────────────────────────────────────► ISOLATION  │
│                                                                             │
│   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────────────────┐│
│   │  Shared   │   │  Shared   │   │ Dedicated │   │  Dedicated            ││
│   │Everything │   │  Compute  │   │  Compute  │   │  Subscription         ││
│   │(Namespace │   │ Dedicated │   │ Dedicated │   │  (Full Isolation)     ││
│   │Separation)│   │  Storage  │   │  Storage  │   │                       ││
│   └───────────┘   └───────────┘   └───────────┘   └───────────────────────┘│
│        │               │               │                    │              │
│     $1-2K/mo       $2-4K/mo        $5-8K/mo           $10-20K/mo           │
│                                                                             │
│   Best for:       Best for:       Best for:          Best for:             │
│   • Startups      • SMB           • Mid-market       • Enterprise          │
│   • Non-regulated • Low-risk      • Regulated        • Government          │
│   • Cost-first    • data          • Compliance       • Financial           │
│                                     mandates          • Healthcare          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Recommended: Hybrid Tiered Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JanuSec Tenant Tier Architecture                                            │
│                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ SHARED CONTROL PLANE (All Tenants)                                      ││
│ │                                                                         ││
│ │ • Tenant onboarding / management                                        ││
│ │ • Billing and usage tracking                                            ││
│ │ • Platform health monitoring                                            ││
│ │ • Shared threat intelligence (anonymized)                               ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                          │                                                  │
│     ┌────────────────────┼────────────────────┐                            │
│     │                    │                    │                            │
│     ▼                    ▼                    ▼                            │
│ ┌─────────────┐    ┌─────────────┐    ┌──────────────────────────────────┐│
│ │ STANDARD    │    │ BUSINESS    │    │ ENTERPRISE TIER                  ││
│ │ TIER        │    │ TIER        │    │                                  ││
│ │             │    │             │    │ ┌────────────────────────────┐   ││
│ │ Shared:     │    │ Shared:     │    │ │ Tenant A (Dedicated VNet)  │   ││
│ │ • Compute   │    │ • Compute   │    │ │                            │   ││
│ │ • Database  │    │ (isolated   │    │ │ • Own AKS cluster          │   ││
│ │ • Storage   │    │  namespace) │    │ │ • Own PostgreSQL           │   ││
│ │             │    │             │    │ │ • Own Key Vault (HSM)      │   ││
│ │ Isolation:  │    │ Dedicated:  │    │ │ • Own Storage Account      │   ││
│ │ • Namespace │    │ • Storage   │    │ │ • Private endpoints only   │   ││
│ │ • RLS in DB │    │   container │    │ └────────────────────────────┘   ││
│ │ • Tenant ID │    │ • Key Vault │    │                                  ││
│ │   tagging   │    │   key       │    │ ┌────────────────────────────┐   ││
│ │             │    │             │    │ │ Tenant B (Dedicated VNet)  │   ││
│ │             │    │ Isolation:  │    │ │ (Same pattern)             │   ││
│ │             │    │ • Namespace │    │ └────────────────────────────┘   ││
│ │             │    │ • Container │    │                                  ││
│ │             │    │ • Key       │    │ Peered to shared monitoring     ││
│ └─────────────┘    └─────────────┘    └──────────────────────────────────┘│
│                                                                             │
│ DATA ISOLATION ENFORCEMENT:                                                 │
│                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ Level 1: Network (NSG/Network Policy)                                   ││
│ │ • Tenant A pods cannot communicate with Tenant B pods                   ││
│ │ • Egress limited to tenant's own storage/DB                             ││
│ │                                                                         ││
│ │ Level 2: Compute (Kubernetes Namespace)                                 ││
│ │ • ResourceQuota per namespace                                           ││
│ │ • NetworkPolicy default-deny                                            ││
│ │ • PodSecurityPolicy enforcement                                         ││
│ │                                                                         ││
│ │ Level 3: Storage (Container + Encryption)                               ││
│ │ • Tenant-specific blob container with SAS scoping                       ││
│ │ • Envelope encryption with per-tenant KEK                               ││
│ │                                                                         ││
│ │ Level 4: Database (Row-Level Security)                                  ││
│ │ • tenant_id column on all tables                                        ││
│ │ • RLS policy enforced at connection level                               ││
│ │ • Application cannot bypass (SET SESSION tenant_id)                     ││
│ │                                                                         ││
│ │ Level 5: API (JWT + RBAC)                                               ││
│ │ • Tenant ID in JWT claims                                               ││
│ │ • All API endpoints enforce tenant context                              ││
│ │ • Audit log of cross-tenant access attempts (should be zero)            ││
│ └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Cost Modeling & FinOps

### Demand-Driven Model Cost Comparison

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ Monthly Cost Comparison: 100 Endpoints                                                 │
├─────────────────────────┬─────────────────────┬─────────────────────┬──────────────────┤
│ Component               │ Full Collection     │ Demand-Driven       │ Savings          │
│                         │ (8 domains)         │ (2 + on-demand)     │                  │
├─────────────────────────┼─────────────────────┼─────────────────────┼──────────────────┤
│ COMPUTE                 │                     │                     │                  │
│ • Ingestion workers     │ $3,500              │ $1,200              │ 66%              │
│ • Correlation engine    │ $2,000              │ $1,500              │ 25%              │
│ • API servers           │ $800                │ $600                │ 25%              │
│ • On-demand connectors  │ $0                  │ $300                │ -                │
├─────────────────────────┼─────────────────────┼─────────────────────┼──────────────────┤
│ STORAGE                 │                     │                     │                  │
│ • Hot (30 days)         │ $4,500              │ $800                │ 82%              │
│ • Warm (60 days)        │ $1,500              │ $300                │ 80%              │
│ • Cold (1 year)         │ $800                │ $200                │ 75%              │
│ • Forensic (immutable)  │ $400                │ $150                │ 63%              │
├─────────────────────────┼─────────────────────┼─────────────────────┼──────────────────┤
│ DATABASE                │                     │                     │                  │
│ • Operational DB        │ $800                │ $500                │ 38%              │
│ • Search indices        │ $1,200              │ $400                │ 67%              │
├─────────────────────────┼─────────────────────┼─────────────────────┼──────────────────┤
│ NETWORKING              │                     │                     │                  │
│ • Ingress               │ $0                  │ $0                  │ -                │
│ • Egress                │ $600                │ $150                │ 75%              │
│ • Load balancers        │ $300                │ $200                │ 33%              │
│ • Private endpoints     │ $200                │ $150                │ 25%              │
├─────────────────────────┼─────────────────────┼─────────────────────┼──────────────────┤
│ SECURITY                │                     │                     │                  │
│ • Key Vault ops         │ $150                │ $100                │ 33%              │
│ • Monitoring/logging    │ $300                │ $200                │ 33%              │
├─────────────────────────┼─────────────────────┼─────────────────────┼──────────────────┤
│ API COSTS (On-Demand)   │                     │                     │                  │
│ • Identity queries      │ $0                  │ $50                 │ -                │
│ • Email queries         │ $0                  │ $75                 │ -                │
│ • Cloud queries         │ $0                  │ $50                 │ -                │
│ • DLP queries           │ $0                  │ $25                 │ -                │
├─────────────────────────┼─────────────────────┼─────────────────────┼──────────────────┤
│ TOTAL                   │ $17,050/mo          │ $6,950/mo           │ 59%              │
│ Per Endpoint            │ $170.50             │ $69.50              │                  │
│ Annual                  │ $204,600            │ $83,400             │ $121,200 saved   │
└─────────────────────────┴─────────────────────┴─────────────────────┴──────────────────┘
```

### Scaling Costs by Domain Count

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ Cost Scaling: Demand-Driven Model (100 endpoints baseline)                             │
├───────────────┬──────────────────────────────────────────────────────────┬─────────────┤
│ Configuration │ Description                                              │ Monthly Cost│
├───────────────┼──────────────────────────────────────────────────────────┼─────────────┤
│ TIER 0 ONLY   │ Network + Endpoint (bare minimum)                        │ $5,500      │
│               │ • Basic correlation                                       │             │
│               │ • No on-demand pulls                                      │             │
│               │ • Manual investigation                                    │             │
├───────────────┼──────────────────────────────────────────────────────────┼─────────────┤
│ TIER 0 + 1    │ Network + Endpoint + On-Demand Connectors               │ $6,950      │
│ (RECOMMENDED) │ • Identity, Email, Cloud, DLP on-demand                  │             │
│               │ • Automated context enrichment                           │             │
│               │ • Missing telemetry detection                            │             │
├───────────────┼──────────────────────────────────────────────────────────┼─────────────┤
│ TIER 0 + 1    │ Add continuous Identity (Azure AD/Okta)                  │ $8,200      │
│ + Identity    │ • Faster identity context (no API delay)                 │             │
│               │ • Better privilege escalation detection                  │             │
│               │ • Recommended for high-risk environments                 │             │
├───────────────┼──────────────────────────────────────────────────────────┼─────────────┤
│ TIER 0 + 1    │ Add continuous Email (Proofpoint/Mimecast feed)          │ $9,500      │
│ + Email       │ • Faster phishing detection                              │             │
│               │ • BEC detection without API delay                        │             │
│               │ • Recommended for email-heavy threat model               │             │
├───────────────┼──────────────────────────────────────────────────────────┼─────────────┤
│ FULL STACK    │ All 8 domains continuous                                 │ $17,050     │
│ (Not Rec.)    │ • Maximum coverage, maximum cost                         │             │
│               │ • More false positives due to noise                      │             │
│               │ • Only for compliance mandates                           │             │
└───────────────┴──────────────────────────────────────────────────────────┴─────────────┘
```

### FinOps Recommendations

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ FinOps Best Practices for JanuSec                                           │
│                                                                             │
│ 1. RIGHT-SIZE COLLECTION                                                    │
│ ────────────────────────                                                    │
│ • Start with Network + Endpoint only                                        │
│ • Add domains only when detection gaps are proven                           │
│ • Use Missing Telemetry Detector to identify actual needs                   │
│ • Review connector usage monthly - disable unused connectors                 │
│                                                                             │
│ 2. OPTIMIZE STORAGE LIFECYCLE                                               │
│ ──────────────────────────────                                              │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ Age       │ Storage Tier │ Cost/GB │ Access Pattern                     ││
│ │ 0-7 days  │ Hot (SSD)    │ $0.0184 │ Frequent (correlation, queries)   ││
│ │ 7-30 days │ Cool (HDD)   │ $0.0100 │ Occasional (investigation)        ││
│ │ 30-90 days│ Cold         │ $0.0020 │ Rare (forensics, hunting)         ││
│ │ 90+ days  │ Archive      │ $0.0010 │ Compliance only (rehydrate 15h)   ││
│ │ 365+ days │ Delete       │ $0.0000 │ Unless legal hold                 ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ 3. RESERVED CAPACITY                                                        │
│ ────────────────────                                                        │
│ • 1-year reserved instances for baseline compute: 30-40% savings           │
│ • 3-year reserved for storage: 50% savings                                 │
│ • Spot/preemptible for burst processing: 60-80% savings                    │
│                                                                             │
│ 4. COMPRESSION AND DEDUPLICATION                                            │
│ ────────────────────────────────                                            │
│ • Zstd compression for logs: 5-10x reduction                               │
│ • Event deduplication at ingestion: 20-40% reduction                       │
│ • Field pruning (remove unnecessary fields): 30% reduction                 │
│                                                                             │
│ 5. REGIONAL OPTIMIZATION                                                    │
│ ─────────────────────────                                                   │
│ • Ingest in same region as data source: avoid cross-region egress          │
│ • Use Private Link: avoid public egress charges                            │
│ • Consider region pricing differences (US East vs US West)                 │
│                                                                             │
│ 6. API COST MANAGEMENT                                                      │
│ ────────────────────────                                                    │
│ • Cache connector responses (5-15 min TTL for context)                     │
│ • Batch API calls where possible                                           │
│ • Negotiate enterprise API tiers with vendors (Proofpoint, etc.)           │
│ • Monitor API usage and set budget alerts                                  │
│                                                                             │
│ 7. TENANT COST ALLOCATION                                                   │
│ ───────────────────────────                                                 │
│ • Tag all resources with tenant_id for cost attribution                    │
│ • Use Azure Cost Management / AWS Cost Explorer for per-tenant billing     │
│ • Set per-tenant quotas to prevent runaway costs                           │
│ • Pass through connector API costs to tenants                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Security & Compliance Considerations

### Compliance Scope Reduction

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Compliance Benefit of Demand-Driven Model                                   │
│                                                                             │
│ FULL COLLECTION MODEL (8 domains stored):                                   │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ Data Types Stored:                    Compliance Implications:           ││
│ │ • Email bodies                        → GDPR Article 9 (special categories)│
│ │ • Email attachments                   → eDiscovery preservation         ││
│ │ • Auth logs (behavioral)              → GDPR biometric concerns         ││
│ │ • Cloud API logs (may contain PII)    → Data residency requirements     ││
│ │ • DLP findings (contains data samples)→ Data minimization violations    ││
│ │                                                                         ││
│ │ Audit Scope: ALL stored data types must be audited                      ││
│ │ DSAR Response: Must search ALL data stores                              ││
│ │ Breach Notification: More data = more potential exposure                ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ DEMAND-DRIVEN MODEL (2 domains stored + on-demand):                         │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ Data Types Stored:                    Compliance Implications:           ││
│ │ • Network metadata (no content)       → Low PII exposure                ││
│ │ • Endpoint events (process, files)    → Operational data, not PII       ││
│ │                                                                         ││
│ │ Data Types Queried (not stored):                                        ││
│ │ • Email (stays in Proofpoint)         → Proofpoint handles compliance  ││
│ │ • Identity (stays in Azure AD)        → Microsoft handles compliance   ││
│ │ • Cloud (stays in CloudTrail)         → AWS handles compliance         ││
│ │                                                                         ││
│ │ Audit Scope: Only Network + Endpoint data                               ││
│ │ DSAR Response: Search only 2 data stores                                ││
│ │ Breach Notification: Limited exposure (metadata only)                    ││
│ └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│ COMPLIANCE FRAMEWORK MAPPING:                                               │
│                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────┐│
│ │ Requirement              │ Full Collection  │ Demand-Driven             ││
│ │ ─────────────────────────┼──────────────────┼───────────────────────────││
│ │ GDPR Data Minimization   │ ❌ Fails (excess)│ ✅ Passes (minimal)       ││
│ │ GDPR Right to Erasure    │ ⚠️ Complex       │ ✅ Simple (less data)     ││
│ │ GDPR Breach Notification │ ⚠️ Broad scope   │ ✅ Narrow scope           ││
│ │ SOC 2 Data Retention     │ ✅ Meets         │ ✅ Meets                  ││
│ │ HIPAA Minimum Necessary  │ ❌ Fails         │ ✅ Passes                 ││
│ │ PCI DSS Scope Reduction  │ ❌ Wide scope    │ ✅ Narrow scope           ││
│ │ ISO 27001 Risk Reduction │ ⚠️ More assets   │ ✅ Fewer assets           ││
│ └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

### Security Controls

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Security Controls for JanuSec Platform                                      │
│                                                                             │
│ DATA PROTECTION                                                             │
│ ───────────────                                                             │
│ • Encryption at rest: AES-256 with per-tenant KEKs in Key Vault/KMS        │
│ • Encryption in transit: TLS 1.3 minimum, mTLS for service-to-service      │
│ • Field-level encryption for sensitive fields (user names, IPs)            │
│ • Tokenization for PII in search indices                                   │
│                                                                             │
│ ACCESS CONTROL                                                              │
│ ──────────────                                                              │
│ • RBAC with tenant-scoped roles                                            │
│ • MFA required for all administrative access                               │
│ • Just-in-time access for production systems (Azure PIM / AWS SSO)         │
│ • API keys scoped to specific tenants and operations                       │
│                                                                             │
│ NETWORK SECURITY                                                            │
│ ────────────────                                                            │
│ • Private endpoints for all storage and database access                    │
│ • NSG/Security Groups with default-deny                                    │
│ • Azure Firewall / AWS Network Firewall for egress control                 │
│ • DDoS protection at edge (Azure DDoS Standard / AWS Shield)               │
│                                                                             │
│ LOGGING AND MONITORING                                                      │
│ ──────────────────────                                                      │
│ • All API calls logged with tenant context                                 │
│ • Administrative actions logged to immutable store                         │
│ • Anomaly detection on platform access patterns                            │
│ • Alert on cross-tenant access attempts (should be zero)                   │
│                                                                             │
│ SUPPLY CHAIN                                                                │
│ ────────────                                                                │
│ • Signed container images with provenance attestation                      │
│ • Vulnerability scanning in CI/CD (Trivy, Grype)                           │
│ • SBOM generation for all deployments                                      │
│ • Dependency pinning and update automation                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Implementation Roadmap

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JanuSec Implementation Phases                                               │
│                                                                             │
│ PHASE 1: FOUNDATION (Weeks 1-4)                                             │
│ ────────────────────────────────                                            │
│ □ Deploy core infrastructure (VNet, subnets, AKS/EKS)                       │
│ □ Set up Network ingestion (Zeek/Suricata or VPC Flow Logs)                │
│ □ Set up Endpoint ingestion (Sysmon via Fluent Bit or EDR API)             │
│ □ Implement OCSF normalization layer                                        │
│ □ Basic correlation engine (entity resolution, temporal linking)            │
│ □ Simple alert generation (no enrichment yet)                               │
│                                                                             │
│ Deliverable: Working Network + Endpoint correlation with basic alerts       │
│                                                                             │
│ PHASE 2: MISSING TELEMETRY DETECTOR (Weeks 5-8)                             │
│ ─────────────────────────────────────────────────                           │
│ □ Implement gap detection logic (identity, email, cloud, DLP)              │
│ □ Build telemetry request queue                                            │
│ □ Create first on-demand connector (Azure AD)                              │
│ □ Add connector for Proofpoint/Mimecast                                    │
│ □ Integrate context into alert enrichment                                  │
│ □ Build investigation UI with connector buttons                            │
│                                                                             │
│ Deliverable: Alerts enriched with on-demand context from 2+ sources        │
│                                                                             │
│ PHASE 3: FALSE POSITIVE REDUCTION (Weeks 9-12)                              │
│ ─────────────────────────────────────────────────                           │
│ □ Implement behavioral baselining (per-entity)                             │
│ □ Add confidence scoring to correlation                                    │
│ □ Build suppression rules with explainability                              │
│ □ Create "Noise Reduction" dashboard                                       │
│ □ Tune detection rules based on FP feedback                                │
│ □ Measure FP rate and document improvement                                 │
│                                                                             │
│ Deliverable: 60-80% reduction in false positives vs baseline               │
│                                                                             │
│ PHASE 4: MULTI-TENANT (Weeks 13-16)                                         │
│ ───────────────────────────────────                                         │
│ □ Implement tenant isolation (namespace, RLS, encryption)                  │
│ □ Add tenant-scoped RBAC                                                   │
│ □ Create tenant onboarding automation                                      │
│ □ Build per-tenant billing and usage tracking                              │
│ □ Test isolation with penetration testing                                  │
│ □ Document compliance posture (SOC 2 prep)                                 │
│                                                                             │
│ Deliverable: Production-ready multi-tenant platform                        │
│                                                                             │
│ PHASE 5: EXPANSION (Weeks 17+)                                              │
│ ──────────────────────────────                                              │
│ □ Add connectors based on customer demand (CloudTrail, DLP, etc.)          │
│ □ Implement threat hunting interface                                       │
│ □ Add automated response actions (quarantine, block, revoke)               │
│ □ Build customer-facing portal for self-service                            │
│ □ Pursue SOC 2 Type II certification                                       │
│ □ Expand to additional cloud providers (AWS, GCP)                          │
│                                                                             │
│ Deliverable: Full-featured XDR triage platform                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 12. Further Reading

### Architecture & Design
- [OCSF (Open Cybersecurity Schema Framework)](https://github.com/ocsf/ocsf-schema) - Schema for normalization
- [MITRE ATT&CK Data Sources](https://attack.mitre.org/datasources/) - Coverage mapping
- [Azure Well-Architected Framework - Security](https://learn.microsoft.com/en-us/azure/well-architected/security/)
- [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/)

### Multi-Tenancy
- [Azure SaaS Development](https://learn.microsoft.com/en-us/azure/architecture/guide/saas-multitenant-solution-architecture/)
- [Row-Level Security in PostgreSQL](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [Kubernetes Multi-Tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/)

### Detection Engineering
- [Sigma Rules](https://github.com/SigmaHQ/sigma) - Detection rule format
- [YARA Rules](https://yara.readthedocs.io/) - Pattern matching
- [Elastic Detection Rules](https://github.com/elastic/detection-rules) - Reference implementations

### FinOps
- [FinOps Foundation](https://www.finops.org/) - Cost optimization practices
- [Azure Cost Management](https://learn.microsoft.com/en-us/azure/cost-management-billing/)
- [AWS Cost Optimization](https://aws.amazon.com/aws-cost-management/)

### Compliance
- [SOC 2 Compliance](https://www.aicpa.org/soc-2) - Trust service criteria
- [GDPR Technical Guidance](https://gdpr-info.eu/) - Data protection requirements
- [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html) - Information security

---

## Architecture Decision Record

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Primary Telemetry | Network + Endpoint | 75% ATT&CK coverage at 25% cost |
| Additional Telemetry | On-demand via connectors | Context when needed, not stored |
| Schema | OCSF | Open standard, vendor-neutral |
| Tenant Isolation | Hybrid (tiered by customer need) | Balance cost and compliance |
| False Positive Strategy | Multi-domain correlation + context enrichment | Reduces noise by design |
| Deployment | Cloud-native (Azure/AWS/GCP) with edge option | Flexibility for customer needs |
| Cost Model | Per-endpoint + connector usage | Aligns cost with value |

---

*Document Version: 2.0*  
*Last Updated: January 2026*  
*Author: Architecture Review for CyberStash JanuSec*
