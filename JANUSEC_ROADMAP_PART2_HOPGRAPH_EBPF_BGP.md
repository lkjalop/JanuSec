# JanuSec Platform - HopGraph, eBPF & BGP Roadmap (Part 2 of 3)

**Status**: Architecture & Security Enhancements | **Last Updated**: 2025-10-28
**Purpose**: 3rd HopGraph analysis, eBPF container security, BGP attack detection

---

## 📋 Table of Contents

1. [3rd HopGraph Analysis](#3rd-hopgraph-analysis)
2. [eBPF Container Security](#ebpf-container-security)
3. [BGP Attack Detection & Enrichment](#bgp-attack-detection--enrichment)

---

## 🔀 3rd HopGraph Analysis: Do We Need It?

### **Current State: 2 HopGraphs**

#### HopGraph #1: Event HopGraph (Attack Path Reconstruction)
**File**: `src/core/graph/hopgraph_lite.py` (400+ lines)
**Purpose**: Reconstruct multi-hop attack chains from correlated events
**Nodes**: `host:`, `process:`, `file:`, `ip:`, `user:`
**Edges**: Temporal relationships with decay scoring
**Use Case**: "How did this malware spread from host A to host B?"

**Example Chain**:
```
host:workstation-1
  → process:powershell.exe
  → network:192.168.1.50
  → host:dc-01
  → process:mimikatz.exe
```

#### HopGraph #2: Artifact HopGraph (Prevalence Tracking)
**File**: `src/artifact/hopgraph_lite.py` (135 lines)
**Purpose**: Track artifact prevalence across fleet
**Nodes**: `hash:`, `domain:`, `ip:`, `file_path:`
**Edges**: Co-occurrence relationships
**Use Case**: "Is this hash seen on 1 host or 1000 hosts?"

**Example Chain**:
```
hash:deadbeef
  → host:web-01 (first_seen: 2025-01-10)
  → host:web-02 (first_seen: 2025-01-11)
  → host:web-03 (first_seen: 2025-01-11)
Verdict: Rapidly spreading (3 hosts in 24h)
```

---

### **Option 1: Identity/User HopGraph** 🟢 **RECOMMENDED**

#### **Purpose**: Track lateral movement and privilege escalation via user/identity pivots

**Rationale**:
- Current Event HopGraph shows *host* and *process* chains
- Missing: How attackers pivot across identities (user accounts, service principals, tokens)
- MITRE ATT&CK: T1078 (Valid Accounts), T1550 (Use Alternate Authentication Material)

**Nodes**:
- `user:alice@corp.com` - User account
- `serviceaccount:k8s-api@cluster.local` - Service account
- `token:eyJhbG...` - OAuth/JWT token (hashed)
- `cert:sha256:abc123` - Client certificate
- `session:rdp-session-12345` - Login session

**Edges**:
- `user:alice` → `user:domain_admin` (privilege escalation)
- `user:alice` → `host:dc-01` (lateral movement)
- `serviceaccount:k8s` → `cloud_resource:s3-bucket` (cloud access)
- `token:jwt-a` → `token:jwt-b` (token refresh/lateral movement)

**Example Attack Chain**:
```
user:alice@corp.com (phished)
  → token:oauth-token-1 (initial access)
  → user:service-admin (privilege escalation via password spray)
  → host:dc-01 (lateral movement)
  → user:DOMAIN\Administrator (Kerberos ticket forged)
  → cloud_principal:azure-admin (cloud pivot)
  → cloud_resource:key-vault (exfiltration)
```

**Scoring Factors**:
1. **Privilege delta**: Normal user → Admin = high risk
2. **Lateral movement speed**: 5 hosts in 10 minutes = beaconing
3. **Cross-boundary pivots**: On-prem → Cloud = elevated risk
4. **Token age anomaly**: Token refreshed 50 times in 1 hour = suspicious

**Implementation**:
```python
# NEW FILE: src/core/graph/identity_hopgraph.py
class IdentityHopGraph:
    """Track identity-based attack paths and privilege escalation."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.identity_cache = {}  # user -> {roles, last_login, risk_score}

    def add_identity_event(self, event: dict):
        """Process authentication/authorization event."""
        user = event.get('user')
        target = event.get('target')  # host, resource, or another user
        action = event.get('action')  # login, su, runas, assume_role

        # Track privilege changes
        if action in ['su', 'runas', 'assume_role']:
            self._track_privilege_escalation(user, target, event)

        # Track lateral movement
        if action == 'login' and event.get('source_host') != event.get('dest_host'):
            self._track_lateral_movement(user, event)

        # Track cloud pivots
        if event.get('cloud_resource'):
            self._track_cloud_pivot(user, event)

    def get_identity_risk_chain(self, user: str) -> List[dict]:
        """Return attack chain for a user with risk scores."""
        # Find all paths from initial user to high-value targets
        paths = []
        for target in self._get_high_value_targets():
            if nx.has_path(self.graph, f"user:{user}", target):
                path = nx.shortest_path(self.graph, f"user:{user}", target)
                risk = self._score_identity_path(path)
                paths.append({'path': path, 'risk': risk})
        return sorted(paths, key=lambda x: x['risk'], reverse=True)
```

**Integration Points**:
- **Event Pipeline Stage**: New stage after Stage 10 (Correlation)
- **Data Sources**: Windows Event Logs (4624, 4672), AWS CloudTrail, Azure AD logs, Kubernetes audit logs
- **Factor Emissions**: `identity:priv_escalation`, `identity:lateral_movement`, `identity:cloud_pivot`
- **UI**: New "Identity Graph" tab in frontend

**Pros**:
- ✅ Fills critical gap in attack reconstruction
- ✅ Directly maps to MITRE ATT&CK techniques (15+ techniques)
- ✅ High value for SOC analysts (common attack vector)
- ✅ Unique differentiator vs competitors (Wiz/CrowdStrike focus on hosts, not identities)

**Cons**:
- ❌ Requires parsing auth logs (Windows, Linux, cloud)
- ❌ High cardinality (many users/tokens)
- ❌ Privacy concerns (track user behavior)

**Estimated Effort**: 2-3 weeks (1 engineer)
**Demo Impact**: High - can show APT-style lateral movement

**Verdict**: **YES - Build this for production launch**

---

### **Option 2: Network Flow HopGraph** 🟡 **MAYBE LATER**

#### **Purpose**: Track network traffic patterns and lateral movement via network topology

**Rationale**:
- Current Event HopGraph shows IP connections but not full network topology
- Useful for: Network segmentation analysis, lateral movement via network, data exfiltration paths

**Nodes**:
- `subnet:10.0.1.0/24` - Network subnet
- `vlan:100` - VLAN segment
- `firewall:checkpoint-01` - Network device
- `route:0.0.0.0/0 via 10.0.0.1` - Routing table entry
- `ip:10.0.1.50` - Individual IP (already exists in Event HopGraph)

**Edges**:
- `ip:10.0.1.50` → `subnet:10.0.1.0/24` (membership)
- `subnet:10.0.1.0/24` → `subnet:192.168.1.0/24` (routing)
- `firewall:fw-01` → `subnet:10.0.2.0/24` (policy allows)

**Example Attack Chain**:
```
ip:attacker-external (internet)
  → firewall:edge-fw (allowed via port 443)
  → subnet:dmz (web server compromised)
  → firewall:internal-fw (lateral movement blocked? NO - misconfigured rule)
  → subnet:internal-prod (database server)
  → route:0.0.0.0/0 (exfiltration to C2)
```

**Scoring Factors**:
1. **Segmentation violations**: DMZ → Internal = high risk
2. **Unusual routing**: Direct route bypassing firewall = suspicious
3. **Volume anomaly**: 10GB exfiltrated from internal subnet = critical

**Pros**:
- ✅ Visualizes network segmentation effectiveness
- ✅ Identifies misconfigurations (firewall rules)
- ✅ Useful for compliance (PCI-DSS network segmentation)

**Cons**:
- ❌ Overlaps with existing Event HopGraph (already tracks IP connections)
- ❌ Requires network topology discovery (SNMP, NetFlow, sFlow)
- ❌ Lower priority for most SOC analysts (compared to host/identity pivots)

**Estimated Effort**: 3-4 weeks (1 engineer)
**Demo Impact**: Medium - niche use case

**Verdict**: **DEFER - Build after Identity HopGraph if there's demand**

---

### **Option 3: Cloud Resource HopGraph** 🟢 **RECOMMENDED (Phase 2)**

#### **Purpose**: Track attack paths through cloud infrastructure (CSPM integration)

**Rationale**:
- JanuSec already has CSPM support (AWS, Azure, GCP, OCI)
- Missing: How attackers pivot across cloud resources (S3 → Lambda → RDS → exfiltration)
- Critical for cloud-native attacks (MITRE ATT&CK Cloud Matrix)

**Nodes**:
- `cloud_resource:s3://my-bucket` - S3 bucket, Azure Blob, GCS bucket
- `cloud_resource:lambda:my-function` - Serverless function
- `cloud_resource:rds:my-db` - Database
- `cloud_resource:iam:role/admin` - IAM role/policy
- `cloud_resource:vm:i-1234567` - EC2 instance, Azure VM

**Edges**:
- `iam:role/app` → `s3://sensitive-data` (permission allows)
- `lambda:process-data` → `rds:prod-db` (function accesses DB)
- `s3://public-bucket` → `internet:*` (public exposure)
- `vm:i-1234567` → `iam:role/admin` (instance profile with admin)

**Example Attack Chain**:
```
s3://public-backup-bucket (misconfigured public access)
  → iam_creds:access-key-abc123 (leaked in backup file)
  → iam:role/developer (assumed role)
  → lambda:data-processor (invoked with stolen creds)
  → rds:customer-db (function accesses)
  → s3://exfil-bucket (data copied to attacker bucket)
```

**Scoring Factors**:
1. **Public exposure**: Internet → S3 = critical
2. **Privilege escalation**: Developer role → Admin role = high risk
3. **Data access**: Function accessing PII database = elevated
4. **Exfiltration**: Data copied to external account = critical

**Implementation**:
```python
# NEW FILE: src/core/graph/cloud_hopgraph.py
class CloudHopGraph:
    """Track attack paths through cloud infrastructure."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.cloud_resources = {}  # resource_arn -> metadata

    def ingest_cloud_config(self, cloud_provider: str, resources: List[dict]):
        """Ingest cloud resource topology from CSPM."""
        for resource in resources:
            self._add_resource_node(resource)
            self._add_iam_edges(resource)  # Who can access this?
            self._add_network_edges(resource)  # What can this access?

    def find_attack_paths(self, entry_point: str, target: str) -> List[dict]:
        """Find all paths from entry (e.g., public S3) to target (e.g., database)."""
        paths = nx.all_simple_paths(self.graph, entry_point, target, cutoff=10)
        scored_paths = []
        for path in paths:
            risk = self._score_cloud_path(path)
            scored_paths.append({'path': path, 'risk': risk, 'steps': len(path)})
        return sorted(scored_paths, key=lambda x: x['risk'], reverse=True)
```

**Integration Points**:
- **Data Sources**: AWS Config, Azure Resource Graph, GCP Asset Inventory
- **Existing Integration**: Use scripts in `scripts/aws_config_to_posture.py`, `scripts/azure_defender_to_posture.py`
- **Factor Emissions**: `cloud:public_exposure`, `cloud:priv_escalation`, `cloud:data_access`
- **UI**: New "Cloud Graph" tab showing cloud resource attack paths

**Pros**:
- ✅ Critical for cloud security (fastest growing segment)
- ✅ Unique differentiator (competitors have CSPM but not graph-based attack path analysis)
- ✅ High value for security teams moving to cloud
- ✅ Leverages existing CSPM work

**Cons**:
- ❌ Requires cloud API polling (costs, rate limits)
- ❌ Complex IAM policy parsing (AWS policies can be 10KB JSON)
- ❌ High cardinality (thousands of resources per account)

**Estimated Effort**: 4-5 weeks (1 engineer)
**Demo Impact**: Very High - shows attack path from public S3 to RDS

**Verdict**: **YES - Build this as Phase 2 after Identity HopGraph**

---

### **Recommendation Summary**

| HopGraph | Priority | Effort | Impact | Build When |
|----------|----------|--------|--------|------------|
| **Identity/User** | 🟢 High | 2-3 weeks | Very High | **Now (pre-launch)** |
| **Cloud Resource** | 🟢 High | 4-5 weeks | Very High | Phase 2 (post-launch) |
| **Network Flow** | 🟡 Low | 3-4 weeks | Medium | Phase 3 (if demanded) |

**Recommended Build Order**:
1. **Identity HopGraph** (now) - Fills critical gap, high SOC value
2. **Cloud HopGraph** (3 months post-launch) - Cloud security is growing fast
3. **Network Flow HopGraph** (6-12 months) - Only if customers request it

**Architecture**: Keep all 3-5 HopGraphs separate (different files, different graph instances) to avoid complexity

---

## 🛡️ eBPF Container Security

### **Current Gap: Container Runtime Security**

**Problem**: JanuSec monitors hosts and networks but lacks **kernel-level visibility** into container runtime behavior.

**Competitive Gap**:
- **Wiz**: 92% container security (eBPF-based runtime monitoring)
- **CrowdStrike Falcon**: Kernel-level detection (Windows driver, Linux eBPF)
- **JanuSec**: 75% container security (missing runtime monitoring)

**What eBPF Provides**:
- Syscall monitoring (file access, network, process execution) without kernel modules
- Container escape detection (mount namespace violations, capability abuse)
- Zero-day detection (behavioral anomalies in syscall patterns)
- Low overhead (<5% CPU vs 20%+ for userspace agents)

---

### **Solution: Integrate eBPF for Container Runtime Security**

#### **Option A: Use Falco (Open Source eBPF Engine)** 🟢 **RECOMMENDED**

**Falco**: CNCF-graduated eBPF-based runtime security for Kubernetes/Docker
**GitHub**: https://github.com/falcosecurity/falco (6.5K stars)

**Why Falco**:
- ✅ Production-ready, battle-tested (used by AWS, Google, IBM)
- ✅ 100+ pre-built detection rules for containers
- ✅ Low overhead (2-5% CPU)
- ✅ Kubernetes-native (DaemonSet deployment)
- ✅ JSON output (easy integration)

**How It Works**:
1. Falco runs as DaemonSet on every Kubernetes node
2. eBPF probes intercept syscalls from all containers
3. Falco rules match suspicious patterns (e.g., `write /etc/shadow`, `exec /bin/bash in container`)
4. Events sent to JanuSec via webhook or file export

**Example Falco Rule**:
```yaml
# Detect shell spawned in container
- rule: Terminal shell in container
  desc: A shell was spawned in a container (potential interactive access by attacker)
  condition: >
    spawned_process and container and
    shell_procs and proc.tty != 0
  output: >
    Shell spawned in container (user=%user.name container_id=%container.id
    image=%container.image.repository:%container.image.tag command=%proc.cmdline)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

**Integration Architecture**:
```
┌──────────────────────────────────────────────┐
│  Kubernetes Cluster                          │
│  ┌────────────┐  ┌────────────┐             │
│  │  Node 1    │  │  Node 2    │             │
│  │  ┌──────┐  │  │  ┌──────┐  │             │
│  │  │Falco │  │  │  │Falco │  │  (DaemonSet)│
│  │  │ eBPF │  │  │  │ eBPF │  │             │
│  │  └───┬──┘  │  │  └───┬──┘  │             │
│  └──────┼─────┘  └──────┼─────┘             │
│         │                │                   │
│         │  Webhook       │                   │
│         └────────┬───────┘                   │
└──────────────────┼───────────────────────────┘
                   │
                   ▼
         ┌─────────────────────┐
         │  JanuSec Platform   │
         │  /api/v1/events/    │
         │  ebpf_ingest        │
         └─────────────────────┘
                   │
                   ▼
         ┌─────────────────────┐
         │  Event Pipeline     │
         │  (21 stages)        │
         │                     │
         │  NEW: Stage 22      │
         │  eBPF Container     │
         │  Analysis           │
         └─────────────────────┘
```

**Implementation Steps**:

**Step 1: Deploy Falco on Kubernetes**
```bash
# Add Falco Helm repo
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Deploy Falco with webhook output
helm install falco falcosecurity/falco \
  --set falco.jsonOutput=true \
  --set falco.httpOutput.enabled=true \
  --set falco.httpOutput.url=https://janusec-api.example.com/api/v1/events/ebpf_ingest
```

**Step 2: Add eBPF Ingestion Endpoint**
```python
# NEW FILE: src/api/ebpf_endpoints.py
from fastapi import APIRouter, Request
from src.core.event_pipeline.pipeline import EventPipeline

router = APIRouter(prefix="/api/v1/events", tags=["eBPF"])

@router.post("/ebpf_ingest")
async def ingest_ebpf_event(request: Request):
    """
    Ingest eBPF events from Falco webhook.

    Example Falco event:
    {
      "output": "Shell spawned in container",
      "priority": "Warning",
      "rule": "Terminal shell in container",
      "time": "2025-10-28T10:30:45.123456Z",
      "output_fields": {
        "container.id": "abc123",
        "container.image.repository": "nginx",
        "proc.cmdline": "/bin/bash",
        "user.name": "www-data"
      }
    }
    """
    falco_event = await request.json()

    # Normalize to JanuSec event schema
    normalized = {
        'event_type': 'container_runtime',
        'source': 'falco_ebpf',
        'timestamp': falco_event['time'],
        'severity': _map_falco_priority(falco_event['priority']),
        'rule_name': falco_event['rule'],
        'raw_output': falco_event['output'],
        'container_id': falco_event['output_fields'].get('container.id'),
        'image': falco_event['output_fields'].get('container.image.repository'),
        'command': falco_event['output_fields'].get('proc.cmdline'),
        'user': falco_event['output_fields'].get('user.name'),
        'technique': _map_falco_rule_to_mitre(falco_event['rule'])
    }

    # Send to event pipeline
    pipeline = EventPipeline()
    result = await pipeline.process_event(normalized)

    return {"status": "ok", "event_id": result['event_id']}

def _map_falco_priority(priority: str) -> str:
    """Map Falco priority to JanuSec severity."""
    mapping = {
        'Emergency': 'critical',
        'Alert': 'critical',
        'Critical': 'critical',
        'Error': 'high',
        'Warning': 'medium',
        'Notice': 'low',
        'Informational': 'info',
        'Debug': 'info'
    }
    return mapping.get(priority, 'medium')

def _map_falco_rule_to_mitre(rule_name: str) -> List[str]:
    """Map Falco rule to MITRE ATT&CK techniques."""
    # Falco tags include MITRE techniques
    # Example: "mitre_execution" -> T1059 (Command and Scripting Interpreter)
    rule_mitre_map = {
        'Terminal shell in container': ['T1059'],
        'Write below etc': ['T1222'],  # File Permissions Modification
        'Container Drift Detected': ['T1610'],  # Deploy Container
        'Read sensitive file untrusted': ['T1555'],  # Credentials from Password Stores
        # ... 100+ mappings
    }
    return rule_mitre_map.get(rule_name, [])
```

**Step 3: Add eBPF Analysis Stage to Pipeline**
```python
# NEW FILE: src/core/event_pipeline/stages/ebpf_analysis.py
from typing import Dict, Any, List
from src.core.event_pipeline.stages.base import Stage

class EbpfAnalysisStage(Stage):
    """
    Stage 22: eBPF Container Runtime Analysis

    Detects:
    - Container escape attempts
    - Privilege escalation in containers
    - Suspicious syscall patterns
    - Malicious file access in containers
    """

    def __init__(self):
        super().__init__("ebpf_analysis")
        self.container_baselines = {}  # container_id -> baseline syscalls

    async def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if event.get('source') != 'falco_ebpf':
            return event  # Skip non-eBPF events

        factors = []

        # Detect container escape
        if self._is_container_escape(event):
            factors.append({
                'name': 'ebpf:container_escape',
                'weight': 0.95,
                'reason': 'Syscall pattern indicates container escape attempt'
            })

        # Detect privilege escalation
        if self._is_privilege_escalation(event):
            factors.append({
                'name': 'ebpf:priv_escalation',
                'weight': 0.85,
                'reason': f"User {event['user']} executed privileged operation"
            })

        # Detect unusual syscall pattern
        if self._is_unusual_syscall_pattern(event):
            factors.append({
                'name': 'ebpf:syscall_anomaly',
                'weight': 0.70,
                'reason': 'Syscall pattern deviates from container baseline'
            })

        event['factors'] = event.get('factors', []) + factors
        return event

    def _is_container_escape(self, event: Dict[str, Any]) -> bool:
        """Detect container escape attempts."""
        # Common escape techniques:
        # 1. Mount host filesystem
        # 2. Access /proc/*/root (host filesystem via symlink)
        # 3. Abuse CAP_SYS_ADMIN capability
        command = event.get('command', '').lower()

        escape_patterns = [
            'mount',
            '/proc/*/root',
            'unshare',
            'nsenter',
            'cap_sys_admin'
        ]

        return any(pattern in command for pattern in escape_patterns)

    def _is_privilege_escalation(self, event: Dict[str, Any]) -> bool:
        """Detect privilege escalation in container."""
        # Running as root in container is common, but certain operations are suspicious:
        # - Creating new users
        # - Modifying /etc/passwd, /etc/shadow
        # - Installing backdoors (systemd services, cron jobs)

        command = event.get('command', '').lower()
        suspicious_ops = [
            'useradd', 'adduser',
            '/etc/passwd', '/etc/shadow',
            'systemctl', 'crontab',
            'ssh-keygen', 'authorized_keys'
        ]

        return any(op in command for op in suspicious_ops)

    def _is_unusual_syscall_pattern(self, event: Dict[str, Any]) -> bool:
        """Detect syscall pattern anomaly using baseline."""
        container_id = event.get('container_id')
        if not container_id:
            return False

        # Baseline: what syscalls does this container normally make?
        baseline = self.container_baselines.get(container_id, set())

        # Extract syscalls from event (Falco provides this in output_fields)
        current_syscall = event.get('syscall')

        if not baseline:
            # First event for this container - establish baseline
            self.container_baselines[container_id] = {current_syscall}
            return False

        # Check if current syscall is in baseline
        if current_syscall not in baseline:
            # New syscall - potentially suspicious
            # Add to baseline (adaptive learning)
            self.container_baselines[container_id].add(current_syscall)
            return True

        return False
```

**Step 4: Add eBPF Correlation Rules**
```python
# NEW FILE: src/core/correlation/rules/ebpf/container_escape.py
from src.core.correlation.rules.registry import register_rule

@register_rule(
    id="ebpf-001",
    name="Container Escape with Network Egress",
    description="Container escape followed by network connection to external IP",
    severity="critical",
    mitre=["T1610", "T1041"]
)
def container_escape_with_egress(factors: List[str], context: dict) -> bool:
    """
    Detects:
    1. ebpf:container_escape (container escape attempt)
    2. network:egress_external (connection to external IP)
    Within 5 minutes
    """
    has_escape = 'ebpf:container_escape' in factors
    has_egress = 'network:egress_external' in factors

    if has_escape and has_egress:
        # Check time delta
        escape_time = context.get('ebpf:container_escape_ts', 0)
        egress_time = context.get('network:egress_external_ts', 0)

        if abs(escape_time - egress_time) < 300:  # 5 minutes
            return True

    return False
```

**Step 5: Update Frontend to Show eBPF Events**
```html
<!-- frontend/static/index.html - Add eBPF section -->
<div class="section">
  <h3>Container Runtime Events (eBPF)</h3>
  <table id="ebpf-events">
    <thead>
      <tr>
        <th>Time</th>
        <th>Container</th>
        <th>Image</th>
        <th>Rule</th>
        <th>Command</th>
        <th>Severity</th>
      </tr>
    </thead>
    <tbody id="ebpf-events-body">
      <!-- Populated via API -->
    </tbody>
  </table>
</div>

<script>
async function loadEbpfEvents() {
  const response = await fetch('/api/v1/events?source=falco_ebpf&limit=100', {
    headers: authHeaders()
  });
  const events = await response.json();

  const tbody = document.getElementById('ebpf-events-body');
  tbody.innerHTML = events.map(e => `
    <tr class="severity-${e.severity}">
      <td>${new Date(e.timestamp).toLocaleString()}</td>
      <td>${e.container_id.substring(0, 12)}</td>
      <td>${e.image}</td>
      <td>${e.rule_name}</td>
      <td><code>${e.command}</code></td>
      <td>${e.severity}</td>
    </tr>
  `).join('');
}
</script>
```

---

### **Detecting eBPF Usage (Meta-Detection)**

**Question**: How do we detect if an *attacker* is using eBPF for rootkits/evasion?

**Threat**: eBPF rootkits can hide processes, files, network connections from userspace tools
**Example**: https://github.com/pathtofile/bpf-hookdetect

**Detection Strategy**:

#### 1. Monitor BPF Syscalls
```python
# In Falco rules:
- rule: BPF Program Loaded
  desc: Detect loading of eBPF programs (potential rootkit)
  condition: >
    syscall.type = bpf and
    bpf.cmd = BPF_PROG_LOAD and
    not container.image.repository in (falco, cilium, calico)
  output: >
    eBPF program loaded (user=%user.name command=%proc.cmdline)
  priority: WARNING
```

#### 2. Check for Hidden Kernel Modules
```bash
# Script to detect eBPF rootkits
bpftool prog list  # List all loaded eBPF programs
bpftool map list   # List all eBPF maps

# Compare against known-good baseline
# Flag any unknown programs
```

#### 3. Integrity Checks
```python
# Periodically verify system state
def detect_ebpf_hiding():
    """Detect if eBPF is hiding processes/files."""
    # Method 1: Compare /proc vs syscall results
    proc_pids = set(os.listdir('/proc'))
    syscall_pids = set(get_pids_via_syscall())  # Direct syscall, bypasses eBPF

    hidden = syscall_pids - proc_pids
    if hidden:
        alert(f"eBPF rootkit suspected: {len(hidden)} hidden processes")

    # Method 2: Check for BPF programs attached to kprobes/tracepoints
    bpf_progs = subprocess.check_output(['bpftool', 'prog', 'list']).decode()
    if 'kprobe' in bpf_progs or 'kretprobe' in bpf_progs:
        alert("eBPF kprobe detected - potential rootkit")
```

---

### **Summary: eBPF Integration**

**Recommendation**: **Use Falco** for container runtime security
- ✅ Quick integration (1-2 weeks)
- ✅ Production-ready
- ✅ Closes gap vs Wiz/CrowdStrike

**Estimated Impact**:
- Container security score: 75% → 92% (matches Wiz)
- New detections: +15 container-specific rules
- False positive rate: Low (Falco is well-tuned)

**Files to Create**:
- `src/api/ebpf_endpoints.py` (150 lines)
- `src/core/event_pipeline/stages/ebpf_analysis.py` (200 lines)
- `src/core/correlation/rules/ebpf/container_escape.py` (100 lines)
- `charts/janusec/templates/falco.yaml` (Helm chart for Falco)

**Total Effort**: 2 weeks (1 engineer)

---

## 🌐 BGP Attack Detection & Enrichment

### **Current State**

**File**: `src/integrations/bgp_client.py` (150 lines)
**Status**: Basic BGP incidents client (hijacks/leaks) with caching
**Limitation**: Only stores CIDR prefixes, no active detection or enrichment

### **Enhancement Plan**

#### **Phase 1: BGP Enrichment for Network Events**

**Goal**: Enrich network events with BGP hijack/leak status

**Implementation**:
```python
# Update: src/core/event_pipeline/stages/network.py
from src.integrations.bgp_client import BgpClient

class NetworkEnrichmentStage(Stage):
    """Stage 5: Network Enrichment - Add BGP, ASN, GeoIP."""

    def __init__(self):
        super().__init__("network_enrichment")
        self.bgp_client = BgpClient()
        self.asn_db = MaxmindASNDB()

    async def process(self, event: Dict[str, Any]) -> Dict[str, Any]:
        dest_ip = event.get('dest_ip')
        if not dest_ip:
            return event

        # Existing enrichment
        event['geo'] = self._get_geoip(dest_ip)
        event['asn'] = self.asn_db.lookup(dest_ip)

        # NEW: BGP hijack/leak detection
        bgp_status = await self.bgp_client.check_ip(dest_ip)
        if bgp_status['is_hijacked']:
            event['factors'].append({
                'name': 'network:bgp_hijack_dest',
                'weight': 0.90,
                'reason': f"Destination IP {dest_ip} is in hijacked prefix {bgp_status['prefix']}"
            })

        if bgp_status['is_leaked']:
            event['factors'].append({
                'name': 'network:bgp_leak_dest',
                'weight': 0.75,
                'reason': f"Destination IP {dest_ip} is in leaked prefix (AS path anomaly)"
            })

        event['bgp'] = bgp_status
        return event
```

**Update BGP Client**:
```python
# Update: src/integrations/bgp_client.py
class BgpClient:
    """BGP incidents client with real-time detection."""

    def __init__(self):
        self.feed_url = os.getenv('BGP_FEED_URL', 'https://bgpstream.com/api/v1/incidents')
        self.hijacked_prefixes = set()
        self.leaked_prefixes = set()
        self._load_incidents()

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check if IP is in a hijacked or leaked prefix."""
        ip_obj = ipaddress.ip_address(ip)

        result = {
            'is_hijacked': False,
            'is_leaked': False,
            'prefix': None,
            'asn': None
        }

        # Check hijacked prefixes
        for prefix_str in self.hijacked_prefixes:
            prefix = ipaddress.ip_network(prefix_str)
            if ip_obj in prefix:
                result['is_hijacked'] = True
                result['prefix'] = prefix_str
                result['asn'] = self._get_asn_for_prefix(prefix_str)
                break

        # Check leaked prefixes
        if not result['is_hijacked']:
            for prefix_str in self.leaked_prefixes:
                prefix = ipaddress.ip_network(prefix_str)
                if ip_obj in prefix:
                    result['is_leaked'] = True
                    result['prefix'] = prefix_str
                    break

        return result

    async def refresh_incidents(self):
        """Fetch latest BGP incidents from BGPStream or similar service."""
        if not self.feed_url or not httpx:
            return  # Offline mode

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(self.feed_url)
                data = response.json()

                # Parse incidents
                self.hijacked_prefixes = set()
                self.leaked_prefixes = set()

                for incident in data.get('incidents', []):
                    if incident['type'] == 'hijack':
                        self.hijacked_prefixes.add(incident['prefix'])
                    elif incident['type'] == 'leak':
                        self.leaked_prefixes.add(incident['prefix'])

                self._save()  # Persist to disk
        except Exception as e:
            logging.error(f"Failed to refresh BGP incidents: {e}")
```

---

#### **Phase 2: BGP Attack Detection Rules**

**Add Correlation Rules**:
```python
# NEW FILE: src/core/correlation/rules/network/bgp_attacks.py
from src.core.correlation.rules.registry import register_rule

@register_rule(
    id="bgp-001",
    name="Traffic to BGP Hijacked Prefix",
    description="Network connection to IP in BGP hijacked prefix",
    severity="critical",
    mitre=["T1557"]  # Man-in-the-Middle
)
def traffic_to_hijacked_prefix(factors: List[str], context: dict) -> bool:
    """Detect traffic to BGP hijacked IP."""
    return 'network:bgp_hijack_dest' in factors

@register_rule(
    id="bgp-002",
    name="Large Data Transfer to Hijacked Prefix",
    description="Exfiltration to BGP hijacked IP (potential MitM attack)",
    severity="critical",
    mitre=["T1557", "T1041"]
)
def exfil_to_hijacked(factors: List[str], context: dict) -> bool:
    """Detect large upload to hijacked IP."""
    has_hijack = 'network:bgp_hijack_dest' in factors
    has_large_upload = 'network:large_upload' in factors
    return has_hijack and has_large_upload

@register_rule(
    id="bgp-003",
    name="BGP Leak Route Manipulation",
    description="Traffic routed via BGP leak (potential interception)",
    severity="high",
    mitre=["T1557"]
)
def traffic_via_bgp_leak(factors: List[str], context: dict) -> bool:
    """Detect traffic via leaked BGP route."""
    return 'network:bgp_leak_dest' in factors
```

---

#### **Phase 3: BGP Monitoring Dashboard**

**Frontend UI**:
```html
<!-- NEW FILE: frontend/static/bgp.html -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>BGP Monitoring</title>
  <style>
    body { font-family: Arial; background: #0e1117; color: #e6e6e6; padding: 1rem; }
    .incident { background: #1a1f2e; padding: 1rem; margin: 0.5rem 0; border-left: 4px solid #e74c3c; }
    .incident.leak { border-color: #f39c12; }
    .stat { display: inline-block; margin: 1rem; }
    .stat-value { font-size: 2rem; font-weight: bold; }
  </style>
</head>
<body>
  <h2>BGP Incident Monitoring</h2>

  <div class="stats">
    <div class="stat">
      <div class="stat-value" id="hijack-count">0</div>
      <div>Hijacked Prefixes</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="leak-count">0</div>
      <div>Leaked Prefixes</div>
    </div>
    <div class="stat">
      <div class="stat-value" id="affected-ips">0</div>
      <div>Affected IPs (Last 24h)</div>
    </div>
  </div>

  <h3>Active Incidents</h3>
  <div id="incidents"></div>

  <script>
    async function loadBgpIncidents() {
      const response = await fetch('/api/v1/network/bgp/incidents', {
        headers: {'x-api-key': localStorage.getItem('apiKey') || 'devkey123'}
      });
      const data = await response.json();

      // Update stats
      document.getElementById('hijack-count').textContent = data.hijacked_prefixes.length;
      document.getElementById('leak-count').textContent = data.leaked_prefixes.length;
      document.getElementById('affected-ips').textContent = data.affected_ips_24h || 0;

      // Render incidents
      const incidentsDiv = document.getElementById('incidents');
      incidentsDiv.innerHTML = data.incidents.map(inc => `
        <div class="incident ${inc.type}">
          <strong>${inc.type.toUpperCase()}: ${inc.prefix}</strong><br>
          ASN: ${inc.asn} | Detected: ${new Date(inc.detected_at).toLocaleString()}<br>
          <em>${inc.description}</em>
        </div>
      `).join('');
    }

    loadBgpIncidents();
    setInterval(loadBgpIncidents, 60000);  // Refresh every minute
  </script>
</body>
</html>
```

**Backend API**:
```python
# NEW FILE: src/api/bgp_endpoints.py
from fastapi import APIRouter
from src.integrations.bgp_client import BgpClient

router = APIRouter(prefix="/api/v1/network/bgp", tags=["BGP"])

@router.get("/incidents")
async def get_bgp_incidents():
    """Get current BGP hijack/leak incidents."""
    client = BgpClient()

    incidents = []
    for prefix in client.hijacked_prefixes:
        incidents.append({
            'type': 'hijack',
            'prefix': prefix,
            'asn': client._get_asn_for_prefix(prefix),
            'detected_at': client._get_detection_time(prefix),
            'description': f'Prefix {prefix} is being announced by unauthorized ASN'
        })

    for prefix in client.leaked_prefixes:
        incidents.append({
            'type': 'leak',
            'prefix': prefix,
            'detected_at': client._get_detection_time(prefix),
            'description': f'Prefix {prefix} is being leaked via AS path manipulation'
        })

    # Count affected IPs in last 24h
    affected_ips = await _count_affected_ips_24h(client)

    return {
        'hijacked_prefixes': list(client.hijacked_prefixes),
        'leaked_prefixes': list(client.leaked_prefixes),
        'incidents': incidents,
        'affected_ips_24h': affected_ips,
        'last_updated': client._last
    }
```

---

### **Summary: BGP Enhancement**

**Current**: Basic BGP client with offline prefix caching
**Enhanced**: Real-time enrichment + detection + dashboard

**New Capabilities**:
- ✅ Enrich network events with BGP hijack/leak status
- ✅ Correlation rules for BGP-based attacks
- ✅ BGP monitoring dashboard
- ✅ Real-time feed from BGPStream or similar

**Estimated Effort**: 1 week (1 engineer)

**Files to Update**:
- `src/integrations/bgp_client.py` (+100 lines)
- `src/core/event_pipeline/stages/network.py` (+30 lines)
- `src/core/correlation/rules/network/bgp_attacks.py` (NEW, 100 lines)
- `src/api/bgp_endpoints.py` (NEW, 100 lines)
- `frontend/static/bgp.html` (NEW, 150 lines)

---

## 🎯 Summary: Part 2 Recommendations

| Enhancement | Priority | Effort | Impact | Build When |
|-------------|----------|--------|--------|------------|
| **Identity HopGraph** | 🟢 Critical | 2-3 weeks | Very High | **Now** |
| **eBPF (Falco)** | 🟢 High | 2 weeks | High | **Now** |
| **BGP Enrichment** | 🟡 Medium | 1 week | Medium | Post-launch |
| **Cloud HopGraph** | 🟢 High | 4-5 weeks | Very High | 3 months post-launch |
| **Network Flow HopGraph** | 🔴 Low | 3-4 weeks | Low | Only if demanded |

**Total Pre-Launch Effort**: 4-5 weeks for Identity HopGraph + eBPF
**Post-Launch**: BGP (1 week), Cloud HopGraph (4-5 weeks)

**Next**: See Part 3 for Visual Polish and Data Preparation
