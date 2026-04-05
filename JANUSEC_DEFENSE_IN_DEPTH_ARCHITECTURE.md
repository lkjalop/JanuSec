# JanuSec Defense-in-Depth Architecture Guide
## Comprehensive Deployment Scenarios & Design Patterns

**Document Version:** 1.0
**Last Updated:** December 21, 2025
**Audience:** Security Architects, Infrastructure Engineers, CISOs

---

## TABLE OF CONTENTS

1. [Executive Summary](#executive-summary)
2. [Defense-in-Depth Principles](#defense-in-depth-principles)
3. [Deployment Scenarios](#deployment-scenarios)
   - [Scenario 1: JanuSec in Front of CDN](#scenario-1-janusec-in-front-of-cdn)
   - [Scenario 2: Between CDN and Firewall](#scenario-2-between-cdn-and-firewall)
   - [Scenario 3: Behind Firewall (Traditional)](#scenario-3-behind-firewall-traditional)
   - [Scenario 4: Parallel to SIEM (Tee/Mirror)](#scenario-4-parallel-to-siem-teemirror)
   - [Scenario 5: Hybrid Multi-Tier](#scenario-5-hybrid-multi-tier)
4. [Minimum Deployment Requirements](#minimum-deployment-requirements)
5. [Data Connector Strategy](#data-connector-strategy)
6. [Data Storage Architecture](#data-storage-architecture)
7. [Federated Learning Considerations](#federated-learning-considerations)
8. [Architectural Decision Framework](#architectural-decision-framework)
9. [Reference Architectures](#reference-architectures)

---

## EXECUTIVE SUMMARY

**JanuSec is NOT a network appliance** - it's a **threat detection and correlation platform** that ingests security telemetry (logs, events, network flows) from multiple sources to detect multi-domain attacks.

**Key Architectural Decision:**
JanuSec operates **out-of-band** (analysis mode), not **in-line** (blocking mode), so its placement is about **data access** and **latency**, not traffic interception.

**Recommended Architecture:**
- **Primary Deployment:** Behind firewall, ingesting from SIEM, EDR, network sensors, cloud APIs
- **Optional Augmentation:** Tap/mirror network traffic for real-time packet analysis
- **Integration Pattern:** Complement existing SIEM (Splunk, Elastic, Sentinel) as a specialized correlation engine

---

## DEFENSE-IN-DEPTH PRINCIPLES

### Traditional Defense-in-Depth Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Internet / External Threats               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌──────────────────────────────────────┐
        │        Layer 1: Perimeter            │
        │  - CDN (DDoS protection, caching)    │
        │  - WAF (Web Application Firewall)    │
        └──────────────────────────────────────┘
                              │
                              ▼
        ┌──────────────────────────────────────┐
        │        Layer 2: Network              │
        │  - Firewall (stateful inspection)    │
        │  - IDS/IPS (intrusion detection)     │
        │  - Network segmentation (VLANs)      │
        └──────────────────────────────────────┘
                              │
                              ▼
        ┌──────────────────────────────────────┐
        │        Layer 3: Application          │
        │  - Load balancers                    │
        │  - Reverse proxies                   │
        │  - API gateways                      │
        └──────────────────────────────────────┘
                              │
                              ▼
        ┌──────────────────────────────────────┐
        │        Layer 4: Endpoint             │
        │  - EDR (endpoint detection/response) │
        │  - Antivirus                         │
        │  - Host-based firewalls              │
        └──────────────────────────────────────┘
                              │
                              ▼
        ┌──────────────────────────────────────┐
        │        Layer 5: Data                 │
        │  - Encryption at rest                │
        │  - Access controls (IAM)             │
        │  - DLP (data loss prevention)        │
        └──────────────────────────────────────┘
                              │
                              ▼
        ┌──────────────────────────────────────┐
        │  Layer 6: Detection & Response       │
        │  - SIEM (log aggregation)            │
        │  - SOAR (orchestration)              │
        │  - JanuSec (correlation & AI triage) │ ◄─── YOU ARE HERE
        └──────────────────────────────────────┘
```

### Where JanuSec Fits

**JanuSec is a Layer 6 (Detection & Response) platform** that:
- Ingests telemetry from Layers 1-5
- Correlates events across domains
- Detects multi-stage attacks
- Provides AI-powered triage and investigation tools

**It does NOT replace:**
- Firewalls (Layer 2)
- WAF (Layer 1)
- EDR (Layer 4)
- SIEM (Layer 6 - complementary)

**It AUGMENTS:**
- SIEM with advanced correlation and AI analysis
- SOC workflows with attack chain visualization
- Incident response with forensic capabilities

---

## DEPLOYMENT SCENARIOS

### SCENARIO 1: JanuSec in Front of CDN (❌ NOT RECOMMENDED)

**Architecture:**

```
    ┌─────────────┐
    │   Internet  │
    └──────┬──────┘
           │
           ▼
    ┌──────────────────┐
    │    JanuSec       │ ◄── ❌ INCORRECT PLACEMENT
    │  (In-line??)     │
    └──────┬───────────┘
           │
           ▼
    ┌──────────────────┐
    │      CDN         │
    │  (Cloudflare,    │
    │   Akamai, etc.)  │
    └──────┬───────────┘
           │
           ▼
    ┌──────────────────┐
    │    Firewall      │
    └──────┬───────────┘
           │
           ▼
    ┌──────────────────┐
    │  Web Servers     │
    └──────────────────┘
```

#### Analysis

**Why This Doesn't Make Sense:**

1. **JanuSec is not a network appliance** - It cannot operate in-line to inspect/block traffic
2. **CDN should be the first line of defense** - Purpose-built for DDoS mitigation and caching
3. **Latency impact** - Adding JanuSec in-line would add 50-200ms per request (unacceptable)
4. **Scalability** - JanuSec cannot handle 100k+ req/sec like a CDN
5. **Wrong tool for the job** - Use WAF/CDN for perimeter protection

**Verdict:** ❌ **NEVER USE THIS ARCHITECTURE**

---

### SCENARIO 2: Between CDN and Firewall (⚠️ RARELY USEFUL)

**Architecture:**

```
    ┌─────────────┐
    │   Internet  │
    └──────┬──────┘
           │
           ▼
    ┌──────────────────┐
    │      CDN         │
    │  + WAF Rules     │
    └──────┬───────────┘
           │
           ├──────────────────┐
           │                  │
           ▼                  ▼
    ┌──────────────┐   ┌──────────────────┐
    │  Firewall    │   │  JanuSec         │ ◄── Passive Tap/Mirror
    │              │   │  (Out-of-band)   │
    └──────┬───────┘   └──────────────────┘
           │                  │
           │                  │ (Telemetry only)
           ▼                  ▼
    ┌──────────────────┐   ┌──────────────────┐
    │  Web Servers     │   │  SIEM / Storage  │
    └──────────────────┘   └──────────────────┘
```

#### Configuration: Network Tap/Mirror

**How It Works:**
- **SPAN/Mirror port** on switch copies traffic to JanuSec
- JanuSec runs **passive network analysis** (Zeek/Suricata-like functionality)
- Firewall continues normal traffic flow (no latency impact)

#### Pros

| Benefit | Explanation |
|---------|-------------|
| ✅ **Real-time visibility** | See traffic before firewall drops it |
| ✅ **No latency impact** | Out-of-band, doesn't affect production traffic |
| ✅ **Early threat detection** | Detect reconnaissance before it reaches internal network |
| ✅ **CDN bypass detection** | Identify attackers bypassing CDN to hit origin directly |

#### Cons

| Drawback | Explanation |
|----------|-------------|
| ❌ **High bandwidth** | Must handle full internet-facing traffic (10-100 Gbps+) |
| ❌ **Limited context** | Only sees network packets, not endpoint/cloud events |
| ❌ **Expensive infrastructure** | Requires high-performance packet capture (FPGA, GPU) |
| ❌ **Duplicate effort** | Overlaps with existing IDS/IPS |
| ❌ **Complex deployment** | Network tap configuration, SPAN port limits |

#### Use Cases

**When to Use:**
1. **You need full packet capture** for forensic analysis
2. **You want to detect CDN bypass attacks** (attackers hitting origin IP directly)
3. **You have no other network visibility** (no IDS/IPS/firewall logs)
4. **Compliance requires network-level monitoring** (PCI-DSS, HIPAA)

**When NOT to Use:**
1. You already have IDS/IPS (Suricata, Snort) feeding logs to JanuSec
2. CDN provides sufficient WAF logs
3. Budget/complexity concerns
4. Cloud-hosted applications (use cloud-native flow logs instead)

#### Technical Requirements

- **Network tap or SPAN/mirror port** configured on core switch
- **10 Gbps+ network interface** on JanuSec server
- **High-performance packet processing** (DPDK, AF_PACKET, PF_RING)
- **Zeek/Suricata integration** for protocol parsing

**Estimated Cost:** $20k-$50k for high-performance NIC + tap infrastructure

---

### SCENARIO 3: Behind Firewall (✅ RECOMMENDED - Traditional)

**Architecture:**

```
    ┌─────────────┐
    │   Internet  │
    └──────┬──────┘
           │
           ▼
    ┌──────────────────┐
    │      CDN + WAF   │
    └──────┬───────────┘
           │
           ▼
    ┌──────────────────┐
    │    Firewall      │
    │    + IDS/IPS     │
    └──────┬───────────┘
           │
           ▼
    ┌──────────────────────────────────────────────────┐
    │              Internal Network                      │
    │                                                    │
    │  ┌─────────────┐  ┌─────────────┐  ┌──────────┐ │
    │  │Web Servers  │  │API Gateways │  │Endpoints │ │
    │  └──────┬──────┘  └──────┬──────┘  └─────┬────┘ │
    │         │                 │                │      │
    │         └─────────────────┼────────────────┘      │
    │                           │                       │
    │                           ▼                       │
    │                  ┌──────────────────┐            │
    │                  │  Log Forwarders  │            │
    │                  │  (Beats, Agents) │            │
    │                  └────────┬─────────┘            │
    └───────────────────────────┼──────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   JanuSec Platform    │ ◄── ✅ RECOMMENDED PLACEMENT
                    │   (Log Ingestion)     │
                    ├───────────────────────┤
                    │ - Network logs        │
                    │ - Endpoint logs       │
                    │ - Cloud API data      │
                    │ - Email events        │
                    │ - IAM changes         │
                    │ - SBOM analysis       │
                    └───────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │  SIEM (Optional)      │
                    │  Splunk, Elastic, etc.│
                    └───────────────────────┘
```

#### How It Works

**Data Flow:**
1. **External traffic** hits CDN → WAF → Firewall
2. **Internal systems** (servers, endpoints, cloud) generate logs
3. **Log forwarders** (Filebeat, Winlogbeat, Fluentd) send to JanuSec
4. **Cloud APIs** (AWS CloudTrail, Azure AD, O365) polled by JanuSec
5. **JanuSec** correlates events, detects attacks, generates alerts
6. **Optional:** JanuSec forwards enriched events to SIEM for long-term storage

#### Pros

| Benefit | Explanation |
|---------|-------------|
| ✅ **Multi-domain correlation** | Sees network, endpoint, cloud, email, IAM in one place |
| ✅ **No network complexity** | Standard log forwarding (syslog, HTTP, API) |
| ✅ **Cloud-compatible** | Works with cloud-native logging (CloudWatch, Stackdriver) |
| ✅ **Cost-effective** | No expensive packet capture hardware |
| ✅ **Scalable** | Can process millions of events/day with standard servers |
| ✅ **Low latency** | Out-of-band, no impact on production traffic |
| ✅ **Easy deployment** | Docker/Kubernetes, no network reconfiguration |

#### Cons

| Drawback | Explanation |
|----------|-------------|
| ⚠️ **Depends on log quality** | Only as good as the logs you send it |
| ⚠️ **Delayed detection** | Relies on log forwarding (5-60 second delay typical) |
| ⚠️ **No packet-level analysis** | Can't do deep packet inspection (use Zeek/Suricata for that) |
| ⚠️ **Requires log forwarding setup** | Need to configure agents on all systems |

#### Use Cases

**When to Use:** (Most Common)
1. ✅ **Standard enterprise deployment** - You have firewalls, EDR, cloud services
2. ✅ **Cloud-first organizations** - AWS/Azure/GCP with native logging
3. ✅ **Hybrid environments** - Mix of on-prem and cloud
4. ✅ **Budget-conscious deployments** - No expensive network taps needed
5. ✅ **Multi-domain threat hunting** - Need to correlate email → endpoint → network
6. ✅ **Compliance** - Need log retention and correlation for SOC 2, ISO 27001

**Recommended For:**
- 90% of customers
- Enterprise IT environments
- SaaS/cloud-native companies
- Organizations with existing SIEM

#### Technical Requirements

**Minimum Infrastructure:**
- **JanuSec server:** 8 CPU, 32GB RAM, 500GB SSD (for <10k events/sec)
- **Network:** 1 Gbps (for log ingestion)
- **Log forwarders:** Filebeat, Winlogbeat, or Fluentd on endpoints
- **API access:** OAuth credentials for cloud services (AWS, Azure, O365, Okta)

**Data Sources:**
```
┌─────────────────────────────────────────────────────────┐
│            Recommended Data Sources                      │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Network Layer:                                          │
│    - Firewall logs (Palo Alto, Fortinet, pfSense)       │
│    - IDS/IPS alerts (Suricata, Snort)                   │
│    - DNS logs (BIND, Infoblox)                          │
│    - Proxy logs (Squid, Zscaler)                        │
│    - VPN logs (OpenVPN, Cisco AnyConnect)               │
│                                                           │
│  Endpoint Layer:                                         │
│    - Sysmon (Windows)                                    │
│    - Auditd (Linux)                                      │
│    - EDR (CrowdStrike, SentinelOne, Carbon Black)       │
│    - osquery (cross-platform)                            │
│                                                           │
│  Cloud Layer:                                            │
│    - AWS CloudTrail, VPC Flow Logs, GuardDuty           │
│    - Azure Activity Logs, NSG Flow Logs                 │
│    - GCP Cloud Logging, VPC Flow Logs                   │
│                                                           │
│  Application Layer:                                      │
│    - Web server logs (Apache, Nginx)                    │
│    - Application logs (JSON, syslog)                    │
│    - Database audit logs (PostgreSQL, MySQL)            │
│    - API gateway logs (Kong, Apigee)                    │
│                                                           │
│  Identity Layer:                                         │
│    - Okta events                                         │
│    - Azure AD sign-ins                                   │
│    - Google Workspace audit logs                        │
│    - Active Directory (Windows Event Logs)              │
│                                                           │
│  Email Layer:                                            │
│    - Office 365 message trace                           │
│    - Gmail audit logs                                    │
│    - Email gateway logs (Proofpoint, Mimecast)          │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

---

### SCENARIO 4: Parallel to SIEM (Tee/Mirror) (✅ RECOMMENDED - Hybrid)

**Architecture:**

```
┌──────────────────────────────────────────────────────────┐
│              Data Sources (All Layers)                    │
│  Network │ Endpoints │ Cloud │ Email │ IAM │ Apps        │
└────────────────────────┬─────────────────────────────────┘
                         │
                         ▼
            ┌────────────────────────┐
            │   Log Aggregator       │
            │   (Logstash, Fluentd)  │
            └────────────────────────┘
                         │
          ┌──────────────┴──────────────┐
          │                             │
          ▼                             ▼
┌──────────────────┐          ┌──────────────────┐
│  JanuSec         │          │  SIEM            │
│  (Correlation +  │          │  (Storage +      │
│   AI Analysis)   │          │   Dashboards)    │
├──────────────────┤          ├──────────────────┤
│ - Multi-domain   │          │ - Long-term      │
│   attack chains  │          │   retention      │
│ - HopGraph       │          │ - Compliance     │
│ - LLM triage     │          │   reporting      │
│ - Factor scoring │          │ - SOC dashboards │
└────────┬─────────┘          └────────┬─────────┘
         │                             │
         │   ┌─────────────────────┐   │
         └──►│  Alert Enrichment   │◄──┘
             │  (Bidirectional)    │
             └─────────────────────┘
                       │
                       ▼
             ┌─────────────────────┐
             │  SOAR Platform      │
             │  (PagerDuty, Tines) │
             └─────────────────────┘
```

#### How It Works

**Data Flow:**
1. **All logs** go to central log aggregator (Logstash, Kafka, Fluentd)
2. **Logs are duplicated (tee'd)** to both JanuSec and SIEM simultaneously
3. **JanuSec** performs real-time correlation and AI analysis
4. **SIEM** stores raw logs for compliance and historical queries
5. **JanuSec** sends high-confidence alerts to SOAR for automated response
6. **SIEM** provides dashboards and long-term trend analysis

**Integration Points:**
- JanuSec → SIEM: Enriched alerts with attack chain context
- SIEM → JanuSec: Historical data for baseline building
- Both → SOAR: Alerts for orchestrated response

#### Pros

| Benefit | Explanation |
|---------|-------------|
| ✅ **Best of both worlds** | SIEM for storage/compliance, JanuSec for correlation |
| ✅ **Reduces SIEM cost** | Store raw logs in SIEM, only send alerts to JanuSec |
| ✅ **Advanced correlation** | JanuSec specializes in multi-domain attack detection |
| ✅ **Preserve SIEM investment** | Keeps existing Splunk/Elastic dashboards |
| ✅ **Faster detection** | JanuSec processes in real-time without SIEM indexing delay |
| ✅ **Reduced alert fatigue** | JanuSec's AI triage filters noise before SIEM |

#### Cons

| Drawback | Explanation |
|----------|-------------|
| ⚠️ **Duplicate storage** | Some data stored in both JanuSec and SIEM |
| ⚠️ **Integration complexity** | Need to manage two platforms |
| ⚠️ **Potential conflicts** | Overlapping alerts from both systems |
| ⚠️ **Higher cost** | Running both platforms (though may save on SIEM licensing) |

#### Use Cases

**When to Use:**
1. ✅ **You have existing SIEM** (Splunk, Elastic, Sentinel) with lots of custom dashboards
2. ✅ **SIEM costs are high** - Use JanuSec for hot data, SIEM for cold storage
3. ✅ **Need specialized correlation** - SIEM good at storage, JanuSec good at attack chains
4. ✅ **Compliance requires SIEM** - Can't replace SIEM, but want better detection
5. ✅ **Large security team** - Different teams use different tools (SOC uses SIEM, IR uses JanuSec)

**Cost Optimization Strategy:**
- **Hot data (0-7 days):** JanuSec + SIEM (full indexing)
- **Warm data (8-90 days):** SIEM only (indexed)
- **Cold data (91-365 days):** SIEM (frozen/archived)
- **Very cold (1+ years):** S3/Glacier (compliance only)

#### Technical Implementation

**Option 1: Logstash Tee**
```ruby
# Logstash configuration
output {
  # Send to JanuSec
  http {
    url => "https://janusec.company.com/api/v1/events"
    http_method => "post"
    format => "json"
    headers => {
      "x-api-key" => "${JANUSEC_API_KEY}"
    }
  }

  # Also send to SIEM
  elasticsearch {
    hosts => ["https://elasticsearch.company.com:9200"]
    index => "logs-%{+YYYY.MM.dd}"
  }
}
```

**Option 2: Kafka Topic Duplication**
```
Producers → Kafka Topic (raw_logs)
              ├─ Consumer: JanuSec
              └─ Consumer: SIEM (Elastic/Splunk)
```

**Option 3: Fluentd Multi-Output**
```xml
<match **>
  @type copy
  <store>
    @type http
    endpoint https://janusec.company.com/api/v1/events
    headers {"x-api-key":"${JANUSEC_API_KEY}"}
  </store>
  <store>
    @type elasticsearch
    host elasticsearch.company.com
    port 9200
  </store>
</match>
```

---

### SCENARIO 5: Hybrid Multi-Tier (✅ RECOMMENDED - Enterprise)

**Architecture:**

```
┌────────────────────────────────────────────────────────────────┐
│                     External Perimeter                          │
│                                                                  │
│  Internet ──► CDN/WAF ──► Firewall ──► IDS/IPS                 │
│                  │            │             │                   │
│                  └────────────┴─────────────┘                   │
│                              │                                  │
│                         (WAF Logs, FW Logs, IDS Alerts)        │
└──────────────────────────────┼─────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────┐
│                   Internal Network                              │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │ Web Servers │  │  Endpoints  │  │  Databases  │            │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘            │
│         │                 │                 │                   │
│    (App Logs)      (Sysmon/EDR)      (Audit Logs)             │
└─────────┼─────────────────┼─────────────────┼──────────────────┘
          │                 │                 │
          └─────────────────┼─────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────────┐
│                     Cloud Services                              │
│                           │                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │   AWS    │  │  Azure   │  │  O365    │  │   Okta   │      │
│  │CloudTrail│  │ Activity │  │  Email   │  │   IAM    │      │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘      │
│       │             │              │             │             │
│       └─────────────┼──────────────┼─────────────┘             │
└─────────────────────┼──────────────┼───────────────────────────┘
                      │              │
                      ▼              ▼
        ┌──────────────────────────────────────┐
        │      Log Collection Layer             │
        │  ┌────────────┐    ┌────────────┐   │
        │  │  Filebeat  │    │  API       │   │
        │  │  Winlogbeat│    │  Pollers   │   │
        │  │  Fluentd   │    │  (OAuth)   │   │
        │  └──────┬─────┘    └──────┬─────┘   │
        └─────────┼──────────────────┼──────────┘
                  │                  │
                  └────────┬─────────┘
                           │
                  ┌────────▼─────────┐
                  │  Message Queue   │
                  │  (Kafka/Redis)   │
                  └────────┬─────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
│   JanuSec       │ │    SIEM     │ │  Data Lake      │
│   (Correlation) │ │  (Storage)  │ │  (S3/ADLS)      │
├─────────────────┤ ├─────────────┤ ├─────────────────┤
│ Hot Data:       │ │ Indexed:    │ │ Cold Storage:   │
│ - Last 7 days   │ │ - 30 days   │ │ - 1+ years      │
│ - Real-time     │ │ - Dashboards│ │ - Compliance    │
│   correlation   │ │ - Compliance│ │ - Big data      │
│ - Attack chains │ │   queries   │ │   analytics     │
└────────┬────────┘ └──────┬──────┘ └────────┬────────┘
         │                 │                  │
         └────────┬────────┴──────────────────┘
                  │
                  ▼
         ┌────────────────────┐
         │  Alert Enrichment  │
         │  & Orchestration   │
         └────────┬───────────┘
                  │
                  ▼
         ┌────────────────────┐
         │  SOAR Platform     │
         │  (Automated        │
         │   Response)        │
         └────────────────────┘
```

#### Data Tiers

**Tier 1: Hot (Real-Time) - JanuSec**
- **Retention:** 7-30 days
- **Purpose:** Real-time correlation, attack chain detection, AI triage
- **Storage:** SSD/NVMe (fast random access)
- **Query latency:** <100ms
- **Cost:** High ($/GB), but small volume

**Tier 2: Warm (Indexed) - SIEM**
- **Retention:** 30-90 days
- **Purpose:** Compliance queries, dashboards, historical analysis
- **Storage:** SSD or high-performance HDD
- **Query latency:** <1 second
- **Cost:** Medium

**Tier 3: Cold (Archived) - Data Lake**
- **Retention:** 1-7 years
- **Purpose:** Compliance, forensic investigations, big data analytics
- **Storage:** Object storage (S3, Azure Blob, GCS)
- **Query latency:** Seconds to minutes (batch queries)
- **Cost:** Very low ($0.023/GB/month for S3)

#### Pros

| Benefit | Explanation |
|---------|-------------|
| ✅ **Optimized costs** | Each tier uses appropriate storage technology |
| ✅ **Best performance** | Hot data on fast storage for real-time detection |
| ✅ **Compliance-ready** | Long-term retention in cheap object storage |
| ✅ **Scalable** | Can handle petabytes in data lake |
| ✅ **Flexible** | Different tools for different use cases |

#### Cons

| Drawback | Explanation |
|----------|-------------|
| ⚠️ **Complex architecture** | Multiple systems to manage |
| ⚠️ **Data lifecycle management** | Need automated tiering policies |
| ⚠️ **Query complexity** | May need to search multiple systems |

#### Use Cases

**When to Use:**
1. ✅ **Large enterprises** (10k+ employees, 100k+ events/sec)
2. ✅ **Strict compliance** (HIPAA, PCI-DSS requiring multi-year retention)
3. ✅ **Cost optimization** - Can't afford to index everything in SIEM
4. ✅ **Big data analytics** - Want to run ML on historical data

**Recommended For:**
- Fortune 500 companies
- Healthcare/financial services
- Organizations with >1TB/day log volume

---

## MINIMUM DEPLOYMENT REQUIREMENTS

### Minimum Viable Deployment

**To fully utilize JanuSec's capabilities, you need AT MINIMUM:**

```
┌─────────────────────────────────────────────────────────────┐
│         Minimum Required Data Sources (Choose 3+)            │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Network (Pick 1):                                           │
│    ☑ Firewall logs OR                                       │
│    ☑ IDS/IPS alerts (Suricata/Snort) OR                    │
│    ☑ Zeek/Bro network logs OR                               │
│    ☑ VPC Flow Logs (AWS/Azure/GCP)                         │
│                                                               │
│  Endpoint (Pick 1):                                          │
│    ☑ Sysmon (Windows) OR                                    │
│    ☑ EDR logs (CrowdStrike, SentinelOne, etc.) OR          │
│    ☑ Auditd (Linux) OR                                      │
│    ☑ osquery                                                 │
│                                                               │
│  Cloud/Identity (Pick 1):                                    │
│    ☑ AWS CloudTrail OR                                      │
│    ☑ Azure Activity Logs OR                                 │
│    ☑ GCP Cloud Logging OR                                   │
│    ☑ Okta events OR                                         │
│    ☑ Azure AD sign-ins                                      │
│                                                               │
│  Optional (High Value):                                      │
│    ☐ Email logs (O365, Gmail)                              │
│    ☐ DNS logs                                                │
│    ☐ Proxy logs                                              │
│    ☐ Application logs                                        │
│    ☐ SBOM files                                              │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

**Why 3+ Domains?**
- JanuSec's strength is **multi-domain correlation**
- A single domain (network only) → just use Suricata/Zeek
- Two domains (network + endpoint) → basic correlation, limited value
- **Three+ domains** → Can detect email phishing → endpoint execution → network exfiltration chains

### Infrastructure Requirements

**Small Deployment (SMB: <1000 employees)**
```
JanuSec Server:
  - 8 vCPU
  - 32 GB RAM
  - 500 GB SSD
  - 1 Gbps network

Database (PostgreSQL):
  - 4 vCPU
  - 16 GB RAM
  - 1 TB SSD (for 30-day retention)

Cache (Redis):
  - 2 vCPU
  - 8 GB RAM
  - 50 GB SSD

Total: ~$500-$800/month (AWS/Azure)
```

**Medium Deployment (Mid-Market: 1k-10k employees)**
```
JanuSec (3-node cluster):
  - 16 vCPU per node
  - 64 GB RAM per node
  - 1 TB NVMe per node
  - 10 Gbps network

Database (PostgreSQL HA):
  - Primary: 8 vCPU, 32 GB RAM, 2 TB SSD
  - Replica: 8 vCPU, 32 GB RAM, 2 TB SSD

Cache (Redis Cluster):
  - 3 nodes x (4 vCPU, 16 GB RAM)

Total: ~$3k-$5k/month
```

**Large Deployment (Enterprise: 10k+ employees)**
```
JanuSec (Kubernetes):
  - 10+ pods (auto-scaling)
  - 32 vCPU, 128 GB RAM per pod
  - Shared NVMe storage (10 TB+)

Database (PostgreSQL + TimescaleDB):
  - 32 vCPU, 256 GB RAM
  - 10 TB SSD (with automatic archival to S3)

Cache (Redis Enterprise):
  - 6-node cluster
  - 8 vCPU, 32 GB RAM per node

Message Queue (Kafka):
  - 3 brokers
  - 16 vCPU, 64 GB RAM each

Total: ~$20k-$40k/month
```

---

## DATA CONNECTOR STRATEGY

### Connector Options

#### Option 1: Native JanuSec Connectors (✅ RECOMMENDED)

**Pros:**
- Deep integration with JanuSec's correlation engine
- Optimized data parsing and normalization
- Real-time ingestion with low latency
- Built-in OAuth handling for cloud APIs

**Cons:**
- Limited to connectors JanuSec implements
- Requires development for custom sources

**Currently Implemented:**
- ✅ Zeek network logs
- ✅ Sysmon (Windows Event Logs)
- ✅ CSV upload (generic)
- ✅ AWS CloudTrail (basic)
- 🟡 Email (OAuth in progress)
- 🟡 Okta/Azure AD (OAuth in progress)

**Roadmap (P0):**
- Office 365 (MS Graph API)
- Gmail (Gmail API)
- Okta events
- Azure AD sign-ins

#### Option 2: Via Wazuh (⚠️ PARTIAL INTEGRATION)

**Architecture:**
```
Endpoints ──► Wazuh Agent ──► Wazuh Manager ──► JanuSec
                                   │
                                   └──► SIEM (Optional)
```

**Pros:**
- Wazuh provides lightweight agents for endpoints
- Built-in log collection from 100+ sources
- File integrity monitoring (FIM)
- Rootkit detection
- Active response capabilities

**Cons:**
- Adds another layer (complexity)
- Wazuh's rule engine may conflict with JanuSec's
- Duplicate processing (Wazuh analyzes, then JanuSec analyzes again)

**When to Use:**
- You already have Wazuh deployed
- Need host-based IDS (HIDS) features
- Want Wazuh's compliance modules (PCI-DSS, HIPAA)

**Integration Method:**
```python
# Wazuh forwards alerts to JanuSec via syslog/HTTP
# wazuh_manager.conf
<integration>
  <name>custom-webhook</name>
  <hook_url>https://janusec.company.com/api/v1/events</hook_url>
  <level>5</level>  <!-- Only forward alerts >= severity 5 -->
  <alert_format>json</alert_format>
</integration>
```

#### Option 3: Via ELK Stack (✅ RECOMMENDED for Existing ELK Users)

**Architecture:**
```
Data Sources ──► Beats (Filebeat/Winlogbeat) ──► Logstash ──┬──► Elasticsearch
                                                              │
                                                              └──► JanuSec
```

**Pros:**
- Leverage existing Beats agents (widely deployed)
- Logstash provides powerful parsing (Grok, JSON)
- Can reuse Elastic pipelines
- Dual output (ELK + JanuSec) easy to configure

**Cons:**
- Logstash adds processing latency (1-5 seconds)
- Need to manage ELK stack separately
- Higher infrastructure cost

**When to Use:**
- You already have ELK/Elastic stack deployed
- Need Kibana dashboards for operational metrics
- Want centralized log parsing (Logstash)

**Integration Method:**
```ruby
# Logstash output to both Elastic and JanuSec
output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    index => "logs-%{+YYYY.MM.dd}"
  }

  http {
    url => "https://janusec.company.com/api/v1/events/bulk"
    http_method => "post"
    format => "json_batch"
    headers => {"x-api-key" => "${JANUSEC_API_KEY}"}
    batch => 100
    batch_timeout => 5
  }
}
```

#### Option 4: Direct Integration (✅ BEST PERFORMANCE)

**Architecture:**
```
Data Sources ──► Lightweight Forwarder ──► JanuSec API
                  (Filebeat, Fluentd)
```

**Pros:**
- Lowest latency (<1 second)
- Simplest architecture
- No intermediate processing
- Lower cost (no SIEM/ELK needed)

**Cons:**
- No centralized parsing (JanuSec must handle all formats)
- No visual dashboards (unless JanuSec UI sufficient)
- Less flexibility for custom enrichment

**When to Use:**
- Greenfield deployment (no existing SIEM)
- Cost-sensitive (small budget)
- Need real-time detection (<5 second latency)

**Example: Filebeat → JanuSec**
```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/auth.log

output.http:
  hosts: ["https://janusec.company.com"]
  path: "/api/v1/events"
  headers:
    x-api-key: "${JANUSEC_API_KEY}"
  bulk_max_size: 100
```

### Connector Comparison Matrix

| Connector Type | Latency | Cost | Complexity | Flexibility | Recommendation |
|---------------|---------|------|------------|-------------|----------------|
| **Native JanuSec** | <1s | Low | Low | Medium | ✅ Best for greenfield |
| **Via Wazuh** | 2-5s | Medium | Medium | High | ⚠️ If already using Wazuh |
| **Via ELK** | 5-10s | High | High | Very High | ✅ If ELK already deployed |
| **Direct (Beats)** | <1s | Very Low | Low | Low | ✅ Best for performance |

### Recommended Connector Strategy

**Tier 1 (Critical Data Sources) - Direct Integration:**
- Network: Zeek/Suricata → JanuSec (real-time)
- Endpoint: Sysmon/EDR → JanuSec (real-time)
- Cloud: AWS/Azure/GCP APIs → JanuSec (5-minute polling)

**Tier 2 (High-Volume Logs) - Via ELK:**
- Application logs → Logstash → JanuSec + Elasticsearch
- Web server logs → Filebeat → Logstash → JanuSec + Elasticsearch

**Tier 3 (Compliance/Audit) - Via SIEM:**
- All logs → SIEM (long-term storage)
- SIEM alerts → JanuSec (enrichment)

---

## DATA STORAGE ARCHITECTURE

### Storage Options Comparison

#### 1. Local Hard Drives (HDD)

**Architecture:**
```
JanuSec Server
├── OS: 256 GB SSD
└── Data: 4x 4TB HDD (JBOD)
    └── PostgreSQL database
```

**Pros:**
- ✅ Cheapest ($/GB): ~$0.02/GB
- ✅ Simple setup
- ✅ No network latency

**Cons:**
- ❌ Slow random I/O (100-150 IOPS)
- ❌ No redundancy (single disk failure = data loss)
- ❌ Limited scalability (physical server limits)
- ❌ Poor performance for JanuSec's workload (random reads)

**When to Use:**
- ❌ **NOT RECOMMENDED** for JanuSec
- HDD too slow for real-time correlation queries
- Use only for cold archival (if budget is extremely tight)

---

#### 2. RAID Arrays

**Architecture:**
```
JanuSec Server
├── OS: 256 GB SSD (RAID 1)
└── Data: 8x 2TB SSD (RAID 10)
    ├── Usable capacity: 8 TB
    ├── Read IOPS: ~50k
    └── Write IOPS: ~25k
```

**RAID Levels:**

**RAID 1 (Mirroring):**
- 2 disks, 50% capacity loss
- Great for OS and critical data
- Excellent read performance

**RAID 5 (Parity):**
- ❌ **NOT RECOMMENDED** - Write penalty, rebuild risk

**RAID 6 (Double Parity):**
- Good for cold storage
- Can survive 2 disk failures
- Still has write penalty

**RAID 10 (Striped Mirrors):**
- ✅ **BEST FOR JANUSEC**
- 50% capacity loss (acceptable trade-off)
- Excellent read/write performance
- Can survive multiple disk failures (if right disks)

**Pros:**
- ✅ Hardware redundancy (no single point of failure)
- ✅ Good performance (RAID 10: 50k+ IOPS)
- ✅ Predictable latency (<1ms)

**Cons:**
- ⚠️ 50% capacity overhead (RAID 10)
- ⚠️ Limited by single server (can't scale horizontally)
- ⚠️ Rebuild times can be long (24+ hours for 10TB array)

**When to Use:**
- ✅ **Small to medium deployments** (<10TB data)
- ✅ Single-server JanuSec installation
- ✅ On-prem deployments

**Recommended Configuration:**
```
Hot Data (PostgreSQL + Redis):
  - 8x 2TB NVMe SSD (RAID 10)
  - Usable: 8 TB
  - IOPS: 50k+
  - Cost: ~$5k hardware

Warm Data (Archives):
  - 12x 4TB SATA SSD (RAID 6)
  - Usable: 40 TB
  - Cost: ~$6k hardware
```

---

#### 3. Network Attached Storage (NAS)

**Architecture:**
```
┌──────────────────┐          ┌──────────────────┐
│  JanuSec Server  │◄────────►│  NAS Appliance   │
│  (Compute)       │  10 GbE  │  (Storage)       │
│                  │          │                  │
│ - PostgreSQL     │          │ - 24x 4TB SSD    │
│ - Redis          │          │ - RAID 6         │
│ - App tier       │          │ - 80 TB usable   │
└──────────────────┘          └──────────────────┘
```

**NAS Protocols:**
- **NFS (Network File System):** Linux-friendly, good for logs
- **SMB/CIFS:** Windows-friendly
- **iSCSI:** Block-level (can run databases on it)

**Pros:**
- ✅ Centralized storage (multiple servers can access)
- ✅ Easy capacity expansion (add more disks)
- ✅ Built-in snapshots and backups (most NAS appliances)
- ✅ Good for shared data (e.g., KAPE artifact storage)

**Cons:**
- ⚠️ Network latency (1-3ms vs. <0.1ms local SSD)
- ⚠️ Network bandwidth bottleneck (10 GbE = ~1 GB/s max)
- ⚠️ Single point of failure (NAS appliance itself)
- ❌ **NOT SUITABLE for PostgreSQL database** (too much latency)

**When to Use:**
- ✅ **File storage** (KAPE artifacts, PCAP files, SBOM uploads)
- ✅ **Log archives** (older data, infrequent access)
- ✅ **Shared storage** across multiple JanuSec nodes
- ❌ **NOT for PostgreSQL** (use local SSD or SAN instead)

**Recommended Use Case:**
```
JanuSec Server:
  - Local NVMe: PostgreSQL database, Redis cache
  - NAS (NFS): KAPE artifacts, archived logs, PCAP files

This hybrid approach gets best of both worlds:
  - Low latency for database queries
  - High capacity for file storage
```

**NAS Products:**
- **Synology/QNAP:** $2k-$10k (good for SMB)
- **NetApp/Dell EMC:** $50k+ (enterprise)
- **TrueNAS/FreeNAS:** Open-source (DIY)

---

#### 4. Data Lake (S3, Azure Blob, GCS)

**Architecture:**
```
┌──────────────────┐
│  JanuSec Server  │
│  (Hot Data)      │
│  - Last 7 days   │
│  - PostgreSQL    │
└────────┬─────────┘
         │ Automated archival
         ▼
┌──────────────────┐
│  Data Lake       │
│  (Cold Storage)  │
│  - S3 / Azure    │
│  - Parquet files │
│  - 1+ years      │
└──────────────────┘
```

**Object Storage Tiers:**

**AWS S3:**
- **S3 Standard:** $0.023/GB/month (hot data, frequent access)
- **S3 Infrequent Access:** $0.0125/GB/month (warm data)
- **S3 Glacier:** $0.004/GB/month (cold archive)
- **S3 Glacier Deep Archive:** $0.00099/GB/month (compliance archive)

**Azure Blob:**
- **Hot tier:** $0.0184/GB/month
- **Cool tier:** $0.01/GB/month
- **Archive tier:** $0.002/GB/month

**GCS (Google Cloud Storage):**
- **Standard:** $0.020/GB/month
- **Nearline:** $0.010/GB/month (30-day minimum)
- **Coldline:** $0.004/GB/month (90-day minimum)
- **Archive:** $0.0012/GB/month (365-day minimum)

**Pros:**
- ✅ **Extremely cheap** ($0.001/GB/month for deep archive)
- ✅ **Unlimited capacity** (petabyte-scale)
- ✅ **Durability:** 99.999999999% (11 nines)
- ✅ **Lifecycle policies** (auto-tier old data)
- ✅ **Queryable** (Athena, BigQuery, Synapse)

**Cons:**
- ❌ **High latency** (100ms-10s for cold tiers)
- ❌ **Retrieval costs** ($0.01-$0.03/GB for Glacier retrieval)
- ❌ **Not suitable for real-time queries**
- ⚠️ **Egress costs** ($0.09/GB to download)

**When to Use:**
- ✅ **Compliance archives** (7+ years retention)
- ✅ **Forensic data** (PCAP files, KAPE artifacts)
- ✅ **Historical analysis** (big data, ML training)
- ✅ **Cost optimization** (hot → warm → cold tiering)

**Data Lifecycle Example:**
```
Day 0-7:   JanuSec (NVMe SSD)      → Real-time correlation
Day 8-30:  SIEM (SSD)              → Dashboards, queries
Day 31-90: S3 Standard             → Occasional investigations
Day 91-365: S3 Glacier             → Rare forensic analysis
Day 365+:  S3 Glacier Deep Archive → Compliance only
```

**Cost Comparison (1TB for 1 year):**
- Local SSD: ~$100 (hardware depreciation)
- SIEM (Splunk): ~$2,000 (licensing + storage)
- S3 Standard: ~$276
- S3 Glacier: ~$48
- S3 Deep Archive: ~$12

---

#### 5. Data Lakehouse (Databricks, Snowflake)

**Architecture:**
```
┌──────────────────┐
│  JanuSec Server  │
│  (Real-time)     │
└────────┬─────────┘
         │ Stream events
         ▼
┌──────────────────┐
│  Kafka / Kinesis │
│  (Event Stream)  │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────┐
│      Data Lakehouse              │
│  (Databricks / Snowflake)        │
│                                  │
│  - Delta Lake / Iceberg format  │
│  - ACID transactions             │
│  - SQL + ML analytics            │
│  - Time travel (versioning)      │
└──────────────────────────────────┘
         │
         ├──► BI Dashboards (Tableau, Power BI)
         ├──► ML Models (threat prediction)
         └──► Long-term storage (S3/ADLS)
```

**What is a Lakehouse?**
Combines benefits of **data lake** (cheap object storage) and **data warehouse** (SQL queries, ACID).

**Technologies:**
- **Databricks** (Delta Lake on S3/ADLS/GCS)
- **Snowflake** (proprietary format on S3)
- **AWS Lake Formation** (Iceberg/Hudi on S3)
- **Azure Synapse Analytics**

**Pros:**
- ✅ **SQL queries on S3** (low-cost storage + high-performance queries)
- ✅ **ACID transactions** (consistency for updates)
- ✅ **Schema evolution** (change schema over time)
- ✅ **Time travel** (query historical versions)
- ✅ **ML integration** (train models on historical data)
- ✅ **Scalable** (petabyte-scale)

**Cons:**
- ⚠️ **Higher cost than raw S3** (compute charges for queries)
- ⚠️ **Complexity** (need Spark/SQL expertise)
- ❌ **Not real-time** (batch processing, minutes to hours latency)
- ⚠️ **Vendor lock-in** (Snowflake proprietary, Databricks complex)

**When to Use:**
- ✅ **Big data analytics** (analyzing petabytes of historical logs)
- ✅ **Machine learning** (training threat models on 1+ year of data)
- ✅ **Business intelligence** (executive dashboards, trend analysis)
- ✅ **Compliance reporting** (complex queries over years of data)
- ❌ **NOT for real-time detection** (JanuSec handles that)

**Cost Example (1TB for 1 year):**
- **Databricks:** ~$500-$1,000 (storage + compute)
- **Snowflake:** ~$400-$800 (on-demand pricing)
- **DIY (Spark on S3):** ~$300 (S3 + EMR/Glue)

**Use Case for JanuSec:**
```
Real-time detection:
  JanuSec (7 days) → Alerts on attacks

Historical analysis:
  JanuSec archives → S3 → Databricks
  ├─ Threat hunting queries (SQL)
  ├─ ML model training (predict future attacks)
  └─ Executive reports (trends over 6 months)
```

---

#### 6. Data Warehouse (Redshift, BigQuery)

**Architecture:**
```
┌──────────────────┐
│  JanuSec Server  │
│  (OLTP)          │
└────────┬─────────┘
         │ ETL nightly
         ▼
┌──────────────────────────┐
│  Data Warehouse          │
│  (OLAP - Analytics)      │
│                          │
│  - Redshift / BigQuery  │
│  - Star schema          │
│  - Aggregated metrics   │
└──────────────────────────┘
         │
         └──► BI Dashboards
```

**Difference from Lakehouse:**
- **Warehouse:** Structured data only, optimized for SQL
- **Lakehouse:** Unstructured + structured, optimized for SQL + ML

**Pros:**
- ✅ **Fast SQL queries** (optimized for analytics)
- ✅ **Mature ecosystem** (many BI tools integrate)
- ✅ **Predictable performance** (dedicated compute)

**Cons:**
- ❌ **Expensive** ($1,000-$10,000/month typical)
- ❌ **Structured data only** (logs must be parsed first)
- ❌ **Not suitable for raw logs** (better for aggregated metrics)

**When to Use:**
- ✅ **Executive dashboards** (aggregated security metrics)
- ✅ **Compliance reports** (pre-computed summaries)
- ❌ **NOT for raw log storage** (use data lake for that)

---

### Storage Recommendation Matrix

| Use Case | Recommended Storage | Rationale |
|----------|-------------------|-----------|
| **Real-time correlation** | Local NVMe SSD (RAID 10) | <1ms latency required |
| **Hot data (7 days)** | Local SSD or cloud SSD (EBS, Azure Disk) | Fast queries, frequent access |
| **Warm data (8-90 days)** | SIEM (SSD) or S3 Standard | Balance cost/performance |
| **Cold archive (1+ years)** | S3 Glacier / Azure Archive | Compliance, $0.001/GB/month |
| **File storage (KAPE, PCAP)** | NAS or S3 | Large files, infrequent access |
| **Big data analytics** | Data Lakehouse (Databricks) | ML training, threat hunting |
| **BI dashboards** | Data Warehouse (Redshift) | Executive metrics |

### Recommended Tiering Strategy

**Small Deployment (<10TB total):**
```
All data: Local SSD RAID 10
  - Simple, fast, no cloud costs
```

**Medium Deployment (10-100TB):**
```
Hot:  Local NVMe (7 days)
Warm: S3 Standard (8-90 days)
Cold: S3 Glacier (91+ days)
```

**Large Deployment (100TB+):**
```
Real-time: JanuSec on NVMe (7 days)
Indexed:   SIEM on SSD (30 days)
Archive:   S3 Standard (31-90 days)
Compliance: S3 Glacier (91-365 days)
Long-term: S3 Deep Archive (1+ years)
Analytics: Databricks Lakehouse (all data, queryable)
```

---

## FEDERATED LEARNING CONSIDERATIONS

### What is Federated Learning?

**Traditional ML:**
```
Customer A logs ──┐
Customer B logs ──┼──► Central server → Train model → Deploy to all
Customer C logs ──┘
```
❌ **Problem:** Privacy concerns, data sovereignty, centralized risk

**Federated Learning:**
```
Customer A: Local model training ──┐
Customer B: Local model training ──┼──► Share only model updates (gradients)
Customer C: Local model training ──┘         ↓
                                    Central aggregation → Global model
                                             ↓
                              Deploy improved model to all customers
```
✅ **Benefit:** Data stays on-premise, only model weights shared

### Applicability to JanuSec

**Current JanuSec Approach:**
- Each tenant (customer) has isolated detection models
- Models trained on customer's own data only
- No cross-tenant learning (privacy preserved)

**Potential Federated Learning Use Cases:**

#### 1. Threat Intelligence Sharing (✅ HIGH VALUE)

**Scenario:**
- Customer A detects new malware hash (via binary analysis)
- Customer B detects new phishing domain
- Customer C detects new LOLBin technique

**Federated Approach:**
```
┌─────────────────────────────────────────────────────────┐
│            Federated Threat Intel Network                │
│                                                           │
│  Customer A ──► Hash: abc123 (malware) ──┐              │
│  Customer B ──► Domain: evil.com ────────┼──► Central   │
│  Customer C ──► LOLBin: new variant ─────┘    Aggregator│
│                                                  │        │
│                                                  ▼        │
│                            ┌──────────────────────────┐  │
│                            │  Global IOC Database     │  │
│                            │  (Deduplicated)          │  │
│                            └──────────────────────────┘  │
│                                     │                     │
│                 ┌───────────────────┼───────────────┐    │
│                 ▼                   ▼               ▼    │
│           Customer A           Customer B      Customer C│
│          (Gets B+C IOCs)     (Gets A+C IOCs) (Gets A+B) │
└─────────────────────────────────────────────────────────┘
```

**Privacy Preserved:**
- Only IOCs shared (hashes, domains, IPs), not raw logs
- No customer attribution (don't reveal which customer saw it)
- Opt-in participation

**Implementation:**
```python
# src/ai/federated/threat_intel_sharing.py

class FederatedThreatIntel:
    """Anonymized threat intelligence sharing across tenants."""

    async def share_ioc(self, ioc_type: str, ioc_value: str, confidence: float):
        """Share IOC with central aggregator (anonymized)."""

        # Only share if high confidence (>0.8)
        if confidence < 0.8:
            return

        # Anonymize submission
        payload = {
            "ioc_type": ioc_type,  # hash, domain, ip, etc.
            "ioc_value": ioc_value,
            "confidence": confidence,
            "first_seen": datetime.utcnow().isoformat(),
            "tenant_id": hash(self.tenant_id)  # One-way hash (anonymous)
        }

        # Send to central aggregator (JanuSec cloud service)
        async with httpx.AsyncClient() as client:
            await client.post(
                "https://intel.janusec.com/api/v1/federated/iocs",
                json=payload,
                headers={"x-api-key": self.api_key}
            )

    async def fetch_global_iocs(self) -> List[Dict[str, Any]]:
        """Fetch global IOCs from other tenants."""

        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://intel.janusec.com/api/v1/federated/iocs/recent",
                headers={"x-api-key": self.api_key}
            )

            return response.json()["iocs"]
```

**Benefits:**
- ✅ Customer A detects threat → Customer B protected within hours
- ✅ Network effect (more customers = better protection)
- ✅ Privacy preserved (no raw logs shared)

---

#### 2. False Positive Feedback Loop (⚠️ MEDIUM VALUE)

**Scenario:**
- Analyst at Customer A marks alert as false positive
- Similar alert triggered at Customer B
- Can Customer B benefit from Customer A's feedback?

**Challenge:**
- High variance across customers (different environments)
- What's a false positive for A may be real for B

**Federated Approach:**
```
Customer A: Alert X marked as FP ──┐
Customer B: Alert Y marked as FP ──┼──► Central aggregator
Customer C: Alert Z marked as FP ──┘          │
                                               ▼
                                  Find common patterns in FPs
                                               │
                                               ▼
                                  Suggest allowlist rules
                                  (Tenant-specific, not forced)
```

**Privacy Preserved:**
- Only alert factors shared (not raw data)
- Suggestions, not automatic suppression
- Opt-in per tenant

**Benefits:**
- ⚠️ Moderate (high variance across environments)
- Better for industry-specific models (e.g., healthcare FPs)

---

#### 3. Attack Pattern Learning (❌ LOW VALUE, HIGH RISK)

**Scenario:**
- Train global model on attack patterns from all customers
- Improve detection accuracy

**Challenge:**
- Privacy risk (model may leak sensitive information)
- Adversarial attacks (poisoning federated model)
- Complexity (differential privacy, secure aggregation)

**Federated Approach:**
```
Customer A: Train local model on attacks ──┐
Customer B: Train local model on attacks ──┼──► Share gradients (encrypted)
Customer C: Train local model on attacks ──┘          │
                                                       ▼
                                           Aggregate gradients
                                                       │
                                                       ▼
                                           Global model update
                                                       │
                                     ┌─────────────────┼─────────────────┐
                                     ▼                 ▼                 ▼
                                Customer A        Customer B        Customer C
                              (Deploy model)    (Deploy model)    (Deploy model)
```

**Privacy Risks:**
- Model inversion attacks (reconstruct training data from gradients)
- Membership inference (detect if specific customer participated)

**Mitigations:**
- Differential privacy (add noise to gradients)
- Secure multi-party computation (encrypted aggregation)
- Homomorphic encryption (compute on encrypted gradients)

**Complexity:**
- Very high (research-level techniques)
- Performance overhead (10-100x slower)

**Recommendation:**
- ❌ **NOT RECOMMENDED** for JanuSec at this time
- Too complex, privacy risks, marginal benefit

---

### Federated Learning Recommendation

**Implement:**
1. ✅ **Threat Intelligence Sharing** - High value, low risk, easy to implement
   - Share IOCs (hashes, domains, IPs) anonymously
   - Build global threat database
   - Opt-in per tenant

**Consider (Future):**
2. ⚠️ **False Positive Feedback** - Moderate value, moderate complexity
   - Share FP patterns for allowlist suggestions
   - Industry-specific models (healthcare, finance)

**Avoid:**
3. ❌ **Attack Pattern Learning** - Low benefit, high risk/complexity
   - Privacy concerns (model inversion)
   - Adversarial attacks (model poisoning)
   - Better to use public datasets (MITRE, ATT&CK)

---

## ARCHITECTURAL DECISION FRAMEWORK

### Decision Tree

```
START: Where should I deploy JanuSec?
│
├─ Do you need real-time packet inspection? ─── YES ──► Scenario 2 (Network Tap)
│                                                         + Scenario 3 (Behind FW)
│                                                         (Hybrid approach)
│
├─ NO ──► Do you have existing SIEM? ─── YES ──► Scenario 4 (Parallel to SIEM)
│                                                  or Scenario 5 (Multi-Tier)
│
├─────── NO ──► Budget? ─── Low (<$5k/month) ──► Scenario 3 (Behind FW, Direct)
│                                                  with local SSD storage
│
├─────────────── Medium ($5k-$20k/month) ──► Scenario 3 + Data Lake (S3)
│
└─────────────── High (>$20k/month) ──► Scenario 5 (Multi-Tier Enterprise)
                                          with Lakehouse analytics
```

### Evaluation Criteria

| Criterion | Weight | Scenario 1 (Front of CDN) | Scenario 2 (CDN-FW) | Scenario 3 (Behind FW) | Scenario 4 (Parallel SIEM) | Scenario 5 (Multi-Tier) |
|-----------|--------|---------------------------|---------------------|------------------------|----------------------------|-------------------------|
| **Performance** | 25% | ❌ 0/10 (adds latency) | ⚠️ 6/10 (passive tap) | ✅ 9/10 (out-of-band) | ✅ 8/10 (slight dup overhead) | ✅ 9/10 (optimized tiers) |
| **Cost** | 20% | ❌ 1/10 (expensive infra) | ❌ 4/10 (packet capture) | ✅ 9/10 (cheap) | ⚠️ 6/10 (run 2 platforms) | ⚠️ 5/10 (complex, multi-tier) |
| **Scalability** | 20% | ❌ 2/10 (can't scale) | ⚠️ 6/10 (bandwidth limited) | ✅ 9/10 (horizontal scale) | ✅ 8/10 (each scales independently) | ✅ 10/10 (designed for scale) |
| **Ease of Deployment** | 15% | ❌ 1/10 (wrong approach) | ⚠️ 4/10 (network reconfig) | ✅ 9/10 (standard log forwarding) | ⚠️ 6/10 (manage 2 systems) | ❌ 4/10 (complex architecture) |
| **Multi-Domain Correlation** | 20% | ❌ 1/10 (network only) | ⚠️ 5/10 (network focus) | ✅ 10/10 (all domains) | ✅ 10/10 (all domains) | ✅ 10/10 (all domains + analytics) |
| **TOTAL** | 100% | ❌ **1.6/10** | ⚠️ **5.3/10** | ✅ **9.2/10** | ✅ **8.0/10** | ✅ **8.3/10** |

**Winner:** **Scenario 3 (Behind Firewall)** for most deployments

**Runner-up:** **Scenario 5 (Multi-Tier)** for large enterprises with compliance requirements

---

## REFERENCE ARCHITECTURES

### Architecture 1: Small Business (50-500 employees)

```
┌─────────────────────────────────────────────────────┐
│                   Internet                           │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │   Cloud Firewall     │
          │   (Azure Firewall,   │
          │    AWS Network FW)   │
          └──────────┬───────────┘
                     │
          ┌──────────┴───────────┐
          │                      │
          ▼                      ▼
   ┌─────────────┐      ┌─────────────┐
   │Cloud VMs    │      │ Endpoints   │
   │(Web, API)   │      │ (Laptops)   │
   └──────┬──────┘      └──────┬──────┘
          │                     │
          │   ┌─────────────────┘
          │   │
          └───┼──────────┐
              │          │
              ▼          ▼
      ┌────────────────────────┐
      │  Lightweight Agents    │
      │  (Filebeat/Fluentd)    │
      └───────────┬────────────┘
                  │
                  ▼
      ┌────────────────────────┐
      │   JanuSec Platform     │
      │   (Single VM)          │
      │   - 8 vCPU, 32 GB RAM  │
      │   - 500 GB SSD         │
      │   - $500/month         │
      └────────────────────────┘
```

**Data Sources:**
- Cloud firewall logs (Azure Firewall, AWS Network Firewall)
- Endpoint EDR (CrowdStrike, SentinelOne, or free: Wazuh)
- Cloud audit logs (CloudTrail, Azure Activity Log)
- Office 365 email (via P0 OAuth integration)

**Storage:**
- 7 days hot (local SSD)
- 30 days warm (S3 Standard)
- 1 year cold (S3 Glacier)

**Cost:** ~$800/month total (VM + storage)

---

### Architecture 2: Mid-Market (500-5000 employees)

```
┌───────────────────────────────────────────────────────┐
│                      Internet                          │
└────────────────────┬──────────────────────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │   CDN + WAF          │
          │   (Cloudflare)       │
          └──────────┬───────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │   Firewall           │
          │   (Palo Alto)        │
          └──────────┬───────────┘
                     │
          ┌──────────┴───────────┐
          │                      │
          ▼                      ▼
   ┌─────────────┐      ┌─────────────┐
   │ On-Prem     │      │   Cloud     │
   │ Network     │      │   (AWS)     │
   └──────┬──────┘      └──────┬──────┘
          │                     │
          └──────────┬──────────┘
                     │
                     ▼
      ┌──────────────────────────┐
      │   Log Aggregation        │
      │   (Logstash Cluster)     │
      └─────────┬────────────────┘
                │
         ┌──────┴──────┐
         │             │
         ▼             ▼
┌────────────────┐  ┌────────────────┐
│  JanuSec       │  │  Elastic       │
│  (3-node HA)   │  │  (SIEM)        │
│  - Correlation │  │  - Dashboards  │
│  - AI Triage   │  │  - Compliance  │
└────────┬───────┘  └────────┬───────┘
         │                    │
         └─────────┬──────────┘
                   │
                   ▼
         ┌──────────────────┐
         │  SOAR Platform   │
         │  (Tines/Cortex)  │
         └──────────────────┘
```

**Data Sources:**
- Firewall logs (Palo Alto, Fortinet)
- IDS/IPS (Suricata)
- EDR (CrowdStrike, Carbon Black)
- Cloud (AWS CloudTrail, GuardDuty)
- Email (O365 via MS Graph)
- IAM (Okta, Azure AD)

**Storage:**
- 7 days hot (JanuSec NVMe)
- 30 days warm (Elastic SSD)
- 90 days (S3 Standard)
- 1 year (S3 Glacier)

**Cost:** ~$8k/month (infrastructure + licenses)

---

### Architecture 3: Enterprise (10k+ employees)

```
                    ┌────────────────────────────────┐
                    │          Internet              │
                    └────────────┬───────────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │   Multi-Region CDN + WAF     │
                  │   (Akamai, Cloudflare)       │
                  └──────────────┬───────────────┘
                                 │
                  ┌──────────────┴────────────────┐
                  │                               │
                  ▼                               ▼
       ┌──────────────────┐          ┌──────────────────┐
       │  On-Prem DC      │          │  Multi-Cloud     │
       │  - Firewalls     │          │  - AWS           │
       │  - IDS/IPS       │          │  - Azure         │
       │  - Core Servers  │          │  - GCP           │
       └────────┬─────────┘          └────────┬─────────┘
                │                              │
                └───────────┬──────────────────┘
                            │
                            ▼
              ┌──────────────────────────┐
              │   Kafka Event Streaming  │
              │   (Multi-Region)         │
              └──────────┬───────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  JanuSec    │  │   Splunk    │  │  Data Lake  │
│  (K8s 10+   │  │   (SIEM)    │  │  (S3 +      │
│   pods)     │  │             │  │  Databricks)│
│             │  │             │  │             │
│ - Real-time │  │ - Storage   │  │ - Analytics │
│ - HopGraph  │  │ - Dashboards│  │ - ML        │
│ - AI Triage │  │ - Compliance│  │ - BI        │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │  SOAR Automation │
              │  (ServiceNow +   │
              │   Phantom)       │
              └──────────────────┘
```

**Data Sources (Comprehensive):**
- **Network:** Firewalls (multi-vendor), IDS/IPS, DNS, Proxy, VPN
- **Endpoint:** EDR (CrowdStrike), Sysmon, osquery, Wazuh
- **Cloud:** AWS (CloudTrail, GuardDuty, VPC Flow), Azure, GCP
- **Email:** O365, Gmail (multi-tenant)
- **IAM:** Okta, Azure AD, Google Workspace, Active Directory
- **Applications:** Web servers, databases, API gateways
- **SBOM:** Software composition analysis

**Storage Tiers:**
- **Real-time (0-7 days):** JanuSec (10 TB NVMe cluster)
- **Hot (8-30 days):** Splunk (50 TB SSD)
- **Warm (31-90 days):** S3 Standard (200 TB)
- **Cold (91-365 days):** S3 Glacier (2 PB)
- **Archive (1+ years):** S3 Deep Archive (10 PB)
- **Analytics:** Databricks Lakehouse (all data, queryable)

**Cost:** ~$100k-$200k/month (fully loaded)

---

## CONCLUSION

### Key Recommendations

**1. Deployment Location:**
- ✅ **Behind firewall (Scenario 3)** for 90% of deployments
- ✅ **Parallel to SIEM (Scenario 4)** if you have existing SIEM
- ✅ **Multi-tier (Scenario 5)** for large enterprises

**2. Minimum Data Sources:**
- ☑ Network logs (firewall or IDS)
- ☑ Endpoint logs (Sysmon or EDR)
- ☑ Cloud logs (CloudTrail or Azure Activity)
- ☑ **At least 3 domains** for effective correlation

**3. Connectors:**
- ✅ **Direct integration (Beats)** for best performance
- ✅ **Via ELK** if you already have Elastic
- ⚠️ **Via Wazuh** if you need HIDS features

**4. Storage:**
- ✅ **Local NVMe RAID 10** for hot data (<10TB)
- ✅ **S3 tiering** for cold/compliance data
- ✅ **Data lakehouse** for big data analytics (optional)

**5. Federated Learning:**
- ✅ **Implement threat intel sharing** (high value, low risk)
- ⚠️ **Consider FP feedback** (future enhancement)
- ❌ **Avoid federated training** (too complex, privacy risks)

### Final Architecture for Most Organizations

**Recommended: Scenario 3 + Data Lake Tiering**

```
Internet ──► CDN ──► Firewall ──► Internal Network
                                         │
                         ┌───────────────┼───────────────┐
                         │               │               │
                         ▼               ▼               ▼
                    Endpoints         Servers         Cloud
                         │               │               │
                         └───────────────┼───────────────┘
                                         │
                                         ▼
                              ┌──────────────────┐
                              │  Log Forwarders  │
                              │  (Filebeat)      │
                              └────────┬─────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │  JanuSec         │
                              │  (Behind FW)     │
                              │  - Real-time     │
                              │  - 7 days NVMe   │
                              └────────┬─────────┘
                                       │
                                       ├──► Alerts ──► SOAR
                                       │
                                       └──► Archive ──► S3 (Glacier)
                                                         │
                                                         └──► Databricks (Analytics)
```

**This architecture provides:**
- ✅ Real-time multi-domain correlation
- ✅ Cost-effective tiered storage
- ✅ Compliance-ready long-term retention
- ✅ Optional analytics for advanced use cases
- ✅ Simple deployment (no network reconfiguration)
- ✅ Scalable (cloud-native, Kubernetes-ready)

---

**Document End**
