# JanuSec Distribution & Deployment Guide for Customers

**Version:** 1.0
**Last Updated:** 2025-01-22
**Target Audience:** Cyberstash developers, SOC teams, Security vendors

---

## 📋 EXECUTIVE SUMMARY

### What is JanuSec?

**JanuSec** is an AI-powered threat triage platform that reduces security alert analysis time by **97.6%** (from 20 minutes to 30 seconds per alert) while saving **$240K+/year** in analyst costs.

**Key Features:**
- 21-stage automated threat detection pipeline
- LLM-powered deep analysis (Tier 1 + Tier 2)
- HopGraph attack chain visualization
- Domain-specific playbooks (network vs endpoint)
- Historical incident learning
- Multi-cloud deployment (AWS, Azure, GCP, on-prem)
- Bring-your-own LLM (Claude, GPT, Ollama, custom fine-tuned models)

---

## 🎯 TARGET CUSTOMERS

### Who Should Use JanuSec?

| Customer Segment | Use Case | Expected Value |
|-----------------|----------|----------------|
| **MSSPs (Managed Security Service Providers)** | Multi-tenant SOC triage | $500K+/year savings per 1000 customers |
| **Enterprise SOC Teams (500+ employees)** | Internal threat triage | $240K/year savings, 97% faster |
| **Security Vendors (EDR/XDR)** | Embedded triage engine | Differentiation, reduce analyst burden |
| **Financial Services** | Regulatory compliance + fast incident response | Meet SLA requirements, audit trail |
| **Healthcare** | HIPAA-compliant threat detection | Data privacy (on-prem/air-gapped) |
| **Government/Defense** | Classified network security | Air-gapped deployment, custom models |
| **Mid-market Companies (100-500 employees)** | Affordable SOC-in-a-box | $50K/year savings vs hiring analysts |

### Specific Companies That Would Benefit:

**MSSPs:**
- Arctic Wolf
- Secureworks
- Rapid7
- CrowdStrike Falcon Complete
- Sophos MDR

**Enterprise Customers:**
- Fortune 500 companies with 24/7 SOC
- Banks, insurance companies (regulatory requirements)
- Critical infrastructure (energy, utilities)

**Security Vendors:**
- SentinelOne, Palo Alto Networks, Fortinet
- Could embed JanuSec as "AI Analyst" feature

**Cyberstash Use Case:**
- Internal deployment for their own customers
- White-label and resell to their client base
- Integration with existing Cyberstash platform

---

## 📦 DISTRIBUTION OPTIONS

### Option 1: Docker Image (RECOMMENDED)

**Best For:** Quick deployment, cloud environments, multi-cloud

**Distribution Method:**
```bash
# Public Registry (Docker Hub)
docker pull janusec/platform:latest

# Private Registry (for paid customers)
docker pull registry.janusec.com/platform:enterprise

# With authentication
docker login registry.janusec.com
docker pull janusec/platform:1.0.0
```

**Pros:**
- ✅ Easy deployment (1 command)
- ✅ Version control built-in
- ✅ Cross-platform (Windows, Linux, macOS)
- ✅ Isolated environment
- ✅ Easy updates (`docker pull` new version)

**Cons:**
- ⚠️ Requires Docker installed
- ⚠️ ~2.5 GB download size

**Size:** 2.5 GB compressed, 6 GB uncompressed

---

### Option 2: Terraform Infrastructure-as-Code (RECOMMENDED for Enterprise)

**Best For:** Enterprise deployment, compliance, repeatable infrastructure

**Distribution Method:**
```bash
# GitHub repository (private for customers)
git clone https://github.com/janusec/terraform-aws
git clone https://github.com/janusec/terraform-azure
git clone https://github.com/janusec/terraform-gcp

# Terraform Registry
terraform init
terraform apply -var-file="customer.tfvars"
```

**What's Included:**
- Full infrastructure definition (VPC, subnets, security groups)
- Auto-scaling groups
- Load balancers
- Database setup (RDS, Aurora, or PostgreSQL)
- Monitoring (CloudWatch, Azure Monitor, Stackdriver)
- Secrets management (AWS Secrets Manager, Azure Key Vault)

**Pros:**
- ✅ Automated deployment
- ✅ Compliance-friendly (audit trail)
- ✅ Version controlled infrastructure
- ✅ Multi-cloud support
- ✅ Easy to customize

**Cons:**
- ⚠️ Requires Terraform knowledge
- ⚠️ More complex initial setup

**Size:** ~50 MB (source code + config)

---

### Option 3: Source Code (GitHub Private Repository)

**Best For:** Developers, customization, on-prem air-gapped deployments

**Distribution Method:**
```bash
# GitHub private repository with customer access
git clone https://github.com/janusec/platform-private.git

# Or download ZIP from release page
wget https://github.com/janusec/platform/releases/download/v1.0.0/janusec-v1.0.0.zip

# Or via Google Drive (for customers without GitHub access)
# Share link: https://drive.google.com/file/d/XXXXX/view?usp=sharing
```

**What's Included:**
- Complete source code (Python, JavaScript, Terraform)
- Requirements.txt and package.json
- Documentation
- Example configurations
- Test data

**Pros:**
- ✅ Full customization ability
- ✅ Can audit entire codebase
- ✅ Works in air-gapped environments
- ✅ No vendor lock-in

**Cons:**
- ⚠️ Requires Python/Node.js expertise
- ⚠️ Customer responsible for dependencies
- ⚠️ More complex deployment

**Size:** ~500 MB (source + dependencies)

---

### Option 4: Virtual Machine Image (VMware/VirtualBox)

**Best For:** Quick POC, demo environments, on-prem without Docker

**Distribution Method:**
```bash
# Download OVA file
wget https://downloads.janusec.com/janusec-v1.0.0.ova

# Or via Google Drive
# Share link: https://drive.google.com/file/d/XXXXX/view?usp=sharing

# Import to VMware/VirtualBox
# Pre-configured Ubuntu 22.04 with JanuSec installed
```

**Pros:**
- ✅ Zero configuration
- ✅ Works immediately
- ✅ Good for POC/demo
- ✅ Isolated from host system

**Cons:**
- ⚠️ Large file size (8-10 GB)
- ⚠️ Not suitable for production
- ⚠️ Slower than native deployment

**Size:** 8-10 GB

---

### Option 5: Kubernetes Helm Chart (RECOMMENDED for Cloud-Native)

**Best For:** Kubernetes environments, microservices architecture

**Distribution Method:**
```bash
# Add Helm repository
helm repo add janusec https://charts.janusec.com
helm repo update

# Install with default values
helm install janusec janusec/platform

# Or with custom values
helm install janusec janusec/platform -f custom-values.yaml
```

**What's Included:**
- Kubernetes manifests
- Service definitions
- Ingress configurations
- Persistent volume claims
- ConfigMaps and Secrets

**Pros:**
- ✅ Cloud-native deployment
- ✅ Auto-scaling built-in
- ✅ High availability
- ✅ Easy rollbacks

**Cons:**
- ⚠️ Requires Kubernetes cluster
- ⚠️ More complex than Docker

**Size:** ~100 MB (Helm chart)

---

## 📊 SIZE & SYSTEM REQUIREMENTS

### JanuSec Platform Size

| Component | Size |
|-----------|------|
| **Source Code Only** | ~100 MB |
| **Source + Python Dependencies** | ~500 MB |
| **Docker Image (compressed)** | ~2.5 GB |
| **Docker Image (uncompressed)** | ~6 GB |
| **VM Image (OVA)** | ~8-10 GB |
| **With Sample Data** | +500 MB |

**Recommended Distribution Size:**
- **For Developers:** 500 MB (source + deps)
- **For Customers:** 2.5 GB (Docker image)
- **For POC/Demo:** 8 GB (VM image)

---

### Minimum System Requirements

**For Development/Testing (Single User):**
```
CPU: 2 cores
RAM: 4 GB
Disk: 20 GB
OS: Ubuntu 22.04, Windows 10+, macOS 12+
Python: 3.11+
Database: SQLite (included) or PostgreSQL 14+
```

**For Production (Small - up to 1,000 alerts/day):**
```
CPU: 4 cores
RAM: 8 GB
Disk: 100 GB SSD
OS: Ubuntu 22.04 LTS (recommended)
Database: PostgreSQL 14+ or Neon Serverless
Network: 1 Gbps
```

**For Production (Medium - up to 10,000 alerts/day):**
```
CPU: 8 cores
RAM: 16 GB
Disk: 500 GB SSD
Database: PostgreSQL 14+ with read replicas
Load Balancer: Yes
Auto-scaling: Recommended
```

**For Production (Large - up to 100,000 alerts/day):**
```
CPU: 16+ cores (distributed)
RAM: 32+ GB
Disk: 1 TB+ SSD
Database: PostgreSQL with partitioning + read replicas
Kubernetes: Recommended
Redis: Required for caching
```

**For MSSP (Multi-Tenant - 100+ customers):**
```
CPU: 32+ cores (distributed)
RAM: 64+ GB
Disk: 2 TB+ SSD
Database: Managed PostgreSQL (Aurora, Cloud SQL)
Kubernetes: Required
Redis Cluster: Required
Object Storage: S3/Azure Blob for artifacts
CDN: Recommended for frontend
```

---

### Cloud Instance Recommendations

**AWS:**
```
Small: t3.large (2 vCPU, 8 GB RAM) - $60/month
Medium: t3.xlarge (4 vCPU, 16 GB RAM) - $120/month
Large: c5.2xlarge (8 vCPU, 16 GB RAM) - $250/month
MSSP: c5.4xlarge (16 vCPU, 32 GB RAM) - $500/month
```

**Azure:**
```
Small: Standard_D2s_v3 (2 vCPU, 8 GB RAM) - $70/month
Medium: Standard_D4s_v3 (4 vCPU, 16 GB RAM) - $140/month
Large: Standard_D8s_v3 (8 vCPU, 32 GB RAM) - $280/month
```

**GCP:**
```
Small: n2-standard-2 (2 vCPU, 8 GB RAM) - $65/month
Medium: n2-standard-4 (4 vCPU, 16 GB RAM) - $130/month
Large: n2-standard-8 (8 vCPU, 32 GB RAM) - $260/month
```

---

## 🔑 CUSTOMER API TOKEN CONFIGURATION

### Bring Your Own LLM API Keys

JanuSec supports multiple LLM providers. Customers can use their own API keys to avoid vendor lock-in and control costs.

### Configuration File: `.env`

```bash
# Option 1: Anthropic Claude (RECOMMENDED)
DEFAULT_CLIENT=anthropic
ANTHROPIC_API_KEY=sk-ant-api03-XXXXX

# Option 2: OpenAI GPT
DEFAULT_CLIENT=openai
OPENAI_API_KEY=sk-XXXXX

# Option 3: Local Ollama (No API key needed)
DEFAULT_CLIENT=ollama
OSS_MODELS_ENABLE=true
OSS_MODELS_BACKEND=ollama
OLLAMA_DEFAULT_MODEL=llama3:8b

# Option 4: Azure OpenAI
DEFAULT_CLIENT=azure_openai
AZURE_OPENAI_API_KEY=XXXXX
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_NAME=gpt-4o

# Option 5: Custom Fine-Tuned Model (via OpenAI-compatible API)
DEFAULT_CLIENT=custom
CUSTOM_LLM_ENDPOINT=https://your-model.com/v1/chat/completions
CUSTOM_LLM_API_KEY=XXXXX
```

### How Customers Get API Keys

**Anthropic Claude:**
1. Sign up at https://console.anthropic.com
2. Navigate to API Keys section
3. Create new API key
4. Copy and paste into JanuSec `.env` file

**Cost:** $0.0005/request (Claude Haiku) to $0.01/request (Claude Opus)

**OpenAI GPT:**
1. Sign up at https://platform.openai.com
2. Add payment method
3. Generate API key
4. Copy and paste into JanuSec `.env` file

**Cost:** $0.0005/request (GPT-3.5) to $0.03/request (GPT-4)

**Azure OpenAI (Enterprise):**
1. Create Azure account
2. Request Azure OpenAI access (approval required)
3. Create resource in Azure Portal
4. Deploy model (GPT-4, GPT-3.5-turbo, etc.)
5. Copy endpoint and API key

**Cost:** Similar to OpenAI, but billed through Azure

---

## 🤖 RECOMMENDED LLM MODELS

### Tier 1: Cloud API Models (Best Performance)

| Model | Provider | Speed | Quality | Cost/Request | Use Case |
|-------|----------|-------|---------|--------------|----------|
| **Claude Haiku** | Anthropic | ⚡⚡⚡ | ⭐⭐⭐⭐ | $0.0005 | **RECOMMENDED** - Best balance |
| **Claude Sonnet** | Anthropic | ⚡⚡ | ⭐⭐⭐⭐⭐ | $0.003 | Deep analysis, complex threats |
| **GPT-4o-mini** | OpenAI | ⚡⚡⚡ | ⭐⭐⭐⭐ | $0.0002 | Budget-conscious deployments |
| **GPT-4o** | OpenAI | ⚡⚡ | ⭐⭐⭐⭐⭐ | $0.01 | Maximum accuracy needed |
| **GPT-3.5-turbo** | OpenAI | ⚡⚡⚡ | ⭐⭐⭐ | $0.0005 | Fast triage only |

**Why Claude Haiku (RECOMMENDED):**
- ✅ Best speed/quality/cost ratio
- ✅ Strong reasoning for security context
- ✅ Follows instructions precisely
- ✅ Lower hallucination rate than GPT
- ✅ Good at structured output

**When to Use GPT-4o:**
- Need maximum accuracy
- Complex multi-step reasoning
- Budget is not primary concern

**When to Use GPT-3.5-turbo:**
- Extreme cost sensitivity
- Simple triage only (not deep analysis)

---

### Tier 2: Open Source Local Models (Privacy + No API Costs)

| Model | Size | Speed (CPU) | Speed (GPU) | Quality | Use Case |
|-------|------|-------------|-------------|---------|----------|
| **Llama 3 8B** | 4.7 GB | ⚡ | ⚡⚡⚡ | ⭐⭐⭐ | **RECOMMENDED for Ollama** |
| **Llama 3 70B** | 40 GB | ❌ | ⚡⚡ | ⭐⭐⭐⭐⭐ | Maximum accuracy, needs GPU |
| **Mistral 7B** | 4.1 GB | ⚡ | ⚡⚡⭐ | ⭐⭐⭐ | Alternative to Llama 3 8B |
| **Phi-3 Mini** | 2.3 GB | ⚡⚡ | ⚡⚡⚡ | ⭐⭐ | Fastest, lowest accuracy |
| **Mixtral 8x7B** | 26 GB | ❌ | ⚡⚡ | ⭐⭐⭐⭐ | Good balance if GPU available |

**Why Llama 3 8B (RECOMMENDED for local):**
- ✅ Good balance of size vs quality
- ✅ Fits in 8 GB RAM
- ✅ Fast on GPU (3-8 sec)
- ✅ Meta-licensed (permissive)
- ✅ Works with Ollama out-of-box

**When to Use Llama 3 70B:**
- Have GPU with 48+ GB VRAM
- Need maximum accuracy
- Data privacy is critical

**When to Use Phi-3 Mini:**
- Very limited resources
- Need fastest possible response
- Accuracy less important

---

### Tier 3: Fine-Tuned Security Models (RECOMMENDED for Enterprise)

**Option A: Fine-Tune Llama 3 on Security Data**

```bash
# Base model: Llama 3 8B
# Fine-tuning data: 10,000+ security incidents with analyst decisions
# Training time: 4-8 hours on A100 GPU
# Cost: ~$200 one-time

# Result: 15-20% accuracy improvement on security tasks
# Deployment: Same as Llama 3 8B (4.7 GB)
```

**Why Fine-Tune:**
- ✅ Better at security-specific terminology (IOCs, MITRE, CVE)
- ✅ Learns customer's specific threat patterns
- ✅ Reduces false positives
- ✅ Can encode compliance requirements
- ✅ One-time cost, then free to run

**Fine-Tuning Dataset (Recommended):**
- Historical incidents from customer's SOC (if available)
- Public security datasets:
  - MITRE ATT&CK descriptions
  - CVE descriptions + severity
  - Security Stack Exchange Q&A
  - Security blog posts (Krebs, Schneier, SANS)
- Synthetic data generated from JanuSec's pipeline

**Training Services:**
- HuggingFace (easiest): $50-200
- Replicate: $100-300
- Self-hosted (if GPU available): Free

---

### Tier 4: Commercial Security-Specific Models

| Model | Provider | Cost | Quality | Availability |
|-------|----------|------|---------|--------------|
| **SecLM** | SecOps.ai | $0.01/req | ⭐⭐⭐⭐ | Closed Beta |
| **ThreatGPT** | ThreatConnect | $0.02/req | ⭐⭐⭐⭐⭐ | Enterprise only |
| **CyberBERT** | Open source | Free | ⭐⭐⭐ | HuggingFace |

**Why NOT Recommended (Yet):**
- ⚠️ Most are not publicly available
- ⚠️ Very expensive compared to Claude/GPT
- ⚠️ Limited evidence of superior performance
- ⚠️ Vendor lock-in

**When to Consider:**
- Customer has existing relationship with security AI vendor
- Regulatory requirement for "security-specific" model
- Budget is not a constraint

---

## 🔌 MCP (Model Context Protocol) Integration

### What is MCP?

**MCP (Model Context Protocol)** is an open standard for connecting LLMs to external data sources (threat intel feeds, databases, APIs).

**Use Cases for JanuSec:**
- Pull latest IOCs from VirusTotal, AlienVault OTX
- Query internal SIEM for correlated events
- Fetch CVE details from NVD
- Check domain reputation from threat intel feeds

### How to Configure MCP in JanuSec

**1. Install MCP Server (if using custom threat intel):**

```bash
# Install MCP SDK
pip install mcp-server

# Create MCP server config
cat > mcp_config.json <<EOF
{
  "servers": {
    "virustotal": {
      "url": "https://www.virustotal.com/api/v3",
      "api_key": "YOUR_VT_API_KEY"
    },
    "otx": {
      "url": "https://otx.alienvault.com/api/v1",
      "api_key": "YOUR_OTX_KEY"
    }
  }
}
EOF
```

**2. Configure JanuSec to Use MCP:**

```bash
# In .env file
ENABLE_MCP=true
MCP_CONFIG_PATH=/path/to/mcp_config.json

# Specify which MCP tools to enable
MCP_TOOLS=virustotal,otx,misp,opencti
```

**3. LLM Will Automatically Use MCP:**

When analyzing an artifact, LLM will:
1. Extract IOCs (IP, domain, hash)
2. Query MCP servers for threat intel
3. Include results in summary

**Example:**

```
THREAT INTELLIGENCE LOOKUP (via MCP):

SHA256: 9bf41199f05fa1de8be5b84c6ef6e0a37f7b3d3f7a6e5d4c3b2a1f0e9d8c7b6a

VirusTotal: 45/70 vendors flagged as malicious
  - First seen: 2025-01-15
  - Community votes: 23 malicious, 0 benign
  - Tags: trojan, emotet, credential-stealer

AlienVault OTX: 3 pulses mention this hash
  - "Emotet Campaign 2025-01" (5 days ago)
  - Associated IPs: 185.220.101.45, 192.168.1.50
  - C2 domains: evil-c2.com, malware-drop.net
```

### MCP vs Fine-Tuning

| Approach | When to Use | Pros | Cons |
|----------|-------------|------|------|
| **MCP** | Real-time threat intel needed | ✅ Always up-to-date<br>✅ No training required | ⚠️ Slower (API calls)<br>⚠️ Depends on external services |
| **Fine-Tuning** | Customer-specific patterns | ✅ Fast (no API calls)<br>✅ Works offline | ⚠️ Need training data<br>⚠️ Static (needs retraining) |
| **Both** | **RECOMMENDED** | ✅ Best of both worlds | ⚠️ More complex setup |

---

## 📤 DISTRIBUTION METHODS (How to Send)

### Method 1: Private GitHub Repository (RECOMMENDED)

**Setup:**
1. Create private repository: `github.com/janusec/platform-private`
2. Add customer as collaborator
3. Customer clones repository

**Pros:**
- ✅ Version control built-in
- ✅ Easy updates (`git pull`)
- ✅ Customer can create branches for customizations
- ✅ Free (for up to 3 collaborators on GitHub Free)

**Cons:**
- ⚠️ Customer needs GitHub account
- ⚠️ Source code is visible (not compiled)

---

### Method 2: Docker Registry (RECOMMENDED for Production)

**Setup:**
1. Push image to private registry
2. Provide customer with credentials
3. Customer pulls image

**Example:**
```bash
# Your side:
docker tag janusec/platform:latest registry.janusec.com/customer-abc/platform:1.0.0
docker push registry.janusec.com/customer-abc/platform:1.0.0

# Customer side:
docker login registry.janusec.com -u customer-abc -p PASSWORD
docker pull registry.janusec.com/customer-abc/platform:1.0.0
docker run -p 8000:8000 registry.janusec.com/customer-abc/platform:1.0.0
```

**Pros:**
- ✅ Easy deployment
- ✅ Versioned releases
- ✅ Can revoke access anytime
- ✅ Supports air-gapped (customer can save image locally)

**Cons:**
- ⚠️ Need to host private registry (~$10-50/month)

---

### Method 3: Google Drive / OneDrive (For POC/Demo)

**Setup:**
1. Create ZIP or OVA file
2. Upload to Google Drive
3. Share link with customer

**Example:**
```bash
# Create distribution package
tar -czf janusec-v1.0.0.tar.gz \
  --exclude='.git' \
  --exclude='__pycache__' \
  --exclude='.venv' \
  --exclude='node_modules' \
  .

# Upload to Google Drive
# Share link: https://drive.google.com/file/d/XXXXX/view?usp=sharing
```

**Pros:**
- ✅ No technical setup needed
- ✅ Easy for non-technical customers
- ✅ Good for POC/trials

**Cons:**
- ⚠️ Not suitable for production
- ⚠️ Large file size (download can be slow)
- ⚠️ No version control

**Size Limit:**
- Google Drive: Free (15 GB), Paid ($2/month for 100 GB)
- OneDrive: Free (5 GB), Paid ($2/month for 100 GB)

---

### Method 4: Cloud Marketplace (RECOMMENDED for SaaS)

**AWS Marketplace:**
- List JanuSec as AMI (Amazon Machine Image)
- Customers launch with 1-click
- Billing integrated with AWS

**Azure Marketplace:**
- List JanuSec as VM offer
- Customers deploy via Azure Portal
- Billing integrated with Azure

**Pros:**
- ✅ Built-in billing/licensing
- ✅ Trusted distribution channel
- ✅ 1-click deployment for customers
- ✅ Automatic updates

**Cons:**
- ⚠️ AWS/Azure take 20% commission
- ⚠️ Approval process (2-4 weeks)

---

### Method 5: Terraform Module (RECOMMENDED for Enterprise)

**Setup:**
1. Publish Terraform module to Terraform Registry
2. Customer references module in their IaC

**Example:**
```hcl
# Customer's main.tf
module "janusec" {
  source  = "janusec/platform/aws"
  version = "1.0.0"

  instance_type = "t3.large"
  database_size = "db.t3.medium"
  api_key_anthropic = var.anthropic_api_key
}
```

**Pros:**
- ✅ Infrastructure as Code
- ✅ Version controlled
- ✅ Easy to customize
- ✅ Multi-cloud support

**Cons:**
- ⚠️ Requires Terraform knowledge

---

## 📋 CUSTOMER ONBOARDING CHECKLIST

### Step 1: Qualify Customer

- [ ] Confirm customer has need (SOC team, 100+ alerts/day)
- [ ] Confirm budget ($5K-50K/year depending on deployment)
- [ ] Confirm technical capability (can deploy Docker/Terraform)
- [ ] Confirm LLM provider preference (Claude, GPT, Ollama, custom)

### Step 2: Provide Trial/POC

- [ ] Send Docker image or VM (Google Drive)
- [ ] Provide trial license key (30 days)
- [ ] Share documentation (QUICK_START.md, API_REFERENCE.md)
- [ ] Schedule demo call

### Step 3: Customer Setup

- [ ] Customer deploys JanuSec (Docker/Terraform/VM)
- [ ] Customer configures LLM API keys
- [ ] Customer uploads test CSV (provided by you)
- [ ] Verify: Platform starts, LLM summaries generate

### Step 4: Integration

- [ ] Integrate with customer's SIEM (Splunk, Sentinel, etc.)
- [ ] Configure threat intel feeds (VirusTotal, OTX, MISP)
- [ ] Set up alerting (Slack, PagerDuty, email)
- [ ] Train customer's analysts (1-hour session)

### Step 5: Production Go-Live

- [ ] Customer purchases license
- [ ] Upgrade to production deployment (auto-scaling, HA)
- [ ] Configure monitoring (Prometheus, Grafana)
- [ ] Set up backup/DR
- [ ] Hand off to customer's operations team

### Step 6: Ongoing Support

- [ ] Monthly check-in calls
- [ ] Provide updates (new features, security patches)
- [ ] Monitor usage metrics (number of alerts processed)
- [ ] Upsell opportunities (additional features, more users)

---

## 💰 PRICING RECOMMENDATION

### Licensing Models

**Option 1: Per-Analyst License**
- $5,000/year per analyst
- Unlimited alerts
- Includes all features
- **Target:** Enterprise SOC teams

**Option 2: Consumption-Based**
- $0.10 per alert analyzed
- Volume discounts (>10K alerts: $0.05/alert)
- Pay-as-you-go
- **Target:** Variable workload, mid-market

**Option 3: Flat-Rate SaaS**
- $10,000/year (up to 10,000 alerts/month)
- $25,000/year (up to 50,000 alerts/month)
- $50,000/year (unlimited)
- **Target:** Predictable pricing, enterprise

**Option 4: White-Label for MSSPs**
- $100,000/year base fee
- Unlimited end customers
- Customer can rebrand as their own
- **Target:** Cyberstash, other MSSPs

### What's Included vs Add-Ons

**Included:**
- ✅ Core platform (21-stage pipeline, LLM summaries)
- ✅ Documentation
- ✅ Community support (Slack channel)
- ✅ Security updates

**Add-Ons:**
- 💰 Dedicated support ($10K/year)
- 💰 Custom integrations ($5K-20K one-time)
- 💰 Fine-tuned model training ($5K one-time)
- 💰 On-site training ($2K/day)
- 💰 Professional services (custom development)

---

## 🎯 RECOMMENDED DISTRIBUTION STRATEGY

### For Cyberstash:

**Recommended Approach:**
1. **Distribution:** Docker image via private registry
2. **Deployment:** Terraform modules for AWS/Azure
3. **LLM:** Customer brings own API key (Claude Haiku recommended)
4. **Licensing:** White-label for their customers
5. **Support:** You provide L3 support, Cyberstash provides L1/L2

**Package Contents:**
```
janusec-cyberstash-v1.0.0/
├── docker/
│   ├── docker-compose.yml
│   ├── Dockerfile
│   └── .env.example
├── terraform/
│   ├── aws/
│   ├── azure/
│   └── gcp/
├── docs/
│   ├── QUICK_START.md
│   ├── API_REFERENCE.md
│   ├── TROUBLESHOOTING.md
│   └── LLM_CONFIGURATION.md
├── tests/
│   └── test_data/
└── LICENSE.txt
```

**Size:** ~500 MB (Docker image 2.5 GB separate download)

**Delivery Method:**
1. Private GitHub repository (source code + Terraform)
2. Docker Hub private registry (images)
3. Google Drive backup (for air-gapped customers)

---

## ✅ QUICK START FOR CUSTOMERS

```bash
# Step 1: Pull Docker image
docker pull registry.janusec.com/cyberstash/platform:1.0.0

# Step 2: Configure API key
cat > .env <<EOF
DEFAULT_CLIENT=anthropic
ANTHROPIC_API_KEY=sk-ant-api03-YOUR-KEY-HERE
EOF

# Step 3: Start platform
docker-compose up -d

# Step 4: Open browser
http://localhost:8000

# Step 5: Upload CSV and test!
```

**Total time: 5 minutes** ⚡

---

**Need help deciding distribution strategy? Contact me for personalized recommendation based on your customer profile.**
