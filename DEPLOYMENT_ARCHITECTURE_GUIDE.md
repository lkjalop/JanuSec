# JanuSec Platform: Deployment Architecture Guide
## Edge/Private vs Public/Online Deployment Strategies

## Executive Summary

JanuSec supports **three primary deployment models**:
1. **Edge/Private (Air-Gapped)** - On-premises, no internet connectivity
2. **Public/Online (Cloud-Native)** - Fully cloud-hosted (AWS/Azure/GCP)
3. **Hybrid (Best of Both)** - Edge collectors + cloud analytics

This guide provides architecture blueprints, onboarding steps, and decision frameworks for each model.

**Recommended Approach**: Start with **Hybrid** for maximum flexibility and gradual migration path.

---

## Table of Contents

1. [Deployment Model Comparison](#section-1-deployment-model-comparison)
2. [Edge/Private Deployment Architecture](#section-2-edgeprivate-deployment-architecture)
3. [Public/Online Deployment Architecture](#section-3-publiconline-deployment-architecture)
4. [Hybrid Deployment Architecture](#section-4-hybrid-deployment-architecture)
5. [Onboarding Procedures](#section-5-onboarding-procedures)
6. [Security Considerations](#section-6-security-considerations)
7. [Scaling & Performance](#section-7-scaling--performance)
8. [Cost Analysis](#section-8-cost-analysis)
9. [Decision Framework](#section-9-decision-framework)

---

## SECTION 1: DEPLOYMENT MODEL COMPARISON

### Quick Reference Matrix

| Capability | Edge/Private | Public/Online | Hybrid |
|-----------|--------------|---------------|--------|
| **Data Residency** | On-prem only | Cloud provider | Configurable |
| **LLM Capability** | Ollama local only | Full Claude/GPT-4 | Both (fallback) |
| **Internet Required** | No | Yes | Optional |
| **Latency** | <10ms local | 50-200ms API calls | Mixed |
| **Initial Cost** | High (hardware) | Low (pay-as-go) | Medium |
| **Operational Cost** | Low (fixed) | Variable (usage) | Optimized |
| **Compliance** | SOC2, HIPAA, PCI | Depends on CSP | Best of both |
| **Scaling** | Manual (hardware) | Auto-scale | Auto-scale analytics |
| **HA/DR** | Complex (on-prem) | Built-in (cloud) | Cloud HA + edge resilience |
| **Sensor Latency** | Best (local) | Varies | Best (edge collection) |
| **Update Complexity** | Manual | Managed | Semi-automated |

### Use Cases by Deployment Model

#### Edge/Private Best For:
- Government/defense (air-gapped requirements)
- Healthcare (HIPAA strict data residency)
- Financial services (PCI-DSS on-prem mandate)
- Industrial/OT (no external connectivity)
- High-volume network monitoring (100GB+/day pcap)

#### Public/Online Best For:
- SaaS companies (cloud-native)
- Startups (low upfront cost)
- Global distributed teams
- Rapid prototyping/POC
- Multi-cloud environments (AWS+Azure+GCP)

#### Hybrid Best For:
- Enterprises with compliance + cloud strategy
- Gradual cloud migration
- Edge collection + centralized analytics
- Cost optimization (local preprocessing, cloud AI)
- Multi-site deployments

---

## SECTION 2: EDGE/PRIVATE DEPLOYMENT ARCHITECTURE

### Architecture Diagram (ASCII)

```
┌─────────────────────────────────────────────────────────────┐
│                    ON-PREMISES DEPLOYMENT                    │
│                     (Air-Gapped/Private)                     │
└─────────────────────────────────────────────────────────────┘

┌──────────────────────┐
│   Data Sources       │
│  ┌────────────────┐  │
│  │ Zeek/Suricata  │──┼─┐
│  │ Sysmon/ETW     │──┼─┤
│  │ Email Logs     │──┼─┤
│  │ Cloud APIs     │──┼─┤  ┌─────────────────────────────┐
│  │ CSV Uploads    │──┼─┼─>│   JanuSec Edge Cluster      │
│  └────────────────┘  │ │  │  ┌────────────────────────┐ │
└──────────────────────┘ │  │  │ Ingestion Layer        │ │
                         │  │  │  - Zeek Adapter        │ │
                         │  │  │  - CSV Handler         │ │
                         │  │  │  - API Collectors      │ │
                         │  │  └────────────────────────┘ │
                         │  │                             │
                         │  │  ┌────────────────────────┐ │
                         │  │  │ Event Pipeline (14+)   │ │
                         │  │  │  - Baseline Detection  │ │
                         │  │  │  - Regex Rules         │ │
                         │  │  │  - Correlation Engine  │ │
                         │  │  │  - Factor Synthesis    │ │
                         │  │  └────────────────────────┘ │
                         │  │                             │
                         │  │  ┌────────────────────────┐ │
                         │  │  │ AI/ML Layer (Local)    │ │
                         │  │  │  - Ollama (LLaMA3)     │ │
                         │  │  │  - Local embeddings    │ │
                         │  │  │  - Deterministic LLM   │ │
                         │  │  │  - No external calls   │ │
                         │  │  └────────────────────────┘ │
                         │  │                             │
                         │  │  ┌────────────────────────┐ │
                         │  │  │ Storage Layer          │ │
                         │  │  │  - PostgreSQL (local)  │ │
                         │  │  │  - Redis (cache)       │ │
                         │  │  │  - Vector DB (Weaviate)│ │
                         │  │  │  - SQLite (hopgraph)   │ │
                         │  │  └────────────────────────┘ │
                         │  └─────────────────────────────┘
                         │
                         │  ┌─────────────────────────────┐
                         └─>│   Analyst Workstations      │
                            │  - Web UI (internal)        │
                            │  - CSV Upload Interface     │
                            │  - HopGraph Visualizer      │
                            │  - Report Export (offline)  │
                            └─────────────────────────────┘
```

### Hardware Requirements

#### Minimum Configuration (POC/Small Deployment)
- **Compute**: 8 vCPU, 32GB RAM
- **Storage**: 500GB SSD (events) + 1TB HDD (archive)
- **Network**: 1Gbps NIC
- **Capacity**: ~1K events/sec, 10K assets

#### Recommended Configuration (Production)
- **API/Web Tier**: 16 vCPU, 64GB RAM x 2 nodes (HA)
- **Pipeline Workers**: 32 vCPU, 128GB RAM x 3 nodes (parallel processing)
- **Ollama/LLM Node**: 16 vCPU, 64GB RAM, 1x NVIDIA A100 (or 2x RTX 4090)
- **Database**: 16 vCPU, 128GB RAM, 2TB NVMe SSD (PostgreSQL primary)
- **Database Replica**: Same spec (read replica for queries)
- **Redis Cache**: 8 vCPU, 32GB RAM
- **Vector DB**: 16 vCPU, 64GB RAM, 1TB SSD
- **Total**: ~7-8 nodes for full HA deployment
- **Capacity**: ~10K events/sec, 100K+ assets

#### Enterprise Configuration (Large Scale)
- **Load Balancer**: 2x HAProxy/Nginx (active-passive)
- **API Tier**: 4 nodes (horizontal scale)
- **Pipeline Workers**: 6+ nodes (auto-scale based on queue depth)
- **LLM Cluster**: 3 nodes with GPU (round-robin inference)
- **Database**: PostgreSQL cluster with Patroni (3 nodes)
- **Redis Sentinel**: 3 nodes for HA
- **Capacity**: 50K+ events/sec, 500K+ assets

### Software Stack (Air-Gapped)

```yaml
Base OS: Ubuntu 22.04 LTS (or RHEL 8+)
Container Runtime: Docker 24.x + Docker Compose
Database: PostgreSQL 15.x
Cache: Redis 7.x
Vector DB: Weaviate 1.24+ (local mode)
LLM Runtime: Ollama 0.1.x (with LLaMA3 8B/70B)
Web Server: Uvicorn + Nginx reverse proxy
Monitoring: Prometheus + Grafana (local)
```

### Network Topology (Air-Gapped)

```
┌────────────────────────────────────────────────────┐
│              Management VLAN (10.1.0.0/24)         │
│  - Analyst workstations                            │
│  - Admin jump hosts                                │
│  - Bastion access                                  │
└────────────────────────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────────────┐
│         JanuSec Application VLAN (10.2.0.0/24)     │
│  - API servers (10.2.0.10-15)                      │
│  - Web UI (10.2.0.20)                              │
│  - Load balancer (10.2.0.5 VIP)                    │
└────────────────────────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────────────┐
│         Processing VLAN (10.3.0.0/24)              │
│  - Pipeline workers (10.3.0.10-30)                 │
│  - Ollama LLM nodes (10.3.0.40-42)                 │
│  - Redis cache (10.3.0.50)                         │
└────────────────────────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────────────┐
│           Data VLAN (10.4.0.0/24)                  │
│  - PostgreSQL primary (10.4.0.10)                  │
│  - PostgreSQL replica (10.4.0.11)                  │
│  - Vector DB (10.4.0.20)                           │
│  - Backup storage (10.4.0.30)                      │
└────────────────────────────────────────────────────┘
                      │
                      ▼
┌────────────────────────────────────────────────────┐
│         Sensor/Collection VLAN (10.5.0.0/24)       │
│  - Zeek sensors (span ports)                       │
│  - Syslog receivers                                │
│  - File upload endpoints                           │
└────────────────────────────────────────────────────┘
```

### Data Flow (Air-Gapped)

1. **Ingestion**: Sensors → Collectors (10.5.x.x) → API (10.2.x.x)
2. **Processing**: API → Redis Queue → Pipeline Workers (10.3.x.x)
3. **AI Analysis**: Workers → Ollama (10.3.0.40) → Workers
4. **Storage**: Workers → PostgreSQL (10.4.0.10)
5. **Query**: Web UI (10.2.0.20) → API → Database
6. **Export**: Analysts (10.1.x.x) → Web UI → Offline reports

### Deployment Steps (Edge/Private)

#### Phase 1: Infrastructure Setup (Week 1)

```bash
# 1. Provision hardware/VMs
# 2. Install Ubuntu 22.04 on all nodes
# 3. Configure VLANs and firewall rules

# On each node:
sudo apt update && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose-v2 python3.11 python3-pip

# 4. Configure NTP (critical for correlation)
sudo apt install -y chrony
sudo systemctl enable chrony

# 5. Set up shared storage (NFS/iSCSI for artifacts)
# 6. Configure DNS (internal)
```

#### Phase 2: Database Layer (Week 1)

```bash
# On database primary (10.4.0.10):
docker run -d \
  --name postgres-primary \
  -e POSTGRES_PASSWORD=<secure-password> \
  -e POSTGRES_DB=janusec \
  -v /data/postgres:/var/lib/postgresql/data \
  -p 5432:5432 \
  postgres:15-alpine

# Run migrations
cd /opt/janusec
export DATABASE_URL="postgresql://postgres:<password>@10.4.0.10:5432/janusec"
python -m alembic upgrade head

# Set up replication to 10.4.0.11 (read replica)
# Configure Patroni for HA (optional)
```

#### Phase 3: Cache & Vector DB (Week 1)

```bash
# Redis on 10.3.0.50:
docker run -d \
  --name redis \
  -p 6379:6379 \
  -v /data/redis:/data \
  redis:7-alpine redis-server --appendonly yes

# Weaviate on 10.4.0.20:
docker run -d \
  --name weaviate \
  -p 8080:8080 \
  -e PERSISTENCE_DATA_PATH=/var/lib/weaviate \
  -v /data/weaviate:/var/lib/weaviate \
  semitechnologies/weaviate:1.24.1
```

#### Phase 4: Ollama LLM Setup (Week 1-2)

```bash
# On LLM node 10.3.0.40 (with GPU):
curl -fsSL https://ollama.ai/install.sh | sh

# Pull models (do this via USB transfer in air-gapped):
# From internet-connected machine:
ollama pull llama3:8b
ollama pull llama3:70b  # If sufficient GPU memory
ollama pull nomic-embed-text  # For embeddings

# Export models:
cd ~/.ollama/models
tar -czf ollama-models.tar.gz *

# Transfer to air-gapped node via USB/secure transfer
# On air-gapped node:
mkdir -p ~/.ollama/models
tar -xzf ollama-models.tar.gz -C ~/.ollama/models

# Start Ollama service:
ollama serve
```

#### Phase 5: JanuSec Application Deployment (Week 2)

```bash
# On API nodes (10.2.0.10-15):
cd /opt/janusec

# Create .env file:
cat > .env << EOF
DATABASE_URL=postgresql://janusec:<password>@10.4.0.10:5432/janusec
REDIS_URL=redis://10.3.0.50:6379/0
WEAVIATE_URL=http://10.4.0.20:8080
OLLAMA_URL=http://10.3.0.40:11434
LLM_PROVIDER=ollama
LLM_MODEL=llama3:8b
ENABLE_EXTERNAL_LLM=false
TENANT_ID=default
LOG_LEVEL=INFO
PROMETHEUS_PORT=9090
EOF

# Build and start services:
docker-compose -f docker-compose.yml -f docker-compose.override.yml up -d

# Services started:
# - API server (port 8000)
# - Worker pool (internal)
# - Metrics exporter (port 9090)
```

#### Phase 6: Load Balancer & Web UI (Week 2)

```bash
# On load balancer 10.2.0.5:
apt install -y haproxy

# Configure HAProxy:
cat > /etc/haproxy/haproxy.cfg << EOF
frontend janusec_api
    bind *:443 ssl crt /etc/ssl/certs/janusec.pem
    default_backend api_servers

backend api_servers
    balance roundrobin
    option httpchk GET /health
    server api1 10.2.0.10:8000 check
    server api2 10.2.0.11:8000 check
    server api3 10.2.0.12:8000 check
EOF

systemctl restart haproxy

# Deploy frontend:
cd /opt/janusec/frontend/static
# Serve via Nginx on 10.2.0.20
```

#### Phase 7: Monitoring (Week 2)

```bash
# Prometheus on monitoring node:
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v /opt/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus

# Grafana:
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=<password> \
  grafana/grafana

# Import dashboards from grafana/*.json
```

#### Phase 8: Data Source Integration (Week 3)

```bash
# Configure Zeek sensor to send logs:
# On Zeek sensor nodes:
cat >> /usr/local/zeek/share/zeek/site/local.zeek << EOF
@load policy/tuning/json-logs.zeek
redef LogAscii::use_json = T;
EOF

# Forward logs to JanuSec:
# Via filebeat or custom script to POST to http://10.2.0.5/api/v1/events/zeek

# CSV manual upload:
# Users access https://10.2.0.5/csv_analyzer.html
# Upload CSV files, get instant risk scoring
```

### Offline Update Procedure

```bash
# On internet-connected build machine:
# 1. Pull latest JanuSec images
docker pull janusec/api:latest
docker pull janusec/worker:latest

# 2. Save images
docker save janusec/api:latest | gzip > janusec-api-v1.2.tar.gz
docker save janusec/worker:latest | gzip > janusec-worker-v1.2.tar.gz

# 3. Pull latest Ollama models
ollama pull llama3:8b
cd ~/.ollama/models && tar -czf ollama-updates.tar.gz *

# 4. Transfer to USB drive
# 5. On air-gapped system:
docker load < janusec-api-v1.2.tar.gz
docker load < janusec-worker-v1.2.tar.gz

# 6. Rolling update (zero downtime):
docker-compose up -d --no-deps --build api
# Wait for health check
docker-compose up -d --no-deps --build worker
```

---

## SECTION 3: PUBLIC/ONLINE DEPLOYMENT ARCHITECTURE

### Architecture Diagram (Cloud-Native)

```
┌─────────────────────────────────────────────────────────────┐
│                    CLOUD DEPLOYMENT (AWS/Azure/GCP)         │
└─────────────────────────────────────────────────────────────┘

Internet
   │
   ▼
┌──────────────────────────────────────────────────────┐
│   CloudFront/CloudFlare CDN (Global Distribution)    │
│   - TLS termination                                  │
│   - DDoS protection                                  │
│   - WAF (OWASP rules)                                │
└──────────────────────────────────────────────────────┘
   │
   ▼
┌──────────────────────────────────────────────────────┐
│   Application Load Balancer (ALB/Azure LB)           │
│   - Auto-scaling trigger                             │
│   - Health checks                                    │
│   - SSL/TLS                                          │
└──────────────────────────────────────────────────────┘
   │
   ├────────────────────────────────────────────┐
   │                                            │
   ▼                                            ▼
┌────────────────────┐              ┌────────────────────┐
│ EKS/AKS/GKE Cluster│              │ Managed Services   │
│  ┌──────────────┐  │              │  ┌──────────────┐  │
│  │ API Pods     │  │              │  │ RDS/CloudSQL │  │
│  │ (auto-scale) │  │              │  │ (PostgreSQL) │  │
│  │  - FastAPI   │  │              │  └──────────────┘  │
│  │  - Uvicorn   │  │              │                    │
│  └──────────────┘  │              │  ┌──────────────┐  │
│                    │              │  │ ElastiCache  │  │
│  ┌──────────────┐  │              │  │ (Redis)      │  │
│  │ Worker Pods  │  │              │  └──────────────┘  │
│  │ (auto-scale) │  │              │                    │
│  │  - Pipeline  │  │              │  ┌──────────────┐  │
│  │  - Correlate │  │              │  │ S3/Blob Stor │  │
│  └──────────────┘  │              │  │ (Artifacts)  │  │
│                    │              │  └──────────────┘  │
│  ┌──────────────┐  │              │                    │
│  │ LLM Pods     │  │              │  ┌──────────────┐  │
│  │ (GPU nodes)  │  │              │  │ Bedrock/AI   │  │
│  │  - Ollama    │──┼──────────────┼─>│ Claude API   │  │
│  │  - Fallback  │  │              │  │ GPT-4 API    │  │
│  └──────────────┘  │              │  └──────────────┘  │
│                    │              └────────────────────┘
│  ┌──────────────┐  │
│  │ Frontend     │  │
│  │ (Static CDN) │  │
│  └──────────────┘  │
└────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────┐
│   Observability Stack (CloudWatch/Datadog/Grafana Cloud)│
│   - Logs aggregation                                   │
│   - Metrics (Prometheus)                               │
│   - Distributed tracing (Jaeger/X-Ray)                 │
│   - Alerting (PagerDuty)                               │
└────────────────────────────────────────────────────────┘
```

### Cloud Provider-Specific Services

#### AWS Deployment

```yaml
Compute: EKS (Kubernetes) + EC2 (GPU nodes for LLM)
Database: RDS PostgreSQL (Multi-AZ)
Cache: ElastiCache Redis (cluster mode)
Storage: S3 (artifacts, pcaps, archives)
LLM: Bedrock (Claude) + SageMaker (Ollama backup)
Networking: VPC, ALB, Route53
Security: WAF, Shield, Secrets Manager, KMS
Monitoring: CloudWatch, X-Ray
Cost: AWS Cost Explorer
```

#### Azure Deployment

```yaml
Compute: AKS (Kubernetes) + VM Scale Sets (GPU)
Database: Azure Database for PostgreSQL (HA)
Cache: Azure Cache for Redis
Storage: Blob Storage (artifacts)
LLM: Azure OpenAI Service + Azure ML (Ollama)
Networking: VNet, Application Gateway, Traffic Manager
Security: Azure Firewall, Key Vault, Defender
Monitoring: Azure Monitor, Application Insights
Cost: Azure Cost Management
```

#### GCP Deployment

```yaml
Compute: GKE (Kubernetes) + Compute Engine (GPU)
Database: Cloud SQL PostgreSQL (HA)
Cache: Memorystore for Redis
Storage: Cloud Storage (artifacts)
LLM: Vertex AI (Claude/PaLM) + AI Platform (Ollama)
Networking: VPC, Cloud Load Balancing, Cloud CDN
Security: Cloud Armor, Secret Manager, Cloud KMS
Monitoring: Cloud Monitoring, Cloud Trace
Cost: Cloud Billing
```

### Kubernetes Deployment Manifest (Cloud)

```yaml
# janusec-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: janusec-api
  namespace: janusec
spec:
  replicas: 3  # Auto-scaled by HPA
  selector:
    matchLabels:
      app: janusec-api
  template:
    metadata:
      labels:
        app: janusec-api
    spec:
      containers:
      - name: api
        image: janusec/api:1.2.0
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: janusec-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: janusec-secrets
              key: redis-url
        - name: LLM_PROVIDER
          value: "claude"
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: janusec-secrets
              key: anthropic-api-key
        resources:
          requests:
            cpu: "1000m"
            memory: "2Gi"
          limits:
            cpu: "2000m"
            memory: "4Gi"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: janusec-api-hpa
  namespace: janusec
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: janusec-api
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80

---
apiVersion: v1
kind: Service
metadata:
  name: janusec-api
  namespace: janusec
spec:
  selector:
    app: janusec-api
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

### Deployment Steps (Public/Online)

#### Phase 1: Cloud Account Setup (Day 1)

```bash
# AWS Example:
# 1. Create AWS account / organization
# 2. Set up IAM roles and policies
# 3. Enable required services (EKS, RDS, ElastiCache, S3)

# Install AWS CLI and kubectl:
pip install awscli
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Configure AWS credentials:
aws configure
# Enter: Access Key, Secret Key, Region (us-east-1), Output (json)
```

#### Phase 2: Infrastructure as Code (Day 1-2)

```bash
# Using Terraform (recommended):
cd infra/terraform

# Initialize Terraform:
terraform init

# Review plan:
terraform plan -out=plan.tfplan

# Apply (creates VPC, EKS, RDS, ElastiCache, S3):
terraform apply plan.tfplan

# Outputs:
# - EKS cluster name
# - RDS endpoint
# - Redis endpoint
# - S3 bucket name
```

#### Phase 3: Kubernetes Cluster Setup (Day 2)

```bash
# Get EKS credentials:
aws eks update-kubeconfig --region us-east-1 --name janusec-cluster

# Verify cluster:
kubectl get nodes
# Should show 3-5 nodes (t3.xlarge or similar)

# Create namespace:
kubectl create namespace janusec

# Install ingress controller (NGINX or ALB):
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/aws/deploy.yaml
```

#### Phase 4: Managed Services Setup (Day 2)

```bash
# RDS PostgreSQL:
# - Created via Terraform (Multi-AZ, encrypted)
# - Get endpoint: janusec-db.xxxxxx.us-east-1.rds.amazonaws.com:5432

# Run migrations:
export DATABASE_URL="postgresql://janusec:<password>@<rds-endpoint>:5432/janusec"
python -m alembic upgrade head

# ElastiCache Redis:
# - Created via Terraform (cluster mode enabled)
# - Get endpoint: janusec-cache.xxxxx.cache.amazonaws.com:6379

# S3 Bucket:
# - Created via Terraform (versioning enabled, encrypted)
# - Bucket name: janusec-artifacts-<account-id>
```

#### Phase 5: Secrets Management (Day 2)

```bash
# Store secrets in AWS Secrets Manager:
aws secretsmanager create-secret \
  --name janusec/database-url \
  --secret-string "postgresql://janusec:<password>@<rds-endpoint>:5432/janusec"

aws secretsmanager create-secret \
  --name janusec/anthropic-api-key \
  --secret-string "sk-ant-..."

# Create Kubernetes secrets from AWS Secrets Manager:
# (Using External Secrets Operator or manual creation)
kubectl create secret generic janusec-secrets \
  --from-literal=database-url="postgresql://..." \
  --from-literal=redis-url="redis://..." \
  --from-literal=anthropic-api-key="sk-ant-..." \
  -n janusec
```

#### Phase 6: Deploy JanuSec Application (Day 3)

```bash
# Deploy API, workers, and frontend:
kubectl apply -f k8s/janusec-deployment.yaml
kubectl apply -f k8s/janusec-worker-deployment.yaml
kubectl apply -f k8s/janusec-frontend-deployment.yaml

# Check rollout status:
kubectl rollout status deployment/janusec-api -n janusec

# Get load balancer URL:
kubectl get svc janusec-api -n janusec
# External IP will be assigned (may take 2-3 minutes)
```

#### Phase 7: DNS and SSL/TLS (Day 3)

```bash
# Get load balancer DNS name:
export LB_DNS=$(kubectl get svc janusec-api -n janusec -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Create Route53 record (or your DNS provider):
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "janusec.yourdomain.com",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{"Value": "'$LB_DNS'"}]
      }
    }]
  }'

# Install cert-manager for automatic TLS:
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create Let's Encrypt issuer:
kubectl apply -f k8s/letsencrypt-issuer.yaml

# TLS will be automatically provisioned
```

#### Phase 8: Configure Auto-Scaling (Day 3)

```bash
# Metrics server (if not installed):
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# HPA already applied in janusec-deployment.yaml
# Verify:
kubectl get hpa -n janusec

# Cluster autoscaler (for node scaling):
kubectl apply -f k8s/cluster-autoscaler.yaml
```

#### Phase 9: Monitoring & Observability (Day 4)

```bash
# Install Prometheus + Grafana via Helm:
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack -n monitoring --create-namespace

# Get Grafana password:
kubectl get secret -n monitoring prometheus-grafana -o jsonpath="{.data.admin-password}" | base64 --decode

# Access Grafana:
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80

# Import JanuSec dashboards from grafana/*.json
```

#### Phase 10: Data Source Integration (Day 4-5)

```bash
# Configure cloud log ingestion:
# AWS CloudTrail → S3 → Lambda → JanuSec API
# Azure Activity Logs → Event Hub → Function → JanuSec API
# GCP Logging → Pub/Sub → Cloud Function → JanuSec API

# Configure API endpoints for pull connectors:
# Okta, Microsoft 365, Gmail, etc. (OAuth flows)

# CSV manual upload:
# Users access https://janusec.yourdomain.com/csv_analyzer.html
```

### Cost Optimization (Cloud)

```bash
# Use Spot/Preemptible instances for workers:
# - API tier: On-demand (uptime critical)
# - Workers: 70% spot, 30% on-demand
# - LLM inference: Spot (can retry on failure)

# Right-size instances:
# - Start small (t3.medium), scale based on metrics
# - Use AWS Compute Optimizer recommendations

# Database cost reduction:
# - Use read replicas for analytics queries
# - Enable query caching (ElastiCache)
# - Archive old events to S3 Glacier

# LLM cost control:
# - Set budget alerts in AWS Budgets
# - Use Ollama fallback when Claude API rate-limited
# - Batch LLM requests (avoid per-event calls)
```

---

## SECTION 4: HYBRID DEPLOYMENT ARCHITECTURE

### Architecture Diagram (Hybrid)

```
┌─────────────────────────────────────────────────────────────┐
│                       HYBRID DEPLOYMENT                      │
│              (Edge Collection + Cloud Analytics)             │
└─────────────────────────────────────────────────────────────┘

ON-PREMISES (Data Center / Branch Office)
┌────────────────────────────────────────────────────┐
│  ┌──────────────────────────────────────────────┐  │
│  │       Edge Collector (Lightweight)           │  │
│  │  ┌────────────────────────────────────────┐  │  │
│  │  │ Zeek/Suricata (network capture)        │  │  │
│  │  │ Sysmon/ETW (endpoint events)           │  │  │
│  │  │ Email logs (local SMTP)                │  │  │
│  │  └────────────────────────────────────────┘  │  │
│  │              ↓                                │  │
│  │  ┌────────────────────────────────────────┐  │  │
│  │  │ Local Preprocessing                    │  │  │
│  │  │  - Event normalization                 │  │  │
│  │  │  - PII masking/redaction               │  │  │
│  │  │  - Local deduplication                 │  │  │
│  │  │  - Compression                         │  │  │
│  │  └────────────────────────────────────────┘  │  │
│  │              ↓                                │  │
│  │  ┌────────────────────────────────────────┐  │  │
│  │  │ Local Buffer (SQLite/Redis)            │  │  │
│  │  │  - Store up to 7 days                  │  │  │
│  │  │  - Resilient to network outage         │  │  │
│  │  └────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
                      │
                      │ TLS 1.3 (mutual auth)
                      │ Batch upload (1min intervals)
                      ▼
              ┌───────────────┐
              │  VPN/Direct   │
              │  Connect      │
              └───────────────┘
                      │
                      ▼
CLOUD (AWS/Azure/GCP)
┌────────────────────────────────────────────────────┐
│  ┌──────────────────────────────────────────────┐  │
│  │       Ingestion Gateway (Cloud)              │  │
│  │  - Validate edge collector auth              │  │
│  │  - Decompress batches                        │  │
│  │  - Enqueue to processing pipeline            │  │
│  └──────────────────────────────────────────────┘  │
│                      ↓                              │
│  ┌──────────────────────────────────────────────┐  │
│  │   Full Event Pipeline (Cloud)                │  │
│  │  - All 14+ detection stages                  │  │
│  │  - Heavy correlation (not on edge)           │  │
│  │  - Factor synthesis                          │  │
│  └──────────────────────────────────────────────┘  │
│                      ↓                              │
│  ┌──────────────────────────────────────────────┐  │
│  │   AI/ML Layer (Cloud)                        │  │
│  │  - Claude API (tier 2 deep analysis)         │  │
│  │  - Ollama backup (tier 1 summaries)          │  │
│  │  - Vector DB (historical context)            │  │
│  └──────────────────────────────────────────────┘  │
│                      ↓                              │
│  ┌──────────────────────────────────────────────┐  │
│  │   Storage & Analytics (Cloud)                │  │
│  │  - RDS PostgreSQL (hot data 90 days)         │  │
│  │  - S3 Glacier (cold archive >90 days)        │  │
│  │  - Athena/BigQuery (analytics)               │  │
│  └──────────────────────────────────────────────┘  │
│                      ↓                              │
│  ┌──────────────────────────────────────────────┐  │
│  │   Web UI & API (Global Access)               │  │
│  │  - Analysts access from anywhere             │  │
│  │  - Incident response workflows               │  │
│  │  - HopGraph visualization                    │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
                      ↑
                      │ HTTPS (analysts)
                      │
          ┌───────────┴───────────┐
          │                       │
    Security Analyst       Compliance Officer
    (Remote)              (HQ)
```

### Hybrid Benefits

1. **Data Sovereignty**: Sensitive data never leaves premises (can be configured)
2. **Low Latency**: Edge collection has <10ms latency to sensors
3. **Resilience**: Edge buffer survives cloud outages (up to 7 days)
4. **Cost Optimization**: Preprocessing reduces cloud egress costs by 60-80%
5. **Compliance**: GDPR/HIPAA data can stay regional, metadata to cloud
6. **Best AI**: Cloud has full LLM capabilities (Claude, GPT-4)
7. **Scalability**: Cloud auto-scales for analytics, edge is fixed capacity

### Edge Collector Specification

```yaml
Hardware Requirements:
  CPU: 4 vCPU
  RAM: 16GB
  Storage: 500GB SSD (7-day buffer)
  Network: 1Gbps (bidirectional)

Software Stack:
  OS: Ubuntu 22.04 (minimal)
  Runtime: Docker (single container)
  Services:
    - Zeek adapter
    - Syslog receiver
    - CSV upload endpoint (local only)
    - Preprocessing engine
    - Batch uploader (to cloud)
    - Local SQLite buffer

Configuration:
  - Tenant ID (pre-configured)
  - Cloud endpoint URL
  - API key (rotated monthly)
  - Compression: gzip level 6
  - Batch interval: 60 seconds
  - Max batch size: 10,000 events
  - Buffer retention: 7 days
  - PII masking: Enabled (configurable fields)
```

### Data Flow (Hybrid)

```
1. Event Capture (Edge):
   Sensor → Zeek → Edge Collector (0-5ms)

2. Preprocessing (Edge):
   - Normalize to canonical schema (5-10ms)
   - Mask PII (email, IP, username) - optional (2ms)
   - Deduplicate (local cache check) (1ms)
   - Compress batch (gzip) (10-20ms)

3. Buffering (Edge):
   - Write to local SQLite (1ms)
   - Mark for upload

4. Upload (Edge → Cloud):
   - Every 60 seconds, batch upload via TLS
   - Mutual TLS authentication
   - If cloud unavailable, queue up to 7 days

5. Ingestion (Cloud):
   - Validate batch signature
   - Decompress
   - Enqueue to pipeline (SQS/Pub/Sub)

6. Processing (Cloud):
   - Full pipeline (14+ stages)
   - Correlation across all tenants (multi-site)
   - AI/ML analysis

7. Storage (Cloud):
   - Hot: RDS (90 days)
   - Warm: S3 Standard (1 year)
   - Cold: S3 Glacier (7 years)

8. Access (Anywhere):
   - Analysts log in to cloud UI
   - Query historical data
   - Generate reports
```

### Deployment Steps (Hybrid)

#### Phase 1: Cloud Setup (Week 1)

Follow **Section 3** (Public/Online) steps 1-7 to set up cloud infrastructure.

#### Phase 2: Edge Collector Build (Week 1)

```bash
# Build edge collector Docker image:
cd deployment/edge-collector

# Dockerfile:
cat > Dockerfile << 'EOF'
FROM ubuntu:22.04
RUN apt update && apt install -y zeek syslog-ng python3.11 sqlite3
COPY edge-collector.py /opt/
COPY config.yaml /etc/janusec/
CMD ["python3", "/opt/edge-collector.py"]
EOF

# Build:
docker build -t janusec/edge-collector:1.0 .

# Save for offline deployment:
docker save janusec/edge-collector:1.0 | gzip > edge-collector-1.0.tar.gz
```

#### Phase 3: Edge Deployment (Week 2)

```bash
# On each edge location (data center, branch office):

# 1. Provision edge hardware (4 vCPU, 16GB RAM)

# 2. Install Docker:
curl -fsSL https://get.docker.com | sh

# 3. Load image (if offline):
docker load < edge-collector-1.0.tar.gz

# 4. Configure edge collector:
cat > /etc/janusec/edge-config.yaml << EOF
tenant_id: customer-abc-site-01
cloud_endpoint: https://api.janusec.cloud/v1/events/batch
api_key: <edge-collector-api-key>
batch_interval_seconds: 60
max_batch_size: 10000
buffer_retention_days: 7
pii_masking:
  enabled: true
  fields: ["user_email", "src_ip", "dst_ip"]
compression: gzip
local_buffer_path: /data/buffer.db
EOF

# 5. Start edge collector:
docker run -d \
  --name janusec-edge \
  --restart unless-stopped \
  -v /etc/janusec:/etc/janusec:ro \
  -v /data/janusec:/data \
  -p 514:514/udp \
  -p 8080:8080 \
  janusec/edge-collector:1.0

# 6. Configure sensors to send to edge collector:
# Zeek: @load policy/tuning/json-logs.zeek + forward to localhost:514
# Sysmon: Configure syslog output to localhost:514
```

#### Phase 4: Network Connectivity (Week 2)

```bash
# Option A: Site-to-Site VPN
# AWS: Create VPN connection from customer gateway to VPC
aws ec2 create-vpn-connection \
  --type ipsec.1 \
  --customer-gateway-id cgw-xxxxx \
  --vpn-gateway-id vgw-xxxxx

# Option B: AWS Direct Connect / Azure ExpressRoute
# (For high-bandwidth, low-latency)

# Option C: Internet + TLS (lowest cost)
# Edge collector uses HTTPS POST to cloud endpoint
# Mutual TLS authentication (client cert validation)
```

#### Phase 5: Monitoring (Week 2)

```bash
# Edge collector metrics exposed on :9090/metrics
# Prometheus scrapes from cloud via VPN

# Add to Prometheus config:
scrape_configs:
  - job_name: 'edge-collectors'
    static_configs:
      - targets:
        - 'edge-01.customer-vpc:9090'
        - 'edge-02.customer-vpc:9090'
    metric_relabel_configs:
      - source_labels: [__address__]
        target_label: edge_site

# Grafana dashboard for edge health:
# - Events/sec ingested
# - Buffer depth (days)
# - Upload lag (seconds)
# - Network errors
```

### Hybrid Cost Comparison

| Component | Edge Only | Cloud Only | Hybrid |
|-----------|-----------|------------|--------|
| **Hardware** | $50K (5 sites) | $0 | $10K (5 edge collectors) |
| **Compute (monthly)** | $2K (power, maintenance) | $5K (EKS + workers) | $3K (cloud only) |
| **Storage (monthly)** | $500 (on-prem SAN) | $2K (RDS + S3) | $1K (cloud 90d + S3 archive) |
| **Network (monthly)** | $0 | $3K (egress) | $500 (compressed batches) |
| **LLM (monthly)** | $0 (Ollama only) | $2K (Claude API) | $1.5K (hybrid usage) |
| **Total (Year 1)** | $80K | $144K | $82K |
| **Total (Year 3)** | $114K | $432K | $190K |

**Winner**: Hybrid (42% cheaper than cloud-only over 3 years)

---

## SECTION 5: ONBOARDING PROCEDURES

### Onboarding Checklist (All Deployments)

#### Week 1: Planning & Prerequisites
- [ ] Define deployment model (edge/cloud/hybrid)
- [ ] Identify data sources (Zeek, Sysmon, email, cloud logs)
- [ ] Determine compliance requirements (GDPR, HIPAA, PCI)
- [ ] Size infrastructure (events/sec, assets, retention)
- [ ] Provision cloud accounts or hardware
- [ ] Set up VPN/network connectivity
- [ ] Create DNS records
- [ ] Obtain SSL/TLS certificates

#### Week 2: Infrastructure Deployment
- [ ] Deploy database (RDS or on-prem PostgreSQL)
- [ ] Deploy cache (ElastiCache or on-prem Redis)
- [ ] Deploy vector DB (Weaviate)
- [ ] Deploy LLM runtime (Ollama or cloud API)
- [ ] Deploy Kubernetes cluster (cloud) or Docker Compose (edge)
- [ ] Configure load balancer
- [ ] Set up monitoring (Prometheus + Grafana)
- [ ] Configure backup/disaster recovery

#### Week 3: Application Deployment
- [ ] Run database migrations
- [ ] Deploy API servers
- [ ] Deploy worker pool
- [ ] Deploy frontend (web UI)
- [ ] Configure secrets (API keys, database passwords)
- [ ] Test health checks and readiness probes
- [ ] Configure auto-scaling (cloud) or capacity planning (edge)
- [ ] Set up alerting (PagerDuty, Slack)

#### Week 4: Data Source Integration
- [ ] Configure Zeek sensors (if network monitoring)
- [ ] Configure Sysmon/ETW (if endpoint monitoring)
- [ ] Set up email connectors (O365, Gmail)
- [ ] Configure IAM connectors (Okta, Azure AD)
- [ ] Set up cloud log ingestion (CloudTrail, Activity Logs)
- [ ] Test CSV manual upload
- [ ] Validate event ingestion (check database for events)
- [ ] Tune correlation rules (tenant-specific adjustments)

#### Week 5: User Onboarding & Training
- [ ] Create user accounts (SSO integration)
- [ ] Assign roles (analyst, manager, admin)
- [ ] Conduct training sessions (web UI navigation)
- [ ] Document runbooks (incident response workflows)
- [ ] Create dashboards (per-team views)
- [ ] Test end-to-end workflows (upload CSV → risk score → report)

#### Week 6: Production Cutover
- [ ] Final security review (penetration test)
- [ ] Performance testing (load test to 2x expected volume)
- [ ] Disaster recovery test (failover simulation)
- [ ] Go-live decision (stakeholder sign-off)
- [ ] Cutover from legacy SIEM (if applicable)
- [ ] Monitor for 48 hours (on-call support)
- [ ] Post-launch review (lessons learned)

### Post-Deployment: Continuous Improvement

#### Monthly Tasks
- [ ] Review correlation rule effectiveness (false positive rate)
- [ ] Update factor weights based on feedback
- [ ] Rotate API keys and certificates
- [ ] Review cost metrics (cloud spend, LLM usage)
- [ ] Update threat intel feeds
- [ ] Patch and update software

#### Quarterly Tasks
- [ ] Conduct tabletop exercises (incident simulation)
- [ ] Review compliance posture (audit readiness)
- [ ] Benchmark performance (latency, throughput)
- [ ] Evaluate new data sources (expand coverage)
- [ ] Review and update runbooks

---

## SECTION 6: SECURITY CONSIDERATIONS

### Network Security

#### Edge/Private:
- **Firewall rules**: Deny all inbound except admin (port 22, 443)
- **VLAN segmentation**: Separate management, data, processing
- **IDS/IPS**: Monitor JanuSec infrastructure itself
- **Access control**: Jump host for admin access
- **Audit logging**: All admin actions logged

#### Cloud:
- **VPC isolation**: Private subnets for database, workers
- **Security groups**: Least privilege (only required ports)
- **WAF**: OWASP Top 10 protection
- **DDoS protection**: CloudFront/CloudFlare + AWS Shield
- **Network ACLs**: Deny known malicious IPs

#### Hybrid:
- **VPN**: Site-to-site IPsec VPN or Direct Connect
- **Mutual TLS**: Edge collector → cloud API (client cert validation)
- **IP allowlisting**: Cloud ingestion only from known edge IPs

### Authentication & Authorization

#### Multi-Factor Authentication (MFA):
- Required for all admin accounts
- Optional for analyst accounts (recommended)
- SSO integration (SAML 2.0, OIDC)

#### RBAC (Role-Based Access Control):
```yaml
Roles:
  - admin:
      Permissions:
        - manage_users
        - manage_integrations
        - view_all_tenants
        - delete_artifacts

  - analyst:
      Permissions:
        - view_events
        - upload_csv
        - generate_reports
        - view_own_tenant

  - compliance:
      Permissions:
        - view_compliance_dashboard
        - export_audit_logs
        - generate_compliance_reports

  - readonly:
      Permissions:
        - view_dashboards
```

#### API Key Management:
- Rotate every 90 days (automated)
- Scope-limited keys (per data source)
- Audit log of all API key usage
- Revocation workflow (compromised keys)

### Data Protection

#### Encryption at Rest:
- **Database**: AES-256 encryption (RDS native encryption)
- **S3/Blob Storage**: SSE-S3 or customer-managed keys (KMS)
- **Local disks**: LUKS full-disk encryption (on-prem)

#### Encryption in Transit:
- **TLS 1.3**: All API communication
- **Certificate pinning**: Edge collector → cloud
- **Perfect forward secrecy**: ECDHE ciphers only

#### PII Masking (Optional):
```python
# Configure in tenant settings:
pii_masking:
  enabled: true
  fields:
    - user_email: "sha256"  # Hash email addresses
    - src_ip: "last_octet"  # Mask last octet (10.1.2.XXX)
    - dst_ip: "last_octet"
    - username: "first_last_initial"  # John Doe → J. D.
    - credit_card: "redact"  # Full redaction
```

### Compliance

#### GDPR (General Data Protection Regulation):
- **Data residency**: Deploy in EU region (eu-west-1, europe-west1)
- **Right to deletion**: API endpoint to purge user data
- **Data export**: API to export user data (JSON/CSV)
- **Consent management**: Track consent for analytics

#### HIPAA (Health Insurance Portability and Accountability Act):
- **BAA (Business Associate Agreement)**: Required with cloud provider
- **Encryption**: At rest and in transit (verified)
- **Audit logs**: 6-year retention
- **Access controls**: MFA required for all PHI access

#### PCI-DSS (Payment Card Industry):
- **Network segmentation**: CDE (Cardholder Data Environment) isolation
- **Quarterly scans**: ASV (Approved Scanning Vendor)
- **Penetration testing**: Annual requirement
- **No cardholder data**: JanuSec logs events, not payment data

---

## SECTION 7: SCALING & PERFORMANCE

### Performance Benchmarks

#### Target Metrics:
- **Event ingestion**: 10K events/sec (production), 50K events/sec (enterprise)
- **API latency**: p50 < 100ms, p95 < 500ms, p99 < 1s
- **LLM tier 1 summary**: < 2s end-to-end
- **LLM tier 2 deep analysis**: < 30s end-to-end
- **CSV upload**: 100K rows in < 60s (risk scoring)
- **HopGraph query**: < 500ms for 10K-node graph

### Scaling Strategies

#### Horizontal Scaling (Cloud):
- **API tier**: Auto-scale 3-20 pods based on CPU (70%) and memory (80%)
- **Workers**: Auto-scale 5-50 pods based on queue depth (SQS/Redis)
- **LLM inference**: 3-10 GPU pods (round-robin load balancing)

#### Vertical Scaling (Edge/Private):
- **Database**: Increase instance size (RDS) or add RAM (on-prem)
- **Worker pool**: Add more CPU cores (process pool scales automatically)
- **Redis**: Increase memory allocation

#### Database Optimization:
```sql
-- Add indexes for common queries:
CREATE INDEX idx_events_tenant_timestamp ON events(tenant_id, timestamp DESC);
CREATE INDEX idx_events_src_ip ON events(src_ip) WHERE src_ip IS NOT NULL;
CREATE INDEX idx_incidents_status ON incidents(status, tenant_id);

-- Partition large tables:
CREATE TABLE events_2025_01 PARTITION OF events
  FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

-- Analyze query performance:
EXPLAIN ANALYZE SELECT * FROM events WHERE tenant_id = 'abc' AND timestamp > NOW() - INTERVAL '1 hour';
```

#### Caching Strategy:
```python
# Redis cache layers:
# L1: Factor synthesis cache (TTL: 5 minutes)
# L2: Correlation rule cache (TTL: 1 hour)
# L3: Domain reputation cache (TTL: 24 hours)

# Cache hit ratio target: >80%
# Monitor via Prometheus: redis_keyspace_hits_total / (redis_keyspace_hits_total + redis_keyspace_misses_total)
```

### Load Testing

```bash
# Using k6 (load testing tool):
k6 run --vus 100 --duration 5m load-test.js

# load-test.js:
import http from 'k6/http';
export default function() {
  const payload = JSON.stringify({
    event_type: 'network',
    src_ip: '10.1.2.3',
    dst_ip: '8.8.8.8',
    timestamp: new Date().toISOString()
  });

  http.post('https://janusec.yourdomain.com/api/v1/events', payload, {
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer xxx' }
  });
}

# Expected results:
# - 100 VUs (virtual users)
# - 1000 requests/sec sustained
# - p95 latency < 500ms
# - 0% error rate
```

---

## SECTION 8: COST ANALYSIS

### Edge/Private (On-Premises) - 3 Year TCO

```yaml
Initial Capital Expenditure:
  Hardware: $50,000 (7 servers, switches, UPS)
  Licenses: $0 (open-source stack)
  Installation: $10,000 (professional services)
  Total CapEx: $60,000

Annual Operating Costs:
  Year 1:
    Power/cooling: $6,000
    Maintenance: $5,000
    Staff (1 FTE): $120,000
    Software updates: $0
    Total: $131,000

  Year 2-3: $131,000/year (same)

3-Year TCO: $60K + $131K + $131K + $131K = $453,000
Per-event cost: ~$0.0015 (assuming 300M events over 3 years)
```

### Public/Online (Cloud) - 3 Year TCO

```yaml
AWS Cost Estimate (Monthly):
  Compute (EKS):
    - 5 x t3.xlarge (API): $750
    - 10 x c5.2xlarge (workers): $3,400
    - 2 x p3.2xlarge (GPU/LLM): $6,000
  Database (RDS PostgreSQL Multi-AZ):
    - db.r6g.2xlarge: $1,200
  Cache (ElastiCache Redis):
    - cache.r6g.xlarge: $400
  Storage (S3):
    - 10TB standard: $230
    - 50TB glacier: $200
  Network:
    - Data transfer out: $2,000
  LLM API (Anthropic Claude):
    - 10M tokens/month: $1,500
  Monitoring (CloudWatch, X-Ray):
    - $300
  Total Monthly: $15,980

Annual Costs:
  Year 1: $191,760
  Year 2: $191,760
  Year 3: $191,760

3-Year TCO: $575,280
Per-event cost: ~$0.0019
```

### Hybrid Deployment - 3 Year TCO

```yaml
Edge Collector CapEx:
  Hardware (5 sites): $10,000
  Installation: $5,000
  Total CapEx: $15,000

Cloud Costs (Monthly):
  Compute (smaller footprint):
    - 3 x t3.large (API): $300
    - 5 x c5.xlarge (workers): $850
    - 1 x p3.2xlarge (GPU): $3,000
  Database (RDS PostgreSQL):
    - db.r6g.xlarge: $600
  Cache: $200
  Storage (less data, shorter retention):
    - 2TB S3: $46
    - 20TB glacier: $80
  Network (compressed batches):
    - Data transfer: $500
  LLM API (reduced usage):
    - $1,000
  Total Monthly: $6,576

Annual Costs:
  Year 1: $15K + $78,912 = $93,912
  Year 2-3: $78,912/year

3-Year TCO: $15K + $93,912 + $78,912 + $78,912 = $266,736
Per-event cost: ~$0.0009

Savings vs. Cloud-Only: 54% ($308K saved over 3 years)
```

### Cost Optimization Recommendations

1. **Use reserved instances** (cloud): 40-60% discount vs. on-demand
2. **Right-size instances**: Monitor CPU/memory, downsize over-provisioned
3. **Archive old data**: S3 Glacier/Azure Cool Blob (90% cheaper than hot storage)
4. **Compress events**: Reduces storage by 70-80%
5. **Batch LLM requests**: Reduces API calls by 50% (vs. per-event)
6. **Use Ollama for tier 1**: Reserve Claude API for tier 2 only
7. **Spot instances for workers**: 70% discount (acceptable for non-critical workloads)
8. **Multi-cloud arbitrage**: Use cheapest CSP per region

---

## SECTION 9: DECISION FRAMEWORK

### When to Choose Edge/Private

✅ **Choose Edge/Private if**:
- Regulatory requirement for data residency (HIPAA, PCI, government)
- Air-gapped environment (no internet connectivity)
- Very high network traffic (>100GB/day PCAP)
- Existing on-prem infrastructure (sunk cost)
- Low operational budget (after initial CapEx)

❌ **Avoid Edge/Private if**:
- Small team (<10 people, no dedicated ops)
- Need rapid scaling (unpredictable growth)
- Want latest AI models (cloud APIs evolve faster)
- Multi-region deployment (complex to manage on-prem)

### When to Choose Public/Online

✅ **Choose Public/Online if**:
- Cloud-native organization (AWS/Azure/GCP already in use)
- Startup or POC (low upfront cost)
- Global team (analysts in multiple regions)
- Need auto-scaling (variable workload)
- Want managed services (less operational burden)

❌ **Avoid Public/Online if**:
- Strict data residency laws (cannot use CSP in required region)
- Very large event volume (cloud egress costs prohibitive)
- Compliance audit requires on-prem (some industries)
- Budget-constrained (cloud costs grow linearly with usage)

### When to Choose Hybrid

✅ **Choose Hybrid if**:
- Gradual cloud migration strategy
- Compliance + innovation balance needed
- Multi-site deployment (centralized analytics)
- Cost optimization priority (edge preprocessing reduces cloud costs)
- Want best of both worlds (local collection, cloud AI)

❌ **Avoid Hybrid if**:
- Very small deployment (overhead not worth it)
- Fully air-gapped (no cloud connectivity possible)
- Simplicity over cost (hybrid adds complexity)

### Decision Matrix

| Criteria | Edge/Private | Public/Online | Hybrid |
|----------|--------------|---------------|--------|
| **Upfront Cost** | High ($60K+) | Low ($0) | Medium ($15K) |
| **3-Year TCO** | $453K | $575K | $267K |
| **Scalability** | Manual | Auto | Auto (cloud) |
| **AI Capability** | Limited (Ollama) | Full (Claude, GPT-4) | Full |
| **Compliance** | Excellent | Depends on CSP | Excellent |
| **Ops Complexity** | High | Low | Medium |
| **Network Latency** | Best (<10ms) | Variable (50-200ms) | Best (edge) |
| **Vendor Lock-In** | None | High (CSP-specific) | Medium |

### Recommendation

**For most organizations**: Start with **Hybrid**
- Deploy edge collectors at critical sites (low latency, compliance)
- Use cloud for analytics and AI (best models, auto-scaling)
- Gradually migrate to full cloud or full edge based on learnings

**For startups/POCs**: **Public/Online**
- Get started in 1 week with minimal investment
- Prove value before committing to infrastructure

**For government/defense**: **Edge/Private**
- No choice due to air-gap requirements
- Accept higher TCO for compliance

---

## APPENDIX: Quick Start Commands

### Edge/Private Quick Start
```bash
# 1. Clone repository
git clone https://github.com/yourdomain/janusec.git
cd janusec

# 2. Configure environment
cp .env.example .env
# Edit .env with database credentials, etc.

# 3. Start stack
docker-compose up -d

# 4. Run migrations
docker-compose exec api python -m alembic upgrade head

# 5. Create admin user
docker-compose exec api python scripts/create_admin.py --email admin@example.com

# 6. Access UI
open http://localhost:8000
```

### Public/Online Quick Start (AWS)
```bash
# 1. Install prerequisites
brew install awscli terraform kubectl helm

# 2. Clone and configure
git clone https://github.com/yourdomain/janusec.git
cd janusec/infra/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with AWS account details

# 3. Deploy infrastructure
terraform init
terraform apply

# 4. Deploy application
aws eks update-kubeconfig --region us-east-1 --name janusec-cluster
helm install janusec ./helm/janusec -n janusec --create-namespace

# 5. Get URL
kubectl get svc janusec-api -n janusec -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
```

### Hybrid Quick Start
```bash
# 1. Deploy cloud (follow Public/Online steps above)

# 2. Deploy edge collectors
# On each edge site:
docker run -d \
  --name janusec-edge \
  -e CLOUD_ENDPOINT=https://api.janusec.cloud/v1/events/batch \
  -e API_KEY=<your-api-key> \
  -e TENANT_ID=<your-tenant-id> \
  -v /data/janusec:/data \
  janusec/edge-collector:latest

# 3. Configure sensors (Zeek, Sysmon) to send to edge collector IP
```

---

## CONCLUSION

JanuSec's flexible deployment architecture supports **edge, cloud, and hybrid** models to meet diverse organizational needs. The **hybrid approach** offers the best balance of cost, performance, and compliance for most enterprises.

**Next Steps**:
1. Review this guide with stakeholders
2. Complete decision matrix for your organization
3. Select deployment model
4. Provision infrastructure (Week 1-2)
5. Deploy JanuSec (Week 2-3)
6. Onboard data sources (Week 3-4)
7. Train users and go live (Week 5-6)

For questions or professional services, contact: support@janusec.io
