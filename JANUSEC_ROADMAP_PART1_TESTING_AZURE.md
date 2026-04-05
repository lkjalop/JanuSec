# JanuSec Platform - Testing & Azure Validation Roadmap (Part 1 of 3)

**Status**: Production-Ready (91%) | **Last Updated**: 2025-10-28
**Purpose**: Complete testing/fixing checklist and Azure validation plan

---

## 📋 Table of Contents

1. [Backend Testing & Fixes](#backend-testing--fixes)
2. [Frontend Testing & Fixes](#frontend-testing--fixes)
3. [Azure Validation Plan](#azure-validation-plan)
4. [Priority Matrix](#priority-matrix)

---

## 🔧 Backend Testing & Fixes

### **P0 - Critical (CEO Demo Blockers)**

#### 1. Redis High Availability
**File**: `src/core/correlation/redis_cache.py` (lines 1-250)
**Issue**: Single point of failure for correlation engine
**Fix Required**:
- Add Redis Sentinel support for automatic failover
- Implement connection pool with retry logic
- Add health checks for Redis connectivity

**Test**: `tests/test_redis_ha_failover.py` (NEW - needs creation)
```python
# Test failover behavior when primary Redis goes down
# Test sentinel election and client reconnection
# Test data consistency after failover
```

**Validation Steps**:
1. Deploy Redis cluster with Sentinel (3 nodes minimum)
2. Kill primary node during correlation processing
3. Verify automatic failover within 30 seconds
4. Confirm no correlation data loss
5. Monitor for split-brain scenarios

**Azure Deployment**:
```bash
# Use Azure Cache for Redis Premium tier with clustering
az redis create --name janusec-redis-prod \
  --resource-group janusec-rg \
  --location eastus \
  --sku Premium --vm-size P1 \
  --enable-non-ssl-port false \
  --redis-configuration '{"maxmemory-policy":"allkeys-lru"}'
```

---

#### 2. PostgreSQL Migration from SQLite
**Files**:
- `src/db/database.py` (lines 45-120) - Database adapter
- `src/db/migrator.py` (lines 1-200) - Migration engine
- `migrations/*.sql` (18 migration files)

**Issue**: Production needs PostgreSQL; SQLite is dev-only
**Fix Required**:
- Test all 18 migrations against PostgreSQL 15+
- Verify pgvector extension installation
- Test multi-tenant schema isolation
- Validate foreign key constraints

**Test**: `tests/test_postgres_migration_full.py` (NEW)
```python
# Test fresh PostgreSQL install + all migrations
# Test SQLite -> PostgreSQL data migration
# Test rollback procedures
# Test concurrent migration safety
```

**Validation Steps**:
1. Provision Azure PostgreSQL Flexible Server
2. Run migration script: `python scripts/run_smoke_migration.py --target postgres`
3. Verify all tables created: `\dt` in psql
4. Test pgvector: `SELECT * FROM pg_extension WHERE extname='vector';`
5. Load test with 10K events, measure write latency

**Azure Deployment**:
```bash
# Create PostgreSQL Flexible Server with HA
az postgres flexible-server create \
  --name janusec-db-prod \
  --resource-group janusec-rg \
  --location eastus \
  --admin-user janusec_admin \
  --admin-password '<secure-password>' \
  --sku-name Standard_D2s_v3 \
  --tier GeneralPurpose \
  --high-availability Enabled \
  --storage-size 128 \
  --version 15

# Enable pgvector extension
az postgres flexible-server parameter set \
  --resource-group janusec-rg \
  --server-name janusec-db-prod \
  --name shared_preload_libraries \
  --value 'pgvector'
```

**Migration Command**:
```bash
# Set environment variables
export DB_TYPE=postgres
export DB_HOST=janusec-db-prod.postgres.database.azure.com
export DB_PORT=5432
export DB_NAME=janusec
export DB_USER=janusec_admin
export DB_PASSWORD='<password>'
export DB_SSL_MODE=require

# Run migrations
python scripts/run_smoke_migration.py --confirm
```

---

#### 3. Load Testing (10K events/sec target)
**Files**:
- `src/api/stream_ingest.py` (lines 1-300) - Event ingestion
- `src/core/event_pipeline/pipeline.py` (lines 1-500) - 21-stage pipeline
- `scripts/stress_run_http_concurrent.py` - Load test harness

**Issue**: 10K events/sec claim not validated
**Fix Required**:
- Benchmark current throughput (likely 2-3K/sec)
- Add batch ingestion optimization
- Implement worker pool for pipeline stages
- Add backpressure handling

**Test**: `tests/test_load_10k_events.py` (NEW)
```python
# Test sustained 10K events/sec for 5 minutes
# Measure P50, P95, P99 latency
# Monitor memory usage and GC pressure
# Test graceful degradation at 15K events/sec
```

**Validation Steps**:
1. Deploy to Azure Container Apps with autoscaling
2. Run load test: `python scripts/stress_run_http_concurrent.py --rate 10000 --duration 300`
3. Monitor metrics in Azure Application Insights
4. Verify no dropped events (check DLQ)
5. Confirm P95 latency < 500ms

**Azure Container Apps Scaling**:
```bash
# Update container app with autoscaling rules
az containerapp update \
  --name janusec-api \
  --resource-group janusec-rg \
  --min-replicas 3 \
  --max-replicas 20 \
  --scale-rule-name http-rule \
  --scale-rule-type http \
  --scale-rule-http-concurrency 100
```

**Optimization Checklist**:
- [ ] Enable async pipeline stages (currently sync)
- [ ] Add Redis pipeline for batch writes
- [ ] Implement message queue (Azure Service Bus)
- [ ] Use connection pooling for DB
- [ ] Add in-memory cache for hot data

---

### **P1 - High Priority (Production Readiness)**

#### 4. Security Audit & Penetration Testing
**Files**:
- `src/security/auth.py` (lines 1-200) - Authentication
- `src/api/auth_rate_limit.py` (lines 1-150) - Rate limiting
- `src/security/security_controls.py` (lines 1-300) - Security controls

**Issue**: No external security audit performed
**Fix Required**:
- OWASP Top 10 compliance verification
- API authentication bypass testing
- SQL injection testing (all endpoints)
- Rate limit bypass testing
- Multi-tenant isolation verification

**Test**: `tests/test_security_comprehensive.py` (NEW)
```python
# Test authentication bypass attempts
# Test SQL injection on all query parameters
# Test rate limit effectiveness
# Test tenant isolation (cross-tenant data access)
# Test CSRF protection
```

**Validation Steps**:
1. Run OWASP ZAP against deployed API
2. Test all 47 API endpoints for injection
3. Attempt tenant isolation bypass
4. Test rate limit with distributed attack
5. Review Azure Security Center recommendations

**Security Hardening**:
```python
# src/security/auth.py - Add JWT validation improvements
def validate_token(token: str) -> dict:
    # Add: Check token expiration with clock skew
    # Add: Verify issuer claim
    # Add: Check token revocation list
    # Add: Audit log for failed attempts
    pass
```

---

#### 5. SBOM VPR/CVSS Integration Testing
**Files**:
- `src/api/sbom_endpoints.py` (lines 150-250) - VPR enrichment
- `src/integrations/tenable_client.py` (lines 1-100) - Tenable client
- `src/integrations/qualys_client.py` (lines 1-100) - Qualys client
- `src/modules/sbom_vuln_mapper.py` (lines 200-400) - Vulnerability mapping

**Issue**: VPR enrichment is offline stub only
**Fix Required**:
- Add real Tenable.io API integration
- Add real Qualys VMDR API integration
- Test VPR score caching and refresh
- Test rate limiting for external APIs
- Add fallback when APIs unavailable

**Test**: `tests/test_sbom_live_vpr_enrichment.py` (NEW)
```python
# Test live Tenable.io API integration
# Test VPR cache hit/miss scenarios
# Test API rate limit handling
# Test fallback to CVSS when VPR unavailable
# Test CVE not found scenarios
```

**Validation Steps**:
1. Configure Tenable.io credentials in Azure Key Vault
2. Upload SBOM with 100 CVEs
3. Verify VPR scores fetched and cached
4. Test cache expiration (default 24h)
5. Monitor API usage and costs

**Production Integration**:
```python
# src/integrations/tenable_client.py - Add real API calls
async def get_vpr_for_cves(self, cves: List[str]) -> Dict[str, float]:
    """Fetch VPR scores from Tenable.io API."""
    # Add: Batch API calls (100 CVEs per request)
    # Add: Retry with exponential backoff
    # Add: Circuit breaker for API failures
    # Add: Cost tracking per API call
    url = f"{self.api_url}/vulnerabilities/export"
    headers = {"X-ApiKeys": f"accessKey={self.access_key};secretKey={self.secret_key}"}
    # Implementation needed
```

---

#### 6. HopGraph Stress Testing
**Files**:
- `src/core/graph/hopgraph_lite.py` (lines 1-400) - Event HopGraph
- `src/artifact/hopgraph_lite.py` (lines 1-135) - Artifact HopGraph
- `tests/test_hopgraph_stress.py` - Stress test (exists but needs expansion)

**Issue**: Graph performance under load unknown
**Fix Required**:
- Test graph with 100K nodes, 1M edges
- Measure path finding latency at scale
- Test memory usage with large graphs
- Add graph pruning for old edges
- Test concurrent read/write safety

**Test**: Expand `tests/test_hopgraph_stress.py`
```python
# Test 100K node graph construction
# Test path finding with depth=10
# Test graph serialization/deserialization
# Test memory usage over 24h simulation
# Test graph pruning algorithms
```

**Validation Steps**:
1. Generate synthetic attack chain (100 hops)
2. Build graph with 100K events over 1 week
3. Query explanation for target node
4. Measure path finding latency (target: <100ms)
5. Monitor memory usage (target: <2GB)

**Performance Optimization**:
```python
# src/core/graph/hopgraph_lite.py - Add pruning
def prune_old_edges(self, max_age_hours: int = 168):
    """Remove edges older than max_age_hours (default 7 days)."""
    now = time.time()
    cutoff = now - (max_age_hours * 3600)
    # Add: Iterate and remove old edges
    # Add: Update metrics
    # Add: Log pruning statistics
```

---

### **P2 - Medium Priority (Post-Demo)**

#### 7. EWMA Adaptive Detector Tuning
**Files**:
- `src/core/detect/beacon_analyzer.py` (lines 50-150) - Beacon detection
- `tests/test_ewma_adaptive.py` - EWMA tests (passing but basic)

**Issue**: EWMA parameters not tuned for production traffic
**Fix Required**:
- Tune alpha parameter for different traffic types
- Add baseline warm-up period
- Test false positive rate on real traffic
- Add per-tenant EWMA thresholds

**Test**: `tests/test_ewma_production_tuning.py` (NEW)
```python
# Test EWMA on real Zeek logs (1M connections)
# Measure false positive rate
# Test warm-up period effectiveness
# Test per-tenant threshold isolation
```

---

#### 8. TF-IDF LOLBin Detection Validation
**Files**:
- `src/core/event_pipeline/stages/primitives.py` (lines 300-450) - TF-IDF stage
- `tests/test_lolbin_tfidf_basic.py` - Basic tests (passing)

**Issue**: TF-IDF tokenizer not tested on diverse LOLBins
**Fix Required**:
- Test on LOLBAS dataset (200+ binaries)
- Tune IDF weighting for rare binaries
- Test command line obfuscation resistance
- Add dynamic vocabulary updates

**Test**: `tests/test_lolbin_comprehensive.py` (NEW)
```python
# Test all 200+ LOLBAS binaries
# Test command line variants (base64, hex, etc)
# Test IDF scoring accuracy
# Test vocabulary drift over time
```

---

## 🎨 Frontend Testing & Fixes

### **P0 - Critical (CEO Demo Blockers)**

#### 1. Graph Visualization (D3.js Implementation)
**File**: `frontend/static/graph_explain.html` (lines 1-71)
**Current State**: Text-based table rendering (lines 32-49)
**Issue**: No interactive graph visualization

**Fix Required**: Replace text rendering with D3.js force-directed graph

**Implementation** (see Part 3 for full code):
```html
<!-- Add D3.js library -->
<script src="https://d3js.org/d3.v7.min.js"></script>

<!-- Replace renderChain() function at line 32 -->
<script>
function renderChain(data){
  // D3.js force-directed graph implementation
  // Node: host, process, file, ip
  // Edge: attack path with weight/score
  // Interactive: zoom, pan, click for details
}
</script>
```

**Test Plan**:
1. Load attack chain with 20+ nodes
2. Test zoom/pan interactions
3. Test node click for details
4. Test edge hover for metadata
5. Verify performance with 100+ node graphs

**Files to Update**:
- `frontend/static/graph_explain.html` (lines 32-65)
- `frontend/static/css/graph.css` (NEW - create styles)

---

#### 2. MITRE Heatmap Enhancement
**File**: `frontend/static/mitre.html` (lines 1-83)
**Current State**: Grid with bars (lines 43-51)
**Issue**: No color gradient, limited interactivity

**Fix Required**: Add color-coded heatmap with intensity gradient

**Implementation** (see Part 3 for full code):
```javascript
// Update grid rendering at line 43
const colorScale = d3.scaleLinear()
  .domain([0, max])
  .range(["#1a1f2e", "#e74c3c"]); // Dark blue to red

// Add background color to cells
.style('background', d => colorScale(d.count))
```

**Test Plan**:
1. Load with 50+ techniques
2. Verify color gradient accuracy
3. Test hover tooltips
4. Test click-through to events
5. Test responsive layout

**Files to Update**:
- `frontend/static/mitre.html` (lines 43-56)
- Add color legend component

---

#### 3. CSV Analyzer File Upload
**File**: `frontend/static/csv_analyzer.html`
**Issue**: File upload UI exists but needs validation

**Fix Required**:
- Add client-side file validation (size, type)
- Add progress indicator for large files
- Add error handling for malformed CSVs
- Test with 1M+ row CSVs

**Test Plan**:
1. Upload 1MB CSV (10K rows)
2. Upload 100MB CSV (1M rows)
3. Upload malformed CSV
4. Upload non-CSV file
5. Test concurrent uploads

**Files to Update**:
- `frontend/static/csv_analyzer.html`
- `src/api/csv_endpoints.py` (backend validation)

---

### **P1 - High Priority**

#### 4. Remediation UX Modals
**Files**: Multiple HTML files with SOAR actions
**Issue**: No confirmation modals for destructive actions

**Fix Required**: Add confirmation modals for:
- Block IP address
- Quarantine file
- Kill process
- Disable user account

**Implementation** (see Part 3):
```javascript
// Add modal component
function confirmAction(action, target, callback) {
  const modal = createModal({
    title: `Confirm ${action}`,
    message: `Are you sure you want to ${action} on ${target}?`,
    confirmText: 'Execute',
    cancelText: 'Cancel',
    onConfirm: callback
  });
  modal.show();
}
```

**Test Plan**:
1. Test modal for each action type
2. Test cancel flow
3. Test confirm flow + API call
4. Test keyboard navigation (ESC to close)
5. Test accessibility (screen readers)

**Files to Update**:
- `frontend/static/js/modals.js` (NEW - create)
- `frontend/static/approvals.html`
- `frontend/static/index.html` (SOAR actions section)

---

#### 5. Frontend Performance Optimization
**Files**: `frontend/static/app.js` (1,200+ lines)
**Issue**: Large payload fetches on page load

**Fix Required**:
- Implement pagination for artifact lists
- Add lazy loading for tabs
- Add service worker for caching
- Optimize bundle size

**Test Plan**:
1. Measure initial page load time
2. Test pagination with 10K artifacts
3. Test offline mode with service worker
4. Measure Lighthouse score (target: 90+)

---

## ☁️ Azure Validation Plan

### **Phase 1: Infrastructure Provisioning (Week 1)**

#### Step 1.1: Deploy Core Infrastructure
```bash
# 1. Login to Azure
az login
az account set --subscription "<your-subscription-id>"

# 2. Create resource group
az group create \
  --name janusec-prod-rg \
  --location eastus \
  --tags Environment=production Project=JanuSec

# 3. Deploy using Terraform
cd azure-deployment/terraform
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

**Validation**:
- [ ] Resource group created
- [ ] Container registry created
- [ ] Log Analytics workspace created
- [ ] Container Apps environment created

---

#### Step 1.2: Deploy PostgreSQL with High Availability
```bash
# Create PostgreSQL Flexible Server with zone-redundant HA
az postgres flexible-server create \
  --name janusec-db-prod \
  --resource-group janusec-prod-rg \
  --location eastus \
  --admin-user janusec_admin \
  --admin-password '<strong-password>' \
  --sku-name Standard_D4s_v3 \
  --tier GeneralPurpose \
  --high-availability ZoneRedundant \
  --storage-size 256 \
  --backup-retention 30 \
  --version 15

# Configure firewall for Azure services
az postgres flexible-server firewall-rule create \
  --resource-group janusec-prod-rg \
  --name janusec-db-prod \
  --rule-name AllowAzureServices \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0

# Enable pgvector extension
az postgres flexible-server parameter set \
  --resource-group janusec-prod-rg \
  --server-name janusec-db-prod \
  --name shared_preload_libraries \
  --value 'pgvector'

# Restart server to apply extension
az postgres flexible-server restart \
  --resource-group janusec-prod-rg \
  --name janusec-db-prod
```

**Validation Tests**:
```bash
# Test connection
psql "host=janusec-db-prod.postgres.database.azure.com port=5432 dbname=postgres user=janusec_admin password=<password> sslmode=require"

# Verify pgvector
psql> CREATE EXTENSION IF NOT EXISTS vector;
psql> \dx vector

# Test failover
az postgres flexible-server restart --resource-group janusec-prod-rg --name janusec-db-prod
# Verify automatic failover to standby (should take <30 seconds)
```

---

#### Step 1.3: Deploy Redis Premium Cluster
```bash
# Create Redis Premium with clustering and persistence
az redis create \
  --name janusec-redis-prod \
  --resource-group janusec-prod-rg \
  --location eastus \
  --sku Premium \
  --vm-size P1 \
  --enable-non-ssl-port false \
  --shard-count 2 \
  --redis-configuration "maxmemory-policy=allkeys-lru" \
  --zones 1 2

# Get connection details
az redis show \
  --name janusec-redis-prod \
  --resource-group janusec-prod-rg \
  --query "[hostName,sslPort,primaryKey]"
```

**Validation Tests**:
```bash
# Test connection with redis-cli
redis-cli -h janusec-redis-prod.redis.cache.windows.net -p 6380 -a <primaryKey> --tls

# Test clustering
CLUSTER INFO
CLUSTER NODES

# Test persistence (AOF)
CONFIG GET appendonly
# Should return "appendonly yes"

# Test failover simulation
# Azure handles this automatically - monitor in portal
```

---

### **Phase 2: Application Deployment (Week 1)**

#### Step 2.1: Build and Push Container Image
```bash
# 1. Build Docker image
docker build -t janusec-api:v1.0.0 -f Dockerfile .

# 2. Login to ACR
az acr login --name janusecprodacr

# 3. Tag and push
docker tag janusec-api:v1.0.0 janusecprodacr.azurecr.io/janusec-api:v1.0.0
docker push janusecprodacr.azurecr.io/janusec-api:v1.0.0

# 4. Verify image
az acr repository show \
  --name janusecprodacr \
  --image janusec-api:v1.0.0
```

---

#### Step 2.2: Deploy Container App
```bash
# Create Container App with environment variables
az containerapp create \
  --name janusec-api \
  --resource-group janusec-prod-rg \
  --environment janusec-env-prod \
  --image janusecprodacr.azurecr.io/janusec-api:v1.0.0 \
  --target-port 8080 \
  --ingress external \
  --min-replicas 2 \
  --max-replicas 10 \
  --cpu 2 \
  --memory 4Gi \
  --env-vars \
    DB_TYPE=postgres \
    DB_HOST=janusec-db-prod.postgres.database.azure.com \
    DB_PORT=5432 \
    DB_NAME=janusec \
    DB_USER=janusec_admin \
    DB_PASSWORD=secretref:db-password \
    REDIS_HOST=janusec-redis-prod.redis.cache.windows.net \
    REDIS_PORT=6380 \
    REDIS_PASSWORD=secretref:redis-password \
    REDIS_SSL=true \
    ENVIRONMENT=production \
    RATE_LIMIT_ENABLED=1

# Add secrets
az containerapp secret set \
  --name janusec-api \
  --resource-group janusec-prod-rg \
  --secrets \
    db-password=<postgres-password> \
    redis-password=<redis-primary-key>
```

**Validation Tests**:
```bash
# Get app URL
APP_URL=$(az containerapp show \
  --name janusec-api \
  --resource-group janusec-prod-rg \
  --query properties.configuration.ingress.fqdn -o tsv)

# Test health endpoint
curl https://$APP_URL/health

# Test API endpoint
curl -H "x-api-key: devkey123" https://$APP_URL/api/v1/report/ingestion
```

---

#### Step 2.3: Configure Autoscaling
```bash
# Add HTTP scaling rule
az containerapp update \
  --name janusec-api \
  --resource-group janusec-prod-rg \
  --scale-rule-name http-rule \
  --scale-rule-type http \
  --scale-rule-http-concurrency 50

# Add CPU scaling rule
az containerapp update \
  --name janusec-api \
  --resource-group janusec-prod-rg \
  --scale-rule-name cpu-rule \
  --scale-rule-type cpu \
  --scale-rule-metadata "type=Utilization" "value=70"

# Add custom metric (queue depth)
az containerapp update \
  --name janusec-api \
  --resource-group janusec-prod-rg \
  --scale-rule-name queue-rule \
  --scale-rule-type azure-queue \
  --scale-rule-metadata \
    "queueName=event-queue" \
    "queueLength=100" \
    "accountName=janusecprodstore"
```

**Validation Tests**:
```bash
# Trigger autoscaling with load test
python scripts/stress_run_http_concurrent.py \
  --url https://$APP_URL \
  --rate 5000 \
  --duration 300

# Monitor scaling in real-time
az containerapp revision list \
  --name janusec-api \
  --resource-group janusec-prod-rg \
  --query "[].{Name:name,Replicas:properties.replicas}" -o table

# Watch metrics in portal:
# Portal > Container App > Monitoring > Metrics
# - HTTP Request Count
# - CPU Usage
# - Memory Usage
# - Replica Count
```

---

### **Phase 3: Load Testing & Validation (Week 2)**

#### Step 3.1: 10K Events/Sec Load Test
```bash
# Setup: Deploy load test VM in same region
az vm create \
  --name loadtest-vm \
  --resource-group janusec-prod-rg \
  --image UbuntuLTS \
  --size Standard_D8s_v3 \
  --admin-username azureuser \
  --generate-ssh-keys

# SSH into VM and run load test
ssh azureuser@<vm-ip>

# Install dependencies
sudo apt update
sudo apt install python3-pip -y
pip3 install httpx asyncio

# Run load test
python3 stress_run_http_concurrent.py \
  --url https://$APP_URL/api/v1/events/ingest \
  --rate 10000 \
  --duration 600 \
  --workers 20
```

**Success Criteria**:
- [ ] Sustained 10K events/sec for 10 minutes
- [ ] P95 latency < 500ms
- [ ] P99 latency < 1000ms
- [ ] 0% error rate
- [ ] Memory usage < 80%
- [ ] CPU usage < 70%
- [ ] Autoscaling triggered correctly

**Monitor**:
```bash
# Application Insights query
az monitor app-insights query \
  --app janusec-ai \
  --analytics-query "
    requests
    | where timestamp > ago(10m)
    | summarize
        count=count(),
        p50=percentile(duration, 50),
        p95=percentile(duration, 95),
        p99=percentile(duration, 99)
    by bin(timestamp, 1m)
  "
```

---

#### Step 3.2: Database Performance Validation
```bash
# Run migration performance test
time python scripts/run_smoke_migration.py --target postgres --confirm

# Expected: < 60 seconds for all 18 migrations

# Test write throughput
python scripts/measure_db_writes.py \
  --host janusec-db-prod.postgres.database.azure.com \
  --rate 1000 \
  --duration 300

# Expected: 1000 writes/sec sustained
```

**Success Criteria**:
- [ ] Migrations complete in < 60s
- [ ] 1000 writes/sec sustained
- [ ] Query latency P95 < 50ms
- [ ] Connection pool exhaustion = 0
- [ ] Deadlocks = 0

---

#### Step 3.3: Redis Performance Validation
```bash
# Test correlation cache performance
python scripts/test_redis_correlation.py \
  --host janusec-redis-prod.redis.cache.windows.net \
  --port 6380 \
  --ssl true \
  --operations 100000

# Expected: 10K ops/sec, P95 latency < 5ms
```

**Success Criteria**:
- [ ] 10K ops/sec throughput
- [ ] P95 latency < 5ms
- [ ] Cache hit rate > 80%
- [ ] Memory eviction rate < 1%
- [ ] Connection errors = 0

---

### **Phase 4: Security Validation (Week 2)**

#### Step 4.1: OWASP ZAP Security Scan
```bash
# Run ZAP baseline scan
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://$APP_URL \
  -r zap-report.html

# Run full active scan (takes 2-4 hours)
docker run -t owasp/zap2docker-stable zap-full-scan.py \
  -t https://$APP_URL \
  -r zap-full-report.html
```

**Success Criteria**:
- [ ] 0 high-severity vulnerabilities
- [ ] < 5 medium-severity vulnerabilities
- [ ] SQL injection tests = PASS
- [ ] XSS tests = PASS
- [ ] CSRF tests = PASS

---

#### Step 4.2: Multi-Tenant Isolation Test
```bash
# Create two test tenants
curl -X POST https://$APP_URL/api/v1/admin/tenants \
  -H "x-api-key: admin123" \
  -d '{"tenant_id": "tenant-a", "name": "Tenant A"}'

curl -X POST https://$APP_URL/api/v1/admin/tenants \
  -H "x-api-key: admin123" \
  -d '{"tenant_id": "tenant-b", "name": "Tenant B"}'

# Upload events for tenant-a
curl -X POST https://$APP_URL/api/v1/events/ingest \
  -H "x-api-key: tenant-a-key" \
  -H "x-tenant-id: tenant-a" \
  -d @sample_events.json

# Attempt cross-tenant access (should fail)
curl https://$APP_URL/api/v1/alerts \
  -H "x-api-key: tenant-b-key" \
  -H "x-tenant-id: tenant-a"  # Wrong tenant!

# Expected: 403 Forbidden
```

**Success Criteria**:
- [ ] Cross-tenant data access blocked
- [ ] Tenant isolation in database verified
- [ ] Redis cache isolated per tenant
- [ ] Audit log captures access attempts

---

## 📊 Priority Matrix

| Priority | Component | Effort | Impact | Azure Dependency |
|----------|-----------|--------|--------|------------------|
| **P0** | Redis HA | 3 days | High | Azure Cache Premium |
| **P0** | PostgreSQL Migration | 2 days | Critical | PostgreSQL Flexible |
| **P0** | Load Testing 10K/sec | 4 days | High | Container Apps + VM |
| **P0** | D3.js Graph Viz | 2 days | High | None |
| **P0** | MITRE Heatmap | 1 day | Medium | None |
| **P1** | Security Audit | 5 days | Critical | Security Center |
| **P1** | SBOM VPR Integration | 3 days | Medium | Key Vault |
| **P1** | HopGraph Stress Test | 2 days | Medium | None |
| **P1** | Remediation Modals | 2 days | Low | None |
| **P2** | EWMA Tuning | 3 days | Low | None |
| **P2** | TF-IDF Validation | 2 days | Low | None |

**Total Estimated Effort**: 29 days (6 weeks with parallel work)
**Azure Credit Required**: $500-800 for 2 weeks of testing

---

## 🎯 Next Steps

1. **Read Part 2**: 3rd HopGraph analysis, eBPF security, BGP detection
2. **Read Part 3**: Visual polish implementation + data preparation
3. **Provision Azure resources** using terraform scripts
4. **Run P0 tests** in order (Redis HA → PostgreSQL → Load Test)
5. **Schedule security audit** with external firm

**For questions or clarifications, see the other roadmap parts.**
