# JanuSec Platform - Azure Terraform Deployment

This directory contains Terraform infrastructure-as-code for deploying the JanuSec security triage platform on Microsoft Azure.

## Architecture Overview

```
Internet → App Gateway (WAF) → Container Apps (API + Worker) → PostgreSQL + Redis
                                          ↓
                                  Key Vault (secrets)
                                          ↓
                          Azure Monitor + App Insights (observability)
```

## Prerequisites

### 1. Install Required Tools

- **Azure CLI** (v2.50+): https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
- **Terraform** (v1.5+): https://www.terraform.io/downloads
- **Git**: https://git-scm.com/downloads

### 2. Azure Subscription

You need an active Azure subscription with:
- **Contributor** role (to create resources)
- **User Access Administrator** role (to assign managed identities)
- **$200+ AUD** in credits or billing enabled

### 3. Authenticate to Azure

```bash
# Login to Azure
az login

# List subscriptions
az account list --output table

# Set active subscription
az account set --subscription "YOUR_SUBSCRIPTION_NAME_OR_ID"

# Verify
az account show
```

## Deployment Steps

### Step 1: Clone Repository

```bash
git clone https://github.com/janusec/platform.git
cd platform/terraform/azure
```

### Step 2: Configure Variables

```bash
# Copy example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit configuration (use your preferred editor)
nano terraform.tfvars
```

**Key variables to customize:**
- `admin_email`: Your email for budget alerts
- `slack_webhook_url`: Slack webhook for alert notifications (optional)
- `azure_region`: Keep as `australiasoutheast` for APAC data residency
- `postgres_sku`: Use `B_Standard_B2s` for testing, `GP_Standard_D4s` for production
- `enable_waf`: Set to `false` for testing (saves ~$180/month)

### Step 3: Initialize Terraform

```bash
terraform init

# Expected output:
# Terraform has been successfully initialized!
```

### Step 4: Plan Deployment (Dry-Run)

```bash
terraform plan -out=tfplan

# Review output carefully:
# - Resource count: ~25 resources
# - Estimated cost: ~$150-300 AUD/month
# - No errors or warnings
```

### Step 5: Deploy Infrastructure

```bash
terraform apply tfplan

# This takes 8-12 minutes to provision:
# - Resource Group (30 sec)
# - Virtual Network + Subnets (1 min)
# - PostgreSQL Flexible Server (3-4 min)
# - Redis Premium Cache (4-5 min)
# - Container Apps (1-2 min)
# - Key Vault + Secrets (30 sec)
```

### Step 6: Verify Deployment

```bash
# Display deployment outputs
terraform output

# Test API health endpoint
API_URL=$(terraform output -raw api_url)
curl $API_URL/health

# Expected response:
# {"status": "healthy", "database": "connected", "redis": "connected"}
```

## Post-Deployment Tasks

### 1. Retrieve Admin Password

```bash
# Get Key Vault name
KV_NAME=$(terraform output -raw key_vault_name)

# Retrieve admin password
az keyvault secret show --vault-name $KV_NAME --name admin-password --query value -o tsv
```

### 2. Configure Slack Notifications

```bash
# Update Slack webhook URL in Key Vault
az keyvault secret set \
  --vault-name $KV_NAME \
  --name slack-webhook-url \
  --value "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Restart worker to pick up new secret
RG_NAME=$(terraform output -raw resource_group_name)
az containerapp revision restart --name janusec-worker --resource-group $RG_NAME
```

### 3. Upload Sample Data

```bash
# Upload CSV with 1000 sample events
curl -X POST $API_URL/api/v1/csv/upload \
  -H "Authorization: Bearer $(az account get-access-token --query accessToken -o tsv)" \
  -F "file=@../../sample_data/xdr_events_1000.csv"

# Check processing status
curl $API_URL/api/v1/events/stats
```

### 4. View Logs

```bash
# API logs (last 50 lines)
az containerapp logs show --name janusec-api --resource-group $RG_NAME --tail 50

# Worker logs (last 50 lines)
az containerapp logs show --name janusec-worker --resource-group $RG_NAME --tail 50

# PostgreSQL slow queries
az postgres flexible-server show --name $(terraform output -raw postgres_host | cut -d'.' -f1) --resource-group $RG_NAME
```

### 5. Access Monitoring Dashboards

```bash
# Open Application Insights in browser
az monitor app-insights show --app $(terraform output -raw application_insights_key) --resource-group $RG_NAME --query id -o tsv | xargs -I {} open "https://portal.azure.com/#@/resource{}/overview"

# Query logs with Azure CLI
az monitor app-insights query \
  --app $(terraform output -raw application_insights_key) \
  --analytics-query "traces | where timestamp > ago(1h) | take 100"
```

## Load Testing

### Install K6 (Load Testing Tool)

```bash
# macOS
brew install k6

# Windows (Chocolatey)
choco install k6

# Linux
sudo apt-get install k6
```

### Run Load Test

```bash
# Basic load test: 10 virtual users, 5 minutes
k6 run ../../scripts/loadtest.js \
  --vus 10 \
  --duration 5m \
  --env API_URL=$API_URL

# Expected results:
# - Throughput: 500-1000 events/sec
# - p95 latency: <200ms
# - Error rate: <1%
```

### Monitor Auto-Scaling

```bash
# Watch replica count (refresh every 5 seconds)
watch -n 5 "az containerapp revision list --name janusec-api --resource-group $RG_NAME --query '[].{name:name, replicas:properties.replicas, traffic:properties.trafficWeight}' -o table"

# Expected behavior:
# - Starts at 2 replicas (min)
# - Scales up to 10 replicas under load
# - Scales down to 2 replicas after load stops (5-10 min)
```

## Cost Management

### View Current Costs

```bash
# Current month costs by resource
az consumption usage list \
  --start-date 2025-10-01 \
  --end-date 2025-10-31 \
  --query "[?contains(instanceName, 'janusec')].{Resource:instanceName, Cost:pretaxCost}" \
  -o table

# Total cost to date
az consumption usage list \
  --start-date 2025-10-01 \
  --end-date 2025-10-31 \
  --query "sum([?contains(instanceName, 'janusec')].pretaxCost)"
```

### Optimize Costs

**For Testing (Minimal Cost: ~$150 AUD/month):**
```bash
# Scale down API replicas
az containerapp update --name janusec-api --resource-group $RG_NAME --min-replicas 1 --max-replicas 3

# Downgrade Redis to Basic tier (WARNING: loses HA)
az redis update --name $(terraform output -raw redis_host | cut -d'.' -f1) --resource-group $RG_NAME --sku Basic --vm-size C1
```

**For Production (Optimal Performance: ~$600 AUD/month):**
```bash
# Scale up PostgreSQL
# Edit terraform.tfvars: postgres_sku = "GP_Standard_D4s"
terraform apply

# Enable WAF
# Edit terraform.tfvars: enable_waf = true
terraform apply

# Scale up API replicas
az containerapp update --name janusec-api --resource-group $RG_NAME --min-replicas 4 --max-replicas 20
```

## Troubleshooting

### Issue 1: PostgreSQL Connection Timeout

**Symptom:** API logs show `could not connect to PostgreSQL`

**Fix:** Add Container Apps subnet to PostgreSQL firewall
```bash
az postgres flexible-server firewall-rule create \
  --resource-group $RG_NAME \
  --name $(terraform output -raw postgres_host | cut -d'.' -f1) \
  --rule-name allow-container-apps \
  --start-ip-address 10.0.2.0 \
  --end-ip-address 10.0.2.255
```

### Issue 2: Redis AUTH Failed

**Symptom:** Worker logs show `NOAUTH Authentication required`

**Fix:** Update Redis password in Container App env vars
```bash
REDIS_PASSWORD=$(az keyvault secret show --vault-name $KV_NAME --name redis-password --query value -o tsv)

az containerapp update \
  --name janusec-worker \
  --resource-group $RG_NAME \
  --set-env-vars REDIS_PASSWORD=$REDIS_PASSWORD
```

### Issue 3: Container App Crash Loop

**Symptom:** Replicas stuck in `CrashLoopBackOff`

**Debug:**
```bash
# View recent logs
az containerapp logs show --name janusec-api --resource-group $RG_NAME --tail 100

# Check environment variables
az containerapp show --name janusec-api --resource-group $RG_NAME --query "properties.template.containers[0].env" -o table

# Restart revision
az containerapp revision restart --name janusec-api --resource-group $RG_NAME
```

### Issue 4: High Costs (>$500/month)

**Fix:** Review and scale down resources
```bash
# Check per-resource costs
az consumption usage list --query "[?contains(instanceName, 'janusec')].{Resource:instanceName, Cost:pretaxCost, Unit:usageQuantity}" -o table

# Disable Application Gateway if not needed (saves $180/month)
# Edit terraform.tfvars: enable_waf = false
terraform apply

# Scale down to minimal replicas
az containerapp update --name janusec-api --resource-group $RG_NAME --min-replicas 1
az containerapp update --name janusec-worker --resource-group $RG_NAME --min-replicas 1
```

## Security Hardening (Production)

### 1. Restrict Network Access

```bash
# Update terraform.tfvars to allow only your office IP
allowed_ip_ranges = ["203.0.113.0/24"]  # Replace with your IP range

# Apply changes
terraform apply
```

### 2. Enable Private Endpoints

```bash
# Edit main.tf to enable private endpoints for PostgreSQL and Redis
# This removes public IP access (recommended for production)

# Uncomment private_endpoint blocks in main.tf
terraform apply
```

### 3. Enable Managed Identity

```bash
# Assign system-assigned identity to Container Apps
az containerapp identity assign --name janusec-api --resource-group $RG_NAME --system-assigned

# Grant Key Vault access to managed identity
IDENTITY_ID=$(az containerapp show --name janusec-api --resource-group $RG_NAME --query identity.principalId -o tsv)

az keyvault set-policy --name $KV_NAME --object-id $IDENTITY_ID --secret-permissions get list
```

### 4. Rotate Secrets

```bash
# Generate new API secret key
NEW_SECRET=$(openssl rand -base64 48)

# Update in Key Vault
az keyvault secret set --vault-name $KV_NAME --name api-secret-key --value $NEW_SECRET

# Restart services to pick up new secret
az containerapp revision restart --name janusec-api --resource-group $RG_NAME
az containerapp revision restart --name janusec-worker --resource-group $RG_NAME
```

## Backup & Disaster Recovery

### Manual Backup

```bash
# PostgreSQL: Trigger manual backup
az postgres flexible-server backup create \
  --resource-group $RG_NAME \
  --name $(terraform output -raw postgres_host | cut -d'.' -f1) \
  --backup-name "manual-backup-$(date +%Y%m%d)"

# Redis: Force RDB snapshot
az redis force-reboot --name $(terraform output -raw redis_host | cut -d'.' -f1) --resource-group $RG_NAME --reboot-type AllNodes
```

### Point-in-Time Restore (PITR)

```bash
# Restore PostgreSQL to specific timestamp
az postgres flexible-server restore \
  --resource-group $RG_NAME \
  --name janusec-db-restored \
  --source-server $(terraform output -raw postgres_host | cut -d'.' -f1) \
  --restore-time "2025-10-20T14:30:00Z"
```

## Cleanup (Destroy Infrastructure)

```bash
# WARNING: This deletes ALL resources and data!
# Ensure you have backups before running this command.

# Review what will be destroyed
terraform plan -destroy

# Destroy all resources
terraform destroy

# Confirm by typing "yes" when prompted
# Deletion takes ~5 minutes

# Verify resource group is deleted
az group list --query "[?name=='$RG_NAME']"
# Should return empty array: []
```

## Cost Summary

| Configuration | Monthly Cost (AUD) | Use Case |
|---------------|-------------------|----------|
| **Minimal (Testing)** | $150-200 | Local dev, proof-of-concept |
| **Standard (Production)** | $400-600 | Small-medium business, MSSP |
| **Enterprise (HA + WAF)** | $800-1200 | Large enterprise, government |

**Key Cost Drivers:**
- Application Gateway (WAF): ~$180/month (optional)
- Redis Premium: ~$95/month (HA, recommended)
- PostgreSQL: $58-290/month (depends on SKU)
- Container Apps: $30-200/month (scales with traffic)

## Support

**Issues?** Open a ticket at: https://github.com/janusec/platform/issues

**Questions?** Email: support@janusec.com.au

**Documentation:** https://docs.janusec.com.au/azure-deployment

---

**Next Steps:** After successful deployment, proceed to upload sample data and run load tests to validate the platform under real-world conditions.
