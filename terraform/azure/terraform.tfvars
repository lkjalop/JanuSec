# JanuSec Platform - Terraform Configuration
# Minimal config for testing deployment

# Azure Configuration
azure_region        = "australiaeast"  # Use Australia East for resource availability
resource_group_name = "janusec-prod-rg-aue-test"
environment         = "production"

# Admin Contact - CHANGE THIS TO YOUR EMAIL
admin_email = "leomark.jalop@studytafensw.edu.au"

# Slack Integration (optional - leave as-is if you don't have Slack)
# For POC set a harmless dummy webhook to satisfy secret requirements.
slack_webhook_url = "https://example.invalid/dummy-webhook"

# Database Configuration (minimal for testing)
postgres_admin_username = "janusec_admin"
postgres_sku            = "B_Standard_B2s"    # Burstable tier for testing
postgres_storage_gb     = 32
postgres_backup_days    = 7

# Redis Configuration (Premium for HA)
redis_sku      = "Premium"
redis_family   = "P"
redis_capacity = 1  # P1 = 6GB RAM

# Container Apps Auto-Scaling (minimal for testing)
api_min_replicas    = 2
api_max_replicas    = 10
worker_min_replicas = 1
worker_max_replicas = 5

# Security (disable WAF for testing to save costs)
enable_waf = false

# Reuse existing Container Apps managed environment to avoid subscription limit
# Set to false to avoid creating a new environment; provide existing env id below.
create_container_app_environment = false
container_app_environment_id = "/subscriptions/348f6251-1eff-4210-9394-54a58d6e1d9b/resourceGroups/janusec-prod-rg/providers/Microsoft.App/managedEnvironments/janusec-env-z7xgn7"

# Allowed IP ranges (allow all for testing)
allowed_ip_ranges = [
  "0.0.0.0/0"  # WARNING: Allow all IPs (testing only)
]

# Tags
tags = {
  CostCenter = "Security"
  Owner      = "Platform"
  Environment = "Testing"
}
