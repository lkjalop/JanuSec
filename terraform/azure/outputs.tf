# JanuSec Platform - Terraform Outputs
# These values are displayed after successful deployment

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_location" {
  description = "Azure region where resources are deployed"
  value       = azurerm_resource_group.main.location
}

output "api_url" {
  description = "JanuSec API endpoint URL"
  value       = "https://${azurerm_container_app.api.latest_revision_fqdn}"
}

output "api_fqdn" {
  description = "API fully qualified domain name"
  value       = azurerm_container_app.api.latest_revision_fqdn
}

output "worker_fqdn" {
  description = "Worker fully qualified domain name"
  value       = azurerm_container_app.worker.latest_revision_fqdn
}

output "postgres_host" {
  description = "PostgreSQL server hostname"
  value       = azurerm_postgresql_flexible_server.main.fqdn
  sensitive   = true
}

output "postgres_database" {
  description = "PostgreSQL database name"
  value       = azurerm_postgresql_flexible_server_database.main.name
}

output "postgres_username" {
  description = "PostgreSQL admin username"
  value       = var.postgres_admin_username
  sensitive   = true
}

output "redis_host" {
  description = "Redis cache hostname"
  value       = azurerm_redis_cache.main.hostname
  sensitive   = true
}

output "redis_port" {
  description = "Redis SSL port"
  value       = azurerm_redis_cache.main.ssl_port
}

output "key_vault_name" {
  description = "Azure Key Vault name"
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "Azure Key Vault URI"
  value       = azurerm_key_vault.main.vault_uri
}

output "storage_account_name" {
  description = "Storage account name for artifacts"
  value       = azurerm_storage_account.main.name
}

output "storage_container_name" {
  description = "Blob container name for artifacts"
  value       = azurerm_storage_container.artifacts.name
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID"
  value       = azurerm_log_analytics_workspace.main.id
}

output "application_insights_key" {
  description = "Application Insights instrumentation key"
  value       = azurerm_application_insights.main.instrumentation_key
  sensitive   = true
}

output "application_insights_connection_string" {
  description = "Application Insights connection string"
  value       = azurerm_application_insights.main.connection_string
  sensitive   = true
}

output "admin_password" {
  description = "Generated admin password (stored in Key Vault)"
  value       = random_password.admin_password.result
  sensitive   = true
}

output "deployment_summary" {
  description = "Deployment summary with key information"
  value = <<-EOT
    ╔════════════════════════════════════════════════════════════════════════════════╗
    ║                  JANUSEC PLATFORM DEPLOYMENT SUMMARY                           ║
    ╚════════════════════════════════════════════════════════════════════════════════╝

    📍 Region: ${azurerm_resource_group.main.location}
    🏷️  Environment: ${var.environment}
    📦 Resource Group: ${azurerm_resource_group.main.name}

    🌐 API ENDPOINT:
       https://${azurerm_container_app.api.latest_revision_fqdn}

    🔧 SERVICES:
       - API Replicas: ${var.api_min_replicas} (min) → ${var.api_max_replicas} (max)
       - Worker Replicas: ${var.worker_min_replicas} (min) → ${var.worker_max_replicas} (max)
       - PostgreSQL: ${var.postgres_sku} (${var.postgres_storage_gb}GB)
       - Redis: ${var.redis_sku} ${var.redis_family}${var.redis_capacity}

    🔐 SECRETS (stored in Key Vault):
       - Key Vault: ${azurerm_key_vault.main.name}
       - Retrieve admin password:
         az keyvault secret show --vault-name ${azurerm_key_vault.main.name} --name admin-password

    📊 MONITORING:
       - Application Insights: ${azurerm_application_insights.main.name}
       - Log Analytics: ${azurerm_log_analytics_workspace.main.name}

    ✅ NEXT STEPS:
       1. Test API health: curl https://${azurerm_container_app.api.latest_revision_fqdn}/health
       2. Upload sample data: scripts/upload_test_data.sh
       3. View logs: az monitor app-insights query --app ${azurerm_application_insights.main.name} --analytics-query "traces | take 10"
       4. Access Key Vault: az keyvault secret list --vault-name ${azurerm_key_vault.main.name}

    💰 ESTIMATED MONTHLY COST: ~$150-300 AUD (testing tier)
       - Scale up postgres_sku to GP_Standard_D4s for production (+$250/month)
       - Enable WAF (enable_waf = true) for production (+$180/month)

    🎯 PLATFORM READY FOR VALIDATION!
  EOT
}

output "connection_strings" {
  description = "Connection strings for manual configuration"
  value = {
    postgres = "postgresql://${var.postgres_admin_username}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/janusec?sslmode=require"
    redis    = "rediss://:${azurerm_redis_cache.main.primary_access_key}@${azurerm_redis_cache.main.hostname}:${azurerm_redis_cache.main.ssl_port}"
  }
  sensitive = true
}

output "quick_commands" {
  description = "Useful Azure CLI commands for post-deployment"
  value = <<-EOT
    # Restart API container
    az containerapp revision restart --name janusec-api --resource-group ${azurerm_resource_group.main.name}

    # Scale API manually
    az containerapp update --name janusec-api --resource-group ${azurerm_resource_group.main.name} --min-replicas 5 --max-replicas 15

    # View API logs (last 50 lines)
    az containerapp logs show --name janusec-api --resource-group ${azurerm_resource_group.main.name} --tail 50

    # Get admin password from Key Vault
    az keyvault secret show --vault-name ${azurerm_key_vault.main.name} --name admin-password --query value -o tsv

    # Check PostgreSQL firewall rules
    az postgres flexible-server firewall-rule list --resource-group ${azurerm_resource_group.main.name} --name ${azurerm_postgresql_flexible_server.main.name}

    # View Redis metrics
    az redis show --name ${azurerm_redis_cache.main.name} --resource-group ${azurerm_resource_group.main.name}

    # Check cost to date
    az consumption usage list --subscription $(az account show --query id -o tsv) --start-date 2025-10-01 --end-date 2025-10-31
  EOT
}
