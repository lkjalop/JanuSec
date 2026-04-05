# JanuSec Platform - Azure Terraform Deployment
# Version: 1.0
# Region: Australia Southeast (Sydney)

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
      recover_soft_deleted_key_vaults = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

# Generate random suffix for globally unique names
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.azure_region

  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
    Project     = "JanuSec"
  }
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "janusec-vnet-${random_string.suffix.result}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    Environment = var.environment
  }
}

# Public Subnet (DMZ - for Application Gateway)
resource "azurerm_subnet" "public" {
  name                 = "public-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Private Subnet (Container Apps)
resource "azurerm_subnet" "private" {
  name                 = "private-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/23"]
}

# Data Subnet (PostgreSQL, Redis)
resource "azurerm_subnet" "data" {
  name                 = "data-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.4.0/24"]

  service_endpoints = ["Microsoft.Storage"]

  delegation {
    name = "postgres-delegation"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}

# Network Security Group for Private Subnet
resource "azurerm_network_security_group" "private" {
  name                = "janusec-private-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "10.0.1.0/24"  # From public subnet
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowHTTP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "10.0.1.0/24"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "private" {
  subnet_id                 = azurerm_subnet.private.id
  network_security_group_id = azurerm_network_security_group.private.id
}

# PostgreSQL Flexible Server
resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "janusec-db-${random_string.suffix.result}"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  version                = "15"
  delegated_subnet_id    = azurerm_subnet.data.id
  private_dns_zone_id    = azurerm_private_dns_zone.postgres.id
  administrator_login    = var.postgres_admin_username
  administrator_password = random_password.postgres_password.result
  # zone intentionally omitted to avoid Availability Zone unavailability errors
  # zone = "1"
  storage_mb             = var.postgres_storage_gb * 1024
  sku_name               = var.postgres_sku
  backup_retention_days  = var.postgres_backup_days
  public_network_access_enabled = false

  lifecycle {
    # Avoid Terraform attempting to remove/change availability zone on an
    # existing server created earlier in this workspace. This prevents the
    # "zone can only be changed" error during replace operations in a POC run.
    ignore_changes = [zone]
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]

  tags = {
    Environment = var.environment
  }
}

# PostgreSQL Private DNS Zone
resource "azurerm_private_dns_zone" "postgres" {
  name                = "janusec-postgres.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "postgres-vnet-link"
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.main.id
  resource_group_name   = azurerm_resource_group.main.name
}

# PostgreSQL Database
resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "janusec"
  server_id = azurerm_postgresql_flexible_server.main.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

# PostgreSQL Firewall Rule (Allow Container Apps subnet)
resource "azurerm_postgresql_flexible_server_firewall_rule" "container_apps" {
  name             = "allow-container-apps"
  server_id        = azurerm_postgresql_flexible_server.main.id
  start_ip_address = "10.0.2.0"
  end_ip_address   = "10.0.3.255"
}

# Redis Cache (Premium tier for HA)
resource "azurerm_redis_cache" "main" {
  name                = "janusec-redis-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  capacity            = var.redis_capacity
  family              = var.redis_family
  sku_name            = var.redis_sku
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"

  redis_configuration {
    enable_authentication = true
    maxmemory_policy      = "allkeys-lru"
  }

  tags = {
    Environment = var.environment
  }
}

# Key Vault for Secrets Management
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                        = "janusec-kv-${random_string.suffix.result}"
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  sku_name                    = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get", "List", "Create", "Delete", "Update",
    ]

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Recover", "Backup", "Restore", "Purge",
    ]

    storage_permissions = [
      "Get", "List", "Set", "Delete",
    ]
  }

  tags = {
    Environment = var.environment
  }
}

# Generate Secrets
resource "random_password" "postgres_password" {
  length  = 32
  special = true
}

resource "random_password" "api_secret_key" {
  length  = 64
  special = true
}

resource "random_password" "admin_password" {
  length  = 24
  special = true
}

# Store Secrets in Key Vault
resource "azurerm_key_vault_secret" "postgres_password" {
  name         = "postgres-password"
  value        = random_password.postgres_password.result
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_key_vault_secret" "redis_password" {
  name         = "redis-password"
  value        = azurerm_redis_cache.main.primary_access_key
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_key_vault_secret" "api_secret_key" {
  name         = "api-secret-key"
  value        = random_password.api_secret_key.result
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_key_vault_secret" "admin_password" {
  name         = "admin-password"
  value        = random_password.admin_password.result
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_key_vault_secret" "slack_webhook" {
  name         = "slack-webhook-url"
  value        = var.slack_webhook_url
  key_vault_id = azurerm_key_vault.main.id
}

# Log Analytics Workspace for Monitoring
resource "azurerm_log_analytics_workspace" "main" {
  name                = "janusec-logs-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Environment = var.environment
  }
}

# Application Insights
resource "azurerm_application_insights" "main" {
  name                = "janusec-insights-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"

  tags = {
    Environment = var.environment
  }
}

# Container Apps Environment
resource "azurerm_container_app_environment" "main" {
  count                      = var.create_container_app_environment ? 1 : 0
  name                       = "janusec-env-${random_string.suffix.result}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  infrastructure_subnet_id   = azurerm_subnet.private.id

  tags = {
    Environment = var.environment
  }
}

# Select either the created environment id (when count = 1) or an existing
# environment id supplied via var.container_app_environment_id. The `try`
# call prevents lookup errors when the resource is not created.
locals {
  container_app_environment_id = try(azurerm_container_app_environment.main[0].id, var.container_app_environment_id)
}

# Container App - API Server
resource "azurerm_container_app" "api" {
  name                         = "janusec-api"
  container_app_environment_id = local.container_app_environment_id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  template {
    min_replicas = var.api_min_replicas
    max_replicas = var.api_max_replicas

    container {
      name   = "janusec-api"
      image  = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"  # Replace with actual image
      cpu    = 1.0
      memory = "2Gi"

      env {
        name  = "POSTGRES_HOST"
        value = azurerm_postgresql_flexible_server.main.fqdn
      }

      env {
        name  = "POSTGRES_USER"
        value = var.postgres_admin_username
      }

      env {
        name        = "POSTGRES_PASSWORD"
        secret_name = "postgres-password"
      }

      env {
        name  = "POSTGRES_DB"
        value = "janusec"
      }

      env {
        name  = "REDIS_HOST"
        value = azurerm_redis_cache.main.hostname
      }

      env {
        name        = "REDIS_PASSWORD"
        secret_name = "redis-password"
      }

      env {
        name        = "SECRET_KEY"
        secret_name = "api-secret-key"
      }

      env {
        name  = "APPINSIGHTS_INSTRUMENTATIONKEY"
        value = azurerm_application_insights.main.instrumentation_key
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
    }
  }

  secret {
    name  = "postgres-password"
    value = random_password.postgres_password.result
  }

  secret {
    name  = "redis-password"
    value = azurerm_redis_cache.main.primary_access_key
  }

  secret {
    name  = "api-secret-key"
    value = random_password.api_secret_key.result
  }

  ingress {
    external_enabled = true
    target_port      = 8000

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  tags = {
    Environment = var.environment
  }
}

# Container App - Background Worker
resource "azurerm_container_app" "worker" {
  name                         = "janusec-worker"
  container_app_environment_id = local.container_app_environment_id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  template {
    min_replicas = var.worker_min_replicas
    max_replicas = var.worker_max_replicas

    container {
      name   = "janusec-worker"
      image  = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"  # Replace with actual image
      cpu    = 2.0
      memory = "4Gi"

      env {
        name  = "POSTGRES_HOST"
        value = azurerm_postgresql_flexible_server.main.fqdn
      }

      env {
        name  = "POSTGRES_USER"
        value = var.postgres_admin_username
      }

      env {
        name        = "POSTGRES_PASSWORD"
        secret_name = "postgres-password"
      }

      env {
        name  = "POSTGRES_DB"
        value = "janusec"
      }

      env {
        name  = "REDIS_HOST"
        value = azurerm_redis_cache.main.hostname
      }

      env {
        name        = "REDIS_PASSWORD"
        secret_name = "redis-password"
      }

      env {
        name        = "SLACK_WEBHOOK_URL"
        secret_name = "slack-webhook"
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }

      env {
        name  = "WORKER_MODE"
        value = "background"
      }
    }
  }

  secret {
    name  = "postgres-password"
    value = random_password.postgres_password.result
  }

  secret {
    name  = "redis-password"
    value = azurerm_redis_cache.main.primary_access_key
  }

  secret {
    name  = "slack-webhook"
    value = var.slack_webhook_url
  }

  tags = {
    Environment = var.environment
  }
}

# Storage Account for Artifacts
resource "azurerm_storage_account" "main" {
  name                     = "janusecstore${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  tags = {
    Environment = var.environment
  }
}

resource "azurerm_storage_container" "artifacts" {
  name                  = "artifacts"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

# Application Gateway (WAF) - Optional, expensive
resource "azurerm_public_ip" "appgw" {
  count               = var.enable_waf ? 1 : 0
  name                = "janusec-appgw-pip"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Environment = var.environment
  }
}

# Cost Management - Budget Alert
resource "azurerm_consumption_budget_resource_group" "main" {
  name              = "janusec-budget"
  resource_group_id = azurerm_resource_group.main.id

  amount     = 500
  time_grain = "Monthly"

  time_period {
    start_date = "2025-10-01T00:00:00Z"
    end_date   = "2026-12-31T23:59:59Z"
  }

  notification {
    enabled   = true
    threshold = 80.0
    operator  = "GreaterThan"

    contact_emails = [
      var.admin_email,
    ]
  }

  notification {
    enabled   = true
    threshold = 100.0
    operator  = "GreaterThan"

    contact_emails = [
      var.admin_email,
    ]
  }
}
