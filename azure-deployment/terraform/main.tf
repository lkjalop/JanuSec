# JanuSec Platform - Azure Deployment with Terraform
# This creates a complete Azure environment for the JanuSec threat detection platform

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Variables
variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
  default     = "janusec-platform-rg"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "East US"
}

variable "app_name" {
  description = "Name of the application"
  type        = string
  default     = "janusec-platform"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "container_image" {
  description = "Full container image (e.g. myacr.azurecr.io/janusec-api:tag)"
  type        = string
}

variable "allowed_origins" {
  description = "Comma-separated list of allowed CORS origins"
  type        = string
}

# Resource Group
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    Environment = var.environment
    Project     = "JanuSec"
    Purpose     = "Threat Detection Platform"
  }
}

# Container Registry
resource "azurerm_container_registry" "acr" {
  name                = "${var.app_name}acr${var.environment}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = true

  tags = {
    Environment = var.environment
    Component   = "Container Registry"
  }
}

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.app_name}-logs-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Environment = var.environment
    Component   = "Logging"
  }
}

# Container Apps Environment
resource "azurerm_container_app_environment" "main" {
  name                       = "${var.app_name}-env-${var.environment}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  tags = {
    Environment = var.environment
    Component   = "Container Environment"
  }
}

# PostgreSQL Flexible Server
resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "${var.app_name}-db-${var.environment}"
  resource_group_name    = azurerm_resource_group.main.name
  location              = azurerm_resource_group.main.location
  version               = "14"
  administrator_login   = "janusec_admin"
  administrator_password = "JanuSec2025!"
  storage_mb            = 32768
  sku_name              = "B_Standard_B1ms"

  backup_retention_days = 7

  tags = {
    Environment = var.environment
    Component   = "Database"
  }
}

# PostgreSQL Database
resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "janusec_platform"
  server_id = azurerm_postgresql_flexible_server.main.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

# Container App for JanuSec Platform
resource "azurerm_container_app" "main" {
  name                         = "${var.app_name}-app-${var.environment}"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  template {
    min_replicas = 1
    max_replicas = 3

    container {
      name   = "janusec-platform"
      image  = var.container_image
      cpu    = 1
      memory = "2Gi"

      startup_probe {
        port = 8000
        path = "/health"
      }

      liveness_probe {
        port = 8000
        path = "/health"
      }

      readiness_probe {
        port = 8000
        path = "/health"
      }

      env {
        name  = "PORT"
        value = "8000"
      }

      env {
        name  = "DB_TYPE"
        value = "postgres"
      }

      env {
        name  = "DATABASE_URL"
        value = "postgresql://janusec_admin:JanuSec2025!@${azurerm_postgresql_flexible_server.main.fqdn}:5432/janusec_platform"
      }

      env {
        name  = "ALLOWED_ORIGINS"
        value = var.allowed_origins
      }

      env {
        name  = "RATE_LIMIT_ENABLED"
        value = "1"
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
    }
  }

  ingress {
    allow_insecure_connections = false
    external_enabled          = true
    target_port               = 8000

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  tags = {
    Environment = var.environment
    Component   = "Application"
  }
}

# Storage Account for artifacts and logs
resource "azurerm_storage_account" "main" {
  name                     = "${var.app_name}storage${var.environment}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    Environment = var.environment
    Component   = "Storage"
  }
}

# Key Vault for secrets
resource "azurerm_key_vault" "main" {
  name                = "${var.app_name}-kv-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete",
      "Purge",
      "Recover"
    ]
  }

  tags = {
    Environment = var.environment
    Component   = "Security"
  }
}

data "azurerm_client_config" "current" {}

# Outputs
output "application_url" {
  description = "URL of the deployed JanuSec platform"
  value       = "https://${azurerm_container_app.main.latest_revision_fqdn}"
}

output "database_fqdn" {
  description = "PostgreSQL server FQDN"
  value       = azurerm_postgresql_flexible_server.main.fqdn
}

output "container_registry_login_server" {
  description = "Container registry login server"
  value       = azurerm_container_registry.acr.login_server
}

output "storage_account_name" {
  description = "Storage account name"
  value       = azurerm_storage_account.main.name
}

output "key_vault_uri" {
  description = "Key Vault URI"
  value       = azurerm_key_vault.main.vault_uri
}
