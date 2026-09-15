# JanuSec Platform - Terraform Variables
# Configure these values in terraform.tfvars

variable "azure_region" {
  description = "Azure region for deployment"
  type        = string
  default     = "australiasoutheast"  # Sydney
  validation {
    condition     = contains(["australiasoutheast", "australiaeast", "australiacentral"], var.azure_region)
    error_message = "Must be an Australian region for data sovereignty"
  }
}

variable "resource_group_name" {
  description = "Name of the Azure resource group"
  type        = string
  default     = "janusec-prod-rg"
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production"
  }
}

variable "admin_email" {
  description = "Admin email for alerts and notifications"
  type        = string
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for alert notifications"
  type        = string
  default     = ""
  sensitive   = true
}

# Database Configuration
variable "postgres_admin_username" {
  description = "PostgreSQL administrator username"
  type        = string
  default     = "janusec_admin"
}

variable "postgres_sku" {
  description = "PostgreSQL SKU (B_Standard_B2s for testing, GP_Standard_D4s for production)"
  type        = string
  default     = "B_Standard_B2s"
  validation {
    condition     = contains(["B_Standard_B1ms", "B_Standard_B2s", "GP_Standard_D2s", "GP_Standard_D4s", "MO_Standard_E4s"], var.postgres_sku)
    error_message = "Invalid PostgreSQL SKU"
  }
}

variable "postgres_storage_gb" {
  description = "PostgreSQL storage in GB"
  type        = number
  default     = 32
  validation {
    condition     = var.postgres_storage_gb >= 32 && var.postgres_storage_gb <= 16384
    error_message = "Storage must be between 32GB and 16TB"
  }
}

variable "postgres_backup_days" {
  description = "PostgreSQL backup retention in days"
  type        = number
  default     = 35
  validation {
    condition     = var.postgres_backup_days >= 7 && var.postgres_backup_days <= 35
    error_message = "Backup retention must be between 7 and 35 days"
  }
}

# Redis Configuration
variable "redis_sku" {
  description = "Redis SKU (Basic, Standard, Premium)"
  type        = string
  default     = "Premium"
  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.redis_sku)
    error_message = "Redis SKU must be Basic, Standard, or Premium"
  }
}

variable "redis_family" {
  description = "Redis family (C for Basic/Standard, P for Premium)"
  type        = string
  default     = "P"
  validation {
    condition     = contains(["C", "P"], var.redis_family)
    error_message = "Redis family must be C or P"
  }
}

variable "redis_capacity" {
  description = "Redis capacity (0-6 for C family, 1-5 for P family)"
  type        = number
  default     = 1
  validation {
    condition     = var.redis_capacity >= 0 && var.redis_capacity <= 6
    error_message = "Redis capacity must be between 0 and 6"
  }
}

# Container Apps Scaling
variable "api_min_replicas" {
  description = "Minimum API replicas"
  type        = number
  default     = 2
  validation {
    condition     = var.api_min_replicas >= 1 && var.api_min_replicas <= 30
    error_message = "API min replicas must be between 1 and 30"
  }
}

variable "api_max_replicas" {
  description = "Maximum API replicas"
  type        = number
  default     = 10
  validation {
    condition     = var.api_max_replicas >= 1 && var.api_max_replicas <= 30
    error_message = "API max replicas must be between 1 and 30"
  }
}

variable "worker_min_replicas" {
  description = "Minimum worker replicas"
  type        = number
  default     = 1
  validation {
    condition     = var.worker_min_replicas >= 1 && var.worker_min_replicas <= 30
    error_message = "Worker min replicas must be between 1 and 30"
  }
}

variable "worker_max_replicas" {
  description = "Maximum worker replicas"
  type        = number
  default     = 5
  validation {
    condition     = var.worker_max_replicas >= 1 && var.worker_max_replicas <= 30
    error_message = "Worker max replicas must be between 1 and 30"
  }
}

# Security
variable "enable_waf" {
  description = "Enable Application Gateway with WAF (adds ~$180 AUD/month)"
  type        = bool
  default     = false  # Disable for testing to save costs
}

variable "allowed_ip_ranges" {
  description = "Allowed IP ranges for ingress (restrict in production)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# Tags
variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}

# Optional: reuse an existing Container Apps managed environment instead of
# creating a new one. Set `container_app_environment_id` to the existing
# environment ID (resource id) to reuse it. If empty, Terraform will create
# the environment when `create_container_app_environment` is true.
variable "container_app_environment_id" {
  description = "Optional existing Container Apps environment resource id to reuse (empty = create new)"
  type        = string
  default     = ""
}

variable "create_container_app_environment" {
  description = "Whether to create a new Container Apps environment. If false, `container_app_environment_id` must be set."
  type        = bool
  default     = true
}
