**Terraform Guidance — Azure-focused Secure Multi‑Tenant Janusec Deployment**

Purpose: provide high-level Terraform patterns and resource guidance to implement the ASCII architecture. This is cloud-agnostic guidance with Azure examples.

Design choices
- Use modules to encapsulate repeatable constructs: `network`, `tenant`, `ingest`, `storage`, `kms`.
- Prefer separate Azure subscriptions for high-security tenants; otherwise, logical tenant isolation with tags and RBAC.
- Use Terraform remote state (e.g., storage account with blobs + Azure AD auth) for state locking.

High-level module list (suggested)
- `network` module: create VNET, subnets (dmz, app, data, forensic), Azure Firewall, NSGs, route tables.
- `ingest` module: public LB/API GW (Application Gateway/WAF), per-tenant API keys, autoscale VMSS or AKS for processors.
- `storage` module: storage account (blob) with SSE-KMS, container for forensic and DLQ with immutability policy.
- `db` module: optional Azure SQL / PostgreSQL flexible server per tenant or shared with row-level encryption.
- `kms` module: Key Vault + managed keys; RBAC policies to restrict key usage per tenant.
- `monitoring` module: Log Analytics workspace, Azure Monitor diagnostic settings, Prometheus exporters (if self-hosted).

Terraform pattern examples (pseudocode)

- Provider & backend
```
terraform {
  backend "azurerm" {
    resource_group_name  = "tfstate-rg"
    storage_account_name = "tfstateacct"
    container_name       = "tfstate"
    key                  = "janusec.terraform.tfstate"
  }
}

provider "azurerm" {
  features {}
}
```

- Network module example (inputs + outputs)
```
module "network" {
  source = "./modules/network"
  name   = "janusec-core"
  region = var.region
  address_space = ["10.0.0.0/16"]
  subnets = {
    dmz     = "10.0.1.0/24"
    app     = "10.0.2.0/24"
    data    = "10.0.3.0/24"
    forensic= "10.0.4.0/24"
  }
}
```

- Storage + forensic
```
resource "azurerm_storage_account" "forensic" {
  name                     = "janusecforensic${random_id.suffix.hex}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = var.region
  account_tier             = "Standard"
  account_replication_type = "GRS"
  enable_https_traffic_only= true
  is_hns_enabled           = false

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [module.network.subnet_forensic_id]
  }

  blob_properties {
    delete_retention_policy { days = 0 }
  }
}

resource "azurerm_storage_container" "dlq" {
  name                  = "dlq"
  storage_account_name  = azurerm_storage_account.forensic.name
  container_access_type = "private"
}

# Configure immutability via Azure CLI/ARM or policies (Terraform has limited direct support)
```

- Key Vault & keys
```
resource "azurerm_key_vault" "kv" {
  name                        = "janusec-kv-${random_id.suffix.hex}"
  resource_group_name         = azurerm_resource_group.rg.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_enabled         = true
  purge_protection_enabled    = true
  sku_name                    = "standard"
}

resource "azurerm_key_vault_key" "master_key" {
  name         = "janusec-master"
  key_vault_id = azurerm_key_vault.kv.id
  key_type     = "RSA"
  key_size     = 4096
}
```

- Per-tenant DB strategy
  - Option A: separate database servers per tenant (strong isolation). Create with `for_each` over tenants.
  - Option B: shared DB with tenant_id and row-level encryption (cheaper, requires careful RBAC and query sharding).

Policy & Compliance
- Use Azure Policy to enforce storage encryption, private endpoint usage, and tag policy for tenants.
- Use resource locks for critical resources and periodic drift detection via Sentinel or Terraform Cloud runs.

Latency & ingestion tuning
- Deploy ingestion endpoints in the region closest to the data source.
- Use EventHub or Azure Blob as local ingest durability, then replicate/stream to central analytics only when needed.
- Batch size: tune agent batching to balance latency vs egress cost. Use compression (snappy/gzip) and binary protocols when possible.

Operational recommendations
- CI/CD: use Terraform workspaces or separate state per environment (dev/stage/prod).
- Use `terraform fmt` and `tflint` in CI; run `terraform plan` and require PR approvals.
- Secrets: use managed identities for services, avoid storing credentials in TF state.

Interoperability for other LLM analysis (Claude/Opus)
- Provide concise JSON or YAML summaries of module inputs/outputs and resource names for LLM parsing.
- Export `tfplan` as JSON for audit analysis.

Appendix: quick checklist
- [ ] VNET + subnets (dmz, app, data, forensic)
- [ ] NSGs + Azure Firewall
- [ ] Storage account + container (DLQ, forensic) with private endpoints
- [ ] Key Vault + tenant-scoped keys
- [ ] Ingest compute (AKS/VMSS/Functions) with MSI
- [ ] DB provisioning (per-tenant or shared with sharding)
- [ ] Monitoring (Log Analytics) and alerting
