<#
quick_test_run.ps1

Safe helper to perform a minimal test deploy -> smoke validation -> teardown.
Usage: run from repository root or anywhere; script will cd into terraform/azure.
It attempts to install terraform via winget (or chocolatey if winget missing) if terraform is not found.

This script WILL destroy the deployed resources if you confirm the final prompt.
Read the script before running. You need Azure CLI authenticated (az login) and sufficient permissions.
#>

param(
    [int]$WaitMinutes = 10,
    [switch]$AutoApproveInstall,
    [switch]$SkipK6,
    [switch]$AutoApprove
)

function Write-Info { Write-Host "[INFO]" -ForegroundColor Cyan; Write-Host $args }
function Write-Warn { Write-Host "[WARN]" -ForegroundColor Yellow; Write-Host $args }
function Write-Err { Write-Host "[ERROR]" -ForegroundColor Red; Write-Host $args }

# Resolve repo paths
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
# If script is run from scripts/ make repo root one level up
if ((Split-Path $RepoRoot -Leaf) -ieq 'scripts') { $RepoRoot = Split-Path $RepoRoot -Parent }
$TerraformDir = Join-Path $RepoRoot 'terraform\azure'
$SampleCsv = Join-Path $RepoRoot 'sample_data\xdr_events_1000.csv'

Write-Info "Repo root: $RepoRoot"
Write-Info "Terraform dir: $TerraformDir"

# Check Azure CLI authentication
try {
    az account show > $null 2>&1
} catch {
    Write-Warn "Azure CLI not authenticated. Run 'az login' in another shell and re-run this script."
}

# Check terraform availability
$tf = Get-Command terraform -ErrorAction SilentlyContinue
if (-not $tf) {
    Write-Warn "Terraform not found on PATH. Attempting to install..."

    $canWinget = Get-Command winget -ErrorAction SilentlyContinue
    $canChoco  = Get-Command choco -ErrorAction SilentlyContinue

    if ($canWinget) {
        Write-Info "Installing Terraform via winget (requires interactive consent unless run with admin)"
        if ($AutoApproveInstall) { winget install --id HashiCorp.Terraform -e } else { winget install --id HashiCorp.Terraform -e }
    } elseif ($canChoco) {
        Write-Info "Installing Terraform via Chocolatey"
        choco install terraform -y
    } else {
        Write-Err "No winget or choco detected. Please install Terraform manually: https://www.terraform.io/downloads.html"
        exit 1
    }

    # re-check
    Start-Sleep -Seconds 3
    $tf = Get-Command terraform -ErrorAction SilentlyContinue
    if (-not $tf) {
        Write-Err "Terraform install attempted but terraform still not available. Ensure it's on PATH and re-run."
        exit 1
    }
}

# Confirm action
Write-Host "This script will: deploy a minimal test infra (Terraform), run quick smoke tests, then destroy the infra." -ForegroundColor Magenta
$ok = 'N'
if ($AutoApprove) { $ok = 'Y' } else { $ok = Read-Host "Continue? (Y/N)" }
if ($ok -notin @('Y','y')) { Write-Info "Aborting."; exit 0 }

Push-Location $TerraformDir

# Backup existing terraform.tfvars if present
$tfvarsPath = Join-Path $TerraformDir 'terraform.tfvars'
$tfvarsBackup = $null
if (Test-Path $tfvarsPath) {
    $tfvarsBackup = "$tfvarsPath.bak.$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
    Copy-Item $tfvarsPath $tfvarsBackup
    Write-Info "Backed up existing terraform.tfvars to $tfvarsBackup"
}

# Create a minimal terraform.tfvars for testing
$tfvarsContent = @"
azure_region = "australiasoutheast"
resource_group_name = "janusec-test-rg"
environment = "test"
admin_email = "test@example.local"
slack_webhook_url = ""

# Small test SKUs
postgres_sku = "B_Standard_B1ms"
postgres_storage_gb = 32
# If repo supports toggling Redis, try to disable it for fastest deploy. Otherwise this will be ignored.
redis_enabled = false
enable_waf = false
api_min_replicas = 1
api_max_replicas = 1
worker_min_replicas = 1
worker_max_replicas = 1
"@

Write-Info "Writing minimal terraform.tfvars for test (will overwrite existing)"
$tfvarsContent | Set-Content -Path $tfvarsPath -Encoding UTF8

# Terraform init/plan/apply
Write-Info "Running 'terraform init'..."
terraform init
if ($LASTEXITCODE -ne 0) { Write-Err "terraform init failed"; Pop-Location; exit 1 }

Write-Info "Running 'terraform plan'..."
terraform plan -out=tfplan
if ($LASTEXITCODE -ne 0) { Write-Err "terraform plan failed"; Pop-Location; exit 1 }

Write-Info "Apply will make real changes in your Azure subscription. Proceed with terraform apply? (Y/N)"
$ok2 = 'N'
if ($AutoApprove) { $ok2 = 'Y' } else { $ok2 = Read-Host "Apply?" }
if ($ok2 -notin @('Y','y')) { Write-Info "Skipping apply. Restoring tfvars and exiting."; if ($tfvarsBackup) { Copy-Item $tfvarsBackup $tfvarsPath -Force }; Pop-Location; exit 0 }

Write-Info "Applying the plan (this may take several minutes)..."
terraform apply -auto-approve tfplan
if ($LASTEXITCODE -ne 0) { Write-Err "terraform apply failed"; if ($tfvarsBackup) { Copy-Item $tfvarsBackup $tfvarsPath -Force }; Pop-Location; exit 1 }

# Grab outputs
Write-Info "Terraform apply complete. Fetching outputs..."
$apiUrl = terraform output -raw api_url 2>$null
$kvName = terraform output -raw key_vault_name 2>$null
Write-Info "api_url = $apiUrl"
Write-Info "key_vault_name = $kvName"

# Health check
if ($apiUrl) {
    Write-Info "Running health check against $apiUrl/health"
    try {
        $h = Invoke-RestMethod -Uri "$($apiUrl.TrimEnd('/'))/health" -Method GET -TimeoutSec 30
        Write-Info "Health response:`n$($h | ConvertTo-Json -Depth 4)"
    } catch {
        Write-Warn "Health check failed: $_"
    }
} else {
    Write-Warn "No api_url output; skipping health check."
}

# Upload sample CSV if present
if (Test-Path $SampleCsv -and $apiUrl) {
    Write-Info "Uploading sample CSV: $SampleCsv"
    $uploadCmd = "curl -X POST '$($apiUrl.TrimEnd('/'))/api/v1/csv/upload' -F 'file=@$SampleCsv'"
    Write-Info "Running upload (using PowerShell Invoke-WebRequest)..."
    try {
        $response = Invoke-RestMethod -Uri "$($apiUrl.TrimEnd('/'))/api/v1/csv/upload" -Method Post -InFile $SampleCsv -ContentType 'multipart/form-data'
        Write-Info "Upload response: $($response | ConvertTo-Json -Depth 4)"
    } catch {
        Write-Warn "Upload failed: $_"
    }
} else {
    Write-Warn "Sample CSV not found at $SampleCsv or no api_url; skipping upload."
}

# Optional: run tiny k6 test if available and not skipped
$k6 = Get-Command k6 -ErrorAction SilentlyContinue
if (-not $SkipK6 -and $k6 -and $apiUrl) {
    Write-Info "Running a small k6 smoke test (5 VUs, 1m) against the API ingestion endpoint"
    # assume scripts/loadtest.js exists and honors API_URL env
    Push-Location $RepoRoot
    try {
        k6 run scripts/loadtest.js --vus 5 --duration 1m --env API_URL=$apiUrl
    } catch {
        Write-Warn "k6 run failed or not configured: $_"
    }
    Pop-Location
} else {
    if ($SkipK6) { Write-Info "Skipping k6 as requested." } else { Write-Warn "k6 not found or api_url missing; skipping k6." }
}

Write-Info "Smoke tests done. Waiting $WaitMinutes minute(s) before teardown (you can change -WaitMinutes)."
Start-Sleep -Seconds ($WaitMinutes * 60)

# Prompt for destroy
Write-Info "Ready to destroy the deployed test infrastructure to avoid charges. Proceed to destroy? (Y/N)"
$ok3 = 'N'
if ($AutoApprove) { $ok3 = 'Y' } else { $ok3 = Read-Host "Destroy?" }
if ($ok3 -in @('Y','y')) {
    Write-Info "Destroying Terraform-managed resources (terraform destroy -auto-approve)"
    terraform destroy -auto-approve
    if ($LASTEXITCODE -ne 0) { Write-Warn "terraform destroy reported errors." }
} else {
    Write-Warn "Skipping destroy. You must run 'terraform destroy' later to avoid charges." 
}

# Restore tfvars if backed up
if ($tfvarsBackup -and (Test-Path $tfvarsBackup)) {
    Copy-Item $tfvarsBackup $tfvarsPath -Force
    Write-Info "Restored original terraform.tfvars from backup."
}

Pop-Location
Write-Info "Script finished."
