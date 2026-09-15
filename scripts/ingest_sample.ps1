# Ingest a small batch of sample endpoint events to drive visuals in the UI and Grafana
param(
    [string]$ApiBase = "http://localhost:8080",
    [int]$Count = 8,
    [string]$Tenant = "default"
)

$events = @()
$now = [int][double]::Parse(((Get-Date -UFormat %s)))
for($i=0; $i -lt $Count; $i++){
    $id = "evt-$now-$i"
    $e = @{
        id = $id
        host = "zeek-gw"
        dns_rcode = if($i % 3 -eq 0){ 3 } else { 0 }
        process = @{ name = "powershell.exe"; parent = if($i % 2 -eq 0){ "winword.exe" } else { "explorer.exe" } }
        details = @{ ip = "10.0.0.$i"; domain = if($i % 2 -eq 0){ "suspicious$i.test" } else { "ok$i.local" } }
    }
    $events += $e
}

$body = @{
    events = $events
    classify = $true
    include_rules = $true
    send_alerts = $true
    tenant_id = $Tenant
} | ConvertTo-Json -Depth 6

Write-Host "Posting $Count sample events to $ApiBase/api/v1/endpoints/log_batch ..."
$resp = Invoke-RestMethod -Method POST -Uri "$ApiBase/api/v1/endpoints/log_batch" -ContentType 'application/json' -Body $body -TimeoutSec 30
$resp | ConvertTo-Json -Depth 6

Write-Host "Recent sanitized events:" -ForegroundColor Cyan
$recent = Invoke-RestMethod -Uri "$ApiBase/api/v1/events/sanitized?limit=5" -TimeoutSec 15
$recent | ConvertTo-Json -Depth 6

Write-Host "Metrics presence (self-test):" -ForegroundColor Cyan
$m = Invoke-RestMethod -Uri "$ApiBase/api/v1/metrics/self_test" -TimeoutSec 15
$m | ConvertTo-Json -Depth 4
