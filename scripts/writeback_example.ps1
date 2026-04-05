param(
  [string]$ApiBase = "http://localhost:8080",
  [string]$ApiKey = "devkey123",
  [string]$AlertId = "ecl-123",
  [string[]]$AddTags = @('investigated','true_positive'),
  [string]$Note = "Analyst enrichment",
  [string]$Severity = "high"
)

$body = @{ add_tags = $AddTags; note = $Note; severity = $Severity } | ConvertTo-Json -Depth 6

$uri = "$ApiBase/api/v1/integrations/eclipse/writeback?alert_id=$([uri]::EscapeDataString($AlertId))"
Invoke-RestMethod -Method Post -Uri $uri -Headers @{ 'x-api-key' = $ApiKey } -ContentType 'application/json' -Body $body -TimeoutSec 20 | ConvertTo-Json -Depth 6
