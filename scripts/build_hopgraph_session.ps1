Param(
  [string]$BaseUrl = 'http://localhost:8080',
  [string]$ApiKey = 'devkey123'
)
$ErrorActionPreference = 'Stop'
$hdr = @{ 'x-api-key' = $ApiKey; 'Content-Type' = 'application/json' }
$payload = @{ session_ids = @('batch-abc123','batch-def456'); correlate = $true; ewma = $true; ewma_alpha = 0.6; mapping = @{ user='user'; host='host'; sha256='file_hash' } } | ConvertTo-Json
$resp = Invoke-RestMethod -Method POST -Uri ($BaseUrl + '/api/v1/graph/session/build') -Headers $hdr -Body $payload
$resp | ConvertTo-Json -Depth 8 | Write-Output | Out-Host
