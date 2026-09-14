Param(
    [string]$BaseUrl = "http://localhost:8080",
    [string]$AdminApiKey = "devkey123"
)
$ErrorActionPreference = 'Stop'

Write-Host "[1/4] GET /api/v1/admin/factors/telemetry"
$hdrGet = @{ 'x-api-key' = $AdminApiKey }
try {
    $tele = Invoke-RestMethod -Method GET -Uri ($BaseUrl + '/api/v1/admin/factors/telemetry') -Headers $hdrGet
    $tele | ConvertTo-Json -Depth 6 | Write-Output | Out-Host
} catch {
    Write-Warning "Initial telemetry GET failed: $($_.Exception.Message)"
}

Write-Host "[2/4] POST context multipliers"
$hdrJson = @{ 'x-api-key' = $AdminApiKey; 'Content-Type' = 'application/json' }
$body1 = @{ context = @{ 'iam:highrisk' = 1.35; 'remote:night' = 0.72 } } | ConvertTo-Json
$resp1 = Invoke-RestMethod -Method POST -Uri ($BaseUrl + '/api/v1/admin/factors/context') -Headers $hdrJson -Body $body1
$resp1 | ConvertTo-Json -Depth 6 | Write-Output | Out-Host

Write-Host "[3/4] POST factor observations"
$body2 = @{ observations = @{ 'endpoint:lolbin' = @{ tp = 42; fp = 3 }; 'dns:nxdomain_spike' = @{ tp = 11; fp = 8 } } } | ConvertTo-Json
$resp2 = Invoke-RestMethod -Method POST -Uri ($BaseUrl + '/api/v1/admin/factors/observations') -Headers $hdrJson -Body $body2
$resp2 | ConvertTo-Json -Depth 6 | Write-Output | Out-Host

Write-Host "[4/4] Verify telemetry snapshot after seeding"
$tele2 = Invoke-RestMethod -Method GET -Uri ($BaseUrl + '/api/v1/admin/factors/telemetry') -Headers $hdrGet
$tele2 | ConvertTo-Json -Depth 8 | Write-Output | Out-Host

Write-Host "Done."
