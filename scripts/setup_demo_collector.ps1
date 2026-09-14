# Demo PowerShell script to register a demo collector and send a telemetry sample
param(
    [string]$BaseUrl = 'http://localhost:8080',
    [string]$CollectorId = 'demo_collector'
)

Write-Host "Sending demo telemetry to $BaseUrl as $CollectorId"
$payload = @{collector_id=$CollectorId; status='ok'; ts=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json
Invoke-RestMethod -Uri "$BaseUrl/api/v1/collector_telemetry" -Method Post -Body $payload -ContentType 'application/json'
Write-Host "Done"
