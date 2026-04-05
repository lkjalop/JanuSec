param(
  [int]$Count = 50,
  [string]$ApiBase = "http://localhost:8080",
  [string]$ApiKey = "devkey123",
  [string]$Tenant = "default"
)

function New-Event($i){
  $now = Get-Date
  $id = "lat-$($now.ToFileTimeUtc())-$i"
  return (@{
    id = $id
    details = @{ process = @{ name = "powershell.exe"; parent_name = "winword.exe" } ; domain = "suspicious$i.test" }
  })
}

$durations = @()
for($i=0; $i -lt $Count; $i++){
  $evt = New-Event $i | ConvertTo-Json -Depth 6
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try{
    Invoke-RestMethod -Method Post -Uri "$ApiBase/api/v1/events" -ContentType 'application/json' -Headers @{ 'x-api-key' = $ApiKey; 'x-tenant-id' = $Tenant } -Body $evt -TimeoutSec 15 | Out-Null
  } catch {
    continue
  }
  $sw.Stop()
  $durations += $sw.Elapsed.TotalMilliseconds
}

if($durations.Count -gt 0){
  $avg = [Math]::Round(($durations | Measure-Object -Average).Average,2)
  $p95 = [Math]::Round(($durations | Sort-Object | Select-Object -Last [int]([Math]::Ceiling($durations.Count*0.95)))[-1],2)
  [pscustomobject]@{ count=$durations.Count; mean_ms=$avg; p95_ms=$p95 }
} else {
  Write-Warning "No successful measurements"
}
