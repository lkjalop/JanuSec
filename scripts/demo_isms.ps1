Param()

$base = 'http://localhost:8080'
$apikey = 'devkey123'

function Post-Evidence {
    param($summary)
    $body = @{ summary = $summary; tags = @('demo','ctrl-A') } | ConvertTo-Json
    $r = Invoke-RestMethod -Uri "$base/api/v1/isms/evidence" -Method Post -Body $body -ContentType 'application/json' -Headers @{ 'x-api-key' = $apikey }
    return $r
}

function Upload-File {
    param($path)
    $r = Invoke-RestMethod -Uri "$base/api/v1/isms/evidence/upload" -Method Post -InFile $path -ContentType 'multipart/form-data' -Headers @{ 'x-api-key' = $apikey }
    return $r
}

function Download-Report {
    param($out)
    $sig = ''
    $url = "$base/api/v1/isms/report/download?hmac_secret=demo-secret"
    Invoke-WebRequest -Uri $url -OutFile $out -Headers @{ 'x-api-key' = $apikey }
    Write-Host "Saved report to $out"
}

Write-Host 'Posting sample evidence...'
$r = Post-Evidence -summary 'Demo evidence from script'
Write-Host "Posted: $($r.id)"
$tmp = Join-Path $env:TEMP 'demo_evidence.txt'
'example content' | Out-File -FilePath $tmp -Encoding utf8
Write-Host 'Uploading file...'
$u = Upload-File -path $tmp
Write-Host "Uploaded: $($u.id)"
$out = Join-Path $env:TEMP 'isms_report.zip'
Download-Report -out $out
Write-Host 'Done.'
