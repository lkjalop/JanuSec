param(
  [Parameter(Mandatory=$true)][string]$Folder,
  [string]$ApiBase = "http://localhost:8080",
  [string]$ApiKey = "devkey123"
)

$allowed = @('.csv','.json','.xlsx','.xls','.pcap','.pcapng','.evtx','.log','.txt')
$files = Get-ChildItem -File -Path $Folder | Where-Object { $allowed -contains $_.Extension.ToLower() }
if(-not $files){ Write-Warning "No eligible files (.csv,.json,.xlsx,.xls,.pcap,.pcapng,.evtx,.log,.txt) in $Folder"; exit 0 }

Add-Type -AssemblyName System.Net.Http

function Upload-File([string]$ApiBase, [string]$ApiKey, [System.IO.FileInfo]$File){
  $client = New-Object System.Net.Http.HttpClient
  try{
    $client.DefaultRequestHeaders.Add('x-api-key', $ApiKey)
    $uri = "$ApiBase/api/v1/upload/files"
    $content = New-Object System.Net.Http.MultipartFormDataContent
    $fs = [System.IO.File]::OpenRead($File.FullName)
    try{
      $sc = New-Object System.Net.Http.StreamContent($fs)
      $sc.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/octet-stream')
      $null = $content.Add($sc, 'files', $File.Name)
      $resp = $client.PostAsync($uri, $content).Result
      return $resp
    } finally {
      if($fs){ $fs.Dispose() }
      if($content){ $content.Dispose() }
    }
  } finally {
    if($client){ $client.Dispose() }
  }
}

foreach($f in $files){
  Write-Host "Uploading $($f.Name)" -ForegroundColor Cyan
  try{
    $resp = Upload-File -ApiBase $ApiBase -ApiKey $ApiKey -File $f
    $code = [int]$resp.StatusCode
    if($code -ge 200 -and $code -lt 300){
      Write-Host "Status $code" -ForegroundColor Green
    } else {
      $body = $resp.Content.ReadAsStringAsync().Result
      Write-Warning "Upload failed ($code): $body"
    }
  } catch {
    Write-Warning $_
  }
}

Write-Host "Tabular sessions:" -ForegroundColor Cyan
try {
  Invoke-RestMethod -Uri "$ApiBase/api/v1/upload/tabular/sessions" -Headers @{ 'x-api-key' = $ApiKey } -TimeoutSec 30 | ConvertTo-Json -Depth 6
} catch { Write-Warning $_ }
