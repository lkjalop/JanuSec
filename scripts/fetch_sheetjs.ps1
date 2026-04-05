Param(
    [string]$PackagePath = "node_modules\xlsx\dist\xlsx.full.min.js",
    [string]$Dest = "frontend\static\vendor\xlsx.full.min.js",
    [string]$CDN = "https://cdn.jsdelivr.net/npm/xlsx@0.19.3/dist/xlsx.full.min.js"
)

$ErrorActionPreference = 'Stop'

Write-Host "Ensuring vendor xlsx is present at $Dest"

$destDir = Split-Path $Dest -Parent
if(-not (Test-Path $destDir)){
    New-Item -ItemType Directory -Path $destDir | Out-Null
}

if(Test-Path $PackagePath){
    Write-Host "Copying from local node_modules: $PackagePath -> $Dest"
    Copy-Item -Path $PackagePath -Destination $Dest -Force
    Write-Host "Copied local xlsx.full.min.js"
    exit 0
}

# Try download from CDN
try{
    Write-Host "Local package not found; downloading from CDN: $CDN"
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($CDN, $Dest)
    Write-Host "Downloaded xlsx.full.min.js to $Dest"
    exit 0
}catch{
    Write-Error "Failed to download or copy xlsx.full.min.js: $_"
    exit 2
}
