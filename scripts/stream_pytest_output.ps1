Set-Location 'D:\AI\Threat_thy_sniffer'
if (-not (Test-Path .\tmp)) { New-Item -ItemType Directory -Path .\tmp | Out-Null }
for ($i = 0; $i -lt 10; $i++) {
    Write-Output ('=== sample {0} at {1} ===' -f $i, (Get-Date))
    if (Test-Path .\tmp\pytest_output.txt) {
        Get-Content .\tmp\pytest_output.txt -Tail 500
    } else {
        Write-Output 'pytest_output-not-found'
    }
    Start-Sleep -Seconds 30
}
Write-Output 'streaming-complete'