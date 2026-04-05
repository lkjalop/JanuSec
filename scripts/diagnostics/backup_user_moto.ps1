$userBase = Join-Path $env:LOCALAPPDATA 'Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\site-packages'
$u = Join-Path $userBase 'moto'
if (Test-Path $u) {
    $bak = $u + '.backup'
    try {
        Rename-Item -Path $u -NewName (Split-Path $bak -Leaf) -Force
        Write-Output "Renamed $u to $bak"
    } catch {
        Write-Output "Failed to rename $u : $_"
    }
} else {
    Write-Output "User-local moto not found at $u"
}
