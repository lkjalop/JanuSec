<#
.SYNOPSIS
Create a GitHub Pull Request using the REST API and a Personal Access Token (PAT).

USAGE
1) Save your GitHub PAT to an environment variable GITHUB_PAT or enter when prompted.
2) From repository root run:
   powershell -ExecutionPolicy Bypass -File .\scripts\create_pr_ps.ps1

This will read PR_HOPGRAPH.md for the PR body and create a PR from
feature/hopgraph-persistence-and-tests -> main.
#>

param()

function Read-PRBody {
    $path = Join-Path -Path (Get-Location) -ChildPath 'PR_HOPGRAPH.md'
    if (-not (Test-Path $path)) {
        Write-Error "PR body file not found: $path"
        exit 2
    }
    return Get-Content -Raw -Path $path
}

function Get-GitHubPAT {
    if ($env:GITHUB_PAT) { return $env:GITHUB_PAT }
    if ($env:GITHUB_TOKEN) { return $env:GITHUB_TOKEN }
    Write-Host "Enter a GitHub Personal Access Token (scopes: repo) or press Enter to abort:" -ForegroundColor Yellow
    $secure = Read-Host -AsSecureString
    if (-not $secure) { Write-Error "No token provided"; exit 3 }
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}

try {
    $owner = 'lkjalop'
    $repo = 'JanuSec'
    $head = 'feature/hopgraph-persistence-and-tests'
    $base = 'main'

    $body = Read-PRBody
    $title = "feat(hopgraph): sqlite snapshots, bgp wiring, tests"

    $pat = Get-GitHubPAT
    $apiUrl = "https://api.github.com/repos/$owner/$repo/pulls"

    $payload = @{ title = $title; head = $head; base = $base; body = $body } | ConvertTo-Json -Depth 6

    $headers = @{
        Authorization = "token $pat"
        Accept = 'application/vnd.github+json'
        'User-Agent' = 'JanuSec-CreatePR-Script'
    }

    Write-Host "Creating PR $head -> $base on $owner/$repo..."
    $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $payload -ContentType 'application/json'

    if ($response.html_url) {
        Write-Host "PR created: $($response.html_url)" -ForegroundColor Green
    } else {
        Write-Error "Unexpected response from GitHub API"
        $response | Format-List | Out-String | Write-Host
    }
} catch {
    Write-Error "Failed to create PR: $($_.Exception.Message)"
    exit 1
}
