param(
    [string]$dsn = "postgresql://test:test@localhost:5433/testdb",
    [string]$outdir = "backups",
    [string]$s3uri = $null,
    [int]$keep = 5,
    [switch]$DryRun,
    [switch]$Sign,
    [int]$KeepLogs = 10
)
Write-Host "Preparing enhanced pre-migration backup for $dsn"
if(-not (Test-Path $outdir)) { New-Item -ItemType Directory -Path $outdir | Out-Null }

function Write-Log([string]$msg){
        $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        $line = "$ts - $msg"
        Write-Host $line
        try{
    Write-RotatedLog -LogPath (Join-Path $outdir "migration_backup.log") -MaxFiles $KeepLogs
        Add-Content -Path (Join-Path $outdir "migration_backup.log") -Value $line -ErrorAction SilentlyContinue
        } catch { }
}

function Write-RotatedLog([string]$LogPath, [int]$MaxFiles){
    try{
        if(-not (Test-Path $LogPath)) { return }
        $fi = Get-Item $LogPath
        $maxSize = 5MB
        if($fi.Length -lt $maxSize){ return }
        $ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
        $arch = "$LogPath.$ts"
        Move-Item -Path $LogPath -Destination $arch -Force
        # cleanup old archives
        $dir = Split-Path $LogPath -Parent
        $base = Split-Path $LogPath -Leaf
        $archives = Get-ChildItem -Path $dir -Filter "$base.*" | Sort-Object LastWriteTime -Descending
        $i = 0
        foreach($a in $archives){ $i++; if($i -gt $MaxFiles){ Remove-Item $a.FullName -Force } }
    } catch { }
}
try{
    $uri = [uri]$dsn
    $user = $uri.UserInfo.Split(':')[0]
    $pass = $uri.UserInfo.Split(':')[1]
    $pg_host = $uri.Host
    $pg_port = $uri.Port
    $db = $uri.AbsolutePath.TrimStart('/')
} catch{
    Write-Warning "Failed to parse DSN; skipping backup"
    exit 0
}
# build output filename and ensure pg_dump exists
$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$outfile = Join-Path $outdir "migration_backup_${db}_$ts.sql"
$pgdump = Get-Command pg_dump -ErrorAction SilentlyContinue
if(-not $pgdump){
    Write-Log "pg_dump not found in PATH. Skipping backup. To enable backups, install PostgreSQL client tools and ensure pg_dump is on PATH."
    exit 0
}
$env:PGPASSWORD = $pass
# Use Start-Process with explicit args to avoid shell quoting issues
$pgArgs = @('-h', $pg_host, '-p', $pg_port.ToString(), '-U', $user, '-F', 'p', '-f', $outfile, $db)
Write-Log "Running pg_dump with args: $($pgArgs -join ' ')"
if(-not $DryRun){
    $p = Start-Process -FilePath 'pg_dump' -ArgumentList $pgArgs -NoNewWindow -Wait -PassThru -ErrorAction Stop
    if($p.ExitCode -ne 0){ Write-Log "pg_dump exited with code $($p.ExitCode)."; exit 1 }
    Write-Log "Backup written to $outfile"
} else { Write-Log "DryRun: skipping pg_dump" }
# optional S3 upload via AWS CLI
# optional encryption (GPG) and S3 upload via AWS CLI
$encrypted = $null
try{
    $gpg_recipient = $env:GPG_RECIPIENT
    $gpg_pass = $env:GPG_PASSPHRASE
    if($gpg_recipient -or $gpg_pass){
        $gpg = Get-Command gpg -ErrorAction SilentlyContinue
        if(-not $gpg){ Write-Warning "gpg not found; skipping encryption" }
        else{
            $encfile = "$outfile.gpg"
            if($gpg_pass){
                # symmetric encryption
                $gpgArgs = @('--batch','--yes','--passphrase', $gpg_pass,'-c','-o', $encfile, $outfile)
            } else {
                # public key encryption
                $gpgArgs = @('--batch','--yes','-o', $encfile, '-r', $gpg_recipient, '--encrypt', $outfile)
            }
            Write-Log "Encrypting backup to $encfile"
            if(-not $DryRun){
                $pgp = Start-Process -FilePath 'gpg' -ArgumentList $gpgArgs -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
                if($pgp -and $pgp.ExitCode -eq 0){ $encrypted = $encfile } else { Write-Log "gpg failed (exit code $($pgp.ExitCode))" }
            } else { Write-Log "DryRun: skipping gpg encryption"; $encrypted = "$outfile.gpg" }
        }
    }
} catch { Write-Warning "Encryption step failed: $_" }

if($s3uri){
    $aws = Get-Command aws -ErrorAction SilentlyContinue
    if(-not $aws){ Write-Log "AWS CLI not found; skipping S3 upload"; exit 1 }
    else{
        # create sidecar sha256 checksum
        $shaFile = "$outfile.sha256"
        try{
            if(-not $DryRun){
                Get-FileHash -Algorithm SHA256 -Path $outfile | ForEach-Object { $_.Hash } | Out-File -Encoding ascii $shaFile
            } else { Write-Log "DryRun: would compute SHA256 -> $shaFile" }
        } catch { Write-Log "Failed to compute checksum: $_"; exit 1 }

        # if signing requested, create detached signature
        $sigFile = $null
        if($Sign){
            $sigFile = "$outfile.sig"
            Write-Log "Creating detached signature $sigFile"
            if(-not $DryRun){
                $sgn = Start-Process -FilePath 'gpg' -ArgumentList @('--batch','--yes','--armor','--output',$sigFile,'--detach-sign',$outfile) -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
                if(-not $sgn -or $sgn.ExitCode -ne 0){ Write-Log "GPG sign failed (exit $($sgn.ExitCode))"; exit 1 }
            } else { Write-Log "DryRun: skipping signing" }
        }

        # choose upload targets (plaintext or encrypted plus sidecars)
        $uploadFiles = @()
        if($encrypted){ $uploadFiles += $encrypted } else { $uploadFiles += $outfile }
        $uploadFiles += $shaFile
        if($sigFile){ $uploadFiles += $sigFile }

        foreach($f in $uploadFiles){
            $targetUri = ($s3uri.TrimEnd('/') + '/' + (Split-Path $f -Leaf))
            Write-Log "Uploading $f -> $targetUri"
            if(-not $DryRun){
                $awsArgs = @('s3','cp',$f,$targetUri)
                $ap = Start-Process -FilePath 'aws' -ArgumentList $awsArgs -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
                if(-not $ap -or $ap.ExitCode -ne 0){ Write-Log "S3 upload failed for $f (exit $($ap.ExitCode))"; exit 1 }
                Write-Log "Uploaded $f"
                # verify using head-object to check existence and ContentLength
                try{
                    $headArgs = @('s3api','head-object','--bucket',(($s3uri -replace '^s3://','') -split '/')[0],'--key',($targetUri -replace '^s3://[^/]+/',''))
                    $hp = Start-Process -FilePath 'aws' -ArgumentList $headArgs -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
                    if(-not $hp -or $hp.ExitCode -ne 0){ Write-Log "S3 head-object verification failed for $f (exit $($hp.ExitCode))"; exit 1 }
                    else { Write-Log "S3 head-object verification succeeded for $f" }
                } catch { Write-Log "S3 verification error: $_"; exit 1 }
            } else { Write-Log "DryRun: would upload $f to $targetUri" }
        }

        # cleanup plaintext if we uploaded encrypted file successfully
        if($encrypted -and -not $DryRun){
            try{ Remove-Item $outfile -Force; Write-Log "Removed plaintext $outfile" } catch { Write-Log "Failed to remove plaintext file: $_"; exit 1 }
        }
    }
}
# retention cleanup
try{
    $files = Get-ChildItem -Path $outdir -Filter "migration_backup_*.sql" | Sort-Object LastWriteTime -Descending
    $i = 0
    foreach($f in $files){
        $i++
        if($i -gt $keep){ Remove-Item $f.FullName -Force }
    }
} catch{ Write-Warning "Retention cleanup failed: $_" }
Write-Host "Enhanced backup complete"
exit 0
