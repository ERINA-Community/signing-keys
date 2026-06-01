#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Verify cosign signature on EESSI Docker images.

.DESCRIPTION
  External consumers use this to confirm that an image was actually built
  and signed by the official EESSI pipeline (not a local copy or a tampered
  variant).

  The public key is fetched from the published GitHub repo
  (ERINA-Community/signing-keys) — no Azure access required.

.PARAMETER ImageRefs
  One or more image references. Accepts:
    eessi-java:4.1.2.14-prerelease
    eessi-java@sha256:d84846038c9647a3c81800ed5f76620a3a9759230ccf5115a6af84f8031dec6a
    eessidockerrepository.azurecr.io/eessi-java:4.1.2.14-prerelease

.EXAMPLE
  ./Verify-Image.ps1 eessi-java:4.1.2.14-prerelease

.EXAMPLE
  ./Verify-Image.ps1 eessi-java:1.2.3 eessi-circuitbreaker:1.2.3

.NOTES
  Prerequisites:
    - Logged in to eessidockerrepository.azurecr.io with 'docker login'
      (the same credentials you use for docker pull).
    - Network access to:
        github.com           (downloads the cosign binary and the public key)
        rekor.sigstore.dev   (transparency log inclusion proof)
        eessidockerrepository.azurecr.io  (fetches the image manifest and .sig artifact)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
    [string[]]$ImageRefs
)

$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 defaults to TLS 1.0/1.1 — GitHub requires 1.2+.
# pwsh 7+ already defaults to 1.2+, so this is a no-op there.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# === Pinned constants ===
$CosignVersion = "3.0.6"
# SHA256 from the official cosign_checksums.txt for v3.0.6.
# Re-verify when bumping the version:
#   https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign_checksums.txt
$CosignSha256WindowsAmd64 = "9b85a88ebff2d9dd30ff4984a6f61f2cedc232dd87d81fa7f2ff3c0ed96c241c"
$PubkeyUrl = "https://raw.githubusercontent.com/ERINA-Community/signing-keys/main/signing.pub"
$Registry = "eessidockerrepository.azurecr.io"

# === Install cosign if not cached ===
$CosignDir = Join-Path $env:LOCALAPPDATA "eessi-cosign\$CosignVersion"
$CosignBin = Join-Path $CosignDir "cosign.exe"
if (-not (Test-Path $CosignBin)) {
    New-Item -ItemType Directory -Path $CosignDir -Force | Out-Null
    Write-Host "Downloading cosign $CosignVersion to $CosignBin..."
    Invoke-WebRequest -Uri "https://github.com/sigstore/cosign/releases/download/v$CosignVersion/cosign-windows-amd64.exe" -OutFile $CosignBin -UseBasicParsing
    $actual = (Get-FileHash -Algorithm SHA256 $CosignBin).Hash.ToLowerInvariant()
    if ($actual -ne $CosignSha256WindowsAmd64) {
        Remove-Item $CosignBin -Force
        throw "cosign SHA256 mismatch. Expected $CosignSha256WindowsAmd64, got $actual"
    }
}

# === Fetch the public key fresh each run (cheap, and catches key rotation) ===
$PubkeyFile = New-TemporaryFile
$pass = 0
$fail = 0
try {
    Invoke-WebRequest -Uri $PubkeyUrl -OutFile $PubkeyFile -UseBasicParsing

    foreach ($raw in $ImageRefs) {
        # Prepend the registry if a short form was given (no registry hostname).
        if ($raw -like "*.azurecr.io/*") {
            $ref = $raw
        }
        else {
            $ref = "$Registry/$raw"
        }

        Write-Host ""
        Write-Host "=== $ref ==="
        $output = & $CosignBin verify --key $PubkeyFile $ref 2>&1
        $outputStr = ($output | Out-String)
        if ($LASTEXITCODE -eq 0) {
            $pass++
            ($outputStr -split "`n") |
                Where-Object { $_ -match "^Verification for|^  - " } |
                Select-Object -First 4 |
                ForEach-Object { Write-Host $_.TrimEnd() }
            Write-Host "VERIFIED" -ForegroundColor Green
        }
        else {
            $fail++
            ($outputStr -split "`n") |
                Select-Object -Last 5 |
                ForEach-Object { Write-Host $_.TrimEnd() -ForegroundColor Red }
            Write-Host "FAILED" -ForegroundColor Red
            if ($outputStr -match "UNAUTHORIZED|authentication required") {
                Write-Host "Hint: run 'docker login $Registry' with your credentials and try again." -ForegroundColor Yellow
            }
        }
    }
}
finally {
    Remove-Item $PubkeyFile -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "=== Result: $pass/$($ImageRefs.Count) verified ==="
exit $fail
