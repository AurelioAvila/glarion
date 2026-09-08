param([Parameter(Mandatory=$true)][string]$Manifest)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$publisher = '4F8341A74D16077AE1849DC8B8CAC99F22606754'
$signature = Get-AuthenticodeSignature -LiteralPath $Manifest
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $publisher -or -not $signature.TimeStamperCertificate) {
    throw 'A valid timestamped publisher signature is required before deployment.'
}
# The manifest is signed data. Never execute it.
$content = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Manifest).Path)
$imageMatch = [regex]::Match($content, '(?m)^# image=(registry\.fly\.io/glarion-api@sha256:[a-f0-9]{64})\r?$')
$configMatch = [regex]::Match($content, '(?m)^# config-sha256=([A-Fa-f0-9]{64})\r?$')
if (-not $imageMatch.Success -or -not $configMatch.Success) { throw 'Incomplete signed manifest.' }
$configPath = Join-Path $repoRoot 'fly.toml'
if ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ne $configMatch.Groups[1].Value) {
    throw 'Deployment configuration changed after signing.'
}
Push-Location $repoRoot
try {
    & flyctl deploy --config $configPath --image $imageMatch.Groups[1].Value
    if ($LASTEXITCODE -ne 0) { throw 'Deployment failed; inspect machine status before retrying.' }
} finally { Pop-Location }
