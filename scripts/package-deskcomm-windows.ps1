param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DistDir = Join-Path $ProjectDir "dist"
$StageDir = Join-Path $ProjectDir ".deskcomm-windows-package"
$Binary = Join-Path $ProjectDir "target\release\deskcomm-i2p.exe"
$PackageName = "deskcomm-i2p-v$Version-windows-x86_64"
$PackageDir = Join-Path $StageDir $PackageName
$Archive = Join-Path $DistDir "$PackageName.zip"

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "Release binary is missing: $Binary"
}

Remove-Item -LiteralPath $StageDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $DistDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $PackageDir -Force | Out-Null
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

Copy-Item -LiteralPath $Binary -Destination (Join-Path $PackageDir "deskcomm-i2p.exe")
Compress-Archive -LiteralPath $PackageDir -DestinationPath $Archive -CompressionLevel Optimal

$Hash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
$ChecksumText = "$Hash  $([System.IO.Path]::GetFileName($Archive))`n"
$Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    (Join-Path $DistDir "SHA256SUMS"),
    $ChecksumText,
    $Utf8WithoutBom
)
