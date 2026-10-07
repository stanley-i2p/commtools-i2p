param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DistDir = Join-Path $ProjectDir "dist"
$StageDir = Join-Path $ProjectDir ".windows-package"
$Binary = Join-Path $ProjectDir "target\release\termcomm-i2p.exe"
$Documents = @(
    (Join-Path $ProjectDir "LICENSE"),
    (Join-Path $ProjectDir "NOTICE"),
    (Join-Path $ProjectDir "README.md"),
    (Join-Path $ProjectDir "COMMERCIAL-LICENSING.md")
)
$PackageName = "termcomm-i2p-v$Version-windows-x86_64"
$PackageDir = Join-Path $StageDir $PackageName
$Archive = Join-Path $DistDir "$PackageName.zip"

foreach ($Required in @($Binary) + $Documents) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "Required TermComm packaging input is missing: $Required"
    }
}

Remove-Item -LiteralPath $StageDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $DistDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $PackageDir -Force | Out-Null
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

Copy-Item -LiteralPath $Binary -Destination (Join-Path $PackageDir "termcomm-i2p.exe")
foreach ($Document in $Documents) {
    Copy-Item -LiteralPath $Document -Destination (Join-Path $PackageDir (Split-Path $Document -Leaf))
}
Compress-Archive -LiteralPath $PackageDir -DestinationPath $Archive -CompressionLevel Optimal

$Hash = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
$ChecksumText = "$Hash  $([System.IO.Path]::GetFileName($Archive))`n"
$Utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    (Join-Path $DistDir "SHA256SUMS"),
    $ChecksumText,
    $Utf8WithoutBom
)
