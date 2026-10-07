param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("termcomm-i2p", "deskcomm-i2p")]
    [string]$Product,

    [Parameter(Mandatory = $true)]
    [string]$ReleaseTag
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-X64Pe([string]$Path) {
    $Stream = [System.IO.File]::OpenRead($Path)
    $Reader = New-Object System.IO.BinaryReader($Stream)
    try {
        if ($Reader.ReadUInt16() -ne 0x5A4D) { throw "Not a PE executable: $Path" }
        $Stream.Position = 0x3C
        $PeOffset = $Reader.ReadInt32()
        $Stream.Position = $PeOffset
        if ($Reader.ReadUInt32() -ne 0x00004550) { throw "Invalid PE signature: $Path" }
        if ($Reader.ReadUInt16() -ne 0x8664) { throw "Executable is not x86_64: $Path" }
    } finally {
        $Reader.Dispose()
        $Stream.Dispose()
    }
}

$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Archive = Join-Path $ProjectDir "dist\$Product-$ReleaseTag-windows-x86_64.zip"
$Binary = Join-Path $ProjectDir "target\release\$Product.exe"
$Checksums = Join-Path $ProjectDir "dist\SHA256SUMS"

foreach ($Required in @($Archive, $Binary, $Checksums)) {
    if (-not (Test-Path -LiteralPath $Required -PathType Leaf)) {
        throw "Required Windows artifact is missing: $Required"
    }
}
Assert-X64Pe $Binary

$CheckDir = Join-Path $ProjectDir ".windows-check"
Remove-Item -LiteralPath $CheckDir -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath $Archive -DestinationPath $CheckDir
$ExtractedPackageDir = Join-Path $CheckDir "$Product-$ReleaseTag-windows-x86_64"
$PackagedBinary = Join-Path $ExtractedPackageDir "$Product.exe"
if (-not (Test-Path -LiteralPath $PackagedBinary -PathType Leaf)) {
    throw "Packaged Windows binary is missing: $PackagedBinary"
}

foreach ($Document in @("LICENSE", "NOTICE", "README.md", "COMMERCIAL-LICENSING.md")) {
    $PackagedDocument = Join-Path $ExtractedPackageDir $Document
    if (-not (Test-Path -LiteralPath $PackagedDocument -PathType Leaf)) {
        throw "Packaged licensing document is missing: $PackagedDocument"
    }
}

foreach ($Line in Get-Content -LiteralPath $Checksums) {
    if ([string]::IsNullOrWhiteSpace($Line)) { continue }
    $Parts = $Line -split "  ", 2
    if ($Parts.Count -ne 2) { throw "Invalid checksum line: $Line" }
    $Artifact = Join-Path (Join-Path $ProjectDir "dist") $Parts[1]
    $Actual = (Get-FileHash -LiteralPath $Artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Parts[0]) { throw "Checksum mismatch: $($Parts[1])" }
}
