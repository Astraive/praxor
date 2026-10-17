param(
    [string]$Destination = "D:\poiesis-worktrees\write-matrix-baseline-636d2dd",
    [string]$Revision = "636d2ddee1ba82966212a4d4bfbb06497ec3a871"
)
$ErrorActionPreference = "Stop"
$sourceRoot = Split-Path -Parent $PSScriptRoot
if (Test-Path -LiteralPath $Destination) {
    throw "Baseline destination already exists; choose a fresh destination to preserve provenance."
}
$parent = Split-Path -Parent $Destination
if (-not (Test-Path -LiteralPath $parent)) { throw "Destination parent does not exist: $parent" }
$archive = Join-Path $parent ("write-matrix-baseline-" + [guid]::NewGuid().ToString() + ".tar")
git -C $sourceRoot archive --format=tar --output=$archive $Revision
if ($LASTEXITCODE -ne 0) { throw "git archive failed" }
New-Item -ItemType Directory -Path $Destination | Out-Null
tar -xf $archive -C $Destination
if ($LASTEXITCODE -ne 0) { throw "archive extraction failed" }
$benchDir = Join-Path $Destination "benches\durability"
New-Item -ItemType Directory -Path $benchDir -Force | Out-Null
$files = @(
    "write_amplification_matrix.rs",
    "write_amplification_allocations.rs",
    "write_matrix_support.rs"
)
$hashes = @{}
foreach ($file in $files) {
    $source = Join-Path $sourceRoot "benches\durability\$file"
    Copy-Item -LiteralPath $source -Destination (Join-Path $benchDir $file)
    $hashes[$file] = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifestAddition = @'

[[bench]]
name = "write_amplification_matrix"
path = "benches/durability/write_amplification_matrix.rs"
harness = false

[[bench]]
name = "write_amplification_allocations"
path = "benches/durability/write_amplification_allocations.rs"
harness = false
'@
Add-Content -LiteralPath (Join-Path $Destination "Cargo.toml") -Value $manifestAddition
$provenance = @{
    source_revision = $Revision
    archive_sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    cargo_lock_sha256 = (Get-FileHash -LiteralPath (Join-Path $Destination "Cargo.lock") -Algorithm SHA256).Hash.ToLowerInvariant()
    copied_harness_sha256 = $hashes
    source_modifications = "Only benchmark targets and the three identical harness source files were added."
}
$provenance | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Destination "write-matrix-provenance.json")
Write-Output $Destination
