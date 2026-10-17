param(
    [ValidateSet("Smoke", "Timing", "Allocations")][string]$Mode = "Smoke",
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [Parameter(Mandatory = $true)][string]$TargetDir,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [Parameter(Mandatory = $true)][string]$DataDir,
    [Parameter(Mandatory = $true)][string]$Revision,
    [ValidateSet("baseline", "candidate")][string]$Label = "candidate"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $DataDir -PathType Container)) { throw "Create the data parent first: $DataDir" }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$benchmark = if ($Mode -eq "Allocations") { "write_amplification_allocations" } else { "write_amplification_matrix" }
$binary = Get-ChildItem -LiteralPath (Join-Path $TargetDir "release\deps") -Filter "$benchmark-*.exe" |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
if ($null -eq $binary) { throw "Build $benchmark with --locked --jobs 2 --target-dir $TargetDir first." }
if (Test-Path -LiteralPath (Join-Path $SourceRoot ".git")) {
    $actualRevision = (git -C $SourceRoot rev-parse HEAD).Trim()
    if ($actualRevision -ne $Revision) { throw "Requested revision differs from source HEAD: $actualRevision" }
}
$inputs = @(Get-ChildItem -LiteralPath (Join-Path $SourceRoot "src") -Filter *.rs -Recurse)
$inputs += Get-Item -LiteralPath @(
    (Join-Path $SourceRoot "benches\durability\write_amplification_matrix.rs"),
    (Join-Path $SourceRoot "benches\durability\write_amplification_allocations.rs"),
    (Join-Path $SourceRoot "benches\durability\write_matrix_support.rs")
)
$inputs += Get-Item -LiteralPath (Join-Path $SourceRoot "Cargo.toml"), (Join-Path $SourceRoot "Cargo.lock")
if ($inputs | Where-Object { $_.LastWriteTimeUtc -gt $binary.LastWriteTimeUtc }) {
    throw "Source files are newer than the selected binary; rebuild before capture."
}
$hashes = [ordered]@{}
foreach ($name in @("write_amplification_matrix.rs", "write_amplification_allocations.rs", "write_matrix_support.rs")) {
    $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $SourceRoot "benches\durability\$name") -Algorithm SHA256).Hash.ToLowerInvariant()
}
$hashBytes = [Text.Encoding]::UTF8.GetBytes(($hashes | ConvertTo-Json -Compress))
$harnessHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($hashBytes)).ToLowerInvariant()
$prefix = Join-Path $OutputDir "$Label-$($Mode.ToLowerInvariant())"
$arguments = @("--label", $Label, "--source-revision", $Revision, "--harness-hash", $harnessHash, "--data-dir", $DataDir)
if ($Label -eq "candidate") { $arguments += "--expect-stable-manifest" }
if ($Mode -eq "Smoke") { $arguments += @("--probe", "--batches", "2", "--warmup-batches", "1", "--repetitions", "1") }
if ($Mode -eq "Allocations") { $arguments += @("--repetitions", "1") }
$provenance = [ordered]@{
    mode = $Mode; source_revision = $Revision; source_root = $SourceRoot
    executable = $binary.FullName
    executable_sha256 = (Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    harness_sha256 = $harnessHash; harness_files_sha256 = $hashes
    cargo_lock_sha256 = (Get-FileHash -LiteralPath (Join-Path $SourceRoot "Cargo.lock") -Algorithm SHA256).Hash.ToLowerInvariant()
    rustc = (rustc --version | Out-String).Trim(); cargo = (cargo --version | Out-String).Trim()
    operating_system = [Runtime.InteropServices.RuntimeInformation]::OSDescription
    process_architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    cpu = (Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors)
    data_volume = (Get-Volume -FilePath $DataDir | Select-Object DriveLetter, FileSystem, FileSystemLabel, Size, SizeRemaining)
    data_disk = (Get-Partition -DriveLetter ([IO.Path]::GetPathRoot($DataDir).Substring(0, 1)) | Get-Disk | Select-Object Number, FriendlyName, BusType, Size)
    arguments = $arguments; started_utc = [DateTime]::UtcNow.ToString("o")
}
& $binary.FullName @arguments 1> "$prefix-stdout.log" 2> "$prefix.jsonl"
$result = $LASTEXITCODE
$provenance["exit_code"] = $result
$provenance["ended_utc"] = [DateTime]::UtcNow.ToString("o")
$provenance | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$prefix-provenance.json"
if ($result -ne 0) { throw "Matrix exited $result; inspect $prefix.jsonl" }
Write-Output "$prefix.jsonl"
