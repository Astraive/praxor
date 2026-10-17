$ErrorActionPreference = "Stop"

$paths = @(
    "src/storage",
    "src/store",
    "src/wal",
    "src/manifest",
    "src/recovery",
    "src/index",
    "src/cache",
    "src/kernel"
)

$forbidden = @(
    @{ Name = "println!"; Pattern = "println!" },
    @{ Name = "eprintln!"; Pattern = "eprintln!" },
    @{ Name = "dbg!"; Pattern = "dbg!" },
    @{ Name = "tracing::"; Pattern = "tracing::" },
    @{ Name = "log::"; Pattern = "(?<![A-Za-z0-9_])log::" }
)

$violations = @()
foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        continue
    }
    foreach ($rule in $forbidden) {
        $matches = Get-ChildItem -Path $path -Recurse -Filter *.rs |
            Select-String -Pattern $rule.Pattern
        foreach ($match in $matches) {
            $violations += "$($match.Path):$($match.LineNumber): forbidden storage logging pattern '$($rule.Name)'"
        }
    }
}

if ($violations.Count -gt 0) {
    $violations | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output "storage slog gate passed"
