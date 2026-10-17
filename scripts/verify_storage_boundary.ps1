$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$scanRoots = @(
    @("src", "core_records"),
    @("src", "store"),
    @("src", "storage"),
    @("src", "index"),
    @("src", "kernel"),
    @("src", "wal"),
    @("src", "manifest"),
    @("src", "recovery"),
    @("src", "transactions"),
    @("src", "memory"),
    @("src", "cache")
)

$forbidden = @(
    "execute_sql",
    "parse_sql",
    "create_table",
    "drop_table",
    "create_schema",
    "create_role",
    "grant_role",
    "stored_procedure",
    "trigger",
    "cypher",
    "graphql_parser",
    "distributed_coordinator",
    "cluster_topology",
    "route_query"
)

$violations = @()
foreach ($scanRoot in $scanRoots) {
    $path = $root
    foreach ($part in $scanRoot) {
        $path = Join-Path $path $part
    }

    if (-not (Test-Path $path)) {
        continue
    }

    foreach ($file in Get-ChildItem -Path $path -Recurse -Filter *.rs) {
        $matches = Select-String -Path $file.FullName -Pattern $forbidden -SimpleMatch
        foreach ($match in $matches) {
            $relative = Resolve-Path -Path $file.FullName -Relative
            $violations += "${relative}:$($match.LineNumber):$($match.Line.Trim())"
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Error ("storage boundary gate failed`n" + ($violations -join "`n"))
}

Write-Host "storage boundary gate passed"
