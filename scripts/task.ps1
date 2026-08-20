#Requires -Version 5.1
<#
.SYNOPSIS
    Task runner for secure-access-relay on Windows. Mirrors the Makefile targets
    so developers without GNU make get the same commands as CI.

.EXAMPLE
    .\scripts\task.ps1 build
    .\scripts\task.ps1 test
    .\scripts\task.ps1 lint
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('all', 'build', 'test', 'test-race', 'integration', 'win-integration', 'vet', 'fmt', 'lint', 'tidy', 'clean')]
    [string]$Task = 'all'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# Static binaries, no C toolchain. See docs/decisions/0006.
$env:CGO_ENABLED = '0'

function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
}

function Test-Gofmt {
    $unformatted = & gofmt -l . | Where-Object { $_ -notmatch '^vendor[\/]' }
    if ($unformatted) {
        Write-Host 'gofmt needed on:' -ForegroundColor Red
        $unformatted | ForEach-Object { Write-Host "  $_" }
        throw 'gofmt check failed'
    }
    Write-Host 'gofmt clean'
}

switch ($Task) {
    'build'           { Invoke-Step 'build'       { go build -o bin/ ./cmd/... } }
    'test'            { Invoke-Step 'unit tests'  { go test -count=1 ./... } }
    'test-race'       {
        # The race detector requires cgo and a C toolchain. Shipped binaries stay
        # CGO_ENABLED=0; only the test harness relaxes that.
        $env:CGO_ENABLED = '1'
        try   { Invoke-Step 'race tests' { go test -race -count=1 ./... } }
        finally { $env:CGO_ENABLED = '0' }
    }
    'integration'     { Invoke-Step 'integration' { go test -tags=integration -count=1 ./... } }
    'win-integration' {
        Write-Warning 'Windows integration tests install services and alter firewall state.'
        Write-Warning 'Run these on a disposable, snapshot-revertible VM only.'
        Invoke-Step 'windows integration' { go test -tags=windows_integration -count=1 ./... }
    }
    'vet'   { Invoke-Step 'go vet' { go vet ./... } }
    'fmt'   { Invoke-Step 'gofmt' { gofmt -l -w . } }
    'lint'  { Invoke-Step 'go vet' { go vet ./... }; Test-Gofmt }
    'tidy'  { Invoke-Step 'go mod tidy' { go mod tidy } }
    'clean' {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue bin, coverage.out
        Write-Host 'cleaned'
    }
    'all' {
        Invoke-Step 'go vet' { go vet ./... }
        Test-Gofmt
        Invoke-Step 'unit tests' { go test -count=1 ./... }
        $env:CGO_ENABLED = '1'
        try   { Invoke-Step 'race tests' { go test -race -count=1 ./... } }
        finally { $env:CGO_ENABLED = '0' }
        Invoke-Step 'build'      { go build -o bin/ ./cmd/... }
    }
}
