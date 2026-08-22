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
    [ValidateSet('all', 'build', 'native', 'test', 'test-race', 'integration', 'win-integration', 'vet', 'fmt', 'lint', 'tidy', 'clean')]
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

function Find-CCompiler {
    <#
        Locates a C compiler for the optional native library.

        $env:CC wins if set. Otherwise gcc or clang from PATH, then the places
        MinGW-w64 is commonly installed - because a compiler that is present but
        not on PATH should not read as a compiler that is missing.
    #>
    if ($env:CC) { return $env:CC }

    foreach ($name in @('gcc', 'clang')) {
        $found = Get-Command $name -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }
    foreach ($path in @(
            'C:\ProgramData\mingw64\mingw64\bin\gcc.exe',
            'C:\msys64\mingw64\bin\gcc.exe',
            'C:\mingw64\bin\gcc.exe')) {
        if (Test-Path $path) { return $path }
    }

    throw @'
No C compiler found. Install MinGW-w64, or set $env:CC to one.

The agent does not need it: sardiag is optional, and the Go binaries build and
run without a C toolchain. Only this task and the diagnostics library need one.
'@
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
    'native' {
        # The optional C diagnostics library. Separate from 'build' on purpose:
        # it needs a C compiler, the Go binaries do not, and a checkout without
        # one must still build and test everything else.
        #
        # The compiler is invoked directly rather than through native/sardiag/build.sh.
        # `bash` on a Windows machine is as likely to be WSL's as Git Bash's, and
        # WSL's cannot see C:\ paths or a MinGW toolchain - so shelling out finds
        # the wrong shell and reports a missing compiler on a machine that has
        # one. The .sh script is for Unix shells and the Makefile; the two are
        # short and must stay in step, and the C tests below are what proves it.
        Invoke-Step 'sardiag' {
            $cc = Find-CCompiler
            $root = 'native/sardiag'
            $build = Join-Path $root 'build'
            New-Item -ItemType Directory -Force -Path $build | Out-Null

            $warn = @('-Wall', '-Wextra', '-Wpedantic', '-Wconversion', '-Werror')
            $src = @(
                "$root/src/sardiag.c", "$root/src/jbuf.c",
                "$root/src/collect_windows.c", "$root/src/collect_stub.c"
            )
            $libs = @('-lws2_32', '-liphlpapi', '-lwinhttp')
            $inc = @("-I$root/include", "-I$root/src")

            Write-Host "    compiler: $cc"

            & $cc -std=c99 @warn -O1 @inc -o "$build/test_sardiag.exe" `
                "$root/tests/test_sardiag.c" @src @libs
            if ($LASTEXITCODE -ne 0) { throw 'sardiag tests failed to build' }

            & "$build/test_sardiag.exe"
            if ($LASTEXITCODE -ne 0) { throw 'sardiag tests failed' }

            # SARDIAG_BUILD_DLL is what turns the declarations into exports.
            # Without it the library builds, links, loads, and exports nothing -
            # a failure that looks like a missing file at runtime.
            & $cc -std=c99 @warn -O2 -shared -DSARDIAG_BUILD_DLL @inc `
                -o "$build/sardiag.dll" @src @libs
            if ($LASTEXITCODE -ne 0) { throw 'sardiag library failed to build' }

            Write-Host "    built $build/sardiag.dll"
            Write-Host '    run `.\scripts\task.ps1 test` to exercise it through internal/diagbridge'
        }
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
