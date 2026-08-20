#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the secure-access-relay endpoint agent as a Windows service.

.DESCRIPTION
    Copies the agent to Program Files, creates an ACL-protected state directory,
    enrolls the device if an enrollment code is supplied, and registers the
    service with the service control manager.

    Binaries live under Program Files, which only Administrators can write to.
    Mutable state lives under ProgramData. The two are never mixed: a service
    able to write its own executable is a privilege-escalation primitive.

.PARAMETER Source
    Directory containing sar-agent.exe. Defaults to the directory holding this
    script, then to a bin directory beside it.

.PARAMETER EnrollmentCode
    Enrollment code from 'sar-server token -device <name>'. If omitted, the
    service is installed but not enrolled, and will not start successfully until
    'sar-agent enroll' has been run.

.PARAMETER RelayAddr
    Relay address the agent connects out to.

.PARAMETER Target
    Local service to expose. Must be a loopback literal with an explicit port;
    the agent refuses to start otherwise.

.EXAMPLE
    .\install.ps1 -EnrollmentCode sar1.eyJ... -RelayAddr relay.example:443 -Target 127.0.0.1:8080
#>
[CmdletBinding()]
param(
    [string]$Source,
    [string]$EnrollmentCode,
    [string]$RelayAddr = "127.0.0.1:17070",
    [string]$Target    = "127.0.0.1:8080",
    [string]$LogLevel  = "info"
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'SecureAccessRelayAgent'
$InstallDir  = Join-Path $env:ProgramFiles 'secure-access-relay'
$StateDir    = Join-Path $env:ProgramData  'secure-access-relay'

function Write-Step { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }

# --- locate the binary -------------------------------------------------------

if (-not $Source) {
    $candidates = @($PSScriptRoot, (Join-Path (Split-Path -Parent $PSScriptRoot) 'bin'))
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c 'sar-agent.exe')) { $Source = $c; break }
    }
}
if (-not $Source -or -not (Test-Path (Join-Path $Source 'sar-agent.exe'))) {
    throw "sar-agent.exe not found. Pass -Source with the directory containing it."
}
$SourceExe = Join-Path $Source 'sar-agent.exe'

# --- stop and remove any previous installation -------------------------------
#
# Removing first rather than upgrading in place: the old process holds its
# executable open, and a copy over a running binary fails in a way that leaves
# the machine half-updated.

Write-Step "Removing any previous installation"
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    & (Join-Path $InstallDir 'sar-agent.exe') service uninstall 2>$null
    if ($LASTEXITCODE -ne 0) {
        # Fall back to the SCM directly if the installed binary is unusable.
        sc.exe stop   $ServiceName | Out-Null
        sc.exe delete $ServiceName | Out-Null
    }
    Start-Sleep -Seconds 2
}

# --- install the binary ------------------------------------------------------

Write-Step "Installing to $InstallDir"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Copy-Item -Path $SourceExe -Destination $InstallDir -Force
$InstalledExe = Join-Path $InstallDir 'sar-agent.exe'

# --- state directory and its ACL ---------------------------------------------
#
# Inheritance is broken explicitly. The default inherited ACL grants Users read
# access, which would expose the device certificate and — on a platform without
# DPAPI — the private key itself.

Write-Step "Creating state directory $StateDir"
if (-not (Test-Path $StateDir)) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
}

$acl = Get-Acl $StateDir
$acl.SetAccessRuleProtection($true, $false)   # protected, inherited rules discarded
$acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

$rights = [System.Security.AccessControl.FileSystemRights]::FullControl
$inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$prop = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow

foreach ($principal in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $principal, $rights, $inherit, $prop, $allow)
    $acl.AddAccessRule($rule)
}
Set-Acl -Path $StateDir -AclObject $acl
Write-Host "    SYSTEM and Administrators only; Users have no access"

# --- enroll ------------------------------------------------------------------

if ($EnrollmentCode) {
    Write-Step "Enrolling this device"
    # The code is passed as an argument here, which is a compromise: arguments
    # are visible to other local processes and can land in transcripts. It is
    # acceptable for a single-use credential valid for one hour, and the MSI
    # deliberately will not accept one as a property, where it would be written
    # to the installer log permanently.
    & $InstalledExe enroll -state-dir $StateDir -code $EnrollmentCode
    if ($LASTEXITCODE -ne 0) { throw "Enrollment failed." }
} else {
    Write-Warning "No enrollment code supplied. The service will not start until you run:"
    Write-Warning "  `"$InstalledExe`" enroll -state-dir `"$StateDir`" -code <code>"
}

# --- register the service ----------------------------------------------------

Write-Step "Registering the service"
& $InstalledExe service install `
    -relay-addr $RelayAddr `
    -state-dir  $StateDir `
    -target     $Target `
    -log-level  $LogLevel
if ($LASTEXITCODE -ne 0) { throw "Service registration failed." }

if ($EnrollmentCode) {
    Write-Step "Starting the service"
    & $InstalledExe service start
    if ($LASTEXITCODE -ne 0) { throw "The service did not start." }
    Start-Sleep -Seconds 2
    & $InstalledExe service status
}

Write-Host ""
Write-Host "Installed." -ForegroundColor Green
Write-Host "  binary:  $InstalledExe"
Write-Host "  state:   $StateDir"
Write-Host "  target:  $Target"
Write-Host ""
Write-Host "The endpoint opens no inbound port. Verify with:"
Write-Host "  netstat -ano | Select-String 'LISTENING' | Select-String (Get-Process sar-agent).Id"
