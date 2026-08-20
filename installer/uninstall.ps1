#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the secure-access-relay endpoint agent.

.DESCRIPTION
    Stops and deregisters the service, removes the event log source, and deletes
    the installed binary.

    State — the device key, its certificate, and the trust anchor — is kept by
    default. Removing an enrolled identity because someone uninstalled a service
    turns a reinstall into a re-enrollment and an upgrade into an outage. Pass
    -RemoveState when the intent really is to forget this device.

.PARAMETER RemoveState
    Also delete the state directory, including the device key and certificate.
    The device must be enrolled again afterwards.

.EXAMPLE
    .\uninstall.ps1
    .\uninstall.ps1 -RemoveState
#>
[CmdletBinding()]
param(
    [switch]$RemoveState
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'SecureAccessRelayAgent'
$InstallDir  = Join-Path $env:ProgramFiles 'secure-access-relay'
$StateDir    = Join-Path $env:ProgramData  'secure-access-relay'
$InstalledExe = Join-Path $InstallDir 'sar-agent.exe'

function Write-Step { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }

Write-Step "Stopping and removing the service"
if (Test-Path $InstalledExe) {
    # The binary's own uninstall also removes the event log source, which a raw
    # sc.exe delete would leave behind in the registry.
    & $InstalledExe service uninstall
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "The agent could not remove itself; falling back to the service manager."
        sc.exe stop   $ServiceName | Out-Null
        sc.exe delete $ServiceName | Out-Null
    }
} else {
    sc.exe stop   $ServiceName | Out-Null
    sc.exe delete $ServiceName | Out-Null
}

Start-Sleep -Seconds 2

Write-Step "Removing the installed binary"
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) {
        Write-Warning "$InstallDir could not be removed; a file may still be in use. Remove it after a reboot."
    }
}

if ($RemoveState) {
    Write-Step "Removing state, including the device key and certificate"
    if (Test-Path $StateDir) {
        Remove-Item -Path $StateDir -Recurse -Force
    }
    Write-Host "    this device must be enrolled again before it can connect"
} else {
    Write-Step "Keeping state"
    Write-Host "    $StateDir"
    Write-Host "    re-run install.ps1 without an enrollment code to reuse this identity"
    Write-Host "    pass -RemoveState to delete it"
}

Write-Step "Verifying nothing is left behind"
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Warning "The service is still registered. A reboot may be required to complete removal."
} else {
    Write-Host "    service: removed"
}
$eventKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$ServiceName"
if (Test-Path $eventKey) {
    Write-Warning "The event log source is still registered at $eventKey"
} else {
    Write-Host "    event log source: removed"
}

Write-Host ""
Write-Host "Uninstalled." -ForegroundColor Green
