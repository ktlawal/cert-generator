<#
.SYNOPSIS
    Proves the Apple Business lookup runs from inside the module, on the lab
    machine, with the real config and key.

.DESCRIPTION
    Read-only. Loads the config from outside the repo, loads the key, signs an
    assertion, gets a token and looks up one serial with the module's own
    Get-AppleBusinessDevice - the same code the server will run.

    Prints lengths, never values, for the assertion and the token, and never
    anything of the key. Prints the device attributes the certificate uses,
    plus status and releasedFromOrgDateTime for the released-device question.

    Run it elevated (the key is readable only by SYSTEM and Administrators),
    once under pwsh.exe and once under powershell.exe.

.EXAMPLE
    .\Test-AppleLookup.ps1 -Serial <serial>

.EXAMPLE
    .\Test-AppleLookup.ps1 -Serial <serial-of-a-released-device>

    The released-device test: does Apple still return a device after it has
    been released from the organization?
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Serial,
    [string]$ConfigPath = 'C:\ProgramData\AppleCert\config.json'
)

Import-Module (Join-Path $PSScriptRoot 'AppleCert.psm1') -Force -ErrorAction Stop

function Show-Step([string]$Label, [string]$Value, [string]$Color = 'Gray') {
    Write-Host ("  {0,-26} {1}" -f $Label, $Value) -ForegroundColor $Color
}

$Serial = $Serial.Trim().ToUpperInvariant()
if (-not (Test-SerialNumber $Serial)) {
    Write-Host "Serial number must be 1 to 32 letters and digits." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Apple Business lookup test" -ForegroundColor Cyan
Show-Step 'Runtime' "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)), .NET $([Environment]::Version)"
Show-Step 'Running as' ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

try {
    $config = Import-AppleCertConfig -Path $ConfigPath
    Show-Step 'Config' $ConfigPath
    Show-Step 'Key file' $config.PrivateKeyPath

    $key = Import-EcPrivateKey -Path $config.PrivateKeyPath
    $size = $key.KeySize
    $key.Dispose()
    Show-Step 'Key' "loaded, P-$size" 'Green'

    $assertion = New-AppleClientAssertion -ClientId $config.ClientId -KeyId $config.KeyId `
                     -PrivateKeyPath $config.PrivateKeyPath
    Show-Step 'Client assertion' "signed, $($assertion.Length) characters" 'Green'
    $assertion = $null

    [void](Get-AppleAccessToken -Config $config -Force)
    $state = Get-AppleTokenState
    Show-Step 'Access token' "received, $($state.Length) characters, in memory only" 'Green'

    $result = Get-AppleBusinessDevice -Serial $Serial -Config $config
}
catch {
    Write-Host ""
    Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
if (-not $result.Found) {
    Write-Host "  Not found (HTTP $($result.Status)): $($result.Message)" -ForegroundColor Yellow
    Write-Host "  If this device has been released from Apple Business, it cannot be certified:" -ForegroundColor Yellow
    Write-Host "  released devices are not reliably returned. Issue certificates before release." -ForegroundColor Yellow
    exit 2
}

$d = $result.Device
Write-Host "  On the certificate" -ForegroundColor Cyan
foreach ($pair in @(
        @('Device Type',     'productFamily'),
        @('Model',           'deviceModel'),
        @('Serial Number',   'serialNumber'),
        @('Device Capacity', 'deviceCapacity'),
        @('Part Number',     'partNumber'))) {
    Show-Step $pair[0] ([string](Get-DataProperty $d $pair[1]))
}

Write-Host "  For the released-device question" -ForegroundColor Cyan
foreach ($name in 'status', 'addedToOrgDateTime', 'updatedDateTime', 'releasedFromOrgDateTime') {
    $v = [string](Get-DataProperty $d $name)
    if (-not $v) { $v = '(not present)' }
    Show-Step $name $v
}

Write-Host "  Everything else Apple returned" -ForegroundColor Cyan
$shown = 'productFamily', 'deviceModel', 'serialNumber', 'deviceCapacity', 'partNumber',
         'status', 'addedToOrgDateTime', 'updatedDateTime', 'releasedFromOrgDateTime'
foreach ($p in @($d.PSObject.Properties | Where-Object { $shown -notcontains $_.Name } | Sort-Object Name)) {
    $v = $p.Value
    if ($v -is [array]) { $v = ($v -join ', ') }
    Show-Step $p.Name ([string]$v) 'DarkGray'
}
Write-Host ""
exit 0
