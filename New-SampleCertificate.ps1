<#
.SYNOPSIS
    Writes sample certificates, with made-up data, for checking the layout.

.DESCRIPTION
    Two files, through the same New-CertificateHtml the server will use:

      sample-certificate.html      a typical certificate
      sample-certificate-long.html the worst case: 500 characters of notes,
                                   a long model name, blank asset tag and email

    Open each in Edge, press Print, choose Save as PDF, and check that it is
    one page with no browser header or footer. No Apple call, no key, no
    config: the device data here is invented.

.EXAMPLE
    .\New-SampleCertificate.ps1 -OutputFolder $env:USERPROFILE\Desktop
#>

[CmdletBinding()]
param([string]$OutputFolder = $PSScriptRoot)

Import-Module (Join-Path $PSScriptRoot 'AppleCert.psm1') -Force -ErrorAction Stop
$options = Import-CertificateOption -Path (Join-Path $PSScriptRoot 'CertificateOptions.json')
$issued  = [DateTimeOffset]::Now

$typical = New-CertificateData -Options $options -CertificateId "AC-$($issued.Year)-000042" `
    -Device ([pscustomobject]@{ productFamily = 'Mac'; deviceModel = 'MacBook Air 13-inch (M2, 2022)'
                                serialNumber = 'C02TEST0SN01'; deviceCapacity = '256GB'; partNumber = 'MLY33LL/A' }) `
    -TechnicianName 'Alex Example' -TechnicianEmail 'alex.example@example.org' -TechnicianAccount 'DOMAIN\aexample' `
    -WipeMethod $options.WipeMethod.Default -ComplianceStandard $options.ComplianceStandard.Default `
    -WipeDate $issued.ToString('yyyy-MM-dd') -AssetTag 'IT-004521' `
    -Notes 'Activation Lock confirmed off before erase. Device returned to stock.' -IssuedAt $issued

$notes = ('Worst-case note to prove the certificate still fits on one page. ' * 10)
$notes = $notes.Substring(0, 456) + "`nSecond line, to show line breaks are kept."
$long = New-CertificateData -Options $options -CertificateId "AC-$($issued.Year)-000043" `
    -Device ([pscustomobject]@{ productFamily = 'iPad'; deviceModel = 'iPad Pro 12.9-inch (6th generation) Wi-Fi + Cellular'
                                serialNumber = 'DMPTEST0SN02'; deviceCapacity = '2TB'; partNumber = 'MP2D3LL/A' }) `
    -TechnicianName 'Alexandra Example-Longname' -TechnicianEmail '' -TechnicianAccount 'DOMAIN\aexample' `
    -WipeMethod 'Restore via Finder/iTunes' -ComplianceStandard $options.ComplianceStandard.Default `
    -WipeDate $issued.AddDays(-1).ToString('yyyy-MM-dd') -AssetTag '' -Notes $notes -IssuedAt $issued

foreach ($pair in @(@('sample-certificate.html', $typical), @('sample-certificate-long.html', $long))) {
    $path = Join-Path $OutputFolder $pair[0]
    # UTF-8 without a BOM, byte for byte what the server will send.
    [IO.File]::WriteAllText($path, (New-CertificateHtml -Data $pair[1] -HomeLink '/applecert/'),
                            (New-Object Text.UTF8Encoding($false)))
    Write-Host "Wrote $path"
}
