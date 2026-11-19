<#
.SYNOPSIS
    Proves one certificate can go from the lab machine to SharePoint through
    the Power Automate flow: stored page -> PDF with Edge -> the flow.

.DESCRIPTION
    The proof before the upload task is built. Run it as SYSTEM (see HANDOFF,
    "SharePoint upload: proof"), because that is how the task will run: with
    nobody signed in, no browser profile and SYSTEM's own network settings.

    1. Reads the stored page of one certificate (as issued) and its serial
       from the register.
    2. Renders it to a one-page PDF with Edge, headless, in a private
       profile under the data folder.
    3. Sends the PDF to the flow as JSON, with the shared key in the
       x-applecert-key header, and prints the flow's answer.

    The flow's address and the shared key come from the config file
    (SharePointFlowUrl, SharePointFlowKey). Both are secrets: only their
    lengths are printed, never their values.

    Nothing in the register changes. The PDF is kept under
    <DataPath>\upload-work so it can be opened and checked.

.EXAMPLE
    .\Test-SharePointUpload.ps1 -Id AC-2026-000001
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Id,
    [string]$ConfigPath = 'C:\ProgramData\AppleCert\config.json',
    # Found in the usual places when not given.
    [string]$EdgePath
)

Import-Module (Join-Path $PSScriptRoot 'AppleCert.psm1') -Force -ErrorAction Stop

function Show-Step([string]$Label, [string]$Value, [string]$Color = 'Gray') {
    Write-Host ("  {0,-22} {1}" -f $Label, $Value) -ForegroundColor $Color
}
function Stop-Test([string]$Message) {
    Write-Host ""
    Write-Host "  FAILED: $Message" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "SharePoint upload test" -ForegroundColor Cyan
Show-Step 'Runtime'    "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
Show-Step 'Running as' ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

# --- Config: the usual values, plus the flow's address and key ------------
try { $config = Import-AppleCertConfig -Path $ConfigPath }
catch { Stop-Test $_.Exception.Message }
$raw = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
$flowUrl = ([string](Get-DataProperty $raw 'SharePointFlowUrl')).Trim()
$flowKey = ([string](Get-DataProperty $raw 'SharePointFlowKey')).Trim()
if ($flowUrl -notmatch '^https://[^\s/]+/') { Stop-Test 'SharePointFlowUrl in the config must be the flow''s https address.' }
if ($flowKey.Length -lt 32)               { Stop-Test 'SharePointFlowKey in the config must be the shared key (at least 32 characters).' }
Show-Step 'Flow address' "$($flowUrl.Length) characters (host $(([uri]$flowUrl).Host))"
Show-Step 'Shared key'   "$($flowKey.Length) characters"

# --- The certificate, as issued ----------------------------------------
if (-not (Test-CertificateId $Id)) { Stop-Test "Not a certificate ID: $Id" }
$bytes = Get-IssuedCertificate -DataPath $config.DataPath -Id $Id
if ($null -eq $bytes) { Stop-Test "No stored certificate $Id." }
$row = @(Get-CertificateRegister -DataPath $config.DataPath | Where-Object { $_.CertificateID -ceq $Id })[0]
if ($null -eq $row) { Stop-Test "$Id is not in the register." }
$fileName = "$Id - $($row.SerialNumber).pdf"
Show-Step 'Certificate' "$Id, serial $($row.SerialNumber)"

# --- PDF with Edge --------------------------------------------------------
if (-not $EdgePath) {
    $EdgePath = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}
if (-not $EdgePath -or -not (Test-Path -LiteralPath $EdgePath)) { Stop-Test 'Microsoft Edge was not found. Pass -EdgePath.' }

$work = Join-Path $config.DataPath 'upload-work'
New-Item -ItemType Directory -Path $work -Force | Out-Null
$html    = Join-Path $work "$Id.html"
# Rendered under the ID alone: no spaces, so no quoting to get wrong. The
# name with the serial is only the name it is uploaded under.
$pdf     = Join-Path $work "$Id.pdf"
# A fresh profile every run. With a shared one, a copy of Edge left behind by
# an earlier run takes the page instead, and prints its own blank tab.
$edgeProfile = Join-Path $work ('edge-' + [Guid]::NewGuid().ToString('n'))
[IO.File]::WriteAllBytes($html, $bytes)
if (Test-Path -LiteralPath $pdf) { Remove-Item -LiteralPath $pdf -Force }

# Start-Process joins its arguments with spaces, so a path is quoted only
# when it has a space in it (a DataPath somewhere other than the default).
function Format-PathArg([string]$Path) {
    if ($Path -match '\s') { return "`"$Path`"" }
    $Path
}
$pageUri = (New-Object System.UriBuilder -ArgumentList 'file', '', -1, $html.Replace('\', '/')).Uri.AbsoluteUri
if ($pageUri -notmatch '^file:///') { Stop-Test "Could not build a file address for $html." }
$edgeArgs = @('--headless', '--disable-gpu', '--no-first-run', '--no-pdf-header-footer',
              "--user-data-dir=$(Format-PathArg $edgeProfile)", "--print-to-pdf=$(Format-PathArg $pdf)", $pageUri)
$sw = [Diagnostics.Stopwatch]::StartNew()
try { $proc = Start-Process -FilePath $EdgePath -ArgumentList $edgeArgs -PassThru -WindowStyle Hidden -ErrorAction Stop }
catch { Stop-Test "Edge could not be started: $($_.Exception.Message)" }
$finished = $proc.WaitForExit(60000)
if (-not $finished) {
    # Edge runs as several processes: stop them all, not just the first.
    & taskkill.exe /PID $proc.Id /T /F 2>&1 | Out-Null
    try { $proc.Kill() } catch { }
}
$sw.Stop()
Remove-Item -LiteralPath $html -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $edgeProfile -Recurse -Force -ErrorAction SilentlyContinue
if (-not $finished) { Stop-Test 'Edge did not finish the PDF within 60 seconds.' }

if (-not (Test-Path -LiteralPath $pdf)) { Stop-Test "Edge exited (code $($proc.ExitCode)) without writing a PDF." }
$pdfBytes = [IO.File]::ReadAllBytes($pdf)
$head = [Text.Encoding]::ASCII.GetString($pdfBytes, 0, [Math]::Min(5, $pdfBytes.Length))
if ($head -ne '%PDF-') { Stop-Test 'Edge wrote a file, but it is not a PDF.' }
# The PDF's title is the page's <title>, which starts with the certificate ID.
# Anything else (a blank "New Tab", an error page) is not this certificate.
$pdfText = [Text.Encoding]::ASCII.GetString($pdfBytes)
$utf16Id = -join ([Text.Encoding]::BigEndianUnicode.GetBytes($Id) | ForEach-Object { $_.ToString('X2') })
if (-not ($pdfText.Contains("/Title ($Id ") -or $pdfText.Contains("FEFF$utf16Id"))) {
    $shownTitle = '(none)'
    if ($pdfText -match '/Title \(([^)]{0,60})') { $shownTitle = $Matches[1] }
    Stop-Test "Edge made a PDF of something else, titled '$shownTitle', not certificate $Id."
}
$pages = ([regex]::Matches($pdfText, '/Type\s*/Page[^s]')).Count
$pageColor = 'Green'
if ($pages -ne 1) { $pageColor = 'Yellow' }
Show-Step 'PDF' ("{0:N0} KB, {1} page(s), {2:N1} s - {3}" -f ($pdfBytes.Length / 1KB), $pages, $sw.Elapsed.TotalSeconds, $pdf) $pageColor

# --- Send it to the flow ------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$body = @{ fileName = $fileName; contentBase64 = [Convert]::ToBase64String($pdfBytes) } | ConvertTo-Json -Compress
try {
    $resp = Invoke-WebRequest -Uri $flowUrl -Method Post -Body $body -ContentType 'application/json' `
                -Headers @{ 'x-applecert-key' = $flowKey } -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
    $status = [int]$resp.StatusCode
    $answer = [string]$resp.Content
}
catch {
    $status = 0
    if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
    $answer = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $answer = $_.ErrorDetails.Message }
}
if ($answer.Length -gt 200) { $answer = $answer.Substring(0, 200) + '...' }

Write-Host ""
switch ($status) {
    200     { Write-Host "  SENT: the flow saved $fileName. Check the SharePoint repository." -ForegroundColor Green; exit 0 }
    403     { Write-Host "  REFUSED by the flow (403): the shared key or the file name did not pass its check." -ForegroundColor Yellow }
    0       { Write-Host "  NO ANSWER from the flow: $answer" -ForegroundColor Red }
    default { Write-Host "  The flow answered HTTP ${status}: $answer" -ForegroundColor Yellow }
}
exit 2
