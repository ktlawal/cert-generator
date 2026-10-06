<#
.SYNOPSIS
    Serves the Apple device erasure certificate app on this machine.

.DESCRIPTION
    A small HTTPS front end over AppleCert.psm1, beside AppFilter on the same
    port. A technician opens the URL, types a serial, checks the device Apple
    Business returns, chooses the wipe details, and gets a numbered
    certificate to save with the browser's Print -> Save as PDF.

        GET  /applecert/                     serial form
        GET  /applecert/device?serial=X      device details, existing
                                             certificates, technician form
        POST /applecert/certificate          check Origin, re-fetch the device
                                             from Apple, validate, issue,
                                             record, then 303 to the GET below
        GET  /applecert/certificate?id=X     an issued certificate, as stored
        GET  /applecert/health               OK

    Windows Integrated sign-in, HTTPS only, and every route but /health
    checked against AllowedGroup from the config. The Apple key, client ID and
    key ID live in the config outside the repo and never reach a page or the
    log.

.EXAMPLE
    .\Start-AppleCertServer.ps1

.NOTES
    Runs under the startup scheduled task as SYSTEM. The URL must be reserved
    for that account, once:

        netsh http add urlacl url=https://+:5000/applecert/ user="NT AUTHORITY\SYSTEM"

    The TLS certificate bound to 0.0.0.0:5000 is AppFilter's and is shared.
    The config is read at startup: restart the task after changing it.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 5000,

    # Must match the URL reservation exactly.
    [string]$BasePath = '/applecert/',

    [string]$ConfigPath = 'C:\ProgramData\AppleCert\config.json',

    [string]$OptionsPath,

    [ValidateSet('IntegratedWindowsAuthentication', 'Negotiate', 'Ntlm')]
    [string]$AuthScheme = 'IntegratedWindowsAuthentication',

    # Default: AppleCertServer.log in the config's DataPath, beside the
    # register - it names technicians and serials, so it lives where only
    # SYSTEM and Administrators can read.
    [string]$LogPath
)

# Windows PowerShell 5.1 leaves $PSScriptRoot empty while it binds parameter
# defaults when a script is started with -File, so defaults that need the
# script's folder are filled in here, in the body.
if (-not $OptionsPath) { $OptionsPath = Join-Path $PSScriptRoot 'CertificateOptions.json' }

Import-Module (Join-Path $PSScriptRoot 'AppleCert.psm1') -Force -ErrorAction Stop
Add-Type -AssemblyName System.Web

# Requests bigger than this are refused before they are read. The form is a
# few hundred bytes; 500 characters of notes is at most a few KB encoded.
$MaxBodyBytes = 16KB


# ------------------------------------------------------------------
#  Shared look: AppFilter's split page
# ------------------------------------------------------------------
$PageCss = @'
  * { box-sizing: border-box; }
  html, body { min-height: 100%; }
  body { margin: 0; display: grid; grid-template-columns: minmax(0,42%) minmax(0,1fr);
         min-height: 100vh;
         font-family: "Segoe UI", -apple-system, system-ui, Calibri, Arial, sans-serif;
         color: #101828; background: #fff; }

  .left { background: #22254e; color: #fff; padding: 46px 56px 46px 40px;
          display: flex; flex-direction: column; justify-content: center;
          align-items: flex-end; }
  .left .inner { max-width: 34ch; }
  .mark { font-size: 12px; font-weight: 600; letter-spacing: .14em;
          text-transform: uppercase; color: #7dd3fc; }
  .left h2 { font-size: 26px; font-weight: 600; letter-spacing: -.02em;
             line-height: 1.25; margin: 16px 0 0; }
  .left p { color: #94a3b8; font-size: 14px; line-height: 1.6; margin: 14px 0 0; }

  .right { display: grid; place-items: center start;
           padding: 40px 40px 40px 56px; min-width: 0; }
  .form { width: min(380px, 100%); min-width: 0; }
  .form.wide { width: min(560px, 100%); }
  h1 { font-size: 23px; font-weight: 600; letter-spacing: -.015em; margin: 0 0 26px; }
  h1 .sub { display: block; font-size: 14px; font-weight: 400; color: #667085;
            letter-spacing: 0; margin-top: 6px; }
  label, .label { display: block; font-size: 11px; font-weight: 600; letter-spacing: .09em;
                  text-transform: uppercase; color: #98a2b3; margin-bottom: 8px; }
  input[type=text].serial { width: 100%; min-width: 0;
                     font-family: Consolas, "Cascadia Mono", ui-monospace, monospace;
                     font-size: 22px; letter-spacing: .09em; text-transform: uppercase;
                     padding: 9px 15px; border: 1.5px solid #e4e7ec; border-radius: 10px;
                     outline: none; background: #fcfcfd; color: #101828;
                     transition: border-color .15s, background .15s; }
  input[type=text].serial::placeholder { color: #cdd2db; }
  input[type=text].serial:focus { border-color: #0f172a; background: #fff; }
  button { width: 100%; margin-top: 16px; font: inherit; font-size: 15px; font-weight: 600;
           color: #fff; background: #22254e; border: 0; border-radius: 10px;
           padding: 13px; cursor: pointer; transition: background .15s; }
  button:hover { background: #1e293b; }
  button:focus-visible { outline: 2px solid #0f172a; outline-offset: 2px; }

  .err { margin: 0 0 22px; padding: 12px 14px; border: 1px solid #f3b7b2;
         border-left-width: 3px; border-radius: 8px; background: #fef4f3;
         color: #b3261e; font-size: 13.5px; line-height: 1.5; }
  .err ul { margin: 6px 0 0; padding-left: 18px; }
  .err .why { display: block; margin-top: 6px; color: #7a2e28; }
  .warn { margin: 0 0 22px; padding: 12px 14px; border: 1px solid #f5d48a;
          border-left-width: 3px; border-radius: 8px; background: #fffaeb;
          color: #7a4c00; font-size: 13.5px; line-height: 1.5; }
  .warn ul { margin: 8px 0 0; padding-left: 18px; }
  .warn li { margin: 3px 0; }
  .warn a { color: #7a4c00; font-weight: 600; }

  /* Device details: read-only, from Apple. */
  table.facts { width: 100%; border-collapse: collapse; margin: 0 0 24px; font-size: 14px; }
  table.facts th, table.facts td { text-align: left; vertical-align: top; padding: 7px 0;
                                   border-bottom: 1px solid #f2f4f7; }
  table.facts th { width: 38%; font-weight: 500; color: #667085; padding-right: 12px; }
  table.facts td { color: #101828; overflow-wrap: anywhere; }
  .muted { color: #98a2b3; font-size: 13px; margin: -12px 0 24px; }

  /* The technician's choices. */
  .field { margin-bottom: 16px; }
  .field select, .field input, .field textarea {
          width: 100%; min-width: 0; font: inherit; font-size: 15px; color: #101828;
          padding: 9px 12px; border: 1.5px solid #e4e7ec; border-radius: 10px;
          background: #fcfcfd; outline: none; }
  .field select:focus, .field input:focus, .field textarea:focus { border-color: #0f172a; background: #fff; }
  .field textarea { min-height: 84px; resize: vertical; }
  .field .hint { font-size: 12px; color: #98a2b3; margin-top: 5px; }
  .row { display: grid; grid-template-columns: 1fr 1fr; gap: 0 14px; }

  .foot { margin-top: 26px; font-size: 12.5px; color: #98a2b3; line-height: 1.5; }
  .foot a { color: #667085; }

  /* The device page has no left panel: one centred column, room for the form. */
  body.single { grid-template-columns: minmax(0,1fr); }
  body.single .right { place-items: start center; padding: 48px 40px; }

  @media (max-width: 720px) {
    body { grid-template-columns: minmax(0,1fr); grid-template-rows: auto 1fr; }
    .left { padding: 28px 24px; align-items: stretch; }
    .left h2 { font-size: 21px; }
    .left p { display: none; }
    .right { padding: 32px 24px; justify-items: stretch; }
    .row { grid-template-columns: minmax(0,1fr); }
  }
  @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
'@

function New-SplitPage {
    <#
        Every page shares one shell. -NoPanel drops the left panel (the device
        page, once a lookup has been made) and centres the working column.
    #>
    param([string]$Title, [string]$Body, [switch]$Wide, [switch]$NoPanel)
    $cls = 'form'
    if ($Wide) { $cls = 'form wide' }
    $bodyTag = '<body>'
    $panel = @'
  <div class="left">
    <div class="inner">
      <div class="mark">PC DECOMMISSIONING</div>
      <h2>Apple Devices:<br />Certificate of data erasure</h2>
      <p>Looks the device up in Apple Business, records how it was wiped, and issues a numbered certificate to save as PDF.</p>
    </div>
  </div>
'@
    if ($NoPanel) { $bodyTag = '<body class="single">'; $panel = '' }
    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>$(ConvertTo-HtmlText $Title)</title>
<style>$PageCss</style>
</head>
$bodyTag
$panel  <div class="right">
    <div class="$cls">
$Body
    </div>
  </div>
</body>
</html>
"@
}

function Format-SignedIn {
    param($Technician)
    if (-not $Technician) { return '' }
    $who = ConvertTo-HtmlText $Technician.DisplayName
    if ($Technician.Email) { $who += " &middot; $(ConvertTo-HtmlText $Technician.Email)" }
    "Signed in as $who"
}

# Shown under "no device with that serial". Apple Business does not reliably
# keep released devices visible to the API, so certificates are issued before
# a device is released.
$NotFoundHint = 'If this device has been released from Apple Business, it cannot be certified here. Issue certificates before releasing devices.'

function New-FormPage {
    param([string]$Error, [string]$Serial, $Technician, [string]$Hint)

    $errHtml = ''
    if ($Error) {
        $hintHtml = ''
        if ($Hint) { $hintHtml = "<span class=`"why`">$(ConvertTo-HtmlText $Hint)</span>" }
        $errHtml = "      <p class=`"err`">$(ConvertTo-HtmlText $Error)$hintHtml</p>`n"
    }

    $body = @"
      <h1>Look up a device</h1>
$errHtml      <form method="get" action="${BasePath}device">
        <label for="serial">Serial number</label>
        <input type="text" class="serial" id="serial" name="serial" autofocus autocomplete="off"
               spellcheck="false" maxlength="32" placeholder="C02XXXXXXXXX" value="$(ConvertTo-HtmlText $Serial)" />
        <button type="submit">Look up</button>
      </form>
      <p class="foot">$(Format-SignedIn $Technician)</p>
"@
    New-SplitPage -Title 'Apple Device Erasure Certificate' -Body $body
}

function New-ErrorPage {
    param([string]$Title, [string]$Detail)
    $body = @"
      <h1>$(ConvertTo-HtmlText $Title)</h1>
      <p class="err">$(ConvertTo-HtmlText $Detail)</p>
      <form method="get" action="$BasePath"><button type="submit">Back</button></form>
"@
    New-SplitPage -Title $Title -Body $body
}

function Format-IsoDate {
    # Apple's timestamps and the register's, shown as "1 October 2026".
    param([string]$Value)
    if (-not $Value) { return '' }
    $t = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture,
                                   [Globalization.DateTimeStyles]::None, [ref]$t)) {
        return $t.ToLocalTime().ToString('d MMMM yyyy', [Globalization.CultureInfo]::InvariantCulture)
    }
    $Value
}

function New-DevicePage {
    <#
        Apple's record (read-only), any certificates already issued for the
        serial, and the form. On a failed POST it is shown again with the
        problems listed and the technician's choices kept.
    #>
    param(
        [Parameter(Mandatory)]$Device,
        [object[]]$History = @(),
        $Technician,
        [string[]]$Problems = @(),
        [hashtable]$Values = @{}
    )

    $serial = [string](Get-DataProperty $Device 'serialNumber')
    $model  = [string](Get-DataProperty $Device 'deviceModel')

    $facts = @(
        @('Device Type',     (Get-DataProperty $Device 'productFamily')),
        @('Model',           $model),
        @('Serial Number',   $serial),
        @('Device Capacity', (Get-DataProperty $Device 'deviceCapacity')),
        @('Part Number',     (Get-DataProperty $Device 'partNumber')),
        @('Colour',          (Get-DataProperty $Device 'color')),
        @('Status',          (Get-DataProperty $Device 'status')),
        @('Added to Apple Business', (Format-IsoDate ([string](Get-DataProperty $Device 'addedToOrgDateTime'))))
    )
    $released = [string](Get-DataProperty $Device 'releasedFromOrgDateTime')
    if ($released) { $facts += ,@('Released from Apple Business', (Format-IsoDate $released)) }

    $factRows = foreach ($f in $facts) {
        $v = [string]$f[1]
        if (-not $v) { $v = '&mdash;' } else { $v = ConvertTo-HtmlText $v }
        "        <tr><th>$($f[0])</th><td>$v</td></tr>"
    }

    # Already certified? Say so plainly, with links, but do not block: a device
    # can legitimately be wiped and certified again.
    $historyHtml = '      <p class="muted">No certificates have been issued for this device yet.</p>'
    $hist = @($History)
    if ($hist.Count -gt 0) {
        $items = foreach ($h in $hist) {
            $id = [string]$h.CertificateID
            $link = ConvertTo-HtmlText ("${BasePath}certificate?id=$id")
            "          <li><a href=`"$link`">$(ConvertTo-HtmlText $id)</a> &mdash; issued $(ConvertTo-HtmlText (Format-IsoDate $h.IssuedAt)) by $(ConvertTo-HtmlText $h.TechnicianName): $(ConvertTo-HtmlText $h.WipeMethod), wiped $(ConvertTo-HtmlText (Format-IsoDate $h.WipeDate))</li>"
        }
        $noun = 'certificate'
        if ($hist.Count -ne 1) { $noun = 'certificates' }
        $historyHtml = @"
      <div class="warn"><b>This device already has $($hist.Count) $noun.</b> Check you are not issuing a duplicate. Issue a new one only if the device was wiped again.
        <ul>
$($items -join "`n")
        </ul>
      </div>
"@
    }

    $errHtml = ''
    $probs = @($Problems)
    if ($probs.Count -gt 0) {
        $li = ($probs | ForEach-Object { "<li>$(ConvertTo-HtmlText $_)</li>" }) -join ''
        $errHtml = "      <div class=`"err`">The certificate was not issued:<ul>$li</ul></div>`n"
    }

    function Select-Options([object[]]$Choices, [string]$Selected) {
        ($Choices | ForEach-Object {
            $sel = ''
            if ([string]$_ -ceq $Selected) { $sel = ' selected' }
            "<option value=`"$(ConvertTo-HtmlText $_)`"$sel>$(ConvertTo-HtmlText $_)</option>"
        }) -join ''
    }

    $today = (Get-Date).ToString('yyyy-MM-dd')
    $wm = $Values['WipeMethod'];         if (-not $wm) { $wm = $options.WipeMethod.Default }
    $cs = $Values['ComplianceStandard']; if (-not $cs) { $cs = $options.ComplianceStandard.Default }
    $wd = $Values['WipeDate'];           if (-not $wd) { $wd = $today }

    $title = $model
    if (-not $title) { $title = 'Device' }

    $body = @"
      <h1>$(ConvertTo-HtmlText $title)<span class="sub">Serial $(ConvertTo-HtmlText $serial) &middot; from Apple Business</span></h1>
      <table class="facts">
$($factRows -join "`n")
      </table>
$historyHtml
$errHtml      <form method="post" action="${BasePath}certificate">
        <input type="hidden" name="serial" value="$(ConvertTo-HtmlText $serial)" />
        <div class="field">
          <label for="wipeMethod">Wipe method</label>
          <select id="wipeMethod" name="wipeMethod">$(Select-Options $options.WipeMethod.Options $wm)</select>
        </div>
        <div class="field">
          <label for="complianceStandard">Compliance standard</label>
          <select id="complianceStandard" name="complianceStandard">$(Select-Options $options.ComplianceStandard.Options $cs)</select>
        </div>
        <div class="row">
          <div class="field">
            <label for="wipeDate">Wipe date</label>
            <input type="date" id="wipeDate" name="wipeDate" required max="$today" value="$(ConvertTo-HtmlText $wd)" />
          </div>
          <div class="field">
            <label for="assetTag">Asset tag <span style="text-transform:none;letter-spacing:0;font-weight:400">(optional)</span></label>
            <input type="text" id="assetTag" name="assetTag" maxlength="32" autocomplete="off" spellcheck="false" value="$(ConvertTo-HtmlText $Values['AssetTag'])" />
          </div>
        </div>
        <div class="field">
          <label for="notes">Notes <span style="text-transform:none;letter-spacing:0;font-weight:400">(optional)</span></label>
          <textarea id="notes" name="notes" maxlength="500">$(ConvertTo-HtmlText $Values['Notes'])</textarea>
          <div class="hint">Up to 500 characters. Printed on the certificate.</div>
        </div>
        <button type="submit">Generate certificate</button>
      </form>
      <p class="foot">$(Format-SignedIn $Technician)<br /><a href="$BasePath">&larr; look up another device</a></p>
"@
    New-SplitPage -Title "$serial - Apple Device Erasure Certificate" -Body $body -Wide -NoPanel
}


# ------------------------------------------------------------------
#  Logging (as AppFilter: one line per request, lifecycle lines too)
# ------------------------------------------------------------------
function Limit-LogSize {
    param([string]$Path, [int]$MaxBytes = 5MB)
    try {
        $item = Get-Item -Path $Path -ErrorAction Stop
        if ($item.Length -lt $MaxBytes) { return }
        $previous = "$Path.1"
        if (Test-Path $previous) { Remove-Item $previous -Force -ErrorAction Stop }
        Rename-Item -Path $Path -NewName (Split-Path $previous -Leaf) -ErrorAction Stop
    }
    catch { }
}

function Write-ServerLog {
    param([string]$Message)
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), ($Message -replace '[\x00-\x1f]', '?')
    Write-Host $line
    if (-not $LogPath) { return }
    Limit-LogSize -Path $LogPath
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop }
    catch { Write-Warning "Could not write to $LogPath - $($_.Exception.Message)" }
}

function Write-RequestLog {
    param([string]$User, [string]$Serial, [string]$Outcome)
    if (-not $User)   { $User   = '-' }
    if (-not $Serial) { $Serial = '-' }
    # Keep every request to one line: a %0A in a query string must not forge
    # a second log entry.
    $Serial = ($Serial -replace '[\x00-\x1f]', '?')
    if ($Serial.Length -gt 40) { $Serial = $Serial.Substring(0, 40) }
    $Outcome = ($Outcome -replace '[\x00-\x1f]', '?')
    $line = '{0}  {1,-28} {2,-16} {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $User, $Serial, $Outcome
    Write-Host $line
    if (-not $LogPath) { return }
    Limit-LogSize -Path $LogPath
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop }
    catch { Write-Warning "Could not write to $LogPath - $($_.Exception.Message)" }
}


# ------------------------------------------------------------------
#  Fail on configuration before opening a port
# ------------------------------------------------------------------
try {
    $config  = Import-AppleCertConfig -Path $ConfigPath
    if (-not $LogPath) { $LogPath = Join-Path $config.DataPath 'AppleCertServer.log' }
    $options = Import-CertificateOption -Path $OptionsPath
    $groupSid = Resolve-AllowedGroupSid -Group $config.AllowedGroup

    # Prove the key loads now, not on the first certificate. Nothing of it is kept.
    $probeKey = Import-EcPrivateKey -Path $config.PrivateKeyPath
    $probeKey.Dispose()

    $certFolder = Join-Path $config.DataPath 'Certificates'
    if (-not (Test-Path -LiteralPath $certFolder)) { New-Item -ItemType Directory -Path $certFolder -Force | Out-Null }
}
catch {
    $reason = $_.Exception.Message
    Write-Host "Refusing to start: $reason" -ForegroundColor Red
    # The log may not be known yet; fall back to beside the script.
    if (-not $LogPath) { $LogPath = Join-Path $PSScriptRoot 'AppleCertServer.log' }
    Write-ServerLog "FAILED TO START (configuration) - $reason"
    exit 1
}

$BasePath   = '/' + $BasePath.Trim('/') + '/'
$basePrefix = $BasePath.TrimEnd('/')

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("https://+:${Port}${BasePath}")
$listener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::$AuthScheme

try { $listener.Start() }
catch {
    $reason = $_.Exception.Message
    Write-Host "Could not listen on https://+:${Port}${BasePath} - $reason" -ForegroundColor Red
    if ($reason -match 'conflicts with an existing registration') {
        Write-Host "Either something else is listening (an earlier instance, or the runtime probe)," -ForegroundColor Yellow
        Write-Host "or the URL is reserved for a different account. Check who holds it:" -ForegroundColor Yellow
        Write-Host "    netsh http show urlacl url=https://+:${Port}${BasePath}"
    } elseif ($reason -match 'Access is denied') {
        Write-Host "This account may not listen on that URL. Reserve it, once, elevated:" -ForegroundColor Yellow
        Write-Host "    netsh http add urlacl url=https://+:${Port}${BasePath} user=`"NT AUTHORITY\SYSTEM`""
    }
    Write-ServerLog "FAILED TO START  https://+:${Port}${BasePath} - $reason"
    exit 1
}

$runtime = "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
Write-ServerLog ("STARTED  https://+:{0}{1}  auth={2}  group={3}  origin={4}  data={5}  {6}  pid={7}" -f
                 $Port, $BasePath, $AuthScheme, $config.AllowedGroup, $config.PublicOrigin,
                 $config.DataPath, $runtime, $PID)

$security = Get-AppleCertSecurityHeader

try {
    while ($listener.IsListening) {

        # GetContext() blocks in native code where Ctrl+C cannot reach it;
        # waiting on the async version in slices keeps the console responsive.
        $pending = $listener.GetContextAsync()
        while (-not $pending.Wait(250)) {
            if (-not $listener.IsListening) { break }
        }
        if (-not $pending.IsCompleted) { break }
        $context = $pending.Result
        $req = $context.Request

        $principal = $context.User
        $user = 'anonymous'
        if ($principal -and $principal.Identity) { $user = $principal.Identity.Name }

        $path = $req.Url.AbsolutePath
        if ($path.StartsWith($basePrefix, [StringComparison]::OrdinalIgnoreCase)) { $path = $path.Substring($basePrefix.Length) }
        if (-not $path.StartsWith('/')) { $path = '/' + $path }

        $method   = $req.HttpMethod
        $status   = 200
        $body     = $null     # a string page, or
        $rawBytes = $null     # a stored certificate, sent exactly as issued
        $redirect = $null
        $serialForLog = '-'

        try {
            if ($path -match '^/health/?$') {
                $body = 'OK'
                $context.Response.ContentType = 'text/plain; charset=utf-8'
            }
            elseif (-not (Test-AllowedUser -Principal $principal -GroupSid $groupSid)) {
                # Viewing a stored certificate is refused as firmly as issuing one.
                $status = 403
                $body = New-ErrorPage -Title 'No access' `
                            -Detail 'Your account is not allowed to use this application. Ask IT to add you to the group that grants access.'
                Write-RequestLog -User $user -Serial '-' -Outcome "REFUSED (not in $($config.AllowedGroup)) $method $path"
            }
            elseif ($path -match '^/?$' -and $method -eq 'GET') {
                $tech = Get-TechnicianIdentity -Principal $principal
                $body = New-FormPage -Technician $tech
            }
            elseif ($path -match '^/device/?$' -and $method -eq 'GET') {
                $serial = ([string]$req.QueryString['serial']).Trim().ToUpperInvariant()
                $serialForLog = $serial
                $tech = Get-TechnicianIdentity -Principal $principal

                if (-not (Test-SerialNumber $serial)) {
                    $status = 400
                    $body = New-FormPage -Technician $tech -Serial $serial `
                                -Error 'That does not look like a serial number. Letters and digits only, up to 32.'
                    Write-RequestLog -User $user -Serial $serial -Outcome 'rejected (bad serial)'
                }
                else {
                    $result = Get-AppleBusinessDevice -Serial $serial -Config $config
                    if (-not $result.Found) {
                        $status = 404
                        $body = New-FormPage -Technician $tech -Serial $serial -Error $result.Message -Hint $NotFoundHint
                        Write-RequestLog -User $user -Serial $serial -Outcome 'not found in Apple Business'
                    } else {
                        $history = @(Get-CertificateHistory -DataPath $config.DataPath -Serial $serial)
                        $body = New-DevicePage -Device $result.Device -History $history -Technician $tech
                        Write-RequestLog -User $user -Serial $serial -Outcome "device shown ($($history.Count) existing)"
                    }
                }
            }
            elseif ($path -match '^/certificate/?$' -and $method -eq 'POST') {

                $origin = $req.Headers['Origin']
                if (-not (Test-RequestOrigin -Origin $origin -ExpectedOrigin $config.PublicOrigin)) {
                    $status = 403
                    $shown = '(none)'
                    if ($null -ne $origin) { $shown = $origin }
                    $body = New-ErrorPage -Title 'Request refused' `
                                -Detail 'That request did not come from this application. Start again from the serial number page.'
                    Write-RequestLog -User $user -Serial '-' -Outcome "REFUSED POST (Origin $shown)"
                }
                elseif ($req.ContentLength64 -gt $MaxBodyBytes) {
                    $status = 413
                    $body = New-ErrorPage -Title 'Request too large' -Detail 'That form was larger than this application accepts.'
                    Write-RequestLog -User $user -Serial '-' -Outcome "REFUSED POST (body $($req.ContentLength64) bytes)"
                }
                else {
                    # Read at most one byte more than allowed, so a request with
                    # no Content-Length still cannot be made to stream forever.
                    $buffer = New-Object byte[] ($MaxBodyBytes + 1)
                    $read = 0
                    while ($read -lt $buffer.Length) {
                        $n = $req.InputStream.Read($buffer, $read, $buffer.Length - $read)
                        if ($n -le 0) { break }
                        $read += $n
                    }
                    if ($read -gt $MaxBodyBytes) { throw 'POST body over the limit without a Content-Length.' }
                    $form = [System.Web.HttpUtility]::ParseQueryString([Text.Encoding]::UTF8.GetString($buffer, 0, $read))

                    $serial = ([string]$form['serial']).Trim().ToUpperInvariant()
                    $serialForLog = $serial
                    $values = @{
                        WipeMethod         = [string]$form['wipeMethod']
                        ComplianceStandard = [string]$form['complianceStandard']
                        WipeDate           = [string]$form['wipeDate']
                        AssetTag           = ([string]$form['assetTag']).Trim()
                        Notes              = [string]$form['notes']
                    }
                    $tech = Get-TechnicianIdentity -Principal $principal

                    if (-not (Test-SerialNumber $serial)) {
                        $status = 400
                        $body = New-FormPage -Technician $tech -Error 'That does not look like a serial number.'
                        Write-RequestLog -User $user -Serial $serial -Outcome 'rejected POST (bad serial)'
                    }
                    else {
                        # Never trust the form for anything about the device:
                        # fetch it from Apple again, now.
                        $result = Get-AppleBusinessDevice -Serial $serial -Config $config
                        if (-not $result.Found) {
                            $status = 404
                            $body = New-FormPage -Technician $tech -Serial $serial -Error $result.Message -Hint $NotFoundHint
                            Write-RequestLog -User $user -Serial $serial -Outcome 'rejected POST (not in Apple Business)'
                        }
                        else {
                            $now = [DateTimeOffset]::Now
                            $problems = @(Test-CertificateInput -Options $options -WipeMethod $values.WipeMethod `
                                            -ComplianceStandard $values.ComplianceStandard -WipeDate $values.WipeDate `
                                            -Notes $values.Notes -AssetTag $values.AssetTag -Today $now.Date)
                            if ($problems.Count -gt 0) {
                                $status = 400
                                $history = @(Get-CertificateHistory -DataPath $config.DataPath -Serial $serial)
                                $body = New-DevicePage -Device $result.Device -History $history -Technician $tech `
                                            -Problems $problems -Values $values
                                Write-RequestLog -User $user -Serial $serial -Outcome "rejected POST ($($problems -join ' '))"
                            }
                            else {
                                $issued = New-IssuedCertificate -DataPath $config.DataPath -Device $result.Device `
                                              -Options $options -Technician $tech -WipeMethod $values.WipeMethod `
                                              -ComplianceStandard $values.ComplianceStandard -WipeDate $values.WipeDate `
                                              -Notes $values.Notes -AssetTag $values.AssetTag -HomeLink $BasePath -IssuedAt $now
                                Write-RequestLog -User $user -Serial $serial `
                                    -Outcome ("ISSUED {0}  method={1}  standard={2}  wiped={3}  sha256={4}  ad={5}" -f
                                              $issued.CertificateID, $issued.WipeMethod, $issued.ComplianceStandard,
                                              $issued.WipeDateIso, $issued.Sha256, $tech.Source)
                                # Redirect, so a refresh or Back shows this
                                # certificate again instead of issuing another.
                                $status = 303
                                $redirect = "${BasePath}certificate?id=$($issued.CertificateID)"
                            }
                        }
                    }
                }
            }
            elseif ($path -match '^/certificate/?$' -and $method -eq 'GET') {
                $id = [string]$req.QueryString['id']
                $rawBytes = Get-IssuedCertificate -DataPath $config.DataPath -Id $id
                if ($null -eq $rawBytes) {
                    $status = 404
                    $body = New-ErrorPage -Title 'Not found' -Detail 'There is no certificate with that ID.'
                    $shownId = $id
                    if ($shownId.Length -gt 40) { $shownId = $shownId.Substring(0, 40) }
                    Write-RequestLog -User $user -Serial '-' -Outcome "certificate not found ($shownId)"
                } else {
                    Write-RequestLog -User $user -Serial '-' -Outcome "certificate viewed $id"
                }
            }
            else {
                $status = 404
                $body = New-ErrorPage -Title 'Not found' -Detail 'Nothing is served at that address.'
            }
        }
        catch {
            # One bad request must not take the server down. The detail goes
            # to the log only: it can name paths, tenants and API errors.
            $status = 500
            $rawBytes = $null
            $redirect = $null
            Write-RequestLog -User $user -Serial $serialForLog -Outcome "ERROR $($_.Exception.Message)"
            $body = New-ErrorPage -Title 'Something went wrong' `
                        -Detail 'That request could not be completed. The details are in the server log.'
        }

        try {
            $context.Response.StatusCode = $status
            foreach ($k in $security.Keys) { $context.Response.AddHeader($k, $security[$k]) }

            if ($redirect) {
                $context.Response.AddHeader('Location', $redirect)
                $bytes = New-Object byte[] 0
            } elseif ($null -ne $rawBytes) {
                $bytes = $rawBytes
                $context.Response.ContentType = 'text/html; charset=utf-8'
            } else {
                $bytes = [Text.Encoding]::UTF8.GetBytes([string]$body)
                if (-not $context.Response.ContentType) {
                    $context.Response.ContentType = 'text/html; charset=utf-8'
                }
            }
            $context.Response.ContentLength64 = $bytes.Length
            if ($bytes.Length -gt 0) { $context.Response.OutputStream.Write($bytes, 0, $bytes.Length) }
        }
        catch {
            Write-Warning "Could not send the response: $($_.Exception.Message)"
        }
        finally { $context.Response.Close() }
    }
}
finally {
    $listener.Stop()
    $listener.Close()
    Write-ServerLog 'STOPPED'
}
