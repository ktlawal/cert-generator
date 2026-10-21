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
        GET  /applecert/manual?serial=X      manual entry, for a serial Apple
                                             Business does not return
        POST /applecert/certificate/manual   check Origin, confirm Apple still
                                             does not return it, validate,
                                             issue, record, then 303
        GET  /applecert/health               OK

    Windows Integrated sign-in, HTTPS only, and every route but /health
    checked against AllowedGroup from the config. The two manual routes also
    need ManualAllowedGroup, and are off when it is not set. The Apple key, client ID and
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
# The whole form must arrive within this many seconds. The server answers one
# request at a time; without a deadline one slow client stalls everyone.
$BodyTimeoutSeconds = 10


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

  .left { position: relative; background: #22254e; color: #fff; padding: 46px 56px 46px 40px;
          display: flex; flex-direction: column; justify-content: center;
          align-items: flex-end; }
  .left .inner { width: 34ch; max-width: 100%; }
  /* Branding and support, along the bottom of the panel, lined up with the
     text above. */
  /* Width in the same ch as .inner (so the same font size here); the small
     size goes on the lines inside. */
  .panel-foot { position: absolute; right: 56px; bottom: 30px; width: 34ch;
                max-width: calc(100% - 96px); }
  .panel-foot div { font-size: 12.5px; line-height: 1.6; color: #94a3b8; }
  .panel-foot div.brand { font-weight: 600; color: #cbd5e1; }
  .panel-foot a { color: #7dd3fc; }
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
  /* Two columns of label-over-value in a light card. Model and serial are
     in the heading above, so they are not repeated here. */
  .device { margin: 0 0 24px; border: 1px solid #eaecf0; border-radius: 12px; background: #fcfcfd;
            overflow: hidden; }
  .device .dhead { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;
                   padding: 18px 20px 14px; border-bottom: 1px solid #eaecf0; }
  .device h1 { margin: 0; font-size: 22px; }
  .device .sub { font-size: 14px; color: #667085; margin-top: 4px; }
  .facts { display: grid; grid-template-columns: minmax(0,1fr) minmax(0,1fr); gap: 14px 28px;
           padding: 16px 20px 18px; }
  /* Apple's assignment status. Green: assigned. Amber: anything else.
     Red: Apple gives a release date - the case to stop and think about. */
  .badge { flex: none; white-space: nowrap; font-size: 12px; font-weight: 700; letter-spacing: .04em;
           padding: 4px 10px; border-radius: 999px; border: 1px solid; }
  .badge.ok   { background: #ecfdf3; color: #067647; border-color: #abefc6; }
  .badge.note { background: #fffaeb; color: #93370d; border-color: #fedf89; }
  .badge.bad  { background: #fef3f2; color: #b42318; border-color: #fecdca; }
  .facts div span { display: block; font-size: 11px; font-weight: 600; letter-spacing: .08em;
                    text-transform: uppercase; color: #98a2b3; margin-bottom: 2px; }
  .facts div b { display: block; font-weight: 500; font-size: 15px; color: #101828; overflow-wrap: anywhere; }
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
  .optional { text-transform: none; letter-spacing: 0; font-weight: 400; }
  .group { margin: 26px 0 14px; padding-top: 18px; border-top: 1px solid #eaecf0;
           font-size: 14px; font-weight: 600; color: #344054; }
  .group:first-child { margin-top: 0; padding-top: 0; border-top: 0; }
  .device .explain { padding: 14px 20px 16px; font-size: 13.5px; line-height: 1.55; color: #475467; margin: 0; }
  .err a.manual { display: inline-block; margin-top: 8px; color: #b3261e; font-weight: 600; }

  .foot { margin-top: 26px; font-size: 12.5px; color: #98a2b3; line-height: 1.5; }
  .foot a { color: #667085; }

  /* The device page has no left panel: one centred column, room for the form. */
  body.single { grid-template-columns: minmax(0,1fr); }
  body.single .right { place-items: start center; padding: 48px 40px; }

  @media (max-width: 720px) {
    body { grid-template-columns: minmax(0,1fr); grid-template-rows: auto 1fr; }
    .left { padding: 28px 24px; align-items: stretch; }
    .left .inner { width: auto; }
    .panel-foot { position: static; width: auto; max-width: none; margin-top: 16px; }
    .left h2 { font-size: 21px; }
    .left p { display: none; }
    .right { padding: 32px 24px; justify-items: stretch; }
    .row { grid-template-columns: minmax(0,1fr); }
  }
  @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
'@

function Format-PanelFoot {
    # "Product of Endpoint Management Team", and the support mailbox from
    # SupportEmail in the config when one is set.
    $support = ''
    if ($config.SupportEmail) {
        $mail = ConvertTo-HtmlText $config.SupportEmail
        $support = "<div>Support: <a href=`"mailto:$mail`?subject=Apple%20Certificate%20app`">$mail</a></div>"
    }
    "    <div class=`"panel-foot`"><div class=`"brand`">Product of Endpoint Management Team</div>$support</div>`n"
}

function New-SplitPage {
    <#
        Every page shares one shell. -NoPanel drops the left panel (the device
        page, once a lookup has been made) and centres the working column.
    #>
    param([string]$Title, [string]$Body, [switch]$Wide, [switch]$NoPanel)
    $cls = 'form'
    if ($Wide) { $cls = 'form wide' }
    $bodyTag = '<body>'
    $panel = @"
  <div class="left">
    <div class="inner">
      <div class="mark">PC DECOMMISSIONING</div>
      <h2>Apple Devices:<br />Certificate of data erasure</h2>
      <p>Looks the device up in Apple Business, records how it was wiped, and issues a certificate to save as PDF.</p>
    </div>
$(Format-PanelFoot)  </div>

"@
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
    # As AppFilter: the Windows account, DOMAIN\username. Landing page only.
    param([string]$User)
    if (-not $User) { return '' }
    "Signed in as $(ConvertTo-HtmlText $User)"
}

# Shown under "no device with that serial". Apple Business does not reliably
# keep released devices visible to the API, so certificates are issued before
# a device is released. Someone in ManualAllowedGroup gets a link to the
# manual form as well; everyone else is told who can help.
$NotFoundHint = 'Check the serial. If the device was released from Apple Business or never enrolled, a certificate with manually entered details can be issued by someone allowed to. Issue certificates before releasing devices.'
$NotFoundHintManual = 'Check the serial. If the device was released from Apple Business or never enrolled, you can issue a certificate with the details entered manually. Issue certificates before releasing devices.'

function Get-NotFoundPage {
    # The serial form with Apple's "not found", and the manual link for those
    # allowed to use it.
    param([string]$User, [string]$Serial, [string]$Message, [bool]$CanManual)
    if ($CanManual) {
        return New-FormPage -User $User -Serial $Serial -Error $Message -Hint $NotFoundHintManual -ManualSerial $Serial
    }
    New-FormPage -User $User -Serial $Serial -Error $Message -Hint $NotFoundHint
}

function New-FormPage {
    param([string]$Error, [string]$Serial, [string]$User, [string]$Hint, [string]$ManualSerial)

    $errHtml = ''
    if ($Error) {
        $hintHtml = ''
        if ($Hint) { $hintHtml = "<span class=`"why`">$(ConvertTo-HtmlText $Hint)</span>" }
        if ($ManualSerial -and (Test-SerialNumber $ManualSerial)) {
            $href = ConvertTo-HtmlText ("${BasePath}manual?serial=$ManualSerial")
            $hintHtml += "<a class=`"manual`" href=`"$href`">Issue a certificate with manually entered details &rarr;</a>"
        }
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
      <p class="foot">$(Format-SignedIn $User)</p>
"@
    New-SplitPage -Title 'Apple Device Erasure Certificate' -Body $body
}

function New-ErrorPage {
    param([string]$Title, [string]$Detail, [string]$LinkHref, [string]$LinkText)
    $link = ''
    if ($LinkHref -and $LinkText) {
        $link = "<a class=`"manual`" href=`"$(ConvertTo-HtmlText $LinkHref)`">$(ConvertTo-HtmlText $LinkText) &rarr;</a>"
    }
    $body = @"
      <h1>$(ConvertTo-HtmlText $Title)</h1>
      <p class="err">$(ConvertTo-HtmlText $Detail)$link</p>
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

function ConvertTo-ReadableText {
    # Apple sends colours and statuses in capitals with underscores:
    # "SPACE GRAY" -> "Space Gray", "DEVICE_ASSIGNMENT_UNKNOWN" -> "Device Assignment Unknown".
    # Display only; nothing printed on the certificate changes.
    param([string]$Text)
    if (-not $Text) { return '' }
    $t = $Text.Replace('_', ' ').Trim().ToLowerInvariant()
    [Globalization.CultureInfo]::InvariantCulture.TextInfo.ToTitleCase($t)
}

function Format-StatusBadge {
    param([string]$Status, [string]$Released)
    if ($Released) { return '<span class="badge bad">&#9679; Released</span>' }
    if (-not $Status) { return '<span class="badge note">&#9679; Status unknown</span>' }
    $cls = 'note'
    if ($Status -eq 'ASSIGNED') { $cls = 'ok' }
    "<span class=`"badge $cls`">&#9679; $(ConvertTo-HtmlText (ConvertTo-ReadableText $Status))</span>"
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
        @('Colour',          (ConvertTo-ReadableText ([string](Get-DataProperty $Device 'color')))),
        @('Added to Apple Business', (Format-IsoDate ([string](Get-DataProperty $Device 'addedToOrgDateTime'))))
    )
    $released = [string](Get-DataProperty $Device 'releasedFromOrgDateTime')
    $badge = Format-StatusBadge -Status ([string](Get-DataProperty $Device 'status')) -Released $released
    if ($released) { $facts += ,@('Released from Apple Business', (Format-IsoDate $released)) }

    # The heading carries the serial, and the model when Apple gives one, so
    # the grid does not repeat them.
    $factRows = foreach ($f in $facts) {
        if ($f[0] -eq 'Serial Number') { continue }
        if ($f[0] -eq 'Model' -and $model) { continue }
        $v = [string]$f[1]
        if (-not $v) { $v = '&mdash;' } else { $v = ConvertTo-HtmlText $v }
        "        <div><span>$($f[0])</span><b>$v</b></div>"
    }

    $historyHtml = Format-History -History $History
    $errHtml = Format-Problems -Problems $Problems
    $wipeFields = Format-WipeFields -Values $Values

    $title = $model
    if (-not $title) { $title = 'Device' }

    $body = @"
      <div class="device">
        <div class="dhead">
          <div><h1>$(ConvertTo-HtmlText $title)</h1><div class="sub">Serial $(ConvertTo-HtmlText $serial) &middot; from Apple Business</div></div>
          $badge
        </div>
        <div class="facts">
$($factRows -join "`n")
        </div>
      </div>
$historyHtml
$errHtml      <form method="post" action="${BasePath}certificate">
        <input type="hidden" name="serial" value="$(ConvertTo-HtmlText $serial)" />
$wipeFields
        <button type="submit">Generate certificate</button>
      </form>
      <p class="foot"><a href="$BasePath">&larr; look up another device</a></p>
"@
    New-SplitPage -Title "$serial - Apple Device Erasure Certificate" -Body $body -Wide -NoPanel
}

function Format-History {
    # Already certified? Say so plainly, with links, but do not block: a device
    # can legitimately be wiped and certified again.
    param([object[]]$History = @())
    $historyHtml = '      <p class="muted">No certificates have been issued for this device yet.</p>'
    $hist = @($History)
    if ($hist.Count -gt 0) {
        $items = foreach ($h in $hist) {
            $id = [string]$h.CertificateID
            $link = ConvertTo-HtmlText ("${BasePath}certificate?id=$id")
            $how = ''
            if ($h.DeviceSource -ceq 'Manual') { $how = ' (details entered manually)' }
            "          <li><a href=`"$link`">$(ConvertTo-HtmlText $id)</a>$how &mdash; issued $(ConvertTo-HtmlText (Format-IsoDate $h.IssuedAt)) by $(ConvertTo-HtmlText $h.TechnicianName): $(ConvertTo-HtmlText $h.WipeMethod), wiped $(ConvertTo-HtmlText (Format-IsoDate $h.WipeDate))</li>"
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
    $historyHtml
}

function Format-Problems {
    param([string[]]$Problems = @())
    $probs = @($Problems)
    if ($probs.Count -eq 0) { return '' }
    $li = ($probs | ForEach-Object { "<li>$(ConvertTo-HtmlText $_)</li>" }) -join ''
    "      <div class=`"err`">The certificate was not issued:<ul>$li</ul></div>`n"
}

function Select-Options {
    # <option>s for a dropdown. -Prompt adds a first, empty choice, so a
    # required field has to be chosen rather than left on its first value.
    param([object[]]$Choices, [string]$Selected, [string]$Prompt)
    $out = @()
    if ($Prompt) { $out += "<option value=`"`">$(ConvertTo-HtmlText $Prompt)</option>" }
    $out += $Choices | ForEach-Object {
        $sel = ''
        if ([string]$_ -ceq $Selected) { $sel = ' selected' }
        "<option value=`"$(ConvertTo-HtmlText $_)`"$sel>$(ConvertTo-HtmlText $_)</option>"
    }
    $out -join ''
}

function Format-WipeFields {
    # The technician's wipe details: the same fields on both forms.
    param([hashtable]$Values = @{}, [string]$NotesHint = 'Up to 500 characters. Printed on the certificate.')
    $today    = (Get-Date).ToString('yyyy-MM-dd')
    $earliest = (Get-Date).AddDays(-180).ToString('yyyy-MM-dd')
    $wm = $Values['WipeMethod'];         if (-not $wm) { $wm = $options.WipeMethod.Default }
    $cs = $Values['ComplianceStandard']; if (-not $cs) { $cs = $options.ComplianceStandard.Default }
    $wd = $Values['WipeDate'];           if (-not $wd) { $wd = $today }

    @"
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
            <input type="date" id="wipeDate" name="wipeDate" required min="$earliest" max="$today" value="$(ConvertTo-HtmlText $wd)" />
          </div>
          <div class="field">
            <label for="assetTag">Asset tag <span class="optional">(optional)</span></label>
            <input type="text" id="assetTag" name="assetTag" maxlength="32" autocomplete="off" spellcheck="false" value="$(ConvertTo-HtmlText $Values['AssetTag'])" />
          </div>
        </div>
        <div class="field">
          <label for="notes">Notes <span class="optional">(optional)</span></label>
          <textarea id="notes" name="notes" maxlength="500">$(ConvertTo-HtmlText $Values['Notes'])</textarea>
          <div class="hint">$(ConvertTo-HtmlText $NotesHint)</div>
        </div>
"@
}

function New-ManualPage {
    <#
        Manual entry, for a serial Apple Business does not return. Reached
        only from "not found", and only by ManualAllowedGroup. The technician
        types the serial again, the device details and a reason; the wipe
        fields are the same as on the device page.
    #>
    param(
        [Parameter(Mandatory)][string]$Serial,
        [object[]]$History = @(),
        [string[]]$Problems = @(),
        [hashtable]$Values = @{}
    )
    $manual = Get-ManualOption
    $historyHtml = Format-History -History $History
    $errHtml = Format-Problems -Problems $Problems
    $wipeFields = Format-WipeFields -Values $Values `
                      -NotesHint 'Up to 500 characters. Printed on the certificate under "Device details entered manually".'
    $s = ConvertTo-HtmlText $Serial

    $body = @"
      <div class="device">
        <div class="dhead">
          <div><h1>Manual certificate</h1><div class="sub">Serial $s &middot; not found in Apple Business</div></div>
          <span class="badge note">&#9679; Manual entry</span>
        </div>
        <p class="explain">Apple Business has no record of this serial, so the device details below are typed in, not looked up. Copy them from the device itself or its packaging. The certificate will say <b>Device details entered manually</b>.</p>
      </div>
$historyHtml
$errHtml      <form method="post" action="${BasePath}certificate/manual">
        <input type="hidden" name="serial" value="$s" />
        <div class="group">Why it is entered manually</div>
        <div class="row">
          <div class="field">
            <label for="reason">Reason</label>
            <select id="reason" name="reason" required>$(Select-Options $manual.Reasons $Values['Reason'] -Prompt 'Choose a reason')</select>
          </div>
          <div class="field">
            <label for="reasonDetail">Explanation <span class="optional">(required for Other)</span></label>
            <input type="text" id="reasonDetail" name="reasonDetail" maxlength="200" autocomplete="off" value="$(ConvertTo-HtmlText $Values['ReasonDetail'])" />
          </div>
        </div>
        <div class="group">Device information</div>
        <div class="row">
          <div class="field">
            <label for="serialConfirm">Serial number, again</label>
            <input type="text" id="serialConfirm" name="serialConfirm" required maxlength="32" autocomplete="off" spellcheck="false" value="$(ConvertTo-HtmlText $Values['SerialConfirm'])" />
            <div class="hint">Type it again from the device. It must match $s.</div>
          </div>
          <div class="field">
            <label for="deviceType">Device type</label>
            <select id="deviceType" name="deviceType" required>$(Select-Options $manual.DeviceTypes $Values['DeviceType'] -Prompt 'Choose a type')</select>
          </div>
        </div>
        <div class="field">
          <label for="model">Model</label>
          <input type="text" id="model" name="model" required maxlength="80" autocomplete="off" placeholder="MacBook Air 13-inch (M2, 2022)" value="$(ConvertTo-HtmlText $Values['Model'])" />
        </div>
        <div class="row">
          <div class="field">
            <label for="deviceCapacity">Device capacity <span class="optional">(optional)</span></label>
            <input type="text" id="deviceCapacity" name="deviceCapacity" maxlength="16" autocomplete="off" placeholder="256GB" value="$(ConvertTo-HtmlText $Values['DeviceCapacity'])" />
          </div>
          <div class="field">
            <label for="partNumber">Part number <span class="optional">(optional)</span></label>
            <input type="text" id="partNumber" name="partNumber" maxlength="20" autocomplete="off" spellcheck="false" placeholder="MLY33LL/A" value="$(ConvertTo-HtmlText $Values['PartNumber'])" />
          </div>
        </div>
        <div class="group">Wipe details</div>
$wipeFields
        <button type="submit">Generate manual certificate</button>
      </form>
      <p class="foot"><a href="$BasePath">&larr; look up another device</a></p>
"@
    New-SplitPage -Title "$Serial - Manual Apple Device Erasure Certificate" -Body $body -Wide -NoPanel
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
    # Echoed only in an interactive session. Under the startup task the console
    # is captured into task-output.log, which never rotates and sits outside
    # the locked data folder; the log file below is the record.
    if ([Environment]::UserInteractive) { Write-Host $line }
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
    # The manual path is off unless a group is named for it.
    $manualGroupSid = $null
    if ($config.ManualAllowedGroup) { $manualGroupSid = Resolve-AllowedGroupSid -Group $config.ManualAllowedGroup }

    # A register from before the manual columns is brought up to date now,
    # with a .bak copy beside it, rather than on the first certificate.
    if (Update-RegisterLayout -DataPath $config.DataPath) {
        $registerUpgraded = $true
    }

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
# http.sys's own limit on a stalled request body (default 2 minutes), as a
# second line behind Read-LimitedBody's deadline. Applies to this app's URL
# only, not to AppFilter's. Windows only; elsewhere the setting is absent.
try { $listener.TimeoutManager.EntityBody = [TimeSpan]::FromSeconds($BodyTimeoutSeconds) } catch { }

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
$supportShown = $config.SupportEmail
if (-not $supportShown) { $supportShown = '(none - set SupportEmail in the config)' }
$manualShown = $config.ManualAllowedGroup
if (-not $manualShown) { $manualShown = '(off - set ManualAllowedGroup in the config)' }
if ($registerUpgraded) { Write-ServerLog 'REGISTER UPDATED to the current columns (previous copy: register.csv.bak)' }
Write-ServerLog ("STARTED  https://+:{0}{1}  auth={2}  group={3}  manual={4}  origin={5}  data={6}  support={7}  {8}  pid={9}" -f
                 $Port, $BasePath, $AuthScheme, $config.AllowedGroup, $manualShown, $config.PublicOrigin,
                 $config.DataPath, $supportShown, $runtime, $PID)

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

        # Manual certificates: only when the path is on and the caller is in its group.
        $canManual = $false
        if ($manualGroupSid) { $canManual = Test-AllowedUser -Principal $principal -GroupSid $manualGroupSid }

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
                $body = New-FormPage -User $user
            }
            elseif ($path -match '^/device/?$' -and $method -eq 'GET') {
                $serial = ([string]$req.QueryString['serial']).Trim().ToUpperInvariant()
                $serialForLog = $serial

                if (-not (Test-SerialNumber $serial)) {
                    $status = 400
                    $body = New-FormPage -User $user -Serial $serial `
                                -Error 'That does not look like a serial number. Letters and digits only, up to 32.'
                    Write-RequestLog -User $user -Serial $serial -Outcome 'rejected (bad serial)'
                }
                else {
                    $result = Get-AppleBusinessDevice -Serial $serial -Config $config
                    if (-not $result.Found) {
                        $status = 404
                        $body = Get-NotFoundPage -User $user -Serial $serial -Message $result.Message -CanManual $canManual
                        Write-RequestLog -User $user -Serial $serial -Outcome 'not found in Apple Business'
                    } else {
                        $history = @(Get-CertificateHistory -DataPath $config.DataPath -Serial $serial)
                        $body = New-DevicePage -Device $result.Device -History $history
                        Write-RequestLog -User $user -Serial $serial -Outcome "device shown ($($history.Count) existing)"
                    }
                }
            }
            elseif ($path -match '^/manual/?$' -and $method -eq 'GET') {
                $serial = ([string]$req.QueryString['serial']).Trim().ToUpperInvariant()
                $serialForLog = $serial

                if (-not $canManual) {
                    $status = 403
                    $body = New-ErrorPage -Title 'No access' `
                                -Detail 'Your account is not allowed to issue certificates with manually entered details.'
                    Write-RequestLog -User $user -Serial $serial -Outcome 'REFUSED manual form (not in manual group)'
                }
                elseif (-not (Test-SerialNumber $serial)) {
                    $status = 400
                    $body = New-FormPage -User $user -Serial $serial `
                                -Error 'That does not look like a serial number. Letters and digits only, up to 32.'
                    Write-RequestLog -User $user -Serial $serial -Outcome 'rejected manual form (bad serial)'
                }
                else {
                    # Manual entry only for a serial Apple really does not return.
                    $result = $null
                    try { $result = Get-AppleBusinessDevice -Serial $serial -Config $config }
                    catch {
                        $status = 503
                        $body = New-ErrorPage -Title 'Apple Business could not be checked' `
                                    -Detail 'A manual certificate needs Apple Business to confirm it has no record of the device. Try again in a few minutes.'
                        Write-RequestLog -User $user -Serial $serial -Outcome "manual form unavailable ($($_.Exception.Message))"
                    }
                    if ($result -and $result.Found) {
                        $status = 303
                        $redirect = "${BasePath}device?serial=$serial"
                        Write-RequestLog -User $user -Serial $serial -Outcome 'manual form: found in Apple Business, sent to device page'
                    }
                    elseif ($result) {
                        $history = @(Get-CertificateHistory -DataPath $config.DataPath -Serial $serial)
                        $body = New-ManualPage -Serial $serial -History $history
                        Write-RequestLog -User $user -Serial $serial -Outcome "manual form shown ($($history.Count) existing)"
                    }
                }
            }
            elseif ($path -match '^/certificate(/manual)?/?$' -and $method -eq 'POST') {
                $isManualPost = $path -match '^/certificate/manual/?$'

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
                elseif (($bodyRead = Read-LimitedBody -Stream $req.InputStream -MaxBytes $MaxBodyBytes `
                                         -TimeoutSeconds $BodyTimeoutSeconds).Status -ne 'ok') {
                    # Over the limit however it was sent (chunked has no
                    # Content-Length), or not all there in time: refuse cleanly
                    # rather than hold the one request slot.
                    if ($bodyRead.Status -eq 'toolarge') {
                        $status = 413
                        $body = New-ErrorPage -Title 'Request too large' -Detail 'That form was larger than this application accepts.'
                    } else {
                        $status = 408
                        $body = New-ErrorPage -Title 'Request timed out' -Detail 'The form did not arrive in time. Please try again.'
                    }
                    Write-RequestLog -User $user -Serial '-' -Outcome "REFUSED POST (body $($bodyRead.Status))"
                }
                elseif ($isManualPost -and -not $canManual) {
                    $status = 403
                    $body = New-ErrorPage -Title 'No access' `
                                -Detail 'Your account is not allowed to issue certificates with manually entered details.'
                    Write-RequestLog -User $user -Serial '-' -Outcome 'REFUSED manual POST (not in manual group)'
                }
                elseif ($isManualPost) {
                    $form = [System.Web.HttpUtility]::ParseQueryString($bodyRead.Text)
                    $serial = ([string]$form['serial']).Trim().ToUpperInvariant()
                    $serialForLog = $serial
                    $values = @{
                        Reason             = [string]$form['reason']
                        ReasonDetail       = [string]$form['reasonDetail']
                        SerialConfirm      = [string]$form['serialConfirm']
                        DeviceType         = [string]$form['deviceType']
                        Model              = [string]$form['model']
                        DeviceCapacity     = [string]$form['deviceCapacity']
                        PartNumber         = [string]$form['partNumber']
                        WipeMethod         = [string]$form['wipeMethod']
                        ComplianceStandard = [string]$form['complianceStandard']
                        WipeDate           = [string]$form['wipeDate']
                        AssetTag           = ([string]$form['assetTag']).Trim()
                        Notes              = [string]$form['notes']
                    }

                    if (-not (Test-SerialNumber $serial)) {
                        $status = 400
                        $body = New-FormPage -User $user -Error 'That does not look like a serial number.'
                        Write-RequestLog -User $user -Serial $serial -Outcome 'rejected manual POST (bad serial)'
                    }
                    else {
                        # Ask Apple again, now: if it has the device, the
                        # details must come from Apple; if Apple cannot be
                        # reached, an outage is no reason to type them in.
                        $result = $null
                        try { $result = Get-AppleBusinessDevice -Serial $serial -Config $config }
                        catch {
                            $status = 503
                            $body = New-ErrorPage -Title 'Apple Business could not be checked' `
                                        -Detail 'The certificate was not issued: a manual certificate needs Apple Business to confirm it has no record of the device. Try again in a few minutes.'
                            Write-RequestLog -User $user -Serial $serial -Outcome "rejected manual POST (Apple unavailable: $($_.Exception.Message))"
                        }
                        if ($result -and $result.Found) {
                            $status = 409
                            $body = New-ErrorPage -Title 'Device found in Apple Business' `
                                        -Detail 'The certificate was not issued: Apple Business has this device, so its details must come from Apple.' `
                                        -LinkHref "${BasePath}device?serial=$serial" -LinkText 'Open the device page'
                            Write-RequestLog -User $user -Serial $serial -Outcome 'rejected manual POST (found in Apple Business)'
                        }
                        elseif ($result) {
                            $now = [DateTimeOffset]::Now
                            $problems = @(Test-ManualDeviceInput -Serial $serial -SerialConfirm $values.SerialConfirm `
                                              -DeviceType $values.DeviceType -Model $values.Model `
                                              -DeviceCapacity $values.DeviceCapacity -PartNumber $values.PartNumber `
                                              -Reason $values.Reason -ReasonDetail $values.ReasonDetail)
                            $problems += @(Test-CertificateInput -Options $options -WipeMethod $values.WipeMethod `
                                               -ComplianceStandard $values.ComplianceStandard -WipeDate $values.WipeDate `
                                               -Notes $values.Notes -AssetTag $values.AssetTag -Today $now.Date)
                            if ($problems.Count -gt 0) {
                                $status = 400
                                $history = @(Get-CertificateHistory -DataPath $config.DataPath -Serial $serial)
                                $body = New-ManualPage -Serial $serial -History $history -Problems $problems -Values $values
                                Write-RequestLog -User $user -Serial $serial -Outcome "rejected manual POST ($($problems -join ' '))"
                            }
                            else {
                                $tech = Get-TechnicianIdentity -Principal $principal
                                $manualDevice = New-ManualDevice -Serial $serial -DeviceType $values.DeviceType `
                                                    -Model $values.Model -DeviceCapacity $values.DeviceCapacity `
                                                    -PartNumber $values.PartNumber
                                $issued = New-IssuedCertificate -DataPath $config.DataPath -Device $manualDevice `
                                              -Options $options -Technician $tech -WipeMethod $values.WipeMethod `
                                              -ComplianceStandard $values.ComplianceStandard -WipeDate $values.WipeDate `
                                              -Notes $values.Notes -AssetTag $values.AssetTag -HomeLink $BasePath -IssuedAt $now `
                                              -DeviceSource 'Manual' -ManualReason $values.Reason `
                                              -ManualReasonDetail $values.ReasonDetail
                                Write-RequestLog -User $user -Serial $serial `
                                    -Outcome ("ISSUED {0}  MANUAL reason={1}  method={2}  standard={3}  wiped={4}  sha256={5}  ad={6}" -f
                                              $issued.CertificateID, $issued.ManualReason, $issued.WipeMethod,
                                              $issued.ComplianceStandard, $issued.WipeDateIso, $issued.Sha256, $tech.Source)
                                $status = 303
                                $redirect = "${BasePath}certificate?id=$($issued.CertificateID)"
                            }
                        }
                    }
                }
                else {
                    $form = [System.Web.HttpUtility]::ParseQueryString($bodyRead.Text)

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
                        $body = New-FormPage -User $user -Error 'That does not look like a serial number.'
                        Write-RequestLog -User $user -Serial $serial -Outcome 'rejected POST (bad serial)'
                    }
                    else {
                        # Never trust the form for anything about the device:
                        # fetch it from Apple again, now.
                        $result = Get-AppleBusinessDevice -Serial $serial -Config $config
                        if (-not $result.Found) {
                            $status = 404
                            $body = Get-NotFoundPage -User $user -Serial $serial -Message $result.Message -CanManual $canManual
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
                                $body = New-DevicePage -Device $result.Device -History $history `
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
