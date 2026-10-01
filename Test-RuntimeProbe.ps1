<#
.SYNOPSIS
    Proves the runtime on the lab machine before the app is built on it.

.DESCRIPTION
    Two modes.

    -Serve (on the lab machine, under the scheduled task, as SYSTEM)
        Opens an HttpListener on https://+:5000/applecert/ with Windows
        Integrated authentication, using the module's security headers and
        Origin check, and answers:

          GET  /applecert/          who you are, as the server sees it: account,
                                    SID, the AllowedGroup check, the AD display
                                    name and mail, the runtime - and a form that
                                    POSTs back, like the real certificate form
          POST /applecert/post      the strict Origin check: 200 for an exact
                                    match to PublicOrigin, 403 for anything
                                    else, including "null" and no Origin at all
          GET  /applecert/health    OK

        It stops by itself after -Minutes, so a probe left running cannot hold
        the reservation the real server will need.

    -Check (from a technician's PC, as yourself)
        Sends the requests a browser cannot be made to send - Origin: null, no
        Origin, a foreign Origin - plus a correct one, and reports which were
        accepted. Uses your Windows sign-in, as a browser would.

    The real form POST from Edge is the one test this script cannot do for
    you: open the page, press the button, and read the result.

.EXAMPLE
    .\Test-RuntimeProbe.ps1 -Serve -PublicOrigin https://<lab-machine>.<domain>:5000 -AllowedGroup DOMAIN\AppleCert-Users

.EXAMPLE
    .\Test-RuntimeProbe.ps1 -Check -Url https://<lab-machine>.<domain>:5000/applecert/
#>

[CmdletBinding(DefaultParameterSetName = 'Serve')]
param(
    [Parameter(ParameterSetName = 'Serve')][switch]$Serve,
    [Parameter(ParameterSetName = 'Serve')][ValidateRange(1, 65535)][int]$Port = 5000,
    [Parameter(ParameterSetName = 'Serve')][string]$BasePath = '/applecert/',
    [Parameter(ParameterSetName = 'Serve')][string]$PublicOrigin,
    [Parameter(ParameterSetName = 'Serve')][string]$AllowedGroup,
    [Parameter(ParameterSetName = 'Serve')][ValidateRange(1, 240)][int]$Minutes = 30,
    [Parameter(ParameterSetName = 'Serve')]
    [ValidateSet('IntegratedWindowsAuthentication', 'Negotiate', 'Ntlm')]
    [string]$AuthScheme = 'IntegratedWindowsAuthentication',
    [Parameter(ParameterSetName = 'Serve')][string]$LogPath = "$PSScriptRoot\RuntimeProbe.log",

    [Parameter(ParameterSetName = 'Check', Mandatory)][switch]$Check,
    [Parameter(ParameterSetName = 'Check', Mandatory)][string]$Url
)

Import-Module (Join-Path $PSScriptRoot 'AppleCert.psm1') -Force -ErrorAction Stop

function Write-ProbeLog {
    param([string]$Message)
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), ($Message -replace '[\x00-\x1f]', '?')
    Write-Host $line
    if ($LogPath) {
        try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    }
}

# ==================================================================
#  -Check: from a technician's PC
# ==================================================================
if ($PSCmdlet.ParameterSetName -eq 'Check') {

    $Url = $Url.TrimEnd('/') + '/'
    $u = [uri]$Url
    $origin = "$($u.Scheme)://$($u.Host)"
    if (-not $u.IsDefaultPort) { $origin += ":$($u.Port)" }
    $origin = $origin.ToLowerInvariant()

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    function Send-Probe {
        param([string]$Method, [string]$Target, $OriginHeader, [switch]$NoOrigin)
        $p = @{ Uri = $Target; Method = $Method; UseDefaultCredentials = $true; ErrorAction = 'Stop' }
        if ($PSVersionTable.PSVersion.Major -lt 6) { $p.UseBasicParsing = $true }
        if ($Method -eq 'Post') {
            $p.Body = 'probe=1'
            $p.ContentType = 'application/x-www-form-urlencoded'
            if (-not $NoOrigin) { $p.Headers = @{ Origin = $OriginHeader } }
        }
        try   { return [int](Invoke-WebRequest @p).StatusCode }
        catch {
            $r = $_.Exception.Response
            if ($r) { return [int]$r.StatusCode }
            return "error: $($_.Exception.Message)"
        }
    }

    $cases = @(
        @{ Label = 'GET the page (signed in)';           Method = 'Get';  Want = 200 }
        @{ Label = "POST, Origin: $origin";              Method = 'Post'; Origin = $origin;                 Want = 200 }
        @{ Label = 'POST, Origin: null';                 Method = 'Post'; Origin = 'null';                  Want = 403 }
        @{ Label = 'POST, no Origin header';             Method = 'Post'; NoOrigin = $true;                 Want = 403 }
        @{ Label = 'POST, Origin: https://evil.example'; Method = 'Post'; Origin = 'https://evil.example';  Want = 403 }
    )
    if ($origin.StartsWith('https://')) {
        $cases += @{ Label = 'POST, same host over http'; Method = 'Post'; Origin = ($origin -replace '^https', 'http'); Want = 403 }
    }

    Write-Host ""
    Write-Host "Probing $Url as $env:USERDOMAIN\$env:USERNAME (PowerShell $($PSVersionTable.PSVersion))"
    $bad = 0
    foreach ($c in $cases) {
        $target = $Url
        if ($c.Method -eq 'Post') { $target = $Url + 'post' }
        $got = Send-Probe -Method $c.Method -Target $target -OriginHeader $c.Origin -NoOrigin:([bool]$c.NoOrigin)
        if ([string]$got -eq [string]$c.Want) {
            Write-Host ("  PASS  {0,-42} {1}" -f $c.Label, $got) -ForegroundColor Green
        } else {
            $bad++
            Write-Host ("  FAIL  {0,-42} {1}  wanted {2}" -f $c.Label, $got, $c.Want) -ForegroundColor Red
        }
    }
    Write-Host ""
    Write-Host "Still to do by hand: open $Url in Edge, press 'Send a form POST', and confirm it says ACCEPTED."
    if ($bad) { exit 1 }
    exit 0
}

# ==================================================================
#  -Serve: on the lab machine
# ==================================================================
if (-not $PublicOrigin) { throw '-PublicOrigin is required, e.g. https://<lab-machine>.<domain>:5000' }
$PublicOrigin = $PublicOrigin.Trim().TrimEnd('/').ToLowerInvariant()

$BasePath   = '/' + $BasePath.Trim('/') + '/'
$basePrefix = $BasePath.TrimEnd('/')

$groupSid = $null
$groupNote = 'not set (-AllowedGroup)'
if ($AllowedGroup) {
    try   { $groupSid = Resolve-AllowedGroupSid -Group $AllowedGroup; $groupNote = "$AllowedGroup = $groupSid" }
    catch { $groupNote = "$AllowedGroup could not be resolved: $($_.Exception.Message)" }
}

$runtime = "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)), .NET $([Environment]::Version)"
$runAs   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("https://+:${Port}${BasePath}")
$listener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::$AuthScheme

try { $listener.Start() }
catch {
    Write-ProbeLog "PROBE FAILED TO START  https://+:${Port}${BasePath}  $runtime  as $runAs - $($_.Exception.Message)"
    Write-Host "Check the reservation: netsh http show urlacl url=https://+:${Port}${BasePath}" -ForegroundColor Yellow
    Write-Host "and the certificate:   netsh http show sslcert ipport=0.0.0.0:$Port" -ForegroundColor Yellow
    exit 1
}

$stopAt = (Get-Date).AddMinutes($Minutes)
Write-ProbeLog "PROBE STARTED  https://+:${Port}${BasePath}  $runtime  as $runAs  auth=$AuthScheme  origin=$PublicOrigin  group=$groupNote  until $($stopAt.ToString('HH:mm'))"

function New-ProbePage {
    param([string]$Title, [string]$Body)
    @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>$(ConvertTo-HtmlText $Title)</title>
<style>
  body { font-family: "Segoe UI", system-ui, Calibri, Arial, sans-serif; color: #101828;
         background: #fff; margin: 0; padding: 32px 16px; }
  main { max-width: 760px; margin: 0 auto; }
  .mark { font-size: 12px; font-weight: 600; letter-spacing: .14em; text-transform: uppercase; color: #22254e; }
  h1 { font-size: 23px; margin: 8px 0 20px; }
  table { border-collapse: collapse; width: 100%; font-size: 14px; }
  th, td { text-align: left; vertical-align: top; padding: 7px 10px; border-bottom: 1px solid #e4e7ec; }
  th { width: 34%; color: #475467; font-weight: 600; }
  td { font-family: Consolas, "Cascadia Mono", ui-monospace, monospace; font-size: 13px; overflow-wrap: anywhere; }
  .ok { color: #067647; font-weight: 700; } .no { color: #b3261e; font-weight: 700; }
  button { margin-top: 20px; font: inherit; font-size: 15px; font-weight: 600; color: #fff;
           background: #22254e; border: 0; border-radius: 10px; padding: 12px 22px; cursor: pointer; }
  p { line-height: 1.5; }
</style></head>
<body><main><div class="mark">Apple Certificate &middot; runtime probe</div>
$Body
</main></body></html>
"@
}

function Format-Row {
    param([string]$Label, [string]$Value, [string]$Class)
    $c = ''
    if ($Class) { $c = " class=`"$Class`"" }
    "<tr><th>$(ConvertTo-HtmlText $Label)</th><td$c>$(ConvertTo-HtmlText $Value)</td></tr>"
}

try {
    while ($listener.IsListening -and (Get-Date) -lt $stopAt) {

        $pending = $listener.GetContextAsync()
        while (-not $pending.Wait(250)) {
            if (-not $listener.IsListening -or (Get-Date) -ge $stopAt) { break }
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

        $status = 200
        $body = ''
        $originHeader = $req.Headers['Origin']
        $originShown = '(none)'
        if ($null -ne $originHeader) { $originShown = $originHeader }

        try {
            if ($path -match '^/health/?$') {
                $body = 'OK'
                $context.Response.ContentType = 'text/plain; charset=utf-8'
                Write-ProbeLog "$user  GET health"
            }
            elseif ($path -match '^/post/?$' -and $req.HttpMethod -eq 'POST') {
                if (Test-RequestOrigin -Origin $originHeader -ExpectedOrigin $PublicOrigin) {
                    $verdict = '<p class="ok">ACCEPTED &mdash; the Origin header matched exactly.</p>'
                    Write-ProbeLog "$user  POST accepted  Origin=$originShown"
                } else {
                    $status = 403
                    $verdict = '<p class="no">REFUSED &mdash; the Origin header did not match exactly.</p>'
                    Write-ProbeLog "$user  POST REFUSED  Origin=$originShown"
                }
                $rows = @(
                    Format-Row 'Origin received' $originShown
                    Format-Row 'Origin expected' $PublicOrigin
                    Format-Row 'Referer received' ([string]$req.Headers['Referer'])
                    Format-Row 'Signed in as' $user
                ) -join "`n"
                $body = New-ProbePage -Title 'POST result' -Body @"
<h1>Form POST</h1>
$verdict
<table>$rows</table>
<p><a href="$BasePath">Back</a></p>
"@
            }
            elseif ($path -match '^/?$' -and $req.HttpMethod -eq 'GET') {
                $allowed = 'not checked (no group)'
                $allowedClass = ''
                if ($groupSid) {
                    if (Test-AllowedUser -Principal $principal -GroupSid $groupSid) { $allowed = 'yes'; $allowedClass = 'ok' }
                    else { $allowed = 'NO'; $allowedClass = 'no' }
                }
                $who = $null
                if ($principal -and $principal.Identity -and $principal.Identity.IsAuthenticated) {
                    $who = Get-TechnicianIdentity -Principal $principal
                }
                $display = '-'; $mail = '-'; $source = '-'; $sid = '-'
                if ($who) {
                    $display = $who.DisplayName; $mail = $who.Email; $source = $who.Source; $sid = [string]$who.Sid
                    if (-not $mail) { $mail = '(blank in AD)' }
                }
                $authType = '-'
                if ($principal -and $principal.Identity) { $authType = [string]$principal.Identity.AuthenticationType }

                $rows = @(
                    Format-Row 'Signed in as'           $user
                    Format-Row 'SID'                    $sid
                    Format-Row 'Authentication'         $authType
                    Format-Row 'In allowed group'       $allowed $allowedClass
                    Format-Row 'Allowed group'          $groupNote
                    Format-Row 'AD display name'        $display
                    Format-Row 'AD mail'                $mail
                    Format-Row 'AD lookup'              $source
                    Format-Row 'Server runtime'         $runtime
                    Format-Row 'Server running as'      $runAs
                    Format-Row 'Expected origin'        $PublicOrigin
                    Format-Row 'Probe stops at'         $stopAt.ToString('HH:mm')
                ) -join "`n"
                $body = New-ProbePage -Title 'Runtime probe' -Body @"
<h1>Who the server thinks you are</h1>
<table>$rows</table>
<p>This sends a real form POST, exactly as the certificate form will. It should say <b>ACCEPTED</b>.</p>
<form method="post" action="${BasePath}post"><input type="hidden" name="probe" value="1" /><button type="submit">Send a form POST</button></form>
"@
                Write-ProbeLog "$user  GET page  group=$allowed  ad=$source  displayName=$display  mail=$mail"
            }
            else {
                $status = 404
                $body = New-ProbePage -Title 'Not found' -Body '<h1>Not found</h1>'
            }
        }
        catch {
            $status = 500
            Write-ProbeLog "$user  ERROR $($_.Exception.Message)"
            $body = New-ProbePage -Title 'Error' -Body '<h1>Something went wrong</h1><p>The details are in the probe log.</p>'
        }

        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($body)
            $context.Response.StatusCode = $status
            $h = Get-AppleCertSecurityHeader
            foreach ($k in $h.Keys) { $context.Response.AddHeader($k, $h[$k]) }
            if (-not $context.Response.ContentType) { $context.Response.ContentType = 'text/html; charset=utf-8' }
            $context.Response.ContentLength64 = $bytes.Length
            $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        }
        catch { Write-ProbeLog "could not send the response: $($_.Exception.Message)" }
        finally { $context.Response.Close() }
    }
}
finally {
    $listener.Stop()
    $listener.Close()
    Write-ProbeLog 'PROBE STOPPED'
}
