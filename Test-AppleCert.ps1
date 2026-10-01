<#
.SYNOPSIS
    Checks AppleCert.psm1 against known cases.

.DESCRIPTION
    Imports AppleCert.psm1 and exercises everything that does not need the
    network, Active Directory or the lab machine: input validation, escaping,
    the Origin check, the security headers, the options file, the certificate
    page, and the private-key loader and ES256 signing (against a throwaway key
    generated in memory - no key is ever read from or written to the repo).

    Nothing here calls Apple. Run it under both Windows PowerShell 5.1 and
    PowerShell 7: the module is meant to work in either.

.EXAMPLE
    .\Test-AppleCert.ps1
#>

[CmdletBinding()]
param([string]$OptionsPath = "$PSScriptRoot\CertificateOptions.json")

$module = Join-Path $PSScriptRoot 'AppleCert.psm1'
if (-not (Test-Path $module)) { throw "Cannot find AppleCert.psm1 next to this test." }
Import-Module $module -Force -ErrorAction Stop

Write-Host ("PowerShell {0} ({1})" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)

# Every script is only worth testing if it parses. Catch a syntax error here
# rather than when the scheduled task starts it.
foreach ($script in @(Get-ChildItem -Path $PSScriptRoot -Filter '*.ps*1')) {
    $errors = $null; $tokens = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$errors)
    if ($errors) {
        $errors | ForEach-Object { Write-Host -ForegroundColor Red "PARSE $($script.Name) $($_.Extent.StartLineNumber): $($_.Message)" }
        throw "$($script.Name) does not parse."
    }
}

$failures = 0
function Assert-That {
    param([string]$Label, $Got, $Want)
    if ([string]$Got -ceq [string]$Want) {
        Write-Host ("  PASS  {0}" -f $Label)
    } else {
        $script:failures++
        Write-Host -ForegroundColor Red ("  FAIL  {0} -> '{1}'  wanted '{2}'" -f $Label, $Got, $Want)
    }
}
function Assert-Throws {
    param([string]$Label, [scriptblock]$Block, [string]$Like = '*')
    try { & $Block; $script:failures++; Write-Host -ForegroundColor Red "  FAIL  $Label -> did not throw" }
    catch {
        if ($_.Exception.Message -like $Like) { Write-Host "  PASS  $Label" }
        else { $script:failures++; Write-Host -ForegroundColor Red "  FAIL  $Label -> threw '$($_.Exception.Message)'" }
    }
}


Write-Host "`nHTML escaping" -ForegroundColor Cyan
Assert-That '<script>'          (ConvertTo-HtmlText '<script>alert(1)</script>') '&lt;script&gt;alert(1)&lt;/script&gt;'
Assert-That 'double quote'      (ConvertTo-HtmlText '" onfocus="x')  '&quot; onfocus=&quot;x'
Assert-That 'single quote'      (ConvertTo-HtmlText "' onmouseover='x") '&#39; onmouseover=&#39;x'
Assert-That 'ampersand first'   (ConvertTo-HtmlText '&lt;')          '&amp;lt;'
Assert-That 'empty'             (ConvertTo-HtmlText '')              ''
Assert-That 'null'              (ConvertTo-HtmlText $null)           ''


Write-Host "`nSerial numbers" -ForegroundColor Cyan
Assert-That 'letters and digits'     (Test-SerialNumber 'C02TEST0SN01') 'True'
Assert-That 'one character'          (Test-SerialNumber 'A')            'True'
Assert-That '32 characters'          (Test-SerialNumber ('A' * 32))     'True'
Assert-That '33 characters'          (Test-SerialNumber ('A' * 33))     'False'
Assert-That 'empty'                  (Test-SerialNumber '')             'False'
Assert-That 'null'                   (Test-SerialNumber $null)          'False'
Assert-That 'hyphen'                 (Test-SerialNumber 'ABC-123')      'False'
Assert-That 'slash'                  (Test-SerialNumber 'ABC/..')       'False'
Assert-That 'space'                  (Test-SerialNumber 'ABC 123')      'False'
Assert-That 'trailing newline'       (Test-SerialNumber "ABC123`n")     'False'
Assert-That 'non-ASCII digit'        (Test-SerialNumber "ABC١٢٣")       'False'
# Validation happens before any token is requested or URL is built.
Assert-Throws 'lookup refuses a bad serial' { Get-AppleBusinessDevice -Serial '../v1/users' -Config ([pscustomobject]@{}) } 'Serial number must be*'


Write-Host "`nCertificate IDs" -ForegroundColor Cyan
Assert-That 'AC-2026-000042'         (Test-CertificateId 'AC-2026-000042')   'True'
Assert-That 'lower case'             (Test-CertificateId 'ac-2026-000042')   'False'
Assert-That 'five digits'            (Test-CertificateId 'AC-2026-00042')    'False'
Assert-That 'seven digits'           (Test-CertificateId 'AC-2026-0000042')  'False'
Assert-That 'path traversal'         (Test-CertificateId '..\AC-2026-000042') 'False'
Assert-That 'trailing path'          (Test-CertificateId 'AC-2026-000042\..\x') 'False'
Assert-That 'extension'              (Test-CertificateId 'AC-2026-000042.html') 'False'
Assert-That 'trailing newline'       (Test-CertificateId "AC-2026-000042`n") 'False'
Assert-That 'empty'                  (Test-CertificateId '')                 'False'


Write-Host "`nOrigin check" -ForegroundColor Cyan
$own = 'https://lab-machine.example.org:5000'
Assert-That 'exact match'            (Test-RequestOrigin -Origin $own -ExpectedOrigin $own)                    'True'
Assert-That 'missing'                (Test-RequestOrigin -Origin $null -ExpectedOrigin $own)                   'False'
Assert-That 'empty'                  (Test-RequestOrigin -Origin '' -ExpectedOrigin $own)                      'False'
Assert-That 'literal null'           (Test-RequestOrigin -Origin 'null' -ExpectedOrigin $own)                  'False'
Assert-That 'other site'             (Test-RequestOrigin -Origin 'https://evil.example' -ExpectedOrigin $own)  'False'
Assert-That 'http, not https'        (Test-RequestOrigin -Origin 'http://lab-machine.example.org:5000' -ExpectedOrigin $own) 'False'
Assert-That 'other port'             (Test-RequestOrigin -Origin 'https://lab-machine.example.org:5001' -ExpectedOrigin $own) 'False'
Assert-That 'short name'             (Test-RequestOrigin -Origin 'https://lab-machine:5000' -ExpectedOrigin $own) 'False'
Assert-That 'suffix trick'           (Test-RequestOrigin -Origin "$own.evil.example" -ExpectedOrigin $own)     'False'
Assert-That 'trailing slash'         (Test-RequestOrigin -Origin "$own/" -ExpectedOrigin $own)                 'False'


Write-Host "`nSecurity headers" -ForegroundColor Cyan
$headers = Get-AppleCertSecurityHeader
# same-origin, not no-referrer: under no-referrer a browser's form POST says
# "Origin: null" and the strict check above would refuse every certificate.
Assert-That 'Referrer-Policy'        $headers['Referrer-Policy']        'same-origin'
Assert-That 'nosniff'                $headers['X-Content-Type-Options'] 'nosniff'
Assert-That 'frame deny'             $headers['X-Frame-Options']        'DENY'
Assert-That 'CSP frame-ancestors'    ($headers['Content-Security-Policy'] -match "frame-ancestors 'none'") 'True'
Assert-That 'CSP form-action self'   ($headers['Content-Security-Policy'] -match "form-action 'self'")     'True'
Assert-That 'CSP no unsafe-inline script' ($headers['Content-Security-Policy'] -match "script-src[^;]*'unsafe-inline'") 'False'


Write-Host "`nOptions file" -ForegroundColor Cyan
$options = Import-CertificateOption -Path $OptionsPath
Assert-That 'three wipe methods'     @($options.WipeMethod.Options).Count         3
Assert-That 'wipe method default'    $options.WipeMethod.Default                  'Erase All Content and Settings'
# One option must still be a list, not a bare string, on 5.1.
Assert-That 'one compliance standard' @($options.ComplianceStandard.Options).Count 1
Assert-That 'compliance default'     $options.ComplianceStandard.Default          'Built-in Erase (Factory Reset)'

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("applecert-test-" + [Guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $bad = Join-Path $tmp 'bad-default.json'
    '{"WipeMethod":{"Default":"Nope","Options":["A"]},"ComplianceStandard":{"Default":"B","Options":["B"]}}' |
        Set-Content -LiteralPath $bad -Encoding UTF8
    Assert-Throws 'default not in list refused' { Import-CertificateOption -Path $bad } '*not one of its options*'
    '{"WipeMethod":{"Default":"A","Options":["A","A"]},"ComplianceStandard":{"Default":"B","Options":["B"]}}' |
        Set-Content -LiteralPath $bad -Encoding UTF8
    Assert-Throws 'duplicate option refused' { Import-CertificateOption -Path $bad } '*same option twice*'
}
finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }


Write-Host "`nTechnician input" -ForegroundColor Cyan
$today = [datetime]'2026-10-01'
function Get-Problem {
    param([hashtable]$Override = @{})
    $p = @{ Options = $options; WipeMethod = 'MDM Remote Wipe'; ComplianceStandard = 'Built-in Erase (Factory Reset)'
            WipeDate = '2026-10-01'; Notes = ''; AssetTag = ''; Today = $today }
    foreach ($k in $Override.Keys) { $p[$k] = $Override[$k] }
    @(Test-CertificateInput @p)
}
Assert-That 'valid input'            (Get-Problem).Count 0
Assert-That 'unknown wipe method'    (Get-Problem @{ WipeMethod = 'Hammer' }).Count 1
Assert-That 'wrong-case wipe method' (Get-Problem @{ WipeMethod = 'mdm remote wipe' }).Count 1
Assert-That 'unknown standard'       (Get-Problem @{ ComplianceStandard = 'NIST 800-88 Purge' }).Count 1
Assert-That 'missing wipe method'    (Get-Problem @{ WipeMethod = $null }).Count 1
Assert-That 'wipe date in future'    (Get-Problem @{ WipeDate = '2026-10-02' }).Count 1
Assert-That 'wipe date in the past'  (Get-Problem @{ WipeDate = '2026-09-01' }).Count 0
Assert-That 'wipe date not a date'   (Get-Problem @{ WipeDate = '2026-13-01' }).Count 1
Assert-That 'wipe date other format' (Get-Problem @{ WipeDate = '01/10/2026' }).Count 1
Assert-That '500-char notes'         (Get-Problem @{ Notes = ('x' * 500) }).Count 0
Assert-That '501-char notes'         (Get-Problem @{ Notes = ('x' * 501) }).Count 1
Assert-That 'asset tag'              (Get-Problem @{ AssetTag = 'IT-004521' }).Count 0
Assert-That 'asset tag with markup'  (Get-Problem @{ AssetTag = '<b>' }).Count 1
Assert-That 'asset tag too long'     (Get-Problem @{ AssetTag = ('A' * 33) }).Count 1


Write-Host "`nCertificate data" -ForegroundColor Cyan
$device = [pscustomobject]@{
    productFamily = 'Mac'; deviceModel = 'MacBook Air <13-inch> "M2" & co'; serialNumber = 'C02TEST0SN01'
    deviceCapacity = '256GB'; partNumber = 'MLY33LL/A'; status = 'ASSIGNED'
}
$issued = [DateTimeOffset]::new(2026, 10, 1, 14, 32, 0, [TimeSpan]::FromHours(-5))
$base = @{
    Device = $device; Options = $options; CertificateId = 'AC-2026-000042'
    TechnicianName = "Alex O'Example"; TechnicianEmail = 'alex@example.org'; TechnicianAccount = 'DOMAIN\aexample'
    WipeMethod = 'Erase All Content and Settings'; ComplianceStandard = 'Built-in Erase (Factory Reset)'
    WipeDate = '2026-10-01'; Notes = "Line one`r`nLine <two>`a"; AssetTag = ' IT-1 '; IssuedAt = $issued
}
$data = New-CertificateData @base
Assert-That 'device type from Apple'  $data.DeviceType      'Mac'
Assert-That 'serial from Apple'       $data.SerialNumber    'C02TEST0SN01'
Assert-That 'asset tag trimmed'       $data.AssetTag        'IT-1'
Assert-That 'wipe date shown'         $data.WipeDate        '1 October 2026'
Assert-That 'issued shown'            $data.DateIssued      '1 October 2026, 14:32 (UTC-05:00)'
Assert-That 'issued for register'     $data.IssuedAtIso     '2026-10-01T14:32:00.0000000-05:00'
Assert-That 'notes: CRLF to LF, bell removed' $data.Notes   "Line one`nLine <two>"
Assert-Throws 'bad option refused'    { $b = $base.Clone(); $b.WipeMethod = 'Hammer'; New-CertificateData @b } '*wipe method*'
Assert-Throws 'future date refused'   { $b = $base.Clone(); $b.WipeDate = '2026-10-02'; New-CertificateData @b } '*future*'
Assert-Throws 'bad certificate ID'    { $b = $base.Clone(); $b.CertificateId = '..\x'; New-CertificateData @b } 'Not a certificate ID*'


Write-Host "`nCertificate page" -ForegroundColor Cyan
$html = New-CertificateHtml -Data $data -HomeLink '/applecert/'
Assert-That 'no template placeholders left'  ($html -match '«|»')                        'False'
Assert-That 'title'                          ($html -match '>CERTIFICATE OF DATA ERASURE<') 'True'
Assert-That 'subtitle'                       ($html -match '>Apple Device Wipe Verification<') 'True'
foreach ($section in 'DEVICE INFORMATION', 'WIPE DETAILS', 'CERTIFICATE DETAILS') {
    Assert-That "section $section"           ($html -match "<h2>$section</h2>")          'True'
}
Assert-That 'closing line'                   ($html -match 'Retain for audit and compliance purposes\.') 'True'
Assert-That 'footer'                         ($html -match 'CONFIDENTIAL &bull; IT ASSET MANAGEMENT') 'True'
Assert-That 'Apple data escaped'             ($html -match 'MacBook Air &lt;13-inch&gt; &quot;M2&quot; &amp; co') 'True'
Assert-That 'technician escaped'             ($html -match 'Alex O&#39;Example')          'True'
Assert-That 'notes escaped'                  ($html -match 'Line &lt;two&gt;')            'True'
Assert-That 'no raw markup from data'        ($html -match '<two>|<13-inch>')            'False'
Assert-That 'certificate ID shown'           ($html -match '<td>AC-2026-000042</td>')     'True'
Assert-That 'title names the ID (PDF name)'  ($html -match '<title>AC-2026-000042 Certificate of Data Erasure C02TEST0SN01</title>') 'True'

$blank = $data.PSObject.Copy(); $blank.AssetTag = ''; $blank.TechnicianEmail = ''
$blankHtml = New-CertificateHtml -Data $blank
Assert-That 'blank shows a dash'             ($blankHtml -match '<th>Asset Tag</th><td>&mdash;</td>') 'True'

# One page, US Letter, and nowhere for the browser's own header and footer.
Assert-That '@page letter, no margin'        ($html -match '@page \{ size: letter portrait; margin: 0; \}') 'True'
Assert-That 'screen-only hidden in print'    ($html -match '\.screen-only \{ display: none !important; \}') 'True'

# The print button's handler is the one script the CSP allows, by the SHA-256
# of its exact text. Pin the text, then recompute the hash from the page itself
# and check the header carries that hash.
Assert-That 'print handler exact'            ($html -match '<button class="action" type="button" onclick="window\.print\(\)">Print</button>') 'True'
$handlers = @([regex]::Matches($html, ' on[a-z]+="([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
Assert-That 'exactly one inline handler'     $handlers.Count 1
$sha = [System.Security.Cryptography.SHA256]::Create()
$hash = [Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($handlers[0])))
$sha.Dispose()
Assert-That 'CSP hash matches the handler'   ($headers['Content-Security-Policy'].Contains("'sha256-$hash'")) 'True'
Assert-That 'no script elements'             ($html -match '<script')                     'False'
Assert-That 'back link'                      ($html -match 'href="/applecert/"')          'True'
Assert-That 'no back link when not asked'    ($blankHtml -match 'look up another device') 'False'


Write-Host "`nPrivate key and ES256 signing" -ForegroundColor Cyan
# A throwaway P-256 key, generated in memory, written as PKCS#8 PEM by hand so
# this works on .NET Framework too, loaded back through the module's loader,
# then used to sign. The original key verifies the signature.
$orig = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$p = $orig.ExportParameters($true)
$der = [byte[]](0x30,0x81,0x87, 0x02,0x01,0x00,
                0x30,0x13, 0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01, 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,
                0x04,0x6D, 0x30,0x6B, 0x02,0x01,0x01, 0x04,0x20) + $p.D +
       [byte[]](0xA1,0x44, 0x03,0x42,0x00,0x04) + $p.Q.X + $p.Q.Y
$b64 = [Convert]::ToBase64String([byte[]]$der, 'InsertLineBreaks')
$keyDir = Join-Path ([IO.Path]::GetTempPath()) ("applecert-key-" + [Guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $keyDir | Out-Null
$keyPath = Join-Path $keyDir 'test.pem'
try {
    "-----BEGIN PRIVATE KEY-----`n$b64`n-----END PRIVATE KEY-----`n" | Set-Content -LiteralPath $keyPath -Encoding ASCII

    $loaded = Import-EcPrivateKey -Path $keyPath
    $back = $loaded.ExportParameters($false)
    Assert-That 'public point survives load' ([Convert]::ToBase64String($back.Q.X + $back.Q.Y)) ([Convert]::ToBase64String($p.Q.X + $p.Q.Y))
    $loaded.Dispose()

    $jwt = New-AppleClientAssertion -ClientId 'BUSINESSAPI.test' -KeyId 'kid-test' -PrivateKeyPath $keyPath
    $parts = $jwt.Split('.')
    Assert-That 'three parts'                $parts.Count 3
    function ConvertFrom-B64Url([string]$s) {
        $s = $s.Replace('-', '+').Replace('_', '/')
        switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
        ,[Convert]::FromBase64String($s)
    }
    $hdr    = [Text.Encoding]::UTF8.GetString((ConvertFrom-B64Url $parts[0])) | ConvertFrom-Json
    $claims = [Text.Encoding]::UTF8.GetString((ConvertFrom-B64Url $parts[1])) | ConvertFrom-Json
    $sig    = ConvertFrom-B64Url $parts[2]
    Assert-That 'alg ES256'                  $hdr.alg 'ES256'
    Assert-That 'kid'                        $hdr.kid 'kid-test'
    Assert-That 'iss = client ID'            $claims.iss 'BUSINESSAPI.test'
    Assert-That 'sub = client ID'            $claims.sub 'BUSINESSAPI.test'
    Assert-That 'aud has /v2'                $claims.aud 'https://account.apple.com/auth/oauth2/v2/token'
    Assert-That 'five minutes'               ($claims.exp - $claims.iat) 300
    Assert-That 'jti is a GUID'              ($claims.jti -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') 'True'
    Assert-That 'signature is r||s (64 bytes)' $sig.Length 64
    $ok = $orig.VerifyData([Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])"), $sig,
                           [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    Assert-That 'signature verifies'         $ok 'True'

    "-----BEGIN PUBLIC KEY-----`nAAAA`n-----END PUBLIC KEY-----" | Set-Content -LiteralPath $keyPath -Encoding ASCII
    Assert-Throws 'public key file refused'  { Import-EcPrivateKey -Path $keyPath } '*no PKCS#8 or EC private key*'
}
finally {
    $orig.Dispose()
    Remove-Item -LiteralPath $keyDir -Recurse -Force -ErrorAction SilentlyContinue
}


Write-Host "`nOnly one call to Apple's API" -ForegroundColor Cyan
# business.api can release devices and change users and groups. The module may
# make exactly two web requests: the token POST and the device GET. A third
# one, or a different method, has to be a deliberate change to this test too.
$ast = [System.Management.Automation.Language.Parser]::ParseFile($module, [ref]$null, [ref]$null)
$calls = @($ast.FindAll({
    param($n)
    $n -is [System.Management.Automation.Language.CommandAst] -and
    $n.GetCommandName() -in @('Invoke-RestMethod', 'Invoke-WebRequest', 'irm', 'iwr', 'curl', 'wget')
}, $true))
Assert-That 'two web requests in the module' $calls.Count 2
$methods = @($calls | ForEach-Object { ($_.Extent.Text -replace '\s+', ' ') -replace '.*-Method (\w+).*', '$1' } | Sort-Object)
Assert-That 'one GET, one POST'              ($methods -join ',') 'Get,Post'
$get = @($calls | Where-Object { $_.Extent.Text -match '-Method Get' })[0].Extent.Text
Assert-That 'GET goes to $uri'               ($get -match '-Uri \$uri ') 'True'
$src = Get-Content -LiteralPath $module -Raw
Assert-That 'the GET URI is /v1/orgDevices/' ($src -match '\$uri = "\$\(\$script:AppleApiBase\)/v1/orgDevices/\$\(\[uri\]::EscapeDataString\(\$Serial\)\)"') 'True'
Assert-That 'no HttpClient side door'        ($src -match 'HttpClient|WebClient|HttpWebRequest') 'False'


Write-Host ""
if ($failures -eq 0) { Write-Host "All cases passed." -ForegroundColor Green }
else { Write-Host "$failures case(s) failed." -ForegroundColor Red; exit 1 }
