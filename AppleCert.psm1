# AppleCert.psm1
#
# Apple device erasure certificates: look a device up in Apple Business by
# serial, merge what Apple says with what the technician chose, and render a
# printable certificate the technician saves with the browser's own
# Print -> Save as PDF.
#
# No credentials live in this file. The client ID, key ID and key path come
# from a config file outside the repository (see config.example.json), and are
# passed in by whoever calls these functions.
#
# Runs on Windows PowerShell 5.1 and PowerShell 7 alike, so the choice of
# runtime on the lab machine is a deployment decision, not a code change:
#   - no ternary, no ??, no ImportFromPem, no DSASignatureFormat
#   - wrap anything counted in @(): a single value has no .Count in 5.1
#   - failed-request bodies are read from $_.ErrorDetails.Message
#
# No Set-StrictMode, for the same reason as AppFilter: this reads a JSON API
# whose optional fields come and go, and missing-property-is-null is
# load-bearing. Read optional fields through Get-DataProperty.

# ------------------------------------------------------------------
#  Fixed facts about Apple Business. Not configuration on purpose.
# ------------------------------------------------------------------
$script:AppleTokenUrl      = 'https://account.apple.com/auth/oauth2/token'
# The assertion's audience carries /v2; the URL it is posted to does not.
$script:AppleTokenAudience = 'https://account.apple.com/auth/oauth2/v2/token'
$script:AppleApiBase       = 'https://api-business.apple.com'

# The token, in memory only. Never written anywhere, never logged.
$script:AppleToken        = $null
$script:AppleTokenExpires = [DateTimeOffset]::MinValue

# \z, not $: in .NET a $ also matches before a trailing newline, so
# "AC-2026-000042`n" would pass a $-anchored pattern and reach a file name.
$script:SerialPattern        = '^[A-Za-z0-9]{1,32}\z'
$script:CertificateIdPattern = '^AC-\d{4}-\d{6}\z'
$script:AssetTagPattern      = '^[A-Za-z0-9\-_/]{0,32}\z'
$script:NotesMaxLength       = 500

# The one inline script any page may run, and the CSP hash that permits it.
# The hash is over the handler's exact text: change one and the other must
# change with it, or the print button silently stops working.
# Test-AppleCert.ps1 recomputes the hash from the page this module emits.
$script:PrintHandler     = 'window.print()'
$script:PrintHandlerHash = 'sha256-MguIPR6qNR8D3B+eAlK+bIRTZe8t3wkOY4B/56Me9FU='


# ------------------------------------------------------------------
#  Small helpers
# ------------------------------------------------------------------
function Get-DataProperty {
    <#
        Reads a property off an object parsed from JSON, returning $null when
        it is absent rather than assuming the shape.
    #>
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function ConvertTo-HtmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    # Quotes matter as much as angle brackets: values land inside value="..."
    # as well as between tags. Ampersand first, or the escapes get re-escaped.
    $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').
          Replace('"', '&quot;').Replace("'", '&#39;')
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Test-SerialNumber {
    param([string]$Serial)
    if ($null -eq $Serial) { return $false }
    return ($Serial -cmatch $script:SerialPattern)
}

function Test-CertificateId {
    <#
        A certificate ID becomes a file name, so it is checked against the
        exact shape before anything is built from it. Nothing that passes this
        can contain a path separator, a dot or a drive letter.
    #>
    param([string]$Id)
    if ($null -eq $Id) { return $false }
    return ($Id -cmatch $script:CertificateIdPattern)
}

function Get-AppleCertSecurityHeader {
    <#
        The response headers every page gets, as AppFilter sends them, with
        one deliberate difference: Referrer-Policy is same-origin, not
        no-referrer. Under no-referrer a browser sends "Origin: null" on a form
        POST, and the strict Origin check on POST /applecert/certificate would
        refuse every legitimate request. same-origin still sends nothing to
        any other site.
    #>
    [ordered]@{
        'Content-Security-Policy' =
            "default-src 'none'; style-src 'unsafe-inline'; " +
            "script-src 'unsafe-hashes' '$($script:PrintHandlerHash)'; " +
            "img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        'X-Content-Type-Options'  = 'nosniff'
        'X-Frame-Options'         = 'DENY'
        'Referrer-Policy'         = 'same-origin'
    }
}

function Test-RequestOrigin {
    <#
        Strict CSRF check for the POST. Windows sign-in is silent, so any site
        a technician visits could otherwise make their browser submit a
        certificate request with their identity attached.

        Accepts only an exact match to our own origin. A missing header, the
        literal "null", and anything else are refused. The expected origin is
        stored lower-case (see Import-AppleCertConfig) and browsers serialize
        the origin lower-case, so this is an ordinal comparison.
    #>
    param([string]$Origin, [Parameter(Mandatory)][string]$ExpectedOrigin)
    if ([string]::IsNullOrEmpty($Origin)) { return $false }
    return [string]::Equals($Origin, $ExpectedOrigin, [StringComparison]::Ordinal)
}


# ------------------------------------------------------------------
#  Configuration and options
# ------------------------------------------------------------------
function Import-AppleCertConfig {
    <#
        Reads the config file kept outside the repository. Fails loudly on
        anything missing, so the server refuses to start rather than starting
        and failing on the first lookup.

        Returns the values plus nothing secret: the private key itself is read
        only when a token is needed, and never held here.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Config file not found: $Path" }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $cfg = $raw | ConvertFrom-Json

    $missing = @()
    foreach ($name in 'ClientId', 'KeyId', 'PrivateKeyPath', 'PublicOrigin', 'AllowedGroup', 'DataPath') {
        $v = [string](Get-DataProperty $cfg $name)
        if ([string]::IsNullOrWhiteSpace($v)) { $missing += $name }
    }
    if (@($missing).Count -gt 0) { throw "Config file $Path is missing: $($missing -join ', ')" }

    $origin = ([string]$cfg.PublicOrigin).Trim().TrimEnd('/').ToLowerInvariant()
    if ($origin -notmatch '^https://[a-z0-9.\-]+(:\d{1,5})?$') {
        throw "PublicOrigin must look like https://<lab-machine>.<domain>:5000 - got '$origin'."
    }

    [pscustomobject]@{
        ClientId       = ([string]$cfg.ClientId).Trim()
        KeyId          = ([string]$cfg.KeyId).Trim()
        PrivateKeyPath = ([string]$cfg.PrivateKeyPath).Trim()
        PublicOrigin   = $origin
        AllowedGroup   = ([string]$cfg.AllowedGroup).Trim()
        DataPath       = ([string]$cfg.DataPath).Trim()
    }
}

function Import-CertificateOption {
    <#
        The dropdown choices, from CertificateOptions.json, so adding a wipe
        method is a data edit. Each field has a list and a default that must be
        in the list.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Options file not found: $Path" }
    $json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json

    $result = [ordered]@{}
    foreach ($field in 'WipeMethod', 'ComplianceStandard') {
        $node    = Get-DataProperty $json $field
        $options = @(Get-DataProperty $node 'Options' | ForEach-Object { ([string]$_).Trim() } |
                     Where-Object { $_ })
        $default = ([string](Get-DataProperty $node 'Default')).Trim()

        if (@($options).Count -eq 0) { throw "Options file: $field has no options." }
        if (@($options | Select-Object -Unique).Count -ne @($options).Count) {
            throw "Options file: $field lists the same option twice."
        }
        if ($options -cnotcontains $default) {
            throw "Options file: the default for $field ('$default') is not one of its options."
        }
        $result[$field] = [pscustomobject]@{ Options = $options; Default = $default }
    }
    [pscustomobject]$result
}


# ------------------------------------------------------------------
#  The private key, without ImportFromPem
# ------------------------------------------------------------------
function Read-DerElement {
    # One DER TLV at $Offset. Returns tag, content offset, content length and
    # the offset just past the element.
    param([byte[]]$Der, [int]$Offset)
    if ($Offset + 2 -gt $Der.Length) { throw 'Private key: truncated DER.' }
    $tag = $Der[$Offset]
    $len = [int]$Der[$Offset + 1]
    $pos = $Offset + 2
    if ($len -band 0x80) {
        $n = $len -band 0x7f
        if ($n -lt 1 -or $n -gt 3) { throw 'Private key: unsupported DER length.' }
        $len = 0
        for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) -bor $Der[$pos + $i] }
        $pos += $n
    }
    if ($pos + $len -gt $Der.Length) { throw 'Private key: truncated DER.' }
    [pscustomobject]@{ Tag = $tag; Start = $pos; Length = $len; Next = $pos + $len }
}

function Get-DerBytes {
    param([byte[]]$Der, $Element)
    $out = New-Object byte[] $Element.Length
    [Array]::Copy($Der, $Element.Start, $out, 0, $Element.Length)
    ,$out
}

function ConvertFrom-EcPrivateKeyDer {
    <#
        SEC1 ECPrivateKey:
            SEQUENCE { INTEGER 1, OCTET STRING d, [0] curve OPTIONAL, [1] BIT STRING Q OPTIONAL }
        Returns d and the uncompressed public point, if present.
    #>
    param([byte[]]$Der)
    $seq = Read-DerElement $Der 0
    if ($seq.Tag -ne 0x30) { throw 'Private key: ECPrivateKey is not a SEQUENCE.' }
    $ver = Read-DerElement $Der $seq.Start
    if ($ver.Tag -ne 0x02) { throw 'Private key: ECPrivateKey has no version.' }
    $d = Read-DerElement $Der $ver.Next
    if ($d.Tag -ne 0x04) { throw 'Private key: ECPrivateKey has no private value.' }

    $result = @{ D = (Get-DerBytes $Der $d); Q = $null; CurveOid = $null }
    $pos = $d.Next
    $end = $seq.Next
    while ($pos -lt $end) {
        $el = Read-DerElement $Der $pos
        if ($el.Tag -eq 0xA0) {
            $oid = Read-DerElement $Der $el.Start
            $result.CurveOid = Get-DerBytes $Der $oid
        } elseif ($el.Tag -eq 0xA1) {
            $bits = Read-DerElement $Der $el.Start
            $raw  = Get-DerBytes $Der $bits
            # First byte of a BIT STRING is the unused-bit count (0 here).
            $q = New-Object byte[] ($raw.Length - 1)
            [Array]::Copy($raw, 1, $q, 0, $q.Length)
            $result.Q = $q
        }
        $pos = $el.Next
    }
    $result
}

function Import-EcPrivateKey {
    <#
        Loads an ES256 (P-256) private key from a PEM file into an ECDsa
        object, in a way that works on .NET Framework 4.7+ (Windows PowerShell
        5.1) as well as .NET 6+ (PowerShell 7). Accepts PKCS#8
        ("BEGIN PRIVATE KEY") and SEC1 ("BEGIN EC PRIVATE KEY").

        The caller disposes the returned object. Nothing here prints or logs
        any part of the key.
    #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "Private key file not found: $Path" }
    $pem = Get-Content -LiteralPath $Path -Raw

    $m = [regex]::Match($pem, '-----BEGIN (PRIVATE KEY|EC PRIVATE KEY)-----(.*?)-----END \1-----',
                        [Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $m.Success) { throw 'Private key: no PKCS#8 or EC private key block in the PEM file.' }
    $der = [Convert]::FromBase64String(($m.Groups[2].Value -replace '\s', ''))

    # 1.2.840.10045.3.1.7, prime256v1, as DER content bytes.
    $p256 = [byte[]](0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07)

    if ($m.Groups[1].Value -eq 'PRIVATE KEY') {
        # PKCS#8: SEQUENCE { INTEGER 0, SEQUENCE { OID ecPublicKey, OID curve }, OCTET STRING ECPrivateKey }
        $outer = Read-DerElement $der 0
        $ver   = Read-DerElement $der $outer.Start
        $alg   = Read-DerElement $der $ver.Next
        $algId = Read-DerElement $der $alg.Start
        $curve = Read-DerElement $der $algId.Next
        $inner = Read-DerElement $der $alg.Next
        if ($outer.Tag -ne 0x30 -or $alg.Tag -ne 0x30 -or $inner.Tag -ne 0x04 -or $curve.Tag -ne 0x06) {
            throw 'Private key: not a PKCS#8 EC key.'
        }
        $curveOid = Get-DerBytes $der $curve
        $ec = ConvertFrom-EcPrivateKeyDer (Get-DerBytes $der $inner)
    } else {
        $ec = ConvertFrom-EcPrivateKeyDer $der
        $curveOid = $ec.CurveOid
    }

    if ($null -ne $curveOid -and
        [Convert]::ToBase64String($curveOid) -ne [Convert]::ToBase64String($p256)) {
        throw 'Private key: not a P-256 key. Apple Business keys are ES256 (P-256).'
    }

    $d = $ec.D
    # A leading zero can be stripped or added; P-256 wants exactly 32 bytes.
    if ($d.Length -gt 32) { $d = $d[($d.Length - 32)..($d.Length - 1)] }
    if ($d.Length -lt 32) { $d = [byte[]](@(0) * (32 - $d.Length)) + $d }

    $params = New-Object System.Security.Cryptography.ECParameters
    $params.Curve = [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7')
    $params.D = [byte[]]$d

    if ($null -ne $ec.Q -and $ec.Q.Length -eq 65 -and $ec.Q[0] -eq 0x04) {
        $point = New-Object System.Security.Cryptography.ECPoint
        $point.X = [byte[]]$ec.Q[1..32]
        $point.Y = [byte[]]$ec.Q[33..64]
        $params.Q = $point
    } elseif ($PSVersionTable.PSVersion.Major -lt 6) {
        # .NET Framework will not derive the public point from D.
        throw 'Private key: the PEM file has no public key part, which Windows PowerShell 5.1 needs. Re-export it with the public key, or run under PowerShell 7.'
    }

    [System.Security.Cryptography.ECDsa]::Create($params)
}


# ------------------------------------------------------------------
#  Apple Business: token and the one GET
# ------------------------------------------------------------------
function New-AppleClientAssertion {
    <#
        An ES256 client assertion, valid for five minutes. Signed fresh each
        time a token is needed. Never printed or logged.
    #>
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$KeyId,
        [Parameter(Mandatory)][string]$PrivateKeyPath
    )

    $now    = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = [ordered]@{ alg = 'ES256'; kid = $KeyId; typ = 'JWT' }
    $claims = [ordered]@{
        iss = $ClientId
        sub = $ClientId
        aud = $script:AppleTokenAudience
        iat = $now
        exp = $now + 300
        jti = [Guid]::NewGuid().ToString()
    }

    $enc     = [Text.Encoding]::UTF8
    $signing = (ConvertTo-Base64Url $enc.GetBytes(($header | ConvertTo-Json -Compress))) + '.' +
               (ConvertTo-Base64Url $enc.GetBytes(($claims | ConvertTo-Json -Compress)))

    $key = Import-EcPrivateKey -Path $PrivateKeyPath
    try {
        # Both .NET Framework and .NET 6+ return the IEEE P1363 (r||s) form
        # by default, which is what a JWS ES256 signature is.
        $sig = $key.SignData($enc.GetBytes($signing),
                             [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    }
    finally { $key.Dispose() }

    if ($sig.Length -ne 64) { throw "ES256 signature has the wrong length ($($sig.Length))." }
    "$signing.$(ConvertTo-Base64Url $sig)"
}

function Get-AppleAccessToken {
    <#
        Returns a bearer token, reusing the one in memory until a minute before
        it expires. Apple's tokens last an hour.
    #>
    param([Parameter(Mandatory)]$Config, [switch]$Force)

    if (-not $Force -and $script:AppleToken -and
        [DateTimeOffset]::UtcNow -lt $script:AppleTokenExpires) {
        return $script:AppleToken
    }

    Enable-Tls12

    $assertion = New-AppleClientAssertion -ClientId $Config.ClientId -KeyId $Config.KeyId `
                     -PrivateKeyPath $Config.PrivateKeyPath
    $body = @{
        grant_type            = 'client_credentials'
        client_id             = $Config.ClientId
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $assertion
        scope                 = 'business.api'
    }

    try {
        $resp = Invoke-RestMethod -Uri $script:AppleTokenUrl -Method Post `
                    -ContentType 'application/x-www-form-urlencoded' -Body $body -ErrorAction Stop
    }
    catch {
        # Apple's error body names the problem (invalid_client and so on) and
        # carries no secret. The assertion is never part of the message.
        throw "Apple token request failed: $(Get-FailureDetail $_)"
    }

    $token = [string](Get-DataProperty $resp 'access_token')
    if ([string]::IsNullOrWhiteSpace($token)) { throw 'Apple token request returned no access token.' }

    $life = 3600
    $exp  = Get-DataProperty $resp 'expires_in'
    if ($exp) { $life = [int]$exp }

    $script:AppleToken        = $token
    $script:AppleTokenExpires = [DateTimeOffset]::UtcNow.AddSeconds([Math]::Max(60, $life - 60))
    $token
}

function Clear-AppleAccessToken {
    $script:AppleToken        = $null
    $script:AppleTokenExpires = [DateTimeOffset]::MinValue
}

function Get-AppleTokenState {
    # For diagnostics: whether a token is held and its length. Never the token.
    $len = 0
    if ($script:AppleToken) { $len = $script:AppleToken.Length }
    [pscustomobject]@{ Held = [bool]$script:AppleToken; Length = $len; Expires = $script:AppleTokenExpires }
}

function Enable-Tls12 {
    # Windows PowerShell 5.1 may still default to TLS 1.0/1.1. Apple needs 1.2+.
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
}

function Get-HttpStatus {
    param($ErrorRecord)
    try {
        $r = $ErrorRecord.Exception.Response
        if ($r) { return [int]$r.StatusCode }
    } catch { }
    return 0
}

function Get-FailureDetail {
    <#
        What went wrong with a web request, for the log. Apple's error body
        when there is one (it names the problem, e.g. invalid_client, and
        carries no secret); otherwise the exception, so a DNS, proxy or TLS
        failure is not reported as a bare "HTTP 0".
    #>
    param($ErrorRecord)
    $status = Get-HttpStatus $ErrorRecord
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return "HTTP $status - $($ErrorRecord.ErrorDetails.Message)"
    }
    if ($status -ne 0) { return "HTTP $status" }
    return "no HTTP response - $($ErrorRecord.Exception.Message)"
}

function Get-AppleBusinessDevice {
    <#
        Looks up one device by serial.

        The business.api scope can also release devices from the organization
        and change users, groups and device management assignments. So this is
        the only call to Apple in the whole app: a GET, to
        /v1/orgDevices/{serial}, with the method and path fixed in code.
        Anything else needs a deliberate code change.

        Returns Found, Status, Message and Device (the record's attributes).
    #>
    param(
        [Parameter(Mandatory)][string]$Serial,
        [Parameter(Mandatory)]$Config
    )

    $Serial = $Serial.Trim().ToUpperInvariant()
    if (-not (Test-SerialNumber $Serial)) {
        throw 'Serial number must be 1 to 32 letters and digits.'
    }

    $uri = "$($script:AppleApiBase)/v1/orgDevices/$([uri]::EscapeDataString($Serial))"

    $attempt = 0
    while ($true) {
        $attempt++
        $token = Get-AppleAccessToken -Config $Config -Force:($attempt -gt 1)
        try {
            $resp = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop `
                        -Headers @{ Authorization = "Bearer $token"; Accept = 'application/json' }
            break
        }
        catch {
            $status = Get-HttpStatus $_
            # A token can be revoked before its hour is up. Retry once with a
            # fresh one; a second 401 is real.
            if ($status -eq 401 -and $attempt -eq 1) { Clear-AppleAccessToken; continue }
            if ($status -eq 404) {
                return [pscustomobject]@{
                    Found = $false; Status = 404; Device = $null
                    Message = "Apple Business has no device with serial $Serial in this organization."
                }
            }
            throw "Apple device lookup failed: $(Get-FailureDetail $_)"
        }
    }

    $data  = Get-DataProperty $resp 'data'
    $attrs = Get-DataProperty $data 'attributes'
    if ($null -eq $attrs) {
        throw 'Apple device lookup returned no attributes.'
    }

    [pscustomobject]@{ Found = $true; Status = 200; Device = $attrs; Message = '' }
}


# ------------------------------------------------------------------
#  The certificate
# ------------------------------------------------------------------
function Test-CertificateInput {
    <#
        Checks what the technician chose. Returns a list of plain-English
        problems; an empty list means it is acceptable. Every dropdown value is
        checked against the options file - the form is never trusted to have
        offered only those.
    #>
    param(
        [Parameter(Mandatory)]$Options,
        [string]$WipeMethod,
        [string]$ComplianceStandard,
        [string]$WipeDate,
        [string]$Notes,
        [string]$AssetTag,
        [datetime]$Today = (Get-Date).Date
    )

    $errors = @()
    if ($Options.WipeMethod.Options -cnotcontains $WipeMethod) {
        $errors += 'Choose a wipe method from the list.'
    }
    if ($Options.ComplianceStandard.Options -cnotcontains $ComplianceStandard) {
        $errors += 'Choose a compliance standard from the list.'
    }

    $parsed = [datetime]::MinValue
    if (-not [datetime]::TryParseExact([string]$WipeDate, 'yyyy-MM-dd',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        $errors += 'Wipe date must be a date.'
    } elseif ($parsed.Date -gt $Today.Date) {
        $errors += 'Wipe date cannot be in the future.'
    }

    if ($null -ne $Notes -and $Notes.Length -gt $script:NotesMaxLength) {
        $errors += "Notes can be at most $($script:NotesMaxLength) characters."
    }
    if ($null -ne $AssetTag -and $AssetTag -cnotmatch $script:AssetTagPattern) {
        $errors += 'Asset tag can be up to 32 letters, digits, hyphens, underscores and slashes.'
    }
    ,$errors
}

function ConvertTo-CleanNotes {
    # Free text, kept to one paragraph per line: control characters other than
    # a newline go, Windows line endings become plain newlines.
    param([string]$Notes)
    if ($null -eq $Notes) { return '' }
    $t = $Notes.Replace("`r`n", "`n").Replace("`r", "`n")
    $t = $t -replace '[\x00-\x09\x0B-\x1F\x7F]', ''
    $t.Trim()
}

function New-CertificateData {
    <#
        Merges Apple's record with the technician's choices into the fourteen
        values the certificate shows. Device details come only from $Device,
        which the server re-fetched from Apple - never from the submitted form.

        Throws if the technician's input fails Test-CertificateInput.
    #>
    param(
        [Parameter(Mandatory)]$Device,
        [Parameter(Mandatory)]$Options,
        [Parameter(Mandatory)][string]$CertificateId,
        [Parameter(Mandatory)][string]$TechnicianName,
        [string]$TechnicianEmail,
        [Parameter(Mandatory)][string]$TechnicianAccount,
        [string]$WipeMethod,
        [string]$ComplianceStandard,
        [string]$WipeDate,
        [string]$Notes,
        [string]$AssetTag,
        [DateTimeOffset]$IssuedAt = [DateTimeOffset]::Now
    )

    if (-not (Test-CertificateId $CertificateId)) { throw "Not a certificate ID: $CertificateId" }

    $AssetTag = ([string]$AssetTag).Trim()
    $Notes    = ConvertTo-CleanNotes $Notes
    $problems = Test-CertificateInput -Options $Options -WipeMethod $WipeMethod `
                    -ComplianceStandard $ComplianceStandard -WipeDate $WipeDate `
                    -Notes $Notes -AssetTag $AssetTag -Today $IssuedAt.Date
    if (@($problems).Count -gt 0) { throw ($problems -join ' ') }

    $wipe = [datetime]::ParseExact($WipeDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $inv  = [Globalization.CultureInfo]::InvariantCulture

    [pscustomobject][ordered]@{
        DeviceType         = [string](Get-DataProperty $Device 'productFamily')
        Model              = [string](Get-DataProperty $Device 'deviceModel')
        SerialNumber       = [string](Get-DataProperty $Device 'serialNumber')
        AssetTag           = $AssetTag
        DeviceCapacity     = [string](Get-DataProperty $Device 'deviceCapacity')
        PartNumber         = [string](Get-DataProperty $Device 'partNumber')
        WipeMethod         = $WipeMethod
        WipeDate           = $wipe.ToString('d MMMM yyyy', $inv)
        ComplianceStandard = $ComplianceStandard
        Technician         = $TechnicianName
        TechnicianEmail    = [string]$TechnicianEmail
        Notes              = $Notes
        CertificateID      = $CertificateId
        DateIssued         = $IssuedAt.ToString('d MMMM yyyy, HH:mm', $inv) + ' (UTC' + $IssuedAt.ToString('zzz', $inv) + ')'

        # Not printed; kept for the register.
        TechnicianAccount  = $TechnicianAccount
        WipeDateIso        = $wipe.ToString('yyyy-MM-dd', $inv)
        IssuedAtIso        = $IssuedAt.ToString('o', $inv)
    }
}

function New-CertificateHtml {
    <#
        The printable certificate, laid out from the Word template
        (Apple_Device_Erasure_Certificate_Template.docx): US Letter, the same
        margins, colours, sizes and spacing, in Calibri.

        The page box is the whole sheet and @page has no margin, so the
        template's margins are padding inside it. With no page margin there is
        nowhere for the browser to put its own header and footer (title, URL,
        date, page number), so they never print whatever the dialog's
        "Headers and footers" box says.

        The toolbar - print button and back link - is screen-only. What reaches
        the paper, or the PDF, is the certificate and nothing else.

        The returned text is stored as issued and served back byte for byte, so
        it must not depend on anything but $Data.
    #>
    param(
        [Parameter(Mandatory)]$Data,
        [string]$HomeLink
    )

    function v([string]$s) {
        # Every value is escaped, Apple's included. Blank shows as a dash.
        if ([string]::IsNullOrWhiteSpace($s)) { return '&mdash;' }
        ConvertTo-HtmlText $s
    }

    function row([string]$label, [string]$value, [string]$cls) {
        $c = ''
        if ($cls) { $c = " class=`"$cls`"" }
        "        <tr><th>$label</th><td$c>$value</td></tr>"
    }

    $device = @(
        row 'Device Type'     (v $Data.DeviceType)
        row 'Model'           (v $Data.Model)
        row 'Serial Number'   (v $Data.SerialNumber)
        row 'Asset Tag'       (v $Data.AssetTag)
        row 'Device Capacity' (v $Data.DeviceCapacity)
        row 'Part Number'     (v $Data.PartNumber)
    ) -join "`n"

    $wipe = @(
        row 'Wipe Method'         (v $Data.WipeMethod)
        row 'Wipe Date'           (v $Data.WipeDate)
        row 'Compliance Standard' (v $Data.ComplianceStandard)
        row 'Technician'          (v $Data.Technician)
        row 'Technician Email'    (v $Data.TechnicianEmail)
        row 'Notes'               (v $Data.Notes) 'notes'
    ) -join "`n"

    $cert = @(
        row 'Certificate ID' (v $Data.CertificateID)
        row 'Date Issued'    (v $Data.DateIssued)
    ) -join "`n"

    # The print button is AppFilter's, handler for handler. Its inline onclick
    # is the one script the CSP allows, by the SHA-256 of 'window.print()'.
    # Change that text by so much as a space and the hash must be recomputed.
    $toolbar  = "  <div class=`"toolbar screen-only`">`n"
    $toolbar += "    <button class=`"action`" type=`"button`" onclick=`"window.print()`">Print</button>`n"
    $toolbar += "    <span class=`"hint`">or press Ctrl+P, then choose <b>Save as PDF</b> as the destination</span>`n"
    if ($HomeLink) {
        $toolbar += "    <a class=`"hint`" href=`"$(ConvertTo-HtmlText $HomeLink)`">&larr; look up another device</a>`n"
    }
    $toolbar += "  </div>`n"

    # The page title is what the browser offers as the PDF's file name.
    $title = "$($Data.CertificateID) Certificate of Data Erasure $($Data.SerialNumber)"

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>$(ConvertTo-HtmlText $title)</title>
<style>
  /* Measurements are the Word template's, converted from twips (1/20 pt).
     Page 12240 x 15840 = US Letter. Margins: top 1296 = 0.9in, left/right
     1008 = 0.7in, bottom 936 = 0.65in. Footer sits 720 = 0.5in from the
     bottom edge. */
  @page { size: letter portrait; margin: 0; }
  * { box-sizing: border-box; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { margin: 0; background: #e5e7eb; color: #374151;
         font-family: Calibri, Carlito, "Segoe UI", Arial, sans-serif; font-size: 10pt;
         /* Word's "Multiple 1.15" is 1.15 x the font's own line height, and
            Calibri's own line height is about 1.22em. */
         line-height: 1.4; }

  .toolbar { width: 8.5in; max-width: 100%; margin: 16px auto 10px; display: flex;
             gap: 12px; align-items: center; flex-wrap: wrap; padding: 0 4px;
             font-family: "Segoe UI", system-ui, Calibri, Arial, sans-serif; }
  .action { font: inherit; font-size: 14px; font-weight: 600; padding: 9px 22px;
            border: 0; background: #22254e; color: #fff; border-radius: 8px;
            cursor: pointer; }
  .action:hover { background: #1e293b; }
  .action:focus-visible { outline: 2px solid #0f172a; outline-offset: 2px; }
  .hint { font-size: 13px; color: #4b5563; }
  a.hint { color: #22254e; margin-left: auto; }

  .page { position: relative; width: 8.5in; height: 11in; margin: 0 auto 24px;
          padding: 0.9in 0.7in 0.65in; background: #fff; overflow: hidden;
          box-shadow: 0 1px 6px rgba(0,0,0,.2); }

  p { margin: 0; }
  .title    { text-align: center; color: #1F4E79; font-weight: bold; font-size: 23pt;
              line-height: 1.2; margin-bottom: 2pt; }
  .subtitle { text-align: center; color: #4B5563; font-weight: bold; font-size: 12pt;
              margin-bottom: 8pt; }

  table { border-collapse: collapse; margin: 0 auto; table-layout: fixed; }
  /* The introduction: one full-width cell, 10224 twips = 7.1in. Its
     paragraph keeps Word's default 10pt space after, inside the cell. */
  .intro { width: 7.1in; border: 1pt solid #B8C7D9; }
  .intro td { background: #F5F8FB; padding: 6.5pt 8pt 16.5pt; text-align: center;
              font-style: italic; font-size: 9.5pt; }

  h2 { color: #1F4E79; font-weight: bold; font-size: 10pt; margin: 10pt 0 4pt; }

  /* Label 2952 twips = 2.05in, value 7128 = 4.95in, centred on the page. */
  .grid { width: 7in; }
  .grid col.l { width: 2.05in; }
  .grid col.v { width: 4.95in; }
  .grid th, .grid td { border: 0.75pt solid #D1D5DB; padding: 4.5pt 5.5pt;
                       vertical-align: middle; text-align: left; }
  .grid th { background: #F3F6F9; font-weight: bold; font-size: 9pt; color: #374151; }
  .grid td { color: #1F4E79; font-size: 10pt; overflow-wrap: anywhere; }
  .grid td.notes { white-space: pre-wrap; }

  .closing { text-align: center; color: #6B7280; font-style: italic; font-size: 8pt;
             margin-top: 8pt; }
  .footer { position: absolute; left: 0.7in; right: 0.7in; bottom: 0.5in;
            text-align: center; color: #6B7280; font-weight: bold; font-size: 7.5pt;
            line-height: 1; }

  /* What reaches the paper: the sheet, nothing else. */
  @media print {
    body { background: #fff; }
    .page { margin: 0; box-shadow: none; break-after: avoid; page-break-after: avoid; }
    .screen-only { display: none !important; }
  }
</style>
</head>
<body>
$toolbar  <div class="page">
    <p class="title">CERTIFICATE OF DATA ERASURE</p>
    <p class="subtitle">Apple Device Wipe Verification</p>
    <table class="intro"><tr><td>This certificate confirms that the device identified below was processed for data erasure in accordance with the specified procedure and compliance standard.</td></tr></table>

    <h2>DEVICE INFORMATION</h2>
    <table class="grid">
      <colgroup><col class="l" /><col class="v" /></colgroup>
      <tbody>
$device
      </tbody>
    </table>

    <h2>WIPE DETAILS</h2>
    <table class="grid">
      <colgroup><col class="l" /><col class="v" /></colgroup>
      <tbody>
$wipe
      </tbody>
    </table>

    <h2>CERTIFICATE DETAILS</h2>
    <table class="grid">
      <colgroup><col class="l" /><col class="v" /></colgroup>
      <tbody>
$cert
      </tbody>
    </table>

    <p class="closing">This document serves as an official record of device data erasure. Retain for audit and compliance purposes.</p>
    <div class="footer">CONFIDENTIAL &bull; IT ASSET MANAGEMENT</div>
  </div>
</body>
</html>
"@
}


# ------------------------------------------------------------------
#  The technician: who they are, and whether they may use this
# ------------------------------------------------------------------
function Resolve-AllowedGroupSid {
    <#
        Turns DOMAIN\Group into its SID once, at startup. Fails if the group
        does not exist, so a typo stops the server instead of locking everyone
        out (or worse, nobody).
    #>
    param([Parameter(Mandatory)][string]$Group)
    $account = New-Object System.Security.Principal.NTAccount($Group)
    $account.Translate([System.Security.Principal.SecurityIdentifier])
}

function Test-AllowedUser {
    <#
        Group membership from the caller's Windows token - no AD query. The
        token is built at sign-in, so someone just added to the group gets in
        after they next sign in to Windows.
    #>
    param($Principal, [Parameter(Mandatory)][System.Security.Principal.SecurityIdentifier]$GroupSid)
    if ($null -eq $Principal) { return $false }
    if ($Principal -isnot [System.Security.Principal.WindowsPrincipal]) { return $false }
    if (-not $Principal.Identity.IsAuthenticated) { return $false }
    return $Principal.IsInRole($GroupSid)
}

function Get-TechnicianIdentity {
    <#
        Display name and email for the signed-in account, from Active
        Directory by SID. Falls back to DOMAIN\user and a blank email when AD
        cannot be read, and says so in .Source - a certificate is still issued.
    #>
    param([Parameter(Mandatory)]$Principal)

    $account = [string]$Principal.Identity.Name
    $sid     = $null
    try { $sid = $Principal.Identity.User.Value } catch { }

    $result = [pscustomobject]@{
        Account = $account; Sid = $sid; DisplayName = $account; Email = ''; Source = 'account name only'
    }
    if (-not $sid) { return $result }

    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://<SID=$sid>")
        $name  = [string]($entry.Properties['displayName'].Value)
        $mail  = [string]($entry.Properties['mail'].Value)
        if ($name) { $result.DisplayName = $name.Trim() }
        if ($mail) { $result.Email = $mail.Trim() }
        $result.Source = 'Active Directory'
        $entry.Dispose()
    }
    catch {
        $result.Source = "account name only (AD lookup failed: $($_.Exception.Message))"
    }
    $result
}


Export-ModuleMember -Function @(
    'ConvertTo-HtmlText', 'Get-DataProperty', 'Test-SerialNumber', 'Test-CertificateId',
    'Get-AppleCertSecurityHeader', 'Test-RequestOrigin',
    'Import-AppleCertConfig', 'Import-CertificateOption',
    'Import-EcPrivateKey', 'New-AppleClientAssertion',
    'Get-AppleAccessToken', 'Clear-AppleAccessToken', 'Get-AppleTokenState',
    'Get-AppleBusinessDevice',
    'Test-CertificateInput', 'New-CertificateData', 'New-CertificateHtml',
    'Resolve-AllowedGroupSid', 'Test-AllowedUser', 'Get-TechnicianIdentity'
)
