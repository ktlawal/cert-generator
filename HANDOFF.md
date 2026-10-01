# Apple device erasure certificate — handoff

An internal web app on the lab machine, beside AppFilter: look an Apple device
up in Apple Business by serial, record the technician's wipe details, and issue
a numbered certificate the technician saves with the browser's own
**Print → Save as PDF**. No Word, and no PDF generation on the server.

```
Apple Business lookup -> certificate data (Apple + technician) -> certificate HTML -> browser Print -> Save as PDF
```

## Where the build is

| Step | State |
|---|---|
| 1. Decisions | **Agreed**, below |
| 2. Prove the runtime on the lab machine | **Scripts ready, not yet run there**: `Test-RuntimeProbe.ps1`, `Test-AppleLookup.ps1` |
| 3. Certificate HTML matching the Word template | **Built, awaiting approval** after a Print → Save as PDF in Edge |
| 4. Pages (serial form, device page, certificate routes) | Not started (waits on 2 and 3) |
| 5. Register and the rest of the tests | Not started |
| 6. Deploy (URL reservation, scheduled task) | Not started |

## Decisions

| | Decision |
|---|---|
| PowerShell | The module runs under **both** Windows PowerShell 5.1 and PowerShell 7: its key loader parses the PEM by hand into `ECParameters`, and needs neither `ImportFromPem` nor `DSASignatureFormat`. The runtime probe decides which one the scheduled task starts. Preferred: `pwsh.exe`, if it is installed and the probe passes under it. |
| Asset tag | Typed by the technician, **optional**, `^[A-Za-z0-9\-_/]{0,32}$`. Blank prints "—". |
| Technician | Certificate shows the AD **`displayName`**. The email is AD **`mail`**, looked up by SID through LDAP (no RSAT). If AD cannot be read, the account name is used, the email is blank ("—"), and it is logged; the certificate is still issued. The register also keeps `DOMAIN\user` and the SID. |
| Certificate ID | **`AC-YYYY-NNNNNN`**: a sequence number that restarts each year, e.g. `AC-2026-000042`. Checked against `^AC-\d{4}-\d{6}\z` before any file name is built from it. |
| Register | `C:\ProgramData\AppleCert\` (readable only by SYSTEM and Administrators): `register.csv` plus `Certificates\<ID>.html` as issued, served back byte for byte so the SHA-256 in the register stays checkable. Kept indefinitely; nothing deletes them. |
| Who can use it | One AD group, set as `AllowedGroup` in the config, resolved to a SID at startup (a typo stops the server). Checked from the caller's Windows token on every route except `/health`, for viewing stored certificates as well as issuing them. Refusals are logged. |
| Network | Domain firewall profile only (the existing TCP 5000 rule). |
| Referrer-Policy | **`same-origin`** for this app, not AppFilter's `no-referrer`. Under `no-referrer` a browser sends `Origin: null` on a form POST — confirmed with Chromium — which the Origin check below would refuse every time. `same-origin` still sends nothing to other sites. |
| Origin check | On `POST /applecert/certificate`: accept **only** an exact match to `PublicOrigin` from the config. `null`, a missing Origin, `http://`, another port, the short name — all refused (403). |
| Page | **US Letter**, as the Word template. Columns 2.05" / 4.95", from the template's cell widths (its grid says 50/50, but Word lays out by the cell widths). |
| Other limits | Notes at most 500 characters (keeps the certificate on one page). Wipe date cannot be in the future. Devices are always re-fetched from Apple on the POST; nothing about the device is taken from the form. |

## Files

| File | What it is |
|---|---|
| `AppleCert.psm1` | The module. No credentials. Apple sign-in and the one lookup, input checks, the certificate page, the Origin and group checks, the AD lookup, the security headers. |
| `CertificateOptions.json` | The dropdown choices and their defaults. A new wipe method is an edit here. |
| `config.example.json` | The shape of the real config, which lives at `C:\ProgramData\AppleCert\config.json` and never in the repo. |
| `Test-AppleCert.ps1` | Offline tests: 113 checks. Run under both runtimes. |
| `Test-RuntimeProbe.ps1` | Step 2: listener + Windows sign-in + group + AD + Origin check, on the lab machine. |
| `Test-AppleLookup.ps1` | Step 2: the Apple lookup through the module, with the real config and key. Also the released-device test. |
| `New-SampleCertificate.ps1` | Step 3: writes two sample certificates (typical, and worst case) with invented data. |

## Apple Business: what the code does and does not do

- Token: an ES256 client assertion (`kid` = key ID, `iss` = `sub` = client ID,
  `aud` = `https://account.apple.com/auth/oauth2/v2/token`, `iat`, `exp` five
  minutes later, a fresh `jti`), posted to
  `https://account.apple.com/auth/oauth2/token` with `scope=business.api`.
  The token is held in memory only and reused until a minute before it expires;
  each new token gets a freshly signed assertion.
- Lookup: `GET https://api-business.apple.com/v1/orgDevices/{serial}`, and
  nothing else. `business.api` can also release devices and change users and
  groups, so the module makes exactly two web requests — that token POST and
  this GET — and `Test-AppleCert.ps1` fails if a third appears or the method
  changes. A 401 is retried once with a new token; a 404 is "not found".
- Never printed or logged: the key, the assertion, the token. Diagnostics show
  lengths only.
- The serial is checked (`^[A-Za-z0-9]{1,32}\z`) before any token or URL.
- Your original script printed `attributes.assignedServer`; it is a
  relationship, not an attribute, and the app does not use it.

**A trap fixed on the way:** in .NET a regex `$` also matches before a trailing
newline, so `"AC-2026-000042\n"` passed a `$`-anchored check. Every pattern
here ends in `\z`. The tests cover it.

## Step 2 — prove the runtime on the lab machine

Copy the repo to `<install-path>` on the lab machine.

### 2a. Key and config

```powershell
# Folder only SYSTEM and Administrators can read (SIDs, so it works in any language)
New-Item -ItemType Directory -Path C:\ProgramData\AppleCert -Force
icacls C:\ProgramData\AppleCert /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"

# Then put the Apple key in it as apple-business-key.pem, and copy
# config.example.json to C:\ProgramData\AppleCert\config.json and fill it in.
```

### 2b. Offline tests, under both runtimes

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File <install-path>\Test-AppleCert.ps1
pwsh.exe       -NoProfile -ExecutionPolicy Bypass -File <install-path>\Test-AppleCert.ps1
```

Both should end `All cases passed.` The key-loading checks are the ones that
matter most under 5.1.

### 2c. Apple lookup through the module (elevated)

```powershell
pwsh.exe       -NoProfile -File <install-path>\Test-AppleLookup.ps1 -Serial <serial>
powershell.exe -NoProfile -File <install-path>\Test-AppleLookup.ps1 -Serial <serial>
```

Then once with the serial of a device **already released** from Apple
Business. Exit code 2 / "Not found" means released devices are not returned, so
the certificate must be issued **before** a device is released; a record with
`releasedFromOrgDateTime` set means they are. Record which one here.

### 2d. Listener, Windows sign-in, group, AD, Origin — as SYSTEM

Reserve the app's URL for SYSTEM (this is the real reservation; it stays):

```
netsh http add urlacl url=https://+:5000/applecert/ user="NT AUTHORITY\SYSTEM"
```

Run the probe as a **one-off** scheduled task as SYSTEM, capturing its output
from the first run. `*>` only works inside `-Command`, not after `-File`:

```powershell
$probe = '<install-path>\Test-RuntimeProbe.ps1'
$out   = '<install-path>\probe-task-output.log'
$taskArgs = "-NoProfile -ExecutionPolicy Bypass -Command `"& '$probe' -Serve " +
            "-PublicOrigin 'https://<lab-machine>.<domain>:5000' -AllowedGroup 'DOMAIN\AppleCert-Users' " +
            "-Minutes 30 *> '$out'`""
Register-ScheduledTask -TaskName 'AppleCert runtime probe' -User 'NT AUTHORITY\SYSTEM' -RunLevel Highest `
    -Action (New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument $taskArgs) -Force
Start-ScheduledTask -TaskName 'AppleCert runtime probe'
```

Then, from a technician PC (not the lab machine):

1. Open `https://<lab-machine>.<domain>:5000/applecert/` in **Edge**. Expect no
   sign-in prompt, your account, "In allowed group: yes", your AD display name
   and mail, and the runtime `PowerShell 7…`.
2. Press **Send a form POST**. Expect **ACCEPTED**, with the Origin shown as
   `https://<lab-machine>.<domain>:5000`.
3. In PowerShell:
   `.\Test-RuntimeProbe.ps1 -Check -Url https://<lab-machine>.<domain>:5000/applecert/`
   Expect PASS on all: the correct Origin 200; `Origin: null`, no Origin, a
   foreign Origin and the same host over http all 403.
4. Ask someone **not** in the group to open the page: "In allowed group: NO".

Repeat with `-Execute 'powershell.exe'` if pwsh fails, or to confirm the 5.1
fallback. The probe stops itself after 30 minutes; delete the task afterwards:
`Unregister-ScheduledTask -TaskName 'AppleCert runtime probe' -Confirm:$false`.
The probe log is `<install-path>\RuntimeProbe.log`.

## Step 3 — approve the certificate

```powershell
.\New-SampleCertificate.ps1 -OutputFolder $env:USERPROFILE\Desktop
```

Open each file in **Edge**, press **Print**, choose **Save as PDF**, and check:

- one page, US Letter
- no browser header or footer (title, URL, date, page number), **with
  "Headers and footers" left ticked**. The certificate sets `@page { margin: 0 }`
  and draws the template's margins itself, so the browser has no margin to
  print into. Headless Chromium's PDF engine still draws them, so this cannot
  be proven from a container: it has to be checked in Edge and Chrome. If they
  do appear, the fallback is telling technicians to untick the box.
- colours and the shaded label cells survive ("Background graphics" is forced
  on by the page)
- the PDF's suggested file name is `AC-…-000042 Certificate of Data Erasure C02TEST0SN01`

## Verified so far, and how

| Claim | How |
|---|---|
| Key loader + ES256 signing produce valid assertions | Keys made by OpenSSL (PKCS#8, SEC1, PKCS#8 without the public part); every assertion verified independently with Python `cryptography`. P-384 refused. Under PowerShell 7. **5.1: run `Test-AppleCert.ps1` on Windows.** |
| Strict Origin check | Probe run locally over http: correct Origin 200; `null`, missing and foreign 403. A real Chromium form POST from the page is accepted. |
| `no-referrer` would break the check | Same probe with `no-referrer`: Chromium sent `Origin: null` and was refused. |
| Certificate fits one Letter page, worst case included | Rendered in Chromium with Carlito (metrically identical to Calibri): 1 page each. |
| Escaping | Apple data, technician name, notes, asset tag — tested with markup and quotes. |

**Not verified yet:** anything needing the lab machine — http.sys, Kerberos,
the group check, AD, the Apple API itself, Edge's print dialog.
