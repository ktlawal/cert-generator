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
| 2. Prove the runtime on the lab machine | **Mostly done (2 Oct 2026)**: tests pass under 5.1; listener, silent sign-in and the Origin check proven as SYSTEM. Still to run: 2c (Apple lookup, released device) |
| 3. Certificate HTML matching the Word template | **Built, awaiting approval** after a Print → Save as PDF in Edge |
| 4. Pages (serial form, device page, certificate routes) | Not started (waits on 2 and 3) |
| 5. Register and the rest of the tests | Not started |
| 6. Deploy (URL reservation, scheduled task) | Not started |

## Decisions

| | Decision |
|---|---|
| PowerShell | **Windows PowerShell 5.1** (`powershell.exe`), as AppFilter. PowerShell 7 is not installed on the lab machine, and the agreed rule was to use it only if it already was. The module still runs under both: its key loader parses the PEM by hand into `ECParameters` and needs neither `ImportFromPem` nor `DSASignatureFormat`, so moving to 7 later is a change to the scheduled task, not to the code. |
| Asset tag | Typed by the technician, **optional**, `^[A-Za-z0-9\-_/]{0,32}$`. Blank prints "—". |
| Technician | Certificate shows the AD **`displayName`**. The email is AD **`mail`**, looked up by SID through LDAP (no RSAT). If AD cannot be read, the account name is used, the email is blank ("—"), and it is logged; the certificate is still issued. The register also keeps `DOMAIN\user` and the SID. |
| Certificate ID | **`AC-YYYY-NNNNNN`**: a sequence number that restarts each year, e.g. `AC-2026-000042`. Checked against `^AC-\d{4}-\d{6}\z` before any file name is built from it. |
| Register | `C:\ProgramData\AppleCert\` (readable only by SYSTEM and Administrators): `register.csv` plus `Certificates\<ID>.html` as issued, served back byte for byte so the SHA-256 in the register stays checkable. Kept indefinitely; nothing deletes them. |
| Who can use it | One AD group, set as `AllowedGroup` in the config, resolved to a SID at startup (a typo stops the server). Checked from the caller's Windows token on every route except `/health`, for viewing stored certificates as well as issuing them. Refusals are logged. **For now: `DOMAIN\Domain Users`** (every domain account), by decision; narrowing it later is a config edit and a task restart. |
| Network | Domain firewall profile only (the existing TCP 5000 rule). |
| Referrer-Policy | **`same-origin`** for this app, not AppFilter's `no-referrer`. Under `no-referrer` a browser sends `Origin: null` on a form POST — confirmed with Chromium — which the Origin check below would refuse every time. `same-origin` still sends nothing to other sites. |
| Origin check | On `POST /applecert/certificate`: accept **only** an exact match to `PublicOrigin` from the config. `null`, a missing Origin, `http://`, another port, the short name — all refused (403). |
| Page | **US Letter**, as the Word template. Columns 2.05" / 4.95", from the template's cell widths (its grid says 50/50, but Word lays out by the cell widths). |
| Other limits | Notes at most 500 characters (keeps the certificate on one page). Wipe date cannot be in the future. Devices are always re-fetched from Apple on the POST; nothing about the device is taken from the form. |
| Existing certificates | The device page lists every certificate already issued for that serial, newest first: ID (linking to `GET /applecert/certificate?id=…`), date issued, wipe method, wipe date and technician, read from the register. It warns but does not block: a technician can still issue a new one, for example when a device is wiped again. The list is read on the server and every value is HTML-escaped. |

## Files

| File | What it is |
|---|---|
| `AppleCert.psm1` | The module. No credentials. Apple sign-in and the one lookup, input checks, the certificate page, the Origin and group checks, the AD lookup, the security headers. |
| `CertificateOptions.json` | The dropdown choices and their defaults. A new wipe method is an edit here. |
| `config.example.json` | The shape of the real config, which lives at `C:\ProgramData\AppleCert\config.json` and never in the repo. |
| `Test-AppleCert.ps1` | Offline tests (117 checks). Runs under 5.1 and 7. |
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

**Install path: `C:\Solutions\AppleCertGenerator`** — its own folder, beside
AppFilter's `C:\Solutions\ApplicationList`, not inside it. The key, config and
(later) issued certificates live in `C:\ProgramData\AppleCert`, so copying in
new code never touches them.

The code folder keeps its inherited permissions: only administrators can sign
in to the lab machine, and they could change any permission anyway (the same
reasoning as AppFilter's H-2). Revisit that if anyone else is ever allowed to
sign in.

### Before you start

You need these to hand. None of them is created by the scripts.

- **The AD group** that will be allowed to use the app, e.g.
  `DOMAIN\AppleCert-Users`, with you in it. Group membership is read from your
  Windows sign-in, so if you were just added, sign out and back in to your PC
  first.
- **The Apple Business API account**: client ID, key ID and the private key
  `.pem`, ideally on a custom role that can only view devices.
- **The lab machine's full name**, `<lab-machine>.<domain>`: the one in
  AppFilter's URL.

### 2a. Copy the files, key and config (on the lab machine, elevated)

```powershell
# 1. The code: copy the repo's files into the folder, then unblock them.
#    Files from GitHub or a zip are marked as downloaded, and Windows refuses
#    to run them by hand until they are unblocked.
Get-ChildItem C:\Solutions\AppleCertGenerator -Recurse | Unblock-File

# 2. The data folder: only SYSTEM and Administrators can read it
#    (SIDs, so it works in any Windows language).
New-Item -ItemType Directory -Path C:\ProgramData\AppleCert -Force
icacls C:\ProgramData\AppleCert /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"

# 3. The key: copy the Apple .pem in as
#    C:\ProgramData\AppleCert\apple-business-key.pem
#    and delete any other copy you made on the way (Downloads, desktop, USB).

# 4. The config: start from the example and fill in the real values.
Copy-Item C:\Solutions\AppleCertGenerator\config.example.json C:\ProgramData\AppleCert\config.json
notepad C:\ProgramData\AppleCert\config.json
```

In `config.json`: `ClientId`, `KeyId`, `PublicOrigin` as
`https://<lab-machine>.<domain>:5000` (the full name, no trailing slash),
`AllowedGroup` as `DOMAIN\GroupName`. Leave `PrivateKeyPath` and `DataPath` as
they are. Backslashes in JSON are doubled: `"DOMAIN\\AppleCert-Users"`.

### 2b. Offline tests

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Solutions\AppleCertGenerator\Test-AppleCert.ps1
```

It should end `All cases passed.` **Done on the lab machine: all passed under
5.1.26100**, key loading and ES256 signing included.

### 2c. Apple lookup through the module (elevated)

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Solutions\AppleCertGenerator\Test-AppleLookup.ps1 -Serial <serial>
```

Then once with the serial of a device **already released** from Apple
Business. Exit code 2 / "Not found" means released devices are not returned, so
the certificate must be issued **before** a device is released; a record with
`releasedFromOrgDateTime` set means they are. Record which one here.

### 2d. Listener, Windows sign-in, group, AD, Origin — as SYSTEM

Reserve the app's URL for SYSTEM (this is the real reservation; it stays). The
TLS certificate on port 5000 is AppFilter's and is shared automatically:

```
netsh http add urlacl url=https://+:5000/applecert/ user="NT AUTHORITY\SYSTEM"
```

Run the probe as a **one-off** scheduled task as SYSTEM, capturing its output
from the first run. `*>` only works inside `-Command`, not after `-File`.
Replace the origin and group with your own:

```powershell
$probe = 'C:\Solutions\AppleCertGenerator\Test-RuntimeProbe.ps1'
$out   = 'C:\Solutions\AppleCertGenerator\probe-task-output.log'
$taskArgs = "-NoProfile -ExecutionPolicy Bypass -Command `"& '$probe' -Serve " +
            "-PublicOrigin 'https://<lab-machine>.<domain>:5000' -AllowedGroup 'DOMAIN\AppleCert-Users' " +
            "-Minutes 30 *> '$out'`""
Register-ScheduledTask -TaskName 'AppleCert runtime probe' -User 'NT AUTHORITY\SYSTEM' -RunLevel Highest `
    -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArgs) -Force
Start-ScheduledTask -TaskName 'AppleCert runtime probe'
```

Check it started: `C:\Solutions\AppleCertGenerator\RuntimeProbe.log` should
have a `PROBE STARTED` line naming `PowerShell 5.1…` and `NT AUTHORITY\SYSTEM`.
If not, `probe-task-output.log` says why.

Then, from a technician PC (not the lab machine):

1. Open `https://<lab-machine>.<domain>:5000/applecert/` in **Edge**. Expect no
   sign-in prompt, your account, "In allowed group: yes", your AD display name
   and mail, and the runtime `PowerShell 5.1…`.
2. Press **Send a form POST**. Expect **ACCEPTED**, with the Origin shown as
   `https://<lab-machine>.<domain>:5000`.
3. Copy `Test-RuntimeProbe.ps1` and `AppleCert.psm1` to a folder on that PC,
   unblock them, and run:
   `.\Test-RuntimeProbe.ps1 -Check -Url https://<lab-machine>.<domain>:5000/applecert/`
   Expect PASS on all: the correct Origin 200; `Origin: null`, no Origin, a
   foreign Origin and the same host over http all 403.
4. Once `AllowedGroup` is narrowed from `Domain Users`: ask someone **not** in the
   group to open the page, and expect "In allowed group: NO".

The probe
stops itself after 30 minutes; delete the task afterwards:
`Unregister-ScheduledTask -TaskName 'AppleCert runtime probe' -Confirm:$false`.

**Send back:** the output of 2c, the released-device
result, `RuntimeProbe.log`, and what the Edge page and `-Check` showed.

## Step 3 — approve the certificate

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Solutions\AppleCertGenerator\New-SampleCertificate.ps1 -OutputFolder $env:USERPROFILE\Desktop
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
| Key loader + ES256 signing produce valid assertions | Keys made by OpenSSL (PKCS#8, SEC1, PKCS#8 without the public part); every assertion verified independently with Python `cryptography`. P-384 refused. Under PowerShell 7 here, and the full test suite passed under Windows PowerShell 5.1 on the lab machine. |
| Strict Origin check | Probe run locally over http: correct Origin 200; `null`, missing and foreign 403. A real Chromium form POST from the page is accepted. |
| `no-referrer` would break the check | Same probe with `no-referrer`: Chromium sent `Origin: null` and was refused. |
| Certificate fits one Letter page, worst case included | Rendered in Chromium with Carlito (metrically identical to Calibri): 1 page each. |
| Escaping | Apple data, technician name, notes, asset tag — tested with markup and quotes. |
| Runtime: Windows PowerShell 5.1, as SYSTEM | Lab machine, 2 Oct 2026: `Test-AppleCert.ps1` all passed under 5.1.26100; the probe started under the scheduled task as `NT AUTHORITY\SYSTEM` with IntegratedWindowsAuthentication on `https://+:5000/applecert/`, beside AppFilter on the shared port and certificate. |
| Silent Windows sign-in | Edge on a technician PC loaded the probe page with no prompt. `-Check` from PowerShell 7.6 with default credentials got 200. |
| Strict Origin check, live | Edge's real form POST: ACCEPTED. `-Check`: correct Origin 200; `null`, missing, foreign and same-host-over-http all 403. |
| `Domain Users` resolves as `AllowedGroup` | Probe resolved it to the domain SID ending `-513`. |

**Not verified yet:** the AD display name and mail lookup, the Apple API itself
(2c), whether released devices are returned, and Edge's print dialog (step 3).
