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
| 2. Prove the runtime on the lab machine | **Done (2 Oct–6 Oct 2026)**: tests pass under 5.1; listener, silent sign-in, group, AD and the Origin check proven as SYSTEM; the Apple lookup works through the module under 5.1. Released devices are **not reliably** returned: certify before release |
| 3. Certificate HTML matching the Word template | **Approved (2 Oct 2026)**: one Letter page each, no browser header or footer with the box ticked, colours kept, file name from the title — checked in Edge |
| 4. Pages (serial form, device page, certificate routes) | **Built**: `Start-AppleCertServer.ps1`. Tested end to end in a browser here with stand-ins for Apple, AD and the group; **not yet run on the lab machine** |
| 5. Register and the rest of the tests | **Built**: register in the module, 149 offline checks |
| 6. Deploy (URL reservation, scheduled task) | URL reserved during step 2. Startup task: commands below, **not yet run** |

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
| Other limits | Notes at most 500 characters (keeps the certificate on one page). Wipe date cannot be in the future, nor more than 180 days back. Devices are always re-fetched from Apple on the POST; nothing about the device is taken from the form. |
| Existing certificates | The device page lists every certificate already issued for that serial, newest first: ID (linking to `GET /applecert/certificate?id=…`), date issued, wipe method, wipe date and technician, read from the register. It warns but does not block: a technician can still issue a new one, for example when a device is wiped again. The list is read on the server and every value is HTML-escaped. |

## Files

| File | What it is |
|---|---|
| `AppleCert.psm1` | The module. No credentials. Apple sign-in and the one lookup, input checks, the certificate page, the Origin and group checks, the AD lookup, the security headers. |
| `CertificateOptions.json` | The dropdown choices and their defaults. A new wipe method is an edit here. |
| `config.example.json` | The shape of the real config, which lives at `C:\ProgramData\AppleCert\config.json` and never in the repo. |
| `Start-AppleCertServer.ps1` | The server: listener, routes, sign-in, group check, Origin check, logging. Reads the config at startup. |
| `Test-AppleCert.ps1` | Offline tests (149 checks), register included. Runs under 5.1 and 7. |
| `Test-RuntimeProbe.ps1` | Step 2: listener + Windows sign-in + group + AD + Origin check, on the lab machine. |
| `Test-AppleLookup.ps1` | Step 2: the Apple lookup through the module, with the real config and key. Also the released-device test. |
| `New-SampleCertificate.ps1` | Step 3: writes two sample certificates (typical, and worst case) with invented data. |
| `Apple-Certificate-Quick-Reference.docx` | One-page quick reference for technicians, in the style of AppFilter's: the app link, the four routes, how to issue a certificate, and what is worth knowing. The repo copy has `<lab-machine>.<domain>` in the link; the handout with the real address is kept out of the repo. |
| `tools/build-quick-reference.js` | Rebuilds the quick reference (Node and the `docx` npm package, not needed on the lab machine). Pass the link and the output file. |

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
`releasedFromOrgDateTime` set means they are.

**Result (6 Oct 2026): released devices are NOT reliably returned.** Two
released devices behaved differently:

- One, released in August 2026, came back with `releasedFromOrgDateTime` set
  and `status` `DEVICE_ASSIGNMENT_UNKNOWN`, every certificate field present.
- Another, confirmed as released in the Apple Business portal, returned
  **404 — not found**, both from `Test-AppleLookup.ps1` and from the app.

Apple's documentation does not say how long, or whether, a released device
stays visible to the API. So the working rule is: **issue the certificate
before the device is released from Apple Business.** A released device that
the API still returns can be certified; one it no longer returns cannot, and
the app says "no device with that serial".

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

## The app — routes, pages and register

| Route | What it does |
|---|---|
| `GET /applecert/` | Serial form, AppFilter's split page. Shows who you are signed in as. |
| `GET /applecert/device?serial=X` | Apple's record, read-only. **Any certificates already issued for the serial, newest first, linked** — a warning, not a block. The form: wipe method, compliance standard (from `CertificateOptions.json`), wipe date (today, no future dates), asset tag, notes (500 max). |
| `POST /applecert/certificate` | Origin must match `PublicOrigin` exactly (403 otherwise). Body over 16 KB refused (413). **Device fetched from Apple again**; nothing about the device is taken from the form. Every choice checked against the options file; a refusal shows the device page again with the problems listed and the entries kept. Then: next number, page stored, register row, **303** to the GET below — so a refresh or Back never issues a second certificate. |
| `GET /applecert/certificate?id=X` | The stored page, byte for byte. The ID is checked against `^AC-\d{4}-\d{6}\z` before any path is built. |
| `GET /applecert/health` | `OK`. The only route without the group check. |

Every other route, **viewing stored certificates included**, needs `AllowedGroup`;
refusals are logged. Errors show a generic page; the detail goes to the log.

**Register**, in `C:\ProgramData\AppleCert`:

- `Certificates\AC-2026-000042.html` — each page as issued. Never overwritten:
  a file already at the next number is skipped.
- `register.csv` — one row per certificate: ID, time issued (ISO, with offset),
  serial, device type, model, asset tag, capacity, part number, wipe method,
  wipe date, standard, technician name, email, `DOMAIN\user`, SID, notes, and
  the **SHA-256 of the stored page**. Values starting `= + - @` get a leading
  apostrophe so Excel does not run them; the app strips it on reading.
- `AppleCertServer.log` — every request and refusal, and `ISSUED` lines with
  the ID, choices and hash. Rotates at 5 MB.

Numbers come from the highest already used that year, in the files or the
register, plus one; they restart each January.

**Testing before go-live (decided: no test mode):** test certificates are real
register entries. Before real use, stop the task and delete `register.csv` and
the `Certificates` folder (and `AppleCertServer.log`, if you want a clean log),
so numbering starts again at `000001`:

```powershell
Stop-ScheduledTask -TaskName 'AppleCert server'
Remove-Item C:\ProgramData\AppleCert\register.csv, C:\ProgramData\AppleCert\Certificates -Recurse
Start-ScheduledTask -TaskName 'AppleCert server'
```

## Step 4 — run the app on the lab machine

Needs 2c done first: the real `ClientId`, `KeyId` and key in
`C:\ProgramData\AppleCert`. The server checks the config, the group and the key
before it opens the port, and refuses to start if any is wrong.

```powershell
# 1. The probe and the app share the URL: remove the probe task.
Unregister-ScheduledTask -TaskName 'AppleCert runtime probe' -Confirm:$false

# 2. The startup task: at boot, as SYSTEM, no time limit, restarts on failure,
#    output captured from the first run.
$script = 'C:\Solutions\AppleCertGenerator\Start-AppleCertServer.ps1'
$out    = 'C:\Solutions\AppleCertGenerator\task-output.log'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"& '$script' *> '$out'; exit `$LASTEXITCODE`""
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName 'AppleCert server' -Action $action -Settings $settings `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) -User 'NT AUTHORITY\SYSTEM' -RunLevel Highest -Force
Start-ScheduledTask -TaskName 'AppleCert server'

# 3. Check it started.
Start-Sleep -Seconds 5
(Get-ScheduledTask -TaskName 'AppleCert server').State          # Running
Get-Content C:\ProgramData\AppleCert\AppleCertServer.log -Tail 3  # STARTED ...
```

If it is not running, `task-output.log` and the last lines of
`AppleCertServer.log` say why (`FAILED TO START` with the reason).

Then, from a technician PC, at `https://<lab-machine>.<domain>:5000/applecert/`:

1. Look up a real serial. The device page shows Apple's details and "No
   certificates have been issued for this device yet."
2. Generate a certificate. The address changes to `…/certificate?id=AC-2026-000001`.
   Press F5: the same certificate, not a new number.
3. Print → Save as PDF, as in step 3.
4. Go back to the device page: it now warns about `AC-2026-000001` and links to it.
5. On the lab machine: the file in `Certificates`, the row in `register.csv`,
   and the `ISSUED` line in the log.

**After changing the config or the code:** `Stop-ScheduledTask` then
`Start-ScheduledTask` — the server reads both only at startup.

## Security audit, 7 Oct 2026

A full read of `AppleCert.psm1` and `Start-AppleCertServer.ps1`, a search of
the whole git history, and live probing of a copy of the server with
stand-ins for Apple, AD and the group check. Nothing was changed by the audit
itself; fixes wait on a decision, finding by finding.

| | Finding | State |
|---|---|---|
| M-1 | **One slow request stalls the app for everyone.** The server handles one request at a time and sets no timeouts. A POST that announces a body and then sends it slowly held the server for 23 s in testing; on Windows http.sys waits about 2 minutes by default, and it can be repeated. Calls to Apple have no timeout either (100 s default). Any domain account can do it while `AllowedGroup` is Domain Users. | **Fixed (8 Oct).** The whole form must arrive within 10 s (`Read-LimitedBody`), else 408; http.sys's own body timeout set to match; both Apple calls give up after 20 s. Re-tested: a client dribbling a byte a second is cut off at 10 s (was unlimited). |
| M-2 | **Every request line is also written to `task-output.log` in the code folder.** `Write-RequestLog` echoes to the console, and the startup task captures the console with `*>`. That file never rotates, so it grows for as long as the server runs, and it sits outside the locked `C:\ProgramData\AppleCert`. | **Fixed (8 Oct).** Request lines go to the console only in an interactive session; start, stop and failure lines still reach `task-output.log`. **Check on site:** after a restart, `task-output.log` stops growing with each request. |
| M-3 | **Any domain account can use the app.** `AllowedGroup` is Domain Users by decision, so anyone in the domain can issue a certificate in their own name and open any stored certificate (device details, technician name and email). Every action is logged against the account. | **Pending** (decision, 8 Oct). Domain Users for now; narrow `AllowedGroup` before wider use. |
| M-4 | **The API key is more powerful than the app.** The code can only make a GET to `/v1/orgDevices/{serial}` (and a test enforces it), but `business.api` itself can release devices and change users and groups. A stolen key is only as limited as the API account's role. | **Pending** (to verify on site, 8 Oct): view-only API role; one copy of the key; `icacls C:\ProgramData\AppleCert` shows only SYSTEM and Administrators. |
| L-1 | **No lower limit on the wipe date.** `1900-01-01` was accepted; future dates are refused. | **Fixed (8 Oct).** At most **180 days** back, checked on the server; the date picker stops there too. Re-tested: 180 days accepted, 181 and 1900 refused. |
| L-2 | **Invisible text-direction characters in notes survive onto the certificate.** A right-to-left override can make printed notes read differently from what is stored. Only the technician's own notes; low impact. | **Fixed (8 Oct).** Direction and zero-width characters are stripped from notes. Re-tested: an override in the notes does not reach the certificate. |
| L-3 | **No `Cache-Control: no-store`.** Device pages and certificates can stay in a browser's cache on a shared PC. | **Fixed (8 Oct).** `Cache-Control: no-store` on every response. |
| L-4 | **An oversized chunked body gives a generic 500**, logged as ERROR, instead of a clean 413. Nothing is issued. | **Fixed (8 Oct).** Too large however sent: 413, logged as a refusal. Re-tested with a 20 KB chunked body. |
| L-5 | **The register is not tamper-proof against administrators, and has no backup.** The SHA-256 detects accidental change, not an administrator editing both the page and the row. Everything is on one disk. | **Open.** Suggested: a scheduled copy of `register.csv` and `Certificates` to a share the lab machine's administrators cannot alter. |
| L-6 | **NTLM fallback without Extended Protection.** Kerberos is what browsers use here, but NTLM is still offered; without channel binding, a relayed NTLM sign-in could issue a certificate in a victim's name. Theoretical on this network. | **Open, optional.** Fix: `ExtendedProtectionPolicy` = WhenSupported; test in Edge before keeping it. |
| L-7 | **Opening `register.csv` in Excel on the server blocks issuing.** Excel locks the file; issuing then fails safely (500, the half-written page removed). | **Operational:** copy the register before opening it. |

**Found while fixing L-2 (fixed, 8 Oct):** a browser counts a line break in
the notes as one character against the 500 limit but sends it as two (CR LF),
so a long note with line breaks could pass in the browser and be refused by
the server. The limit is now measured on the notes as stored.

**Checked and sound (probed live where marked ●):**

- ● **Cross-site scripting.** Hostile serials, Apple data (`<img onerror>` in the model), notes and asset tags are all escaped on every page and in stored certificates. The CSP allows no script but the print button's exact handler.
- ● **CSRF.** The POST needs an exact Origin. `null`, missing, wrong case, a trailing slash, another port, a look-alike domain and two Origin headers were all refused.
- ● **Path traversal.** IDs and serials are matched against exact patterns ending `\z`. Traversal, NUL, extra digits and lower-case IDs all gave 404.
- ● **Access control.** A non-member got 403 on the form, the device page, a stored certificate and the POST; only `/health` answers.
- ● **Device details come only from Apple.** Device fields added to the form were ignored; the POST asks Apple again.
- ● **Form tampering.** Duplicate fields, impossible dates, an option not in the file and a JSON body were refused (400).
- ● **Register CSV injection.** A value starting `=` was stored as `'=…`.
- ● **Headers.** CSP, nosniff, frame-deny and `Referrer-Policy: same-origin` on every response, errors included.
- **Secrets.** Git history holds no key, client ID, host name, account or real serial. The token is in memory only; logs carry lengths, never values.
- **Errors.** Pages show generic text; detail goes to the log.
- **Certificates are never overwritten**, and each one's hash is recorded.
- **HSTS deliberately not added:** it would apply to every service on the host name, not only port 5000.

**Not a finding, but worth knowing:** the origin check stops *browsers* being
tricked. An allowed user writing their own script can still issue
certificates, under their own name, and the log shows who.

**Availability reminder:** the TLS certificate shared with AppFilter is pinned
by thumbprint; when it renews (Dec 2026) both apps stop until it is re-bound.

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
| AD display name and mail | Probe page on the lab machine: "AD lookup: Active Directory" for a technician account. |
| Certificate in Edge | Step 3: both samples one Letter page, no browser header or footer with the box ticked, colours kept, file name right. Approved 2 Oct 2026. |
| The pages, end to end | Here, in Chromium, against a copy of the server with stand-ins for Apple, AD and the group (plain HTTP, anonymous): issue redirects to the ID; refresh issues nothing; the device page then lists and links the certificate; the second gets the next number; not found, bad serial and released device shown right; an Apple error shows a generic page with no detail. |
| The POST refuses what it should | `Origin: null`, no Origin, a foreign Origin (403); future date, an option not in the file, a bad serial (400); 20 KB body (413). None issued anything. Device fields added to the form were ignored and Apple was asked again. |
| Group check covers everything | With the user outside the group: form, device page, stored certificate and POST all 403; `/health` 200. |
| Register | Stored page served byte for byte; register hash = SHA-256 of the file; a formula in the notes is stored escaped and read back intact; history newest first; a file already at the next number is skipped, never overwritten; numbers restart each year. |
| Apple lookup on the lab machine | `Test-AppleLookup.ps1` under Windows PowerShell 5.1: key loaded (P-256), assertion signed, token received (lengths only shown), devices returned, both an assigned one (`status` `ASSIGNED`, no release date) and a released one. 6 Oct 2026. `deviceModel` varies in detail: "iPad Pro 11-inch" for a recent device, just "iPad" for an older one; the certificate prints it as given. |
| Released devices: not reliably returned | One released device (August 2026) was returned with `releasedFromOrgDateTime` set; another, confirmed released in the portal, gave 404. Certify before release. |
| Audit fixes under 5.1 | Full `Test-AppleCert.ps1` suite (register, notes cleaning, body limits, key, Apple-call checks) passed under Windows PowerShell 5.1 on the lab machine, 8 Oct 2026. |

**Not verified yet:** the app itself on the lab machine (step 4).
