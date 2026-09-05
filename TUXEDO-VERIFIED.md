# Tuxedo Touch WIFI — TUXW_V5.3.21.0
## Adversarial review results and practical enablers

Owner: Lewis. Scope: static analysis only. Nothing was run against hardware; no device was touched at any point in producing this.

---

# PART 1 — WHAT SURVIVED SCRUTINY

## Scorecard — read this first

Ten high-severity findings were each handed to a skeptic whose job was to kill them.

| Outcome | Count |
|---|---|
| **Survived intact** | **5** |
| **Partly wrong** — mechanism real, scope or consequence corrected | **5** |
| **Killed outright** | **0** |

Nothing was fully refuted. But **half of the findings had their scope or their consequence materially corrected**, and in three cases the correction is the difference between "act now" and "do nothing". Where a skeptic corrected an earlier claim, the corrected claim is what appears below — the original wording is shown only where the difference matters.

Below, the login-lockout finding leads by instruction. Everything after it is ranked by **real risk to this owner, on his own LAN**, not by how alarming it sounds.

---

## LEAD FINDING — The three-failed-logins lockout

**Verdict: PARTLY WRONG. The alarming half is false. Say the correction as loudly as the original.**

### The original claim
"Three failed web logins **permanently** disable **every** web user account; `status=0` is written to all WEBUSERS entries and nothing ever writes it back to 1 — the accounts must be rebuilt."

### The corrected claim
Three *consecutive* failed logins against **one existing, currently-enabled** web username do write `status=0` into **all five** WEBUSERS entries (plus `accountLocked=1` for the offending user), and `status==1` is a hard gate on web login — so yes, **every web account stops working at once**.

But it is **not permanent and nothing has to be rebuilt.** The touchscreen app writes `status` back to 1. `CAccountsSetup` (Settings → user account setup) loads `status` from the file, renders each user's button as "Enabled"/"Disabled" from it, offers per-user reset buttons **and an "Enable All" button**, and on Apply writes `status=1`, `accountLocked=0`, `accLockedCount=0` for every row not showing "Disabled". Usernames and passwords are reloaded from the same file — nothing is retyped.

**Accurate one-liner: three failed web logins disable every web account until someone clears it at the panel's touchscreen.**

Why the original was wrong: its own test — "decode every writer to that field" — was applied only to Barracuda. Barracuda genuinely never writes `status=1` (proved exhaustively: the string "status" appears exactly once in the binary, at `0x8d768`, with five references, all decoded). But `status` is a shared on-disk contract with the touchscreen app, and `tuxedo` does a full read-modify-write of the same file. That path is live, shipped and user-reachable — unlike Barracuda's own `resetLoginFailureCount` at `0x15074`, which really is dead code with zero callers.

### Preconditions
1. Web form login must actually be exercised. LAN browsing only authenticates if "Authentication for web server local access" is enabled (see finding 7). With it off, no failures can be generated at all.
2. The typed **username must exactly match an existing entry**. A wrong/unknown username increments nothing — guessing bogus usernames is completely harmless. Only mistyping the **password of a real account** counts.
3. That entry must currently have `status==1`.
4. The three failures must be consecutive; any successful authenticated page load zeroes that user's counter.
5. Recovery needs physical access to the touchscreen — which Lewis has.

There is **no** self-healing: `accLockedTime` is written by three functions and read by none, and no boot script or init path re-enables anything. Once locked, further attempts keep re-writing `status=0` (the failure counter does not check `status`), which is why it *feels* permanent from the network side.

### Owner action
- **Preventively: nothing.** There is nothing to install, patch or configure.
- **If it happens:** at the panel → Settings → user account setup → press **"Enable All"** (or flip the individual Disabled button to Enabled) → **Apply**. Do **not** press Apply while a row still reads "Disabled" — that row gets `status=0` written.
- **Operational caution that actually matters to you:** if you script, fuzz or replay against `/login.shtml`, **three wrong passwords for a real username take the entire web interface offline for all five accounts** until you walk to the panel. Do that testing only with the panel physically in reach.
- Do not try to hand-restore `webuseraccountsenc.json` as a backup path — it is AES-OFB encrypted and CRC-tracked. The touchscreen reset is the intended and only supported recovery.

**Real-risk rank on your LAN: low.** It is a self-inflicted nuisance with a two-minute fix, not an exposure. It appears first only because you need to know it before you next mistype a password.

---

## RANKED BY REAL RISK ON THIS OWNER'S LAN

### 1. Installer code readable over HTTP with no authentication — `/Config/panelinfo.txt`
**Verdict: SURVIVES.** Highest real risk of the ten: unconditional, no preconditions beyond network reach, and it discloses a live secret.

**Claim (unchanged):** `/opt/tuxedo/configuration/` is mapped to the URL prefix `/Config/` with no authenticator, so `panelinfo.txt` — whose 7th CSV field is the **installer code in plaintext** — is one unauthenticated GET away.

Four independent kill attempts all failed:
- **Parent authenticator?** No. `HttpDir_authenticateAndAuthorize` (`0x6b544`) is 35 instructions and reads only *this* dir's `+0x14`/`+0x18`. No parent walk.
- **Server-level default?** No such field exists; the only realm/FormAuthenticator instances in the image are bound to one dir named `authenticated`, which holds `index.html`.
- **Wrong subtree?** The `Config` dir is inserted as a **sibling** of `authenticated`, not a child. Its parent (`highPrioRootDir`) is a bare memset `HttpDir` with null realm.
- **Gate elsewhere in the pipeline?** Every call out of `processData`/`executeCon`/`serviceRequest` enumerated. Nothing.

The payload holds up read as bytes: `CreatePnlInfoFlashTable` (`0x58f0a8`) emits field 7 from `GetInstallerCode(5, buf)`, falling back to the literal `0000,` on failure, then ships the file to `/opt/tuxedo/configuration/` via a shell `cp` — byte-for-byte plaintext, no encryption.

**Scope is understated, not overstated.** The DiskIo root is the whole directory, so the same prefix also reaches `panelinfo_sec.txt`, `useraccountsetup.txt`, `webuseraccountsenc.json`, `Tuxedo.json`, `SystemConfig.txt`, `MailConf.txt`, `P<n>Info.txt`, `registereddevMAClist.json`, `zwavedevdb.json`, `hascenedb.json` — all names hardcoded in the binary, so no directory listing is needed.

**Preconditions:** network reach to port 80 (opened unconditionally at boot); no credentials/session/cookie; URL segment is **case-sensitive** (`/config/` 404s); `panelinfo.txt` must exist, which happens once the Tuxedo completes an info sync with a paired Vista panel; field 7 is real only if the panel answered the CAL request, otherwise it is the literal `0000`.

**Owner action:**
1. Settle it in one command from another host — I did not run it:
   ```
   curl -sS http://<tuxedo-ip>/Config/panelinfo.txt
   ```
   Count commas; field 7 is the installer code. Also check `/Config/Tuxedo.json` and `/Config/registereddevMAClist.json` — the latter is directly relevant to findings 4 and 5.
2. If it returns the real code, **treat the installer code as disclosed** to anything that has ever been on that network segment. If the panel has ever been port-forwarded or on a flat network with untrusted devices, change it at the panel and re-sync.
3. **Fix at the network layer.** 5.3.21.0 is terminal; there is no vendor fix coming and nothing to disable in the UI — the `/Config/` mapping is created unconditionally at every boot. Remove any port-forward, put the panel on a VLAN/SSID untrusted clients cannot reach.
4. Do **not** rely on the web login. It protects `/authenticated/`; `/Config/` is a sibling of it.
5. If you are patching firmware anyway, the equivalent one-line fix is at `installVirtualDir+0x39c` (`0x14934`): insert `readDir2` into `authenticateDir` rather than the root, or copy the realm/authenticator writes done at `0x147b8`/`0x147bc`. **Caveat:** that breaks the web app's own `Config/cri_vidrec/...` video fetches unless those carry the session — test playback afterward.

---

### 2. Alarm user code travels in a GET query string on an always-open plaintext port 80
**Verdict: SURVIVES.**

`sendCommand()` builds `/handlerequest.html?cmd=...&uCode=<raw code>&sessionid=...` and issues it as GET. Confirmed against the **shipped** JS extracted from the ZIP embedded inside the Barracuda binary itself (EOCD at file `0x4f00fd`, 776 entries), not just the unpacked webapp copy. Server side, the handler calls `getParameter("uCode")` then `atoi`. The documented REST endpoint does the same in lowercase (`ArmWithCode?...&ucode=`).

The plaintext listener is **not conditional on anything**: `barracuda()` calls `openSocketCon(server, disp, 80, 443, 1)` with no guard, and both branches of `openSocketCon` construct a cleartext `HttpServCon` bound on all interfaces alongside the TLS one, against the same `HttpServer`. A non-80 configured Barracuda port simply *adds* a second plaintext listener (default 6280) plus TLS on 9443.

**The one mitigation and its two limits:** `index_html::service` redirects cleartext → HTTPS, but only when the HTTPS toggle is on, and **only from `index.html`**. The toggle defaults **off** (both binaries return 0 when the JSON key is missing, and no `Tuxedo.json` ships). And `/handlerequest.html` itself performs no scheme or port check at all — anything hitting it directly on port 80 is served in the clear. See finding 3 for what that "HTTPS" is worth.

**Preconditions:** Barracuda running (it is — launched from `CHomeScreen::sltInitHomeScreen` every boot); someone actually arms/disarms *through the web UI or REST API*; HTTPS off **or** the client entering at an inner page; and someone positioned to see packets. Note the code does **not** land in browser history or Referer headers — it is an XHR, visible only in devtools.

**Owner action:**
1. **Do not port-forward 80, 6280, or the configured Barracuda port.** Check the router's existing rules — the vendor docs push users toward opening ports for remote access, so a rule may already exist. Use a VPN into the LAN instead.
2. Decide how the code enters the system. If you arm/disarm from the touchscreen and use the web UI only for automation/cameras/config, this never occurs.
3. If you do arm from the web UI, put the panel and the browsing host on a wired segment or dedicated VLAN/SSID. **This is worth more than the HTTPS toggle** (finding 3).
4. Turn HTTPS on anyway if you'll click through the certificate warning — partial, not sufficient.
5. Sweep the LAN for anything that logs full URLs on port 80: router "parental controls"/URL history, Squid/Pi-hole, Zeek/Suricata, **and old pcaps from earlier protocol work in this very repo**. If an arm/disarm was captured, the 4-digit code is sitting in a plaintext log. Purge those.
6. If the web UI has ever been used to arm/disarm over guest Wi-Fi or through a URL-logging router, **change the alarm user code**.
7. For your own tooling: never put `ucode` in a query string in clients you write.

---

### 3. HTTPS presents the TLS vendor's demo certificate, with its 1024-bit private key compiled into the binary
**Verdict: SURVIVES.** Ranked here because it is what makes finding 2's obvious mitigation hollow.

`sharkSslDemoCertSrv` (VA `0x853b1`, 1152 bytes, file offset `0x7d3b1`) decomposes as: 693-byte X.509 DER, `ff ff ff` pad, `expLen`/`modLen`/`e=65537` header, then n, p, q, dP, dQ, qInv at 64 bytes each. **Arithmetically verified**, not assumed: `p*q == n`, `dP == d mod (p-1)`, `dQ == d mod (q-1)`, `qInv == q⁻¹ mod p`, and an encrypt/decrypt round-trip with the reconstructed `d`. The modulus appears verbatim inside the cert's own SubjectPublicKeyInfo — same key, same cert.

Certificate: issuer `Real Time Logic / SharkSSL / "demo CA"`, subject CN `server demo 1024 bits`, md5WithRSA, valid **2009-08-27 to 2019-08-25 — expired six years ago.**

Three kill attempts failed: (a) the key is real, not a decoy; (b) `SharkSsl_constructor` is called exactly **twice** in 5.6 MB, both inside `openSocketCon`, both with this cert, both immediately wired into an `HttpSharkSslServCon` — there is no `setCertificate` API in the build, the PEM loader is unreachable dead code, and no `.pem`/`.crt`/`.key` exists anywhere in the rootfs; (c) `supervis` respawns Barracuda in a loop and the TLS listener is created with no config gate.

**Consequence is conditional and this matters:**
- **Passive decryption** requires the recorded session to have used static-RSA key exchange. The server prefers DHE_RSA (suites `0x006b, 0x0039, 0x009e, 0x0067, 0x0033, 0x0016` ahead of the static-RSA set) with server preference. But modern browsers dropped DHE, so a current Chrome/Firefox lands on `TLS_RSA_WITH_AES_256_CBC_SHA` or similar — no forward secrecy, fully decryptable offline with this key. A browser new enough to have dropped `TLS_RSA` entirely cannot connect at all (no ECDHE, no TLS 1.3 in this build).
- **Silent impersonation:** essentially none. Nothing trusts this credential — unknown CA, name mismatch, expired. Any browser already throws a full interstitial, so an on-path attacker facing a click-through user never needed the key. It adds real capability only against a client that pins this exact cert; no such client exists in this firmware.
- **Not a per-unit secret.** Identical on every Tuxedo running 5.3.21.0, and it self-identifies as RTL's SharkSSL sample credential — plausibly already public in the SDK. *(unconfirmed — could not check against the SDK offline)*

**Not affected:** outbound AlarmNet/Total Connect traffic, which goes through OpenSSL in a separate binary and does not touch this key.

**Owner action:** No configuration fix exists — do not go looking for a toggle.
1. Confirm nothing forwards 80/443/9443/6272 to the panel. This is the only change that matters.
2. Treat the web UI as non-confidential against anything already on the same segment; VLAN-isolate it; reach it over VPN from outside.
3. Do not read the padlock as meaning anything. Rotating panel passwords does not help against an on-path attacker who can decrypt and re-read them.
4. **Optional project, not a security fix:** the blob's layout is fully known and a fresh 1024-bit key plus a ≤693-byte DER cert would fit the same footprint without relocation. That is firmware modification with real bricking risk on a security panel, and it still produces a cert nothing trusts. Do it only if you want key control for your own pinned tooling.

---

### 4. The REST API AES key/IV is derived from `srand(time(NULL))` — at most 32 bits, and the key *is* the authentication
**Verdict: PARTLY WRONG.** The entropy finding survives and is the real issue; the "single global permanent secret generated at the 2013 first boot" framing is over-stated in three ways.

### Corrected claim
The REST API uses one persistent AES-256-CBC key + fixed IV **per registered API identity**, stored in `/opt/tuxedo/configuration/registereddevMAClist.json`. The web UI's identity is literally named `Browser`; its pair is generated once, on the first Barracuda start that finds no `Browser` node, and is never rotated — not on reboot, not on login, not per session.

But: **not "single"** — every MAC enrolled via `AddDeviceMAC` gets its own independent pair. **Not absolutely "permanent"** — `RevokeKeys`/`setrevokekeys` regenerates on demand. **And the 2013 timestamp is a conditional case, not a guarantee** — the boot script only runs `date 0101000013` when `/opt/tuxedo/configuration/datetime` is *absent*, so a unit whose `Browser` node was first created after a firmware upgrade (datetime already present) was seeded from real wall-clock time. Same brokenness, different constant, materially different if you try to reproduce it.

### What survives, hard
`random_string` (`0x1d5d4`): `time(NULL)` → `srand()` → 31× `rand() % 62`. **No `/dev/urandom` anywhere in the binary.** `generateKeyForAPI` (`0x1d96c`) then runs `EVP_BytesToKey(aes-256-cbc, md5, salt=NULL, count=1)`. Key *and* IV together are a pure deterministic function of one 32-bit `time_t`. Ceiling: **32 bits, not 384.** On a virgin first boot the seed is `1356998400` plus the seconds from the `date` line to Barracuda's start — boot path is supervis, sleep 2, tuxedo, sleep 2, Qt init, home-screen init, kill+relaunch Barracuda, i.e. roughly **2⁵–2⁹ candidate keys**. That is not weak; it is enumerable by hand.

It is worse than "guessable": **the IV is the public lookup index.** `WnmpDir_service` matches the cleartext `identity` header against each node's `PublicKey` (= the IV). So a guessed seed is **verifiable directly against the server** — derive key+IV, present the IV as `identity`, and the server tells you whether you guessed right. Three genuine per-session key mechanisms exist (`LoginResp_service`, `addSessionItem1`, `getRandomKeyForSession`) and were traced to their consumers — none feed REST payload crypto. The "not per session" half is confirmed.

### A trap worth recording
`my_key_enc_api` at `0x55a6d4` is hardcoded to the **NIST SP 800-38A / FIPS-197 worked-example** AES-128 key/IV (`2b7e15...` / `000102...`). Despite the name it is **not** the REST key — `encryptAESforTuxdbAPI`/`decryptAESforTuxdbAPI` have zero callers and zero pointer references. Dead code. Reasoning from that symbol name alone produces a claim that *sounds* like this one and is false.

**But** the adjacent `my_key_enc` at `0x55a6b4`, same textbook constants, **is live** — it protects the local web user-account store via `encryptAESforTuxdb`, called from `readUserNamePasswordFromJSON` and the lockout writers. That one is **identical on every unit running this firmware**. It needs filesystem access to exploit, so it ranks below the network findings, but it is arguably a worse secret than the per-device REST key.

### Preconditions
For the 2013 constant specifically, all of: no `Browser` node existed at that boot; `/opt/tuxedo/configuration/datetime` absent (same directory — a factory default or config wipe satisfies both, which is why they usually coincide); internet time did not win the async race; no RTC restored the clock (structurally confirmed — `settime`/hwclock is not in `cfg_services`).
For exploitability: network reach to the HTTPS listener, and note the attacker does not need to capture anything because guesses are verifiable. `/tuxedoapi.html` is **not** an unauthenticated key disclosure — it is gated by `AuthenticatedUser_get1`. Some endpoints are additionally LAN-gated; that set was not enumerated, so a remote attacker's blast radius is narrower by an unmeasured amount.

### Owner action
1. **Settle the seed offline, in minutes, without touching the network.** You already have the answer in two places: `registereddevMAClist.json`, or the `readit` hidden input on `/tuxedoapi.html` while logged in (first 64 hex = key, next 32 = IV). Take **only the 32-hex IV**. Then offline, for `s in range(1356998400, 1356998400+900)`: `srand(s)`, 31 chars of `rand()%62` over `abc…xyz0123456789ABC…XYZ`, `EVP_BytesToKey(aes-256-cbc, md5, salt=NULL, count=1)`, compare the derived IV. A hit proves 2013 seeding on your hardware. No hit means a post-upgrade real timestamp — re-sweep across the plausible install window. **Must use a glibc-compatible `rand()`** — musl and Python's PRNG will not reproduce it.
2. **Do not treat the REST AES layer as security.** It is authentication: `WnmpDir_service` admits a request on `identity`+`authtoken` alone, with no session, no body binding, no nonce. Keep the panel off any port-forward and on a segment where you'd accept anyone reachable being able to drive the alarm API.
3. **Do not expect to fix it on the device.** Forcing regeneration just re-runs `srand(time(NULL))`; with a correct clock you get a real-timestamp seed — better than 2013, still ≤32 bits. A materially better secret means a rebuilt Barracuda, far larger than this warrants.
4. Note for the file: `getKeyFromPassword` (`0x1d648`) writes a NUL at `out[31]` after emitting 32 hex chars, **truncating every session key it produces to 31 characters**. Real bug, harmless-looking.

---

### 5. The REST `authtoken` is static per endpoint, covers neither body nor nonce — captured once, replays forever
**Verdict: SURVIVES.**

`WnmpDir_service` builds exactly `"MACID:" + DeviceMAC + ",Path:" + <dir-relative path>` and runs **one** `HMAC_Update` over it, keyed with the 64-char ASCII PrivateKey, hexified and `strcmp`'d against the header. No timestamp, no counter, no body, no Content-Length, no query. The client's `&tstamp=` + `Math.random()` is never parsed — the byte string `tstamp` does not occur anywhere in the 5.6 MB binary.

Four refutation attempts failed:
- **"A session cookie is also required"** — false, and the truth is *worse* than the claim. `WnmpDir_constructor` calls `HttpDir_overloadService`, which literally replaces the dir's service pointer; `HttpDir_authenticateAndAuthorize` is called only from the *default* `doService` that got replaced. Zero references to `getSession`, `AuthenticatedUser_get1`, `Cookie`, `checkforlocalremote` or `getRemoteAccess` across the 1031-line dispatcher **and** the 10,919-line field handler. The exposure is not "life of a session"; there is no session.
- **"API is off by default"** — false. Shipped `WebConfig.conf` contains `Allow_API:01`.
- **"Something else is in the MAC input"** — false, as above.
- **"The key rotates"** — false. Written once at first boot; `generateKeyForAPI` early-returns when the `Browser` entry exists.

**Scope refinements (neither contradicts the claim):** a replay also needs the `identity` header and POST method — any captured browser request carries both, so this is bookkeeping. And the token is per-(device, path): a `/DisarmWithCode` token is useless for `/ArmWithCode`. Since the body is uncovered, a replayer can swap in a *different* ciphertext for the same path — but forging a decryptable body needs the PrivateKey, and anyone with that can mint every token anyway. **Realistic consequence of one capture: indefinite exact replay of that one operation.**

**Preconditions:** `Allow_API` non-zero (shipped `01`); the `Browser` node exists; a captured request to a path **not** under `API_REV01/System|Administration|AutomationTest`; network reach; and nobody has since revoked keys or factory-reset. Capture requires seeing plaintext HTTP — intercepting proxy, shared browser profile, a saved HAR/devtools log, or MITM against a clicked-through cert.
**Alternative that makes capture unnecessary:** anyone who logs into the web UI once and views `/tuxedoapi.html` reads the raw PrivateKey out of the hidden input and can mint valid tokens for every endpoint, forever.

**Owner action:**
1. **If you don't use the REST API, set `Allow_API:00`** in `/root/Settings/WebConfig.conf` (CRLF line endings, `Key:VV` pairs) and restart the webserver. `allowSystemAPIFromConfig` returns 0, `WnmpDir` is never constructed, the whole surface 404s. **This is the one clean, verifiable mitigation available without rebuilding Barracuda**, and it also removes finding 6 entirely.
2. If you do use it: treat the `Browser` PrivateKey as a permanent, non-expiring bearer credential equivalent to the panel password. Never paste it into shared scripts, gists or issue reports. If leaked, rotate via revoke-keys or delete the `Browser` entry and let it regenerate — every previously captured token dies.
3. Never expose the Barracuda port off-LAN. The HMAC endpoints — including `AdvancedSecurity/DisarmWithCode` — carry **no** local-only restriction, so remote exposure turns one capture into permanent remote disarm.
4. For your own tooling: the token is stable. `HMAC-SHA1(key=PrivateKey_ascii, msg="MACID:Browser,Path:API_REV01/<Endpoint>")`, lowercase hex, with `identity=PublicKey`. No per-request derivation.

**Two flagged side observations, not part of the verdict:** paths under `API_REV01/System`, `/Administration` and `/AutomationTest` **skip the authtoken check entirely** and are gated only by `checkforlocalremote` — a first-three-octets string compare. Those include the key-management calls, so same-subnet peers need no token at all for them. *(untested)*

---

### 6. An empty `authtoken` header skips the entire HMAC verification
**Verdict: SURVIVES** as a mechanism. **The implied "authentication bypass" does not.**

At `0x29c70` the header is fetched again, `ldrb r3,[r0]`, `cmp r3,#0`, `beq 0x29e2c` — a present-but-empty value jumps straight past the MACID/path build, `HMAC_Init_ex`/`Update`/`Final`, the hexify loop, the Base64 and the `strcmp`. Crucially, `0x29e2c` is the **identical target** the HMAC-matched branch jumps to. Empty token lands on the success continuation, not an error path, and proceeds into `WnmpDir_serviceField` — the real command dispatcher.

**Absent vs empty resolved at the parser, not by guesswork:** the header parser NUL-terminates the name at the colon and skips spaces with a pre-indexed `ldrb`; `extractLine` has already written a NUL at the CR. So `authtoken:\r\n` yields a valid pointer to `""` → takes the bypass; a missing header yields NULL → 401.

**What does NOT survive is the consequence.** Before authtoken is ever read, an `identity` header must match a registered `PublicKey` (else 401), and `WnmpDir_serviceField` then Base64-decodes `param` and AES-256-CBC-decrypts it with **the same PrivateKey the skipped HMAC was keyed with**. Anyone who could forge the HMAC already holds everything this grants. **No state-changing command becomes reachable that was not reachable before.**

The real, narrower gain: (a) it removes all binding of the request to (DeviceMAC, URL path), so a captured `param` ciphertext can be replayed against a *different* endpoint; (b) it lets anyone holding **only** the 128-bit `identity`/PublicKey reach `decrypt()` with arbitrary bytes — `EVP_DecryptFinal_ex` fails on padding and `handleErrors` calls **`abort()`**. That is a **remote kill of the Barracuda webserver process**, downgraded from "needs the 256-bit PrivateKey" to "needs the PublicKey".

**Preconditions:** `Allow_API` non-zero; the URL must not be under the three `System`/`Administration`/`AutomationTest` prefixes; at least one API client registered (`registereddevMAClist.json` does **not** ship in the image — a unit that never enrolled a client is completely unreachable this way); attacker knows that client's PublicKey; HTTPS/443 (port-80 requests are 302'd first); POST.

**Owner action:**
1. Same as finding 5 item 1 — `Allow_API:00` removes this entirely.
2. **Treat the `identity`/PublicKey as a secret**, not a public value. It is the sole gate between the network and `decrypt()`, and a wrong ciphertext there aborts the webserver.
3. Don't port-forward 443. Anyone who has ever seen the identity value can crash the web server at will.
4. Prune `registereddevMAClist.json` — each live entry is another PublicKey.
5. **Useful for your interop tooling, deliberately:** you can send `authtoken:` empty and skip the `HmacSHA1("MACID:<mac>,Path:<path>", PrivateKey)` step — the fiddliest part to reproduce. You still need `identity` and a correctly encrypted `param`. Be aware you are relying on a defect.
6. **Do not report this upstream as an "auth bypass."** It is a request-integrity/binding defect plus a remote `abort()` DoS. Framed as auth bypass it will be correctly rejected, because PrivateKey is still required for any command.

---

### 7. `LocalLogin = 0` gives credential-free sessions to same-subnet hosts
**Verdict: PARTLY WRONG.** Real code, high severity, **but latent unless someone unticked a box** — and the claim's mechanics are wrong in two details.

### Corrected claim
When `localLoginStatus == 0` in the running Barracuda process, a client whose TCP source address shares the **first three dot-separated octets** of the panel's own interface address can obtain a session cookie, a 64-hex CSRF token and fully rendered CSP pages with no credentials — **but only via a two-hop redirect**: the first cookie-less GET of `home`/`console`/`armcontrol` returns a 302 to `/redirect.html?url=…`, and it is `MyPage_service` there that mints the session and token before bouncing back.

Three corrections to the original:
1. **"Any host on the /24"** — it is a `strcmp` of the first three octets, **no netmask is consulted**. On a real /24 that coincides. On a flat 10.0.0.0/8 or 192.168.0.0/16 it *under*-matches; a host on a genuinely different subnet sharing three octets is classed local.
2. **"Gets full pages"** — not from the request it makes. Any browser or `requests.Session()` follows the 302 transparently; a bare `curl` without `-L` and a cookie jar gets nothing.
3. **It is not the shipped state.** `addLocalLogin()` runs from `main()` on **every boot** of `tuxedo` and writes `LocalLogin: 1` whenever the key is absent. The checkbox writes 0 only after an explicit "…will be disabled. Do you want to continue saving?" confirmation.

Also subject to the concurrent-client cap (else `/Msg503.html`).

### Reconciliation — this does *not* contradict the `ha-tuxedo-touch` observation
`LocalLogin` gates **only** the CSP HTML pages plus `handlerequest.html`'s no-session branch and `MyPage_service`. It appears nowhere in the FormAuthenticator path — `/authenticated/index.html` always demands credentials regardless — and nowhere in `WnmpDir_service`, which serves the `API_REV01/…` endpoints that integration actually uses. An integration whose first step is "log in" sees **zero** change when the box is unticked. Both observations are true of the same firmware.

### Secondary hazard *(LIKELY, lower confidence)*
`setLoginForLocal` writes the global on only two paths: `fopen` failure → 1 (fail-closed), and a successful `BARRACUDA[0].LocalLogin` lookup. **If `Tuxedo.json` exists and parses but lacks that key, nothing is written and the global keeps its `.bss` value of 0 — fail-open.** `addLocalLogin()` repairs the file, but it lives in a different process (`tuxedo`) from the reader (`Barracuda`, launched by `supervis`, which `startup` backgrounds first). So for that boot the panel runs open until an IPC msg `0x3e` arrives — which only happens when someone toggles the checkbox. This bites a unit whose config predates the key (e.g. upgraded from firmware without it). No `Tuxedo.json` exists in the carve, so this cannot be settled statically. **It is the reason to verify effective behaviour rather than trusting the file.**

### Owner action — one read, no change
**At the panel, confirm "Authentication for web server local access" is ticked.** That checkbox is `BARRACUDA[0].LocalLogin`; nothing else in either binary writes the key. Ticked → none of this is live on your unit, you're done. Unticked → tick it; effect is immediate via IPC, no reboot.

- **If you ever unticked it to make `ha-tuxedo-touch` work, it did not help and you can re-tick it with no loss of function** (see reconciliation above).
- **Optional read-only check of the effective state**, since file and running value can disagree: from a host on the panel's subnet, no cookie jar, `curl -sI http://<panel>/home.html`. A `302` to `/authenticated/index.html?url=home.html` = flag is 1, good. A `302` to `/redirect.html?url=home.html` = flag is 0, exposed — stop, tick the box, re-check. **Don't follow the redirect** — you don't need to, and following it creates a session.

Nothing to patch.

---

### 8. No per-command authorisation on `/handlerequest.html`
**Verdict: PARTLY WRONG.** The mechanism survives; the framing implies a privilege boundary this product does not have.

### Corrected claim
1. **`/handlerequest.html` has no authorisation layer of any kind — this SURVIVES.** Its dir has NULL authenticator and NULL authorizer (installed via `insertCSP` into the first root dir, not under `authenticated`); `cspCheckCondition` only filters HTTP methods; the in-page gate is exactly a matching (sessionid, tokenkey) pair. Past it, all 249 `getParameter` calls and 70 `osal_MqSend` calls are reachable, and `tuxedo`'s `CReceiverThread::run` dispatches the 0x194-byte MQ messages to slots with no further check.
2. **"Any valid session may arm/disarm" needs a qualifier.** The web layer imposes nothing but only forwards `uCode` to the panel, which enforces it. **Disarm (Type 3) always transmits the supplied code digits**, so a session without a valid panel user code cannot disarm. Arm away/stay/night transmit no code when Quick Arm is enabled for the partition and `uCode` is 0 (rewritten to `0xffff`, then the digits are skipped). **Codeless arming is real; codeless disarming is not.**
3. **There is no privilege boundary to cross.** Web accounts (max 5) carry **no role, authority or partition field at all** — only name, password, id, status and lockout counters. This is not privilege escalation; the product simply has one flat web privilege level.
4. **The "leftover demo data" characterisation is correct and understated.** `securityDB` is verbatim the Barracuda sample table (`family/dad`, `family/mom`, `family/kids`, `family`) plus an empty-string catch-all; its role lookup `MyUserDB_user2Roles` is literally `mov r0,#1; bx lr`; and `MySecurityRealm_authorize` has **no reachable call site** — stored into the realm object at construction and never invoked. Even if invoked it would apply only to the `authenticated` dir.
5. **The brief's premise is partly wrong:** there is no `GetUserAuthority` in this firmware. `CUserAuthority::IsAuthorized` and `sltGoAuthLevelReceived` gate only the Qt touchscreen widgets; `sltGoAuthLevelReceived` is a *reporter*, converting the panel's per-partition answer into `VALID_USER_CODE`/`INVALID_USER_CODE` strings for the browser. Neither ever sits in front of a web command.

**Preconditions:** a live (sessionid, tokenkey) pair from the sessItem table — **this is a post-authentication property, not an unauthenticated one**; web interface reachable; for codeless arming, `gQuickArmState[partition-1] == 2`; for disarm, a real panel user code; panel online.

**Owner action: nothing to fix.** There is no per-command authorisation to restore because there was never a privilege model. The `securityDB` ACL is dead sample code; removing or correcting it changes no behaviour.

Two takeaways for your actual work:
1. **Treat `/handlerequest.html` as a flat command bus.** No authority handshake to emulate. Type 1=arm away, 2=arm stay, 3=disarm, 4=arm night; `pID` is a **partition bitmask** built from a `strtok`'d list, not a partition number; `uCode=0` → `0xffff` = "no code", arming only, Quick Arm only.
2. **`sessionid` and `tokenkey` travel in the GET query string.** That — not the missing ACL — is the realistic leak path: any proxy log, router URL history or Referer is enough to replay any command. Same defence as finding 2.

---

### 9. `/thermostatclient` disables TLS certificate validation
**Verdict: PARTLY WRONG.** The flags are real; the scope is wrong twice, and on this owner's likely configuration the answer is **do nothing**.

### Corrected claim
The single curl handle the binary ever creates sets `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` to 0 — confirmed byte-for-byte (options `0x40` and `0x51`, value register `r7` provably 0 at both sites; the decoding is cross-checked because the neighbouring options `20011/10002/10015/10001` line up with the write callback, URL buffer, POST body and write struct). But:

1. **The request never goes to a Honeywell *hostname*.** `perform_http_api` builds the URL from a dotted quad returned by `popen("/dnshelper tccaps.honeywell.com")`, defaulting to the hard-coded literal `199.62.84.94` in `.data` — so the URL is `https://<IP>/ws/MobileV2.asmx/...`. Hostname verification could never have succeeded against an IP-literal URL, **and there is no CA bundle anywhere in the rootfs and no `CURLOPT_CAINFO`/`CAPATH` call in the binary**. This is a structurally unauthenticated TLS client, not one forgotten flag.
2. **On a unit with no Total Connect Comfort account linked, the process launches at every boot but issues zero HTTPS requests.** `WifiThemroInitFunc` finds the username/password files absent, sets `authState = -2`, and the worker loop's first test sends it straight back to the message-queue wait. The disabled verification is real code on a running process, but **dormant until credentials exist**.

The launch is reachable: `ZWaveInitNetwork` posts `"/thermostatclient &"` to the supervision thread on the success path of the Z-Wave serial-API version query. The only two commands that could force a login (`0x68`, `0x6c`) originate **solely** from the touchscreen setup screen; the one command sent at boot (`0x67`) never touches curl. Credentials are written **only** by the Wi-Fi Thermostat setup "Save" button — and Barracuda contains no occurrence of `thermostats/honeywell`, `tccaps` or `MobileV2`, so the web UI is not a second way in.

**Preconditions:** Z-Wave serial API answers (so the process launches); **both** `/opt/tuxedo/configuration/thermostats/honeywell/username` and `.../password` exist and are non-empty — i.e. a TCC account was linked at the touchscreen; and an interceptor positioned on the path to `199.62.84.94`. With no pinning, no CA and no hostname check, any certificate is accepted and the attacker reads the **plaintext TCC username and password** out of the POST body and can forge every response.

### Owner action
- **If no TCC account is linked — do nothing.** Check read-only: `ls -l /opt/tuxedo/configuration/thermostats/honeywell/` (is `username` present and non-empty?). `ps | grep thermostatclient` will almost certainly show the process running; it is parked at `authState -2` and will never open a socket. **Record it in the teardown as dormant, not as live exposure.**
- If credentials are present, or you plan to link an account: that traffic carries your TCC password in effectively unauthenticated transport. Either don't link it, or keep the panel on a segment where you trust everything that can answer `199.62.84.94`.
- **Do not "fix" it by patching the two setopt values to 1.** That breaks the feature outright rather than securing it: the URL is an IP literal so VERIFYHOST fails every request, and with no CA store VERIFYPEER fails too. A real fix means supplying a CA store, setting `CURLOPT_CAINFO`, and putting the hostname back (dropping the `/dnshelper` indirection or using `CURLOPT_RESOLVE`) — much larger, and moot anyway since the TCC MobileV2 endpoint has long been retired. If you want a thermostat service you control, write a new client.

---

## Cross-cutting conclusion from Part 1

Every finding that mattered resolved to the **same defence**, and none to a firmware patch:

> **Network segmentation and no port-forwarding.** 5.3.21.0 is terminal. There is no vendor fix, and for the top three findings there is no setting to change.

The only two on-device configuration changes worth making at all are: `Allow_API:00` if you don't use the REST API (kills findings 5 and 6 outright), and confirming the local-auth checkbox is ticked (finding 7).

---

# PART 2 — THE PRACTICAL ENABLERS

These are the three things that make the repair and extension work actually tractable.

---

## Enabler A — The U-Boot shell

**Bottom line:** the secondary bootloader is a stock-ish **U-Boot 2009.01, built Jun 17 2015 17:52:42**, board "MX35 3STACK", `TEXT_BASE 0x87800000`, with a **fully unlocked interactive shell on UART1**. Autoboot is plain `abortboot`: no `CONFIG_AUTOBOOT_KEYED`, no key sequence, **no password**, no GPIO gate. *(CONFIRMED)*

### Key facts

| Fact | Confidence |
|---|---|
| Prompt is `MX35 U-Boot > `; `start_armboot` ends in an unconditional `for(;;) main_loop();` | CONFIRMED |
| **Any single character** aborts autoboot; no magic key, no password, no `bootstopkey` string anywhere in the 863-string dump | CONFIRMED |
| Window = `bootdelay` seconds, polled **100×/sec** (`udelay(10000)`, 100 iterations) — a held key is reliably caught | CONFIRMED |
| Compiled-in default `bootdelay` = **1 second** | CONFIRMED |
| `bootdelay=-1` → straight to prompt; `bootdelay=0` → zero-length, **uninterruptible** window | CONFIRMED |
| **52 commands** compiled in, table at VA `0x87826b90`–`0x87827070`, 24-byte entries | CONFIRMED |
| Present: `tftpboot nfs dhcp bootp ping setenv saveenv printenv run bootm nand md mm nm mw cp cmp go erase protect nboot loadb loady itest mtest imxtract` | CONFIRMED |
| Absent: `mmc fatload ext2load usb bootz mtdparts env/editenv/askenv date fuse i2c` (I2C is under the older `imd/imm/inm/imw/icrc32/iprobe/iloop` names) | CONFIRMED |
| Environment in NAND: primary `0x1E0000`, redundant `0x200000`, `0x20000` each; 5-byte header, `0x1FFFB` CRC'd | CONFIRMED |
| **`setenv` is RAM-only.** `saveenv_spec` (`0x87816988`) has **exactly one caller** in the whole image — the `saveenv` command handler. Nothing auto-saves. | CONFIRMED |
| `CONFIG_ENV_OVERWRITE` appears defined (the `Can't overwrite "%s"` string is absent) | LIKELY |
| **Vendor patch in `do_bootm`:** if your image fails its header/CRC check, U-Boot **silently** re-reads a kernel from NAND `0x520000`, then `0x820000` (`0x300000` each) into a hardcoded `0x80800000` and boots *that* | CONFIRMED |
| Kernel: Linux 2.6.31-207-g7286c01, legacy uImage, load = entry = `0x80008000`, uncompressed | CONFIRMED |
| `CONFIG_CMDLINE_FORCE` is **not** set (no `Ignoring tag cmdline` string) → U-Boot's bootargs win, `init=` is honoured | CONFIRMED |
| Root-NFS and IP-Config (`CONFIG_IP_PNP`) built in — `root=/dev/nfs` works without an initrd | CONFIRMED |
| Console = UART1 `0x43F90000` = `ttymxc0`, 115200 8N1. UART2/3 not referenced by the bootloader | CONFIRMED |
| **A normally-booted unit offers no serial login** — the getty line in `/etc/inittab` is commented out (`#co:2345:respawn:/bin/sh -i`). U-Boot really is the way in. | CONFIRMED |
| `init=/bin/sh` will work: `/bin/sh` → `bash`, and the static `/dev` has `console`, `null`, `tty` | CONFIRMED |
| Alternative: appending `1` or `single` enters runlevel 1 where inittab respawns `/bin/sh -i` — but `sysinit` still runs first, bringing up more of the system | LIKELY |
| Max command line 255 chars, max 16 args; editing and history compiled in | CONFIRMED |
| No `silent` console option exists | CONFIRMED |
| No `fw_setenv`/`fw_printenv`/`fw_env.config` anywhere in the rootfs | CONFIRMED |
| `nand read` (both the command and the bootm fallback) uses `nand_read_skip_bad` — strictly read-only | CONFIRMED |

Ready-made recipes already in the default environment: `bootcmd_net` (tftp a kernel and boot it — safe) and **`prg_uboot`** (tftp `u-boot.bin`, `protect off`, `erase`, `cp.b`, `saveenv` — **reflashes the bootloader**). *(CONFIRMED)*

### Phase 0 — Serial hardware (the only physically risky step) — **writes nothing, but can destroy the SoC**

1. Power off and disconnect before opening.
2. Locate the UART1 TX/RX/GND pads. **Not determinable from firmware** — find them on the PCB, usually an unpopulated 3–4 pin header near the SoC. Identify GND with a meter against a known ground, unit powered off.
3. Use a **3.3 V TTL** USB-serial adapter (CP2102/FT232 set to 3.3 V). Connect **only three wires**: adapter GND→board GND, adapter RX→board TX, adapter TX→board RX. **Do not connect the adapter's VCC/3V3 to anything.** **Never** use RS-232 (±12 V) or a 5 V adapter — either destroys the SoC UART pins.
4. GND first, then signal.
5. `picocom -b 115200 /dev/ttyUSB0` or `screen /dev/ttyUSB0 115200`; PuTTY: 115200, 8, None, 1, **flow control None**.
6. Sanity-check with a normal boot: you should see U-Boot then kernel messages. If nothing, TX/RX are swapped — fix before proceeding.

### Phase A — Get the prompt — **writes nothing**

1. Terminal open, unit **off**. Start repeatedly pressing **space** (avoid Enter, avoid Ctrl-C).
2. Power on while still spamming.
3. Look for `Hit any key to stop autoboot:  1` then `MX35 U-Boot >`.
4. If it boots to Linux you simply missed the 1-second window. Harmless. Power-cycle and start earlier — the UART RX FIFO buffers keystrokes typed before the banner, so early helps.
5. Excess keystrokes land in your first command line; press Enter once to clear.

Then, **read-only reconnaissance** — log the whole session (`picocom -g` or `screen -L`):

```
version
printenv
bdinfo
nand info
nand bad
```

Record `bootargs`, `bootcmd`, `bootdelay`, `ipaddr`, `serverip`, `ethaddr` verbatim. **The values quoted throughout this document are the compiled-in defaults, used only when the stored env CRC is bad.** If `printenv` shows `*** Warning - bad CRC or NAND, using default environment`, you are on the defaults.

### Phase B — Root shell, no network, nothing written — **writes nothing (do this first)**

Boots the unit's **own** kernel and rootfs with `init=/bin/sh`. `setenv` edits only the RAM copy (verified: `saveenv` is the sole caller of the NAND env writer), so a power cycle restores the unit exactly.

```
printenv bootargs
setenv bootargs ${bootargs} init=/bin/sh
printenv bootargs
```

Read that last line back before continuing.

**Recommended variant** — mount root read-only, because **JFFS2 mounted `rw` writes to NAND on mount** (log replay, write-buffer flush, GC) even if you touch no files:

```
setenv bootargs noinitrd console=ttymxc0,115200 root=/dev/mtdblock16 ro rootfstype=jffs2 init=/bin/sh
```

Substitute the `root=` and `console=` you actually saw. Then load the stock kernel into scratch RAM that avoids **both** `0x80008000` (the kernel's own load address) and `0x80800000` (the bootm fallback target):

```
nand read 0x81000000 0x220000 0x300000
bootm 0x81000000
```

You should see the uImage header (`Linux-2.6.31-207-g7286c01`, load/entry `80008000`), `Starting kernel ...`, then a bash prompt with no login. In the shell:

```
mount -t proc proc /proc
mount -t sysfs sysfs /sys
cat /proc/mtd
cat /proc/cmdline
uname -a
```

**This is the state in which to answer nearly every open question in Part 1** — read `Tuxedo.json`, `registereddevMAClist.json`, `WebConfig.conf`, `thermostats/honeywell/` — all without writing anything.

To return to normal: power-cycle. Nothing persists.

### Phase B′ — Editing a file — **WRITES FLASH**

```
mount -o remount,rw /
cp /etc/hosts /etc/hosts.bak
vi /etc/hosts
sync
mount -o remount,ro /
```

Deliberate and reversible, but no longer zero-write.

### Phase C — Netboot a kernel over TFTP — **writes nothing on the unit**

Only needed for a custom kernel or NFS root.

```
mkimage -A arm -O linux -T kernel -C none \
        -a 0x80008000 -e 0x80008000 \
        -n 'tux-test' -d arch/arm/boot/Image uImage
```

(`-C gzip` with a gzipped Image also works — bootm has gunzip.) Run tftpd-hpa/dnsmasq on the same L2 segment, then:

```
setenv ipaddr 192.168.1.50
setenv netmask 255.255.255.0
setenv serverip 192.168.1.10
printenv ethaddr
ping ${serverip}
tftpboot 0x81000000 uImage
setenv bootargs noinitrd console=ttymxc0,115200 root=/dev/mtdblock16 ro rootfstype=jffs2 init=/bin/sh
bootm 0x81000000
```

If `ethaddr` is missing or all-zero, `setenv ethaddr 02:00:00:00:00:01` (RAM-only). Or `setenv autoload no` then `dhcp`. `ping` first — it is read-only and no-consequence. `nfs 0x81000000 192.168.1.10:/srv/tftp/uImage` is an alternative fetch.

**VERIFY YOUR KERNEL ACTUALLY RAN.** Because of the `do_bootm` fallback, a kernel that never loaded looks like a successful boot. Confirm all four: bootm echoed **your** `mkimage -n` name, not `Linux-2.6.31-207-g7286c01`; `Verifying Checksum ... OK`; no `ERROR :nand read for kernel images` or `All the three kernel images are corrupted`; and `uname -a` in the shell matches your build.

### Phase D — Full NFS root — **writes nothing on the unit, including the rootfs**

Export an unpacked copy of `app2_root` over NFSv3 (`rw,sync,no_root_squash,no_subtree_check`), then:

```
tftpboot 0x81000000 uImage
setenv bootargs console=ttymxc0,115200 root=/dev/nfs rw nfsroot=192.168.1.10:/srv/tux,v3,tcp ip=192.168.1.50:192.168.1.10:192.168.1.1:255.255.255.0::eth0:off init=/bin/sh
bootm 0x81000000
```

(`ip=` is client:server:gateway:netmask:hostname:device:autoconf; `ip=dhcp` also works. Watch the 255-char limit — split via a helper variable and `${}` expansion if you hit `## Command too long!`.) **This is the ideal environment for experimenting** — the unit's NAND is untouched entirely.

### Commands: writes nothing vs writes flash

**WRITES NOTHING — safe:**
`version help ? printenv setenv echo bdinfo coninfo flinfo nand info nand bad nand dump nand read md cmp crc32 base iminfo imls imxtract ping dhcp bootp tftpboot nfs rarpboot bootm boot bootd nboot go sleep itest reset`

**WRITES FLASH / DESTRUCTIVE — never type on this unit:**
- **`saveenv`** — the *only* command that persists the environment; erases and rewrites NAND `0x1E0000` + `0x200000`. Everything above is zero-write precisely because this is never typed.
- **`nand write` / `nand erase`** — writes/erases NAND.
- **`nand scrub`** — erases NAND **including the factory bad-block table**. Unrecoverable; U-Boot's own warning says there is no reliable way to recover them.
- **`nand markbad`** — permanently marks a good block bad.
- **`erase` / `protect`** — NOR erase/unprotect.
- **`cp.b <src> 0xa0000000 …`** — writes the bootloader region.
- **`run prg_uboot`** — present in the stock env; tftps `u-boot.bin`, unprotects, **erases and rewrites the bootloader**, then `saveenv`. **Bricks the unit if it goes wrong.** Never `run <name>` without first `printenv <name>`.
- **`imw` / `imm` / `inm` / `iloop`** — these are **I2C writes**, not memory commands, despite the names. The i.MX35 PMIC is at address 0x08 and U-Boot already pokes registers 0x07/0x1E/0x20 at boot; a wrong PMIC write can kill power rails. `iprobe`/`imd` (probe/read) are fine.
- **`mtest`** — writes patterns over a RAM range; wrong bounds overwrite U-Boot itself (it lives at `0x87800000`).

---

## Enabler B — The partition map

**Found.** It is a static 19-entry `struct mtd_partition[]` compiled into the kernel board file (an MX35 3-Stack derivative), **not** a cmdline `mtdparts=`. Earlier scans missed it for two reasons: 18 of 19 entries use `MTDPART_OFS_APPEND` (offset = `0xFFFFFFFFFFFFFFFF`) rather than literal offsets, so any "contiguous erase-aligned geometry" filter rejects it; and the struct stride is **32 bytes**, not the 20/24/40/48 that were tried.

Array at `vmlinux.bin` file offset **`0x4096C8`** (VA `0xC04116C8`); its owning `flash_platform_data` at VA `0xC0410EBC` holds `parts=0xC04116C8`, `nr_parts=0x13` (19), device name `mxc_nandv2_flash`. *(CONFIRMED)*

### Resolved layout (NAND, 128 KiB erase blocks, all offsets 0x20000-aligned)

| mtd | Offset | Size | Name |
|---|---|---|---|
| 0 | `0x00000000` | 128K | Primary Bootloader |
| 1 | `0x00020000` | 128K | Primary Bootloader Backup |
| 2–8 | `0x00040000`–`0x00100000` | 128K each | Hardware Parameters Block1–7 |
| 9 | `0x00120000` | 256K | Secondary BootLoder 1 |
| 10 | `0x00160000` | 256K | Secondary BootLoder 2 |
| 11 | `0x001A0000` | 256K | Secondary BootLoder 3 |
| 12 | `0x001E0000` | 256K | U-Boot Environment variables |
| 13 | `0x00220000` | 3M | **Kernel 1** |
| 14 | `0x00520000` | 3M | Kernel 2 |
| 15 | `0x00820000` | 3M | Kernel 3 |
| 16 | `0x00B20000` | 180M | **Root File System** (jffs2 = app2.jffs2) |
| 17 | `0x0BF20000` | 58.875M | Second Root File System → `/opt/tuxedo/configuration` |
| 18 | `0x0FA00000` | remainder | PrgCv and BBT |

Fixed span ends at `0x0FA00000` = exactly 250 MiB, leaving **6 MiB** for PrgCv+BBT on a 256 MiB chip. *(chip size LIKELY, not read from the image)*

### The correction that matters

**`root=/dev/mtdblock8` is the kernel's stale compiled-in `CONFIG_CMDLINE`** (`vmlinux.bin` offset `0x17868`). Under this map, mtdblock8 is "Hardware Parameters Block7" — a 128 KiB raw partition that cannot hold a jffs2 root. **The real root is mtdblock16**; U-Boot's ATAG cmdline overrides the built-in one. Anyone anchoring a layout on mtdblock8 is off by eight partitions. *(CONFIRMED)*

### Cross-validation (three independent sources, all agreed)
- Accumulated Kernel 1 offset/size == U-Boot's literal `nand read 0x80800000 0x220000 0x300000`; Kernel 2/3 == the hardcoded bootm fallbacks `0x520000`/`0x820000`. *(CONFIRMED)*
- Index 16 "Root File System" == U-Boot `root=/dev/mtdblock16`. *(CONFIRMED)*
- Index 17 == `/etc/fstab`'s `/dev/mtdblock17 /opt/tuxedo/configuration jffs2`; index 18 == `/dev/mtdblock18`, opened raw by the `tuxedo` binary (error string `could not open mtdblock18 %d`). *(CONFIRMED)*
- `.hdr` container headers place seconboot at NAND `0x120000` load `0x87800000` (independently confirming TEXT_BASE), app1/kernel at `0x220000`, app2/rootfs at `0xB20000`, app3 at `0xBF20000`, ProgCV at `0x0` load `0x80000000`. *(CONFIRMED)*
- `cmdlinepart` and the `mtdparts=` `__setup` token exist in the kernel but are unused — neither U-Boot's bootargs nor `CONFIG_CMDLINE` contains an `mtdparts=` assignment, and the `part_probe_types` slots adjacent to `parts`/`nr_parts` are zero. **The static array is authoritative.** *(CONFIRMED)*

### How to reproduce the find — **writes nothing, no device contact**

The step earlier attempts skipped is #4: don't grep for `mtdparts`, grep for partition **nouns**. The name table is contiguous at `vmlinux.bin` `0x395B04`–`0x395CBD`, right after `mxc_nandv2_flash` (`0x395AB8`) and `Freescale MX35 3-Stack Board` (`0x395A68`).

Then find the array **by name-pointer, not by geometry**. `vmlinux.bin` is raw and links at `0xC0008000`, so VA = `0xC0008000 + file_offset`. For each name string at offset S, search for the LE u32 `0xC0008000 + S`. `Primary Bootloader` (VA `0xC039DB04`) is referenced once, at file `0x4096C8`; the rest follow at exactly `0x20` intervals.

Decode with:
```
struct mtd_partition {          /* 32 bytes, 2.6.31 ARM */
    char     *name;      /*  0 */
    /* 4 bytes padding for u64 alignment */
    uint64_t  size;      /*  8 */
    uint64_t  offset;    /* 16 */
    uint32_t  mask_flags;/* 24 */
    void     *ecclayout; /* 28 */
};
```
`struct.unpack('<IIQQII', d[o:o+0x20])`. Entry 0 has offset 0; entries 1–18 are `-1` (`MTDPART_OFS_APPEND`), so accumulate sizes from 0. Entry 18 has size 0 (`MTDPART_SIZ_FULL`). Confirm `nr_parts` by searching for LE `0xC04116C8` — single hit at `0x408EBC`, followed by `0x00000013` and a pointer to `mxc_nandv2_flash`.

### Verify on hardware — **writes nothing** (Phase B shell)

```
cat /proc/mtd        # expect 19 lines with exactly these names and sizes
cat /proc/cmdline    # shows whether the saved env really passes root=/dev/mtdblock16
```
In U-Boot: `printenv bootargs`, and `nand info` — which settles the true chip size and erase-block size.

### Risks — writes flash / destructive
- **Partitions 2–8 (Hardware Parameters Block1–7)** almost certainly hold per-unit calibration/MAC/serial data. U-Boot prints `Reading hardware paramenter failed` and `HW PARAM READ : All six mirros are bad`, and the env carries a null `ethaddr`, implying the MAC is read from these blocks. **Erasing them is likely unrecoverable without a factory record.**
- This is NAND with bad-block management. The offsets above are **logical MTD offsets**. Any raw read/write must go through `nand_read_skip_bad`/mtd/`nanddump`/`nandwrite`, **never a flat `dd` of the chip**, or bad-block skips shift all data.
- Three redundant copies exist for both bootloader (9/10/11) and kernel (13/14/15). Writing only one leaves the unit bootable from a stale image, and U-Boot silently falls through to copies 2 and 3 — **a flash that appears to succeed can boot the old kernel.**
- Partitions 0/1 could not be verified against any file: no primary-bootloader payload ships in this update package.

---

## Enabler C — The AVR co-processor

**The leading hypothesis is correct: the AVR is the ECP bus front-end.** Confirmed, not inferred — the kernel literally calls it "ECP MICRO" (`###TX TIMEOUT MANY TIMES. RST ECP MICRO.`, `reset_ecpmicro`, `MCU CONF:%d %d %d %d`, `EcpIoctl:`), the AVR dispatches on ECP message-type bytes `0xF0/0xF2/0xF6/0xF7/0xF8/0xFE`, and its USART is 8-data/**even parity**/2-stop — the Ademco ECP frame format. *(CONFIRMED)*

### Part identification
**ATmega164P/PA** (ATmega164/324/644/1284 family I/O map; 1 KB SRAM narrows it to the 164). 31 vectors, SRAM base `0x0100`, `RAMEND 0x04FF` from the SP init; all 31 peripheral addresses touched map cleanly onto that layout. *(CONFIRMED — but see risks: the same image runs unmodified on a 324P/644P/1284P, so read the chip marking before ordering a replacement.)*

**No ADC, no TWI, no analog comparator, no watchdog, no PORTA/PORTB data registers.** It is definitively **not** power/battery management — tamper detection lives in the ARM kernel's LED driver (`tamper_irq` inside the `drvled` block). *(CONFIRMED)*

### The trap that costs the most time
The firmware contains **zero** `in`/`out`/`sbi`/`cbi`/`lds`/`sts` to any peripheral register. Every SFR is reached through a pointer register pair (`ldi r30,lo / ldi r31,hi / ld|st Z`). An exhaustive raw 16-bit scan of all 4,748 words found only SPL/SPH/SREG via in/out — all compiler stack-frame code. **A linear-sweep listing looks like it touches no hardware at all. Do not conclude that.** *(CONFIRMED)*

The way in is a scan for the pointer-pair idiom:
```
for each word a:
  if (m[a]>>12)==0xE and (m[a+1]>>12)==0xE and dest regs are (r26,r27)|(r28,r29)|(r30,r31):
      value = (imm(m[a+1])<<8) | imm(m[a])
  keep values < 0x100, look up in the device SFR map
```
That single scan produced the whole peripheral inventory in one shot and is what identified the part.

### Architecture — a half-duplex ECP modem plus an SPI slave

**Five interrupts only:** INT0 (`0x0704`), TIMER2_OVF (`0x0641`), TIMER1_OVF (`0x0AB3`), TIMER0_OVF (`0x051C`), SPI_STC (`0x0AE5`). The other 26 vectors point at `__bad_interrupt`. *(CONFIRMED)*

- **ECP RX (panel → Tuxedo) on PD2.** INT0 measures pulse widths with Timer2/1024 to classify ECP line events, then a **software bit-banged UART** on Timer2 overflow shifts in 8 data + parity + stop, one sample per bit. **The hardware USART receiver is never enabled** — `RXEN1` is never set anywhere in the image. PD2 is simultaneously RXD1 and INT0 on this part, which is why one pin carries both. *(CONFIRMED)*
- **ECP TX (Tuxedo → panel) on PD3.** Hardware USART1, `UBRR1L=0x9B` (155), `UCSR1C=0x2E` (8E2), and **`TXEN1` is enabled only for the duration of a burst then cleared** — releasing the shared open-collector line. *(CONFIRMED)*
- **Slot response.** Separately, PD3 is driven low directly for `0x48` = 72 Timer2/32 ticks (~192 µs, ~1 bit time) in the assigned slot, iterating slot index 0..7 against **two** stored address values at SRAM `0x02B3` and `0x02B5` — matching the UI's "Tuxedo ECP Address" and "RIS Automation ECP Addr". *(CONFIRMED)*
- **Host link.** SPI **slave** (`SPCR=0xC0`, MISO on PB6 the only driven pin), with **PD4 as an attention/IRQ line into the ARM** — raised when a message is ready, dropped once the host drains it. Kernel counterparts: `spi_irq`, `busint_irq`, `Ext intr req`, `INT_ACK_IN_PROGRESS`. *(CONFIRMED)*
- **Framing timers.** TIMER0_OVF is the end-of-ECP-frame gap (clk/256, 139 ticks ≈ 2.97 ms); TIMER1_OVF is the SPI inter-byte timeout (clk/8, 256 ticks ≈ 171 µs) that resets the link state. *(CONFIRMED)*
- **ECP addresses are pushed down from Linux at runtime**, not compiled in — kernel `MCU CONF:%d %d %d %d`, userspace `ecpIoctl : not able to set ecp device configuration`, ARM symbols `stEcpDevConfig`, `getRisECPAddress`, `getTuxECPAddress`; on the AVR, `0x02B3`/`0x02B5` are written at runtime under cli/sei. *(CONFIRMED)*

**Timing in CPU cycles (crystal-independent — this is the ground truth):** software-RX bit period 74×32 = **2,368 cycles**; start-bit alignment to first sample 106×32 = 3,392 (~1.43 bit times); hardware TX bit period 16×156 = **2,496 cycles**. *(CONFIRMED)* F_CPU is **12 MHz** *(LIKELY)* — two independent anchors agree: ECP is 4800 baud and UBRR=155 needs 11.98 MHz; and the INT0 long-pulse window `0x78..0xB4` at Timer2/1024 is 10.24–15.36 ms, straddling the documented ~13 ms ECP poll pulse. 11.0592 and 12.288 MHz both fit worse.

### What this means for the work
**Yes — the timing-critical half of ECP lives in 9.5 KB of AVR, not in the 14 MB ARM binary.** But the split is lower than it looks. The AVR is a **line-level modem plus slot-responder**: bit timing, framing, poll-pulse classification, address-slot answering. **All message semantics** — F7 display parsing, keypad key encoding, QuickProgramming, supervision counting — are in the ARM's `tuxedo` binary.

> **Changing *what* is said needs no AVR change. Changing *how the wire behaves* (addresses, slot timing, new device classes) does.**

**Do not start by modifying the AVR.** It is a small, tractable 9.5 KB target and that is genuinely significant, but it is the wrong target for most changes.

### Procedure — reproducing and extending — **writes nothing**

Tooling written for this, all under `…\scratchpad\avr\`: `avrdis.py` (a complete-enough AVR8 decoder — all arithmetic/logic, LD/ST including LDD/STD, LDS/STS, LPM, JMP/CALL/RJMP/RCALL, ADIW/SBIW, IN/OUT/SBI/CBI/SBIC/SBIS, all BRBS/BRBC, SBRC/SBRS/BLD/BST, SEx/CLx); `annot.py` (same decoder plus the mega164/324/644 SFR name table, resolving the pointer-pair idiom); `mcu.asm` (full 3,959-line listing).

```
python avrdis.py ..\fw\mcu.bin > mcu.asm
python annot.py 4b9 51c      # the hardware init routine, word addresses in hex
```

1. **Orient.** Vectors `0x0000`–`0x007B`, 31 four-byte `jmp`. Code starts `0x007C` with `eor r1,r1 / out 0x3F,r1` — unmistakable avr-gcc crt0. Read SPH/SPL init → RAMEND; read the `.data` copy loop → flash data base and SRAM extent.
2. **Run the pointer-pair scan** (above). This is the step that unlocks everything.
3. **Identify the part** from three intersecting constraints: 31 vectors, SRAM base `0x0100`, RAMEND `0x04FF`. Verify each recovered SFR is used consistently with its function — `0x29` only read (PIND), `0xCE` only written (UDR1), `0x4E` read in the SPI ISR (SPDR).
4. **Read the init routine first** — word `0x04B9`, reached by the first `call` in `main` at `0x0064`. The entire hardware configuration in ~100 instructions. Decoding `UCSR1C=0x2E` as 8E2 and `UBRR1L=155` is the single most load-bearing fact.
5. **Convert timing to CPU cycles, not microseconds.** Record raw (prescaler × ticks), then solve for F_CPU with an external anchor. **Timer2 has a different prescaler table from Timer0/1** (Timer2: `011`=/32, `111`=/1024; Timer0/1: `011`=/64, `100`=/256). Crossing these produces wrong microsecond figures.
6. **Corroborate against the ARM side** — this is what turned a strong hypothesis into a confirmed one. `vmlinux.bin` strings around byte offset `0x3BC7FC` (the ECP/SPI char driver's message block, adjacent to the zwave and led drivers); and `app2_root\tuxedo`, not stripped, 31,985 symbols — read with pyelftools (the WindowsApps python has it; a bare `python` on PATH does not), filtering for `ecp|Ecp|ECP|Mcu|MCU|Spi|Keypad`. Note `strings` is not on PATH here — use a Python regex over raw bytes.

**To go further, all still static:** unexplored AVR functions worth reading are `0x08E7` (second init call from main), `0x0D66` (returns a flag main branches on), `0x0F48` (called with 0x00/0x01/0x04 — looks like an ECP response-type selector), and `0x0DA4`–`0x0F3F` (the per-message-type ECP handlers — the richest remaining region). **To recover the SPI command set, disassemble the ARM side rather than the AVR**: `th_readEcp`, `th_processEcpOutput`, `th_processEcpInput`, `eil_getMcuFwVers` in `tuxedo`, plus the `/dev/spi` driver near `vmlinux.bin` `0x3BC7B0`–`0x3BC9E0`. The `MCU CONF` ioctl numbers are in there.

**Key SRAM map for reading `mcu.asm`:**

| Address | Meaning |
|---|---|
| `0x0100` / `0x0101` | SPI link state (1/2/3) / phase flag |
| `0x0113` / `0x0114` / `0x0115` | SPI TX index / RX index / RX length |
| `0x011E` / `0x01E8` | last SPI byte received / SPI TX length |
| `0x031A` / `0x037A` | SPI TX buffer (AVR→ARM) / RX buffer (ARM→AVR) |
| `0x0121` / `0x0250` / `0x024B` | ECP line state machine / bit counter / shift register |
| `0x0251` / `0x02B7` | ECP RX byte buffer / RX write index |
| `0x0183` / `0x01EB` | two dispatch copies of a received ECP message (the two addresses) |
| `0x02B3` / `0x02B5` | the two poll-response slot values |
| `0x01E3:0x01E4` / `0x0319` | 16-bit main-loop event flag word / status byte (bit 0x20 = frame in progress) |

### Risks

**Writes nothing (analysis caveats):**
- The 12 MHz crystal is **inferred**. Every microsecond figure scales linearly with it. Measure the crystal before trusting them; reason from the cycle counts.
- There is a real **5.1 % mismatch** between the software receiver's bit period (2,368 cycles) and the hardware transmitter's (2,496). No clean explanation. Could be deliberate early-sampling bias, tolerated sloppiness given per-byte resync, or the two ECP directions genuinely running at different rates. **Do not assume both directions are 4800 baud without measuring.**
- `mcu.asm` is a linear sweep and will desynchronise wherever data is embedded in code — isolated instructions in it can be garbage. Every load-bearing claim above came from alignment-independent raw word scans or hand-followed control flow from a known entry. Treat the listing as a navigation aid, not authority in regions you haven't reached by following flow.
- Vector-index→peripheral mapping depends on the family's ordering. Each ISR body was cross-checked against the registers it touches, so the assignments are sound — but if the part is outside this family the numbering changes.

**WRITES FLASH — the one dangerous operation:**
`MCU.hex` ships inside the firmware bundle, which implies the ARM can **reprogram the AVR** — most plausibly by ISP over the same SPI pins while holding the AVR in reset via the `reset_ecpmicro` GPIO. **This was not verified**, and there is **no bootloader in this image** (it is a bare application starting at `0x0000`). If you ever act on that, **a failed ISP write leaves a bricked ECP interface and a keypad that cannot talk to the panel at all.** Use an external programmer and take a flash backup first. *(mechanism: unconfirmed)*

---

# RANKED NEXT ACTIONS

**Tier 0 — do these before anything else (minutes, zero risk, no device write)**

1. **Check the router's port-forward table.** Nothing to 80, 443, 6280, 9443 or the configured Barracuda port. This single change is the mitigation for findings 1, 2, 3, 4, 5, 6 and 8 simultaneously. *(Everything else is secondary to this.)*
2. **At the panel: confirm "Authentication for web server local access" is ticked.** One read. Settles finding 7. If you unticked it for `ha-tuxedo-touch`, re-tick it — it never helped.
3. **`curl -sS http://<tuxedo-ip>/Config/panelinfo.txt` from another LAN host.** Field 7 is the installer code or `0000`. This is the single highest-value read in the whole document — it converts finding 1 from "confirmed in bytes" to "confirmed on your hardware", and it decides whether you need to change the installer code.
4. **Note the lockout rule** and don't password-fuzz `/login.shtml` unless you're standing at the panel.

**Tier 1 — decide and configure (one deliberate flash write)**

5. **Decide whether you use the REST API.** If not, set `Allow_API:00` in `/root/Settings/WebConfig.conf` and restart the webserver. *(WRITES FLASH — a small, deliberate, reversible config edit.)* This removes findings 5 and 6 entirely and is the only clean, verifiable mitigation available without rebuilding Barracuda. If you do use it, treat the `Browser` PrivateKey as a permanent bearer credential and prune stale entries from `registereddevMAClist.json`.
6. **Sweep the LAN for URL-logging** on port 80 — router parental controls, Squid/Pi-hole, Zeek/Suricata, and **old pcaps in this repo's earlier protocol work**. Purge any captured arm/disarm. If one is found, change the alarm user code.
7. **Network-segment the panel** — VLAN/SSID that untrusted and IoT devices can't reach. This is worth more than the HTTPS toggle.

**Tier 2 — open the box (zero-write, highest information yield)**

8. **Build the serial cable and get the U-Boot prompt.** Phase 0 + A. Capture `version`, `printenv`, `bdinfo`, `nand info`, `nand bad`. This settles the largest single unknown in the document: whether the **live** environment matches the compiled defaults, and whether `bootdelay` is 0 (which would make serial interruption impossible).
9. **Phase B: `init=/bin/sh` with `ro` root.** Zero-write root shell on the unit's own kernel and rootfs. In that shell, read — and only read — `Tuxedo.json` (settles the LocalLogin fail-open question and the HTTPS toggle), `registereddevMAClist.json` (hands you the Browser key/IV directly), `WebConfig.conf`, `thermostats/honeywell/` (settles finding 9 in one `ls`), `/proc/mtd`, `/proc/cmdline`. **This one session answers most of the Open Questions below.**
10. **Run the seed sweep offline** with the IV recovered in step 9. glibc `rand()`, 1356998400 + 900 seconds. A hit proves 2013 seeding on your hardware and hands you the key.

**Tier 3 — the interop and repair work proper (still zero-write on the unit)**

11. **Phase C/D: netboot with NFS root.** The ideal experimentation environment — the unit's NAND is untouched entirely, including the rootfs. Do all firmware experimentation here. **Always verify your kernel actually ran** (the silent NAND fallback).
12. **Recover the SPI command vocabulary from the ARM side**, not the AVR: `th_readEcp`, `th_processEcpOutput`, `th_processEcpInput`, `eil_getMcuFwVers`, and the `/dev/spi` driver strings. Faster than more AVR work and gives you the `MCU CONF` ioctl numbers.
13. **Read the AVR's unexplored ECP handler region** `0x0DA4`–`0x0F3F` to pin down what each of F0/F2/F6/F7/F8/FE does at the line level.
14. **Build your own client** with the corrections from Part 1: `/handlerequest.html` is a flat command bus (Type 1/2/3/4, `pID` is a bitmask, `uCode=0`→`0xffff`); REST tokens are stable per endpoint and can be precomputed; never put `ucode` in a query string.

**Explicitly NOT worth doing**
- Patching `installVirtualDir` to move `/Config/` under `authenticateDir` — unless you're already rebuilding, and it breaks video playback.
- Replacing the SharkSSL demo cert — bricking risk on a security panel for a cert nothing trusts.
- "Fixing" `thermostatclient`'s setopt values to 1 — breaks the feature rather than securing it, and the endpoint is retired.
- Reprogramming the AVR. Most ECP behaviour you'd want to change lives in the ARM binary.
- Reporting the empty-authtoken defect upstream as an "auth bypass" — it will be correctly rejected.

---

# OPEN QUESTIONS

### Settleable in the Phase B zero-write shell (highest priority)
1. **Does `/Config/panelinfo.txt` exist on your unit, and is field 7 a real code or `0000`?** Depends on whether the Tuxedo has completed a CAL info sync with a paired Vista.
2. **What does `Tuxedo.json` actually contain?** No copy exists in the carve. Decides: `BARRACUDA[0].LocalLogin` (finding 7 and its fail-open corollary), `HTTPS` (finding 2's mitigation), `PORT_NUMBER` (which extra listeners exist).
3. **Are the `thermostats/honeywell/username` and `password` files present and non-empty?** One `ls` decides whether finding 9 is live or dormant.
4. **Does `registereddevMAClist.json` exist, and how many identities are enrolled?** Each entry is another PublicKey unlocking finding 6's `decrypt()`→`abort()` path.
5. **Which seed produced your `Browser` key?** Settleable offline in minutes once you have the IV. Requires a glibc-compatible `rand()`.

### Settleable at the U-Boot prompt
6. **What are the LIVE contents of the NAND environment at `0x1E0000`?** Everything quoted here (`bootdelay=1`, `bootcmd`, `bootargs`, absent `ipaddr`/`serverip`) is the **compiled-in default**, used only when the stored env CRC is bad. **This is the single fact that decides whether the whole U-Boot procedure works** — if the manufacturer programmed `bootdelay=0`, serial interruption is impossible without NAND/JTAG intervention or boot glitching.
7. **Is the stored env CRC currently valid?** Visible as the `*** Warning - bad CRC or NAND, using default environment` banner.
8. **True NAND chip size and erase-block size.** Read at runtime by chip ID, absent from the image. `nand info` settles it; decides whether "PrgCv and BBT" is 6 MiB or 262 MiB.
9. **Does the Ethernet PHY come up under U-Boot, and is `ethaddr` recovered from the Hardware Parameters mirrors?** `printenv ethaddr` and `ping` answer it; if all mirrors are bad, TFTP will not work.
10. **Which of mtd9/10/11 does the primary bootloader execute, and are all three the same build?** `version` should print `U-Boot 2009.01 (Jun 17 2015 - 17:52:42)`.
11. **Is the rootfs on mtd16 or mtd17?** Defaults and the update container both say mtd16, but a field-updated unit could differ. Read `root=` from `printenv bootargs`.
12. **Is `verify` set in the live environment?** It controls whether bootm checks the image data CRC — and therefore whether a corrupt download can silently trigger the NAND-kernel fallback.
13. **Is the NOR flash referenced by the default env (`uboot_addr=0xa0000000`, `erase`/`protect`/`flinfo`) actually populated**, or a leftover from the MX35 3STACK reference design? **Do not experiment with those commands to find out.**

### Requires the board, a scope, or a schematic
14. **Physical location and pinout of the UART1 TX/RX/GND pads.** Not in firmware. Blocks everything in Enabler A.
15. **The AVR's actual crystal frequency.** Not determinable from the binary; every microsecond figure scales with it.
16. **The 5.1 % RX/TX bit-period mismatch** — deliberate, tolerated, or evidence that the two ECP directions run at different rates? Needs a scope on the bus.
17. **The exact AVR part marking.** ATmega164P by the SRAM constraint alone; a 324P/644P/1284P would run the same image unmodified.
18. **What PD6 is** (toggled on host SPI byte `0xEF`) — heartbeat, test point, or a real board signal? And **why DDRC is all-outputs when PORTC is never written.**

### Requires further static work
19. **The full SPI command vocabulary.** Confirmed: `0xFE` (host requests upload), `0xEF` (toggles PD6, purpose unclear). Others likely in AVR functions `0x0D66`/`0x0F48`; the ARM-side ioctl constants would settle it faster.
20. **The semantics of each ECP type at the AVR level** (F0/F2/F6/F7/F8/FE). F7 is corroborated as the supervision/display broadcast by ARM symbol names; the rest are in the unexplored `0x0DA4`–`0x0F3F`.
21. **What the 3.07–5.03 ms and 0.51–4.18 ms INT0 pulse windows correspond to** in ECP. The 10.24–15.36 ms window is clearly the poll/sync pulse.
22. **The four values in `MCU CONF:%d %d %d %d`.** Two are almost certainly the Tuxedo and RIS ECP addresses (matching AVR slots `0x02B3`/`0x02B5`); the other two are unidentified.
23. **Where the AVR emits its firmware version** in response to `eil_getMcuFwVers`. The 4-byte `.data` section (`03 01 01 00`) is tempting but those addresses are SPI link-state variables — initial state, not a version tuple.
24. **Which `/system_http_api` endpoints are LAN-gated** versus reachable remotely. Not enumerated; it bounds a remote attacker's blast radius for findings 5 and 6 by an unmeasured amount.
25. **Is the SharkSSL demo credential the same one shipped in the public SharkSSL/Barracuda SDK?** If so the key is already public and "extract from firmware" isn't even required. Could not be checked offline.
26. **The on-flash record layout of Hardware Parameters Block1–7.** Confirmed they exist, are 128 KiB each, and hold the MAC; the parser is near seconboot string `0x201C1` if you want it.
27. **What ProgCV (the primary bootloader, mtd0, loads at `0x80000000`) does before handing off** — in particular whether it touches UART1, which affects how early buffered keystrokes survive. A separate 468 KB image, not analysed.
28. **Whether the AVR is field-reprogrammed via SPI ISP from the ARM**, or some resident mechanism. No bootloader in the image points to ISP, but this is unconfirmed — and getting it wrong bricks the ECP interface.