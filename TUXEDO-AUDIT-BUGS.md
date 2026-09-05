# Tuxedo Touch TUXW_V5.3.21.0 — `/handlerequest.html` Implementation Spec and Findings

Firmware: TUXW_V5.3.21.0 · Platform: Freescale i.MX35, ARM32 LE, Linux 2.6.31 · Owner: Lewis (repair / interoperability)
All evidence is static analysis of `…\scratchpad\fw\carved\app2_root\opt\webserver\Barracuda`, `…\scratchpad\fw\carved\app2_root\tuxedo` (both with intact `.symtab`) and the extracted web app at `…\scratchpad\webapp`. **Nothing has been executed against the panel.** Every recipe below is a hypothesis with a stated first test.

---

# PART 1 — IMPLEMENTATION SPEC: the second API

## 1. The push channel (lead item — this was cracked)

The highest-value finding: **`/handlerequest.html` is fire-and-forget. It never returns a command result.** Results, status changes and keypad text all arrive on a completely separate, always-on push channel. If you implement only the command endpoint you will get `Message Sent` and nothing else, forever.

### 1.1 What it is

Barracuda's classic **EventHandler** push plugin, mounted as one virtual directory: **`/SimpleDebugger.interface`**. Installed by `initAndInstallServlet` @0x0001dd94, which does `EhDir_constructor(&simpleDebugger.ehDir, "SimpleDebugger.interface", server, NULL)` then `HttpDir_insertDir(server->rootDir, dir)`. CONFIRMED.

It is not long-polling and not a queue you drain. It is one long-lived HTTP response. `EhDir_service` @0x0007a380 dispatches on `relPath[0]` with `relPath[1]=='.'`:

| Sub-path | Transport | Response |
|---|---|---|
| `C.` | control / RPC | `text/plain`, header `EhVer: 4.0` |
| `G.` | "Gecko" push | `Content-type: multipart/x-mixed-replace;boundary="EH912ZZ"` |
| `I.` | iframe push | endless `text/html` `<script>` stream |
| (upgrade) | WebSocket | RFC6455 handshake, GUID `258EAFA5-…` present @0x005485e8 |

CONFIRMED. Note the WebSocket path is implemented server-side but **commented out in the shipped `eh.js`** (script/eh.js:857-861) — it has never been exercised by the vendor's own UI on this firmware. Do not start there.

### 1.2 Registration is implicit — you never send code 500

Opening the push connection makes Barracuda call `SimpleDebugger_newClientCon` @0x0001def4, which (a) greets that connection with `statusMessageText("Client Connected")` + `noOfClient(n)`, and (b) calls `sendRegisterCommand(0x1f4 = 500 = SERV_CLIENT_REGISTER)` @0x0002e86c, posting the 404-byte struct to the tuxedo app. That is what turns the panel's broadcast firehose on. CONFIRMED.

Corollary, and it matters: **`SimpleDebugger_vprintf` @0x0001e040 DROPS every message when `noOfClients == 0`.** There is no backlog. A client that reconnects sees nothing until the next state change — so always seed state from a synchronous read (§1.6) immediately after connecting.

### 1.3 Wire format (Gecko transport — recommended for a non-browser client)

Each event on the wire:

```
--EH912ZZ\r\nContent-type: text/plain\r\n\r\n[<payload>]\r\n--EH912ZZ--\r\n
```

Data payload shape: `'ud','<Interface>','<Method>',[<args>],<len>`. So a complete frame body is

```
['ud','SimpleDbgServer2ClientIntf','statusMessageText',["<colon-separated record>"]]
```

Control frames: `['setCid',N]`, `['startPushCon']`, `['unknownCid']`, `['recycled']`, `['onError',N,'msg']`, `['onClose','No access']`. CONFIRMED (`GeckoPage_pushConPrePostFmt` @0x0007786c, `JsEncode_fmt` @0x000788a4).

**Three parsing traps, all CONFIRMED from `BufPrint_jsonString` @0x00063050:**

1. Strings are double-quoted but bytes > 0x22 pass through **raw**, including 0x80–0xFF. The partition flag byte 0xFE/0xFF arrives raw — **decode the socket as latin-1, not utf-8**, or you get `UnicodeDecodeError` on every status frame.
2. It emits `\'` as an escape, which is **not legal JSON**. `json.loads()` raises on any text containing an apostrophe. Replace `\'` with `'` before parsing.
3. Every real broadcast is followed by **exactly three filler frames whose command field is `-1`** (emitted at 0x0000db0c/db30/db50 for cmd 21, and equivalently for 20/22/504/1). They force a stream flush and carry nothing. **Discard any record whose field 1 is `-1`** or you will see phantom duplicates.

### 1.4 Record grammar

All broadcasts arrive through the same method (`statusMessageText`) with one string argument. Field 0 is a session id: **`0` = broadcast to everyone**, non-zero = addressed to the client holding that `hidSession`. There is **no server-side filtering** — `bflush` @0x0001df84 → `EventHandler_sendData2All` @0x00079120 sends everything to every connected client. Filtering is your job.

**Command-response envelope** (commands 1,2,3,4,5,6,7,8,9,25,26,27,29):

```
<sessionID>:<command>:<subCommandId>:<nextPacket>:<partitionNumber>:<responseText>
```

`E_SUBID_*` values, which live **here** and not in the 21/22 broadcasts:

| subId | meaning |
|---|---|
| 1 | valid user code |
| 2 | invalid code |
| 3 | declined |
| 4 | declined with message (text in field 5) |
| 5 | go to partition-selection screen |
| 6 | **partition description** (one record per partition, ≤4; `nextPacket==0` = last) |
| 7 | **partition status** (`responseText` = FLAG+CSS+text) |
| 8 | end of transmission |
| 9 | quick-arm status update (value in `nextPacket`) |
| 10 | user code required |

**Free capability:** `script/eventHandler.js` `armingDisarmingCMD()` has cases 1,2,3,4,5,6,9,10 but **no case 7** — the vendor PC theme silently discards sub-id 7 per-partition status records. A custom client gets them for nothing. Panel side: `CReceiverThread::sltSendPartitionDetailsToWebClient(int)` @0x0014696c stores literal 7. CONFIRMED.

**Code 21 — `SERV_PARTITION_MSG_BROADCAST`** (`0:21:…`):

```
0:21:<panelStatusCode>:<fe|ff>:<FLAG><CSS><text>:<quickArmStatus>
```
- `FLAG` is a raw 0xFE/0xFF byte (0xFF → 'd' deny disarm; 0xFE → 'a' allow), repeated as hex in field 3
- `CSS` is an ASCII digit 1/2/3 = normal / warning / caution
- `text` e.g. `Ready To Arm`, `33 Secs Remaining`
- `panelStatusCode` is `-1` when `PanelIsTalking()==0`

Source: Barracuda `gettuxedoIPCCommFunc` @0x0000da80-0x0000db88 (fmt `%d%s%d%s%d%s%x%s%s%s%d`), tuxedo `CReceiverThread::sltSendChangedPartitionStatus(int)` @0x00144880. CONFIRMED.

**Code 22 — `SERV_PANEL_OFFLINE_MSG_BROADCAST`**: `0:22:<FLAG><CSS><text>:<panelStatusCode>` — same shape, no separate hex field. Emitted when `GetOnlineStatus() != 1`. CONFIRMED.

**Code 20 — `SERV_CONSOLE_MSG_BROADCAST`**: `0:20:2<line1>|<line2>` — the `2` is the CSS digit (the literal separator is the 2-char string `":2"` @0x000852f4). Keypad lines are `|`-separated. Barracuda replaces **only the first** `:` inside the console text with `-` (and only when pos>0); reverse it with a single replace. CONFIRMED.

**Code 504 — `SERV_REG_INI_RESP_DATA`**, the answer to registration, 8 fields:

```
0:504:<currentPartitionNo>:<partitionDescription>:<panelCalImplementation>:<operationMode>:<totalPartitions>:<zwaveControllerStatus>
```
`operationMode`: 0 normal / 1 safe / 2 demo / 4 …. From tuxedo `CReceiverThread::registerclient()` @0x0013c2f8. CONFIRMED.

**Teardown:** `checkvalidSessions` @0x0000d364 emits `<sessionId>:Logout`; a dropped client broadcasts plain `Logout`. Special-case any record containing `Logout` **before** splitting on `:`. CONFIRMED.

### 1.5 Parsing rule that will save you

Colons in panel text are **not** escaped for status or partition-description strings (only for code-20 console text, and only the first one). The vendor's own JS therefore indexes **from the right**: `result[result.length-1]`, `[len-2]`, `[len-3]`. Do the same. Left-to-right splitting will break on a partition named e.g. `Shop: Rear`.

### 1.6 Two synchronous status reads that bypass everything

Both of these solve the documented `GetSecurityStatus` cache bug outright, without touching that cache:

**(a)** `GET /eventhandler.html` with the session cookie renders live status server-side:
```
var systemmode=<n>;var curStatus="<21|22>:<a|d><CSS><text>:<panelStatusCode>";
```
built by `setPartStatus` @0x0002ba74 into global `partStatus` @0x0055b6d4, refreshed on **every** code-21/22 IPC message. The same page carries `hidSession`, `hiddenKey` and `var quickArmStatus=`. One authenticated fetch gives you session, token and live status. CONFIRMED.

**(b)** `GET /handlerequest_mobile.html?commandID=5001&param3=<SID>&tokenkey=<TOK>&…` returns
```
<html><body>21:a1Ready to Arm:1:qastatus=0</body></html>
```
synchronously (handler @0x000484cc, fmt `<html><body>%s:qastatus=%d</body></html>` @0x00543b9c). The vendor mobile theme polls this every 10 s. CONFIRMED.

**Recommendation for a Home Assistant integration: use (b) or (a) as the authoritative seed and heartbeat, and the push channel as the low-latency path.** That combination is robust against the no-backlog behaviour and against the client-registration fragility in §2.6.

---

## 2. Session and token model

### 2.1 The gating answer

**Yes — a client that has already logged in the REST way can reach `/handlerequest.html` with the same login and the same session.** There is only one login on this box. Both APIs authenticate through the identical Barracuda `FormAuthenticator` mounted on the single protected directory `/authenticated`, whose only page is `index.html` (`authPage_service` @0x1418c). Nothing else on the server — not `/handlerequest.html`, not `/eventhandler.html`, not `/tuxedoapi.html` — is under HTTP authentication at all. `installVirtualDir` @0x14598, page registrations 0x146c0-0x147f8. CONFIRMED.

### 2.2 The two values

**`sessionid`** — the Barracuda `HttpSession` id (u32), created by `HttpRequest_getSession` @0x71830. Not secret, not separately issued. The session cookie's 16-hex value is literally `lowerhex8(session_id) || lowerhex8(session_creation_unix_time)` (`HttpSession_fmtSessionId` @0x71100), so:

```
sessionid = int(cookie_value[0:8], 16)   # decimal
# sanity: int(cookie_value[8:16],16) ≈ now
```
CONFIRMED. Or scrape `<input id="hidSession" value="N">`.

**`tokenkey`** — a CSRF token, **31 lowercase hex chars**, generated **once per session slot** in `addSessionItem1` @0x2b444: `random_string(32)` → `getKeyFromPassword` → `EVP_BytesToKey(aes-256-cbc, md5, 1 iter)` → first 16 key bytes hex-printed → truncated to 31 by a stray NUL at `out[31]`. **It does not rotate** — not per request, not per page load, not per command; only a new session slot mints a new one (`getCSRFToken1` @0x2b3bc is read-only; `addSessionItem1` is guarded by the "does this session already own a slot" flag at 0x14334/0x144d8). This is the same generator that produces the REST API's 31-hex `Random` header, which is why both are 31 and not 32. CONFIRMED.

The **only** way to obtain `tokenkey` is to scrape a generated HTML page. `/eventhandler.html` and `/console.html` emit it; `/tuxedoapi.html` does **not**.

### 2.3 Cookie

Name is **fixed per Barracuda process**: `main` @0xc6ec does `sprintf(BA_COOKIE_ID, "z9ZAqJtI_%u", time(NULL))`. It looks random per login only because it changes when the web server restarts. `/handlerequest.html` reads **only** this cookie — never `_zFL`. CONFIRMED.

> ⚠️ **The single most likely integration failure.** If your existing REST client keeps only `_zFL`, or drops cookies across the login redirect, `/handlerequest.html` will reject you with a silent empty body. Use a cookie-jar-backed HTTP session and follow redirects. Which response carries the `Set-Cookie` for `z9ZAqJtI_*` (the POST itself or the 302 target) is **UNKNOWN** — the jar makes it moot.

### 2.4 Lifetime and limits

| Property | Value | Evidence |
|---|---|---|
| Idle timeout | `Session_Timer` minutes from `/root/Settings/WebConfig.conf` = **10 min** on this unit | `getMaxSessionTimeOut` @0x7177c; conf file |
| Concurrent sessions | `No_Of_Users` = **10** on this unit; exceeding → logout + `/Msg503.html` | `getNoOfUsers` @0x312a4; `authPage_service` 0x14350-0x14384 |
| IP binding | Session bound to source IP; changing IP loses it | `HttpRequest_getSession` 0x71a5c, `HttpRequest_session` 0x71064 |
| Explicit kill | `GET /logout.html` | `LogOutPage_service` @0x135e8 |

Practical consequence: **do not re-login per poll.** Ten slots, reaped only when the underlying `HttpSession` dies. A client that re-logs every 30 s will exhaust the table. Cache cookie + sessionid + tokenkey for the life of the session; poll more often than every 10 minutes.

### 2.5 The auth gate, exact order

`handlerequest_html076EF::service` @0x3a2a0, gate 0x3a2cc-0x3a48c. CONFIRMED.

1. `Type = U32_atoi(getParameter("Type"))`
2. `sess = HttpRequest_getSession(req, create=0)` — never creates
3. `id = U32_atoi(getParameter("sessionid"))`; **if `sess != NULL` this is overwritten with `sess->id`** (0x3a33c)
4. `flag = sess ? getRemoteAccess(sess->id) : -1`; if `-1` then `flag = checkforlocalremote(req) ? 1 : getLocalLoginStatus()`
5. reject to `Session_Expired` **only** when `sess == NULL && flag != 0`
6. `tok = getCSRFToken1(id)`; NULL → empty body
7. compare stored Token against the `tokenkey` **HTTP header** if present, else the `tokenkey` **query parameter**; missing or mismatch → empty body
8. if `flag != 0`: require `sess != NULL` **and** `atoi(getParameter("sessionid")) == sess->id`, else empty body
9. only now the `Type` switch runs

`checkforlocalremote` @0x2ddd0 is **not** a netmask test: it string-compares the first three dotted octets of the peer IP against `boardIP`, returning 1 when they differ.

### 2.6 Bootstrap sequence (implementable today)

```
1. GET  /authenticated/index.html?url=eventhandler.html          (no cookies)
     → headers  Random: <31 hex>   RandomID: <1..24>   Set-Cookie: _zFL=…
       (challenge valid 600 s — resetSessionRandomKeys @0x2d65c, 0x258 s)

2. POST /authenticated/index.html?url=eventhandler.html
     Cookie: _zFL=…
     log  = HMAC-SHA512(key = the 31-hex Random AS LITERAL ASCII, msg = lower(user))
     log1 = HMAC-SHA512(same key,               msg = lower(user)+password)
     identity = <RandomID>
     → Set-Cookie: z9ZAqJtI_<digits>=<16 lowercase hex>   ← KEEP THIS ONE

3. sessionid = int(cookie_value[0:8], 16)         # no extra request needed
   GET /eventhandler.html  (with that cookie)
     → scrape id="hiddenKey" value="([0-9a-f]{31})"   → tokenkey
       scrape id="hidSession" value="(\d+)"           → cross-check sessionid
       scrape var curStatus="…"                       → seed live status
     Guards: hiddenKey == "-1" → session has no slot, re-login.
             hidSession == 1234567 (0x12D687) → no-session fallback.
             302 to /authenticated/index.html?url=home.html → cookie invalid.

4. GET /SimpleDebugger.interface/C.?cmd=S   → EhVer header + ['startPushCon']
5. GET /SimpleDebugger.interface/G.         → stream (this auto-registers you)
```

**Total cost on top of the existing REST login: two extra round-trips.**

**First live test, and it validates the entire model in one shot:** log in the REST way, `GET /eventhandler.html`, check that (a) `hiddenKey` is 31 hex and not `-1`, and (b) `hidSession == int(cookie[0:8],16)`. Then `Type=138` (§3.4) as the end-to-end smoke test — it is synchronous and has no side effects.

### 2.7 Dead ends, stated so nobody re-derives them

- **`Type=3180` is not a second login scheme.** The constant 3180 (0xC6C) does not exist anywhere in Barracuda (verified by literal-pool and ARM-immediate scan; control scans on 0x189A and 0x465/0x466 did hit, so the scan works). `login2.html`'s `verifyLoginInfo()` is commented out of `validateCredentails()`; the live path is a plain MD5 form POST, a legacy variant of the same one login. CONFIRMED.
- **`sid` is a pure cache-buster.** Never read. The complete set of parameter literals dereferenced inside the service was extracted from the full 17988-byte disassembly; `sid` and `connectionID` are absent. CONFIRMED.

---

## 3. Request and response format

### 3.1 Canonical request

```
GET /handlerequest.html?cmd=<T>&Type=<T>&pID=<parts>&uCode=<code>&sessionid=<SID>
     &filters=0&index=0&tarTemp=0&tokenkey=<TOK>&sid=<random>
Cookie: z9ZAqJtI_<digits>=<16 hex>
```
Optionally send `tokenkey` as an HTTP **header** instead — it is checked first, and when present the query parameter is ignored. That keeps the token out of URLs and logs; **prefer the header.**

**Dispatch is on `Type`, not `cmd`.** `cmd` is read by only a handful of handlers (notably Type=2). Every vendor client sets `cmd == Type`; do the same. CONFIRMED, 0x3a2cc → switch at 0x3a48c.

Methods: **GET and POST only** — `cspCheckCondition` @0x664b8 passes mask 0x12 = GET|POST; anything else → 405 with `Allow`. POST body decoding is *inferred* from Barracuda's `HttpParameterIterator` and **not proven**; **use GET**, as every vendor client does.

### 3.2 Parameter semantics

**`pID`** — pipe-separated 1-based partition list (`"1"`, `"1|2|3"`, trailing pipe fine). Server: `strtok(pID,"|")` then `mask |= 1 << (atoi(tok)-1)`. `pID=-1` yields a shift of -2, i.e. **mask 0** — so `-1` is only meaningful for Types that ignore `pID`. **Always send `pID` explicitly**, even for those: `getParameter` is NULL-safe and the code will call `strtok(NULL,"|")`, resuming whatever tokenisation ran last. CONFIRMED.

**`uCode`** — and this asymmetry matters:
- Types 1, 2, 4, 6-10: `v = atoi(uCode); if (v==0) store 0xFFFF else store v`. **0xFFFF is the quick-arm / no-code sentinel.**
- **Types 3 (disarm) and 5: no substitution.** A real user code is mandatory; `uCode=0` queues literal 0 and the panel rejects it.

CONFIRMED (0x3a994-0x3a9b4 vs 0x3ab3c-0x3ab54).

**`filters` / `index` / `tarTemp`** — ignored by every security command. Keep them for byte-parity with the vendor client.

### 3.3 Response format — three outcomes, all HTTP 200

Headers are always `Content-Type: text/html; charset=utf-8` plus `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` (`HttpResponse_setDefaultHeaders` @0x6b004, `HttpResponse_noCachHeaders` @0x6afd0), usually chunked.

| Body | Meaning | Recovery |
|---|---|---|
| `<html><body>Message Sent</body></html>` | queued OK — **no result, no error status** | wait on the push channel |
| **empty (zero bytes)** | tokenkey missing/wrong, OR `sessionid` ≠ cookie session id, OR no CSRF slot | re-scrape `/eventhandler.html`; then re-login |
| `Session_Expired` (**plain text, no HTML tags**) | session gone | re-login |

String evidence: `Message Sent` @0x539804; the "empty" sink prints VA 0x548310 which is a **zero-length string**; `Session_Expired` @0x53982c. CONFIRMED. Note the mobile endpoint wraps its version in `<html><body>…</body></html>` — the desktop one does not.

A `Message Sent` with nothing happening also means either an unrecognised Type (default branch) or a server-side no-op (504, 1118). There is **no numeric error code, no JSON, no XML** anywhere in this API's error path.

### 3.4 Per-command recipes

**`Type=1` — ARM AWAY**
```
cmd=1&Type=1&pID=1&uCode=1234&…
```
Ack + push `<SID>:1:<subId>:<nextPacket>:<part>:<text>`, then a `0:21:…` broadcast when the panel actually changes. `uCode=0`/omitted → quick-arm (0xFFFF). Handler 0x3a908; calls `setCurrentV5WebData(0x0D)`. CONFIRMED.

**`Type=2` — ARM STAY.** The **one exception**: it reads the `cmd` parameter and queues *that* as the command (0x3a9fc/0x3aa8c). Always send `cmd == Type`. CONFIRMED.

**`Type=4` — ARM NIGHT.** Same shape as Type=1. Handler 0x3ab84.

**`Type=3` — DISARM**
```
cmd=3&Type=3&pID=1&uCode=<real code>&…
```
**Real code mandatory** (no 0xFFFF substitution). Handler 0x3aad0, `mov r3,#3` at 0x3ab64, `setCurrentV5WebData(0x0E)`. Push subId 2/3 = code rejected. CONFIRMED.

**`Type=5` — GET PARTITION LIST**
```
cmd=5&Type=5&pID=-1&uCode=<code>&…
```
Push: a run of `<SID>:5:6:<nextPacket>:<partNo>:<description>` records (≤4), plus the normally-discarded `:5:7:` per-partition status records, `nextPacket==0` = last, subId 8 = end. This is the enumeration step the vendor UI runs before multi-partition arming. LIKELY (envelope CONFIRMED; the exact run for *this* panel untested).

**`Type=18` — GET HOME PARTITION**
```
cmd=18&Type=18&pID=-1&uCode=0&…
```
Push has **only four colon fields, not six** — parse from the right:
```
<SID>:18:<partNo><space><description>:<quickArmStatus>
e.g.  123456:18:1 Main Floor:2
```
`quickArmStatus`: 0 unknown / 1 disabled / 2 enabled. Server also updates `zoneDescCopy` and calls `HomePartChanged()`/`setQuickArmStatus()`. The vendor JS echoes `Type=1118` back afterwards; **1118 is a server-side no-op (handler 0x3b520) — skip it.** CONFIRMED.

**`Type=138` — GET SYSTEM TIME. The only fully synchronous security-band command, and your smoke test.**
```
cmd=138&Type=138&pID=-1&uCode=0&…
```
Body is the RFC-1123 date **concatenated directly** with the ack (the handler prints then falls through):
```
Sat, 05 Sep 2026 14:03:22 GMT<html><body>Message Sent</body></html>
```
Take everything before the first `<`. `baTime2tm` @0x618b8 is pure epoch arithmetic with **no timezone**, so this is the panel clock rendered as UTC. No IPC, no push event. Handler 0x3e438. CONFIRMED.

**Multi-partition: `Type=6/7/8/9`** (all partitions: away/stay/night/disarm) and **`Type=25/26/27/29`** (explicitly selected set). `pID=1|2|3`. **28 is not implemented.** Vendor flow: Type=5 to enumerate, then 25/26/27/29 with the chosen list. CONFIRMED.

**`Type=19` — CONSOLE MODE (live keypad).** `pID` carries the keystrokes as a `|`-separated list of **decimal ASCII codes**: `pID=|49|50|51`. `pID=-1` = zero keys, meaning "turn the feed on / re-push the cached display" — with zero keys **nothing is transmitted to the panel** (`requestconsolemode` @0x13db5c takes the `beq` at 0x13db6c). Keys go into the same ECP transmit queue the physical keypad uses (`apl_sendEcpConsoleModeData`), so they are byte-for-byte equivalent to pressing keys on a wired keypad.

Key encoding: 48-57 = `0`-`9`, 42 = `*`, 35 = `#`, **65/66/67/68 = A/B/C/D = the panic keys**. The vendor UI gates those behind a confirmation dialog; **the server does not distinguish them from a digit.** Display text arrives as the code-20 broadcast. Handler 0x3cc94; count at msg[0x2e], bytes from msg[0x2f]. CONFIRMED.

> ⚠️ If you expose Console Mode in Home Assistant, filter 65-68 in your own client. Nothing below you will.

**`Type=1125/1126` — CONSOLEMODESTATUSADD/SUB.** A Barracuda-local counter (`consoleMode` @0x55b7d8) with **no message to the panel at all**. Its only effect is to gate Types 502/503. See Bug (a)-2 — it leaks. CONFIRMED.

**`Type=502/503` — BACK/HOME.** Forwarded to the panel *only* when `getConsoleMode()==0`.

**`Type=501`** — its handler is on the **authorisation-failure** path (see Bug (b)-6). Do not use it.

### 3.5 The IPC struct, if you ever go below HTTP

404 bytes (0x194), memset to zero at entry, sent via `osal_MqSend(mq_send6280App, buf, 0x194)`. Layout for security commands: `+0x00` u32 sessionId, `+0x04` u32 command, `+0x08` u32 partition bitmask, `+0x0C` u32 userCode; console mode adds `+0x2e` u8 key count, `+0x2f…` key bytes. Everything else zero. Queues: `/Q_ServCmdTrsmtr` (556×32) and `/Q_ServCmdRcver` (404×32). CONFIRMED. **Beyond offset 0x10 the struct was not mapped** — that layout lives in the tuxedo queue reader.

### 3.6 Full Type dispatch map

Entry addresses inside `handlerequest_html076EF::service`, enumerated from the comparison chain 0x3a48c-0x3a904:

`1`→0x3a908 `2`→0x3a9ec `3`→0x3aad0 `4`→0x3ab84 `5`→0x3ac54 `6`→0x3ad00 `7`→0x3adb4 `8`→0x3ae68 `9`→0x3af1c `10`→0x3afd0 `12`→0x3ca38 `13`→0x3ca94 `14`→0x3cae0 `15`→0x3cb2c `16`→0x3cbe0 `17`→0x3c9b0 `18`→0x3b550 `19`→0x3cc94 `25`→0x3b05c `26`→0x3b108 `27`→0x3b260 `29`→0x3b1b4 `52`→0x3b614 `54`→0x3b9bc `55`→0x3ba48 `56`→0x3bad0 `57`→0x3bb38 `58`→0x3bb80 `59`→0x3bbe4 `100`→0x3c3a4 `101`→0x3b460 `500`→0x3b42c `501`→0x3cf44 `502`→0x3b3ac `503`→0x3b3ec `504`→0x3b488 `506`→0x3d1b4 `600`→0x3d1d0 `800`→0x3d25c `888`→0x3cf64 `1118`→0x3b520 `1121`→0x3cfd0 `1122`→0x3d064 `1123`→0x3d130 `1125`→0x3d24c `1126`→0x3d254 `1152`→0x3b59c `1250`→0x3c5b4; video Types 6285/6287/6288/6290/6297/6298/6400-6403 in the 0x188d-0x189d block; 103-153 prefixed `SERV_ZW_` are Z-Wave. **`28` is not handled.**

> ⚠️ The two agents that enumerated this **disagree on completeness**. One reports the chain fully unwound with no zone code anywhere; the other says the immediate-comparison dispatch tops out around 0x480 with higher codes reached via literal-pool loads it did not fully unwind. Treat the map as **near-complete but not proven exhaustive**.

**ZONES: still a negative.** Both agents searched independently and found no zone command code. The zone handlers exist in `tuxedo` (`sltRequestAllZoneCurrStatus` and 11 siblings) but nothing in the web dispatch reaches them. `Type=17` (handler 0x3c9b0) queues `{sessionId, 17, pID-or-0xFF, filters, index}` into a *second, non-zeroed* 404-byte stack buffer and has no name in any vendor JS; the `filters`/`index` pair makes it *look* like a paged list query. **It is unidentified, not evidence of a zone command.** If you probe it, do so knowing it sends a struct with uninitialised stack bytes to the panel.

### 3.7 A third endpoint: `/handlerequest_mobile.html`

`handlerequest_mobile_html076EF::service` @0x47dd0 (6644 bytes). Different vocabulary: `commandID`, `pID`, `session`/`param3`, `usercode`, `tokenkey`, `param2..param7`, `Mode`, `clientID`, `sid`. Same CSRF check. **Simpler and more synchronous** — it returns real data:
- `commandID=5001` → `<html><body>21:<a|d><CSS><text>:<code>:qastatus=<n></body></html>` (live partition status)
- `commandID=5002` → `<html><body>20:<line1>|<line2></body></html>` (live keypad display — a plain poll, no push channel needed)
- `commandID=5011` → `<html><body>%d:%d:%d:%s</body></html>` from `getuserCodeStatus(session)`
- `commandID=19/500/502/1125/1126` mirror the desktop Types
- `Session_Expired` here **is** wrapped in `<html><body>`

CONFIRMED. **For a Home Assistant integration this is arguably the better surface** — a 10-second poll of 5001 + 5002 needs no multipart parsing, no latin-1 handling, and no filler-frame filtering. Recommend prototyping here first, then adding push for latency.

---

## 4. Marked holes — do not guess past these

| # | Hole | Status |
|---|---|---|
| H1 | **Nothing tested on hardware.** Every recipe is static analysis. | UNKNOWN |
| H2 | **Does `/SimpleDebugger.interface` require the session cookie?** Evidence points to *no* — the EhDir is inserted into the plain root dir with no authenticator, and `newClientCon` returns 0 unconditionally so `['onClose','No access']` never fires. Neither agent could fully trace `HttpDir_authenticateAndAuthorize`'s parent walk. **If an unauthenticated `GET /SimpleDebugger.interface/G.` streams live alarm state, that is a LAN disclosure the owner must know about — test it deliberately.** | UNKNOWN, security-relevant |
| H3 | **Agents disagree on the CSRF token's provenance.** One traced `addSessionItem1` @0x2b444 fully (31 hex chars, one-per-slot, never rotates) and found its call sites in `authPage_service`/`MyPage_service`. The other found **zero BL callers** for it and declared alphabet/length/rotation UNKNOWN. The first account is more specific and internally consistent; **treat the token as opaque, re-scrape on any empty body**, and the disagreement costs you nothing. | CONFLICT (resolvable by test) |
| H4 | **`getLocalLoginStatus()` is a runtime value.** It decides whether a cookie-less same-/24 client can drive the API with a borrowed (sessionid, tokenkey) pair. Reading of the gate says yes when the global is 0. **Do not design around it; use the cookie.** Security implication in (b)-5. | UNKNOWN |
| H5 | **POST body decoding unproven.** Use GET. | LIKELY-not-verified |
| H6 | **Filler-frame multiplexing.** Each event is emitted 3-4 times with differing leading session ids (real, then -1); why is unclear — probably one emission per EventHandler instance. Ignore `-1`. | UNKNOWN |
| H7 | **WebSocket transport untested.** Server speaks it; the vendor UI never has. A 5.x-era Barracuda may use draft framing. | UNKNOWN |
| H8 | **Code-21 trigger cadence inferred, not proven.** `sltSendChangedPartitionStatus` is a Qt slot whose incoming connections could not be resolved. Almost certainly change-driven. **If you need a guaranteed heartbeat, poll 5001.** | LIKELY |
| H9 | **Type dispatch map completeness** — see §3.6. | CONFLICT |
| H10 | **`Type=17` purpose** — unidentified. | UNKNOWN |

---
---

# PART 2 — BUGS AND IMPROVEMENTS

**Dropped for weak refutation: one.** The CAL multi-record parser bug (`CalManager::AnalyzeResponse` @0x581918, stale look-ahead byte latched outside the copy loop) is a real code defect and the finder honestly refuted his own larger overflow claim — but he could not establish that this panel ever emits a multi-response CAL frame, and since `RequestResponseProcessing` only ever consumes record 0, the multi-record path appears never to have been exercised. It cannot be substantiated as affecting anything. Noted here for anyone writing an independent CAL decoder: **don't rely on that function's record splitting; split frames yourself.**

Everything else survived its own refutation attempt and is kept.

---

## (a) Affects him today

### a-1. Three failed logins permanently disable **every** web account — **SEVERITY: HIGH · CONFIRMED**

`updateLoginFailureCount` @0x1537c (Barracuda), called from `LoginTrackerIntf_LoginFailed_func` @0x13a24 on each failed login. It increments that user's `accLockedCount`, then guards a second loop with `cmp r6,#1 / ble` — so from the **3rd failure onward** it walks **all five** WEBUSERS slots. Inside that loop, `cmp r0,#3 / bne 0x155fc` sets `accountLocked=1` only for entries at count 3 — but the `bne` **jumps into** the next block, so `json_pop_back("status"); json_new_i("status", 0)` executes **unconditionally for every account**. Raw bytes verified: 0x155cc `030050e3`, 0x155d8 `0700001a`, 0x1560c `0010a0e3`.

`readUserNamePasswordFromJSON` (sole caller `MyUserDB_getPwd` @0x14f4c) skips any entry whose `status != 1` (0x14ddc `cmp r0,#1` / `bne`). So a `status=0` account supplies no credential, ever.

**The recovery path is asymmetric and that is the killer.** `resetLoginFailureCount1` @0x136d4 rewrites `accLockedCount`, `accLockedTime` and `accountLocked` — and **never touches `status`**. A whole-binary scan for the `"status"` key literal @0x8d768 returns exactly five sites: one reader in the auth path, one writer (this one, value 0), and three unrelated readers. **No function in Barracuda ever writes `status=1`.** The result is AES-encrypted and installed over the real file via `validateCRCFileOnFileWrite` — **persistent across reboot**.

**Impact:** three typos on one account locks Lewis out of his own panel's web interface permanently. A successful login can never happen again to clear it. Reboot does not help.

**Refutation (thorough):** the finder initially assumed the `status=0` write was inside the `count==3` branch and corrected himself from raw bytes. He looked for a time-based auto-unlock (`accLockedTime` has no reader anywhere — no expiry). He confirmed `status` means "account enabled" from the filter chain. He found `resetLoginFailureCount` (no trailing 1) has zero callers and also doesn't write status. He checked the trigger is the 3rd failure, not the 1st, so as not to overstate. **Could not determine:** whether the tuxedo local touchscreen UI rewrites this JSON with `status=1` when a web user is edited — no reference to the `WEBUSERS`/`accountLocked` literals was found from tuxedo code, so the local repair path is unverified.

**Fix:** no client-side workaround. Recovery = decrypt `/opt/tuxedo/configuration/webuseraccountsenc.json`, set `status:1 / accLockedCount:0 / accountLocked:0`, re-encrypt, fix the CRC sidecar `webuseraccountsenc_sec.json`. Or try re-creating web users from the touchscreen (unverified). **Mitigation available right now: use a password manager for the panel and never hand-type it.**

### a-2. First visit to the web keypad kills Back and Home **forever** — **SEVERITY: MEDIUM · CONFIRMED**

Global `consoleMode` @0x55b7d8, three accessors, no other references image-wide: `setConsoleModeAdd` @0x2aad4 (++), `setConsoleModeSub` @0x2aaec (-- clamped ≥0), `getConsoleMode` @0x2ab08. Both Type=502 and Type=503 handlers (0x3b3ac, 0x3b3ec) begin `bl getConsoleMode / cmp r0,#0 / bne <ack>` — nonzero means the command is **silently dropped**, never forwarded to the panel, with a normal-looking response to the browser.

`disableBackBtn()` (consoleRequest.js:156) sends 1125 every time the keypad page loads. The only sender of 1126 is `goBack(pageIDNo)` (eventHandler.js:912) **and only when `pageIDNo == 1`** — and a grep of the whole web app finds all three live `goBack` call sites pass **no argument**. The one `goBack(1)` is inside a commented-out `onunload`. **1126 is never sent by the shipped UI at all.** The counter is strictly monotonic. Nothing decrements on logout or session expiry.

**Impact:** after the first web-keypad visit, Back and Home in the web UI are dead until Barracuda restarts — and the next keypad visit re-arms it.

**Refutation:** the finder's first theory (self-healing via a normal Back press) was killed by the grep. He verified `setConsoleModeSub` has exactly two BL callers, both the cmd-1126 arms. He checked the mobile app — its SUB send is inside `/* */` too. He decoded the literal pool rather than guessing 502/503 from the compare chain, and confirmed both gated arms genuinely forward the 0x194 struct.

**Fix — and this one Lewis can do today:** send `Type=1126` once per keypad visit from your own client to drive the counter back to 0. One-line web-app fix: restore the commented-out `onunload goBack(1)`.

### a-3. Web-facing partition-status poller is **dead code** — **SEVERITY: MEDIUM · CONFIRMED**

`CReceiverThread::getPartitionDetails(char*)` @0x140480 is the only place that creates the poll timer (`new CTimer2(0x61)` @0x140510), connects `sigWebStatusReq()` → `sltPartitionDetailReqTimeout()`, sets 2000 ms, starts it, and tail-jumps into the slot. **A whole-image scan of every PT_LOAD segment for any B/BL targeting 0x140480 and for any data word equal to 0x140480 returns nothing.** The SIGNAL/SLOT literals @0x5daa58 and @0x5daa6c are referenced exactly once each — inside that same dead function. The only other occurrence of the slot name is the moc metaobject table, which dispatches by index.

So the slot is reachable only through `qt_static_metacall`, which needs a connection or an `invokeMethod` that no code performs. And `RequestPartitionStatus(int,bool)` @0x585c28 has exactly two BL callers: this dead-connected slot, and `CGo2Partition::sltStatusReqTimeout()` @0xac778 — **the local touchscreen's Go-To-Partition screen.**

**Impact:** nothing in the web path ever asks the panel for per-partition status. Panel-derived partition data refreshes only as a side effect of somebody standing at the keypad. This is a **second, independent** cause of the stale-remote-status symptom, on top of the already-documented empty-cache default.

**Refutation (exemplary):** BL-only scan → none. Widened to all B/BL forms including conditional (checking bits 27:25) → none. Scanned every PT_LOAD including data for a function-pointer word → not in any vtable. Considered `invokeMethod` by name — the only name string is the moc blob, and moc dispatches by integer index, so an unconnected slot with no invokeMethod is genuinely dead. He also **declined to report** the malloc leak and stale-static-index defects inside that function as live bugs, since they sit in dead code.

**Fix:** firmware patch to re-connect the timer. **Owner mitigation today: drive partition status explicitly from `/handlerequest.html` Type=5/18 or poll mobile `commandID=5001` — which is exactly what Part 1 recommends anyway.**

### a-4. The web interface is effectively **single-client** — **SEVERITY: MEDIUM · CONFIRMED**

`CReceiverThread::registerclient()` @0x13c2f8 **opens** by calling `osal_MqFlush(mpl_msqIdSendToServer)` — the 32×556 tuxedo→Barracuda queue — before composing its reply. Every `SERV_CLIENT_REGISTER` therefore **discards every queued response and broadcast** for whatever client was already connected. The constructors do the same.

Client bookkeeping is not a count: `clients_connected` @0xd2f268 and `F7_Mesgs_enabled` @0xd2f269 are single bytes. `unregisterclient()` @0x13c00c unconditionally zeroes both. `F7_Mesgs_enabled` gates the very top of `wsltHandleRawDataFromPanel` (returns immediately when 0) and is **also cleared by `home_back_press()`** — i.e. by any Home/Back press from any session.

**Impact:** opening the panel's web UI in a second tab or on a phone silently wipes the first one's queued updates; then pressing Back/Home in one session, or closing it, stops the live keypad display in the other. Symptom: a web UI that intermittently freezes or blanks with no error. **Directly relevant: a Home Assistant integration holding a push connection is a second client.**

**Refutation:** checked whether `clients_connected` is a counter incremented elsewhere — the reference scan shows no increment site. Checked whether the flush is first-client-guarded — it is the first thing the function does, before any state test. **Honestly flagged** that this may be intentional single-client design; kept because the failure is silent and cross-session. **Could not determine** whether Barracuda serialises registrations such that a second is impossible while a first is live — hence medium, not high.

**Fix:** no owner-side fix. Practical workaround: **one web client at a time.** If HA holds the push connection, expect the browser UI to fight it — which is another argument for the poll-based mobile endpoint.

### a-5. Event-log retrieval retries forever, every 20 s, with no cap — **SEVERITY: MEDIUM · LIKELY**

State at `[this+0x50a4]`. `setEventIndex()` @0x13e818 issues `AskFromPanel(0x53)`/state 2 or `AskFromPanel(0x55)`/state 3 and starts a 20 s timer (0x4e20). `panelResponseTimeout()` @0x13e978: state 2 → call `setEventIndex()` again (re-issue, re-arm); state 3 → re-issue `AskFromPanel(0x55)`, **write state 3 again**, restart the same timer. **No retry counter, no backoff, no give-up branch.** The only exits are the success paths (`wsltEventDescRcvd`, `sltSetEventIndex`).

**Impact:** if the panel doesn't answer — busy, in programming mode, offline, or the command unsupported on that panel firmware — the same ECP request goes out every 20 s indefinitely, permanent avoidable keypad-bus traffic, and the web-side request never completes and never errors. Event log spins forever instead of failing cleanly.

**Refutation:** looked for a retry cap in both functions — the only nearby counters are the event index and category index, neither bounds retries. Checked for an outer watchdog — all `stop()` calls on that timer are response-driven. Verified the timer restarts with the interval rather than being one-shot. **LIKELY not CONFIRMED because** he could not establish that an unanswered 0x53/0x55 actually occurs on Lewis's panel; if it always answers, the loop always terminates.

**Fix:** firmware. Mitigation: don't repeatedly re-trigger event-log upload if it hangs; restarting tuxedo clears the state.

---

## (b) Security exposure on his own LAN

### b-1. `uCode` — the alarm user code — travels in a **GET query string over plain HTTP** — **SEVERITY: HIGH · CONFIRMED**

Every command is `GET …&uCode=<4-digit code>&…&tokenkey=<31 hex>&sessionid=<id>`. The code typed into the keypad dialog is copied **verbatim** (armcontrolscript.js:221/235/303 → `hiduCode` → `sendCommand`); the server does `U32_atoi` on it, which only makes sense for cleartext. Barracuda's `openSocketCon` @0x0000c848 constructs **two plain `HttpServCon` listeners** (0x0000c938, 0x0000c990) in addition to the SharkSSL one, and the vendor's own doc strings use `http://` examples.

**Impact — this is the most practical attack on a LAN Lewis otherwise controls.** One captured arm/disarm yields three things: **the panel user code in cleartext, the sessionid, and the tokenkey.** That triple disarms the alarm at will for the life of the session. Passive capture is enough: ARP spoofing, a SPAN port, a compromised IoT device, or just Wi-Fi. The code also lands in proxy logs and browser devtools history.

**Refutation:** traced `hidUserCode`/`hiduCode`/`txtuCode` through three scripts looking for client-side hashing — copied unmodified. Looked for a kill switch disabling the plain listener — none found; the HTTP port is user-configurable (default 80, string @0x00530604), so plain HTTP is a configured service, not dead code. **Could not determine** whether Lewis's unit currently has the HTTP listener reachable — **that is a one-command check on his LAN.**

**Fix (config, no patch):** use only the HTTPS port; firewall TCP/80 to the panel at the switch/AP. **And in your own client, send `tokenkey` as an HTTP header** (§3.1) so at least the CSRF token stays out of URLs — the `uCode` still doesn't, which needs firmware.

### b-2. All web secrets come from `srand(time(NULL))` — **one second of entropy** — **SEVERITY: HIGH · CONFIRMED**

`random_string()` @0x0001d5d4 calls `time(NULL)` then `srand()` on **every invocation**, then builds the string with `rand()%62`. glibc `rand()` is fully deterministic per seed, so the entire output is a pure function of the current UNIX second. It is the only randomness source for web secrets, with three consumers:

1. `LoginResp_service` @0x000133dc → the `Random` login-challenge header. **The `strb r3,[r7,#0x1f]` NUL write at 0x0001d704 is exactly why `Random` is 31 hex chars and not 32** — the long-standing observation now has a cause.
2. `addSessionItem1` @0x0002b444 → **the `tokenkey`** compared by strcmp on every `/handlerequest.html` call.
3. `generateKeyForAPI` @0x0001d96c → the REST API AES-256 key and IV.

Second-order: two `random_string()` calls in the same second return **identical** strings.

**Impact:** none of these is a secret against an attacker who can bound the generating second. Reconstruction is offline, one MD5 per candidate second. For `tokenkey`, someone who knows roughly when Lewis logged in has ~10²-10⁴ candidates for the token that authorises **every** command — arm, disarm, keypad keys, panic. For the login `Random`, a captured `log1` cracks offline with no rate limit and no nonce to guess.

**Refutation:** cross-referenced every caller of `random_key` and `random_string` across the whole binary (manual BL decode over all executable sections). `random_key` has **zero** callers (dead). `random_string` has exactly four, all listed. Checked whether `srand` might be called once at startup with a better seed — no, it is inside `random_string` at 0x0001d5e8, per call. Checked for `/dev/urandom` or `RAND_bytes` in the auth path — SharkSSL has its own RNG but none of the three functions touch it.

**Fix:** firmware. Mitigation: keep the panel off any segment an untrusted device reaches; use HTTPS so the token isn't also on the wire.

### b-3. REST AES key/IV is a **permanent, global device secret** minted at first boot with the clock at **01 Jan 2013** — **SEVERITY: HIGH · CONFIRMED (scoping) / LIKELY (seed window)**

`generateKeyForAPI` @0x0001d96c runs once from `barracuda()` @0x000108b8 (single BL xref image-wide). It derives key+IV from a `random_string` passphrase via `EVP_BytesToKey` and stores them as `PrivateKey`/`PublicKey` on a device node whose `DeviceMAC` is the literal string `"Browser"` in `/opt/tuxedo/configuration/registereddevMAClist.json`. It **first walks the list and returns without writing if a "Browser" node already exists** (0x0001db18-0x0001db50). Generated exactly once, on the first boot where that file has no Browser node, then persists forever. Per-**device**, not per-session, not per-user — the same blob every browser reads from `<input id="readit">`.

The seed is `time(NULL)` at Barracuda startup, and `/etc/rc.d/init.d/startup` sets the clock first: **if `/opt/tuxedo/configuration/datetime` is absent it runs `date 0101000013`** — 01 Jan 2013 00:00:00. That config directory is **empty** in the firmware image.

**Impact:** anyone who recovers this key/IV decrypts and forges every REST payload and `authtoken`, **permanently**. Logging out, changing the web password and rebooting do not rotate it. Only a factory reset does. On a first-boot-derived key the offline search space is roughly the seconds between `date 0101000013` and Barracuda's start — **tens to a few hundred candidates.**

**Refutation:** tried to show the key is per-session (it's read from a page per login, so plausible) — refuted: single call site, short-circuits on the existing node, no login path rotates it. Tried to show the file ships pre-populated (which would mean a factory key, not first-boot-derived) — the config dir is empty in the carve. **Could not determine** whether that directory lives on a separate JFFS2 volume absent from this carve, so the exact seed window on Lewis's unit is unverified — hence the split confidence.

**Fix:** firmware. Partial owner mitigation: a factory reset performed while the clock is NTP-correct (so `datetime` exists) widens the seed window considerably — still time-seeded, still global.

### b-4. **No per-command authorisation**, and the URL ACL is Barracuda's leftover demo data — **SEVERITY: HIGH · CONFIRMED**

`handlerequest_html076EF::service` does exactly three checks (session/locality, token non-NULL, token strcmp) and falls straight into the Type switch. **Across the whole 17988-byte function there is not a single call to `AuthenticatedUser_*`, `MyUserDB_user2Roles`, or any role/level accessor.**

Worse, the realm's authoriser `MySecurityRealm_authorize` @0x0001dcb4 walks a 5-entry table at `securityDB` @0x0008b8b8 whose path prefixes are **Barracuda's shipped sample data — `family/dad`, `family/mom`, `family/kids`, `family`** — and **returns 1 (ALLOW) when the loop exhausts with no prefix match** (0x0001dd7c). No real panel URL begins with "family". And `MyUserDB_user2Roles` @0x00014a50 is a two-instruction stub: `mov r0,#1; bx lr`.

**Impact:** there is no privilege separation in the web interface. Any account that can log in — including one Lewis created as "limited" — can drive every command: arm/disarm, multi-partition, console keypad mode (including the A/B/C/D panic keys), cameras, scenes. The only thing between a low-privilege web user and a disarm is the panel user code, validated over ECP by the panel, not by the web layer.

**Refutation:** assumed the check might live upstream of the handler, so traced the realm/authoriser path instead of trusting the handler — that's how `securityDB` and the `user2Roles` stub surfaced. Searched for a second real ACL table and for any alternative `AuthorizerIntf` installer — the only reference to `MySecurityRealm_authorize` is one data word at 0x0001dcb0. Checked whether the account JSON carries a privilege field — it holds `userName`, `passWord`, `u8UserId`, `status` only, used for selection and enable/disable, not gating.

**Fix:** firmware. **Mitigation now: treat every web account as full-privilege. Do not create "limited" web users expecting them to be limited.**

### b-5. With `LocalLogin=0`, any host on the /24 gets pages, a session and a tokenkey with **no credentials** — **SEVERITY: HIGH · CONFIRMED (code) / effective state UNKNOWN**

Every page handler follows one pattern. `armcontrol_html076EF::service` @0x000445b8: if no session and `checkforlocalremote(req)==0`, set `r6 = getLocalLoginStatus()`; then `cmp r6,#1 / bne` — **the `AuthenticatedUser_get1` check and the login redirect happen only when `r6 == 1`.** Any other value renders the page — which embeds `hidSession` and `hiddenKey`. The same call heads the handlers for home, console, consolekeypad, index, mobileview, devicelist, camerasetup, videoscreen, eventhandler and more.

`localLoginStatus` is loaded by `setLoginForLocal` @0x0002bf50 from `/opt/tuxedo/configuration/Tuxedo.json`, key `BARRACUDA[0].LocalLogin`, **defaulting to 1 (safe) only if the file cannot be opened.** `checkforlocalremote` is the first-three-octets string comparison, not a netmask test.

**Impact:** if the "require login for local access" setting is off, an unauthenticated device on the same /24 loads armcontrol/consolekeypad/home, **harvests sessionid and tokenkey straight out of the HTML**, then issues commands. Arming with `uCode=0` is forwarded with the 0xFFFF placeholder. Console mode forwards raw keypresses **including A/B/C/D, which on a Honeywell panel need no user code and will signal fire/police/medical.** Disarm still needs a valid code. The /24 heuristic also mis-classifies flat 10/8 or 192.168/16 LANs in both directions.

**Refutation:** tried to show the pages gate on something else after rendering — they don't; the fall-through leads to rendering. Tried to establish the shipped default so as to say whether this is live on Lewis's unit — **`Tuxedo.json` is not in the extracted rootfs (config dir empty), so the effective value is UNKNOWN.** The code default when the file is missing is the safe one, so this bites only if the setting was turned off. Stated explicitly rather than assuming the worst.

**Fix — pure config, no patch, and it's the single highest-value action in this document:** verify `BARRACUDA[0].LocalLogin = 1` on the panel (the "require login for local access" setting).

### b-6. `Type=501` is processed **on the authorisation-failure path** — **SEVERITY: LOW · CONFIRMED**

When the session/locality gate denies a request it branches to 0x0003e85c, which is **not** a plain error return: it compares Type against 0x1F5 (501) and on a match jumps to 0x0003e648, which reads `sessionid`, writes command 0x1F7 (503, HOME) into the struct and calls `osal_MqSend` to the tuxedo app. This happens **before and instead of** the token comparison. No session, no cookie, no token required.

**Impact:** an unauthenticated client — including a genuinely remote one that fails the subnet check — can inject a HOME command into the panel's IPC. Practically that pushes the touchscreen back to Home. Low direct harm, but it is a **real pre-auth path into panel IPC**, a reliable liveness oracle, and repeated use makes the touchscreen unusable.

**Refutation:** checked whether the 0x194 buffer might leak stack contents on this path — it does not, both branches memset first, so this is **not** a memory-disclosure primitive (the finder deliberately downgraded his own claim). Checked whether 0x0003e85c is dead code — it is the target of the `beq` at 0x0003a3b8, i.e. exactly the unauthenticated-remote case.

### b-7. Session cookie has **no HttpOnly, no Secure**; the token is a cookie-less bearer credential; session ids are **invertible** — **SEVERITY: MEDIUM · CONFIRMED**

Three things in one place:

**(i)** The gate denies only "(no session **and** flag set)". With no cookie at all, a same-subnet client while `localLoginStatus==0` falls through to the token check — and the sessionid used for the lookup is then the **query parameter**, since the overwrite at 0x0003a33c only happens when a session exists. So **possession of `sessionid` + `tokenkey` alone is sufficient.**

**(ii)** `HttpRequest_getSession` @0x00071aac creates the cookie with `setValue`/`setPath("/")`/`activate` and calls **neither** a secure nor an HttpOnly setter — even though Barracuda has `"; HttpOnly"` @0x0053f3f0 and `"; secure"` @0x0053f3fc in its formatter. Also: the cookie **name** is `sprintf("z9ZAqJtI_%u", time(NULL))` fixed at process start — **not random per login**, correcting an earlier assumption — and that same timestamp is echoed into the login page as `var server="…"`.

**(iii)** The cookie value is `hex(session->id) ++ hex(creationTime)`, where `session->id = baGetMsClock() * 0x75BCD15`. **0x75BCD15 is odd, so the multiply is a bijection mod 2³²** — any observed sessionid inverts to the device's exact millisecond uptime. An attacker with one legitimate low-privilege session can compute the panel's clock and enumerate a narrow window of candidate ids for another session; the second half of the cookie is just the login's UNIX second.

**Refutation (notably honest):** he **specifically tried to prove classic session fixation and failed** — `HttpRequest_getSession` never adopts a client-supplied id; it looks the cookie value up in a splay tree and mints its own on miss. **Fixation is therefore NOT a finding and he did not report it.** He re-derived the ARM condition codes at 0x0003a3a0-0x0003a3b8 (`rsbs`/`movlo` giving `r3 = !r0`) twice by hand to confirm the cookie-less case falls through. **Could not confirm** how narrow the id-prediction window is in practice — the inversion property is CONFIRMED, the practical prediction attack is LIKELY.

### b-8. "Remember Password" encrypts credentials with a key **printed in the login page** — **SEVERITY: MEDIUM · CONFIRMED**

`validatelogin.js`, when the box is ticked, sets cookies `data1` (username) and `data2` (password) for **365 days**, AES-CBC encrypted with `reqStrLen` as key and `reqStrLen1` as IV — both built by **repeating the page-global `server` string** to 32 and 16 hex chars. `server` is not a secret: `login_shtml076EF::service` @0x0003835c emits `var server="%s"` from `getServerStartTime()` @0x0002df3c — the Barracuda process start time, in plaintext in the login page HTML, and also embedded in the session cookie **name**. Cookies set via bare `document.cookie` — no HttpOnly, no Secure, no SameSite. Separately, the older `webapp/script/login.js` writes `userName`, `userPassword` and `latestuserpwd` ("user:pass") with **no encryption at all**.

**Impact:** anyone who reads the browser cookie jar for the panel origin — shared computer, browser-data stealer, or any script in the panel's origin given the missing HttpOnly — recovers the web password in plaintext, because the decryption key is published on the login page of the same server. 365-day lifetime.

**Fix:** **do not tick "Remember Password."** Clear existing `data1`/`data2`/`userName`/`userPassword`/`latestuserpwd` cookies for the panel origin.

### b-9. REST `authtoken` is a **static per-endpoint value** covering neither body nor nonce — **SEVERITY: HIGH · CONFIRMED**

`tuxapi.js` builds it as `HmacSHA1("MACID:Browser,Path:API_REV01/<endpoint>", api_key_enc)` — the HMAC input is a **constant string per endpoint**, and `api_key_enc` is the global permanent device key from b-3. The body is `param=<b64 ciphertext>&len=<len>&tstamp=` + **`Math.random()`** — `tstamp` is not a timestamp at all, it's a random float, and it is **not covered by the HMAC**. `identity` is just the IV hex, also global.

**Impact:** every request to a given endpoint carries the same token for the life of the device. Anyone who observes one call (see b-1 — a plain-HTTP listener exists) obtains a **permanent** credential for that endpoint, surviving password changes, logout and reboot. There is no replay window to close because there is no replay protection. With the key itself (b-3) they mint tokens for every other endpoint.

**Refutation:** searched the binary for a nonce/timestamp store or monotonic counter checked against `tstamp`, and for any per-session token component — the only per-request inputs are the endpoint path and the global key; nothing server-side consumes `tstamp`. Considered that the session cookie might additionally be required on `/system_http_api` — vendor doc strings (@0x0007ea00) say the authtoken header is the auth mechanism and is "Not applicable for browser clients", implying browser clients are authorised by session instead. **He could not locate the `/system_http_api` dispatcher, so the severity for a token-only, cookie-less attacker is UNKNOWN.** The static-token property itself is CONFIRMED.

---

## (c) Stale components — ranked by **reachability**, not CVE count

Ranked by what actually touches attacker-influenced input on Lewis's LAN.

**1. Barracuda Application Server 5.x, HTTP request path — MAXIMUM reachability.** Every finding in (b) is here. This is a ~2013-era embedded web server parsing unauthenticated HTTP on the LAN, with session management, cookie handling, multipart push, form auth and an ACL layer that (b-4 shows) is **still populated with the vendor's shipped demo data**. Nothing about the version matters next to that: the reachable defects are already enumerated and each has an address.

**2. glibc `rand`/`srand` as the security RNG — MAXIMUM reachability, zero exploitation cost.** Not "stale" so much as never appropriate. See b-2. `/dev/urandom` exists on this kernel; the code chose not to use it. Every web secret on the box depends on this.

**3. OpenSSL `EVP_BytesToKey(md5, salt=NULL, count=1)` — HIGH reachability.** Used in all three key derivations (`getKeyFromPassword` @0x0001d648, `generateKeyForAPI`). Single-iteration, unsalted MD5 KDF: a deprecated construction even when this shipped. It is what turns a 31-char low-entropy passphrase into "the" AES key with no work factor to slow a candidate search (b-2, b-3).

**4. SharkSSL (the HTTPS listener) — HIGH reachability, but UNASSESSED.** It is the mitigation Part 2 recommends for b-1, so its own state matters. Neither agent examined its version, cipher suites, or certificate handling. **This is a hole in the assessment, not a clean bill of health** — see Open Question OQ-5.

**5. Linux 2.6.31 kernel — MODERATE reachability.** Reachable only after something in userspace is already compromised, i.e. it is a privilege-escalation surface rather than an entry point. Not the thing to fix first; it is also the thing Lewis cannot fix at all without a kernel rebuild.

**6. The legacy login pages (`login.js`, `login2.html`) — LOW reachability, trivially removable.** `login.js` writes cleartext credential cookies (b-8); `login2.html` carries a commented-out MD5 login path and the phantom `Type=3180`. Dead weight that still ships and still confuses reverse-engineers.

**7. The `webapp/autogen/` EventHandler stubs — ZERO reachability, but they cost debugging time.** `PartitionsPage.interface` and `IPCamerasPage.interface` do not exist in Barracuda (verified by string scan), so `changePartitionScript.js:275`, `CPScript.js:337` and `camAddEdit.js:528` open EventHandlers that **404**. Ignore `autogen/` entirely; the live channel is the one `eventHandler.js:750` opens.

---

## (d) Unused capability worth switching on

**d-1. Sub-id 7 per-partition status — free, already flowing, silently discarded.** `sltSendPartitionDetailsToWebClient` @0x0014696c emits per-partition status records, and the vendor PC theme's `armingDisarmingCMD()` has no `case 7`. A `Type=5` gets you the whole partition list **with live status per partition**, for nothing. This is the cleanest path to real Home Assistant partition entities. CONFIRMED.

**d-2. The mobile endpoint as the primary integration surface.** `/handlerequest_mobile.html` `commandID=5001` (partition status) and `5002` (live keypad display) are **synchronous, parse in one line, and need no push channel at all**. Given a-4 (single-client fragility), H2 (push auth unknown) and the three parsing traps in §1.3, a 10-second poll of 5001+5002 is very likely the more robust HA integration — with push added later purely for latency. CONFIRMED.

**d-3. `/eventhandler.html` `curStatus` as a one-fetch status read.** One authenticated GET yields session id, CSRF token **and** live status in a single response, bypassing the broken `GetSecurityStatus` cache entirely. It is also the ideal login-health check. CONFIRMED.

**d-4. The WebSocket transport.** `EhDir_service` implements a full RFC6455 handshake; `eh.js` has it commented out. For a Python client it is far cleaner than multipart or iframe parsing. **Worth one experiment** — but assume nothing: a 5.x-era Barracuda may use draft framing, and this path has never run on this firmware. UNKNOWN.

**d-5. `Type=138` as a liveness/clock probe.** Synchronous, side-effect-free, no IPC, no push. Perfect HA availability check and the ideal first smoke test. Note it renders the panel clock as UTC via pure epoch arithmetic — if it disagrees with wall time, that's a panel clock issue, not a parsing bug. CONFIRMED.

---

# OPEN QUESTIONS

1. **OQ-1 — Does an unauthenticated `GET /SimpleDebugger.interface/G.` stream live alarm state?** (H2.) The evidence leans yes. If so it is an unauthenticated disclosure of alarm status on the LAN. **One curl with no cookie settles it.**
2. **OQ-2 — Is `BARRACUDA[0].LocalLogin` set to 1 on Lewis's unit?** (b-5.) `Tuxedo.json` was not in the carve. If it is 0, a large chunk of section (b) is live today rather than theoretical.
3. **OQ-3 — Is the plain-HTTP listener reachable on Lewis's LAN, and is the web UI actually being used over it?** (b-1.) Determines whether the user code is on the wire in cleartext.
4. **OQ-4 — Does the local touchscreen's web-user editor rewrite `status:1`?** (a-1.) This is the difference between "recoverable from the panel" and "recoverable only by editing encrypted JSON off-box."
5. **OQ-5 — What is the state of the SharkSSL listener?** Version, cipher suites, certificate. It is the recommended mitigation for b-1 and **nobody looked at it.**
6. **OQ-6 — What is `Type=17`?** (H10.) Its `filters`/`index` pair looks like a paged list query, and it uses a **non-zeroed** stack buffer. Not evidence of a zone command, but the only remaining unidentified security-band Type.
7. **OQ-7 — Is the Type dispatch map complete?** (H9.) The two agents disagree. Matters only if a zone code is hiding behind a literal-pool load — which would overturn a documented negative.
8. **OQ-8 — Does the 32-deep `/Q_ServCmdTrsmtr` queue actually fill in practice?** Determines the real severity of the two IPC defects folded into a-4's neighbourhood: `osal_MqSend` @0x5a78e0 **flushes the entire queue backlog when full** (`osal_MqFlush` @0x5a7694 drains all 32 with no early break), and the timed variant @0x5a79ac **reports ETIMEDOUT as success** (`cmp r3,#0x6e` → `mov r0,#0`), so `th_readEcp` — which passes a timeout of 0 — silently drops ECP frames and its own error print at 0xc6466c is unreachable. Both CONFIRMED as code defects; both frequency-unknown. **Cheap check: watch `mq_curmsgs` on `/mqRead_ECP_Input` from a shell.**

---

# RANKED NEXT ACTIONS

1. **Verify `LocalLogin = 1` on the panel.** (OQ-2 / b-5.) Pure config, no risk, closes the widest unauthenticated hole. Do this first.
2. **Test OQ-1** — unauthenticated `GET /SimpleDebugger.interface/G.`. One command; it either confirms a LAN disclosure or removes a worry.
3. **Run the model-validating smoke test** (§2.6): REST login → `GET /eventhandler.html` → check `hiddenKey` is 31 hex and not `-1`, and `hidSession == int(cookie[0:8],16)` → then `Type=138`. **This validates the whole Part 1 spec in two requests.** Watch for the cookie trap in §2.3 first.
4. **Stop using "Remember Password"; clear `data1`/`data2`/`userName`/`userPassword`/`latestuserpwd`** for the panel origin. (b-8.) Two minutes, permanent.
5. **Confirm whether plain HTTP is reachable; if so, firewall TCP/80 to the panel and use HTTPS only.** (OQ-3 / b-1.) This is what stops the user code being sniffable.
6. **Prototype the HA integration against `/handlerequest_mobile.html` 5001 + 5002**, not the push channel. (d-2.) Fastest path to working entities, and it sidesteps the single-client fragility, the push-auth unknown and all three parsing traps.
7. **Then add the push channel for latency**, seeding state from 5001/`curStatus` on every connect (there is no backlog — §1.2), discarding `-1` filler frames, decoding latin-1, and parsing from the right.
8. **Harvest sub-id 7 records via `Type=5`** for real per-partition HA entities. (d-1.) Free capability the vendor UI throws away.
9. **Send `Type=1126` once per keypad-page visit** from your client to keep Back/Home working. (a-2.) One line.
10. **Prepare, but do not yet execute, the a-1 lockout recovery**: know how to decrypt `webuseraccountsenc.json`, set `status:1`, re-encrypt and fix the CRC sidecar — **before** you need it. Meanwhile, never hand-type the panel password.
11. **Assess SharkSSL** (OQ-5) before relying on HTTPS as the mitigation for b-1.
12. **Optional, low priority:** resolve OQ-6 (`Type=17`) and OQ-7 (dispatch completeness). Only OQ-7 could overturn the zone negative, and neither blocks the integration.

---

**Z-Wave.** Out of scope per the owner, and nothing here depends on it. For completeness only: Types 103-153 prefixed `SERV_ZW_` are the Z-Wave command band and were ignored throughout; the code-504 registration broadcast's last field carries a `zwaveControllerStatus` value; and `/BookmarksHandler.interface` (`initAndInstallBookmarksServlet` @0x0001d0d8) is a second, structurally identical EventHandler push channel with its own interface `BookmarksServer2ClientIntf` — unrelated to security status, but a live second push endpoint if it ever matters.
---

## APPENDIX: what the web server actually returns on a failed login

Traced 2026-09-05 to answer a concrete question: can an HTTP client tell a
locked-out account from a wrong password? Yes, and by an unexpected route.

### Status code DOES discriminate — correcting an earlier claim in this file

An earlier draft of this appendix said every outcome is HTTP 200 because
`LoginResp_service` ends in an internal forward. **That is wrong**, and it was
wrong in a self-inflicted way: the symbol at `0x6e024` had already been
resolved as `HttpResponse_sendRedirect` in the same session, and the claim was
written anyway. Four independent verification agents refuted it.

The two destinations use *different* mechanisms:

| Outcome | Call site | Mechanism | On the wire |
|---|---|---|---|
| ordinary failed login | `0x13528` | `HttpResponse_incOrForward` (`0x6e5c4`) | **200**, body is `/login.shtml` |
| accounts unusable | `0x134fc` | `HttpResponse_sendRedirect` (`0x6e024`) | **302** + `Location: /Invalid.html` |
| successful login | — | `sendRedirectI` (`0x6df5c`), status `0x12e` at `0x6dff4` | **302** + `Location` |

So the status code is the primary signal and the body is a secondary check.

**A client must not auto-follow redirects.** Following the 302 fetches
`/Invalid.html`, which returns 200, and the distinction disappears entirely.

The two destinations are `/login.shtml` and `/Invalid.html`. Neither is a file
in the embedded web archive; both are Barracuda compiled server pages living
as code (`login_shtml076EF::service`, `Invalid_html076EF::service`).

### The selection ignores the attempt and looks at stored account state

At `0x134b0` it calls `checkTotalUserAccount(int*,int*,int*)` (`0x2c3f8`),
which reads `/opt/tuxedo/configuration/webuseraccountsenc.json` and counts,
across the five WEBUSERS entries:

- entries with a non-empty `userName` — total configured
- entries with `userName` **and** `status == 1` **and** `accountLocked == 0`
  — usable

Then, with the third out-parameter being dead (stored as literal `0` at
`0x2c5f0`, so the `cmp r2,#1` at `0x134b8` never fires):

| usable | forward to |
|---|---|
| `> 0` | `/login.shtml` — an ordinary failed login |
| `== 0` | `/Invalid.html` — an account-state problem |

A wrong password does not change either count. The stock 3-strike lockout
does: it writes `status = 0` into every entry, which drives usable to 0.

### The credential check itself cannot distinguish anything

Inside `readUserNamePasswordFromJSON` (`0x14bf8`) all three rejections target
the same address, `0x14e78`, which is the loop-continue:

```
0x14dc4  ble #0x14e78    ; u8UserId <= 0
0x14dec  bne #0x14e78    ; status != 1        <- the locked-out account
0x14e28  bne #0x14e78    ; userName mismatch
```

A disabled account is skipped exactly as if it did not exist. The observable
difference comes entirely from the separate `checkTotalUserAccount` call.

### The message that would have explained it is dead code

`Invalid_html076EF::service` (`0x38604`) re-counts the same two things and
emits one of three warnings through `httpWriteSection`:

| selector | string |
|---|---|
| 1 | "…deactivated due to **maximum number of failed logins attempted**. Please go to your Tuxedo's login account setup to reactivate user accounts." |
| 2 | "…deactivated. Go to your Tuxedo's login setup to **create an user account**." |
| 3 | "…deactivated. Go to your Tuxedo's login setup to create an user account **or reactivate an account**." |

**Selector 1 is unreachable.** Every write to that register in the function
sets it to 2 (`0x38688`, `0x38824`), 3 (`0x38844`), or 0 (`0x38874`); the
remaining candidate, `movne r4, r6` at `0x386f8`, is reached only when `r6`
is provably 0, because `subs r6, r0, #0` at `0x3869c` branches away otherwise.

So the one message that names the actual cause never appears. A user locked
out by three failed logins is shown selector 3 instead, which mentions
reactivation but not why it is needed. That is a genuine usability defect on
top of the lockout itself, and it is the reason the condition is so hard to
diagnose from the browser.

### The login PAGE is served normally regardless of account state

Asked because a client's reconnect path may branch differently on a connection
error than on an auth error, and it matters which one a dead-account panel
produces.

`login_shtml076EF::service` (`0x3835c`) **never opens
`webuseraccountsenc.json` and never reads `status` or `accountLocked`.** It
writes its sections, checks for the `Random` / `RandomID` cookies, and emits

```
var login="%s";var myID="%s";var timeOut=%d;var server="%s";
```

A `GET` of the login page therefore returns a normal HTTP 200 page whether the
accounts are healthy, all disabled, or absent. A locked-out panel is still
fully reachable and still serves its login form. It does not look like a
network failure, and a client should expect the auth branch, not the
connection-error branch.

That page also carries its own inline banner,
`<span style="color:red;">Invalid UserName/Password</span>` (`0x38480`), which
is a third distinguishable body separate from the two `Invalid.html` variants.

### Practical detection rule

Primary rule, on status and `Location`:

| Response | Meaning | Recovery |
|---|---|---|
| **200** | ordinary auth failure. On a patched panel this also covers the 300-second lock, because that lock never writes `status` or `accountLocked` | check credentials; retry after five minutes is valid on a patched panel |
| **302** to `/Invalid.html` | account-state problem, in practice the stock 3-strike lockout | touchscreen: login account setup, Enable All, Apply |
| **302** elsewhere | success | — |

Secondary check, on the body of `/Invalid.html` if it is fetched:

| Body contains | Meaning |
|---|---|
| `reactivate an account` | stock 3-strike lockout has disabled every account |
| `create an user account` without `reactivate` | no web accounts configured |

Two further signals on the 200 path, both real but both fragile:

- The failed POST emits `<span style="color:red;">Invalid UserName/Password</span>`,
  preceded by a "Login failed." span whose style differs by **one character**:
  `color:red;;` (doubled semicolon) when the username was found and enabled,
  `color:red;` when it was unknown or already disabled. Do not build a
  user-facing message on a one-character difference.
- A failed POST does **not** set the `_zFL` cookie; an unauthenticated GET of a
  protected page does. That separates "my POST was rejected" from "the server
  handed me the login form" without parsing the body.

This rule is correct on **both** the stock and patched builds without needing
to detect which is running, because the patched 300-second lock lives entirely
in `LoginTracker_validate` and the in-memory node and never writes `status` or
`accountLocked`. Usable stays above zero, so a rate-limited attempt presents
as an ordinary failure.
