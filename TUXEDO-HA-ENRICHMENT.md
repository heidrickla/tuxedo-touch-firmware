# Richer Home Assistant data from the Tuxedo Touch — the gap

**Headline: the REST API's non-Z-Wave surface really is thin — but there is a
SECOND, security-oriented web-request surface in the binary that the REST API
does not expose at all. It covers zones, the event log, multi-partition arming
and console-mode keypad access. Finding the URLs that reach it is the one thing
between here and much richer Home Assistant data.**

> **Revision note.** An earlier version of this document recommended adding
> lights, locks, thermostats, garage doors and water valves as "free entities".
> That was wrong — they are all Z-Wave, which is out of scope. The owner caught
> it; the symbol table confirmed him. The correction is kept in place below
> rather than deleted.

---

## What Home Assistant gets today

From `ha-tuxedo-touch` 0.3.1 (read-only inspection):

| | |
|---|---|
| Platforms | `Platform.ALARM_CONTROL_PANEL` — **one** |
| API methods | `login`, `get_status`, `arm`, `disarm` — **four** |
| Data model | `TuxedoStatus { status: str, color: str \| None }` |
| Endpoints used | `GetSecurityStatus`, `AdvancedSecurity/ArmWithCode`, `AdvancedSecurity/DisarmWithCode` |

So the entire integration surfaces **one entity carrying one string**.

## What the panel already exposes over the same authenticated API

Enumerated from `script/tuxapi.js` — the vendor's own client, extracted from the
ZIP embedded in the `Barracuda` binary. This is not inference; it is the code
Honeywell ships to talk to its own server.

### CORRECTION — these are Z-Wave, and Z-Wave is out of scope

I first listed lights, locks, garage doors, water valves, thermostats and
scenes as "free entities". **That was wrong.** Lewis flagged it and the symbol
table confirms him: every one of those endpoints is served by a handler named
`sltRequestZwave*` on `CReceiverThread`. All 24 of them:

```
sltRequestZwaveLightStatGet/Set      sltRequestZwaveDimmerStatGet/Set
sltRequestZwaveDoorStatGet/Set       sltRequestZwaveGarageDoorStatSet
sltRequestZwaveTermTarTempGet/Set    sltRequestZwaveTermRoomTempGet
sltRequestZwaveTermFanModeGet/Set    sltRequestZwaveThermostatModeSet
sltRequestZwaveThermoStatAllInfoGet/Set   sltRequestZwaveTermSaveEnergyModeGet/Set
sltRequestZwaveDeviceList/Add/Del/Frmv/Abort    sltRequestZwaveAllLightsON/OFF
```

The `?nodeID=` parameter on those REST endpoints is a **Z-Wave node id**. So the
whole "Tier 1 / Tier 2" recommendation was a recommendation to build Z-Wave
support, which is explicitly out of scope. Withdrawn.

**Evidence:** `tuxedo` ELF `.symtab`, 24 symbols matching
`CReceiverThread.*Zwave.*web_request`. **CONFIRMED.**

---

## What is ACTUALLY there, and it is better

Separating the Z-Wave handlers out revealed a **second web-request surface that
is entirely security-oriented and absent from the REST API list**. These are all
`CReceiverThread` slots taking `web_request*` — i.e. **driven by HTTP requests**
— but none appear in `tuxapi.js`.

### Zones — 12 handlers **[CONFIRMED present]**

```
sltRequestAllZoneCurrStatus(web_request*)     <-- current status of ALL zones
sltRequestToBypassZones(web_request*)
sltRequestBypassAllZones(web_request*)
sltRequestToBypassClearZones(web_request*)
sltRequestBypassClearAllZones(web_request*)
getAllZoneListFunc()   getListOfZones(unsigned)   refreshUploadZoneList(int, const int*)
clearBypassedZones()   bypassAllOrSelectedZones(bool)
sltZoneStatusTimeout()  zoneStatusFilterIndexChanged(int)
```

`sltRequestAllZoneCurrStatus` is precisely the zone data an alarm integration
wants, and it is web-request driven.

### Event log **[CONFIRMED present]**

```
sltRequestEventLogUpload(web_request*)
sltTotalNoOfEventsReceived(int)   wsltEventDescRcvd(SaplData)
setEventIndex()  sltSetEventIndex()  sltEventtFilterConfReceived(int)
```

The panel's event history, retrievable over the web interface.

### Multi-partition arming **[CONFIRMED present]**

```
sltRequestMultiPartitionArmAway/ArmStay/ArmNight/Disarm(web_request*)
sltRequestMultiPartitionArmAwaySelectedPartition(web_request*)
sltRequestMultiPartitionDisarmSelectedPartition(web_request*)
sltRequestPartitionStatus(web_request*)
getListOfPartitions(unsigned)   getPartitionDetails(char*)
sltSendPartitionDetailsToWebClient(int)   sltSendChangedPartitionStatus(int)
```

Richer than the single-partition `ArmWithCode` the integration uses today.

### Console mode — the keypad display **[CONFIRMED present]**

```
CReceiverThread::requestconsolemode(web_request*)
apl_getEcpConsoleModeData(char*, char*, short*)
apl_sendEcpConsoleModeData(unsigned char*, bool)
```

Console mode sends raw keystrokes to the panel and reads back its two-line
display. A `web_request` handler for it exists. That display text is a far
richer status source than the one word `GetSecurityStatus` returns — and it
would bypass the status-cache problem entirely, since it reads the panel
directly rather than a cache.

**CONFIRMED BY THE OWNER: console mode arms and disarms the system exactly like
the physical keypad.** So in Home Assistant terms this is not a sensor with a
convenient side effect — it is a full control surface. Reading the display is
passive; sending keystrokes is equivalent to standing at the keypad. Any
integration exposing it must treat it as a control entity with the same care as
arm/disarm, not as a diagnostic read-out.

### User code feedback **[CONFIRMED present]**

```
sltSendUserCodeAcceptedMsg()   sltSendUserCodeDeclinedMsg()
sltSendUserCodeDeclinedWithReasonMsg(QString)   sltGoAuthLevelReceived(SaplData)
```

Explicit accept/decline signalling, including a reason string.

---

## ANSWERED: the second API, and how to call it

**[CONFIRMED]** The handlers are reached through a single dispatch page with a
**numeric command code**:

```
/handlerequest.html?cmd=<CODE>&Type=<CODE>&pID=<partition>&uCode=<usercode>
                   &sessionid=<SID>&filters=0&index=0&tarTemp=0
                   &tokenkey=<TOKEN>&sid=<cache-buster>
```

That generic form is taken verbatim from the panel's own `script/consoleRequest.js`.
Different pages fill in different extra parameters, but `cmd`/`Type`,
`sessionid` and `tokenkey` are constant across all of them.

This is a **completely separate API from `API_REV01`**, which is why enumerating
`tuxapi.js` never found it. It is the one the panel's own web UI actually uses
for security operations.

### The command codes — non-Z-Wave only

| Code | Constant | What it does |
|---:|---|---|
| 1 | `SERV_SEC_CMD_ARM_AWAY` | arm away |
| 2 | `SERV_SEC_CMD_ARM_STAY` | arm stay |
| 3 | `SERV_SEC_CMD_ARM_DISARM` | disarm |
| 4 | `SERV_SEC_CMD_ARM_NIGHT` | arm night |
| 6–9 | `SERV_SEC_CMD_MULTI_ARM_*` | multi-partition away / stay / night / disarm |
| 25–29 | `..._SELECTED_PART` | multi-partition, specific partition |
| 18 | `SERV_GET_HOME_PART` | get home partition |
| 1118 | `SERV_HOME_PART_CHANGED` | home partition changed |
| **19** | **`SERV_CONSOLE_MODE`** | **enter console (keypad) mode** |
| **20** | **`SERV_CONSOLE_MSG_BROADCAST`** | **console display text, pushed** |
| **21** | **`SERV_PARTITION_MSG_BROADCAST`** | **partition status, pushed** |
| **22** | **`SERV_PANEL_OFFLINE_MSG_BROADCAST`** | **panel-offline notification** |
| 1125 / 1126 | `CONSOLEMODESTATUSADD` / `SUB` | subscribe / unsubscribe to console status |
| 500 / 502 / 503 | `SERV_CLIENT_REGISTER` / `BACK` / `HOME` | session management |
| 51, 54, 58, 155 | `SERV_IP_CAMERA_*`, `SERV_MM_GETCAMERALIST` | IP cameras (not Z-Wave) |
| 134–141, 146, 150 | `SERV_*_SCENE_*` | scenes |
| 138 | `SERV_GET_SYSTEM_TIME` | panel time |

Everything numbered 103–153 prefixed `SERV_ZW_` is Z-Wave and out of scope.

### Why the four bold rows change the picture

**`SERV_PARTITION_MSG_BROADCAST` (21) is a PUSH.** The panel broadcasts
partition status to registered clients rather than waiting to be polled. A push
does not read the `GetSecurityStatus` cache, so it should **not exhibit the
"Not available" problem at all** — the whole bug this investigation started
with. **[LIKELY]** — the code is confirmed, the behaviour is not yet tested.

**`SERV_PANEL_OFFLINE_MSG_BROADCAST` (22)** distinguishes "the panel link is
down" from "I have no cached status". Home Assistant currently cannot tell those
apart, and they mean completely different things to a user.

**`SERV_CONSOLE_MODE` (19) with `CONSOLEMODESTATUSADD` (1125)** subscribes to
the live keypad display. That two-line text is what a physical keypad shows —
strictly richer than any single status string, and it comes straight from the
panel rather than from a cache.

**`SERV_CLIENT_REGISTER` (500)** is presumably how a client registers to receive
the broadcasts. Confirming that is the next concrete step.

**What a partition broadcast carries.** The payload is sub-identified, and the
nine `E_SUBID_*` values are the full set:

| Sub-id | Meaning |
|---:|---|
| 1 / 2 | valid / invalid user code |
| 3 / 4 | user code declined, with and without a message |
| 5 | go to partition-selection screen |
| 6 | **partition description** (i.e. partition names) |
| 7 | **partition status** |
| 8 | end of transmission |

So a single broadcast subscription yields partition names, partition status, and
live user-code accept/decline feedback — none of which Home Assistant gets
today.

### Zones: I WAS WRONG — the command exists

**Command 12 is the all-zone current status request.** I searched the shipped
JavaScript, found no zone code, and called it a well-characterised negative.
The negative was real but the conclusion was not: **the command table lives in
the binary, not in the JavaScript.** The multi-agent audit extracted the
dispatch in `CReceiverThread::run()` mechanically and recovered 60+ command ids,
including:

| id | Handler |
|---:|---|
| **12** | `sltRequestAllZoneCurrStatus` |
| 13 / 14 | bypass all zones / clear all bypasses |
| 15 | bypass selected zones |
| **17** | `sltRequestEventLogUpload` |
| 18 | get home partition details |

and confirmed that `Type` in `/handlerequest.html` **is** the command id, passed
through verbatim.

**The methodological error is worth naming:** I searched the client and
concluded about the server. A vendor's shipped UI exercises only the subset of
an API that its own pages need. Absence from the client is evidence about the
client.

There is also a **better source than the API** for zone configuration — see the
per-partition files below.

### The superseded negative, kept for the record What was checked:

- `script/tuxapi.js` — the REST client. No zone endpoint.
- Every `.js` and `.html` in the embedded ZIP, for `SERV_*` constants. 61 command
  codes found, **none zone-related**.
- The large mobile security scripts (`security.js` and siblings, ~500 KB
  combined), which drive the mobile UI. No zone codes.
- The `E_SUBID_*` broadcast payload identifiers. Nine of them, covering user-code
  results, partition description, partition status and end-of-transmission —
  **no zone sub-identifier**.

Yet `sltRequestAllZoneCurrStatus(web_request*)` and eleven sibling zone handlers
**do** exist in the binary. The most likely reading, **[LIKELY]** not confirmed:
those handlers serve the local touchscreen or a legacy/unused path, and zone data
was simply never wired to the web interface on this firmware.

**That consequence was wrong.** Zone data IS reachable over HTTP, two ways:

1. **Command 12** via `/handlerequest.html?cmd=12&Type=12&...`.
2. **`/Config/P<N>Info.txt`** — per-partition files written by
   `CreatePnlInfoFlashTable`, holding a partition header (number, description,
   zone count, panic flags) followed by one comma-delimited line per zone:
   **zone number, zone type, device type, description**. Served from the
   unauthenticated `/Config/` path.

Option 2 is the better one for a field programmer: it is a static text file with
the complete zone table, needs no command protocol, and no authentication.

---

## THE IMPLEMENTABLE SPEC — how to call the second API

All **[CONFIRMED]** by disassembly of the `Barracuda` web server.

### The gating question: does the existing Home Assistant login work here?

**Yes.** There is exactly **one login on this device**. Both APIs authenticate
through the same Barracuda `FormAuthenticator`, mounted on the single protected
directory `/authenticated`, whose only page is `index.html`.

**Nothing else on the server is under HTTP authentication at all** — not
`/handlerequest.html`, not `/eventhandler.html`, not `/tuxedoapi.html`. They are
guarded only by the session cookie plus a per-session CSRF token.

So the integration's existing client can reach the second API with the cookie it
already holds. No second credential exchange.

### `sessionid` — derivable, not separately issued

The session cookie's value is 16 lowercase hex characters, formed as
`hex8(session_id) || hex8(session_creation_time)`. So:

```
sessionid = int(cookie_value[0:8], 16)      # as a decimal string
```

It can equally be scraped from a hidden input on any generated page. It is not
secret.

### `tokenkey` — a per-session CSRF token, scraped once

31 lowercase hex characters. Generated **once per session slot** and **does not
rotate** per request, per page, or per command. It changes only on a new login.

**The only way to obtain it is to scrape a generated page.**
`GET /eventhandler.html` emits both the session id and the token as hidden
inputs. `/tuxedoapi.html` does **not** — which is why an integration that only
ever fetches the key blob has never seen a token.

Recommended client flow:

```
1. log in as today (unchanged)
2. GET /eventhandler.html with the session cookie
3. scrape sessionid and tokenkey from the hidden inputs
4. issue commands:
   /handlerequest.html?cmd=<id>&Type=<id>&sessionid=<sid>&tokenkey=<tok>&...
5. on failure, re-login and repeat from 2
```

### The command id goes in `Type`

`Type` **is** the command id, passed through verbatim to the application. `cmd`
carries the same value in the vendor's own requests. Send both.

### Session slots are finite — 10 on this unit

The server keeps a fixed table of concurrent web sessions, sized from a config
key (`No_Of_Users`, 10 here). Dead sessions are reaped when a new one is
allocated, but **a client that logs in repeatedly without reusing its session
will consume slots**. This is an operational hazard for a polling integration:
re-authenticating on every poll could lock out the browser UI.

**Reuse the session. Re-login only on failure.**

### Corrections this produced

- **`Type=3180` is not a login.** I previously recorded it as the login request
  from `login2.html`. The constant does not exist anywhere in the server binary,
  and that page's function is commented out. It is dead code.
- **The session cookie NAME is not random per login.** It is
  `z9ZAqJtI_<unix time at web-server startup>` — fixed for the life of the
  process. It looks random only because it changes when the server restarts. A
  client should echo back whatever `Set-Cookie` it received, or match the
  `z9ZAqJtI_` prefix.

## Two structural improvements, independent of new data

**1. Console mode gives a keypad entity.** Covered above. Upgraded since first
writing: `CReceiverThread::requestconsolemode(web_request*)` shows it is
**web-request driven**, not merely present in the binary.

**2. The status cache problem does not apply to most of the above.** The
`"Not available"` behaviour is specific to the security-status cache filled by
`UpdatedSecurityStatus2Agent` from ECP messages. Z-Wave device status, scenes,
thermostats and cameras go through different paths and are unlikely to share
that failure mode. So adding those entities improves the integration even while
the alarm status remains flaky.

---

## Ranked recommendation

1. **Try `SERV_PARTITION_MSG_BROADCAST` (21) via `/handlerequest.html`.**
   If partition status can be pushed, it likely bypasses the status cache and
   therefore the "Not available" bug entirely. Highest value, and it directly
   attacks the original complaint.
2. **Try `SERV_CONSOLE_MODE` (19) + `CONSOLEMODESTATUSADD` (1125)** for the live
   keypad display. Richest possible status source, straight from the panel.
3. **Wire up `SERV_PANEL_OFFLINE_MSG_BROADCAST` (22)** so Home Assistant can
   distinguish a dead panel link from a missing cache value.
4. **Do not chase zones through the Tuxedo web API.** Searched thoroughly, no
   command code exists. Use the Envisalink for zone data — it already works on
   this panel.
5. **Ignore everything `SERV_ZW_*`.** Z-Wave, out of scope.

---

## Evidence and provenance

Endpoint list: `script/tuxapi.js`, extracted from the ZIP appended to
`opt/webserver/Barracuda` (776 entries, archive base `0x8a948`, EOCD
`0x4f00fd`). Binary symbols from the `tuxedo` ELF, which is **not stripped**
(10,339 named functions). Current integration surface read from
`ha-tuxedo-touch` 0.3.1 without modification.

Confidence: the endpoint list and the current-coverage gap are **CONFIRMED**.
The zone routes are **LIKELY** candidates, not established. Console-mode
reachability over HTTP is **UNKNOWN**.

---

## LIVE TEST RESULTS — measured against the real panel

Everything above this line was static analysis. This section is what the device
actually did when asked, on 203.0.113.5. **Where the two disagree, believe this
section.**

### Endpoints that RETURN DATA

| Endpoint | Live result |
|---|---|
| `GetSecurityStatus` | `{"Status":"Ready To Arm","Color":"Green"}` |
| `GetSceneList` | `{"Status":"No scenes found"}` |
| `AdvancedMultimedia/GetCameraList` | real camera records with ID, name, IP, model, RTSP and MJPEG paths |
| `AdvancedAutomation/DoorBell/getDoorBell` | `{"Status":"Sucess","Result":{"ID":0,"EventID":0,"Time":"No recent Doorbell press events"}}` |
| `Administration/ViewEnrolledDeviceMAC` | `{Status:"This services are accessable local only"}` |
| `Administration/ViewIPURL` | same local-only refusal |

**An empty request body works** on `GetSecurityStatus`, matching the vendor's own
client. The `operation=get` body the integration sends is accepted but not
required.

### THREE CONFIRMED BUGS, found live

**1. `GetOccupancyMode` is misrouted.** It returns the security status verbatim —
byte-identical to `GetSecurityStatus` — regardless of parameters. The handler is
wired to the wrong function. **[CONFIRMED live]**

**2. MOST DOCUMENTED ENDPOINTS ARE NOT IMPLEMENTED — they return their own
documentation form.** Endpoints taking an argument answer with the built-in test
console's input form:

```
Node ID : <input type="text" name="nodeID" maxlength="3"/>...
Enter The Category (Default All): <input type="text" name="category" .../>
```

I first read this as a missing-parameter fall-through. **It is not.** Supplying
the parameter changes nothing — tested in the encrypted body (`nodeID=1`,
`category=All`, with and without `operation=get`) **and** in the URL query
string. The form comes back identically every time.

So the URL resolves to the API **documentation page** for that endpoint, not to
a handler. Those endpoints are **not callable on this firmware**.
**[CONFIRMED live, both parameter positions tested]**

### CONSEQUENCE: the REST API is far smaller than documented

I earlier wrote that the panel exposes "~40 endpoints" and that the integration
uses 2 of them. That count came from the vendor's own client and the test
console. **Live, only about six actually answer with data:**

`GetSecurityStatus`, `GetSceneList`, `GetOccupancyMode` (misrouted),
`AdvancedMultimedia/GetCameraList`, `AdvancedAutomation/DoorBell/getDoorBell`,
and the two `Administration/View*` calls (which refuse with a local-only
message).

Everything else tested returns a form or an embedded 404. **The "38 unused
endpoints" framing was wrong** — most were never implemented.

**3. Some endpoints answer with an embedded 404.** `GetThermostatClock`,
`GetThermostatSchedule` and `GetVideoEvents` return HTTP 200 carrying an HTML
page whose body contains `{"ErrorCode":"404"}`. Wrong status code, wrong content
type, error buried in markup. **[CONFIRMED live]**

### Camera discovery has false positives

The returned camera list includes an HP LaserJet printer at `203.0.113.227`,
detected as a camera with an RTSP path. Discovery matches too loosely.
**[CONFIRMED live]**

### THINGS THAT DID NOT WORK — static claims the device refuted

| Claim | Live result |
|---|---|
| `/Config/` serves the configuration directory unauthenticated | **404** on every casing and file. No auth challenge, but nothing served. |
| `panelinfo.txt` (installer code) retrievable over HTTP | **not reachable** |
| `P<N>Info.txt` zone tables retrievable over HTTP | **not reachable** |
| `SimpleDebugger.interface` push channel | **404** on GET and POST, and on every URL suffix the client library uses |
| `tokenkey` scrapable from a page | **absent** from every page checked |
| `tokenkey` required for commands | **not required** — commands accept an empty token |
| Commands return their result inline | **no** — HTTP 200 with a zero-byte body |

**The push channel being dead is the important one.** The command API can *send*
(the request is accepted and queued) but cannot *return* data on this unit,
because the mechanism that would deliver replies is not registered. That kills
the hope that a pushed partition status would bypass the status-cache bug.

### Confirmed live: the session model

- Cookie name observed: `z9ZAqJtI_1392221684` — exactly the predicted
  `z9ZAqJtI_<startup time>` format. The embedded timestamp is **February 2014**,
  consistent with the panel's clock being set to a fixed past date at first boot.
- **`sessionid` is the first 8 hex characters of the cookie value read as a
  SIGNED 32-bit integer.** Observed: cookie prefix `0xC62D...` → derived
  unsigned 3325027929 → page reported `-969939367`. They are the same number.
  A client computing it unsigned will send a value the panel does not recognise.

---

## MAJOR REVERSAL — the push channel DOES work

Two sections above say the push channel is dead and that commands cannot return
data. **Both are wrong.** I had the URL separator wrong.

```
GET /SimpleDebugger.interface/G.        <-- works: slash before G.
GET /SimpleDebugger.interfaceG.         <-- 404: what I tried first
```

The working request needs only the session cookie. No token, no query string.

### What it returns

`Content-type: multipart/x-mixed-replace; boundary="EH912ZZ"` — a long-lived
stream, one part per event:

```
['setCid', <connection id>]
['ud','SimpleDbgServer2ClientIntf','statusMessageText',["<payload>"]]
['ud','SimpleDbgServer2ClientIntf','noOfClient',[<n>]]
```

Payloads are colon-delimited, with **the command id in field 2**:

| Observed payload | Meaning |
|---|---|
| `0:504:1:P1  H:1:0:3:3` | 504 = registration/initial data, partition 1 |
| `0:21:1:fe:<p>Ready To Arm:2` | **21 = partition status — the alarm state** |
| `0:18:1 P1  H:2` | 18 = home partition |
| `0:-1:<p>Ready To Arm` | unsolicited status update |

### Why this matters more than anything else found

**Partition status arrives on the push channel, and the channel reads the panel
rather than the `GetSecurityStatus` cache.** That is the bug this whole project
started from. A client on this stream gets the alarm state pushed, without ever
touching the cache that returns `"Not available"`.

It also restores everything that depended on replies: command results, the event
log, and console-mode display text.

### Working client recipe **[CONFIRMED live]**

```
1. log in as today
2. open GET /SimpleDebugger.interface/G. with the session cookie, keep it open
3. read multipart parts; parse ['ud',<intf>,'statusMessageText',["<payload>"]]
4. split payload on ':' — field 2 is the command id
5. issue commands on /handlerequest.html as usual; replies arrive on the stream
```

Both connections coexist — `noOfClient` went to 2 while commands were being
issued on a separate request, so the stream does not monopolise the panel.

### Corrections this forces

- "The push channel is dead" — **WRONG**, wrong URL form.
- "Commands cannot return data on this unit" — **WRONG**, they return on the stream.
- "`tuxedo_console.py` cannot work on this firmware" — **WRONG**, it needs the
  stream as its reply path rather than expecting an inline response.
- The earlier `.interface` 404s were all my URL error, not absent endpoints.

---

## The push frame format, decoded byte-exact

Captured across a live arm/disarm cycle. **[CONFIRMED]**

```
0:21:1:fe:þ1Ready To Arm:2
0:21:1:ff:ÿ259  Secs Remaining:2
|  |  | |   |  ||
|  |  | |   |  |+- display text
|  |  | |   |  +-- COLOUR: 1 green, 2 red  (matches the REST API's "Color")
|  |  | |   +----- the same flag again, as a RAW BYTE
|  |  | +--------- state flag as hex TEXT: fe = ready/disarmed, ff = arming/armed
|  |  +----------- panel status code, NOT the partition number.
|  |                It is -1 when the ECP link to the Vista is down.
|  |                Corrected 2026-09-06, see below.
|  +-------------- command id: 21 partition status, 18 home partition,
|                  504 initial data, -1 unsolicited update
+----------------- 0 in everything observed
```

### Correction, 2026-09-06: field 3 is a panel status code, not the partition

The diagram above labelled the third colon-delimited value the partition number.
That was wrong, and on a single-partition panel no capture can show it, because
both readings render `1`.

`/tuxedo` carries a full symbol table, so the producer can be read directly. It
is `CReceiverThread::sltSendChangedPartitionStatus(int)` at `0x144880`:

    0x144a7c  bl     PanelIsTalking()
    0x144a80  cmp    r0, #0
    0x144a84  mvneq  r3, #0          ; link down -> -1
    0x144a88  streq  r3, [sp, #8]    ; written into the message field
    0x144a8c  bne    0x144ae8        ; otherwise the real value
    ...
    0x144aa0  bl     osal_MqSend(int, char*, int)

**When `PanelIsTalking()` returns 0 the field becomes -1, and the frame is sent
anyway.** So it reports whether the panel is answering, not which partition the
message concerns.

Live capture agrees. An authenticated `GET /eventhandler.html` taken during a
concurrent stream returned

    curStatus = "21:a1Ready To Arm:1"

against the frame `0:21:1:fe:þ1Ready To Arm:2`. The value `eventhandler.html`
itself names `panelStatusCode` is `1`, matching the field above; the frame's
trailing value is `2`, which rules out the trailing value being that code and
leaves the colour reading intact.

**Consequence for any consumer.** Do not use this field as a partition
discriminator. A guard comparing it to a partition number rejects every frame
the moment the ECP link drops, while the stream stays connected and healthy
looking. Handle `-1` explicitly: it means the panel is not answering, which is
worth surfacing rather than discarding.

**The stream must be decoded latin-1, not utf-8.** The state flag is a raw
0xFE/0xFF byte; utf-8 turns it into U+FFFD and the value is lost. I hit this
myself — the first capture showed a replacement character where the flag should
have been.

`decode_status_frame()` in `tuxedo_push.py` implements this and returns
`{cmd, partition, armed, colour, text}`.

### Why this is the answer to the original bug

Arming produced `ff` + red + a live countdown; disarming produced `fe` + green +
`Ready To Arm` — **pushed, within seconds, without polling `GetSecurityStatus`
once.** The push path does not read the cache that returns `"Not available"`,
so a client on this stream cannot experience the fault this project started
from.

### Verified live, end to end

| | |
|---|---|
| Arm stay | accepted, reply nests under `Result.Response` |
| Disarm | accepted, reply nests under `Result.Result` |
| Exit delay | streamed as a live countdown |
| State change latency | seconds, pushed |
| Panel left | disarmed, `Ready To Arm` |

---

## What the push stream does and does NOT carry — measured

Sent commands 12, 17, 22, 51, 134, 155 and 500 while listening for 50 seconds.

**Command ids that ever appeared on the stream:**

| id | Meaning | Arrives |
|---:|---|---|
| 21 | partition status | yes — and spontaneously |
| 18 | home partition | yes |
| 504 | initial registration data | yes, on connect |
| -1 | unsolicited status update | yes, continuously |

**Command ids that produced NOTHING, on the stream or inline:**

`12` (all zone current status), `17` (event log upload), `22` (panel offline
broadcast), `51` (IP camera status), `134` (get scene list), `155` (get camera
list), `500` (client register).

### The boundary this establishes

**The push stream carries partition/alarm state, and only that.** It fixes the
status bug completely — that is a real and sufficient result — but it is **not**
a general reply channel.

This corroborates the audit's finding that command 12 is **orphaned**: the
handler runs and emits one message per zone onto an internal queue, but nothing
forwards those to a web client. The same appears true of the event log.

### Consequence for zone data

Zone-level data is **not reachable over HTTP on this firmware**, by any route
tested:

- no REST zone endpoint (established by enumeration)
- `/Config/P<N>Info.txt` — 404, not served
- command 12 — accepted, produces no reply anywhere observable

So the earlier recommendation stands after all: **for zones, use the Envisalink**,
which already reports them correctly on this panel. The Tuxedo's web interface
cannot supply them.

That is a firm negative reached three independent ways, and it is worth more
than another round of guessing.

### Reconnect safety — measured

A real deployment risk was that the panel keeps only **10 concurrent web session
slots**, so a client reconnecting its push stream might exhaust them and lock the
browser UI out.

**It does not.** Six consecutive connect/disconnect cycles on a single session
held `noOfClient` at **1** every time, and the session remained usable
afterwards. Slots are reclaimed on disconnect.

So a Home Assistant client may reconnect the stream freely — on network blips,
on restart, on error — without risk of lockout. Reuse the login; only the stream
needs re-establishing.

### Push vs poll latency — measured, and it corrects an assumption

I had been describing the push stream as "lower latency". Measured against a
tight polling loop on the same arm event:

| | Saw the change at |
|---|---|
| push stream | **t+1.70 s** |
| REST poll (tight loop) | t+1.92 s |

Essentially the same. The panel itself takes ~1.7 s to reflect an arm command;
the transport is not the bottleneck.

**So the case for push is NOT speed.** It is:

1. **It cannot hit the `"Not available"` fault**, because it does not read that
   cache. That alone is decisive.
2. **No polling loop at all** — no 30-second interval, no wasted requests, no
   contention on a panel that serves one connection at a time.
3. **It reports transitional states** such as the exit-delay countdown, which a
   30-second poll would usually miss entirely.

Against a *realistic* 30-second poll the push stream is of course far faster in
practice — median 15 seconds better — but that is a property of the poll
interval, not of the transport. Worth stating precisely rather than claiming a
speed advantage that a tight loop would disprove.

### Long-lived stability — measured

A 5-minute continuous hold: **81 frames, last at t+296s**, no early close.

The frame gaps show a regular **~33-second cadence** — the panel refreshes
partition status on its own timer, so an idle stream still proves itself alive
roughly twice a minute without any client action.

Practical consequence: a client can treat a gap materially longer than ~35 s as
a dead stream and reconnect, and reconnection is free (see reconnect safety
above). That gives a simple, reliable liveness rule with no keepalive traffic of
its own.

### Concurrent clients — measured

Two independent logins, each holding its own push stream for 25 seconds:

| | Frames received |
|---|---|
| client A | 17 |
| client B | 9 |

Peak `noOfClient` = 2, neither starved.

This matters because the panel **serves one connection at a time** for ordinary
requests, and contention there presents as a hang rather than a refusal. The push
streams do not behave that way — they coexist.

So Home Assistant can hold a stream while a diagnostic tool holds another. That
removes the operational constraint that has shaped this whole investigation,
where every measurement required disabling the integration first.

### Listening ports — scanned live

| Port | State | What it is |
|---|---|---|
| 80 | **open** | the web app, plaintext |
| 443 | **open** | the web app, TLS (2009 demo certificate) |
| **6280** | **open** | **the same web app again, plaintext** |
| 8080, 8443, 5353, 4025, 22, 23 | closed | no SSH, no telnet, no mDNS reachable |

**Port 6280 was not in any documentation I had.** It serves the same pages with
the same session cookie, and the push stream works on it. So there are three
entry points to the full interface, two of them unencrypted.

Firewall consequence: allowing 443 alone is not enough. **80 and 6280 must be
restricted too**, and they carry the alarm user code in a query string.

Confirmed absent, which is the good news: no SSH, no telnet, no mDNS listener,
no secondary web server on the usual alternate ports.

#### Are the plaintext ports a hole? No — measured

Tested every interesting page on :80 and :6280 **with no session cookie**:

| Page | Unauthenticated result |
|---|---|
| `/home.html`, `/consolekeypad.html`, `/tuxedoapi.html` | **302** to login |
| `/eventhandler.html` | 200 — but it is the **login page** under that name |

The one 200 leaks nothing: its only hidden input is an empty `persistentCookie`,
and it simply pulls in the login scripts. No session id, no key material, no
status.

So the plaintext ports are gated exactly like HTTPS. The exposure they create is
**confidentiality, not access** — anyone who can see the traffic reads the alarm
user code out of the query string, but they cannot reach the interface without
credentials.

That is a materially smaller problem than it first looked, and worth stating
plainly rather than leaving an open-port list to imply otherwise.


---

## POST-FLASH RETEST, 2026-09-05: command 12 still returns no zone data

Retested on the patched firmware with a live authenticated session, sending
command 12 ("all zone current status") and command 138 ("get system time") and
watching the push stream for 60 seconds.

**Neither produced a single reply frame.** 140 frames arrived in that window
and not one carried command id 12 or 138. What did arrive:

| Command | Frames | What it is |
|---|---|---|
| 55 / 80 | 28 each | camera and UPnP device discovery, unsolicited |
| 21 | 3 | partition status, `Ready To Arm` |
| 18 | 2 | home partition |
| -1 | 12 | unsolicited status updates |
| 504 | 1 | registration |

So the earlier correction in this file stands, and now stands against live
hardware rather than a reading of the binary: **command 12 exists in the
symbol table but returns nothing on this firmware.** Finding a command id in
the binary is evidence that the vendor implemented a handler, not that the
handler answers.

That leaves the scope limit unchanged. The push stream carries partition and
alarm state. **Zone data is not obtainable from it, from the REST API, or from
`/Config/`.** For zones, use the Envisalink.

`tuxedo_zone_tables.json` in this repo still has the zone *type* numbering and
the descriptor vocabulary, extracted statically from the binary. That is the
part a field programmer needs to pre-populate its dropdowns, and it does not
depend on the panel answering anything at runtime.

### Also retested: `panelinfo.txt` is not served

Nine candidate paths were tried with a valid session cookie
(`/panelinfo.txt`, `/authenticated/...`, `/Config/...`, `/config/...`,
`/tuxedo/...`, and variants). **All returned 404.**

The claim recorded earlier — that the file containing the installer code in
plaintext is one unauthenticated GET away — **does not reproduce**. It was
marked `[CONFIRMED]` statically and `[UNTESTED]` live; the live test has now
been done and it is negative. `CreatePnlInfoFlashTable()` does write that file,
but nothing appears to publish it over HTTP.

---

# The panel already reports whether it accepted a code

Asked whether an arm or disarm was accepted, refused, or never seen. The answer
is that the panel already says so, on the push stream, and no firmware change is
needed.

Arm and disarm over REST return HTTP 200 with a zero-byte body, so the command
response tells you nothing. That is by design: `handlerequest.html` is fire and
forget on this panel, and **every** result comes back on the stream. Confirmed
by measurement: commands 19, 55, 1125, 999999 and 0 all return an identical
`HTTP 200, 0 bytes`, so valid and nonsense commands are indistinguishable in the
response.

Three slots in `CReceiverThread` produce the answer, and all three call
`osal_MqSend` on the same queue that feeds `/SimpleDebugger.interface/G.`:

| Symbol | Address | Sends | Field at `[sp,#0xc]` |
|---|---|---|---|
| `sltSendUserCodeAcceptedMsg` | `0x13c408` | `VALID USER CODE` | 1 |
| `sltSendUserCodeDeclinedMsg` | `0x13dbb4` | `USER CODE DECLINED` | 3 |
| `sltSendUserCodeDeclinedWithReasonMsg` | `0x141f10` | the reason string, `QString::toAscii` then `strcpy` | — |

These are reached from the **web** signal path, not only the touchscreen:
`CUiReceiverThread::wsigUserCodeAccepted`, `wsigUserCodeDeclined` and
`wsigUserCodeDeclinedWithReason` (the `w` prefix marks the web variants),
alongside the local `CKeyPadWin::sltHandleUserCodeAccepted` / `Declined`.

The declined slot also calls `SetGotoStatus(0)` before sending.

**So a client that watches the stream can stop guessing.** Instead of assuming a
command took effect and reconciling later, wait for `VALID USER CODE` or
`USER CODE DECLINED`, and take the reason string when the panel supplies one.
On an alarm panel that is the difference between showing a user what was asked
for and showing them what happened.

Not yet captured live. Doing so means entering a real code on a live system:
the accepted path arms or disarms, and the declined path increments the
failed-login counter that lives on the reflash-surviving partition. The symbol
path, the message construction and the web signal wiring are all read directly
from the binary, but the literal frame text has not been observed on the wire.
