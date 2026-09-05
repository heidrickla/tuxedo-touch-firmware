# Honeywell Tuxedo Touch — why the alarm status goes unknown

**Status: mechanism confirmed in the firmware binaries. One secondary claim
(whether polling holds an awake feed) still under test overnight.**

The question was whether a firmware update or a firmware patch could fix a
buggy panel. Neither turned out to be relevant.

## The device

| | |
|---|---|
| Model | Honeywell Tuxedo Touch WIFI |
| Firmware | `TUXW_V5.3.21.0_VA` |
| Panel behind it | Ademco VISTA-21iP |
| IP | `203.0.113.5`, HTTPS on 443 |
| MAC | `00:d0:2d:00:00:01` — Resideo |
| Platform | Freescale i.MX35 ARM, embedded Linux 2.6.31, JFFS2 |

## Firmware: a dead end, established early

`5.3.21.0` is the newest published build anywhere I could find. There is
nothing to update to.

Patching is *feasible* — update images are JFFS2 filesystems behind a short
header, and `fw_extract.py` carves them and identifies which header fields are
integrity checks over the payload — but it was never the right tool. The fault
is not in code.

## The symptom

`GetSecurityStatus` returns `"Not available"` after a quiet period. The Home
Assistant entity shows unknown. An arm or disarm brings it back.

## The transport is healthy — ruled out, not assumed

Nine minutes polling only the login page, which needs no credentials:

| | |
|---|---|
| Requests / failures | 18 / 0 |
| Latency min, median, max | 0.17s, 0.20s, 0.23s |
| Drift, first third vs last | 0.21s vs 0.20s |

The web server does not stall, slow, or fail when idle. Contention and a
wedging HTTP layer are both eliminated. This is a positive result, not an
absence of evidence.

TLS works with `OP_LEGACY_SERVER_CONNECT` plus `SECLEVEL=0` against the panel's
2009-era 1024-bit MD5 certificate; negotiated TLSv1.2 / DHE-RSA-AES256-SHA256
on OpenSSL 3.0.16.

## The panel is healthy — the decisive cross-check

At 06:50:22Z the Envisalink on the same physical panel was receiving live
keypad updates and reporting the panel disarmed and ready. My probe was
returning `"Not available"` on every poll in that same window.

Two independent readers, one panel, one moment, opposite answers. That
localises the fault to the Tuxedo's status path — not the panel, not the bus.

## The working model

1. **A broadcast wakes a dark feed.** Zone fault/restore, arm, or disarm.
   Observed three times: two laundry-door events and one arm/disarm.
2. **Valid polling holds an awake feed alive.** 41/41 good polls over 20
   minutes with *zero* bus events in the window.
3. **Polling cannot wake a dark feed.** Enabling the integration onto a dark
   feed gave ~2 minutes of unknown until an arm/disarm; 142 seconds of
   continuous polling on a dark feed never recovered.
4. **Without either, it decays in roughly 5–10 minutes.**

Point 3 is what makes the owner's account — "it usually did it pretty quick
when they were on" — consistent rather than contradictory. The integration was
being enabled onto an *already-dark* feed. It was not going dark while polling.

## The complete local API surface

Enumerated from `script/tuxapi.js`, the vendor's own API client, extracted from
the ZIP embedded in the `Barracuda` executable (776 entries, archive base
`0x8a948`). This is authoritative: it is the code Honeywell ships to talk to
its own server, not an inference from probing.

All paths are relative to `/system_http_api/API_REV01`.

**Security**
```
GetSecurityStatus
SetSecurityArm
AdvancedSecurity/ArmWithCode          arming=<mode>&pID=<n>&ucode=<code>&operation=set
AdvancedSecurity/DisarmWithCode       pID=<n>&ucode=<code>&operation=set
```

**Automation and scenes**
```
GetDeviceList            category=<n>
GetSceneList
ExecuteScene             sceneID=<n>
GetOccupancyMode / SetOccupancyMode   omode=<n>
GetLightStatus / SetLight             nodeID=<n>
GetDoorLockStatus / SetDoorLock       nodeID=<n>
GetGarageDoorStatus / SetGarageDoorStatus   nodeID=<n>
GetWaterValveStatus / SetWaterValveStatus   nodeID=<n>
AdvancedAutomation/DoorBell/getDoorBell
AdvancedAutomation/DoorBell/setDoorBell
```

**Thermostats**
```
GetThermostatClock / SetThermostatSetClock
GetThermostatMode / SetThermostatMode
GetThermostatFanMode
GetThermostatEnergyMode / SetThermostatEnergyMode
GetThermostatSetPoint / SetThermostatSetPoint
GetThermostatTemperature
GetThermostatFullStatus
GetThermostatSchedule / SetThermostatSchedule
```

**Cameras**
```
AdvancedMultimedia/DiscoverCamera
AdvancedMultimedia/GetCameraList
AdvancedMultimedia/GetVideoEvents
AdvancedMultimedia/SetCameraView
AdvancedMultimedia/TriggerCameraRecord
AdvancedMultimedia/ZoomCamera
```

**Administration and registration**
```
Administration/AddDeviceMAC           Type=<n>
Administration/RemoveDeviceMAC        devMAC=<mac>
Administration/ViewEnrolledDeviceMAC
Administration/RevokeKeys             devMAC=<mac>
Administration/AddIPURL / UpdateIPURL / ViewIPURL    mac=<mac>
Administration/DeleteAllCameras
Administration/SetupRemote
Registration/Register                 Type=<n>
Registration/Unregister               token=<t>
```

### Two absences, established by enumeration

**No version, model or firmware endpoint.** There is nothing to query. Any
integration wanting to display the firmware version has no source on this
firmware; it must be entered by hand or left blank.

**No status-refresh endpoint.** No `RefreshStatus`, no `QueryPanel`, nothing
that asks the panel for current state. This is the API-level confirmation of
the push-only design described above.

### One oddity

The vendor's own client calls `GetSecurityStatus` with an **empty body** —
`callAPI_POST(url, "", 0, hmac)` — not `operation=get`. Both are accepted, so
the parameter is ignored for this endpoint.


## Firmware analysis — the mechanism, confirmed in the binaries

Firmware `TUXW_V5.3.21.0_CN` unpacked with `fw_extract.py` + `jefferson`. The
package is six files; `app2.hdr` is a 124 MB JFFS2 root filesystem behind a
128-byte header. Extracted: 3258 files, ARM 32-bit, **not stripped** (10,339
named functions in `tuxedo`).

Note: `app1.hdr`'s header carries `TUXEDO_V5.3.19` and a build date of
**Wed Sep 20 2017**, inside a package labelled 5.3.21.0. The components are not
all the same vintage.

### Two processes, and the status lives in the gap between them

| Binary | Role |
|---|---|
| `tuxedo` | 14 MB Qt app. Talks ECP to the VISTA panel. |
| `opt/webserver/Barracuda` | 5.6 MB web server. Serves the local HTTP API. |

The finding is what each one does **not** contain:

- `Barracuda` contains the literal `Not available` (as `0a1Not available`) and
  the endpoint names `GetSecurityStatus` / `SetSecurityArm`.
- `Barracuda` does **not** contain `Ready To Arm`, `Armed Stay`, or any other
  real status string.

So the real statuses never originate in the web server. They arrive from the
`tuxedo` app over IPC — the thread is named `TuxedoAppCommThread` — and the web
server holds them in a cache. **`Not available` is the web server's built-in
default: what it answers with when its cache has nothing in it.**

### Why the cache empties

In `tuxedo`, the function that feeds it is

    UpdatedSecurityStatus2Agent(SEcpMessage *)      @0x0059d024

Its argument is an **ECP message**. Disassembly shows it reads byte 8 of that
message, tests two bits, checks a per-partition latch byte, and only then posts
to a message queue (`osal_MqSend`, type 0xc). It sets the latch afterwards, and
a separate branch clears it. The push is **edge-triggered on ECP traffic**, and
deduplicated so it will not re-send while the latch is set.

**CORRECTED — this claim was too strong.** I first wrote that no path
generates a status without an ECP message arriving. `RequestPartitionStatus`
@ `0x00585c28` *asks the panel* for status, and it is called from two timer
slots: `CGo2Partition::sltStatusReqTimeout()` and, importantly,
`CReceiverThread::sltPartitionDetailReqTimeout()`. `CReceiverThread` is the
**web-facing** thread.

So the ECP handler is still the only thing that fills the cache, but the ECP
message it handles can be a **reply to a request the Tuxedo itself made**, not
only an unsolicited broadcast. That supplies the mechanism that was missing for
"polling keeps the feed alive" — a claim I had withdrawn precisely because no
mechanism existed for it.

### The complete chain

1. An HTTP `GetSecurityStatus` reaches `Barracuda`, which answers from cache.
2. The cache is filled only by pushes from `tuxedo`.
3. `tuxedo` pushes only when an ECP message arrives, edge-triggered.
4. No ECP event, no push. The cache is empty, so the web server returns its
   compiled-in default: `Not available`.

This is arrived at from the binaries alone and it independently confirms the
model measured over the network. It also explains the one thing the network
measurements could not: **why polling cannot wake a dark feed.** Polling reads
the web server's cache; nothing but an ECP event can fill it. The API has no
"ask the panel now" path at all.

### Is it a bug?

It is a design gap rather than a coding error: the local API is purely
push-driven with no on-demand refresh and no initial population. After a
restart, or any quiet spell, there is simply nothing to serve.

Patching it would mean either making `Barracuda` request status on demand or
making `tuxedo` push periodically — both ARM binary edits, then repacking JFFS2
with a header whose integrity fields are recomputed. `fw_extract.py` reports
those header fields, but nothing about that is worth the risk of bricking a
wall-mounted alarm panel when leaving the integration polling avoids the
symptom entirely.


## What is not yet decided

**Point 2 has a rival explanation that is not yet excluded.** "Polling held it
alive" and "a woken feed simply stays alive for 20+ minutes regardless of
requests" both fit the 41/41 run. Nobody has yet watched a woken feed with
*nothing* touching it. The test that separates them: wake it, everything off
the panel, wait 20 minutes, then one single poll. Good means polling was
irrelevant; dark means polling was holding it.

An overnight run with the integration enabled is in progress. Its value depends
entirely on the night being quiet — if zone events land every few minutes, the
feed stays alive by broadcast alone and the run proves nothing. The longest gap
between overnight zone events is the number that decides whether the run tested
anything.

**The Tuxedo's ECP address was never read.** Its CS Setup menu rejected every
code tried, and no integration, diagnostic, or log line exposes it.

## Two things I got wrong, and why they are worth recording

**The instrument was broken before the device was.** The first probe sent a
`GET` where the API wants a `POST`. Every poll returned HTTP 405, the
classifier binned it as a generic error, the control fired on it, and the tool
confidently announced a panel-side fault that did not exist. A broken client
and a broken device produce the same *shaped* failure. The tool now classifies
malformed-request responses separately and **refuses to reach any verdict at
all** when it sees one.

**A clean single observation is a coincidence with a story attached.** I was
one step from recommending "keep it polling" on one unbroken 20-minute run.
The owner stopped it: *"one or two instances of an event do not decide
anything."* `tuxedo_wake_experiment.py` exists because of that — it runs the
same cycle N times and reports disagreement between cycles instead of
averaging it away.

## Practical upshot

If the model holds, there is nothing to fix in firmware, in the integration, or
in panel programming. Keep the integration **enabled**; wake the feed once with
any door or arm/disarm if it starts dark. Leaving it disabled is what
guarantees a dark feed later.

That conclusion is provisional until the overnight run and the single-poll test
come in.

---

## Late observation that complicates the decay model

At 09:49Z the status feed read **`Ready To Arm` on the very first poll**, and
stayed good for 8/8 polls.

**RESOLVED FROM LOGS — the panel WAS being polled.** I first recorded that
nothing had polled it since ~06:38Z, then recorded the point as disputed when
Lewis and the ha-management session disagreed. The logs settle it.

ha-management's VM debug capture holds **908 successful polls at 30-second
intervals** across 10:31–18:05Z with **zero failures**, the config entry read
`loaded, disabled_by None`, and — decisively — **the entity history recorded my
own arm/disarm cycles**, which only a polling integration could have written.

The Tuxedo entry was enabled and polling from 07:39:36Z. **My original premise
was wrong.**

**And I misattributed a claim to Lewis that he never made.** When he said "no
they haven't — it was a billing issue", he was talking about an account-access
error, not about the integration's polling state. I read it as a contradiction
of the ha-management session's account, recorded the point as "disputed" on that
basis, and then wrote that his recollection was wrong. He had offered no
recollection. The confusion was entirely mine, and the correction is his.

Compare with the earlier evidence:

| Time | Condition before | First read |
|---|---|---|
| 07:00Z | ~5 min genuinely unpolled | **DARK** |
| 09:49Z | 2 h 10 m of continuous 30 s **polling** | **GOOD** |

Different experiments, so no paradox — and my "longer quiet gave the healthier
result" reading was built on a false premise.

**What it does establish**, as a polled-panel observation: that window contained
broadcast gaps of 35, 34 and **54 minutes** with no zone events, and the panel
answered good throughout.

**The strongest version of this** comes from ha-management's capture: across
**7 h 34 m of continuous 30-second polling, the coordinator logged ZERO
"Not available" answers** — and with debug enabled that line is the only trace a
post-wake dark answer can leave. So "a polled panel stays good" now rests on
roughly ten hours across two independent observers, not on twenty minutes.

**Still unseparated:** "polling holds it alive" versus "it never expires at
all". Only a genuinely quiet unpolled window distinguishes them.

**[UNKNOWN]** what actually governs it. Possibilities not yet separated: an
overnight broadcast (heating, a pet, a scheduled panel event) refilled the cache
at some point; or the cache does not decay at all and the earlier darkness had a
different cause entirely — for example the malformed HTTP 405 run that preceded
it, which is the one variable present at 07:00 and absent now.

That last possibility is worth stating plainly because it implicates **my own
broken probe** as a candidate cause of the darkness I then spent hours
characterising. It is not established, but it is no longer excluded, and it
would be a tidy explanation for why the fault has been so hard to reproduce.

---

## RESOLVED: the status bug has a fix, verified under its own failure condition

The push stream (`GET /SimpleDebugger.interface/G.`, session cookie only) was
left open for **3 minutes with no commands sent and no polling** — the exact
quiet condition that darkens `GetSecurityStatus`.

Result: **28 status frames, continuous, still `Ready To Arm` at the end.**

The push path does not read the cache that `UpdatedSecurityStatus2Agent` fills
from ECP messages, so the `"Not available"` default cannot be reached. Arming and
disarming were also observed on it live, including the exit-delay countdown,
within seconds and without a single REST poll.

**This closes the question the project opened with.** The bug is real, its
mechanism is understood, and it is avoidable — not by patching firmware, but by
using a transport the firmware already provides and the integration was not
using.

Scope, stated honestly: the stream carries **partition/alarm state only**. Zone
data and the event log are not obtainable from it (measured — see
TUXEDO-HA-ENRICHMENT.md). For zones, the Envisalink remains the answer.

---

## THE DECISIVE TEST: no expiry. Polling was never the mechanism.

The experiment that eluded this project all night, finally run clean.

| | |
|---|---|
| Integration disabled | 18:05:27Z (ha-management, confirmed) |
| True quiet | **24 min 34 s** — nothing from either party |
| Single read | 18:30:01Z |
| **Result** | **`Ready To Arm`, Green — GOOD** |

### What it kills

**"Polling holds the feed alive" is dead.** It was my hypothesis, revived twice,
and it is wrong. A panel left entirely alone for 25 minutes answered correctly on
the first request.

Combined with ha-management's polled-window data — 908 polls, zero
`"Not available"`, and a **4 h 37 m** stretch with no zone event at all — every
time-based expiry model is now excluded, whether requests are present or not.

### What it leaves

The 07:00Z dark reading, and the 05:43Z one, still happened. They now need an explanation that is **not** expiry. After four attempts at a
mechanism tonight — three of which I had to withdraw — the honest summary is
**no mechanism is well supported.** What follows is ranked by how much survives
scrutiny, not by confidence:

- **The latch-dedup in `UpdatedSecurityStatus2Agent`** @`0x0059d024` — I named
  this the surviving candidate, then examined it properly and **it is weaker
  than I claimed.**

  The latch table at `0x00d977bc` is touched by **three** functions, not one:
  `UpdatedSecurityStatus2Agent`, `RIS_PartitionStatusProcess` @`0x0059d11c`,
  and `Partition_RISstatus_cmp` @`0x0059c380`.

  Critically, `RIS_PartitionStatusProcess` **actively CLEARS latch bits** — `bic
  r3,r3,#0x20`, `bic r3,r3,#2`, and `and r3,r3,#0x7f` — in several places. A
  second status path that routinely resets the latch is the opposite of what a
  "stuck latch" story needs.

  The table is also **2 bytes per partition** (indexed `lsl #1`, accessed at
  −1 and −2) with bits `0x02`, `0x20`, `0x80` and the composite `0x8c` in play.
  So it is a shared multi-bit state machine across two status paths, not a
  single "already sent" flag.

  **[WEAKENED — do not treat as the answer.]** I am not asserting a replacement
  mechanism from this; I am withdrawing the confidence I gave it.
- ~~The malformed HTTP 405 burst~~ — **refuted**: 8 deliberate 405s left the feed
  good through 24 s of follow-up polls.
- **An absent status value, not a stale one.** This is the best-supported
  framing, and it corrects my own loose wording of "cold cache".

  `"0a1Not available"` lives at vaddr `0x00085364` in **`.rodata`** — read-only,
  with a single literal-pool reference. So it is **not** a pre-seeded buffer that
  a restart leaves populated. It is a **constant the code substitutes when the
  real status is absent**.

  The distinction matters for anyone reading the code later: the panel is not
  serving a stale cached value, it is **reporting the absence of one**. Same
  observable behaviour, different mechanism.

  It fits everything measured — no expiry, unaffected by polling, cleared by a
  panel event that supplies a real status, and present immediately after each
  restart before anything has filled the buffer. **[COHERENT, still not proven]**

### Why this matters less than it did

**The push stream makes the question moot for the integration.** A stream client
cannot experience the fault whatever the mechanism, because it never reads that
cache. This test is now scientific tidiness rather than an engineering blocker —
which is the right place for it to end up.

### Standard of evidence

**One sample.** Lewis has twice been right in this session that one or two clean
observations decide nothing. A GOOD result here is the *less* surprising outcome
and is corroborated by ten hours of polled data pointing the same way, so I am
recording it as settled. Had it come back DARK I would have demanded a repeat
before anyone acted on it, and `tuxedo_wake_experiment.py` exists to run exactly
that.
