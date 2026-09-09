# The virtual console page — why it is buggy

> **CONFIRMED BY THE OWNER: the virtual console arms and disarms the system
> exactly like the physical keypad.** It is a real keypad, not a monitoring
> view. Every defect below is therefore a defect in a *control surface for a
> live alarm system*, which raises the severity of the ones that silently drop
> or misdirect keystrokes.

Analysis of `script/consoleRequest.js` and `consolekeypad.html` from the panel's
own web application. All **[CONFIRMED]** by reading the shipped code.

## Where these files actually live, and why it changes the effort estimate

They are **not loose files on the filesystem**. `/opt/webserver/` contains one
thing, the `Barracuda` binary. The entire web application is a **776-entry ZIP
archive embedded inside that binary**, occupying file offsets
`0x8a948`-`0x4f0113` (about 4.6 MB), which is how the Barracuda App Server's
ZIP filesystem works.

Consequences for anyone planning to fix these bugs:

* Editing a page is **ZIP surgery inside an ELF**, not a text edit.
* The archive sits in the middle of the file, so it **cannot change size**.
  Everything after it would shift and the ELF would break.
* Therefore each modified entry must recompress to **exactly** its current
  compressed size. `script/consoleRequest.js` is 17,130 bytes raw and 3,625
  deflated. The practical technique is to make the edit, recompress, then pad
  the source with spaces inside a comment and binary-search the padding length
  until the deflated size lands exactly on the original.
* Both the local file header and the central directory record the sizes, so
  both must agree.

This is all doable, and the required edits are small. It is simply a different
and larger job than "edit a JavaScript file", which is what the fix list below
implies if read without this section.

The owner reports the virtual console is unreliable and that "the timeout was
problematic". There is a specific cause, and several contributing defects.

---

## 1. THE TIMEOUT BUG: session-expiry handling is commented out

This is almost certainly what was hit.

In `consoleRequest.js`, the line that redirects to the session-expired page is
**commented out**. The same is true in `armcontrolscript.js` (twice) and
`camerasetup.js`.

Meanwhile the **mobile** UI (`script/mobile/script/security.js`) has the
equivalent redirect **active**.

So on the desktop console page, when the session expires:

- the page carries on sending requests,
- every one fails,
- the failures are swallowed (see §2),
- and **nothing tells the user**.

The console simply goes dead. Keys do nothing, no error appears, and the only
clue is that it stops working. That matches "buggy" and "timeout was
problematic" exactly.

### Why it was probably disabled rather than fixed

The commented-out line, verified in the shipped archive, is
`script/consoleRequest.js` line 105:

```javascript
//document.getElementById("framConsole").src="/SessionPage.htm";
```

It references **`SessionPage.htm`**. **CORRECTION to an earlier draft of this
file:** I previously wrote that the file which actually ships is
`SessionPage.html`. That is wrong. There is no `SessionPage.htm` *or*
`SessionPage.html` anywhere in the web archive. The session-expiry page that
does ship is **`sessiontimeout.html`**, a 299-byte page whose entire body is
the heading "Your Session Has Expired".

So the redirect pointed at a filename that has never existed under either
extension. The likely history is that it 404'd and someone commented it out
instead of correcting the name.

**Fix:** re-enable the line and point it at the page that exists:

```javascript
document.getElementById("framConsole").src="/sessiontimeout.html";
```

Net change is +2 characters of source, which matters because of where the file
lives (see below).

---

## 2. All send errors are silently swallowed

Both send paths wrap the request in a try/catch whose handler is **empty**. A
failed send is indistinguishable from a successful one — to the code and to the
user.

Combined with §1 this is what turns "session expired" into "the console
mysteriously stopped responding".

**Fix:** surface the error. At minimum distinguish a transport failure from an
auth failure, and show something.

---

## 3. Keystrokes are lost when a send fails

The keystroke buffer is cleared **unconditionally**, immediately after the send
is attempted — inside the same block whose errors are discarded.

So if a send fails for any reason, the buffered keys are gone. The user pressed
them; the panel never saw them; nothing reports it.

**Fix:** only clear the buffer once the request is known to have succeeded.

---

## 4. A 1500 ms debounce, which is far too long for a keypad

Keystrokes are batched. Each keypress resets the timer and re-arms it for
another 1500 ms, so **nothing is sent until 1.5 seconds after the last key**.

For an alarm keypad this is a poor fit:

- typing a four-digit code sends nothing for a second and a half after the last
  digit,
- the panel's display does not react as you type, so it feels broken,
- and on entry delay that latency is spent doing nothing.

**Fix:** shorten it substantially, or send each keystroke immediately. The panel
accepts pipe-separated batches, so a much shorter window (100–200 ms) keeps the
batching benefit without the dead feel.

---

## 5. A race between dispatch and buffer clear

The send reads the buffer, then clears it. The request is asynchronous. A
keypress landing between those two statements is written into the buffer and
then wiped by the clear — **silently dropped**.

Narrow window, but a keypad is exactly where fast successive keypresses happen.

**Fix:** snapshot the buffer and clear it atomically before dispatching, rather
than clearing after.

---

## 6. No keepalive while the console is open

Nothing refreshes the session while console mode is in use. A user who opens the
console and reads the display without pressing anything will have the session
expire underneath them — and then hit §1.

**Fix:** either poll the console status on a timer (the code already has
`CONSOLEMODESTATUSADD` / `SUB`, 1125/1126, for subscribing to console status),
or issue a lightweight keepalive.

---

## Summary, ranked by what to fix first

| # | Defect | Severity | Effort |
|---|---|---|---|
| 1 | Session-expiry redirect commented out, wrong filename | **high** | trivial |
| 2 | Empty catch blocks hide all failures | **high** | trivial |
| 3 | Buffer cleared even when the send failed | **high** — this silently drops keypad input to a live alarm panel | small |
| 6 | No keepalive during console use | medium | small |
| 4 | 1500 ms debounce | medium | trivial |
| 5 | Dispatch/clear race | low | small |

Items 1, 2 and 3 compound into the observed symptom: the console stops working,
loses your keystrokes, and tells you nothing. Fixing those three would address
most of the reported unreliability.

---

## Relevance to Home Assistant

This matters beyond the web page. Console mode is the richest status source on
the panel — it returns the actual two-line keypad display rather than a single
status word, and it reads the panel directly instead of the cache that causes
the `"Not available"` bug.

A Home Assistant client implementing console mode should:

- treat session expiry as a first-class case and re-authenticate, rather than
  inheriting the web page's silence,
- not batch keystrokes at all,
- confirm the send before discarding anything,
- and keep the session warm while subscribed.

In other words: the web page's bugs are avoidable in a fresh client, and its
source is still the best available documentation of the protocol.

---

## RETRACTED: "the real root cause, found by live testing"

**Everything in the section below is wrong, and it is wrong because of a URL
typo I made.** It is kept verbatim rather than deleted, because the reasoning
looks convincing and someone re-reading this file needs to see why it failed.

The claim was that `/SimpleDebugger.interface` 404s on this unit, that the push
channel is therefore unregistered, and that the console is broken at the
transport rather than in the page. The conclusion drawn from that — "repairing
the six JS defects would make the page honest about failing, but would not make
it work" — was used to deprioritise the whole fix list.

The channel is not dead. The correct URL has a **slash before the `G.`**:

```
GET /SimpleDebugger.interface/G.        <- works
GET /SimpleDebugger.interfaceG.         <- 404
```

The vendor's `eh.js` appends `G.` to a base that already ends in a slash, which
is exactly how I got it wrong. Every 404 I recorded came from requesting a path
that does not exist. The channel works, carries live partition status, survives
idle, and supports multiple concurrent clients; it is the transport the status
fix in `tuxedo_push.py` is built on.

**So the six JavaScript defects are not a sideshow. They are the story.** The
fix list at the top of this file stands as written, and it is web work in files
that live in the root filesystem, not firmware work.

The general lesson, which is why this retraction is this long: a negative result
from a hand-constructed URL is evidence about the URL first and about the server
second. I inverted that, and it nearly buried the finding this whole project
turned on.

---

## THE SUPERSEDED SECTION, kept for the record

The six JavaScript defects above are all real. **None of them is the main
problem.**

Live against the panel: entering console mode, subscribing to console status,
and requesting the console broadcast (commands 19, 1125 and 20) each return
**HTTP 200 with a zero-byte body**. `/consolekeypad.html` carries no
`consoleText` element before or after. There is no display text to render.

Command replies are delivered over Barracuda's EventHandler push channel,
`/SimpleDebugger.interface`. On this unit that endpoint **404s** — on GET, on
POST, and on every URL suffix the vendor's own `eh.js` constructs. The channel
is not registered.

**So the virtual console is broken at the transport, not in the page.** Its
display is fed by a mechanism that does not run. The JavaScript defects make the
failure silent and confusing; the missing push channel makes it total.

That also revises the fix list: repairing the six JS defects would make the page
*honest* about failing, but would not make it work. Restoring the push channel
is the actual fix, and that is firmware work, not web work.

---

# Console mode, mapped from the binary (2026-09-06)

`/tuxedo` has a full symbol table, so the whole mechanism reads directly. This
replaces the earlier UNVERIFIED reconstruction from `consoleRequest.js`.

## The dispatch

`CReceiverThread::run` at `0x147158`, command `0x13` (19):

    0x147604  cmp  ip, #0x13
    0x147608  bne  <next case>
    0x14760c  ldr  r2, =0xd2f269
    0x147610  mov  r3, #1
    0x147614  str  r3, [r5, #8]      ; gate 2: this+8 = 1
    0x147620  strb r3, [r2]          ; gate 1: the global byte = 1
    0x147624  bl   CReceiverThread::requestconsolemode

`requestconsolemode` at `0x13db5c` is 88 bytes and branches on a key count:

    r6 = [req + 0x2e]                 ; number of keys
    r6 == 0  ->  bl wsltHandleRawDataFromPanel      ; ask for the display
    r6 >  0  ->  for each key at [req + 0x2f]:
                     apl_sendEcpConsoleModeData(&key, 1)

So one request either **reads** the display or **sends** keys, never both.

`CReceiverThread::wsltHandleRawDataFromPanel` at `0x13da00` builds the display
message and sends it with `osal_MqSend`, message size `0x22c`, **command id
`0x14` (20)**. It fetches two 16-character lines via `apl_getEcpConsoleModeData`,
replaces any byte above `0x7e` with a space, concatenates them, and sends.

**The queue is the same one the partition status uses.** Both
`wsltHandleRawDataFromPanel` and `CReceiverThread::sltSendChangedPartitionStatus`
load the handle from `0xd2f29c`. Verified by resolving both literal pools. So a
console display frame should appear on the push stream exactly as `0:21:` frames
do, as `0:20:...`.

## Three gates, all of which must pass

    0x13da0c  ldrb r2, [0xd2f269]     ; set by command 19
              cmp  r2, #0 / beq       ; 0 -> return, silently
    0x13da34  bl   GetOperationMode
              cmp  r0, #1 / beq       ; 1 -> skip the next check
    0x13da44  bl   GetCurrentArmingState
              cmp  r0, #0xff / beq    ; 0xff -> bail
    0x13dad4  ldr  r3, [this + 8]
              cmp  r3, #0 / beq       ; 0 -> return before MqSend

## Correction: the zero-byte body is not the bug

This document previously treated `handlerequest.html` returning **HTTP 200 with
a zero-byte body** as the defect. It is not. Measured against the live panel:

| Command | Response |
|---|---|
| 19, console mode | HTTP 200, 0 bytes |
| 1125, subscribe | HTTP 200, 0 bytes |
| 55, home refresh | HTTP 200, 0 bytes |
| **999999, nonsense** | HTTP 200, 0 bytes |
| **0** | HTTP 200, 0 bytes |

Valid, invalid and nonsense commands are indistinguishable. `handlerequest.html`
is **fire and forget**: it never returns a result, and every answer comes back on
the push stream. The vendor's own pages work this way, reading results from the
event stream in the `panelStatusContent` iframe.

That means a zero-byte body is not evidence of anything, and any client that
waits for a result in the HTTP response will wait forever.

## A real bug, found and fixed

`Console._session_id()` in `tuxedo_api_console.py` matched
`id="hidSession"[^>]*value="..."`. On this firmware the attributes appear in the
other order, so the pattern matched across elements and returned the literal
string **`id=`**. Every `handlerequest.html` command was therefore sent with a
garbage `sessionid`. Fixed by trying both orders; the panel now returns real
values such as `-2094665682`.

The same call also sent `tokenkey=""`. The vendor pages take it from the hidden
field `hiddenKey` in `eventhandler.html` (`getKeyFromEV()` at
`script/eventHandler.js:1260`) and `script/httpRequest.js:49` additionally sets
it as a **request header**. Both are now sent. On this panel the value is `-1`.

The exact request, from `script/consoleRequest.js:12`:

    /handlerequest.html?cmd=<N>&Type=<N>&pID=-1&uCode=0&sessionid=<SID>
        &filters=0&index=0&tarTemp=0&tokenkey=<TOK>&sid=<random>

## Still not working, and what to try next

With a valid session, a real tokenkey, and command 19 accepted, **no `0:20:`
frame has been observed** on the push stream, with or without a preceding
keystroke.

Since the queue is shared and the frame would be visible if sent, the function is
returning before `osal_MqSend`. Both remaining gates have now been read.

    GetOperationMode        0x583068, 28 bytes
        ldrsb r0, [0xd96e38 + 0x6c]        ; one signed byte, a global

    GetCurrentArmingState   0x596f60, 108 bytes
        ip = 1
        if globalPtr == 0            -> return 1
        if [obj + 0x65] != 0         -> return GetPartitionStateVector() & 0xff
        ip = 0xff
        if (operationMode - 2) > 1   -> return 0xff        ; unsigned compare
        else                         -> GetPartitionStateVector() & 0xff

So `GetCurrentArmingState` returns the bail value `0xff` **only** when the flag at
`obj + 0x65` is clear **and** the operation mode is neither 2 nor 3. Combined with
the `cmp r0, #1` on `GetOperationMode` in the caller, the display is produced
whenever the operation mode is **1, 2 or 3**, and suppressed otherwise.

The operation mode is one byte at `0xd96ea4`, and it gates far more than this:
`GetOperationMode` has **68 callers**, including `main`, `CHomeScreen`,
`CSecuScreen` and `CStatusPrompt::updateTopStatusBar`. The binary also carries the
string `ARMING/DISARMING - Can't be done at this time. System in Stand By Mode!`,
so at least one mode value means standby.

Reading the live value needs ptrace: `/proc/<pid>/mem` on 2.6.31 refuses a plain
read, and the panel has no debugger. So the value is not known.

**The cheap way to settle it** is behavioural rather than static, and takes half a
minute. Open Console Mode on the touchscreen (More Choices, then the console-mode
button, which is `CMoreChoiceSr::sltHandleConsoleModeButtonPress`) and watch the
push stream while sending command 19. If `0:20:` frames appear only while that
screen is up, the operation mode is the gate and the web console is a mirror of
the touchscreen screen rather than an independent client. That would also explain
why the vendor's own page is built as an iframe beside the panel status view.

## Settled: the operation mode is 0, and it does not come from the UI

Read out of the live process rather than reasoned about. `/proc/<pid>/mem`
refuses a plain read on 2.6.31 and there is no debugger on the panel, so a
thirty-line `ptrace` reader was built for it (`tools/peek.c`).

    tuxedo pid 907
    00d96ea4  736e4900  bytes 00 49 6e 73

The byte `GetOperationMode` returns is the first of those: **0**.

The address was checked against the ELF rather than trusted: `0xd96ea4` falls in
`.bss` (`0xd0d110`, size `0x9e1e0`), and the words from the struct base
`0xd96e38` read as a plausible configuration block (`1, 0x82, 0x82, 0x20, 1, 1,
0, 0, 0x7530`) rather than string data. The `"Ins"` bytes following the mode are
a separate char array in the same structure.

With mode 0: `cmp r0, #1` fails, so `GetCurrentArmingState` is consulted;
`(0 - 2)` unsigned is `0xfffffffe`, which is `> 1`, so it returns `0xff` and
`wsltHandleRawDataFromPanel` bails before `osal_MqSend`. **That is the whole
reason no `0:20:` frame is ever emitted.**

**The touchscreen hypothesis was wrong.**
`CMoreChoiceSr::sltHandleConsoleModeButtonPress` at `0xb1f90` only allocates and
constructs `CConcoleModeSr`; it never touches the mode. Opening console mode on
the panel would not change it.

There is no `SetOperationMode` in the symbol table, only `GetOperationMode` and
**`eil_getOperationMode`** at `0x59c320`. `eil` is the ECP interface layer, and
the struct base is referenced from `apl_initIpSetup`, `main`, `VoiceEnableCheck`,
`RefreshSettingsTimers` and `CHomeScreen::sltHandleInitialSetUpComplete` /
`Cancelled` / `Timeout`. So the operation mode is a **panel-supplied state**
tied to setup and the ECP link, not a UI mode a client can request.

Which means the web console cannot be made to work by sending the right request.
It is gated on a state the alarm panel dictates, and the next question is which
panel states produce 1, 2 or 3.

## REOPENED 2026-09-05: the mode is written by `tuxedo` itself, and 1 is safe mode

The paragraph above says the mode is "a panel-supplied state ... not a UI mode a
client can request", on the grounds that there is no `SetOperationMode` symbol.
That was true of the *symbol name* and false of the behaviour. Re-checked after
`tuxelf.py` was fixed to count tail calls.

The mode byte `0xd96ea4` is offset `0x6c` from the struct base `0xd96e38`, so
every `strb ... [rN, #0x6c]` against that base writes it. There are four:

| site | writes | when |
|---|---|---|
| `main` @`0x34630` | `0` | mode read back `> 3` — an out-of-range clamp |
| `main` @`0x34ba4` | `1` | counter at base`+0x28` increments past 2 |
| `CHomeScreen::sltHandleSafeModePress` @`0x56050` | `r6` | Safe Mode button; also writes `r6` to base`+0x28` |
| `persistent::sltRestartInSafemode` @`0x8c3e0` | `1` | after `apl_writeCurrentDateTimetoConfFile` |

So base`+0x28` is a counter and base`+0x6c` is the mode: `main` sets the mode to
**1** once that counter passes 2, and `sltHandleSafeModePress` resets both.
`sltRestartInSafemode` sets the mode to **1** directly.

Both safe-mode functions are **live connected slots** — each has its class's
`qt_static_metacall` as a caller. This matters twice over: it is what makes them
reachable, and under the old BL-only caller scan they would have shown zero
callers and read as dead code, which would have made this closure look even
firmer than it already did.

**Mode 1 appears to be safe mode, and console mode is gated on 1, 2 or 3.** If
the gate reading earlier in this document is right, then console mode is a
service feature that works in safe mode and is suppressed in normal operation.
That fits the wider pattern of vendor dev tools left in place but disabled
(NEUTERED-TOOLS.md).

**Not tested, and deliberately so.** Entering safe mode restarts the panel into
a degraded state on a live alarm system. That is the owner's call, not a test to
run unprompted. What is established here is only that the mode has in-process
writers and that two of them are reachable slots; that mode 1 == safe mode is
read from the function names and the restart path, not confirmed by observation.

Modes 2 and 3 remain unaccounted for. No writer of either was found.

## The fix is one byte, and it does not need safe mode

Established 2026-09-06. Safe mode turns out to be the wrong lever entirely.

**The operation mode is effectively binary.** All 28 readers of `0xd96ea4` were
classified, and 27 use the identical test:

```
ldrb r3, [rN, #0x6c]      ; the mode
sub  r3, r3, #2
cmp  r3, #1
bls  <mode is 2 or 3>
```

(The two apparent outliers are the same test with different register
allocation.) So the only distinction any of them draws is **mode 2 or 3 vs
everything else**, and mode 0 and mode 1 are treated *identically* by all of
them — including `sltRequestArmAway`, `ArmStay`, `ArmNight` and `Disarm`.

Working the arithmetic: mode 0 gives `0-2 = 0xFFFFFFFE > 1`, mode 1 gives
`1-2 = 0xFFFFFFFF > 1`. Neither takes the branch. **Entering safe mode would not
change the arm or disarm code path at all** — which is reassuring, but also means
safe mode buys nothing except the console gate.

`GetOperationMode`'s callers include `SimulatedPanelFunc`,
`SendToEmulationScreen` and `SafeModeCheck`, so modes 2/3 look like a
simulation/emulation state. Nothing writes either.

### The actual gate

`CReceiverThread::wsltHandleRawDataFromPanel` @`0x13da00`:

```
0x13da0c  ldrb r2, [r3]          ; subscribe flag - zero returns immediately
0x13da18  bne  0x13da24          ; (set by cmd 1125 CONSOLEMODESTATUSADD)
0x13da34  bl   GetOperationMode
0x13da38  cmp  r0, #1
0x13da3c  beq  0x13da50          ; mode == 1 goes straight to the console path
0x13da40  bl   GetCurrentPartition
0x13da44  bl   GetCurrentArmingState
0x13da48  cmp  r0, #0xff
0x13da4c  beq  0x13db20          ; bail - mode 0 always yields 0xff
0x13da50  bl   apl_getEcpConsoleModeData
```

Making the `beq` at `0x13da3c` unconditional takes the console path regardless
of mode, with no global state change and nothing else affected.

| | |
|---|---|
| Binary | `/tuxedo` |
| VA | `0x13da3c` |
| File offset | `0x135a3f` (one byte) |
| Before | `03 00 00 0a` (`beq 0x13da50`) |
| After | `03 00 00 ea` (`b 0x13da50`) |

Only the condition nibble changes, EQ to AL; the target is untouched.

### Why this is low risk

`apl_getEcpConsoleModeData` @`0x59c5d0` is 116 bytes and calls exactly
`osal_MutexLock`, `memcpy`, `memcpy`, `osal_MutexUnlock` — a mutex-protected
copy of two cached 17-byte buffers. **It transmits nothing to the VISTA.** The
patch enables *reading* a cached copy of the keypad display; it does not enable
sending keystrokes, which is the separate `apl_sendEcpConsoleModeData`.

### DEPLOYED 2026-09-06, AND IT IS NOT SUFFICIENT

The patch is installed and live (`/tuxedo` md5 `98370c31...`, backup at
`/tuxedo.orig` `6f8055f5...`, one byte apart; panel rebooted and healthy on it).
**No `0:20:` console frame was produced.** Tested twice with the stream held
throughout: cmd 19 alone, then cmd 500 -> 1125 -> 19, then 19 again after a
delay. 150 and 41 frames captured; ids seen were `-1`, `18`, `21`, `504`, `51`,
`55`, `59`, `80`. No `0:20:` in any of them.

**Two corrections, both to claims made above, both mine.**

**1. `0x13db20` is not a bail, and "the handler always returns early" was wrong.**
The `beq 0x13db20` at `0x13da4c` does not return. It copies a canned 14-byte
string over the display buffer and branches back into the same send path:

```
0x13db20  add r4, sp, #0x23c ; add r4, r4, #1
0x13db28  mov r0, r4 ; ldr r1, [pc, #0x24] ; mov r2, #0xe
0x13db34  bl  memcpy          <- substitutes a canned 14-byte message
0x13db3c  strb r6, [sp, #0x22c]
0x13db40  b   0x13daa0        <- rejoins the normal path
```

So the operation-mode gate selects *which text is sent* -- real console data or a
placeholder -- and never decided *whether* anything is sent. The one-byte patch
is therefore not the fix for "no console frames", and that claim is withdrawn.

**2. The real send gate is per-client, and command 19 already satisfies it.**
The send is guarded at `0x13dad4` by `ldr r3,[r8,#8] / cmp r3,#0 / beq 0x13da1c`,
and `0x13da1c` IS the return. `CReceiverThread::run` sets that same field to 1 at
`0x147614`, immediately before calling `requestconsolemode`, under
`cmp ip,#0x13` -- command **19**. The subscribe byte at `0xd2f269` has exactly
three writers: `run` sets it to 1 on command 19; `home_back_press` and
`unregisterclient` clear it.

So on the `/tuxedo` side, command 19 opens both gates. Nothing there is blocking.

**The block is upstream, in Barracuda**, which most likely never forwards command
19 onto `/Q_ServCmdRcver`. Consistent with everything observed: commands 500,
1125 and 19 all returned an identical `(200, 0)`, because `handlerequest.html`
is fire-and-forget and its response carries no information.

**Status: patch left installed.** It is inert unless the console path is actually
reached, and it is the correct change for that path when something reaches it. It
is not a fix on its own.

**Moot under the replacement plan.** A server reading and writing the queues
directly does not need Barracuda to forward command 19 -- it posts the command
struct itself. See `WEBSERVER-REPLACEMENT.md`.

### Correction: Barracuda DOES forward command 19, and `pID` carries the keys

The paragraph above guessed that Barracuda "most likely never forwards command
19". **Refuted.** Traced in `handlerequest_html076EF::service` @`0x3a2a0`:

```
0x3a524  cmp r5, #0x13        ; command 19
0x3a528  beq 0x3cc94          ; -> the console handler
...
0x3cd4c  mov r2, #0x194
0x3cd54  bl  osal_MqSend      ; 404-byte command struct, UNCONDITIONAL
```

There is no gate on that path. The command is sent.

**The keystrokes ride in `pID`, pipe-delimited.** The handler reads `sessionid`,
then reads `pID` and runs `strtok(pID, "|")` over it, `atoi`-ing each token into
the key array at struct `+0x2f` and writing the count to `+0x2e`
(`sub ip, r6, #1` / `strb ip, [sp, #0x956]`):

```
GET /handlerequest.html?cmd=19&Type=19&pID=<key>|<key>|...&sessionid=..&tokenkey=..
```

The parse loop terminates on a token of **-1** (`cmn r0, #1`). So the test above,
which sent the default `pID=-1`, requested console mode with a key count of zero
-- valid, but empty.

~~Also established: command 1125 does not exist in Barracuda at all.~~
**WRONG — retracted 2026-09-06.** 1125 **is** dispatched. There is a literal-pool
load of it at `0x3a698` inside `handlerequest_html076EF::service`, and
`setConsoleModeAdd` / `setConsoleModeSub` / `getConsoleMode` all list that
function among their callers.

The error was a scan artifact and the mechanism is worth knowing, because it will
recur:

**ARM `cmp` takes an 8-bit value rotated by an even amount. 1125 (`0x465`) and
1126 (`0x466`) cannot be encoded that way**, so the compiler must materialise
them from the literal pool and compare register-to-register. A scan that collects
`cmp #immediate` operands therefore **cannot see them at all** — not "missed
them", *cannot represent them*. Checked:

| value | hex | encodable as an ARM immediate |
|---|---|---|
| 19 | `0x13` | yes |
| 500 | `0x1f4` | yes |
| 504 | `0x1f8` | yes |
| 1152 | `0x480` | yes |
| **1125** | `0x465` | **no** |
| **1126** | `0x466` | **no** |

That is why 1152 appeared in the earlier list and 1125 did not, and why the
absence looked like evidence. **A `cmp`-immediate scan is only valid for values
that are encodable; for anything else it silently reports nothing.** Scan the
literal pool too, or the result is a false negative by construction.

This is the third scan-blindness of the same family in this project, after the
BL-only caller scan that called 1744 reachable functions dead, and reading
`/proc/<pid>/comm` on a kernel that has no such file. In each case the tool
returned an empty result that read as a finding.

### What is actually still unexplained

Command 19 reaches the queue, and on the `/tuxedo` side `CReceiverThread::run`
sets both gates and calls `requestconsolemode`. Yet no `0:20:` frame appears.
So the remaining candidates are, in order of likelihood:

1. The reply is sent but Barracuda does not relay message type 20 onto the push
   stream (a filter on the *outbound* side, which has not been read).
2. `apl_getEcpConsoleModeData`'s cached buffers are empty because nothing has
   populated them -- they are filled from the ECP layer, and with the panel idle
   there may be no console data to copy.
3. The console session needs a non-empty key press to produce a first display
   refresh.

(3) is the cheapest test but it is **deliberately not run**: `pID` keys are real
keypad presses on a live alarm, and this is the control path, not the read path.
That needs the owner's explicit say-so and a chosen key, not an arbitrary guess.

### ANSWERED: candidate (1). Barracuda discards message type 20

`gettuxedoIPCCommFunc` @`0xd5d0` (12336 bytes) is the Barracuda thread that
reads the tuxedo reply queue with `osal_MqRecv` and turns replies into push
frames. It dispatches on message type through a **compare chain, not a jump
table**, covering 42 distinct values:

```
0-10, 18, 19, 21, 22, 25-27, 29, 51, 55, 56, 59, 61, 62, 103-105,
109, 111, 112, 125, 130, 132, 133, 147, 154, 160-162, 504, 716
```

**Type 20 -- `SERV_CONSOLE_MSG_BROADCAST` -- is not among them.** Type 21 is,
which is why `0:21:` partition frames arrive. Type 18 is, which is why `0:18:`
arrives. Type 20 has no case and falls through the chain, so the console display
is discarded before it can reach any client.

That closes the chain end to end:

| step | outcome |
|---|---|
| `cmd=19` to `handlerequest.html` | Barracuda forwards it, `0x3cd54`, unconditional |
| tuxedo `CReceiverThread::run` | sets both gates, calls `requestconsolemode` |
| `wsltHandleRawDataFromPanel` | copies the display, `osal_MqSend` type 20 |
| Barracuda `gettuxedoIPCCommFunc` | routes 20 at `0xd6b8` to the handler at `0xdb8c` |
| that handler | broadcasts as id 20, again as id **-1**, and calls `setConsoleMessage(20, text)` |
| web UI | `commandID=5002` on `/handlerequest_mobile.html` returns `getConsoleMessage()` |

**CORRECTED 2026-09-08. The Barracuda row previously read "no case for 20 --
dropped" and this section concluded console mode "cannot be reached through
Barracuda by any means". Both were wrong.** Type 20 is dispatched by a **range**
arm, not an equality comparison:

    d6b0  cmp r8, #21
    d6b4  beq da80        <- 21, partition status
    d6b8  bcc db8c        <- r8 < 21, the console handler

so the 42-value list, built by enumerating `cmp`/`beq` pairs, could not see it.
**Any "type N is not dispatched" claim derived by enumerating equality
comparisons in a compiler-generated binary-search chain is unsafe** — range arms
are invisible to it.

**Measured with a control:** msgType 20 carrying a unique marker leaves 2 copies
in the guest heap; msgType 23, genuinely absent from the chain, leaves 0. Both
leave one copy in qemu's raw message buffer, so the instrument discriminates.

The handler reads the text at message **+0x0E**, not +0x0F where the type-21
layout puts it — a driver using the type-21 offset sends an empty string.

Because the handler also broadcasts with id **-1**, console display text
already reaches `ha-tuxedo-touch` as `CMD_UNSOLICITED` whenever console mode is
in use. Stock behaviour, not introduced by any patch here.

It also fits the wider pattern exactly: the capability is intact on the panel
side and cut off at the edge -- the same shape as the other vendor dev tools left
in place but disabled.

**Consequence for the replacement, and it is a good one.** A server reading
`/Q_ServCmdTrsmtr` directly sees type 20, because the discard is Barracuda
behaviour and not anything the alarm application does. That moves console mode
from "not fixable" to **free once Barracuda is gone** -- the two-line keypad
display, which is a far richer status source than `GetSecurityStatus`, arrives
on a queue the replacement is already reading.

Reading the display is passive. Sending keystrokes is the separate
`apl_sendEcpConsoleModeData` write path and remains a control surface to be
treated with the same care as arm/disarm.

### The deployed patch is a PREREQUISITE, not dead weight

Earlier in this document the installed patch is called "inert". That
under-sells it and is worth correcting, because it changes whether it should
stay.

The operation-mode gate chooses between two payloads for the type-20 message:

- **gate fails** (mode 0, the shipped state): `0x13db20` memcpys a canned
  14-byte placeholder over the display buffer, then sends type 20 carrying that
  placeholder.
- **gate passes** (patched, or mode 1/2/3): `apl_getEcpConsoleModeData` copies
  the two real cached 17-byte display lines, and type 20 carries the actual
  keypad text.

Barracuda discards type 20 either way, so on stock firmware the difference is
invisible. **But a replacement reading `/Q_ServCmdTrsmtr` receives whichever
payload `/tuxedo` put there.** Without the patch it would receive a canned
placeholder and nothing else; with it, the real display.

So the patch is necessary-but-not-sufficient rather than inert:

| | type 20 sent | payload | reaches a client |
|---|---|---|---|
| stock | yes | canned 14-byte placeholder | no, Barracuda drops it |
| patched `/tuxedo`, stock Barracuda | yes | **real display text** | no, Barracuda drops it |
| patched `/tuxedo`, replacement server | yes | **real display text** | **yes** |
| stock `/tuxedo`, replacement server | yes | canned placeholder | yes, but useless |

**Keep it installed.** It is the half of the fix that lives in the binary we are
not replacing, and it costs one byte.

### Corroborated against the vendor's own client

The web app ZIP embedded in `Barracuda` (`0x8a948`-`0x4f0113`, 776 entries, 94
JS files) extracts cleanly. `script/consoleRequest.js` is Honeywell's own console
client, and it confirms the binary reading independently:

- The keys are accumulated into a hidden field as `"|"+key` and passed as the
  **`pID`** argument -- so `pID` carrying pipe-delimited keystrokes is the
  vendor's design, not an artefact of my reading.
- `sendCommand(SERV_CONSOLE_MODE, SERV_CONSOLE_MODE, -1, ...)` is the vendor's
  own **no-keys refresh** call. So `pID=-1`, which the failed test sent, is
  exactly what Honeywell's client sends to enter or refresh console mode without
  pressing anything. The test was correct; the frame is dropped regardless.
- Accepted key codes are ASCII: `42` `*`, `35` `#`, `65`-`68` `A`-`D`, `48`-`57`
  `0`-`9`.

The constant table is also the vendor's, and matches what this document assumed:
`SERV_CONSOLE_MODE=19`, `SERV_CONSOLE_MSG_BROADCAST=20`,
`SERV_PARTITION_MSG_BROADCAST=21`, `SERV_GET_HOME_PART=18`,
`SERV_PANEL_OFFLINE_MSG_BROADCAST=22`, `SERV_REG_INI_RESP_DATA=504`.

### The type-20 drop was verified, not assumed

`gettuxedoIPCCommFunc` dispatches by compare chain and the scan found no case for
20. Since a range check would defeat a compare-immediate scan, every
`sub`-with-immediate in the function was examined:

- `0xdcac` and `0xe178` -- `sub r0, r3, #0x10` after `add r3, sb, r3`. Buffer
  pointer arithmetic, not a type test.
- `0xde98`, `0xe11c`, `0xe138` -- stack/pointer adjustments.
- `0xe128` -- `sub r3, r1, #9 / cmp r3, #1`. A genuine range check, covering
  types **9 and 10**, both already in the handled set.

No jump table anywhere in the function. **No construct covers type 20.**

(The extracted web app is vendor copyright and is deliberately NOT committed to
this repository. Only the interface facts above are recorded.)
