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
