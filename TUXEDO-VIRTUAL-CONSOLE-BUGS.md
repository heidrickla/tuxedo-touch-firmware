# The virtual console page — why it is buggy

> **CONFIRMED BY THE OWNER: the virtual console arms and disarms the system
> exactly like the physical keypad.** It is a real keypad, not a monitoring
> view. Every defect below is therefore a defect in a *control surface for a
> live alarm system*, which raises the severity of the ones that silently drop
> or misdirect keystrokes.

Analysis of `script/consoleRequest.js` and `consolekeypad.html` from the panel's
own web application. All **[CONFIRMED]** by reading the shipped code.

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

The commented-out lines reference **`SessionPage.htm`**. The file that actually
ships is **`SessionPage.html`**. The active mobile code uses `.html`.

So the desktop redirect pointed at a filename that does not exist. The likely
history is that it 404'd, and someone commented it out instead of correcting the
extension.

**Fix:** re-enable the redirect and correct the filename to `SessionPage.html`.
One character and one comment marker.

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
