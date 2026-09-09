# What is actually fixed, and where

Status 2026-09-06. **v12 is built** (see `RELEASES.md`); **v11 is flashed and
running**, with v12's three extra patches already applied live over SSH — so the
running panel and the v12 image are byte-identical in every patched binary. `./verify-panel.sh` confirms every patch site in one command.

This document had drifted: it said v10, and it listed two patches as
"outstanding" that had in fact shipped. The cause was that `verify-panel.sh`
only checked the three Barracuda sites, so nothing contradicted the stale text.
The verifier now checks all six, in all three binaries, plus the 6800 listener —
**a patch nothing verifies is a patch the docs will eventually lie about.**

---

## Live on the panel now

| Fix | Where | Evidence |
|---|---|---|
| Login lockout: 3-strikes-permanent becomes 5 attempts with a 300 s self-clearing lock | `Barracuda` P1 `0xd5fc` | bytes read back from the running binary |
| `/Config` no longer binds the config partition to a URL | `Barracuda` P8 `0xc934` | verifier |
| `supervis` camera listener on 6800 removed | `supervis` P9 `0x45e8` | verifier; 6800 not listening |
| Console-mode payload gate (necessary but NOT sufficient — see below) | `/tuxedo` P10 `0x135a3c` | verifier |
| 56-byte heap overflow in the login tracker | `Barracuda` P6 `0x5cef0` | same |
| Validate hook | `Barracuda` P2 `0xbaf0` | same |
| **SSH** | dropbear, glibc-2.5 linked | root login, pty, `verify-panel.sh` |
| **System logging** | busybox `syslogd`/`klogd`, vendor init script unmodified | both daemons running; dropbear logs without `-E` |
| **15 missing tools** | busybox in `/usr/local/bin` | `awk`, `ping`, `strings`, `vi`, ... |
| NTP client | `/bin/ntpclient` + `NTP_SERVER` | sets the clock and `rtc0` |
| `/etc/hosts` defect we introduced in v8 | rewritten, prose moved to `hosts.ota-notes` | `verify-panel.sh` |
| SD dev hook | `rc.local` runs `/mnt/sd/tuxedo-init.sh` | boot logs |

**The clock is fixed at the source.** The keypad follows the VISTA-21iP; setting
the panel's clock corrected the system time, the HTTP `Date` header and the event
log together. The keypad's own NTP could never have held it.

**Updates no longer need the card moved.** `deploy.py` pushes file changes with
no flash; `push-image.sh` writes a full image to `/mnt/sd` over SSH, md5-verified
on the panel, 125 MB in 64 s.

---

## Solved on the client side, needing no firmware change

| Problem | Where it is solved |
|---|---|
| **Status goes to "unknown"** — the original complaint | `tuxedo_push.py`; the push stream never reads the cache that returns "Not available" |
| The panel's own API console is unusable | `tuxedo_api_console.py` |
| Which REST endpoints work | about six; the rest return their own documentation form |
| Richer Home Assistant data | `TUXEDO-HA-ENRICHMENT.md` |
| Zone types and descriptions | `TUXEDO-ZONE-PROGRAMMING.md` |

---

## ~~Outstanding, with a specified fix ready to apply~~ — BOTH SHIPPED

Both items previously listed here are **applied and verified**: `/Config` (P8,
`Barracuda` `0xc934`) and the 6800 camera listener (P9, `supervis` `0x45e8`).
They are in the live-on-the-panel table above. The offsets quoted in the old
version of this section (`0x14934`, `0x4b88`) were wrong; the verifier carries
the correct ones.

## Console mode: the display path in Barracuda is COMPLETE

**This section previously said Barracuda drops reply type 20 and that console
mode "cannot work through Barracuda by any means". That was wrong. Corrected
2026-09-08 by measurement.**

`/tuxedo` P10 at `0x135a3c` is applied and verified: it selects the *payload* of
reply type 20 — real keypad display text versus a canned 14-byte placeholder.

**Barracuda handles type 20.** `gettuxedoIPCCommFunc` routes it at `0xd6b8` to
the handler at `0xdb8c`, which assigns the text (at message **+0x0E**, not
+0x0F), broadcasts it on the push stream as id 20 and again as id **-1**, and
calls `setConsoleMessage(20, text)` at `0xdc70`. That fills the buffer
`getConsoleMessage()` returns, which is exactly what the web UI's
`commandID=5002` poll on `/handlerequest_mobile.html` serves — `/console.html`
issues it every 5 s from `waitForconsoleStatus()`.

**Measured end to end, with a control.** Injecting msgType 20 carrying a unique
marker leaves **2 copies in the guest heap**; injecting msgType 23, which
genuinely is absent from the chain, leaves **0**. Both leave one copy in qemu's
raw message buffer at the same address, so the instrument discriminates rather
than merely reading high.

And the cache itself can be read: after injecting the marker,
`setConsoleMessage`'s buffer holds

    20:CONSOLEMARK42|LINE2TEXT

which is exactly its own format — `Itoa(20)`, the separator at `0x84f5c`, then
the text — and exactly what `getConsoleMessage()` returns for `commandID=5002` to
print. So the path is confirmed from injected IPC message to the bytes the page
would render, not inferred from the disassembly.

**Reading that buffer needs the second-LOAD delta.** Guest VA `0x55b7e4` is
mapped at host `0x56b7e4` under qemu-user, **+0x10000** — the same delta
`patches.tsv` notes for the P14 attr block. Seeking to the guest VA lands in the
read-only ELF mapping instead and returns S-box data, which looks like a failed
write rather than a wrong address.

**Why the old claim survived, and it generalises.** The "42 message types"
list was built by enumerating the dispatch chain's **equality** comparisons.
Type 20 is routed by a **range** arm instead:

    d6b0  cmp r8, #21
    d6b4  beq da80        <- 21, partition status
    d6b8  bcc db8c        <- r8 < 21, the console handler

`bcc` is unsigned less-than. **Enumerating `cmp`/`beq` pairs in a
compiler-generated binary-search chain silently misses every value handled by a
range arm**, so any "type N is not dispatched" claim derived that way needs
re-checking.

**Consequence for Home Assistant:** console display text is broadcast with id
**-1**, which `ha-tuxedo-touch` treats as `CMD_UNSOLICITED` and feeds to its
partition-status path. That is stock behaviour whenever console mode is in use,
not something introduced by any patch here.

So console mode needs **no** Barracuda change. If the web keypad looks broken,
check which page is served first: `/console.html` carries the keypad as 12 static
`<a class="btn" onclick="sendKeys(...)">` cells with all nine assets serving 200,
while `/consolekeypad.html` contains no keypad markup at all.

## Outstanding, analysed but not reduced to bytes

### Affects the panel in daily use

- **a-2** First visit to the web keypad permanently disables Back and Home.
- **a-3** The web-facing partition-status poller is dead code.
- ~~**a-4** The web interface is effectively single-client.~~ **Refuted
  2026-09-06.** Four concurrent authenticated sessions, distinct session ids, all
  still valid after the others connected. Two push-stream clients also coexist.
  See `LIVE-RESULTS.md`.
- **a-5** Event-log retrieval retries forever every 20 s with no cap.

### Virtual console

Six defects, none patched, and now a seventh thing understood: the display
itself is gated on a panel-supplied operation mode that reads 0 on this unit, so
no client request can turn it on. See `TUXEDO-VIRTUAL-CONSOLE-BUGS.md`.

### Security exposure on the local network

Nine findings, none patched, plus two added since: the TLS private key for 443
and 9443 is recoverable from the firmware, and the panel has no netfilter so it
cannot firewall itself. **Deliberately deferred** to a later release on the
owner's instruction; the mitigation meanwhile is network segmentation.

---

## Known unknowns worth keeping visible

- The **lockout deny path has still never been observed**. The patch is
  confirmed present byte for byte, which is not the same as confirming what it
  does.
- The `/Config` 404 is unexplained and common to all three disk-backed
  directories, so it is not a control to rely on.
- The 6800 and 9443 assessments are single-source; their verification pass was
  cut short.
- **NAND: 9 bad blocks.** `verify-panel.sh` fails if that rises.

---

## Historical: why only one fix was in the first image

The lockout patch was taken all the way because it is the one with a reviewer
verdict, an exact byte specification, a rollback procedure, and a failure mode
that cannot brick anything. The rest are either already solved without touching
the panel, or specified but not yet reduced to verified bytes.

The build pipeline now exists and is proven end to end, so adding a second fix
to a future image is a much smaller job than the first one was. The expensive
part was never the patch; it was establishing that a rebuilt filesystem is
byte-correct and that the flasher cannot be made to write the bootloader.

---

## a-3 assessed for patching, and declined

a-3 is the dead web-facing partition-status poller: `getPartitionDetails` at
`0x140480` creates the timer, connects the signal, sets 2000 ms and starts it,
and **nothing calls it**. Confirmed again here — `callers()` returns nothing.

It is the second independent cause of the stale-remote-status symptom, so
reconnecting it is tempting. It should not be done.

**It does not reduce to one instruction.** The natural hook is
`CReceiverThread::registerclient` at `0x13c2f8`, called from `run()` when a web
client registers, which is exactly the right moment. But `getPartitionDetails`
takes a `char*` and returns into `r0`, and the only redundant slot nearby is the
second of two consecutive `bl GetOperationMode` calls:

    0x13c32c  bl GetOperationMode
    0x13c330  strb r0, [sp, #0xb1]
    0x13c334  bl GetOperationMode      <- redundant, r0 already holds it
    0x13c338  cmp r0, #3

Overwriting that call would clobber `r0` before the `cmp r0,#3` that follows.
So the patch needs argument setup and register preservation, which means a code
cave and a multi-instruction insert — in `/tuxedo`, the alarm application
itself, not in the web server.

**Cost against benefit:**

- The practical problem is already solved and running: a client on the push
  stream never consults the cache that returns "Not available". Captured live
  with both transports side by side.
- The patch target is the process that talks to the VISTA over the alarm bus and
  kicks the watchdog. A mistake there is a rebooting alarm panel, not a broken
  web page.
- The beneficiary is a client that polls REST instead of using the stream, and
  the only such client here has already moved to the stream.

So a-3 stays open as **documented and deliberately unpatched**, which is a
different state from unsolved. If a future client genuinely needs the REST cache
to be fresh, `RequestPartitionStatus(int,bool)` at `0x585c28` is the mechanism
and it works; the missing piece is only the connection.

**Worth keeping for any future `/tuxedo` patch:** the redundant
`bl GetOperationMode` at `0x13c334` is a free instruction slot in a function that
runs on every web client registration, as long as whatever replaces it leaves
`r0` holding the operation mode.
