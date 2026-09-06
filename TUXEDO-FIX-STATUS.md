# What is actually fixed, and where

Status 2026-09-06. **v11 is flashed and running**, plus one patch applied live
over SSH since. `./verify-panel.sh` confirms every patch site in one command.

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

## Console mode: patched, and still not reachable

`/tuxedo` P10 at `0x135a3c` is applied and verified. It is **necessary but not
sufficient**, and the reason is worth keeping straight:

- The gate it fixes selects the *payload* of reply message type 20 — real keypad
  display text versus a canned 14-byte placeholder. It never controlled whether
  the message was sent.
- The message is dropped by **Barracuda**, whose reply dispatcher
  `gettuxedoIPCCommFunc` handles 42 message types and has no case for 20.

So console mode cannot work through Barracuda by any means, and it arrives free
once Barracuda is replaced, because a server reading `/Q_ServCmdTrsmtr` directly
receives type 20 — carrying real display text precisely because P10 is applied.
Full trace in `TUXEDO-VIRTUAL-CONSOLE-BUGS.md`.

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
