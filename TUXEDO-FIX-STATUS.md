# What is actually fixed, and where

A single answer to "does the new firmware contain all the bug fixes?"

**No. The built image contains one fix.** Most of what this project solved was
solved on the client side, in Python, without changing the panel at all. That
was deliberate for the headline bug, and incidental for the rest.

Status as of 2026-09-05. Nothing has been flashed.

---

## In the built firmware image

| Fix | Where | Status |
|---|---|---|
| Login lockout: 3-strikes-permanent becomes 5 attempts with a 300-second self-clearing lock | `Barracuda`, 131 bytes across 6 sites | **built and verified, not flashed** |
| 56-byte heap overflow in the login tracker | same patch | **built and verified, not flashed** |
| A documented, discoverable place to redirect firmware updates | `/etc/hosts`, fully commented | **built and verified, not flashed** |

Two files inside the root filesystem differ from stock: `/opt/webserver/Barracuda`
and `/etc/hosts`. Details in `TUXEDO-LOCKOUT-PATCH.md`, build procedure and the
OTA reasoning in `TUXEDO-BUILD.md`.

The heap overflow fix is not optional. The lockout change removes the two cache
wipes that currently make the overflow rare, so shipping the lockout change
without it would turn a rare bug into a routine one.

---

## Solved, but on the client side rather than in the panel

These are working today and need no firmware change. That is why they are not
in the image.

| Problem | Where it is solved |
|---|---|
| **Status goes to "unknown" after a few minutes** — the original complaint | `tuxedo_push.py`. The push stream at `/SimpleDebugger.interface/G.` never reads the cache that returns "Not available", so a client on it cannot experience the fault. |
| The panel's own API test console is unusable | `tuxedo_api_console.py`, a working replacement covering both HTTP APIs and the push stream |
| Which REST endpoints actually work | Answered by probing: about six do, the rest return their own documentation form |
| Richer data for Home Assistant | Zone status, event log, multi-partition arming and keypad display all reachable through the command API; documented in `TUXEDO-HA-ENRICHMENT.md` |
| Zone types and descriptions for the field programmer | Tables extracted from the binary; `TUXEDO-ZONE-PROGRAMMING.md` |
| Installer code retrieval | `panelinfo.txt` is served without authentication; confirmed statically, still untested live |

**A deliberate choice worth stating plainly:** fixing the status bug in the
device was the original goal, and it turned out not to need a device change.
The firmware does not have a status bug so much as a second transport that
nobody was using. Patching the cache would have been more risk for less result.

---

## Identified but NOT fixed anywhere

Everything below is documented in `TUXEDO-AUDIT-BUGS.md` and remains open.

### Affects the panel in daily use

- **a-2** First visit to the web keypad permanently disables the Back and Home
  buttons.
- **a-3** The web-facing partition-status poller is dead code.
- **a-4** The web interface is effectively single-client.
- **a-5** Event-log retrieval retries forever every 20 seconds with no cap.

### Virtual console

Six defects, none patched: session-expiry handling is commented out, send
errors are swallowed, keystrokes are lost when a send fails, a 1500 ms debounce
that is far too long for a keypad, a race between dispatch and buffer clear,
and no keepalive. See `TUXEDO-VIRTUAL-CONSOLE-BUGS.md`.

### Security exposure on the local network

Nine findings, none patched. The significant ones: the alarm user code travels
in a GET query string over plain HTTP; all web secrets derive from
`srand(time(NULL))`; the REST AES key is a permanent global device secret; there
is no per-command authorisation; and `panelinfo.txt`, which contains the
installer code in plaintext, is served to anyone who can reach the panel.

**These are the strongest argument for keeping this device off any untrusted
network segment**, and none of them is addressed by the current build.

### Asked for but not built

- **Using the virtual keypad like any other keypad.** Analysed, not built.
- **A self-hosted OTA server.** The redirection point now exists in the image,
  but nothing has been stood up to serve updates, and the AlarmNet redirector
  protocol has not been reproduced. Redirecting the names without a server
  behind them only makes updates fail, which the panel already tolerates.

---

## Why only one fix is in the image

The lockout patch was taken all the way because it is the one with a reviewer
verdict, an exact byte specification, a rollback procedure, and a failure mode
that cannot brick anything. The rest are either already solved without touching
the panel, or specified but not yet reduced to verified bytes.

The build pipeline now exists and is proven end to end, so adding a second fix
to a future image is a much smaller job than the first one was. The expensive
part was never the patch; it was establishing that a rebuilt filesystem is
byte-correct and that the flasher cannot be made to write the bootloader.
