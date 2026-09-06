# Live results

Everything tested against the actual panel, with the outcome. Check here before
re-testing anything.

This file exists because `/Config/` was tested, recorded in one document, and
then re-derived from scratch twice while a second document still presented it
as a confirmed vulnerability.

## Reachable

| Test | Result | Date |
|---|---|---|
| Ports listening | 80, 443, 6280 only | 2026-09-05 |
| SSH port 22 | refused, after five flash attempts. Cause found, see `ssh/BUILD.md` | 2026-09-05 |
| `GET /` | 200, empty body | 2026-09-05 |
| `GET /login2.html` | 200, 15,258 bytes, matches the embedded archive | 2026-09-05 |
| `GET /eventhandler.html` | 200, 6,311 bytes | 2026-09-05 |
| `GET /tuxedoapi.html` | 302 to `/authenticated/index.html?url=...` | 2026-09-05 |
| `GET /SimpleDebugger.interface/G.` | holds the connection open; the push stream | 2026-09-05 |
| Login as a web user | works | 2026-09-05 |
| Push stream | 19 frames in 30 s, correct partition status | 2026-09-05 |
| REST `GetSecurityStatus` | `Ready To Arm` normally; `Not available` shortly after a reboot | 2026-09-05 |
| REST `GetSceneList` | `No scenes found` | 2026-09-05 |

## Not reachable

| Test | Result | Supersedes |
|---|---|---|
| `GET /Config/<any file>` | **404 on this unit**, ports 80/443/6280, with and without a session. Includes files that certainly exist. **Not a refutation:** the binding is unconditional in shipped code, so treat it as a live risk on stock firmware. Cause of the 404 unidentified. | qualifies `TUXEDO-VERIFIED.md` finding 1 |
| `GET /VideoFiles/`, `/Videos/` | 404. Same disk-backed mechanism as `/Config/` | — |
| `GET /panelinfo.txt` and 8 other paths | 404 with a valid session | — |
| Command 12, all zone status | **zero reply frames** in 60 s while 140 other frames arrived | the presence of the command id in the symbol table |
| Command 138, system time | zero reply frames | — |
| SSH after flashing v2, v3, v4, v7 | port 22 refused each time. Not a flash failure: dropbear runs, binds and listens, then exits from the accept loop | — |

## Confirmed by the v7 SD boot log

The v7 image writes `/mnt/sd/tuxedo-boot.log` at boot. Reading it settled four
open questions at once. Log kept at `evidence/v7-boot.log`.

| Question | Answer |
|---|---|
| Does a custom image ever apply? | **Yes.** `/etc/tuxedo-build` on the running panel reads `BUILD=v7`. Every flash from v2 on has applied. |
| Is the patched Barracuda live? | **Yes.** `/opt/webserver/Barracuda` md5 is `197b7e41daeedd849d6353bd0fb26059`; stock is `324209e1fdfe2d61925a1bb4a7115452`. The lockout and heap patches are running. |
| Is the OTA hosts block live? | **Yes.** 4 block lines in `/etc/hosts`. |
| Is the rootfs writable at runtime? | **Yes.** `/dev/root / jffs2 rw,relatime`. `rc.conf` setting `READONLY_FS=""` does not make it read-only. |

Also read off the same log:

- `/dev/mtdblock17` is mounted on `/opt/tuxedo/configuration`, confirming from
  the running system what was previously inferred from the bootargs.
- `/dev/mmcblk0p1` is mounted `rw` on `/mnt/sd`, so the card is a two-way
  channel, not just a source for the flasher.
- The clock at boot is `Tue Sep  8 01:05:33 UTC 1970`. No RTC, nothing sets it.
- Both start hooks fire. `rc.local` and `etc/rc.d/init.d/startup` each launched
  dropbear, as separate pids, and each failed identically.

## Resolved

| Was | Now |
|---|---|
| SSH refused after five flashes, cause unknown | **Cause found.** The dropbear binary was statically linked against Debian trixie glibc 2.41, a 64-bit `time_t` port, so it issued time64 syscalls (ARM 403+, Linux 5.1) on a 2.6.31 kernel. It bound and listened, then `select()` failed and it exited. Rebuilt in v8 against the panel's own glibc 2.5; highest symbol version required drops from GLIBC_2.38 to GLIBC_2.4, and the select syscall becomes `_newselect`. See `ssh/BUILD.md`. |

## Measured

| Thing | Value |
|---|---|
| Push stream refresh cadence | ~33 s |
| Push stream idle survival | 5 min, verified |
| Status cache expiry | none; 25-minute quiet window still returned `Ready To Arm` |
| Concurrent push clients | 2 coexist |
| Panel clock after a power cycle | resets; no RTC across power loss |

## Never tested

- The login lockout deny path, on either firmware. Testing it needs six failed
  logins, and the failure counter lives on `mtdblock17` which survives reflashes,
  so a test may not start from zero.
- The OTA path end to end. No server has been stood up.

## Iteration cost

Until v8 every change cost a 124 MB reflash to test one line. v8 adds an SD
init hook: `rc.local` runs `/mnt/sd/tuxedo-init.sh` when `/mnt/sd/TUXEDO-DEV` is
also present. Editing a script and swapping the card replaces the flash cycle.

The marker file gates it, so a card without `TUXEDO-DEV` is inert. It is still
root code execution from removable media: physical access to the SD slot is
root on the panel. That is a deliberate development affordance on a unit its
owner controls, not something to leave on a deployed panel. Remove the hook
from `rc.local` for any image that is not being iterated on.

## Rule

A claim marked `[CONFIRMED]` from static analysis is not a live result. When a
live test contradicts one, correct the claim where it was made and add the row
here. Do not leave the two in different documents.
