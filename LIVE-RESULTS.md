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
| SSH port 22 | refused, after four flash attempts | 2026-09-05 |
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
| SSH after flashing v2, v3, v4 | port 22 refused each time | — |

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
- Whether any patched image has ever been applied. `/etc/tuxedo-build` and the
  SD boot log in v6 exist to answer this.
- The OTA path end to end. No server has been stood up.

## Rule

A claim marked `[CONFIRMED]` from static analysis is not a live result. When a
live test contradicts one, correct the claim where it was made and add the row
here. Do not leave the two in different documents.
