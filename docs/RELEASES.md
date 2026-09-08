# Releases

Each entry records what shipped, how it was verified, and enough detail to
rebuild it. The build recipe is in `TUXEDO-BUILD.md`; the patch set is
`patches.tsv`.

---

## v13 — 2026-09-06

**What it is: v12 plus P13, which closes the unauthenticated push stream.**
Before this, `GET /SimpleDebugger.interface/G.` returned live alarm state —
armed/disarmed, the exit-delay countdown, partition status — to anything on the
LAN with no cookie and no login, on all four listeners. That was the highest
item on `tls/THREAT-MODEL.md`'s list.

### Artefacts

| | |
|---|---|
| `app2.hdr` | 125,685,236 bytes, md5 `3ebcbbe2bac88412a3c5fe0fa528c02b` |
| payload | 125,685,108 bytes, md5 `54b14f6831c9131b63701a8b59bae56c` -> rebuilt |
| header | size field `125685108`, checksum `0xd6bb` computed and matching |
| `Barracuda` | md5 `55448f05ff28520f3b68b99312126946` |

Same size as v12 — the patch is a 4-byte hook plus 92 bytes written into a dead
function, so the JFFS2 layout is unchanged.

### New in v13

| patch | binary | what it does |
|---|---|---|
| P13-pushauth-hook | `Barracuda` | `EhDir_service`'s auth call at file 0x72420 redirected into the stub |
| P13-pushauth-cave | `Barracuda` | 92 bytes in the unreferenced `HttpServer_destructor` at file 0x648c0: calls stock `HttpDir_authenticateAndAuthorize`, and for the SimpleDebugger dir only, additionally requires the session to carry `AuthenticatedUser`, else `HTTP 401` |

Design, cave analysis and the full argument are in `PUSH-STREAM-AUTH.md`.

### Verified under emulation BEFORE flashing

This is the first release where the change was executed before it was shipped.
`emu/` runs the real ARM binary under `qemu-user` in a chroot of the rootfs with
the panel's own configuration partition restored into it, and the runner asserts
the process answering is the one it started.

| path | v12 control | v13 |
|---|---|---|
| `/` | 200, 133 B | 200, 133 B |
| push `:80` | 200, 526 B | **401**, 241 B |
| push `:6280` | 200, 526 B | **401**, 241 B |
| `/home.html` | 302 | 302 |
| process afterwards | alive | alive, zero SIGSEGV |

Then the authenticated direction, logging in against the emulated server with
the panel's real account store: anonymous denied on all four listeners,
authenticated OK on all four, web UI 200.

**Home Assistant:** the integration was stopped before the flash and restarted
after, and came back normally. That is the Gate D precondition, done by hand,
not an inference from connection state.

That answered the two things `PUSH-STREAM-AUTH.md` §6 had recorded as
unanswerable before a flash — whether the deny is a clean `401` rather than a
200-with-login-page, and whether the cave faults in the request path. It cost
none of the panel's 24-relaunch watchdog budget.

**What emulation did not cover:** `qemu-user` forwards syscalls to the build
host kernel, so 2.6.31 socket semantics are unmodelled, and with no `/tuxedo`
the stream carries no alarm state.

---

## v12 — 2026-09-06

**What it is: v11 plus the three patches that had only ever existed on the
running panel.** P10, P11 and P12 were applied live over SSH and were not in any
image, so a reflash would have silently reverted them. v12 closes that gap, and
`patches.tsv` plus `apply-patches.py` mean it cannot reopen.

### Artefacts

| | |
|---|---|
| `app2.hdr` | 125,685,236 bytes, md5 `ba42dd950cf4d716c8cbb093e2cbd94d` |
| payload | 125,685,108 bytes, md5 `54b14f6831c9131b63701a8b59bae56c` |
| header | size field `125685108`, checksum `0x4ad4` computed and matching |

Only `app2.hdr` changed. The flasher skips components absent from the card, so
`app1.hdr`, `app3.hdr`, `seconboot.hdr`, `ProgCV.hdr` and `MCU.hex` carry over
from v11 untouched.

The image is **exactly the same size as v11** — only 12 bytes changed, inside
binaries of identical length, so the JFFS2 layout is unchanged.

### New in v12

| patch | binary | what it fixes |
|---|---|---|
| P10 | `/tuxedo` | console mode sends the real keypad display text instead of a canned 14-byte placeholder |
| P11 | `Barracuda` | a-2: Type=502 BACK no longer dropped when `consoleMode` is nonzero |
| P12 | `Barracuda` | a-2: Type=503 HOME, same |

P11 and P12 fix the last defect that affected the panel in daily use: after the
first web-keypad visit, Back and Home died permanently, because command 1125
increments a counter that the shipped UI never decrements.

P10 makes reply type 20 carry real keypad display text instead of a canned
placeholder.

🚨 **This paragraph previously said Barracuda "discards reply type 20 entirely"
so console mode "cannot be reached until Barracuda is replaced". That was wrong,
corrected 2026-09-08 by measurement.** Barracuda routes type 20 at `0xd6b8` to a
handler that broadcasts the text on the push stream and caches it via
`setConsoleMessage`, which is what the web UI's `commandID=5002` poll serves. The
old claim came from enumerating the dispatch chain's equality comparisons; type
20 is caught by a **range** arm (`bcc`), which that method cannot see. So P10 is
sufficient for the display path and **console mode needs no Barracuda change** —
see `TUXEDO-FIX-STATUS.md` for the trace and the control that proves it.

### Staged, NOT yet on the live panel: `tz`

`export TZ="CST6CDT,M3.2.0/2,M11.1.0/2"` appended to `/etc/rc.d/rc.conf` in
`/work/v13/root`. **Staged in the image only** — the same edit to the running
panel was refused by the permission classifier and is the owner's to approve.

**The clock is 5 h out and a timezone is genuinely the fix, but the naive form of
it makes things worse.** Measured 2026-09-08:

    true UTC epoch (NTP)   1788891171
    panel system clock     1788873149      18022 s behind
    panel RTC              18:12:54        correct UTC
    TZ unset      date ->  13:11:58 UTC    correct local, WRONG label
    TZ=CST6CDT    date ->  08:11:58 CDT    WRONG by 5 h

`/tuxedo` sets the clock from the VISTA with `date -s '%d-%d-%d %d:%d:%d'`, and
that time is **local**. `date -s` is TZ-aware — proved read-only with `date -d`,
which returns `1788872400` under `TZ=UTC0` and `1788890400` under `TZ=CST6CDT`,
exactly 18000 s apart. So with no TZ the clock ends up **holding local time while
libc labels it UTC**, which is why every log line after runlevel 3 is 5 h off and
`syslogd started` is the last trustworthy UTC stamp.

🔑 **Set TZ and the same write lands on the correct epoch instead.** `rcS`
sources `rc.conf` at its line 7, before starting any service, so supervis — and
therefore `/tuxedo` and Barracuda — inherits it.

⚠ **ORDER MATTERS on a running panel.** Setting TZ while the clock still holds
local time makes the alarm screen read 08:xx; that is measured, not predicted. On
a boot it is fine, because `settime`/`ntpclient` sets true UTC before `/tuxedo`
starts. To apply it live, set TZ **and** reload the clock from the RTC in one
step: `hwclock -s -f /dev/rtc0`. There is no zoneinfo tree on the panel, so the
POSIX rule string is required — `/etc/localtime` would have nothing to read.

⚠ `/tuxedo` has its own `g_stDateTimeConfig.i8TimeZone` with DST months and a
touchscreen control, persisted in `DateTimeConfig.txt` (28 bytes, with a `_sec`
twin). That is a **separate** setting from the OS TZ and was left alone.

### Carried over from v11

`lockout-patch, heap-fix, ssh, sd-init-hook, hosts-fix, ntp, musl-spare,
busybox, syslog, config-unpublished, cam-listener-off`

### How it was verified

Built on the Ubuntu VM rather than WSL, at the owner's direction.

1. **Base confirmed before touching it.** Extracted `app2.v11.jffs2` (md5
   `f339f3a4…`, size matching the SD card's `app2.hdr` minus its 128-byte
   header). The extracted tree carried `BUILD=v11` and all three binary md5s
   matched the recorded v11 state.
2. **Patches applied by tool, not by hand.** `apply-patches.py --apply` reported
   5 sites already patched and applied exactly 3.
3. **The strongest check available:** after patching, all three binaries matched
   the *running panel* byte for byte — `tuxedo 98370c31`, `Barracuda c8971027`,
   `supervis 6caac69e`. The image reproduces the live panel rather than
   approximating it.
4. **Round-trip clean.** Rebuilt image extracted and `diff -r`'d against the
   source tree under `LC_ALL=C`: **zero real differences.** The 34 diff lines are
   4 special-file pairs that `diff` cannot compare (identical major/minor —
   console 5,1 / null 1,3 / tty 5,0 / initctl fifo) and 30 dangling symlinks with
   identical targets in both trees.
5. **Patch sites re-checked in the round-tripped tree:** 8 of 8 patched.
6. **Header verified as ProgCV validates it:** size and checksum both PASS.

### Flashed 2026-09-06

Staged to `/mnt/sd/app2.hdr` (md5 re-verified on the panel), then rebooted.
**ProgCV flashed it in about 100 seconds** — much faster than expected for a
125 MB image, but the result is unambiguous: the panel came up reporting
`BUILD=v12` with `BUILT=2026-09-06T14:50:09Z`, and both patched binaries present
(`tuxedo 98370c31`, `Barracuda c8971027`).

**A flash removes anything added over SSH.** The `.orig` backups created before
patching (`/tuxedo.orig`, `/opt/webserver/Barracuda.orig`) are gone, because the
flash replaces the whole rootfs rather than merging into it. That is the correct
behaviour and the reason v12 exists at all — but it means any file placed with
`deploy.py`, and any backup taken alongside a live patch, is temporary until it
is in an image. Take pre-patch copies off-panel if they need to survive.

The partition-level baseline in `RECOVERY-BACKUP.md` is unaffected: it lives on
the workstation, not the panel.

### Reproducible from stock, verified 2026-09-06

v12 can be rebuilt from the three genuine stock binaries using `patches.tsv`
alone. 11 of 11 sites apply, and all three outputs match the running panel:

```
Barracuda  324209e1... -> c8971027...
tuxedo     6f8055f5... -> 98370c31...
supervis   04386af2... -> 6caac69e...
```

This was NOT true when v12 shipped. Three P1 sites — two NOP'd `bl`s and the
124-byte lockout stub — predated the patch table and were unrecorded, so the
build could only be reproduced by starting from the v11 payload that already
contained them. An adversarial review noticed P2's branch reaching into a
hand-written stub; comparing against genuine stock on the build VM confirmed
119 bytes were missing. Recording them closed it.

### VERIFIED END-TO-END on the flashed panel, 2026-09-06

**a-2 is genuinely fixed.** With the owner watching the touchscreen, from a
sub-menu, driven against v12 running from flash:

```
cmd 1125  -> consoleMode incremented   (the state that kills Back/Home on stock)
cmd 502   -> BACK
cmd 503   -> HOME    ==> THE PANEL RETURNED TO THE HOME SCREEN
```

Owner's words: *"it went back to home screen."*

That is the decisive observation. On stock firmware, once 1125 has incremented
`consoleMode` — which the shipped web UI does on every keypad page load, and
never decrements — both handlers discard the command silently and permanently,
until Barracuda restarts. The screen moving proves the command reached the panel.

**Scope, stated precisely:** HOME (P12) was observed directly. BACK (P11) was
sent in the same run but its effect was not separately reported. P11 is the
identical one-instruction change in the sibling handler at an adjacent address,
verified byte for byte, so it is strongly implied — but *implied* is the honest
word, and it is not the same as observed.

The earlier failed attempt is kept as a caution: trying to confirm this from the
push stream produced `0:18:` frames that looked like success and were the 33 s
heartbeat, 32.98 s apart. The stream cannot see touchscreen navigation.

---

## v11 and earlier

See `TUXEDO-FIX-STATUS.md` for the cumulative state and
`TUXEDO-BUILD.md` for how the earlier images were produced.
