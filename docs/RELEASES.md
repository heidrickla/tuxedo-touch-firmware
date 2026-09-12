# Releases

Each entry records what shipped, how it was verified, and enough detail to
rebuild it. The build recipe is in `TUXEDO-BUILD.md`; the patch set is
`patches.tsv`.

---

## v15 — 2026-09-12 — FLASHED AND VERIFIED

**What it is: v14 plus tuxweb as the web server, the vendor parked, and the
summer clock fix.** The stage-8 cutover (`WEBSERVER-REPLACEMENT.md` §8d) had put
tuxweb on the panel over SSH ahead of any image; v15 folds it in so the card and
the rootfs carry it and a reflash cannot undo the cutover.

### Artefacts

| | |
|---|---|
| `app2.hdr` | 126,451,920 bytes, md5 `aa78763effed8c4b9fa52badea5b9e01` |
| payload | `v15.jffs2` 126,451,792 bytes |
| header | size field `126451792`, checksum `0xa87b` computed and matching, verified as ProgCV does |
| `/opt/webserver/Barracuda` | **tuxweb**, md5 `ff3898390e17da26222d205857de9b56` (the binary the panel has run since the same day's SSH upgrade) |
| `/opt/webserver/vendor/Barracuda` | the v14 vendor, md5 `0066ad95c82602930f939294f9e80af1`, kept for passthrough and revert |
| `/tuxedo` | md5 `c744e3f162ed0240338381dc64ecbd7b` — changed by P16 |
| built at | `/work/v15` on the build VM, by `build-image.sh` (first release the script built end to end) |

728,604 bytes larger than v14: tuxweb (1.1 MB) minus JFFS2 compression.

### New in v15

- **tuxweb** (`tuxweb/`), installed where supervis launches by name. Serve mode is
  switched on by `/opt/tuxedo/configuration/tuxweb-serve.conf` on mtd17 — present
  on this panel since the cutover; **absent means passthrough to the vendor**, so
  a stock-configured panel flashed with v15 behaves as v14 did until cut over.
  TLS 1.3 on 443, 301-only on 80, 6280/9443 unbound, token-gated push stream and
  API, keypad LCD on the stream (console mode held on), silence re-register.
- **Layout change:** the vendor lives at `vendor/Barracuda`; `patches.tsv`'s 282
  vendor rows name that path now, and `build-image.sh` moves the vendor aside
  before the patch pass (`TUXWEB=` option).
- **P16-dst-isdst** (`/tuxedo` `0x59ea4c`, 8 bytes): `dal_setCurrentTime` set
  `tm_isdst = 0` before `mktime()`, so under the DST-aware `TZ` the VISTA's local
  time was converted as standard time — the clock ran **one hour ahead for two
  thirds of the year** (measured +3578 s on 2026-09-12). `tm_isdst = -1` lets
  `mktime` apply the rule; the spare `tm_yday` load becomes the `mvn`. Found
  with the decompiler; the patched copy disassembles to
  `mvn r3,#0 / str r3,[fp,#-40]` and exactly 4 bytes differ. `TRAPS.md` §6.
- Marker gains `TUXWEB_MD5` and `VENDOR_BARRACUDA_MD5`; `build-image.sh` gains
  `vm:<path>` bases and `MARKER_SET=` for the carried-forward prose.

### Verified before staging

| gate | v15 |
|---|---|
| base | `/work/v14/v14.jffs2`, md5 `a7065e21…` as recorded for v14 |
| all paths `root:root` | yes |
| patches | **285 sites: 284 already patched, 1 applied (P16)**; 285/285 in the re-extracted tree |
| round trip | zero real differences |
| header | `0xa87b` computed = stored, PASS both ways |
| card | `app2.hdr` md5 matches on the panel after transfer; `ProgCV.hdr`, `app1.hdr`, `app3.hdr`, `seconboot.hdr` byte-identical to the stock set |

The tuxweb binary itself is the one already running on the panel, verified live
(`emu/stage8-verify.py`: capabilities, status, token-gated push with console
records, 301, arm and disarm confirmed by the panel).

### Flashed 2026-09-12

**A plain `reboot` did NOT reprogram this time** — the panel came back on v14
in 30 s with the v15 card untouched, so "reflashes when the card differs" is
not the flasher's trigger as recorded for v14. Lewis confirmed the flash on the
touchscreen at the next reboot, and it reprogrammed: SSH gone for ~90 s, back
at `BUILD=v15`, `SYSTEM START` logged 08:33:47 panel time.

| check | result |
|---|---|
| `/etc/tuxedo-build` | `BUILD=v15`; `TUXEDO_MD5 c744e3f1` (P16), `TUXWEB_MD5 ff389839`, `VENDOR_BARRACUDA_MD5 0066ad95` — all three match the image |
| layout | tuxweb at `/opt/webserver/Barracuda`, vendor at `vendor/Barracuda` |
| mtd17 | serve conf, token store and cert all survived the reflash; tuxweb came up in serve mode by itself |
| `verify-panel.sh` | **285 sites ok**, listeners exactly 22/80/443, 6800 gone, services, NAND 9 bad blocks (baseline), card rw, hosts clean — "panel matches expectations" |
| `stage8-verify.py` | capabilities 200, status, push 401/subscribed with console records (`****DISARMED****\|  Ready to Arm  `), 301 — all pass |
| **clock** | panel − real UTC = **−22 s** (same-instant against the VM), from **+3578 s** before P16: the VISTA's own error and nothing else. **P16 confirmed on hardware.** |
| HA | resubscribed on its own in tuxweb mode (took the boot's first `setCid`) |
| rootfs | 55.7 MB free |

Rollback: `push-image.sh /work/v14/app2.hdr --reboot` and confirm on the
touchscreen (vendor at the top, no tuxweb; the serve conf on mtd17 is then
ignored). Without a reflash: `rm` the serve conf and `kill -9` the Barracuda
pid falls back to the parked vendor.

---

## v14 — 2026-09-09 — FLASHED AND VERIFIED

**What it is: v13 plus every leak fix that had been hot-patched over SSH.** First
image whose `BARRACUDA_MD5` equals the binary the panel is running. v13 shipped
`55448f05`; the panel has been running `0066ad95` since 2026-09-08 because
P14-detach and the whole P15-leakfix series were applied live and were not in any
flashed image. v14 folds them in.

### Artefacts

| | |
|---|---|
| `app2.hdr` | 125,723,316 bytes, md5 `a8da9001` |
| payload | 125,723,188 bytes, md5 `a7065e2160d658724d226bde20b4e69f` |
| header | size field `125723188`, checksum `0x10f8` computed and matching |
| `Barracuda` | md5 `0066ad95c82602930f939294f9e80af1` |
| built at | `/work/v14` on the build VM; card set staged in `/work/v14/card` |

38,080 bytes larger than v13, entirely from the longer `/etc/tuxedo-build` record.
125.7 MB against mtd16's 180 MB (`0x0b400000`), so 67% of the partition.

### New in v14

| patch | binary | what it does |
|---|---|---|
| P14-detach | `Barracuda` | 7 sites: the thread-stack leak that took RSS to 2.0 GB |
| P15-leakfix | `Barracuda` | 264 rows, 24 active fixes: HTTP heap-leak sites, IPC-path defects, all 43 `json_strip_white_space` results, the getEScenes tree and its Base64 buffer, the validatePageName page-map tree, and the `cmd=140`/`cmd=141` dispatch-arm frees |
| timezone | `/etc/rc.d/rc.conf` | `export TZ="CST6CDT,M3.2.0/2,M11.1.0/2"`, without which `/tuxedo`'s `date -s` from the VISTA lands 18,022 s off true UTC |

All three are vendor defects; none was introduced by this project.

### Verified

| check | result |
|---|---|
| `apply-patches.py --check` | 284 sites, **284 already patched, 0 needing attention** |
| patch table reproduces the live binary | v13/root + `patches.tsv` yields Barracuda `0066ad95c82602930f939294f9e80af1`, byte-identical to what the panel runs |
| JFFS2 round-trip | extracted the built image back out: **3520 entries identical** — content hash, mode, uid, gid, symlink target and device major/minor, across 3112 files, 228 dirs, 176 links, 3 char devices, 1 fifo |
| payload survived wrapping | `app2.hdr[128:]` md5 equals `v14.jffs2` md5 |
| header | `tuxedo_hdr.py verify` → PASS, computed checksum equals stored |
| whole card set | `tuxedo_hdr.py preflight` over all six files → **ALL FILES WOULD PASS** |

`diff -r` cannot do the round-trip check and was not used for it: it reports
character devices and fifos as differing on both sides, calls an identically
dangling symlink a missing file, and piped to `head` loses its exit status, so
"exit=0" there means nothing. `ci/treecmp.py` compares the attributes JFFS2 stores.

JFFS2 output is not byte-reproducible, so do not verify a build by hashing the
payload against a previous one: v13's original payload is `54b14f68` and a rebuild of
the same tree is `0ddc5f1b`. Use the round-trip extract instead.

### Executed under emulation before flashing

The image tree was booted under `qemu-user` from `/work/emu/v14` via `emu/serve.sh`,
a project rule since v13.

| check | result |
|---|---|
| comes up | 4/4 listeners, serving `/` with 302 |
| P13 push-stream gate | `GET /SimpleDebugger.interface/G.` → **401 on :80, :443 and :9443** |
| `:6280` | handshake times out, identically on the live panel, so it is a property of that listener on this firmware, not a v14 regression |
| API surface | 300 × `/GetSceneList`, **all 300 → HTTP 200** |
| leak profile | **1.0000 leaked JSONNode trees per request**, the same figure measured on the panel; 2.13 strings/request |

A modern TLS client cannot reach these listeners, and its failure looks like a dead
port. `curl` gets `000` in ~10 ms on all three HTTPS listeners, and Python fails with
`UNSAFE_LEGACY_RENEGOTIATION_DISABLED`, because SharkSSL of this vintage predates
RFC 5746. `ci/tlscheck.py` sets `OP_LEGACY_SERVER_CONNECT` and gets a real answer.
Never read `000` as a failed check without running the same client against the panel;
that control separated a client limitation from a regression on three of the four
listeners.

The string-leak rate is config-dependent, so it is not a number to regress against:
this tree measures 2.13/request where another tree on the identical binary measured
3.13. `getRegisteredDevNodes` extracts a `json_as_string` per registered device, so
the count follows how many devices the seeded `registereddevMAClist.json` holds. The
tree count, 1.0000/request, is stable and is the one to watch.

### Not fixed in v14

`/GetSceneList` still leaks ~780 B/request on the API surface: exactly 1.0000
JSONNode trees per request, plus 2–3 libjson strings depending on how many devices
the configuration holds (see the config-dependence note above). Counted in libjson's
allocation registries with `leakfix/jsoncount.py`. The tree is `json_new` at
VA 0x1ef04 in `WnmpDir_serviceField`. Three candidate fixes were built and refuted
under emulation, none shipped: 0x2a084 never executes on that path, and both 0x2955c
and 0x1f0f4 hang inside `json_delete` and deadlock the server, because the stuck
worker holds the dispatcher mutex. See `leakfix/mkapifix.py` LEAK 30 and
`ALLOCATOR-REWORK.md`.

### How it was built, and a gap that closed

v14 was built by hand from `TUXEDO-BUILD.md`'s recipe, not by `build-image.sh`. That
was a miss: the repo's rule is to grep for a tool before hand-rolling one. The build
is equivalent because every gate that script enforces was run against the result
afterwards and passed:

| `build-image.sh` gate | v14 |
|---|---|
| all paths `root:root` before `mkfs.jffs2` | 0 non-root paths. A stray non-root file ships an image nobody can boot, and it has happened |
| geometry `-e 0x20000 -l -n`, no `-p` | matched exactly |
| round-trip diff must be empty | 3520 entries identical via `ci/treecmp.py` |
| patches re-checked in the **extracted** tree | 284/284 already patched in `root_verify`, not just in the source tree |
| header built from the stock template, then verified | PASS |

The one place hand-building was better: the marker. `build-image.sh` regenerated
`/etc/tuxedo-build` from a fixed field list, so v14's `LIVE_DRIFT`, `NEW_IN_V14`,
`PATCH_TABLE`, `KNOWN_UNFIXED` and `ROLLBACK` lines would all have been dropped, the
same failure its own comment records for `CHANGES`, and worse here because `ROLLBACK`
stops someone reaching for a rollback binary that no longer exists. `build-image.sh`
now carries every non-generated line forward, verified against v14's marker: 15 lines
partition into 10 regenerated and exactly those 5 carried, with nothing duplicated.

### Flashed 2026-09-09

Delivered over the network, so the card never moved: `push-image.sh` from the build
VM straight to `/mnt/sd/app2.hdr`, 125,723,316 bytes in 63 s, md5 verified on the
panel before the atomic rename, then `reboot`.

The card was verified before booting by full-file md5 of all six flashable files,
not by re-running the checksum tool. All six matched: the five vendor originals
byte-for-byte, and `app2.hdr` equal to the image that had already passed
`tuxedo_hdr.py verify` and `preflight`. An md5 over the whole file also excludes
truncation, which is the residual risk section 7 of `TUXEDO-BUILD.md` names.

| check | result |
|---|---|
| `/etc/tuxedo-build` | `BUILD=v14`, was v13 |
| `/tuxedo`, `Barracuda`, `/supervis` | all three match the image exactly |
| `verify-panel.sh` | **291 checks, 0 failures**, the same count as before the flash |
| `LIVE_DRIFT` | `NONE` — image hash and running binary are one value |
| rootfs | 70% used, 56 MB free |

The rootfs was replaced rather than patched in place: the `.preedit` and
`.stock55448f05` rollback copies are gone, because the image contains none. That
invalidated this release's own `ROLLBACK` line, which had named them — the same fault
v13's marker had after those files were deleted. It now describes recovery from the
card, and the correction was applied to both the panel and `/work/v14/root`, so a
rebuild carries it. The two markers are byte-identical.

A plain `reboot` triggered the reprogram. A reboot two days earlier had not
reflashed, which was the reason to expect otherwise; the difference is that the
card's `app2.hdr` then matched what was already installed.

Rollback: copy `/work/v13/app2.hdr` (Barracuda `55448f05`) to the card with
`push-image.sh` and reboot.

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

**This paragraph previously said Barracuda "discards reply type 20 entirely"
so console mode "cannot be reached until Barracuda is replaced". That was wrong,
corrected 2026-09-08 by measurement.** Barracuda routes type 20 at `0xd6b8` to a
handler that broadcasts the text on the push stream and caches it via
`setConsoleMessage`, which is what the web UI's `commandID=5002` poll serves. The
old claim came from enumerating the dispatch chain's equality comparisons; type
20 is caught by a **range** arm (`bcc`), which that method cannot see. So P10 is
sufficient for the display path and **console mode needs no Barracuda change** —
see `TUXEDO-FIX-STATUS.md` for the trace and the control that proves it.

### `tz` — APPLIED to the live panel 2026-09-08, active at the next boot

`export TZ="CST6CDT,M3.2.0/2,M11.1.0/2"` appended to `/etc/rc.d/rc.conf`, on the
panel (line 42, backup at `/etc/rc.d/rc.conf.pre-tz`) **and** in `/work/v13/root`
so a reflash keeps it. Owner-approved.

**Inert until the next boot, and verified as effective without one.** `rcS`
sources `rc.conf` at its line 7; sourcing it by hand gives

    TZ=[CST6CDT,M3.2.0/2,M11.1.0/2]
    date -s "2026-09-08 13:45:00" would set epoch  1788893100   (13:45 CDT = 18:45 UTC)
    the same string with no TZ sets               1788875100   (18000 s low)

which is precisely the correction needed. The running system is untouched —
`date` still prints `13:45 UTC` and `TZ` is unset in an ordinary shell, because
nothing re-reads `rc.conf` until boot.

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

**Set TZ and the same write lands on the correct epoch instead.** `rcS`
sources `rc.conf` at its line 7, before starting any service, so supervis — and
therefore `/tuxedo` and Barracuda — inherits it.

**ORDER MATTERS on a running panel.** Setting TZ while the clock still holds
local time makes the alarm screen read 08:xx; that is measured, not predicted. On
a boot it is fine, because `settime`/`ntpclient` sets true UTC before `/tuxedo`
starts. To apply it live, set TZ **and** reload the clock from the RTC in one
step: `hwclock -s -f /dev/rtc0`. There is no zoneinfo tree on the panel, so the
POSIX rule string is required — `/etc/localtime` would have nothing to read.

`/tuxedo` has its own `g_stDateTimeConfig.i8TimeZone` with DST months and a
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
