# Handoff, 2026-09-11

Where the work stands, what is next, and the traps that cost time in this session.
Written to survive a context compaction: everything here is verifiable from the repo
or the panel, not from memory of a conversation.

Repo at `5654644`, both remotes in sync, CI green, 284 patch sites.
Panel on v14 (`0066ad95`), 4/4 listeners, disarmed, budget 8 of 24 this boot.

---

## 1. State of the two workstreams

### The webserver replacement (`WEBSERVER-REPLACEMENT.md`)

| stage | state |
|---|---|
| 0-5 | done |
| 6 | **DONE.** §5.1 answered YES: 29 replies received as sole reader |
| 7a, 7b | bench-proven (`emu/stage7-test.sh`) |
| 7c | **PASSES on the panel** — console mode streamed real console text |
| 7d | **PASSES on the panel** — `VALID USER CODE`, armed STAY, disarmed |
| 8 | **in progress** — decomposed 8a–8d (`WEBSERVER-REPLACEMENT.md`). 8a DONE, 8b/8c bench pieces done and emu-proven, see below |
| 9 | not started — decommission |

**Stage 8 progress this session — on branch `stage8-webserver`.** New in
`tuxweb/src`: `push.rs` (push stream generated from IPC replies, byte-verified vs
both fixtures), `session.rs` (`--push-capture`), `serve.rs` (`--serve`: the
permanent server — B5 reader-thread split, token-gated push with snapshot +
live fan-out, the typed API wired to the queue with confirmation, the 80→301
leg), `redirect.rs`, `api.rs` (capability endpoint, vendor response shapes,
routing), `auth.rs` (admin-issued bearer tokens, hashed on mtd17;
`--issue-token`/`--revoke-token`/`--list-tokens`). `conf.rs` (the 8d switch: serve conf on mtd17 + per-boot crash-loop guard).
`cargo test` 110 green; `emu/push-capture-test.sh` and `emu/push-serve-test.sh`
(full auth + arm/disarm flow against a reactive fake `/tuxedo`, in plaintext,
over TLS, and launched AS `Barracuda` via the conf) all pass on the VM. GitHub
CI green through `abd52c3`, including the ARM cross-build. **Decision (Lewis):
new simpler API + token auth, `ha-tuxedo-touch` updated to use it** — not a
reimplementation of the vendor's AES/HMAC API.

**8d DONE — the panel is CUT OVER, 2026-09-12.** tuxweb (release ARM build
`8ed6abee…`) is the permanent web server: pid 2590, serve conf on mtd17, 2/2
listeners (80 + 443), 6280/9443 gone, 11 fds, no panic, budget `RESTART-10`
(14 left). Verified against the real panel over owner-root-checked TLS 1.3:
capabilities 200, status, push (401/subscribed — the real 504 frame matched the
capture byte for byte), 80→301, **ArmWithCode stay → `Sucess` after the panel
confirmed → "259  Secs Remaining"**, **DisarmWithCode → `Sucess` → "Ready To
Arm"**; panel left DISARMED. HA (`ha-management-02` session) reloaded into
**tuxweb mode**: push connected, capabilities detected, entity disarmed, no
errors; the cutover looked like a reconnect from HA's side, not an outage.
**Arm STAY / disarm through the HA entity PASSED** on Lewis's go there:
`arming` → `armed_home` after the 60 s exit delay → `disarmed`, all by stream,
and the **Envisalink integration on a separate ECP path recorded the same
transitions** — real at the VISTA. Push held one connection throughout. Panel
left DISARMED. **Stage 8 is complete.** (Envisalink says `armed_home` instantly;
Tuxedo says `arming` for the 60 s exit delay first — both correct.)
**v15 FLASHED 2026-09-12 (`RELEASES.md`):** tuxweb is IN the image now
(`TUXWEB_MD5 ff389839`), the vendor parked at `vendor/Barracuda`, and
**P16-dst-isdst** — `/tuxedo` set `tm_isdst=0` before `mktime`, so the clock
ran an hour ahead all summer; `tm_isdst=-1` took it from +3578 s to **−22 s**
against real UTC, confirmed on hardware. `patches.tsv` has 285 rows and its
vendor rows name `vendor/Barracuda`. Two hard-won facts from the day: a plain
`reboot` did NOT reprogram — the flash needed a touchscreen confirmation — and
supervis relaunches a dead Barracuda only on its **10-minute tick**, so
`stage8-panel.sh` now starts the binary itself after a kill (`relaunch_now`).
Also on the stream now: the keypad LCD as `0:20:2…` console records (console
mode held on), and a silence re-register for the Home/Back gap.
**Revert remains one command:** `sh /tmp/stage8-panel.sh
revert` (rm the conf, vendor back from `vendor/Barracuda` `0066ad95`, two
kills). `/tmp` is tmpfs — the runbook and staged binary vanish on reboot, but
the serve conf and token store are on mtd17 and survive; a reboot relaunches
tuxweb in serve mode by itself.

**`ha-tuxedo-touch` is done:** branch `tuxweb-api`, commit `477d2b1`, pushed
to GitHub + gitea, CI green on Linux with **359 tests** (the HA layer cannot
run on Windows — `fcntl`). Detection via `GetCapabilities` (200 ⇒ tuxweb),
bearer token as a new optional entry field, plain-form arm/disarm/status with
200 = confirmed / 504 = not confirmed, token on the stream, `login()` refuses
outright in tuxweb mode so no login can ever be spent against tuxweb.

7a and 7b have **never been run on the panel**. They are bench-proven only, and they
are the two least consequential, so running them is optional rather than blocking.

### The leak work (`leakfix/README.md`)

- LEAKs 1-29: fixed and shipped in v14.
- **LEAK 30: root cause found, NOT fixed.** One exit, `0x29040`. See §3 below.
- **LEAK 31: measured, NOT fixed.** The family leaks 3 trees and 8-12 strings per
  call; three handlers confirmed by trace.

---

## 2. What is worth doing next, in order

**1. Stage 8.** This is the actual goal — the vendor stops being in the request path.
Everything stage 7 was gating is now answered. This is the highest-value remaining
work and it does not depend on any leak fix.

**2. The LEAK 30 cave** (§3). Bounded, well-understood, one tree per request. Do it
on the bench with an A/B against the measured baselines before any window.

**3. The 2 strings per request** that `/GetSceneList` also leaks. Unexplained. The
obvious theory (stranded libjson registry entries) is **refuted** — see §4.

**4. `readCRCJSONFile`** — 45 unfreed strings per IPC message type 154. The count is
known; the message RATE is not, and it is a `/tuxedo` property that has to be
measured rather than read.

**5. LEAK 31 handler fixes.** Lowest value of the five: the write path is not
hammerable (a few arms a day), so the real-world cost is tens of kB/day against a
panel with no headroom deadline.

---

## 3. The LEAK 30 fix, ready to build

`WnmpDir_serviceField` exit `0x29040`, on the module-dispatch path every
`/API_REV01` request takes:

```
29018  ldr pc, [ip, #16]       indirect call into the module method
29020  mov r4, r0              r4 = the handler's reply string
29034  bl  HttpResponse_printf send it
2903c  bl  free                CORRECT -- do not touch, see §4
29040  b   29874               skips both json_delete calls  <-- THE DEFECT
```

`leakfix/exits.py` shows 124 exits delete both trees and 3 do not.

**The fix:** a cave that does `json_delete(r7)` then `b 29874`.

**Three constraints, each of which has already broken something:**

- **Delete r7 ONLY, never r6.** All 125 writes to r6 are `mov r6, r0` after a
  `json_new`, and the first is at `0x1f254` — but the branches reaching this exit
  come from `0x1f118`, `0x1f190`, `0x1f1c4`, all earlier. r6 still holds the
  caller's callee-saved value, so `json_delete(r6)` is a wild free.
- **Do not branch to `0x29860`.** The clean epilogue runs `mov sp, r8` at `0x29870`.
  `r8` is overloaded: `0x1eef4` sets it to the request pointer, and only paths that
  `alloca` later do `mov r8, sp`. On this path r8 is the request, so that
  instruction sets sp to a request pointer. **This is the wedge three earlier
  attempts hit.**
- **r7 is always valid** — set at `0x1ef0c` from the `json_new` at `0x1ef04`, before
  every branch that reaches this exit.

**Verify against the measurement, not the reading.** `/GetSceneList` leaks exactly
1.0000 trees per request today; after the fix it must be 0.0000, with
`/GetSecurityStatus` still 0 and the family down by exactly 1. `leakfix/famcount3.sh`
produces all of those numbers.

---

## 4. Things to watch for

### Refuted experiments — do not repeat these

- **`json_free` at `0x2903c` CRASHES.** `mkapifix.py`'s `WNMPGET_STUB` note records
  it: glibc reported an invalid pointer at `0x40bddcd8`, outside the heap
  `heapwalk` walks — the wrong ALLOCATOR, not the wrong slot. The reply string on
  that path is not a libjson-registry string. The vendor's plain `free` is correct.
  I nearly repeated this from a fresh reading within an hour of finding the note.
- **Moving the free / adding both deletes wedges the request.** Explained in §3.

### Panel operational traps

- **`supervis` respawn after SIGKILL took 90 s once and SEVEN MINUTES another time.**
  Never wait on a new pid with a short timeout. `emu/stage6-panel.sh stage7` now
  waits up to 900 s on the **marker disappearing**, which is the direct signal that
  tuxweb reached `main`, and removes the marker on timeout so no later relaunch takes
  an unattended window. An abandoned window ran, crashed and left no evidence — worse
  than either outcome.
- **SIGTERM costs 2 relaunches, SIGKILL costs 1.** `sigHandler`'s long cleanup often
  faults partway, posting a second message. The live log steps `RESTART-5 -> 7`.
- **SIGTERM also switches the broadcast OFF.** `sigHandler` calls
  `sendUnregisterCommand` → `unregisterclient()` → zeroes `F7_Mesgs_enabled`, which
  gates the top of `wsltHandleRawDataFromPanel`. That is why the first stage-6 window
  logged **zero** and the second logged **29**: one signal changed.
- **The relaunch counter is per BOOT and a reboot clears it.** Verified: 19 of 24
  before a reboot, 0 of 24 after.
- **`/tmp` is tmpfs.** A reboot wipes the staged binary, `stage6-panel.sh`, the user
  code and any window logs. Capture evidence off the panel before rebooting — a 7d
  log was lost to exactly this.
- **The arm marker lives on mtd17 and survives a reflash.** Never put a secret in it.
  The user code goes in `/tmp/tuxweb-usercode`.
- **Home and Back clear the same flag 501 does.** During a window, arm/disarm is a
  good stimulus; Home/Back is not.
- **Registering FLUSHES the queue** (`registerclient`'s first act is `osal_MqFlush`),
  discarding whatever was queued for the previous consumer.
- **`501` is not a refcount.** One unregister switches the broadcast off for every
  consumer.

### Protocol facts worth not re-deriving

- **The user code is at `+0x0C`** of the 404-byte command (`Command.p2`), read by
  `/tuxedo`'s `sltRequestArmStay` @`0x140e44` at `140e80: ldrne r3, [r4, #12]`.
  **`0xFFFF` is the quick-arm sentinel** the panel substitutes when a partition's
  quick-arm byte is 0. Sending `p2 = 0` means **code zero** and is DECLINED — that is
  what the first 7d attempt did, and it exercised the declined path the plan says to
  avoid (`SetGotoStatus(false)` runs before its own guard).
- **502 = BACK, 503 = HOME.** The stage plan said "502/503 (home/back)", which reads
  as 502=home and is backwards. `RELEASES.md` has the measured result.
- **Commands are 404 bytes, replies 556.** Sizing a command from the reply layout is
  wrong; `mq_send` rejects it with EMSGSIZE.
- **The reply is a union, not a struct.** `session` and `msg_type` hold for every
  message; everything after depends on type. `Reply::parse` puts text at `+0x0E`,
  which is right for the status path and wrong for a 504.
- **The WNMP URL rule:** any `/system_http_api/API_REV01/<path>` reaches
  `serviceField` UNLESS `<path>` starts with `System`, `Administration` or
  `AutomationTest`. Those three branch away. `leakfix/fieldtab.py` dumps the 75-entry
  field table that defines the URL tree.

### Tooling traps

- **`ci/checks.sh` runs `sh -n`, and on this Windows host `sh` is Git Bash, not
  dash.** A bashism (process substitution) passed locally and failed CI twice. To
  check properly, ship the scripts to the build VM where `/bin/sh` really is dash.
  **Always check CI after pushing** — `gh run watch <id> --exit-status`.
- **Count the characters before trusting a `substr`.** The relaunch counter read
  `0 of 24` on a panel that had spent 4, because `BARRACUDA_RESTART-` is eighteen
  characters and the awk used `RSTART + 19`. Under-reporting is the dangerous
  direction on the counter guarding a hardware reset.
- **Use the decompiler.** `/opt/ghidra` on the build VM, and **`/tuxedo` is now
  imported** alongside `Barracuda.v14`. Both binaries carry full symbols; `/tuxedo`
  has C++ mangled names. `docs/DECOMPILER.md` has the invocation.
- **A green test on injected fixtures is not evidence.** `emu/cutover-test.sh` passed
  by injecting four replies while the panel path received none at all.

---

## 5. How to run a stage-7 window

```sh
# on the panel, after staging the binary and the script into /tmp
sh /tmp/stage6-panel.sh phase0                    # read-only pre-flight
sh /tmp/stage6-panel.sh phase1                    # install the passthrough
setsid sh /tmp/stage6-panel.sh stage7 "7c s45" > /tmp/s7.log 2>&1 &
# 7d needs the code first:  printf '%s\n' <code> > /tmp/tuxweb-usercode
sh /tmp/stage6-panel.sh revert                    # always available
```

Budget a full `phase1 + window + revert` as **5** relaunches, not 3. Reboot to reset
the counter if fewer than about 8 remain.
