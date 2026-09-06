# Releases

Each entry records what shipped, how it was verified, and enough detail to
rebuild it. The build recipe is in `TUXEDO-BUILD.md`; the patch set is
`patches.tsv`.

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

P10 is necessary but **not** sufficient on its own — Barracuda discards reply
type 20 entirely, so console mode still cannot be reached until Barracuda is
replaced. It is in v12 so that when a replacement does read the queue, the
message already carries real display text.

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
