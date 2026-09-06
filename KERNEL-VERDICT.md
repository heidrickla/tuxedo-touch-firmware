# Kernel & Boot Chain Replacement — Go/No-Go

**Panel:** Honeywell Tuxedo Touch WIFI, TUXW_V5.3.21.0, 203.0.113.5, wired to Ademco VISTA-21iP — **live alarm system in an occupied house**
**Kernel:** `Linux 2.6.31-207-g7286c01 #1094 PREEMPT Tue Sep 19 11:53:48 UTC 2017 armv6l` (MEASURED this pass)
**Date:** 2026-09-06
**Basis:** four independent assessments, each adversarially reviewed; corrected confidences applied throughout; three claims re-derived from the binaries in this synthesis pass.

**Evidence labels used below**
- **MEASURED\*** — re-derived in this synthesis pass (I ran it or disassembled it myself)
- **MEASURED** — a dimension agent ran it on the live panel; `(×2)` = independently reproduced by its reviewer
- **READ** — from a binary, a repo doc, or upstream source
- **INFERRED** — reasoning from the above
- **REFUTED** — a claim that failed review and is recorded here so it is not repeated

Nothing was written to the panel. No service restarted, no reboot, no arm/disarm, no MTD write.

---

## 1. Verdict

**No. Do not replace the kernel. Not now, and not on the evidence available today.**

This is not caution. Three things settle it, in order of decisiveness:

1. **There is no destination.** No mainline kernel at any version can produce a framebuffer on this board. `drivers/video/fbdev/mx3fb.c` and `drivers/dma/ipu/ipu_idmac.c` were deleted in v6.6 (commits `bfac19e239a7`, 2023-08-31, and `f1de55ff7c70`, 2023-08-01). Where they still exist (≤ v6.5) `mx3fb` binds by platform name `"mx3_sdc_fb"` with no `of_device_id`, and `arch/arm/boot/dts/nxp/imx/imx35.dtsi` has **no IPU, display, LCD or panel node at any version** — verified by reading the whole 404-line file. i.MX35 board files were removed in v5.10 (`e1324ece2af4`). So the last kernel where the display path exists in-tree is **v5.9, which is EOL** — trading a 2017 kernel for a 2020 one with no upstream security maintenance, which defeats the doctrine's own rationale. `/tuxedo` mmaps `/dev/fb0` directly (`4147e000-416b1000 rwxs ... /dev/fb0` in `/proc/915/maps`). No framebuffer means no keypad. **READ (×2)**

2. **The payoff is already banked without touching the kernel.** See §2. The kernel blocks *glibc* userland, not *modern* userland.

3. **The failure mode is a lying alarm panel, not a dead one.** `/dev/spi` (char major 251, CSPI1, IRQ 14) is the ECP link to the VISTA-21iP and it is servicing the bus right now — `spi_irq` climbed 10,835 → 11,792 → 25,622 → 30,565 across the four assessment passes. Its driver is undocumented vendor code with two IRQ handlers, an MCU config handshake, a retransmit timer and a checksum scheme. A clean-room reimplementation that is subtly wrong on framing or timing does not fail loudly — the panel boots, the UI comes up, and it mis-speaks to the VISTA. That is worse than a brick. **MEASURED (×2)**

**Is it safe enough to attempt on a live panel?** Not today. It becomes *survivable* — not safe — only after a serial console is wired and proven (§5, §8). Even then, a kernel port is not reachable without writing a device-tree binding that has never existed upstream plus three clean-room char drivers, one of which carries the alarm bus.

**What the doctrine gets right, honestly stated:** the kernel *is* old, *is* unpatched since 2017, and *does* impose a real syscall ceiling. If it were the thing standing between Lewis and a modern stack, replacing it would be correct. It isn't. It is standing between him and nothing he currently wants.

---

## 2. Is the kernel on the critical path? No.

**Plainly: no. A static musl/Rust userland already delivers the modern web and TLS layer on 2.6.31.** This is the most valuable finding in the whole assessment, and it is a good outcome, not a disappointing one.

| Claim | Evidence | Label |
|---|---|---|
| Rust std 1.98.1 runs statically on the panel, both `arm-unknown-linux-musleabi` and `musleabihf`, no INTERP — clocks, SystemTime, 16 threads, HashMap/RandomState, file I/O, TCP accept/echo | `WEBSERVER-REPLACEMENT.md:306` | MEASURED (repo) |
| `rustls` 0.23.43 + `ring` 0.17.14 completes **TLS 1.3 handshakes on this ARM1136 with no SIGILL** | `WEBSERVER-REPLACEMENT.md:310-311`, explicitly labelled MEASURED — I re-read the line this pass | MEASURED (repo) |
| musl 1.2.5 static works on this kernel; dropbear 2022.83 runs with pubkey auth and an interactive pty | `MODERN-USERLAND.md`; SSH into the panel is how this entire assessment was performed | MEASURED |
| musl's kernel floor is 2.6.0, far below 2.6.31 | upstream musl documentation | READ |

**Correction to the task brief:** the panel does **not** ship OpenSSL 1.0.0. `curl --version` → `curl 7.35.0 (arm-unknown-linux-gnu) libcurl/7.35.0 OpenSSL/1.0.1h`; `openssl version` → `OpenSSL 1.0.1h 5 Jun 2014` — which does support TLS 1.2. The pre-TLS-1.2 constraint belongs to **Barracuda's SharkSSL**, a separate stack (19 `SharkSSL` + 170 `SharkSsl` strings in the binary, zero `OpenSSL`/`TLSv1`/`SSLv3`). "1.0.0" in the brief is almost certainly the `libssl.so.1.0.0` SONAME. Barracuda is being replaced anyway, so this constraint dies with it. **MEASURED (×2)**

### What the kernel actually costs us

The complete, enumerated list — not assumed:

- **Exactly three syscalls are a version-level defect.** ARM `calls.S` at v2.6.31 reads `/* 335 */ CALL(sys_ni_syscall) /* eventually pselect6 */`, then `ppoll`, and at 346 `epoll_pwait`. At v2.6.32 all three are implemented. Replicated on the panel: `/proc/kallsyms` has no `sys_ppoll` and no `sys_pselect6`; `sys_epoll_pwait` is a weak alias at `c00b91ec` — the address of `sys_ni_syscall`. **MEASURED (×2)** This is precisely why Go 1.20–1.27.1 die with `runtime: netpoll failed` while 1.17–1.19 run stock. Rust was already chosen over Go, so this buys nothing.
- **~34 syscalls above the 363 ceiling are absent**: `getrandom`, `memfd_create`, `renameat2`, `statx`, `openat2`, `clone3`, `pidfd_open`, `io_uring_setup`, `copy_file_range`, `seccomp`, `bpf`, `userfaultfd`, `execveat`, `prlimit64`, `setns`, `sendmmsg`/`recvmmsg`, and the rest. Present and often wrongly assumed missing: `accept4`, `epoll_create1`, `pipe2`, `dup3`, `signalfd4`, `eventfd2`, `timerfd_*`, `preadv`/`pwritev`, `fallocate`, `utimensat`. **MEASURED**
- **Nine years of unpatched kernel CVEs.** Real. Unquantified. The panel is a LAN device behind a router and the internet-facing-ish surface (the web server) is being replaced.
- **No netfilter, no hardware RNG** — but these are *config* choices in the vendor's own 2.6.31 build, not version limits: `# CONFIG_NETFILTER is not set`; `CONFIG_ARCH_HAS_RNGC=y` alongside `# CONFIG_HW_RANDOM_FSL_RNGC is not set`. Also off: `CGROUPS`, `NAMESPACES`, `SECURITY`, `KEYS`. **MEASURED (×2)**

**Do not treat "just rebuild 2.6.31 with netfilter on" as a cheap escape hatch.** It requires the vendor BSP source we do not have, a 2007-era toolchain, and *the identical NAND write to a live panel* that the whole assessment rates as the risky step. It is the same gated operation wearing different clothes. (Corrected from MEASURED → **INFERRED**.)

Likewise, **"just backport the three syscalls" is not cheap.** That claim was **REFUTED**: the upstream change is not "TIF_RESTORE_SIGMASK plus three table entries." v2.6.32 adds `TIF_NOTIFY_RESUME` as well, and `arch/arm/kernel/signal.c` differs by 137 lines with `entry-common.S` by 66 — a restructuring of `do_signal` and the `work_pending` return path, two of the most delicate files in the ARM port, applied blind to a non-vanilla Freescale BSP tree that already carries a local `kernel/signal.c` modification (dmesg prints `SIGNAL in KERNEL 18 for Process 917 Process Name init` — not upstream). And it ends in the same NAND write.

---

## 3. What the boot chain actually gives you — and one thing it does not

This section exists because three of the four dimensions got this wrong in different directions, and because it is what any future attempt will lean on. I re-derived all of it from `seconboot.bin` (mtd9, dumped read-only) with capstone in this pass. **Load base: `VA = 0x87800000 + file_offset − 0x80`** (128-byte vendor `boot000` header, load address `0x87800000` at header +0x10, NAND offset `0x120000` at +0x0c — confirmed).

### 3.1 The three-slot fallback is REAL and IS on the reachable boot path

**MEASURED\*** — I disassembled `do_bootm` at `0x8780ee54` myself:

```
0x8780eeb4  cmp   r6, #1              ; r6 = argc
0x8780eeb8  ble   #0x8780ef00         ; -> LOOP HEAD
0x8780ef00  <loop head>  r4 = 1 ; [sp,#0x14] = 0x300000
0x8780ef30  bl    #0x8780e794         ; bootm_start (validate)
0x8780ef34  cmp   r0, #0
0x8780ef38  mov   r1, #0x520000       ; Kernel 2 = mtd14
0x8780ef3c  bne   #0x8780f068         ; invalid -> fallback
0x8780f068  cmp   r4, #1 / cmp r4, #2
0x8780f078  mov   r1, #0x820000       ; Kernel 3 = mtd15
0x8780f080  ldr   r3, [pc, #0x58]     ; = 0x80800000   <-- HARDCODED DEST
0x8780f088  bl    #0x8781e89c         ; nand_read_skip_bad
0x8780f090  add   r4, r4, #1
0x8780f094  ldr   r0, ... "ERROR :nand read for kernel images\n"
0x8780f0a0  cmp   r4, #4 / bne #0x8780ef20
0x8780f0a8  ldr   r0, ... "All the three kernel images are corrupted\n"
```

Slot offsets match `/proc/mtd` arithmetic exactly: mtd0-8 = 9×0x20000 = 0x120000; mtd9-12 = 4×0x40000 → 0x220000 = mtd13; then 0x520000 and 0x820000. **MEASURED\*** (partition table re-read this pass).

The **mainline** dimension's claim that "the three kernel slots are not an A/B fallback; the bootloader unconditionally boots Kernel 1 and never reads Kernel 2 or 3" is **REFUTED**. Its method — byte-searching for the packed constants — could never have found them, because the slot offsets are MOV immediates, not literal-pool words. Absence of a search hit was mistaken for absence of the mechanism.

The **constraint** dimension's hedge (strings present but reachability unproven) is superseded: `bootcmd=run bootcmd_nand` → `bootcmd_nand=run bootargs;nand read 0x80800000 0x220000 0x300000; bootm`, and bare `bootm` is `argc==1`, which branches straight to the loop head.

### 3.2 The bootchain dimension's `bootm <addr>` exemption is REFUTED — and this is a live trap

The claim that "`bootm <addr>` takes the ordinary path with NO fallback" is wrong. **MEASURED\***:

```
0x8780eebc  ldr   r0, [r7, #4]        ; argv[1]
0x8780eec8  bl    #0x8781aa64         ; simple_strtoul(argv[1], &endp, 16)
0x8780eed4  cmp   r3, #0              ; *endp == '\0'
0x8780eed8  cmpne r3, #0x3a           ;          or ':'
0x8780eedc  beq   #0x8780ef00         ; -> LOOP HEAD
0x8780eee0  cmp   r3, #0x23           ;          or '#'
0x8780eee4  beq   #0x8780ef00         ; -> LOOP HEAD
0x8780eee8  ... bl #0x8780ec88        ; only NON-NUMERIC arg -> subcommand
```

This is the stock U-Boot 2009.01 FIT/subcommand discriminator. **A numeric address argument enters the same retry loop.**

Combined with `bootm_start`'s address selection (`0x8780e804-0x8780e828`: `if (argc <= 1) addr = load_addr; else addr = simple_strtoul(argv[1],...)` — **MEASURED\***) and the hardcoded `0x80800000` destination, this produces a real trap:

> **If you netboot a candidate kernel to `0x80800000` (which is `loadaddr`, the default, and what `tftpboot uImage` uses if you don't override it) and it fails validation, the fallback overwrites your buffer with the vendor kernel from mtd14, revalidates it, and boots it. You get a working panel and believe your kernel ran.**

Loading to **`0x81000000`** avoids the substitution (retries re-validate the same bad image at `0x81000000`, fail three times, and drop to the prompt). The bootchain assessment recommended `0x81000000` for the right reason but priced it as belt-and-braces; it is load-bearing.

### 3.3 NEW FINDING (this pass): the payload CRC is NOT verified on this unit

None of the four dimensions established this. **MEASURED\***:

```
0x8780e7bc  ldr r0, ="verify" ; bl getenv
0x8780e7c4  str r0, [r5, #0x84]     ; stores the RAW POINTER, not (s && *s=='n') ? 0 : 1
...
0x8780e868  ldr r4, [r4, #0x84]
0x8780e888  bl  #0x878173a8         ; image_check_hcrc -> "Bad Header Checksum\n"  (ALWAYS)
0x8780e8c0  cmp r4, #0
0x8780e8c4  beq #0x8780e8f4         ; verify == NULL -> SKIP the data CRC entirely
0x8780e8cc  bl  #0x8781736c         ; image_check_dcrc -> "Bad Data CRC\n"
```

The string `verify` occurs **exactly once** in the entire bootloader image (file `0x21b5c` / VA `0x87821adc`) — it is the `getenv` key. It is **not** among the 17 variables in the compiled-in default environment, which I dumped in full this pass. And mtd12 is entirely erased (**0 non-0xFF bytes of 262,144** — MEASURED\* on the live panel), so the compiled-in default is what runs.

**Consequence:** on this unit U-Boot validates a kernel image on **magic (`0x27051956`) and the 64-byte header checksum only**. The payload CRC is skipped. A truncated or partially-written kernel whose header survives intact **passes validation, boots, and hangs — and the fallback never fires.**

This makes the safety net materially weaker than any dimension reported. It also means the bootchain agent's instinct to corrupt the *header* rather than the payload for a fallback rehearsal was correct, for a reason they had not established.

### 3.4 What the fallback therefore does and does not catch

| Failure | Fallback fires? |
|---|---|
| Bad magic (wrong file, garbage, erased slot) | **Yes** |
| Bad 64-byte header CRC | **Yes** |
| Bad payload / truncated or interrupted write, header intact | **No** (§3.3) |
| Valid image that panics, hangs, or comes up headless | **No** — and this is the *likely* failure mode of a port |

There is **no bootcount, no `altbootcmd`, no `bootlimit`, no `preboot`** — all absent from the image (**MEASURED**, string search; corroborated by the blank env leaving nothing to persist). There is no watchdog in the bootloader (no `wdog`/`watchdog`/`WDOG` strings and no `0x53FDC000` literal — **INFERRED**, since string absence cannot prove absence of MMIO code), and a reset would re-run the same `bootcmd` against the same slot anyway: a boot loop, not a recovery.

### 3.5 Recovery layers, ranked by how much they are actually worth

| # | Layer | Status |
|---|---|---|
| 1 | **SD card reflash via ProgCV** — mtd0 contains a full SD/MMC + FAT12/16/32 reader and the literal `ProgCV.hdr`; `/mnt/sd/app1.hdr`'s payload is byte-identical to mtd13 (md5 `4d6351f7998243221f89b625d880f106`) | **PROVEN IN PRODUCTION on this unit** (push-image.sh, custom v10 flashed). Strongest layer by far. |
| 2 | **Three-slot kernel fallback** | Mechanism **PROVEN by disassembly** (three independent reads incl. mine). **Never exercised on this unit.** Catches only §3.4 row 1-2. All three slots currently hold the identical known-good kernel: md5 `5becbfff71a5687bb2747a967a3ae7c8` ×3 (**MEASURED\***). |
| 3 | **U-Boot serial prompt** — `Hit any key to stop autoboot: %2d`, `bootdelay=1`, full command set incl. `tftpboot`/`loadb`/`loady`/`nand write` | **Code present (READ). Never exercised. Pads not located.** A recovery path you have not used is a hypothesis. |
| 4 | **JTAG** | Contemplated only by ProgCV's own `USE JTAG PROGRAMMER` string. Header not located. |

**mtd1 "Primary Bootloader Backup" is completely blank** (131,072 bytes, zero non-0xFF). There is no primary-bootloader backup on this unit. Destroying mtd0 = JTAG or scrap. **MEASURED**

**Unresolved and load-bearing:** whether ProgCV writes one kernel slot or all three. It cannot be determined from this unit because the flashed and factory kernels are identical. **A flasher that writes all three would destroy the fallback in the same operation that needs it.** Any kernel experiment must therefore write mtd13 directly from Linux, not via the SD flasher.

---

## 4. If it is ever attempted: the staged path

Presented because Lewis asked for it and because stages 1–2 are worth doing regardless of the verdict. **Recovery is stated before each risky step. Do not reorder.**

### Prerequisite P0 — full rootfs backup (zero risk, do this first)
`dd if=/dev/mtd16ro` over SSH to the workstation (180 MiB). Nothing in stages 1–4 is defensible without it, and it also protects the JFFS2 exposure in stage 1. The panel has **no** mtd-utils — `flash_erase`, `nandwrite`, `nanddump`, `flashcp`, `mtd_debug` are all absent; only `dd`, `base64`, `od`, `md5sum`, busybox 1.36.1, curl and openssl. **MEASURED**

### Stage 1 — wire the serial console. Writes nothing.
**Recovery if it goes wrong:** none needed; nothing is written. The hazards are physical and procedural, not flash.

- UART1 = `0x43F90000` = ttymxc0, **115200 8N1, 3.3 V TTL only**. Never RS-232, never 5 V. GND first; adapter RX→board TX, TX→board RX; **leave VCC disconnected**.
- Pad location is **not determinable from firmware**. It has to be found by inspection with the unit powered off — typically an unpopulated 3–4 pin header near the SoC.
- Sanity check on a normal boot: U-Boot banner then kernel messages (`/proc/cmdline` carries `console=ttymxc0,115200`). Then power-cycle spamming space, looking for `Hit any key to stop autoboot:  1` → `MX35 U-Boot > `.
- Read-only captures at the prompt: `version`, `printenv`, `bdinfo`, `nand info`, `nand bad`. `printenv` **should** show the bad-CRC warning and the 17 defaults in §3.3. **If it does not, the entire bootdelay/blank-env conclusion is void — stop there.**
- **Never type:** `saveenv`, `nand write`, `nand erase`, `nand scrub`, `nand markbad`, `erase`, `protect`, `cp.b`, `run prg_uboot`, `imw`/`imm`/`inm`/`iloop`, `mtest`.

**Honest costs the assessments understated:**
- `/` is JFFS2 mounted **rw** (`/proc/cmdline` confirms `rw`). JFFS2 writes to NAND on mount even if you touch nothing. Every missed 1-second window is another unclean power-cut of a rw NAND volume. Keep the power-cycle count low, and rely on P0 + the proven SD reflash path if the rootfs degrades.
- Opening the case **trips the keypad tamper on a live alarm** (`tamper_irq` is IRQ 129; dmesg already shows `Tamper Detected`). Do it disarmed and expect the event.
- The unit is an **offline alarm keypad** for the duration.

### Stage 2 — netboot a candidate. Writes nothing to the panel.
**Recovery if it goes wrong:** power-cycle. The unit returns to stock byte-for-byte on the NAND side. `setenv` is RAM-only; `saveenv` is the sole NAND-env writer and you simply never type it.

```
mkimage -A arm -O linux -T kernel -C none -a 0x80008000 -e 0x80008000 \
        -n 'tux-test' -d arch/arm/boot/Image uImage
setenv ipaddr <panel> ; setenv netmask <mask> ; setenv serverip <workstation>
printenv ethaddr        # default is 00:00:00:00:00:00 — see below
tftpboot 0x81000000 uImage
setenv bootargs noinitrd console=ttymxc0,115200 root=/dev/mtdblock16 ro rootfstype=jffs2 init=/bin/sh
bootm 0x81000000
```

- **`0x81000000` is mandatory, not stylistic.** §3.2. Do not use `loadaddr`/`0x80800000`, and never a bare `bootm` after a tftpboot.
- The bootloader carries `Reading hardware paramenter failed` / `HW PARAM READ : All six mirros are bad` / `Not able to set ethaddr`. If the mtd2-8 mirrors are unreadable, `setenv ethaddr 02:00:00:00:00:01` (RAM-only) before TFTP will work.
- **Verify your kernel actually ran.** Require all four: `bootm` echoed `tux-test`, not `Linux-2.6.31-207-g7286c01`; no `ERROR :nand read for kernel images`; no `All the three kernel images are corrupted`; and `uname -a` in the shell matches your build.
- Iterate here indefinitely. **This is where the project ends**, because this is where you discover that there is no framebuffer, no `/dev/spi`, no `/dev/led`, no `/dev/zwave` and no touchscreen — for the price of a $3 adapter and zero writes. That is a complete and valuable answer.

### Stage 3 — rehearse the fallback. One write, revertible.
**Recovery before the risky step:** verify `md5sum /dev/mtd14ro /dev/mtd15ro` both still read `5becbfff71a5687bb2747a967a3ae7c8` *before* rebooting; keep `/mnt/sd/app1.hdr` in place; have the serial prompt from stage 1 available.

Take the known-good vendor kernel (payload of `app1.hdr`) and flip one bit **in the 64-byte uImage header** — e.g. in the name field — so the header CRC fails. **Not the payload:** §3.3 proves the payload CRC is not checked on this unit, so a corrupt payload would boot and hang instead of falling back. Write to **mtd13 only**, using a cross-built static-musl `flashcp`/`nandwrite` pushed via deploy.py — not `dd` to `/dev/mtdblock13`. mtd13-15 are `MTD_WRITEABLE` (flags 0x400), 2048-byte pages, 64-byte OOB, and the BBT reports **no bad blocks anywhere in 0x220000–0xB1FFFF** (all 9 bad blocks are at or above 0x2180000, inside mtd16/mtd17). **MEASURED**

Expected: U-Boot rejects slot 1, silently reads `0x520000`, boots the vendor kernel, `uname` unchanged. That proves the net catches **on this unit**. Then restore mtd13 and re-verify the md5.

### Stage 4 — flash a candidate to mtd13
Only with mtd14/15 held as the known-good pair, and only after stage 3. **The fallback does not protect the failure mode you will actually hit** (valid image, no display or no ECP), so this stage's real recovery is the SD card and the serial cable, not the slots.

### Worst-case physical access, ranked
1. **Nothing** — SSH alive: push a `.hdr` to `/mnt/sd`, reboot into ProgCV. Proven in production.
2. **SD card** — pull the card, write a valid `.hdr` set on a PC, reinsert, power-cycle. Bootloader-level; does not depend on the kernel, rootfs, or seconboot.
3. **Serial** — open the case, three wires. Full U-Boot control: `nand read 0x81000000 0x520000 0x300000; bootm 0x81000000` boots the untouched slot-2 kernel. Also the **only** way to see *why* a boot failed.
4. **JTAG** — last resort, header not located.

**Never write mtd0, mtd1, mtd2-8, or mtd9-11.** mtd1 is blank so there is no bootloader backup; the hardware-parameter blocks are probably MAC and calibration with no factory record.

---

## 5. What to do instead, and what would reopen the question

### Do instead
1. **Ship the musl/Rust static userland.** It is measured, it is where the wins are, and it carries none of this risk. Replace Barracuda; leave the kernel alone.
2. **Fire a GPL source request at Resideo — free, zero risk, do it today.** `resideo.com/us/en/pro/opensource/` lists a Tuxedo Series section whose table includes `kernel-2.6.31-imx` v4.5.1 GPL-V2 and `u-boot-2009.01-imx` v4.5.1 GPL-V2, alongside tslib 1.0, gstreamer 0.10.28, avahi 0.6.31, sysvinit 2.85 and openssl 0.9.8g — all consistent with the filesystem. No download link is published; the written-offer route applies. Caveat: v4.5.1 ≠ the panel's 5.3.21.0, so the drop may be for an older release. **READ**
3. **Build the serial cable and run stage 1–2 anyway.** It is the cheapest risk reducer in the project and it settles the kernel question empirically for ~$3.
4. **Capture the wire fixtures (§6).** Read-only, no arming, needed regardless.
5. **Back up mtd16.**

### Reopen the kernel question only if
- **Resideo honours the source request.** This is the big one: it would replace blind reverse-engineering of the vendor driver blob with a diff against a known tree, and would supply the IPU/CLAA panel wiring that mainline has never had.
- **The serial console is proven and stage-2 netboot shows the drivers are portable.** Unlikely, given the display situation, but it is the empirical test and it costs nothing.
- **Something genuinely needs a syscall above 363.** Nothing queued does.
- Not for CVEs alone. Not for netfilter or the RNGC — those are config fixes at 2.6.31 (gated on the same source request and the same NAND write, so not free, but not a version problem either).

### Scope of the port, corrected — it is bigger than reported
The "~9.4 KB contiguous vendor driver blob" (`c0243258`–`c02456f8`) is a **floor, not a total** — **REFUTED as "the entire blob"**. Outside that range and equally required: `mxc_unifi_hardreset` `c008e664`, `mxc_unifi_enable` `c008e668`, `get_unifi_plat_data` `c008e66c`, `kickwatchdog` `c008e884`, `init_watchdog` `c008f488`, `reset_ecpmicro` `c0090020`, `fs_unifi_remove` `c024d3c8`. Plus:

- **The watchdog is not a Linux watchdog.** `/dev/watchdog` is char major 248 (not misc 10:130) and **seven processes hold it open simultaneously** (902 supervis, 986 thermostatclient, 1074 Barracuda, 1078 vidApp, 1112 TotalConnect, 1125 audioapp, 1205 VoiceRecog). Mainline's watchdog core returns `-EBUSY` on a second open. A compat shim is mandatory; getting it wrong means a reboot loop or a watchdog that never fires. **MEASURED (×2)**
- **Touchscreen: not the free win it was reported as.** The panel's `input0` is `mxc_ts` (MC13892 PMIC ADC path, `EV=b`, `ABS=1000003`, `KEY` bit 330 = `BTN_TOUCH`). Mainline's `mc13783_ts.c` registers `platform_driver.name = "mc13783-ts"` with no `id_table`, no OF match, and `module_platform_driver_probe` (exact-name binding), while `mc13xxx-core.c` creates the subdevice as `"%s-ts"` with `variant->name = "mc13892"` → `"mc13892-ts"`. **It does not bind, on either the DT or the platform-data path, in current mainline or at v5.9.** Register compatibility between MC13892 and MC13783 ADC touch mode is untested. (Corrected from "REFUTES the hypothesis, not a blocker" → **INFERRED**, small but real.)
- **`/tuxedo` itself would probably survive** — EABI v4, 264 ordinary libc imports, standard fbdev/evdev/tslib path, one hard kernel requirement: **2,373 references to `0xffff0fc0` (`__kuser_cmpxchg`)**, Qt's `QBasicAtomicInt::deref`. `CONFIG_KUSER_HELPERS` still exists and defaults to `y`, but `CPU_32v6` does not select `NEED_KUSER_HELPERS`, so the prompt is live and a hardened config would kill the app. **MEASURED (×2)**
  - Scope caveat (**corrected to INFERRED**): the "three ioctl magics, five requests" and "zero raw syscalls" findings were measured on `/tuxedo`'s own `.text` only. The process is dynamically linked against vendor-built `libQtCore/QtGui/QtNetwork.so.4` and `libts-1.0.so.0`, none scanned — and **`libQtGui.so.4`, not `/tuxedo`, is the binary containing `/dev/fb0`**, so any private MXCFB ioctls (vsync, page flip; fb0's `virtual_size` is 800,960, i.e. double-buffered panning) live there.
- **Kernel slot headroom is tight.** Current uImage payload `0x0020BC64` = 2,145,892 bytes in a `0x300000` slot (68% full). A modern ARM kernel with an equivalent driver set does not plausibly fit. Merging all three slots into one 9 MB region costs the fallback. **MEASURED / INFERRED**
- **Userland breaks underneath too:** udev 117 populating a plain tmpfs `/dev` (not devtmpfs), `CONFIG_SYSFS_DEPRECATED_V2=y` (removed from mainline years ago), and codec NAU8812 (mainline has NAU8810/8821/8822/8824/8825 — `nau8810.c`'s tables do carry a `"nau8812"` name and `"nuvoton,nau8812"` compatible, so this one is probably fine).
- **Wi-Fi is already dead and unportable anyway:** `Error: fs_unifi_init failed!`; CSR UniFi SDIO was never mainlined; `/tuxedo` uses 17 driver-private WEXT ioctls in `0x8BE1-0x8BF1`. Irrelevant — the panel is wired.

---

## 6. The backwards-compatible API contract

**This is a requirement in its own right, independent of the kernel verdict**, because `ha-tuxedo-touch` is public. The v2 contract is written and validated at
`C:\Users\dev\AppData\Local\Temp\claude\D--PersonalProjects-iot-protocol-tools\000ba43d-52f5-43a6-902d-6c0edfdf3ceb\scratchpad\contract\wire-contract-v2.json`.

It supersedes `D:\Projects\ha-tuxedo-touch\docs\wire-contract.json`, which is written from the *client's* point of view and omits authentication, the AES envelope, the multipart framing bytes, and `/handlerequest.html`. v2 is written from the *server's* point of view — what a replacement must emit — with three conformance levels: **L1 byte-identical**, **L2 semantic**, **L3 behavioural**.

### The four things that will break a replacement

**1. The REST response envelope is two layers, and v1 documents only the inner one.**
The wire body is `{"Result":"<base64 AES-256-CBC>"}`. The documented `{"Status":"Sucess","Result":{...}}` is the **decrypted inner plaintext**. A server built literally from v1 emits plaintext JSON where every client base64-decodes, and every call fails.
*Corrected from INFERRED → **MEASURED**:* a live arm-stay/disarm cycle was already run on 2026-09-06 and recorded at `TUXEDO-HA-ENRICHMENT.md:889-899` ("observed rather than inferred"). Both capture tools decrypt `payload["Result"]` before printing (`api.py:610-625`, `tuxedo_api_console.py:131-132`); on a plaintext wire body the decrypt would raise and the tool would have emitted `[non-JSON]`. The clean recorded plaintext is only producible from a ciphertext-in-`Result` body. **The one blocker's price was overstated: no fresh arm/disarm is needed** — `get_status()` goes through the identical `_call()` path, so a raw-byte capture of `GetSecurityStatus` settles the envelope with zero panel-state change.

**2. The 33 s push heartbeat is a hard server obligation.**
`push.py:455-460` sets `sock_read = PUSH_READ_TIMEOUT = 90`. The vendor repeats partition status on an unconditional timer measured at 32.68–33.31 s across 26 intervals. An event-driven replacement that pushes only on change is silent on a quiet house and enters a permanent reconnect loop that looks entirely healthy from the server side.
*Corrected:* backoff reset requires **both** ≥60 s held **and** ≥1 frame (`push.py:507-509`, `const.py:73-79`). So a fully silent server walks the backoff to `PUSH_BACKOFF_MAX = 300` (≈390 s cycle); a server that emits `setCid` on connect gives the ≈95 s tight loop. Either way the heartbeat is mandatory.

**3. Port 80 must redirect with 302, not 301.**
`WEBSERVER-REPLACEMENT.md` §2.6 (lines 422/506/1025) specifies 301. `api.py:549-566` branches on `302` (raises `TuxedoTouchHttpsRequiredError` → user-visible repair issue) and re-logins on `(401, 302)`; `push.py:468-472` raises `PushSessionExpired` only on 401/302. **A 301 hits neither** and falls through to a generic `HTTP 301` with no repair issue and no re-login. The vendor's measured behaviour is 302. **This is a self-inflicted regression in the current plan — fix the doc before implementation.**

**4. The login hex value is used in two encodings, and this is the single most common reimplementation bug.**
The `Random` header (31 chars — odd length, so not hex) is the **HMAC-SHA512 key as ASCII text**. The `#readit` `key_hex` (64 chars) is **hex-decoded to bytes for AES-256-CBC** and the **same string used as ASCII text for the HMAC-SHA1 authtoken**. Get this wrong and you authenticate fine and then fail every API call.

### The rest of the contract

- **Login success and failure are both HTTP 200.** The only discriminator is whether a session cookie came back; the client takes the first `Set-Cookie` whose name does not start with `_zFL` (`api.py:344-356`). A replacement must not emit any other cookie ahead of the session cookie.
- **Returning 401 for a bad password is free *against the reference client*** (`CREDENTIAL_VERDICT_STATUSES = {401,403}` → same `TuxedoTouchAuthError` as the missing-cookie path) — but *not* free against unenumerable third-party clients that gate on `status == 200`. **Corrected from "the one free improvement" → INFERRED.** Price it the same way as the push-auth change or not at all.
- **Push framing bytes** (L1 byte-identical):
  - part preamble, one contiguous literal at `0x540424`: `--EH912ZZ\r\nContent-type: text/plain\r\n\r\n[`  — **READ (×2)**
  - terminator, one contiguous literal at `0x540026`: `]\r\n--EH912ZZ--\r\n`  — **READ (×2)**
  - top-level header: `Content-type` (`0x540260`) and `multipart/x-mixed-replace;boundary="EH912ZZ"` (`0x540270`) are **separate** literals with four NULs between. The joining `: ` and the emitted capitalisation are reconstructed, not read. **Corrected READ → INFERRED**; fixture P0 settles it, alongside whether the close-delimiter really follows every part.
  - `tests/fake_panel.py:285-290` reproduces none of this (space after the semicolon, no part preamble). The *narrow* true claim: it gives **no regression protection**, so a future tightening toward a strict multipart parser would pass CI and fail on the panel. The broader claim that the client's parser was never proven against vendor bytes is **REFUTED** — `push.py`'s `_FrameDecoder` does not parse multipart structure at all (regex over an accumulating buffer, boundary used only for part counting and buffer bounds) and was written from the live capture.
- **Misspellings are per-string, never a find-and-replace.** `Sucess` occurs **exactly once**, at `0x82fa8`. `Discover cameras command sent successfully` (`0x835c9`) is spelled correctly; `Door bell press command sent sucessfully` (`0x83591`) is not. Take spelling from fixtures. **READ (×2)**
- **Push field 2 is the panel status code, not the partition.** `-1` means the ECP link to the VISTA is down and the frame is sent anyway (`CReceiverThread::sltSendChangedPartitionStatus` @`0x144880`: `bl PanelIsTalking; cmp r0,#0; mvneq r3,#0; streq r3,[sp,#8]`). A client reading it as a partition discards every frame the moment the link drops. `ha-tuxedo-touch` shipped exactly this bug through 0.4.2.
  **Addition from review:** immediately before that, `0x144a5c bl GetOnlineStatus` / `0x144a68-74 movne r3,#1; movne r2,#0x16; strne r2,[sp,#4]` — **when `GetOnlineStatus() != 1` the message id is rewritten from 21 to 22.** So the `-1` status can arrive under id 21 **or id 22**. Id 22 was never observed because the panel was online throughout. Any synthesised link-down fixture must cover both.
- **The state flag exists in two forms.** The `:fe:`/`:ff:` hex-text field appears on id 21 only; the raw `0xFE`/`0xFF` byte appears on id 21 and id -1. **Scan for the raw byte; never key on field position or count.** Latin-1 decoding is load-bearing — UTF-8 turns `0xFE`/`0xFF` into U+FFFD and the display field cannot be located at all. Frame census over 150 s: id 21 ×6, id 18 ×5, id 504 ×1, id -1 ×21, bare/Client-Connected ×16. **MEASURED**
- **`/handlerequest.html` is fire-and-forget.** Commands 19, 55, 1125, 999999 and 0 all returned HTTP 200 with 0 bytes on a valid session — valid and nonsense are indistinguishable. Reproduce that; expose real results on a **new** endpoint behind capability detection. Returning 4xx for an unimplemented command **is** a break.
  *Corrected from MEASURED → INFERRED for "unconditionally":* the cited region `0x531800-0x5318d0` is a **mixed** literal pool, not a parameter pool — `<html><body>Message Sent</body></html>` `0x531804`, `Session_Expired` `0x53182c` (**not** `0x531843`, which is a NUL byte — offset error corrected), `param2` `0x53183c`, `channel` `0x531844`, `sessionid` `0x53184c`, `tokenkey` `0x531858`, `uCode` `0x531868`, `Error Sending Msg` `0x531870`, `cmd` `0x531884`, `filters` `0x531888`, `index` `0x531890`, `tarTemp` `0x531898`, `Allow Add` `0x5318a4`. A full `<html><body>Session_Expired</body></html>` exists at `0x53bb13`. If adjacency attributes the parameter names to this handler, it equally attributes the response bodies — so an expired session may well produce a body. Measured behaviour covers valid sessions only.
- **REST parameter order is not load-bearing.** `api.py:706` sends `arming&pID&ucode&operation`; `tuxedo_api_console.py:166` sends `arming&ucode&pID&operation`. Both work. An order-sensitive parser breaks one shipped client.
- **Push-stream auth: require it.** Costs zero against `ha-tuxedo-touch` (`push.py:447/463/468/470` already sends the cookie, treats 401/302 as expiry with one re-login, and 404 as unsupported). It closes a real unauthenticated LAN disclosure of live alarm state including the exit-delay countdown. The unpriceable cost is every curl/Hubitat/node-red client that opens `/SimpleDebugger.interface/G.` without a cookie. Mitigation, per `WEBSERVER-REPLACEMENT.md` §2.5: stream off by default on port 80, `push.legacy_plaintext=true` re-enables, hourly warning while on, flag removed one release later. **Decide and write this down before building the suite** — it changes what a conforming response to an unauthenticated GET is.
- **Wire compatibility permanently forbids modern password hashing.** The credential POST sends only `HMAC-SHA512(key=Random-as-text, msg=username.lower()+password)`; verifying it requires the plaintext password. No bcrypt/argon2 verifier can satisfy this. The only escape is a second, modern auth path behind capability detection and a multi-release deprecation. **Put this in the threat model now**, not later.

### Conformance test plan

| Tier | What | Notes |
|---|---|---|
| **0** | **Client-side raw-byte capture** — 13 fixtures A1-A3, C1-C4, P0-P3, H1-H2 | Irreversible: once the vendor firmware is replaced these cannot be recaptured except by reflashing back. Capture on the workstation, not the panel — traffic is plaintext on :80 and decryptable client-side on :443, and the panel has no tcpdump/nc-binary/socat/strace/python (busybox 1.36.1 only, / 180 M with 47 M free, /tmp a 20 M tmpfs). **MEASURED** |
| **1** | **Offline fixture replay** — feed the server's frame builder a state, assert bytes equal the fixture | Extends `tests/test_wire_contract.py` in the opposite direction |
| **2** | **Differential proxy** driven by the real client | Exercises request shapes nobody thought to capture |
| **3** | **Unmodified `ha-tuxedo-touch` acceptance**, including a **5-minute idle hold asserting zero reconnects** | The only test that catches a missing heartbeat |
| **4** | **Bounded-window on-panel canary on a spare port**, alongside the vendor binary — never replacing it | Opening a push stream is not passive: registering triggers command 500 and flushes the 32-deep reply queue, transiently stealing events from the production client |

**Hard exclusions — by construction, not by discipline:**
- **Never submit a deliberately wrong password.** Three failed web logins disable the panel's web accounts and **the counter survives a firmware reflash** (`const.py OPT_CREDENTIALS_REJECTED` exists solely because of this). This is the real soft-brick risk in the whole workstream.
- **Never provoke a declined user code** on the alarm side.
- The **ECP-link-down** fixture must be labelled **SYNTHESISED** from producer code, not captured — capturing it requires dropping the VISTA bus on an armed house — and per the correction above it must cover both id 21 and id 22.

**Second-order hardware risk inherited from `supervis`:** at 24 relaunches it disarms the timer created by `wdg_init` (the watchdog keepalive) and the unit resets. Disassembly is **READ**; the consequence is **INFERRED** — no watchdog reset has ever been observed on this unit. It errs toward caution, but it is *why* the tier-4 canary runs beside the vendor binary rather than replacing it, and why the execve-the-vendor-binary-on-startup-failure rule in §1.2 is load-bearing.

---

## 7. The single cheapest experiment

**Wire a 3.3 V USB-TTL adapter to ttymxc0 and obtain a U-Boot prompt.** ~$3 plus opening the case. Zero writes.

**What it settles, in one sitting:**
1. **Whether U-Boot console input is enabled at all on this build.** Everything else is downstream of this. The strings prove the code is linked in; they do not prove the console accepts input, that the pads are populated, or that anything can win a 1-second window. (The claim that the strings "correct" the repo's position is **REFUTED** — `TUXEDO-FIRMWARE.md` §16's "observation-only" is scoped to the Linux login shell, and the repo already logged the U-Boot prompt as `[UNKNOWN]`.)
2. **Whether `bootdelay=1` and the 17-variable compiled-in default env are really live** — the single fact the whole recovery story rests on. `printenv` should show `Warning - bad CRC, using default environment` and the list in §3.3. If it does not, §3 is void.
3. **Whether the hardware-parameter mirrors yield a usable `ethaddr`**, which decides whether TFTP works without a manual `setenv`. One command: `printenv ethaddr`.
4. **Whether the three-slot fallback and the payload-CRC finding behave as disassembled** — `nand info`, `iminfo 0x80800000`, and (stage 3) an actual rehearsal.
5. **And then, for free, the entire kernel question.** Stage 2 netboots a candidate with zero NAND writes and a power cycle as the undo. You find out empirically whether a mainline kernel can produce a framebuffer and drive the ECP bus on this board — the thing the whole assessment says it cannot — without ever risking the panel.

**What it does not tell you:** whether Resideo will supply source, whether `mx3fb` can be made to drive the i.MX35 IPU (it was written and tested for the i.MX31, and no mainline board has ever instantiated it on an i.MX35), or anything about the ECP wire protocol above `/dev/spi`.

**Fire the GPL source request the same day.** It is cheaper still — free, zero risk, no physical access — but it is not an experiment, because the outcome is not under our control.

**The read-only fixture capture (§6) is the cheapest thing on this page** and should happen regardless, but it reduces uncertainty about the *API contract*, not about the kernel.

---

## Appendix A — claims that did not survive review

Recorded so they are not repeated. Overclaiming has cost this project real time before.

| Claim | Status | Correction |
|---|---|---|
| "The three kernel slots are not an A/B fallback; the bootloader unconditionally boots Kernel 1" | **REFUTED** | The retry loop is real and reachable. The search method (byte-searching for packed constants) could not find MOV immediates. |
| "`bootm <addr>` takes the ordinary path with NO fallback" | **REFUTED** | A numeric argument branches to the same loop head. Verified this pass. Creates a real silent-substitution trap at `0x80800000`. |
| "The bootloader iterates the slots, but only on CRC failure" (as a MEASURED finding) | **INFERRED → now MEASURED** | Reachability is now proven; the *trigger* is narrower than "CRC" — magic + header CRC only, **payload CRC is skipped** (§3.3, new this pass). |
| "Backporting pselect6/ppoll/epoll_pwait is cheaper than bumping" | **REFUTED** | ~200-line restructuring of `arch/arm` `signal.c` + `entry-common.S` + a second TIF flag, on a BSP tree we don't have, ending in the same NAND write. |
| "The entire vendor driver blob is ~9.4 KB in one contiguous region" | **REFUTED as a total** | Board-file and UniFi code measurably outside it; 9.4 KB is a floor. |
| "The full vendor ioctl surface is three magics, five requests" / "zero raw syscalls" | **INFERRED** | Measured on `/tuxedo`'s `.text` only; vendor Qt 4.8 QWS and tslib never scanned, and `libQtGui.so.4` is what holds `/dev/fb0`. |
| "Rebuilding 2.6.31 fixes netfilter and the RNGC" | **INFERRED** | Gated on the same source request and the same NAND write; a `.config` symbol does not prove the driver source is present or the block is wired. |
| "Serial console corrects the repo's observation-only note" | **INFERRED** | Not a correction; the repo already logged it `[UNKNOWN]`. Strings ≠ enabled console ≠ located pads. |
| "mc13783_ts drives the MC13892; touchscreen is not a blocker" | **INFERRED** | Driver binds `"mc13783-ts"`, subdevice is named `"mc13892-ts"`; does not bind on any path, including v5.9. |
| "Nothing in any mainline tree can drive this display" | **READ, softened** | The drivers exist in history through v6.5; resurrecting them is materially cheaper than writing from scratch — still gated on a DT binding that has never existed. |
| "No editable boot configuration without serial or reflashing mtd9-11" | **INFERRED** | Writing the env partition from Linux is a third path (the bootloader has `saveenv`/env-in-NAND and falls back to defaults on bad CRC). **But** it is only self-healing in the *botched* case; a well-formed env with a wrong `bootcmd` replaces a known-good default and is not. |
| "Zero risk: everything in step 2" | **INFERRED** | rw JFFS2 writes on mount; repeated power-cycling for the 1-second window is cumulative NAND exposure. Plus tamper and downtime. Mitigated by the P0 backup and the proven SD reflash path. |
| "Blocker: capture C4 requires one real arm and one real disarm" | **Over-priced** | Already performed 2026-09-06 and recorded; the residual gap is capturable read-only via `GetSecurityStatus`. |
| "`fake_panel` means the client parser was never proven against vendor bytes" | **REFUTED** | The decoder is regex-over-buffer and was written from the live capture. True narrow claim: no regression protection. |
| "`/handlerequest.html` returns zero bytes unconditionally" | **INFERRED** | Measured on valid sessions only; the cited pool is mixed and contains three response bodies. `Session_Expired` offset corrected `0x531843` → `0x53182c`. |
| "401 on bad password is free" | **INFERRED** | Free against the reference client only; visible to unenumerable third-party clients. |
| Panel ships OpenSSL 1.0.0 (task brief) | **Corrected** | 1.0.1h (TLS 1.2 capable). The pre-1.2 constraint is Barracuda's SharkSSL. |

## Appendix B — what remains genuinely unknown

- Whether `mx3fb` (as of v6.4) can drive the **i.MX35** IPU at all. Written and tested for the i.MX31; register usage never checked against the i.MX35 reference manual.
- Whether ProgCV writes **one kernel slot or all three**. Undeterminable on this unit; decisive for whether the SD path can ever be used for a kernel experiment.
- ProgCV's reflash gate. A full valid card left inserted does **not** reflash on every boot, yet a same-version `app2.hdr` **did** flash when its content changed. So it is neither "always" nor "skip on equal version". **Do not plan around "leave a good app1.hdr on the card and a bad kernel self-heals".**
- Whether the redundant U-Boot env format can be written correctly from Linux on this unit. Untested; no `fw_setenv`/`fw_printenv` in the rootfs.
- The **ECP wire protocol** between the SoC and the on-board MCU over CSPI1 — framing, the semantics of ioctls `0x7a01`/`0x7a02`, the role of `busint_irq` (IRQ 141, ~0.33/s) as a probable data-ready line, whether `MCU.hex` participates in timing. Only four functions in `/tuxedo` touch the fd, so the surface is small; nothing about the protocol is documented.
- NAND OOB was never read (no `nanddump`/`mtd_debug`, and 2.6.31 MTD sysfs has no `ecc_strength`). ECC byte positions and BBT signature match mainline `mxc_nand` **by geometry** — strengthened by the literal string `Bbt01tbB` found in mtd0. Worth closing read-only before any reflash work of any kind.
- Whether Resideo will honour a source request, and whether the listed `kernel-2.6.31-imx` v4.5.1 corresponds to this unit's 5.3.21.0.
- Whether any non-`ha-tuxedo-touch` client opens the push stream without a cookie. Unknowable — and it is the entire cost of the push-auth decision.
- `/dev/RF5800` appears as a string in `/tuxedo` but no such node exists, no kallsyms symbol matches, and nothing opens it. Unexplained.
- Whether U-Boot's `verify` gate (§3.3) behaves as I read it under a *set* env var — the stored raw pointer inverts stock semantics, so `setenv verify n` would likely *enable* checking. Not exercised.

---

**Bottom line:** the kernel is old, but it is not what is broken, and it is not what is in the way. Replace Barracuda with the static-musl/Rust stack that is already measured to work on 2.6.31, ship the v2 wire contract with its conformance suite, send Resideo a source request, and spend $3 on a serial adapter. If stage 2 then shows the drivers are unportable — which is what the evidence predicts — you will have settled the kernel question for the price of a cable and zero writes to a live alarm panel.