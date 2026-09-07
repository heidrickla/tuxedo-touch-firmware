# Tuxedo Touch firmware — reverse-engineering notes

Working notes toward building a custom image. **Nothing here has been written
to a device.** Everything is read from the official `TUXW_V5.3.21.0_CN`
package.

Status legend: **[CONFIRMED]** verified against the image or disassembly ·
**[LIKELY]** strong inference, not yet proven · **[UNKNOWN]** open question,
blocks repacking.

---

## 1. The update package

Downloaded from Alarm Grid's mirror as a plain ZIP (no `.exe` wrapper on this
one, despite the vendor docs describing a self-extractor).

| File | Size | Payload type | Header | Version stamp | Build date |
|---|---:|---|---:|---|---|
| `app1.hdr` | 2,145,572 | U-Boot legacy image | 128 B | `TUXEDO_V5.3.19` | Wed Sep 20 2017 |
| `app2.hdr` | 124,103,304 | JFFS2 (LE) | 128 B | `TUXEDO_V5.3.21.0` | Tue Mar 20 2018 |
| `app3.hdr` | 252 | JFFS2 (LE) | 128 B | `TUXW_V5.3.9.0` | Thu Oct 06 2016 |
| `ProgCV.hdr` | 468,790 | (opaque) | 128 B | `1.0.47CN` | Thu May 05 2016 |
| `seconboot.hdr` | 159,984 | (opaque) | 128 B | `5.3.9.0` | Thu Oct 06 2016 |
| `MCU.hex` | 26,740 | Intel HEX | — | — | — |

**[CONFIRMED]** The components are not the same vintage. A package labelled
5.3.21.0 ships a 2016 bootloader and a 2017 `app1`. Only `app2` carries the
5.3.21.0 stamp. Anything rebuilt needs to respect that these are versioned and
flashed independently.

---

## 2. The 128-byte header

**[CONFIRMED]** layout, from comparing all five headers:

```
+0x00   8   type magic, ASCII, NUL-padded:
            "appl000"  application images (app1/2/3)
            "prog000"  ProgCV
            "boot000"  seconboot
+0x08   4   payload length, little-endian, EXCLUDING the 128-byte header
+0x0C   4   [UNKNOWN]  app1 0x00220000  app2 0x00b20000
                       app3 0x0bf20000  ProgCV 0  seconboot 0x00120000
+0x10   4   [LIKELY] load/flash address. app1 & seconboot 0x87800000,
            app2 & ProgCV 0x80000000 (i.MX35 DRAM base), app3 0x03ae0000
+0x14   2   [UNKNOWN]  varies per file. Prime checksum candidate; see §3.
+0x16  ~26  build date, ASCII, NUL-terminated ("Wed Sep 20 13:40:35 2017")
+0x30  ~13  source filename ("app1.bin", "app2.jffs2", "ProgCV.bin")
+0x3D  ~17  version string ("TUXEDO_V5.3.21.0", "1.0.47CN")
+0x4E   4   component tag: "APP", "PRO", "BOO"
+0x52  ~14  board type: "TUXEDOPLUSVA"  (ProgCV uses "TFT")
+0x60  32   zero padding
```

**Length field verified on all five files.** `+0x08` equals
`filesize - 128` exactly, every time.

`TUXEDOPLUSVA` also appears in the `tuxedo` binary next to the format string
`Local ver-%s,boardType-%s`, so it is **[CONFIRMED]** a board-type gate, not
decoration. A custom image must carry the matching board type or be rejected.

---

## 3. Checksums — the blocker

**[CONFIRMED]** `RemoteUpgradeHelper::Verify_Checksum()` @ `0x0044a684` in
`tuxedo` implements a **standard CRC-32**. The inner loop disassembles to the
textbook reflected table-driven form:

```asm
mvn  r1, r8                    ; crc = ~0  (init 0xFFFFFFFF)
.loop:
  ldrb r3, [r0, r6]            ; next byte
  eor  r3, r1, r3
  and  r3, r3, #0xff
  ldr  r2, [ip, r3, lsl #2]    ; table[(crc ^ byte) & 0xff]
  eor  r1, r2, r1, lsr #8      ; crc = table[..] ^ (crc >> 8)
  bne  .loop
mvn  r8, r1                    ; final inversion
```

That is poly 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF — identical to
`zlib.crc32`. It reads the file in 0x500000 (5 MB) chunks.

**But that is the REMOTE upgrade path, and its expected CRC comes from an XML
manifest, not from the header.** Neighbouring strings confirm it:
`ParseProductXml`, `ParseRootXml`, XML fields `folderpath / version /
filenumber / platform / notes`, and `GET %s HTTP/1.1` with `Range: bytes=`.

**SUPERSEDED — see §13.** This field turned out NOT to be the gate; the check
that emits `SOURCE CHECKSUM ERROR` is a type-magic `strcmp`. The analysis below
is kept because the negative result is still useful. The 16-bit field at
`+0x14` is not any of: CRC-16 (CCITT/IBM/ANSI/DNP/T10DIF/CDMA, all four
reflect combinations, inits 0000/FFFF/1D0F/B2AA/C6C6/4C06, xorout 0000/FFFF),
byte sum, word sum LE or BE, XOR-16, or the high or low half of CRC-32 — over
the payload, over header-16 + payload, or over the whole file. Brute-forced
against `app3.hdr` (124-byte payload, so cheap to test exhaustively).

Either it is not a checksum, or it covers a range I have not guessed.

**Where to look next:** the `.hdr` magics (`appl000`, `prog000`, `boot000`) do
**not** appear anywhere in the `tuxedo` binary or the rootfs. So the code that
parses and validates these headers is **not in the application** — it is in
the bootloader. `seconboot.hdr`'s payload is the next target, and it is only
160 KB.

---

## 3a. ProgCV is the flash programmer — and it is where the gate lives

**[CONFIRMED]** `ProgCV` is not a data blob. It is a bare-metal ARM program:
the flasher that reads the `.hdr` files from the SD card and writes them to
flash. It contains the component filename table (`app1.bin`, `app2.jffs2`,
`seconboot.bin`, `Lang.bin`, `progvideo.bin`, `voice.bin`, `homepage.bin`,
`SEC_BOOT.bin`), the board tag `TUXEDOPLUSVA`, and a leftover build path:
`C:\Work\Code\progcv\trunk\PEG\SOURCE\pmessage.cpp`.

**[CONFIRMED] Load base is `0x80000000`**, determined by testing which base
makes literal-pool pointers resolve to known strings. It matches the `+0x10`
header field, which supports the [LIKELY] reading of that field as a load
address.

### What the flasher checks, in its own words

Extracted message set, which is effectively the validation spec:

```
Check HDR files
Critical file <name>.hdr is missing          (app1, app2, app3, seconboot,
                                              sec_boot, voice, Lang, homepage,
                                              progvideo, 6280, MCU.hex)
Critical file <name>.hdr type mismatch       (app2 has "mismatch 1"/"mismatch 2")
Hardware Version is New ,But Critical file app1.hdr is old type
Hardware Version is Old ,But Critical file app1.hdr is new type
 %s  SOURCE CHECKSUM ERROR!!!
SOURCE FILE ERROR!!!
ERROR,STOP UPDATE!!!
FLASH WRITE VERIFICATION / WRITE ERROR!!! ADDRESS %08x
FLASH ADDRESS 0x%x EMPTY!!! / ERASE FAILED...AT %x
```

Two things this settles:

- **There is a hardware-revision gate on `app1`**, independent of the board
  tag. An image accepted on one unit can be rejected on another.
- **`app2` is checked twice** ("type mismatch 1" and "2"), so it has two
  distinct validation steps, not one.

### The checksum check is a string comparison

**[CONFIRMED]** The call gating `SOURCE CHECKSUM ERROR!!!` is at
`0x80006b60`, targeting `0x8006a35c`. Disassembling `0x8006a35c` gives the
textbook word-at-a-time **`strcmp`**, not a checksum routine:

```asm
eor  r3, r1, r0        ; alignment test
tst  r3, #3
...
ldr  r2, [r0]  /  ldr r3, [r1]     ; 4 bytes at a time
cmp  r2, r3
subeq r3, r2, ip       ; ip = 0x01010101, the standard NUL-detect trick
biceq r3, r3, r2
tsteq r3, ip, lsl #7
...
subs r0, r2, r3
bx   lr
```

The caller does `mla r1, r2, r0, r1` first — indexing a table by element size
— then compares a stack buffer against that entry.

**So the value the flasher rejects on is compared as a STRING against a table,
not computed as an arithmetic checksum over the payload.** That is consistent
with every arithmetic checksum I brute-forced failing, and it means I have
been looking for the wrong kind of thing.

**[UNKNOWN]** What is in that stack buffer and what the table holds. Resolving
the two literal loads at `0x80006b50` and the table base is the next concrete
step, and it is a bounded task.

---

## 3b. app1 is a stock uImage — fully reproducible

**[CONFIRMED]** `app1.hdr`'s payload is a standard U-Boot legacy image, and
both of its CRCs verify exactly:

| Field | Value |
|---|---|
| magic | `0x27051956` |
| name | `Linux-2.6.31-207-g7286c01` |
| data size | 2,145,380 |
| load / entry | `0x80008000` / `0x80008000` |
| os / arch / type / comp | Linux / ARM / kernel / **uncompressed** |
| header CRC | `0xadacf724` — **verified** |
| data CRC | `0x41dbfd6e` — **verified** |

So the kernel is an ordinary uImage with ordinary CRC-32 protection. Rebuilding
it needs no reverse engineering at all: `mkimage` with these parameters
reproduces a valid one. The Honeywell `+0x14` field matches neither uImage CRC,
confirming they are unrelated mechanisms.

---

## 3c. Recovery — better than feared

**[CONFIRMED]** ProgCV's messages include `PRIMARY BOOT PROGRAMMING`,
`SECONDARY BOOT PROGRAMMING` and, crucially, **`USE JTAG PROGRAMMER`**. So
there is a primary bootloader distinct from `seconboot`, and the vendor's own
flasher contemplates JTAG recovery.

That materially changes the risk calculation: a bricked unit is likely
recoverable over JTAG rather than being scrap. It does **not** make flashing
safe — it means the recovery path should be located, wired and TESTED before
any write, not after.

`seconboot`'s payload is **[CONFIRMED]** a raw ARM U-Boot binary (U-Boot
string at `0x1f830`). It does **not** contain the `.hdr` magics, so it is not
the header parser; ProgCV is.


---

## 4. Platform

**[CONFIRMED]** Freescale i.MX35, ARM 32-bit LSB, EABI4, embedded Linux
2.6.31, JFFS2 root. Extracted rootfs: 3258 files.

| Binary | Size | Notes |
|---|---:|---|
| `tuxedo` | 14 MB | Qt application. **Not stripped** — 10,339 named functions. |
| `opt/webserver/Barracuda` | 5.6 MB | Barracuda web server, serves the local HTTP API. |
| `TotalConnect` | 172 KB | Cloud integration. |
| `SDCardStatus` | 6 KB | SD-card monitor. |

`tuxedo` being unstripped is the single most useful fact for this project.

**[CONFIRMED]** Flash writes go to `/dev/mtdblock%d` — a format string in
`tuxedo`. Partition numbering not yet mapped.

---

## 5. The web application

**[CONFIRMED]** The entire web UI is a ZIP appended to the `Barracuda`
executable: 776 entries, archive base `0x8a948`, EOCD at `0x4f00fd`. Standard
`zipfile` opens it once you slice from the base.

There are **no `.lsp` or `.lua` files** — the API is implemented in C++, not
scripted, so it cannot be modified by editing web assets. Changing API
behaviour means patching `Barracuda` itself.

`script/tuxapi.js` is the vendor's own API client and enumerates the complete
endpoint surface (40+). See `TUXEDO-FINDINGS.md` §API for the full list.

**[CONFIRMED] Two absences, established by enumeration rather than assumed:**
no version/model/firmware endpoint, and no status-refresh endpoint.

---

## 6. The status bug, in code

Documented fully in `TUXEDO-FINDINGS.md`. Summary of the code findings:

- **[CONFIRMED]** `Barracuda` contains the literal `Not available` and the
  endpoint names, but **no real status strings** (`Ready To Arm`, `Armed Stay`
  are absent). Real statuses arrive from `tuxedo` over IPC
  (`TuxedoAppCommThread`) into a cache. `Not available` is the compiled-in
  default for an empty cache.
- **[CONFIRMED]** `UpdatedSecurityStatus2Agent(SEcpMessage*)` @ `0x0059d024`
  is the only feeder. It takes an **ECP message**, reads byte 8, tests two
  bits, checks a per-partition latch byte, and posts via `osal_MqSend`
  (type 0xc, size 0x24). Edge-triggered and **deduplicated** — it will not
  re-send while the latch is set.
- **[CONFIRMED]** No code path produces a status without an ECP message.
- **[UNKNOWN]** Whether the cache has a TTL, and whether the latch causes
  some broadcasts not to refresh it. This matters: it would explain why the
  wake has looked capricious.

**Candidate fix for a custom image:** make `Barracuda` request status on
demand, or make `tuxedo` push periodically rather than only on edges. The
second is likely smaller — a timer already exists
(`CTimerThread::sigPnlStatusTimer`).

---

## 7. What blocks a custom build, in order

1. **The `+0x14` header field.** Until it is understood, no repacked image
   will be accepted. Next step: disassemble `seconboot`.
2. **[UNKNOWN] Whether anything is signed.** No signature has been found, but
   absence of evidence is not evidence of absence — the bootloader has not
   been read yet.
3. **[UNKNOWN] MTD partition map.** Which `mtdblock` each component targets.
4. **Recovery path.** Before writing anything, know how to recover a bricked
   unit. `seconboot` is a *secondary* bootloader, which implies a primary one
   that may offer recovery — unverified.

**Do not flash anything until 1 through 4 are answered.** This is a
wall-mounted alarm panel; a failed write is not a reboot away from fixed.

---

## 8. Tooling

- `fw_extract.py` — carves payloads out of the `.hdr` wrappers and hunts the
  header for integrity fields. Correctly identified all five headers as 128 B
  and located the JFFS2/uImage payloads.
- `jefferson` (pip) extracts the JFFS2. On Windows it needs `os.mknod`,
  `os.makedev`, `os.major`, `os.minor`, `os.mkfifo` and `os.lchown` stubbed —
  device nodes and symlinks become plain files, which is fine for reading.
- `pyelftools` + `capstone` for symbols and ARM disassembly. No Ghidra needed
  so far, precisely because the binary is unstripped.

---

## 9. Codes — what is in the firmware and what is not

Two different codes get conflated constantly; the firmware keeps them separate.

**Dealer code — Tuxedo-local. [CONFIRMED] default `4140`.**
`GetDealerCode(int, char*)` @ `0x005831b0` checks the stored code's length and,
if it is not 4 digits, calls `SetDealerCode()` with a literal resolved from the
pool at `0x005831fc` to `.rodata` `0x005cc6a8` = **`"4140"`**.

This is the code gating the Tuxedo's own setup screens. It is stored on the
Tuxedo, not the panel, and there is a supported recovery path: the UI strings
`Forgot dealer code confirmation` and `Pressing YES will reset the dealer code
to default code` belong to `CMailSetup::sltDealerForgotClicked()` @ `0x00387b20`.
So a forgotten dealer code is resettable from the touchscreen without knowing
the current one.

**Installer code — the VISTA panel's, not the Tuxedo's. [CONFIRMED] NOT in the
firmware.**
`GetInstallerCode()` @ `0x00596a60` returns a pointer at offset `+0x52` into a
runtime object, and falls back to the literal at `0x005d9460` = **`"0000"`**
when that object is null. `0000` is an unset placeholder, not a working code.

The real installer code lives in the VISTA panel's EEPROM. The Tuxedo obtains
it at runtime — hence `Apl_GetInstallerCode`, `HandleInstallerCode`,
`myPanel::SetInstallerCode`, and the strings `Installer Code Received`,
`Invalid installer code`, `Panel Did Not Respond, Installer Code Required`.

**WRONG — CORRECTED BELOW. The installer code IS persisted.**

The claim in this section was based on tracing `SetInstallerCode` alone and
finding no file write in it. That was too narrow a search: a *different*
function writes it. See §17. The original reasoning is left below because the
observation about `SetInstallerCode` itself is accurate — it was the conclusion
drawn from it that was wrong.

**[SUPERSEDED] The installer code is NOT persisted.**
`myPanel::SetInstallerCode(unsigned char*)` @ `0x00594bd4` writes only to
`[r6, #0x52]` — a field in a live object — and every branch (`strbeq`,
`strbgt`, the final `strb`) targets that same in-memory offset. There is no
file write. The code is held in RAM after the panel supplies it and is lost on
reboot.

So it cannot be recovered from the update package **or** from a flash dump. It
exists only in the VISTA panel's EEPROM and transiently in the Tuxedo's RAM.

### Where the Tuxedo does keep state

Config lives in `/opt/tuxedo/configuration/`, and nearly every file has a
`_sec` twin (a second copy). Ones worth knowing about if the unit is ever
dumped:

```
panelinfo.txt / panelinfo_sec.txt          panel data
webuseraccounts.json                       local web UI accounts
webuseraccountsenc.json                    the encrypted form
userdetails.json / useraccountsetup.txt    user records
SystemConfig.txt                           system settings
ZwPrNetKey / ZwScNetKey                    Z-Wave network keys
wpa.conf / wificonfig.conf                 Wi-Fi credentials
thermostats/honeywell/username|password    third-party creds, plaintext paths
```

`/mnt/sd/DealerMailConf.txt` is on the SD card, not internal flash.

---

## 10. The kernel, the partition map, and a much better recovery path

**[CONFIRMED]** `app1`'s uImage payload is a self-decompressing zImage. The
real kernel is a gzip stream at offset `0x3354` inside it, inflating to
4,381,056 bytes. (The uImage header says `comp=0` because the zImage handles
its own decompression — do not read that as "uncompressed kernel".)

```
Linux version 2.6.31-207-g7286c01 (root@optgw2) (gcc 4.1.2) #1094 PREEMPT
Tue Sep 19 11:53:48 UTC 2017
```

### The boot command line — [CONFIRMED], read from the decompressed kernel

```
noinitrd console=ttymxc0,115200 root=/dev/mtdblock8 rw rootfstype=jffs2 ip=off
```

Three things fall out of that one line:

**`root=/dev/mtdblock8`.** The JFFS2 root filesystem — i.e. `app2` — lives on
**mtdblock8**. That is one of the two gates on custom firmware, partly answered:
we now know the rootfs target, though not yet the full partition table.

**`console=ttymxc0,115200`.** There is a **serial console** on the i.MX35's
UART0 at 115200 baud. Finding those pads should come before any flash write.

**Corrected in §16:** this gives boot and kernel OUTPUT only on stock firmware.
There is no login shell — the console `inittab` entry is commented out and the
image ships no `/etc/passwd`. It is a diagnostic channel, not yet a control one.

**NAND, not NOR.** The kernel carries the MXC NAND driver, `nand_bbt` bad-block
handling, and `JFFS2 version 2.2. (NAND) (SUMMARY)`. Bad-block management
matters for any hand-built image: a naive block write that ignores the BBT can
corrupt the filesystem.

**[UNKNOWN] The full partition table — searched for, not found.** There is no
`mtdparts=` on the command line, so partitions come from the board file
compiled into the kernel rather than from boot arguments.

I looked for the static `mtd_partition` array and did not find it. What was
tried, so the next attempt does not repeat it:

- The decompressed kernel links at **`0xC0008000`**, not the `0x80008000`
  physical load address. Verified: with `0xC0008000`, 32-bit words in the image
  dereference to real NUL-terminated strings; with `0x80008000` they do not.
  Any future pointer-chasing in `vmlinux.bin` must use the virtual base.
- Scanned for arrays of string pointers at strides 20, 24, 32, 40 and 48 under
  both bases. Stride 32 under `0xC0008000` yields thousands of hits, but they
  are kernel tracepoint name tables, not partitions.
- Filtered those candidates on flash geometry — every entry erase-block
  aligned (0x20000), size under 1 GiB, and offsets forming a contiguous
  non-overlapping run. **Zero survived.**

So either the partitions are assembled at runtime rather than declared as a
static contiguous array, or the struct layout differs from the assumed
`{char *name; u64 size; u64 offset; u32 mask_flags; void *ecclayout;}`.

Two better routes than more scanning: read `/proc/mtd` on the running unit over
the serial console, or disassemble the board-init code that calls
`mtd_device_register` / `add_mtd_partitions`.

What IS known: **`root=/dev/mtdblock8`**, so the JFFS2 rootfs is partition 8,
and there are therefore at least nine partitions.

### Revised recovery assessment

Earlier I recorded JTAG as the recovery path, from ProgCV's `USE JTAG
PROGRAMMER` string. The serial console is better news: cheaper, non-invasive,
and useful for debugging a custom image rather than only for rescuing a dead
one. **Locate and test the UART before writing anything.**

---

## 11. MCU.hex — there is a second processor, and it is an AVR

The one component in the update package nobody had opened. **[CONFIRMED]**
findings:

`MCU.hex` is Intel HEX, 596 records, decoding to **9,496 bytes** spanning
`0x000000`–`0x002517` with no gaps to speak of (19 bytes of `0xFF`).

**It is an Atmel AVR, not ARM and not 8051.** The image opens with the byte
pattern `0c 94 xx xx` repeated — `0x940C` is the AVR `JMP` opcode, and a
contiguous run of 4-byte `JMP` entries is the classic AVR interrupt vector
table. (Cortex-M was ruled out: word 0 is not a plausible stack pointer. 8051
was ruled out: byte 0 is not `LJMP`.)

| | |
|---|---|
| Vector table | 31 vectors, 124 bytes |
| Reset vector | jumps to word `0x003e` (byte `0x007c`) |
| Interrupts actually used | **4** — vectors 1, 11, 15, 18 |
| All other vectors | point at one shared default/bad-interrupt handler at word `0x005b` |
| Flash | at least 9.3 KiB; `JMP`-based vectors mean the part has **more than 8 KiB** (an 8 KiB AVR would use 2-byte `RJMP`) |

**[UNKNOWN]** The exact part. 31 vectors does not match the common families I
checked (ATmega8 has 21, ATmega16/32 have 26, ATmega48/88/168/328 have 23,
ATmega640/1280/2560 have 43+). Identifying it needs either the board silkscreen
or a datasheet-driven match on the peripheral registers the code touches.

**[LIKELY] What it is for.** Only four interrupts are live, and the rest are
stubbed to a common handler — the profile of a small dedicated peripheral
controller rather than a general-purpose co-processor. Given the Tuxedo's job,
the most plausible role is the **ECP bus interface**: ECP is a timing-critical
two-wire protocol, exactly the kind of work offloaded to a small MCU so the
Linux side does not have to meet hard real-time deadlines. Power/battery
management is the other candidate. **Not confirmed — this is inference from the
interrupt profile, not from decoded logic.**

**Why it matters for a custom build.** `MCU.hex` is listed among the flasher's
critical files (`Critical file MCU.hex is missing`), so it is part of the update
set and presumably reflashed alongside everything else. If it does own the ECP
timing, then the panel-communication behaviour this project has been chasing is
partly implemented *here*, not in the Linux application — and 9.3 KiB of AVR is
a far smaller reversing target than 14 MB of ARM.

That makes it a high-value future target despite its size.

---

## 12. OTA — it already exists, and it is self-hostable

The goal of "add OTA to a custom build" may not need building anything. The
stock firmware ships a **complete OTA client**, `RemoteUpgradeHelper`. All
**[CONFIRMED]** from strings and symbols in `tuxedo`.

### The update servers

```
download.tuxconnect.info
download1.tuxconnect.info
download2.tuxconnect.info
108.170.102.190                (a hardcoded IP present in the binary)
GET /php/getpath.php?mac=<MAC>
```

DNS resolution goes through a helper binary, `/dnshelper`. The client keys its
request on the unit's **MAC address**.

### The flow

1. A query timer fires — normal cadence **2 hours**, backing off to 10 minutes
   after a DNS error (`sigQueryTimer`, `sltGetRootXml`).
2. Fetch the **root XML**, then the **product XML**.
3. Compare `local_ver` against `ver_remote` **and** check `boardType`
   (`Local ver-%s,boardType-%s` — the `TUXEDOPLUSVA` gate again).
4. Download the component files, with HTTP **range requests**
   (`Range:bytes=%d-%d`), **to the SD card** — `/mnt/sd/%s`.
5. Back up the existing flasher: `mv /mnt/sd/ProgCV.hdr /mnt/sd/ProgCV_bkp.hdr`.
6. **Verify the checksum.** Failure gives `Firmware Download Failed checksum
   verification fail.`
7. Prompt, then `The system will reboot in 15 seconds to upgrade the unit.`

### The manifest fields

```
product   filepath   folderpath   version   filenumber
platform  notes      size         checksum  next
```

### THE KEY STRUCTURAL FACT

**OTA is not a separate flashing mechanism. It is an automated fetch onto the SD
card, followed by a reboot into the ordinary SD-card flash path.** The many
`SD not present` / `SD size less than 200MB` / `SD write protected` strings
confirm the SD card is mandatory. `ProgCV` still does the actual writing.

Two consequences:

- A custom image delivered by OTA must still satisfy **exactly the same header
  and validation** as one delivered by hand on an SD card. OTA does not sidestep
  the unsolved `+0x14` header field.
- Conversely, once SD-card flashing works, **OTA works too, for free**. There is
  nothing extra to build.

### Self-hosting looks feasible

**The integrity check is a CRC-32 carried in the manifest. No signature has been
found** — `Verify_Checksum()` @`0x0044a684` is a plain table-driven CRC-32
(poly `0xEDB88320`, init and final-xor `0xFFFFFFFF`), and the expected value
comes from the XML `checksum` field, which the same server supplies. A CRC
detects corruption; it does not authenticate an author. So a server the device
trusts can serve any image that satisfies the header checks.

The device finds that server **by DNS name**, and Lewis controls his own DNS.
This repo already contains `dnsproxy.py`, written for exactly this kind of
redirection. Standing up a local update server therefore looks like the natural
OTA path for a custom build:

1. Point `download.tuxconnect.info` at a local host via DNS.
2. Serve `/php/getpath.php?mac=<MAC>`, then the root and product XML.
3. Advertise a version that compares greater than `TUXW_V5.3.21.0`, with
   `boardType` = `TUXEDOPLUSVA`.
4. Serve the component files with correct `size` and CRC-32 `checksum`, and
   support **HTTP range requests**.

**[UNKNOWN] and worth checking before relying on this:**

- ~~The hardcoded IP as an OTA fallback.~~ **RESOLVED — it is not one.**
  Cross-referencing every literal pointer to that string shows it belongs to a
  different subsystem entirely:

  | Reference site | Function |
  |---|---|
  | `.rodata` `0x00602328` | `get_data(const char*, const char*, char*, unsigned)` — generic HTTP fetch helper |
  | `.data` `0x00d0bfdc` | `writeSrvIptoFile()`, `readSrvIpFromFile()`, `IPCPeriodicUpload(int)` |
  | `.data` `0x00d0c034` | `writeEulaSrvIptoFile()`, `readEulaSrvIpFromFile()`, `EulaIPCPeriodicUpload()` |

  Those are the **data-collection and EULA upload** servers, not firmware
  download. Note both live in **`.data`, not `.rodata`** — they are mutable
  defaults, read from and written back to a file, so the effective address is
  configurable at runtime rather than fixed in the image.

  Meanwhile `get_server_ip(const char*, char*, int)` invokes `/dnshelper`, so
  the OTA hostnames are resolved **by DNS**. **DNS redirection should therefore
  be sufficient to repoint updates**, which is the conclusion this section
  needed.
- Whether the transport is plain HTTP (the format strings suggest `GET ... HTTP/1.1`
  over a raw socket, so probably yes) or TLS.
- The exact root/product XML schema. The field names are known; the element
  nesting is not.

### Incidental finding: the panel phones home on a timer

`IPCPeriodicUpload(int)` and `EulaIPCPeriodicUpload()` do periodic outbound
uploads to those two servers, and there is a `DATACOLLECTIP_CRC` entry plus
`/opt/tuxedo/Log/TuxDatacollect.json` and `datacollect.txt` in the config set.
So the unit performs **periodic telemetry uploads** independent of the update
check. **[CONFIRMED]** that the mechanism exists; **[UNKNOWN]** what it sends.

Since both server addresses are read from a file rather than fixed in the
binary, this is likely disablable or redirectable without patching anything.

### Risk note

This is the owner's own hardware, and self-hosting updates for a device whose
vendor has effectively abandoned it is a reasonable thing to do. But the same
property that makes it possible — **CRC without a signature** — is also a
genuine weakness in the stock product: anything that can win the DNS race can
serve firmware to this panel. Worth knowing, and worth firewalling the panel's
outbound access if it is not going to be updated by the vendor anyway.

---

## 13. BREAKTHROUGH: the "SOURCE CHECKSUM ERROR" gate is not a checksum

The blocker recorded in §3 — an unidentified 16-bit field at `+0x14` assumed to
be a payload checksum — was **the wrong target**. Tracing the code that actually
produces `SOURCE CHECKSUM ERROR!!!` settles it. **[CONFIRMED]** by disassembly.

The sequence immediately before the failing call, at `0x80006b0c`–`0x80006b60`
in `ProgCV`:

```
mov  r2, #0x80              ; 128
ldr  r1, [<header ptr>]     ; the .hdr's 128-byte header
ldr  r0, [<dest>]
bl   memcpy                 ; stash the whole header

mov  r2, #7                 ; SEVEN bytes
ldr  r1, [<header ptr>]     ; from header offset 0
add  r0, sp, #0xc
bl   memcpy                 ; copy header[0..6] to a stack buffer
mov  r1, #0
strb r1, [sp, #0x13]        ; NUL-terminate it -> a 7-char C string

ldrb r0, [<component index>]
mov  r2, #8                 ; stride 8
ldr  r1, [<table base>]
mla  r1, r2, r0, r1         ; entry = table + 8 * component_index
add  r0, sp, #0xc
bl   strcmp                 ; <-- the call whose result gates the error
```

**It compares the first seven characters of the header against a table of
expected values, indexed by component slot.** The first eight header bytes are
the type magic — `appl000`, `prog000`, `boot000`. So the gate is a **type-magic
string check**, and the error message is simply misnamed.

### What this means for a custom build

The thing that looked like an unsolved cryptographic-ish obstacle is a
seven-character string comparison, and the correct values are already known from
the stock images. **It is trivially satisfiable.**

Combined with what §3a established, the SD-card validation appears to be:

| Check | Nature | Satisfiable? |
|---|---|---|
| File present | `Critical file <name>.hdr is missing` | yes |
| Type magic | `strcmp(header[0..6], table[slot])` | **yes — this section** |
| Board type | `TUXEDOPLUSVA` string in the header | yes, copy it |
| Hardware revision | `app1.hdr is old type` / `is new type` | yes, match the stock image |
| Flash write | `FLASH WRITE VERIFICATION` — read-back after write | automatic |

**[UNKNOWN] — and this is the honest remaining caveat.** The `+0x14` field is
still unexplained. What has been shown is that it is **not** what the
`SOURCE CHECKSUM ERROR` path tests. Whether some *other* code path validates a
payload checksum has not been ruled out — `Check HDR files` and the per-component
`type mismatch 1` / `mismatch 2` messages suggest more than one check exists, and
only this one has been traced to its comparison.

So: **do not read this as "there is no integrity check".** Read it as "the check
that produces the scary message is a string comparison, and the field I was
brute-forcing was a red herring". That is a large step forward and it removes
the gate that was blocking the whole custom-firmware track.

### Revised blocker list

1. ~~The `+0x14` header field.~~ Not the gate. Downgraded to a curiosity.
2. ~~Confirm no other payload checksum exists.~~ **Largely done — see below.**
3. **The MTD partition map** — still unknown; §10 records what was tried.
4. **Recovery** — serial console at 115200 on ttymxc0, plus JTAG. Locate and
   test the UART *before* writing anything.

### Blocker 2 followed up: the other checks are string tests too

Tracing the remaining validation messages to their comparisons. **[CONFIRMED]**
by disassembly.

**`app2.hdr type mismatch 1` and `2`** (`0x800031dc`, `0x800031e4`) are both
gated by a small helper at `0x80003194`–`0x800031d0` that does nothing but
compare three header bytes:

```
ldrb r0, [hdr]      ; cmp #0x63  'c'
ldrb r0, [hdr, #1]  ; cmp #0x61  'a'
ldrb r0, [hdr, #2]  ; cmp #0x6c  'l'
-> returns 1 on match, 0 otherwise
```

A three-character prefix test. Not a checksum.

**The hardware-revision gate** (`Hardware Version is New/Old ,But ... app1.hdr
is old/new type`, around `0x80003064`–`0x800030a8`) compares a single stored
byte against the constants **6** and **7** and dispatches accordingly. A
revision-number equality test. Not a checksum.

### Where that leaves it

Three validation paths traced, and **every one is a byte or string comparison
against a constant**. No payload checksum has been found anywhere in the
SD-card flashing path.

**Stated carefully:** this is strong evidence, not exhaustive proof. I traced
the checks that produce error messages; a silent check that fails without a
message would not have been caught this way. But the flasher is chatty — it has
a distinct message for essentially every failure mode — so a silent one would be
out of character.

**Practical conclusion:** the SD-card update path validates *identity*
(is this the right kind of file, for the right board, for the right hardware
revision) and then verifies the *write* by read-back. It does **not**
cryptographically or arithmetically validate the payload it is given. For
someone building firmware for hardware they own, that removes the obstacle that
looked most likely to be fatal.

---

## 14. SAFETY: which write bricks the unit, and which does not

While looking for the flash address table I found the brick path instead, at
`0x80008b00`–`0x80008ba8` in `ProgCV`. **[CONFIRMED]** — the message sequence it
assembles, in order:

```
INCOMPLETE...THE CHIP CANNOT BE
REPROGRAMMED USING MMC ANYMORE...
ORIGINAL BOOTLOADER IS CORRUPTED...
USE JTAG PROGRAMMER
```

After printing these the code returns. **It does not reset, halt, or write
anything** — see the correction below, which supersedes an earlier reading.

### CORRECTION (traced 2026-09-05): this message is printed when the file is MISSING

I previously recorded that this block "calls a reset/halt routine and stops",
and treated it as evidence that a bootloader write had gone wrong. That was a
misreading, made from the strings and their addresses without following the
branches. The control flow says something quite different, and it is good news.

Taking the MCU programmer at `0x80008804` as the worked example (the primary
boot programmer at `0x80008284` has the identical shape):

```
8000891c  bl   0x80064a38          ; open "MCU.hex" from the SD card
80008928  cmp  sl, #0
8000892c  beq  0x80008948          ; 0 = opened
80008938  strb #0 -> 0x83f1eca3    ; NOT FOUND
80008948  strb #1 -> 0x83f1eca3    ; FOUND
...
80008a18  ldrb r0, [0x83f1eca3]
80008a20  cmp  r0, #0
80008a24  beq  0x80008af0          ; <-- file missing jumps INTO the JTAG text
80008a28  ...  " PROGRAMMING" / "START..." / bl 0x8005815c / "COMPLETE..."
80008aec  b    0x80008b88          ; success path joins the exit
80008af0  ...  "INCOMPLETE..." / "USE JTAG PROGRAMMER"
80008b88  <shared epilogue>  pop {r4-r8, sb, sl, pc}
```

The alarming four-line banner sits on the **file-not-found** branch and falls
straight through to the same epilogue the success path uses. Nothing was
erased and nothing was written when it appears. It is a badly worded status
message, not a report of damage.

### The primary bootloader programmer is unreachable on this build

`0x80008284` ("PRIMARY BOOT PROGRAMMING") has exactly one caller, at
`0x80003778`, reached only when a mode byte equals 7:

```
8000376c  cmp  r6, #7
80003770  bne  0x80003780
80003778  bl   0x80008284          ; PRIMARY BOOT PROGRAMMING
```

`r6` is assigned once, at `0x800034f4`, from a call to `0x80002718`, and is
never reassigned afterwards (only zero-extended). That function is a stub whose
real body has been compiled out:

```
80002718  mov  r1, #0
8000271c  movs r0, r1               ; dead - overwritten on the next line
80002720  mov  r1, #2
80002724  movs r0, r1               ; r0 = 2, unconditionally
80002728  uxtb r0, r0
8000272c  bx   lr
```

So on `ProgCV` **1.0.47CN** the mode is always 2, the `cmp r6, #7` never
matches, and **primary boot programming is dead code**. It cannot run.

### Every component write is gated on its own file being present

This is the finding that actually governs the risk. Before each component is
programmed, `0x800072e4` resolves that component's filename, tries to open it
from the card, and sets `0x83f1eca3` to 1 only when the open succeeds
(`0x800073fc`); every failure path stores 0. The programmer then refuses:

| Programmer | Gate | Where a missing file goes |
|---|---|---|
| generic component `0x80007cac` | `0x80007df0` `cmp #1 / bne` | `0x80008208` = epilogue |
| primary boot `0x80008284` | `0x800084bc` `cmp #0 / beq` | `0x800087a0` = epilogue |
| MCU `0x80008804` | `0x80008a18` `cmp #0 / beq` | banner, then epilogue |

**Consequence: a component whose file is absent from the SD card is not erased
and not written.** The card's contents determine what gets touched. A card
carrying only the rootfs cannot cause a bootloader write, because the bootloader
write is downstream of a successful open of a file that is not there.

The `Critical file <x>.hdr is missing` validator behaves the same way — it
clears its return flag and keeps checking. Its effect is to refuse the upgrade,
not to perform a partial one.

### What this establishes

**Writing the bootloader is the one operation that can permanently remove the
SD-card recovery path.** If bootloader programming is interrupted, the unit can
no longer be reprogrammed from MMC/SD at all, and JTAG becomes the only way
back. The firmware says so in its own words.

By implication, the other components are **not** in that category — the
catastrophic message is specific to the bootloader being corrupted.

### The operating rule for any custom-firmware work

| Component | Write it? | Why |
|---|---|---|
| `app1` (kernel), `app2` (rootfs), `app3` | **Yes** | A bad write is recoverable by re-flashing from SD |
| `ProgCV` (the flasher) | **Avoid** | It is what performs recovery; note the stock updater backs it up first, as `ProgCV_bkp.hdr` |
| `seconboot` / primary boot | **DO NOT** | This is the path that produces the message above |

A custom build that changes only the kernel and root filesystem keeps SD-card
recovery intact throughout. That covers everything this project actually wants
to change — the status-cache behaviour, the web API, the application — none of
which lives in the bootloader.

**This is the single most important safety fact found so far, and it should
govern the whole approach:** stay out of `seconboot`, and a mistake costs a
re-flash rather than a wall-mounted brick.

**And the rule is enforceable mechanically, not just by discipline.** Because
each write is gated on its own file opening from the card, "stay out of
`seconboot`" reduces to "do not put a `seconboot` file on the card". The
flasher will skip it. The safe card for this project's purposes therefore
contains the rootfs and nothing else that is writable.

The two ways this could still be wrong, and neither is currently supported by
anything I have read:

1. A component could be written from a source other than the card — an
   embedded copy, or a file already in flash. Every write path traced so far
   opens from `/mnt/sd`-backed handles set up by `0x800623b0` ("PROG MMC DISK").
2. A partially-written card could leave a component file present but truncated.
   That is a real risk and it is what the `.hdr` checksum check exists for;
   verify the card after writing it, before booting the panel with it.

### Still not found

The per-component flash address table. The region around the "PROGRAMMING
APPLICATION n" strings turned out to be error-reporting rather than the address
setup, and the addresses themselves sit behind literal loads into a data region
(`0x83f1xxxx`) that is **outside the ProgCV image** — i.e. RAM populated at
runtime, not constants in the file. That is why static resolution keeps coming
up empty, and it is the same reason the kernel scan failed in §10.

Reading `/proc/mtd` over the serial console remains the cheap answer.

---

## 15. Making the OTA server configurable — no binary patching needed

The obvious approach is to patch the hostname strings in `.rodata`. **There is a
much better one**, and the evidence for it is conclusive.

### The resolution chain, established end to end **[CONFIRMED]**

`/dnshelper` is a tiny ARM ELF whose entire set of imported symbols is:

```
getaddrinfo   freeaddrinfo   inet_ntop   puts   abort   __libc_start_main
```

That is a thin wrapper around **`getaddrinfo`** — the glibc resolver. It does no
raw DNS of its own (no `socket`, `sendto`, `recvfrom`, or `res_*` imports).

Because it goes through glibc, it obeys the image's own resolver configuration:

| File | Content | Effect |
|---|---|---|
| `/etc/nsswitch.conf` | `hosts: files nisplus nis dns` | **`files` is consulted BEFORE `dns`** |
| `/etc/host.conf` | `order hosts,bind` | same conclusion, stated twice |
| `/etc/hosts` | present, already populated | the file that wins |

### The consequence

**A single line in `/etc/hosts` redirects OTA.** No binary patching, no string
length constraints, no relocation. It is already a configuration file, already
consulted first, and already in the writable root filesystem.

```
203.0.113.x   download.tuxconnect.info
203.0.113.x   download1.tuxconnect.info
203.0.113.x   download2.tuxconnect.info
```

### It may not even need custom firmware

The kernel command line mounts the root filesystem **read-write**:

```
root=/dev/mtdblock8 rw rootfstype=jffs2
```

So `/etc/hosts` is editable **on a running unit** — *if you have a shell*.

**Corrected in §16:** stock firmware provides no serial login shell, so this is
not reachable out of the box. It becomes a text edit only after a shell exists,
via a U-Boot prompt or a custom rootfs. The `/etc/hosts` mechanism itself is
still the right design; the "no flashing needed" claim was wrong.

### If you do build custom firmware, do it properly

Shipping `/etc/hosts` pre-pointed is the minimum. A tidier design, still with no
binary patching:

- Keep the vendor hostnames intact so the stock code path is untouched.
- Ship a small config file (say `/opt/tuxedo/configuration/ota_server.conf`) and
  an init script that rewrites the `/etc/hosts` lines from it at boot.
- That gives a real, documented, user-editable setting, and it degrades safely:
  if the config is missing or malformed, leave `/etc/hosts` alone and the unit
  behaves exactly like stock.

The vendor already uses this pattern elsewhere — the data-collection and EULA
server addresses are read from a file via `readSrvIpFromFile()`, not baked in
(§12). So a file-backed server address is consistent with the existing design
rather than a foreign concept.

### Incidental: a stale entry ships in `/etc/hosts`

The stock file contains a **public IP** mapped to a Tuxedo-style hostname,
alongside several `gateway0`–`gateway4` entries on a `192.168.0.x` range. These
look like leftovers from the vendor's build or test environment rather than
anything functional. Harmless, but worth removing in a custom image — an
unexpected public IP in a resolver file on an alarm panel is not something to
leave in place unexamined.

---

## 16. CORRECTION: the serial console does NOT give you a shell on stock firmware

I claimed earlier that the serial console beats JTAG as a recovery path, and
then that `/etc/hosts` could be edited on a running stock unit "with shell
access over the serial console". **Both of those overstated it.** Checking the
init configuration settles it. **[CONFIRMED]**

### What the image actually contains

`/etc/inittab`:

```
id:3:initdefault:                      <- default runlevel is 3
l1:1:respawn:/bin/sh -i                <- a shell, but only at runlevel 1
#co:2345:respawn:/bin/sh -i            <- the console shell is COMMENTED OUT
```

`/etc/passwd` and `/etc/shadow` are **both absent from the image entirely**.
`/etc/securetty` does list `ttymxc0`, but nothing spawns a login on it.

### What that means

At the default runlevel the serial port gives you **kernel and boot output
only**. There is no getty, no login prompt, and no shell. Useful for watching a
boot and diagnosing a failure — genuinely valuable — but you cannot type
commands at it.

So, corrected:

| Earlier claim | Reality |
|---|---|
| "Serial console is a better recovery path than JTAG" | Only for *observing*. It cannot run a recovery command. |
| "Edit `/etc/hosts` on a running stock unit over serial" | **Not possible** — no shell to edit with. |
| "Read `/proc/mtd` over the serial console" | **Not possible** on stock firmware, for the same reason. |

That last one matters: I recommended it twice as the cheap way to recover the
partition map. It is not available without first getting a shell.

### The bootstrapping problem, and the way out

Getting a shell needs `inittab` changed, which needs a modified rootfs flashed,
which is the very thing the shell was meant to assist. Circular.

The way out is the **bootloader**, not Linux. `seconboot` is U-Boot
(confirmed in §10 — the U-Boot string is present in its payload). U-Boot
conventionally offers its own prompt on the serial console during a short window
at power-up, and from that prompt the kernel command line can be changed. Adding
`init=/bin/sh` or booting to `single` yields a shell without modifying anything
on flash.

**[UNKNOWN]** whether this unit's U-Boot has an interactive prompt enabled and
what, if anything, interrupts autoboot. That is the next thing to establish, and
it is answerable simply by attaching to the serial port and watching a
power-up — no writes, no risk.

### One thing worth noting about the shell that is not enabled

Both `inittab` shell entries invoke `/bin/sh -i` **directly**, not through
`login` or `getty`. With no `/etc/passwd` or `/etc/shadow` present, this means
that if either entry were active, the result would be an **unauthenticated root
shell** on the serial port.

For a custom build that is convenient. For the stock product it is the reason
those lines are commented out, and it is worth understanding before enabling
them on a device mounted on a wall — anyone with physical access and three wires
would have root.

### Revised recovery assessment

`USE JTAG PROGRAMMER` (§3c) remains the documented recovery path for a corrupted
bootloader. The serial console is a **diagnostic** channel on stock firmware and
becomes a control channel only if either U-Boot offers a prompt, or a custom
rootfs enables the console shell.

**Establish which, by watching a boot, before relying on either.**

---

## 17. CORRECTION: the installer code IS written to disk, on an unauthenticated path

Two of my earlier conclusions were wrong. Both were overturned by the
multi-agent audit and then re-verified independently here.

### The installer code is written to a file

`CreatePnlInfoFlashTable()` @`0x0058f0a8` builds `/tmp/panelinfo.txt` and it
calls **`GetInstallerCode`** while doing so. Verified independently by decoding
every `BL` in that function; among its 43 named callees are:

```
GetInstallerCode          GetPanelModel           GetPanelSoftwareVersion
GetTotalPartitions        GetPartitionDescription GetPartitionNo
GetTotalZones             GetZoneNumber           GetZoneDescription
GetZoneTypeByZnIndex      GetZoneDeviceType       GetHomePartition
GetPartitionFirePanic     GetPartitionPanicPanic  GetPartitionMedicalPanic
GetHiRFZoneNumber         GetLoRFZoneNumber       GetAuthLevelToEditSlotnRFZone
```

The file is then copied to `/opt/tuxedo/configuration/panelinfo.txt` (and the
`_sec` twin), CRC-checked, with retries.

**Why §9 got it wrong:** I traced `myPanel::SetInstallerCode` and correctly
observed that it only writes to an in-memory field. I then concluded the value
is never persisted. That does not follow — a different function reads it back
out of memory and writes it to a file. **Tracing one writer is not the same as
establishing there are no writers.** The lesson generalises: to claim a negative
about persistence, enumerate readers of the value, not writers of one setter.

### And that directory is served over HTTP without authentication

The audit traced the chain by disassembly: a virtual directory is installed with
`DiskIo_setRootDir(..., "/opt/tuxedo/configuration/")` and registered under the
URL name `Config`, with the authenticator and realm arguments both zero.
`HttpDir_authenticateAndAuthorize` @`0x0006b544` reads those two fields and,
when both are null, returns 1 — which the caller treats as "serve".

So `panelinfo.txt` — containing the **installer code in plaintext**, the panel
model, the software version and the RF zone range — is reachable by an
unauthenticated HTTP GET from anywhere that can reach the panel.

**[CONFIRMED]** statically, end to end. **[UNTESTED]** live: one request against
a real unit settles it, and that request is harmless (a GET of a text file).

### Related exposures from the same audit

- `SimpleDebugger.interface` is installed with no authenticator and its service
  routine never calls the authorisation function at all — it is not merely
  unconfigured, it is off the auth path.
- An **empty `authtoken` header** appears to short-circuit the HMAC comparison
  in the REST API, branching past the entire MACID/HMAC build.

### Practical consequence for the owner

The panel hands out its own installer code to any device on the network. That is
useful — it answers the "can we recover the installer code" question with a yes,
and it does so without touching panel programming. It is also a reason to keep
this device off any untrusted network segment, which reinforces the firewall
advice in §12.
