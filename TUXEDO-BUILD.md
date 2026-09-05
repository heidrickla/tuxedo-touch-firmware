# Building custom Tuxedo Touch firmware

How to take the stock `TUXW_V5.3.21.0_VA` firmware apart, change something in
the root filesystem, put it back together, and prove the result is correct
before it goes anywhere near the panel.

Written after doing it once end to end on 2026-09-05. Everything below was
executed, not planned. Where a step failed the first time, the failure is
recorded, because the failure is the part worth not rediscovering.

---

## 0. The short version

```bash
# one-time environment
wsl --install -d Debian --no-launch
debian.exe install --root
wsl -d Debian -u root -- apt-get install -y mtd-utils python3

# in Debian, with the stock app2 payload as app2.stock.jffs2
python3 tuxedo_jffs2_extract.py app2.stock.jffs2 root_stock   # must run as root
cp -a root_stock root_patched
cp <your patched file> root_patched/<path>
mkfs.jffs2 -r root_patched -o app2.raw -e 0x20000 -l -n
sumtool  -i app2.raw     -o app2.jffs2 -e 0x20000 -l -n
python3 tuxedo_jffs2_extract.py app2.jffs2 root_verify        # then diff -r
```

Then wrap `app2.jffs2` in the vendor 128-byte header with the size field AND
the checksum updated, and copy it to a FAT32 SD card alongside the five other
vendor files:

```bash
python tuxedo_hdr.py build app2.jffs2 app2.hdr --template stock/app2.hdr
copy *.hdr MCU.hex G:python tuxedo_hdr.py verify G:\*.hdr      # verify the CARD, not the staged copy
```

Skipping that last step costs a wasted trip to the panel. It did once.

---

## 1. What the firmware distribution actually is

The vendor ships one zip containing six files and nothing else:

| File | Size | What it is |
|---|---|---|
| `app1.hdr` | 2,145,572 | Linux kernel |
| `app2.hdr` | 124,103,304 | **root filesystem, the interesting one** |
| `app3.hdr` | 252 | a 124-byte JFFS2 holding one file, `temp.txt`, containing `Test` |
| `MCU.hex` | 26,740 | microcontroller image |
| `ProgCV.hdr` | 468,790 | the flasher itself |
| `seconboot.hdr` | 159,984 | secondary bootloader |

There is **no primary bootloader file**. That is consistent with the finding in
`TUXEDO-FIRMWARE.md` that the primary boot programming routine is dead code on
this build.

### The .hdr container

Every `.hdr` file is a 128-byte header followed by the raw payload. Field
offsets, confirmed against all five headers:

| Offset | Size | Field | `app2.hdr` value |
|---|---|---|---|
| `0x00` | 8 | type magic, NUL-padded | `appl000` |
| `0x08` | 4 | payload size, little-endian | 124,103,176 |
| `0x0c` | 4 | unknown, differs per component | `0x00b20000` |
| `0x10` | 4 | load address | `0x80000000` |
| `0x14` | 2 | **unused 16-bit field, see below** | `0x8ad5` |
| `0x16` | 26 | build date, C string | `Tue Mar 20 12:37:33 2018` |
| `0x30` | 13 | payload filename | `app2.jffs2` |
| `0x3d` | 17 | version string | `TUXEDO_V5.3.21.0` |
| `0x4e` | 4 | component type tag | `APP` |
| `0x52` | 14 | platform tag | `TUXEDOPLUSVA` |

Magic values are `appl000` for the three apps, `boot000` for `seconboot`,
`prog000` for `ProgCV`. The flasher compares 7 characters of this.

### The 16-bit field at 0x14 IS a checksum, and it IS enforced

**This section previously said the opposite. It was wrong, and the panel
proved it wrong.** A rebuilt `app2.hdr` carrying the vendor's original
checksum was rejected on the touchscreen with:

```
File app2.hdr Checksum Error: Please remove the SD card and Format SD card
using PC. Copy image again, insert SD card to unit and reboot the system for
reprogramming.
```

The failure was clean: nothing was written, and the unit offered to boot
normally after 30 seconds. That is the fail-safe behaviour §1 predicted, and
it is the only part of the original reasoning that survived.

**Why the wrong conclusion was reached.** The per-component loader at
`0x800074c0` sets its "checksum OK" flag (`0x83f1eca4`) unconditionally after
a successful read, at `0x8000761c`. Reading only that, it looks as though no
verification happens. In fact `0x83f1eca4` means *"the file was present and
readable"*, and it exists so the error reporter at `0x80006410` can choose
between "not found" and "checksum error". The real verification is a separate
routine, and the search that missed it looked for `ldrh [rX, #0x14]`, which
never appears because the header is `memcpy`'d to `0x83f1dddc` first and the
field is read from there.

**The algorithm**, at `0x80003864`, called in chunks from the validator with a
final-chunk flag:

```
80003884  ldrb  r6, [ip]        ; high byte
80003888  lsls  r6, r6, #8
80003894  ldrb  r6, [ip]        ; low byte  -> big-endian 16-bit word
80003898  orrs  lr, r6, lr
800038a0  uxtah r0, r0, lr      ; 32-bit accumulator, NO folding during the loop
800038a4  subs  r4, r4, #2
...                             ; finalisation, last chunk only:
800038d0  lsrs  r6, r0, #0x10
800038d4  uxtah r0, r6, r0      ;   acc = (acc >> 16) + (acc & 0xffff)
800038d8  adds  r0, r0, r0, lsr #16
800038dc  mvns  r0, r0          ;   complement
800038e0  uxth  r0, r0          ;   truncate to 16 bits
```

Sum big-endian 16-bit words into a **32-bit** accumulator, fold twice at the
very end, complement, truncate. It is the internet checksum with a deferred
fold, computed over the **payload only** — not the header, not the whole file.

**The subtlety that produced a near-miss.** An earlier attempt accumulated in
16 bits with end-around carry on every addition. That is the textbook internet
checksum and it gives the *same* answer for short inputs and a *different* one
for long ones. It reproduced `app3.hdr` and `seconboot.hdr` exactly, missed
`ProgCV.hdr` by 1 and `app1.hdr` by 8, and missed `app2.hdr` badly. Two
matches out of five looked like a coincidence rather than a nearly-right
algorithm, and the wrong lesson was drawn. Deferring the fold reproduces all
five exactly.

`tuxedo_hdr.py` in this repo implements it, and `verify` checks a file the way
`ProgCV` will before the card ever goes near the panel:

```bash
python tuxedo_hdr.py build app2.jffs2 app2.hdr --template stock/app2.hdr
python tuxedo_hdr.py verify *.hdr
```

**Always run `verify` on the card itself, not on the staged copy.** The card is
what the panel reads.

### What is actually validated, in order

`0x800074c0` performs these checks after loading a component. Any failure
reports the same generic "Checksum Error" message, so the message does not
tell you which one tripped:

| Check | Where | Notes |
|---|---|---|
| `mmc_header.flashaddress != flashAddress` | `0x800077b8` | header field `0x0c`; leave it alone |
| payload filename extension matches the expected component | `0x80007904` | `strrchr(name, '.')` then `strcmp` |
| header size field vs measured size | `0x80007928` | tautological as written |
| **payload checksum** | `0x80003864` | the one that bites |

### The old, incorrect reasoning, kept for the record

It looks like a checksum, and the flasher does contain the strings
`SOURCE CHECKSUM ERROR!!!` and `File %s Checksum Error: ...`. It is tempting to
assume you must recompute it. **You do not.**

The flag that selects between the "not found" and "checksum error" messages is
a byte at `0x83f1eca4`, and the only code that writes it is the per-component
file loader:

```
800075cc  bl 0x80064a38      ; open the component file
800075dc  beq 0x800075ec     ; opened
800075e8  b  0x8000764c      ; open failed, flags stay 0
800075fc  bl 0x80069048      ; read it; r3 = &bytes_read
80007608  cmp r0, #0
8000760c  beq 0x8000764c     ; read nothing, flags stay 0
80007610  strb #1 -> 0x83f1eca3   ; "file present"
8000761c  strb #1 -> 0x83f1eca4   ; "checksum OK"  <-- unconditional
```

`0x83f1eca4` is set to 1 whenever the file opens and any bytes are read. No
arithmetic is performed over the payload; `0x80069048` is a thin FAT read
wrapper that only validates its arguments. The checksum-error branch exists to
give a better message when a file was present but unreadable.

For the record, the field was also attacked numerically. A ones-complement sum
of big-endian 16-bit words over the payload reproduces it exactly for
`app3.hdr` (`0xebba`) and `seconboot.hdr` (`0xbda7`), but misses `ProgCV.hdr`
by 1, `app1.hdr` by 8, and `app2.hdr` by a lot. No prefix length explains the
misses. Whatever the vendor tool computed, the flasher does not recompute it,
so the stock value is carried through unchanged.

**So: copy the vendor 128-byte header verbatim and change only the size field
at `0x08`.** If the field ever did matter, a wrong value is fail-safe, because
the flasher refuses the file rather than writing anything.

---

## 2. Environment

`mkfs.jffs2` and `sumtool` are Linux-only, and the extraction must run on a
filesystem that can hold Unix modes, symlinks and device nodes. A Windows
extraction silently loses all three.

Docker Desktop was tried first and is a dead end here: it launches but its WSL
distro never leaves `Stopped` without someone clicking through its UI. A real
WSL distro works and needs no interaction:

```bash
wsl --install -d Debian --no-launch      # installs the package
debian.exe install --root                # registers it, no interactive user setup
wsl -d Debian -u root -- apt-get update
wsl -d Debian -u root -- apt-get install -y mtd-utils python3
```

`mkfs.jffs2 (mtd-utils) 2.3.0` and Python 3.13 were what got installed.

**Work inside the distro own filesystem** (`/work`), not under `/mnt/c`. The
Windows mount cannot represent the modes and device nodes, so building from
there produces a wrong image.

### Two traps when driving WSL from Git Bash

Both of these cost time and produced confusing failures.

1. **MSYS path conversion.** Git Bash rewrites arguments that look like Unix
   paths before handing them to a native `.exe`. A command like
   `wsl.exe -- bash /mnt/c/...` arrives as
   `bash 'C:/Program Files/Git/mnt/c/...'`. Prefix the command with
   `MSYS_NO_PATHCONV=1`.
2. **`/tmp` means two different things.** In Git Bash it is the Windows temp
   directory; to a native Windows Python it is `C:\tmp`. A script written to
   `/tmp/x.py` by bash is not necessarily the one Python opens.

The reliable pattern is: write the script into the scratchpad from Git Bash
with a quoted heredoc, then copy it in and run it by its in-distro path.

---

## 3. Reading a JFFS2 image

`tuxedo_jffs2.py` in this repo parses the format; `tuxedo_jffs2_extract.py`
writes the tree out under Linux with metadata intact.

### The CRC is not the CRC you expect

JFFS2 uses the Linux `crc32_le` seeded with 0 **and no final inversion**. It is
not `zlib.crc32`, which pre-inverts and post-inverts. Using the zlib one makes
every node in a perfectly good image look corrupt. The first scan reported
51,896 bad header CRCs and zero valid nodes, which reads exactly like a damaged
image and is not.

```python
def crc(b, seed=0):
    c = seed
    for ch in b:
        c = TBL[(c ^ ch) & 0xFF] ^ (c >> 8)
    return c & 0xFFFFFFFF          # note: no final xor
```

### The two CRC fields are in the opposite order to their names

`jffs2_raw_dirent` ends with `node_crc, name_crc, name[]` and
`jffs2_raw_inode` ends with `data_crc, node_crc, data[]`. Reading them in the
order the names suggest validates the wrong buffer and rejects every node.

### Device nodes have isize == 0

`/dev/null` and friends store their `rdev` in the data node while `isize` is 0,
so any reader that truncates file content to `isize` throws the value away and
produces `0, 0`. Read the winning fragment decompressed payload directly:

```python
fr = max(inodes[ino], key=lambda f: f["ver"])
d  = decompress(fr["ctype"], fr["data"], fr["dsize"])
```

Two bytes is the old `major << 8 | minor` encoding. Getting this right yields
`console 5,1`, `null 1,3`, `tty 5,0`, the canonical numbers, which is itself a
good check that the decode is correct.

### What the stock image contains

```
DIRENT 3483   INODE 47129   SUMMARY 946   bad CRCs 0
224 directories, 3096 files, 159 symlinks, 3 device nodes, 1 fifo
179,681,431 bytes of file data
every uid and gid is 0
compression: zlib 37686, none 9207, rtime 1
```

3483 directory entries and 3483 reconstructed objects, so nothing is
unaccounted for.

---

## 4. Geometry

Derived from the stock image, then confirmed by rebuilding it:

| Parameter | Value | How it was established |
|---|---|---|
| erase block | `0x20000` (128 KiB) | spacing of the 946 summary nodes |
| endianness | little | magic stored as `85 19` |
| cleanmarkers | none | none present, correct for NAND where they live in OOB |
| padding | none | image is 946.83 erase blocks, not a whole number |
| compression | default set | zlib dominant, with rtime and none also present |
| summaries | yes | 946 summary nodes means `sumtool` was run |

```bash
mkfs.jffs2 -r <tree> -o out.raw    -e 0x20000 -l -n
sumtool   -i out.raw -o out.jffs2  -e 0x20000 -l -n
```

`-l` is little-endian, `-n` is no cleanmarkers. Do **not** pass `-p`; the
vendor image is not padded to a whole erase block.

---

## 5. Verification, which is the part that matters

Do not trust a rebuilt filesystem because the command exited 0. Two checks were
run, and both should be repeated for any future build.

### Check 1, rebuild the stock tree unchanged and compare

Build a control image from the **unmodified** extracted tree first. This
separates "my toolchain is wrong" from "my patch is wrong".

```
stock image    124,103,176 bytes
control image  124,103,172 bytes     <- 4 bytes different across 124 MB
```

A four-byte delta over 124 MB is the newer mtd-utils packing nodes very
slightly differently. It is not the patch, because the control image contains
no patch.

Then extract the control image and compare against the source tree:

```
diff -r --no-dereference root_stock root_ctrl      -> exit 0
metadata list (path, mode, uid, gid, type, size)   -> identical, 3484 entries
```

### Check 2, round-trip the patched image

```
diff -r  root_patched root_verify   -> identical apart from the notices diff
                                       always emits about character-special files
metadata diff                       -> exit 0, 3484 vs 3484 entries
diff -rq root_stock  root_verify    -> exactly ONE file differs,
                                       opt/webserver/Barracuda
sha256 of Barracuda read back out of the built image
                                    -> af9d34d2b694ef79... as intended
device nodes in the rebuilt image   -> console 5,1  null 1,3  tty 5,0
symlinks                            -> 159, same as stock
```

The last three are the ones that catch a silently broken build. A rebuilt image
whose device nodes came out `0,0` will still mount and will still look fine in
a file listing.

---

## 6. What was actually built

Two files inside the root filesystem differ from stock. Nothing else.

| Path | Change |
|---|---|
| `opt/webserver/Barracuda` | the login-lockout and heap-overflow patch |
| `etc/hosts` | a commented block for redirecting firmware updates |

| Artifact | sha256 / value | Size |
|---|---|---|
| stock `Barracuda` | `b9bf50d8d1cfe198...60186b` | 5,680,361 |
| patched `Barracuda` | `af9d34d2b694ef79...d273d6be` | 5,680,361 |
| patched `app2.jffs2` | `fee5e687638c312a...2e8260ab` | 124,103,172 |
| its header checksum | `0x6836` (vendor's was `0x8ad5`) | — |

The header carries size `124,103,172` and checksum `0x6836`; every other field
is the vendor's, byte for byte.

The binary patch itself is 131 bytes across six sites and is specified in
`TUXEDO-LOCKOUT-PATCH.md` section 3, with the build record in section 6. The
file size is unchanged, so no ELF section, segment or symbol offset moves.

### The `/etc/hosts` change, and why it is the right place for it

`/etc/nsswitch.conf` reads `hosts: files nisplus nis dns`, so a name resolved
in `/etc/hosts` beats DNS. That makes this file a working redirection switch
with no binary patching at all.

The block added is **entirely commented out**, so it changes no behaviour. It
exists to be discoverable: it names the hosts the panel resolves and explains
how to point any of them somewhere else.

Worth knowing before trying to redirect updates: **the panel contains no
literal firmware-download hostname.** It asks an AlarmNet "AUI redirector"
where to go, then fetches over plain HTTP using `GET` with `Range:` byte
requests. So the names to override are `auiredir1..3.alarmnet.com` and
`auiredirtest.alarmnet.com`. The same three names, paired with IP addresses,
also appear in `/srv_info.conf`, which the firmware parses itself via
`ReadServInfo`, and which is the better lever if you want the same name to
resolve to a different address.

Two hosts that look relevant but are not the updater: `gw.mylanconnect.com` is
the remote-access IP update service (`/php/VAM/dcrypt.php`,
`/php/VAM/sessioncheck.php`), and `tccaps.honeywell.com` is Total Connect.

The OTA client treats a DNS failure as non-fatal and starts a two-hour retry
timer, so a wrong entry degrades updates rather than breaking the panel.

Unlike the SD path, the OTA path **does** verify a checksum: the manifest
carries `checksum`, `folderpath`, `version`, `filenumber`, `platform` and
`notes` fields, and the binary contains a `Verify_Checksum:` routine.

---

## 7. SD card layout

The card must be FAT32 and the firmware files must be the **only** contents.
Windows recreates `System Volume Information` on any FAT32 volume it touches;
that is unavoidable from Windows and has not caused a problem.

Six files, 121 MiB total:

| File | State |
|---|---|
| `app1.hdr` | vendor original |
| `app2.hdr` | **ours** |
| `app3.hdr` | vendor original |
| `MCU.hex` | vendor original |
| `ProgCV.hdr` | vendor original |
| `seconboot.hdr` | vendor original |

### Why all six, and not just app2.hdr

The flasher validates a set of critical files and clears its success flag when
one is missing, reporting `Critical file <x>.hdr is missing`. Omitting files
risks the upgrade simply refusing to run. Shipping the complete vendor set with
one file replaced is what the vendor own updater does.

This is safe because of the finding recorded in `TUXEDO-FIRMWARE.md`: **each
component is written only if its own file opened successfully from the card.**
The files that are byte-identical to the vendor originals get rewritten with
exactly what is already on the panel, which is what a normal vendor upgrade
does anyway.

The residual risk is not a wrong-component write. It is a **truncated file**, a
component present but incomplete. Verify the card file sizes and hashes after
writing it and before booting the panel with it.

---

## 8. What flashing does to the panel

- Power down, insert card, power up. The panel reprograms itself at boot.
- Its web interface and its own touchscreen are unavailable during the run, and
  it reboots at the end.
- The VISTA-21iP alarm panel is a separate device and is not touched. Zone
  monitoring and the Envisalink path are unaffected.
- Anything polling the Tuxedo over HTTP sees it disappear and return.

### Reflashing `app2` does NOT wipe the panel configuration

This was worth checking, because `/opt/tuxedo/configuration` is **empty in the
shipped image** and holds the web user accounts, the Z-Wave device database,
network settings and the update state. If it were part of the root filesystem,
every reflash would reset the panel.

It is not. From `/etc/fstab`:

```
/dev/mtdblock17 /opt/tuxedo/configuration jffs2   defaults    0       0
```

The directory in the image is only a mountpoint. The real configuration lives
on its own MTD partition, which the SD flasher does not write. That is also why
the OTA settings cannot be pre-seeded by editing the image: those JSON files
are created at runtime on `mtdblock17`.

Related detail on persistence: `/etc/rc.d/init.d/filesystems` only relocates
`/tmp`, `/etc` and `/var` into a tmpfs when `READONLY_FS=y`, and `rc.conf` does
not set it, nor is `RAMDIRS` set. So `/etc` is the real on-flash directory and
an edit there persists across reboots. It is replaced by the next `app2`
reflash, which is why the `/etc/hosts` block tells you to keep a copy.

---

## 8b. The web application is a ZIP inside the binary

Worth knowing before planning any web-page change. `/opt/webserver/` holds only
the `Barracuda` binary. The whole web UI is a **776-entry ZIP embedded inside
it**, at file offsets `0x8a948`-`0x4f0113`, roughly 4.6 MB. That is the
Barracuda App Server's ZIP filesystem.

Because the archive sits in the middle of the ELF rather than appended to it,
**it cannot change size**: anything after it would shift. A modified entry must
recompress to exactly its current compressed size, and both the local file
header and the central directory must be updated to agree.

The workable technique is: edit the source, deflate it, then pad the source
with spaces inside a comment and binary-search the padding length until the
compressed size lands exactly on the original. `script/consoleRequest.js`, for
example, is 17,130 bytes raw and 3,625 deflated.

This is why the virtual-console JavaScript fixes are not in the current image.
They are small edits in a container that makes them fiddly, not risky, and they
are a separate job from the binary patch.

---

## 9. Open items

- **The 16-bit header field at `0x14`** is carried through unchanged. It is not
  read by the flasher, but its algorithm is still unidentified. If a future
  firmware does check it, this is the thing to revisit.
- **The field at `0x0c`** (`0x00b20000` for app2, `0x00220000` for app1,
  `0x0bf20000` for app3, `0x00120000` for seconboot) is unexplained. It is also
  carried through unchanged.
- **Nothing here has been flashed yet.** Every claim above is about files on
  disk, verified against each other. The first real flash is still the first
  real test.
