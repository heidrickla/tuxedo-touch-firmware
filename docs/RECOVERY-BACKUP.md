# Backup and recovery baseline

Taken 2026-09-06 from the live panel over SSH, read-only. Nothing was written,
no service restarted, no reboot. This is prerequisite P0 of the staged plan in
`KERNEL-VERDICT.md` — the thing that makes every later risky step recoverable.

**The backup itself is NOT in this repository and must never be.** It contains
`userdetails_sec.json`, `UserNamesFile*.txt`, `ifcfgeth_sec.conf` and the rest of
the panel's configuration — user codes and network settings for a real house.
`ci/checks.sh:check_vendor_blobs` rejects `*.bin` precisely so an accident here
fails the suite rather than becoming a public commit.

## What was captured

| partition | size | verified |
|---|---|---|
| mtd0-mtd15 | 12 MB total | md5 matched end-to-end, all 16 |
| mtd17 (config) | 61,734,912 bytes | size exact; md5 cannot match, see below |
| `/opt/tuxedo/configuration` | 115 entries, 1,404,416 bytes | gzip+tar verified readable |

`mtd16` (the 180 MB root filesystem) was not captured: it is reproducible from
the firmware image already in hand, unlike everything above.

**mtd17 cannot be md5-verified and that is not an error.** It is a mounted `rw`
JFFS2 that the panel writes to continuously. Two consecutive `md5sum /dev/mtd17`
runs *on the panel itself* returned different digests. The captured image is a
valid point-in-time snapshot of the exact expected size; a matching digest is not
achievable while the panel is running, and expecting one would be a mistake.

## What the partition contents actually show

Byte-level analysis of the captured images, which corrects two things the
partition *names* imply:

| partition | state |
|---|---|
| mtd0 Primary Bootloader | 55,479 bytes of data. **Irreplaceable** — holds the SD-card recovery path |
| **mtd1 Primary Bootloader Backup** | **BLANK, all 0xFF** |
| mtd2, mtd3 Hardware Parameters 1-2 | 255 bytes, identical pair. **Irreplaceable** |
| mtd4, mtd5 Hardware Parameters 3-4 | BLANK |
| mtd6, mtd7, mtd8 Hardware Parameters 5-7 | 128 bytes, three identical copies. **Irreplaceable** |
| mtd9, mtd10, mtd11 Secondary Bootloader 1-3 | 156,462 bytes, **three identical copies** — real redundancy |
| **mtd12 U-Boot Environment** | **BLANK, all 0xFF** |
| mtd13, mtd14, mtd15 Kernel 1-3 | 2,133,376 bytes, **three identical copies** |

Two corrections worth stating plainly:

1. **There is no primary bootloader backup.** mtd1 carries the name and is
   erased. If mtd0 is destroyed, the partition that exists to save you is empty.
   This is exactly the state ProgCV's own error text describes: *"ORIGINAL
   BOOTLOADER IS CORRUPTED ... CANNOT BE REPROGRAMMED USING MMC ANYMORE ... USE
   JTAG PROGRAMMER"*. **Never write mtd0 or mtd1.**

2. **mtd12 being blank confirms the boot analysis.** The U-Boot environment is
   erased, so the compiled-in default environment is what runs — which is why
   `verify` is unset and the payload CRC is skipped (`KERNEL-VERDICT.md` §3.3).

The good news is the kernel slots. mtd13, mtd14 and mtd15 hold **byte-identical
images**, so the three-slot fallback currently has two intact spares. Flashing a
candidate to mtd13 alone leaves two good kernels behind it — which is what makes
the staged kernel path survivable *if* it is ever attempted, and it is why the
plan says write mtd13 directly rather than going through the SD flasher, whose
slot behaviour is unknown.

## The irreplaceable set is tiny

mtd0 (55,479 bytes) plus mtd2 (255 bytes) plus mtd6 (128 bytes). Everything else
is either blank, a duplicate of something else, or rebuildable from the firmware
image. That is under 56 KB of genuinely unique, unrecoverable data on the whole
device, and it is now captured and md5-verified.

## Tooling notes, learned the hard way

- **No `tar` on the panel.** Use `busybox tar`. Plain `tar` silently produced a
  zero-byte stream.
- **`awk`, `cmp` and `which` are not on the non-interactive SSH `PATH`.** Set
  `PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH` at the top of every remote command.
  A missing binary inside a `set -e` script aborts it partway with no error,
  which silently skipped an install step once.
- **`/tuxedo` cannot be written in place** — it is running, so writes fail
  `ETXTBSY`. Copy, patch the copy, `mv` over it: `rename(2)` replaces the
  directory entry while the running process keeps its inode. This is the same
  pattern `deploy.py` already uses.
