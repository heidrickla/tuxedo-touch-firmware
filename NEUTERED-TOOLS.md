# What the vendor disabled but left in place

The shipped firmware is a development image with the tools removed and every
trace of them left behind. Init scripts, config files, service registrations and
call sites are all intact; only the binaries are gone. That makes most of this a
matter of supplying a binary rather than building a feature.

Two have already been restored this way, and both worked with no patching:

| Capability | What was missing | Restored in |
|---|---|---|
| SSH | `/usr/sbin/dropbear` | v8 |
| NTP | `/bin/ntpclient`, and `NTP_SERVER` was empty | v9 |

## Everything the init scripts still ask for

Each of these guards on a binary that is not in the image. The script, its
options plumbing and its service entry are all present.

| Service | Wants | Worth restoring? |
|---|---|---|
| `syslog` | `/sbin/syslogd`, `/sbin/klogd` | **Yes, first.** See below |
| `inetd` | `/usr/sbin/inetd` | Superseded by SSH. `/etc/inetd.conf` still carries a `telnet` line pointing at `/usr/sbin/telnetd`, also absent |
| `sshd` | `/usr/sbin/sshd` | No, dropbear covers it in 233 KB |
| `boa` | `/usr/sbin/boa` | No. A second web server is surface, not function |
| `dhcpd` | `/usr/sbin/dhcpd` | No |
| `mdev` | `/sbin/mdev` | No, `udev` is running |
| `devfsd` | `/sbin/devfsd` | No, obsolete |
| `startup_org` | `/mnt/sd/NAND_test.sh` | See the SD hook below |

### syslogd is the one worth doing next

Nothing on the panel captures syslog today. That is why dropbear had to be given
`-E` to log to stderr, and why every diagnostic this project has run needed its
own log plumbing bolted on. `/etc/rc.d/init.d/syslog` is complete: it starts both
daemons, honours `SYSLOGD_OPTIONS` and `KLOGD_OPTIONS` from
`/etc/sysconfig/syslog`, and handles stop and restart.

Supply a musl-static `syslogd` and `klogd` and every daemon on the box starts
logging in the normal way, including the vendor's own. `/etc/sysconfig/` is empty,
so the options file can be created cleanly. `syslog` is in `all_services` but not
`cfg_services`, so `rc.local` has to call it, exactly as `settime` did.

### The vendor already had our SD hook

`etc/rc.d/init.d/startup_org`, lines 70-73:

    if [ -x /mnt/sd/NAND_test.sh ]
    then
    /mnt/sd/NAND_test.sh &
    fi

That is the same mechanism the v8 image adds by hand as
`/mnt/sd/tuxedo-init.sh`. The vendor's version runs from `startup_org`, which
**nothing references** — it is the pre-release startup script, left in the image
alongside the shipped one. `startup_org` also carries commented-out launches for
`/opt/webserver/weblogger`, `/Logger` and `/TotalConnect`.

Three startup variants ship: `startup` (2,319 bytes, the live one), `startup_org`
(2,029), `startup_472` (1,623) and `startup_cwmode` (1,899). Only `startup` is
reachable.

## Dev tooling that was left in place and works

| Path | Size | |
|---|---|---|
| `/sbin/insmod.static` | 527,429 | **Kernel modules can be loaded.** `/lib/modules` holds zero `.ko` files, so nothing does today, but the loader is there |
| `/sbin/ldconfig` | 679,989 | |
| `/sbin/sln` | 540,259 | static `ln`, a recovery tool |
| `/usr/sbin/tcpd` | 6,942 | TCP wrappers, only useful with `inetd` |
| `/Logger` | 8,377 | |

## Artefacts that show it was never cleaned

- `/etc/rc.d/init.d/.startup.swp` — a **Vim swap file**, 12,288 bytes, shipped in
  production firmware.
- `/lib/123librt-2.5_org.so123` and `/lib/1librt-2.5_Backup.1so123` — hand-renamed
  library backups, still in `/lib`.
- `/tuxedo` ships with a full **unstripped symbol table**, 12,592 named functions.
  That single oversight is what made the clock source, the built-in NTP client and
  the push-stream field label solvable in an evening.
- `script/eventHandler_org.js`, `script/scene_setup_org.js`,
  `libgstoss4audio.so.bk` inside the web application.
- RPATHs pointing into the vendor's build tree at
  `/home/tuxedo/QT/Build/buildqt480/`, and that tree is shipped.

## How to use this

When something looks missing, check whether the mechanism is already there before
building it. The panel's own NTP client, its SD-card script hook and its complete
SSH service registration were all found after the equivalent had been designed
from scratch. Look for the init script, the config key and the call site first.

---

# busybox: built, and verified on the panel

Built 2026-09-06 and run on the hardware. This covers `syslogd` and `klogd` from
the roadmap above in one binary, and brings the tools this project kept finding
absent.

    busybox 1.36.1, musl 1.2.5, static
    1,328,384 bytes, EXEC, EABI5 soft-float, 0 INTERP segments

Verified working on the panel:

| Applet | Result |
|---|---|
| `awk` | correct field extraction |
| `ping` | `64 bytes from 203.0.113.1 ... time=0.594 ms` |
| `strings` | read `BUILD=v9` out of `/etc/tuxedo-build` |
| `free` | `Mem: 126016 35724 61980 ...` |
| `pgrep` | found both dropbear pids |
| `netstat` | 6 listeners, matching the known set |
| **`dmesg`** | **the kernel ring buffer is readable**, which it never was before |
| `syslogd`, `klogd` | both present, both print usage |

## The one quirk that matters when installing it

**`busybox <applet>` does not work on this build.** `busybox --list` reports zero
applets and `busybox awk ...` answers `applet not found`. Invoked through a
symlink named after the applet it works perfectly: `argv[0] = awk` extracts
fields, `argv[0] = syslogd` prints the BusyBox banner.

So install it the ordinary way, as symlinks, and do not rely on the multiplexer.
That also suits the panel: `/etc/rc.d/init.d/syslog` looks for `/sbin/syslogd`
and `/sbin/klogd` **by path**, so those two symlinks are what make the vendor's
own service start.

Suggested layout, chosen so nothing already on the panel is shadowed:

    /bin/busybox            the binary
    /sbin/syslogd           -> /bin/busybox     (what the init script wants)
    /sbin/klogd             -> /bin/busybox     (likewise)
    /usr/local/bin/<applet> -> /bin/busybox     for awk, ping, strings, dmesg,
                                                free, pgrep, top, vi, find, sed

Keeping the general tools in `/usr/local/bin` rather than `/bin` means the
vendor's own binaries keep priority on `PATH` and nothing existing changes
behaviour.

## Build notes

musl ships no `linux/*` kernel headers, so three groups had to be copied into
`/opt/musl-armel/include` before `defconfig` would build: `linux`,
`asm-generic` and `asm` (from the ARM cross package, not the host), then `mtd`
for `nandwrite`. `CONFIG_LFS=y` is required because musl is always 64-bit
`off_t` and busybox otherwise trips its own
`BUG_off_t_size_is_misdetected` assertion. `CONFIG_TC` was turned off.

Building from `allnoconfig` with an explicit applet list produced a binary with
an **empty applet table** that failed even through symlinks. Use `defconfig` and
subtract.

## syslog running on the panel, and what it immediately showed

Installed and started on the hardware 2026-09-06, ahead of the v10 flash, using
the **vendor's own `/etc/rc.d/init.d/syslog` unmodified**. It printed
`Starting syslogd and klogd` and both daemons came up. That is the claim that
mattered: supplying `/sbin/syslogd` and `/sbin/klogd` as busybox symlinks is
enough, and no vendor script needed changing.

`dropbear` now logs normally, so the `-E` workaround is no longer required:

    authpriv.warn dropbear[506]: Failed loading /etc/dropbear/dropbear_ecdsa_host_key
    authpriv.info dropbear[511]: Running in background

### Three things that were invisible before

Ranked by frequency in the first minutes of logging:

| Count | Message |
|---|---|
| 10 | `SIGNAL in KERNEL <n> for Process <n> Process Name bonj_client` |
| 9 | `nand_read_bbt: Bad block at 0x...`, nine distinct addresses |
| 3 | `JFFS2 warning: jffs2_sum_write_data: Not enough space for summary, padsize = -N` |

**`bonj_client` is the noisiest process on the panel.** That is the Bonjour
discovery client, part of the camera subsystem. The owner has no cameras on this
panel, and `IPCAMERAS` currently holds two printers it found. Turning the four
discovery flags off would remove the most frequent log source on the device
along with the LAN probing.

**Nine NAND bad blocks** are reported at boot, at

    0x02180000  0x02e00000  0x05080000  0x06400000  0x073e0000
    0x0b220000  0x0d9a0000  0x0dba0000  0x0f280000

plus two bad-block tables found at pages 130944 and 131008. Unremarkable for NAND
of this age, and this is the first time it has been visible. Worth keeping as a
baseline: a growing count is the early warning for a failing device, and three of
these fall inside the `Root File System` partition (`mtd16`, `0x00b20000`
onwards).

The count was first written here as five, taken from a frequency table that
collapsed the addresses. Nine is the number of distinct blocks.

The JFFS2 summary warning is benign but recurring, on a rootfs at 70% (125 MB of
180 MB).

Kernel messages also confirmed the `peek` tool behaving correctly:
`SIGNAL in KERNEL 19 for Process 907 Process Name tuxedo` is the `SIGSTOP` that
`PTRACE_ATTACH` sends, appearing exactly when it was run.

---

# The card no longer has to move

`RemoteUpgradeHelper` in `/tuxedo` is a complete OTA client: root XML, product
XML, `download_file`, `Verify_Checksum`, `CheckUpgradeViability`, then a reboot
into the flasher. Reading `ru_download_file` settles what it actually does:

    'Starting files download'
    '/mnt/sd/%s'                                   <- downloads TO THE SD CARD
    'mv /mnt/sd/ProgCV.hdr /mnt/sd/ProgCV_bkp.hdr'
    'New FW downloaded. Type-Critical Ver-%s_VA.'

So the vendor's own OTA does not avoid the card. It fetches over the network
*onto* the card, then reboots and lets ProgCV flash from it. Config lives in
`/opt/tuxedo/configuration/remotefwupgradeconf.json` and
`remotefwdownloadconf.json`.

Which means there is nothing to reimplement. **The card can simply stay in the
panel**, mounted `rw` at `/mnt/sd`, and we write to it over SSH.

## Two tools, and which to use

**`deploy.py`** — for anything that is a file. The rootfs is JFFS2 mounted rw,
so changes persist across reboots and need no flash at all.

    python deploy.py            # dry run
    python deploy.py --apply

It compares 36 known paths by md5, or by link target for symlinks, and pushes
only what differs. Symlinks must be compared by target: `md5sum` follows a link,
and an absolute target resolves against the *builder's* filesystem, so every
symlink otherwise looks changed.

`/etc/hosts` is skipped by default. The panel rewrites it at boot to substitute
the real gateway, so it always differs and pushing ours back would undo that.

**`push-image.sh`** — for a full image, when a flash is genuinely needed
(a Barracuda patch, or making changes survive the next flash).

    ./push-image.sh stage_v10/app2.hdr [--reboot]

Measured: 125,685,236 bytes in 64 s, 1.9 MB/s, md5 verified **on the panel**
after transfer. It writes to `/mnt/sd/.app2.new` and renames only after the
checksum matches, because a half-copied `app2.hdr` is exactly what the flasher
must never find.

## A note on the shell

`deploy` was a shell script first. Getting a file list out of
`wsl.exe -- bash -c` and back through `ssh` meant three layers of quoting, every
`"$f"` arrived empty, and the comparison silently compared nothing while
reporting all 36 files as changed. Two rounds of patching did not fix it. The
Python rewrite reports `35 already match, 1 changed` on the same input, and the
one change is real.
