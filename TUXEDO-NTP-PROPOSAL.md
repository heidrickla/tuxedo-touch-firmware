# Setting the clock from NTP: what the panel already has

Answering a request for the next firmware build: can the panel set its own
date and time instead of coming up in 2013?

**Short answer: the vendor already built the entire mechanism and shipped it
switched off.** Two things are missing: a small NTP client binary, and one
shell variable. **No existing binary needs patching**, and no boot script needs
restructuring — the invocation, the service registration and the boot ordering
are all already there and correct.

---

## 1. The clock does not reset because of flashing

Correcting something I said immediately after the flash. I reported that the
flash had cleared `/opt/tuxedo/configuration/datetime`. That was wrong, and it
was wrong for a reason I had already established and failed to apply:
**`/opt/tuxedo/configuration` is `mtdblock17`, a separate partition that
survives a reflash.** Nothing the flasher does can clear it.

What actually happens is in `/etc/rc.d/init.d/startup`, lines 48-56:

```sh
#set default date to Jan 01 2013
if [ -e /opt/tuxedo/configuration/datetime ]
then
    chmod 777 /opt/tuxedo/configuration/datetime
    /opt/tuxedo/configuration/datetime
else
    date 0101000013
fi
```

`datetime` is an **executable script** that the boot sequence runs to set the
clock. It persists on `mtdblock17`. If it is missing the panel falls back to
1 Jan 2013.

So the panel simply has no running clock across a power cycle. It restores
whatever was last written to that script. The observed 23 Feb 2014 is a stale
stamp, not a flash artefact, and the panel would have shown it after any power
interruption.

---

## 2. The NTP path already exists in the boot scripts

`/etc/rc.d/init.d/settime`, shipped, unmodified:

```sh
if [ ! -x /sbin/hwclock ]; then exit 0; fi
...
if [ "$1" = "start" -o "$1" = "restart" ]; then
    if [ -x /bin/ntpclient -a "$NTP_SERVER" ]; then
        echo "Setting time from ntp server: $NTP_SERVER"
        /bin/ntpclient -s -c 2 -i 3 -h $NTP_SERVER >/dev/null
    else
        ... print "Please set the system time using date <mmddhhmnyyyy>"
    fi
fi
```

Three gates. Two are already satisfied:

| Gate | State |
|---|---|
| `/sbin/hwclock` executable | **present**, 32,573 bytes |
| `NTP_SERVER` non-empty | declared and **empty**: `/etc/rc.d/rc.conf` line 9, `export NTP_SERVER=""` |
| `/bin/ntpclient` executable | **absent** |

`settime` is a registered service in `rc.conf`'s `all_services`, positioned
after `network` and `dhcpd` and before the UI starts. So it already runs at
the right point in the boot, with networking up.

**What is needed, in full:**

1. Drop a static `ntpclient` binary into `/bin`. It is a small, single-purpose
   program; against a 124 MB image the size is immaterial. See the ABI section
   below for what it has to be built as.
2. Set `NTP_SERVER` in `/etc/rc.d/rc.conf` to a LAN **IP address**.

No binary patching, no new init script, no change to the boot order.

There is no busybox on this system at all, so there is no applet to enable and
no `ntpd`, `ntpdate`, `rdate` or `sntp` anywhere in the image. The client has
to be added.

### What that binary has to be, exactly

Recommending "add a binary" is worthless without the ABI, so it was checked
rather than assumed. From `readelf` on shipped executables:

| Property | Value |
|---|---|
| Class / endianness | ELF32, little-endian |
| Machine | ARM |
| Flags | `0x4000002` — **EABI version 4**, `HASENTRY` |
| Float ABI | **soft-float**. Neither `EF_ARM_ABI_FLOAT_HARD` (`0x400`) nor `EF_ARM_ABI_FLOAT_SOFT` (`0x200`) is set, i.e. the legacy soft-float convention |
| Interpreter | `/lib/ld-linux.so.3` |
| C library | **glibc 2.5** (`libc-2.5.so`, `ld-2.5.so`) |
| Linkage | everything in the image is **dynamic**; there is not one static binary |
| Kernel | 2.6.31 |

Two consequences that decide the build:

1. **It must be `armel` (soft-float), not `armhf`.** A stock Debian/Ubuntu
   armhf binary will not run here. This is the most likely way to get it
   wrong, because armhf is what a modern cross-toolchain gives you by default.
2. **Link it statically.** glibc 2.5 dates from 2006; building dynamically
   against it needs an equally old toolchain, whereas a static binary carries
   its own libc and does not care what is installed. `ntpclient` uses only
   socket, `gettimeofday`/`settimeofday` and `adjtimex`, all of which long
   predate 2.6.31, so a modern static build is safe on that kernel. Modern
   toolchains emit EABI v5, which the kernel accepts alongside v4.

A static `ntpclient` is roughly 50 KB against musl or under a megabyte against
glibc. The extracted tree is 180 MB of content compressing to a 124 MB image,
so either is noise.

If a static build proves awkward, the fallback is to build dynamically against
the panel's own `lib/` directory, which is present in the extracted rootfs and
can be pointed at with `--sysroot`. That is more work and buys nothing.

---

## 3. Use an IP address, not a hostname

The shipped `/etc/resolv.conf` is:

```
nameserver 192.168.1.1
```

That is a factory default. On a panel that is not on a `192.168.1.0/24`
network — and this one is not — **DNS does not resolve at all**. `/etc/hosts`
carries the same stale assumption, with `192.168.0.2` through `192.168.0.6`
mapped as `gateway0` to `gateway4`.

So a hostname-based NTP server would fail silently on the shipped
configuration. This is a stronger reason than network hygiene to point the
panel at a LAN IP, and it happens to agree with the hygiene argument: a local
time source needs no DNS, works when the WAN is down, and does not put an
alarm panel on the public internet.

The application binary does carry a built-in server list — `pool.ntp.org` and
its continental variants, plus `clock.via.net` — but those sit adjacent to the
timezone table, so they are the **UI's picker list**, not the boot path. They
would suffer the same DNS problem.

`NTP_SERVER` being a shell variable in `rc.conf` means it is configurable in a
text file rather than compiled in, which is what was wanted anyway.

---

## 4. Fail open, and bound it

`ntpclient -s -c 2 -i 3` is already a bounded invocation: two samples, three
seconds apart, set the clock and exit. Its output is discarded and its exit
status is not checked, so a dead server cannot stop the boot.

That property must be preserved. A panel that will not boot because a time
server did not answer is far worse than a panel with a wrong clock. This is
the same fail-open reasoning applied to the 300-second login lock, for the
same reason: on an alarm panel, degraded beats absent.

Worth keeping the existing `else` branch too, so an unset server still leaves
the fallback date rather than an undefined clock.

---

## 5. The security angle, and an important limit

Finding b-3 in `TUXEDO-AUDIT-BUGS.md` notes that the REST AES key is derived
from a `random_string` seeded at Barracuda startup, and that when the clock is
pinned to a constant the seed window is small. Setting the clock correctly
**before** the application starts widens it considerably.

The ordering works out: `settime` is an rc service, and the application is
launched later from `startup` (`/tuxedo &`). Barracuda is not started from any
init script — the line in `startup` is commented out — so it is started by the
application, which means anything in the rc sequence runs before it.

### But the benefit is NOT retroactive, and that is now confirmed

`generateKeyForAPI` (`0x1d96c`) has exactly one caller, at `0x108b8`, and the
call is unconditional. The guard is inside the function:

```
0001db30  cmp r0, #0        ; strcmp(entry.DeviceMAC, "Browser") == 0 ?
0001db34  moveq r5, #1      ; found
0001db38  cmp r4, r7        ; loop over stored entries
0001db48  blt 0x1db18
0001db4c  cmp r5, #0
0001db50  bne 0x1dc60       ; FOUND -> return, write nothing
0001db54  ...               ; NOT found -> build and store a new entry
```

It generates a fresh random key at the top of the function every time, then
**discards it if a `Browser` entry already exists**. So an existing key is
never replaced, and a panel that has already minted a weak key keeps it.

**A factory reset is not the only way to get the benefit.** The key store is:

```
/opt/tuxedo/configuration/registereddevMAClist.json
/opt/tuxedo/configuration/registereddevMAClist_sec.json   (integrity twin)
```

Removing the `DeviceMAC: "Browser"` entry causes regeneration on the next
start. That is far less destructive than a factory reset, but it is not free:

- It invalidates the key any existing REST client holds. Anything using the
  encrypted REST API has to be re-registered.
- The `_sec` twin exists for an integrity check. Editing one without the other
  is likely to be rejected or to trip the CRC bookkeeping in `CRCdata.json`.
  **This has not been tested and should not be attempted casually.**

Both files live on `mtdblock17`, so both survive a reflash. That is also why
the weak key survived today's flash.

---

## Recommended shape

1. Add `/bin/ntpclient` to the next image: **ARM EABI, soft-float (armel),
   statically linked**. See the ABI table above; armhf will not run.
2. Set `NTP_SERVER` in `/etc/rc.d/rc.conf` to a **LAN IP address**.
3. Change nothing else. Do not touch the boot order, do not remove the
   fallback date, do not make the boot wait on the network.
4. Treat the AES-key improvement as a **separate, later decision**. It needs
   the key store edited and every REST client re-registered, and the
   integrity-twin behaviour tested first. Do not bundle it with a clock fix.

Item 4 is the one worth being slow about. Items 1 to 3 are a two-file change
to a mechanism the vendor already wrote.

---

# Implemented in v9, and what the panel actually showed

Confirmed over SSH on the running panel rather than from the carved rootfs.

## The mechanism, as it exists on the device

`/etc/rc.d/init.d/settime`:

    if [ ! -x /sbin/hwclock ]; then exit 0; fi
    ...
    if [ -x /bin/ntpclient -a "$NTP_SERVER" ]; then
        /bin/ntpclient -s -c 2 -i 3 -h $NTP_SERVER >/dev/null
    fi

- `/sbin/hwclock` is present, 32,573 bytes, so the guard passes.
- `/bin/ntpclient` does not exist.
- `/etc/rc.d/rc.conf` has `export NTP_SERVER=""`.

Both gaps are the vendor's, in the same pattern as dropbear, telnetd and inetd:
the invocation is shipped, the binary is not.

## What the clock actually does

| Observation | Value |
|---|---|
| System time on a running panel | `Mon Feb 24 02:27:14 UTC 2014` |
| System time immediately after boot | `Tue Sep  8 01:39:51 UTC 1970` |
| `hwclock -r` on `/dev/rtc` | `select() to /dev/rtc to wait for clock tick timed out` |
| `hwclock -r -f /dev/rtc0` | `Tue Sep  8 01:58:37 1970` |
| `hwclock -r -f /dev/rtc1` | times out |

`/dev/rtc` is a symlink to `rtc1`, which does not respond. `rtc0` does respond
but holds the same 1970 value, so nothing has ever written a real time to it.

The frozen `Mon, 24 Feb 2014` in every HTTP response header is not a hardcoded
string. It is the system clock: something moves the clock from 1970 to that
fixed 2014 date during startup. What does that has not been identified.

## The change

| Piece | v9 |
|---|---|
| `/bin/ntpclient` | ntpclient 2015_365, built for ARM against the panel's glibc 2.5, 23,672 bytes, needs at most GLIBC_2.4 |
| `NTP_SERVER` | `pool.ntp.org` in `/etc/rc.d/rc.conf` |
| Invocation | `rc.local` calls `/etc/rc.d/init.d/settime start` after network start |
| RTC write-back | `hwclock -w -f /dev/rtc0`, naming rtc0 because `/dev/rtc` points at the dead rtc1 |
| Log | `/mnt/sd/tuxedo-time.log`, falling back to `/tmp` |

`settime` is in `all_services` but **not** in `cfg_services`, and `rcS` iterates
`cfg_services`. That is why rc.local has to call it; registering it is not
enough.

ntpclient builds with the same constraints as dropbear: no LFS, no stack
protector, non-PIE, libraries after the objects. See `ssh/BUILD.md`.

Verified under emulation against a live NTP server by address, returning two
samples with sane offsets. Resolution was not tested there because the chroot
has no resolver; the panel has `nameserver 203.0.113.1` and
`hosts: files nisplus nis dns`.

## Two things to weigh before flashing

The LAN gateway `203.0.113.1` does **not** answer NTP, so `pool.ntp.org` means
the panel reaches the internet for time. If that is unwanted, change one line
in `rc.conf` to a LAN server.

Moving the clock forward twelve years on a live alarm panel will change how
event log entries are stamped, and anything the panel schedules by date. That
is the point of the change, but it is not a silent one.
