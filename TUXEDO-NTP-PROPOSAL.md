# Setting the clock from NTP: what the panel already has

Answering a request for the next firmware build: can the panel set its own
date and time instead of coming up in 2013?

**Short answer: the vendor already built the entire mechanism and shipped it
switched off.** Two small things are missing. Neither requires touching a
binary.

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
   program; against a 124 MB image the size is immaterial.
2. Set `NTP_SERVER` in `/etc/rc.d/rc.conf`.

No binary patching, no new init script, no change to the boot order.

There is no busybox on this system at all, so there is no applet to enable and
no `ntpd`, `ntpdate`, `rdate` or `sntp` anywhere in the image. The client has
to be added.

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

1. Add `/bin/ntpclient`, static, in the next image.
2. Set `NTP_SERVER` in `/etc/rc.d/rc.conf` to a **LAN IP address**.
3. Change nothing else. Do not touch the boot order, do not remove the
   fallback date, do not make the boot wait on the network.
4. Treat the AES-key improvement as a **separate, later decision**. It needs
   the key store edited and every REST client re-registered, and the
   integrity-twin behaviour tested first. Do not bundle it with a clock fix.

Item 4 is the one worth being slow about. Items 1 to 3 are a two-file change
to a mechanism the vendor already wrote.
