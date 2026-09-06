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
