# Building dropbear for the Tuxedo Touch

**Built and ABI-verified 2026-09-05. Not installed, not tested on the panel.**

The panel ships `/etc/rc.d/init.d/dropbear`, complete and already registered in
`rc.conf`'s service list. It guards on `/usr/sbin/dropbear` existing and
generates its own host key on first start. The vendor removed only the binary.

## Result

| Binary | Size | Type | Flags |
|---|---|---|---|
| `dropbear` | 1,187,028 | `EXEC`, **0 INTERP segments** | `0x5000200` Version5 EABI, **soft-float** |
| `dropbearkey` | 1,023,928 | `EXEC`, **0 INTERP segments** | same |

The panel's own `sbin/hwclock` is `EXEC`, `0x4000002`, Version**4** EABI. EABI
v4 and v5 are accepted by the same kernel loader, and the float ABI matches,
which is the part that would actually break. 2.2 MB combined, against a 124 MB
image.

## Recipe

```bash
apt-get install -y gcc-arm-linux-gnueabi make bzip2
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2022.83.tar.bz2
tar xjf dropbear-2022.83.tar.bz2 && cd dropbear-2022.83

cat > localoptions.h <<'EOF'
#define DROPBEAR_SVR_PASSWORD_AUTH 0
#define DROPBEAR_SVR_PUBKEY_AUTH 1
#define DROPBEAR_CLIENT 0
#define DROPBEAR_SVR_MULTIUSER 1
EOF

./configure --host=arm-linux-gnueabi --disable-zlib --disable-lastlog \
  --disable-utmp --disable-utmpx --disable-wtmp --disable-wtmpx \
  --disable-pututline --disable-pututxline

make PROGRAMS='dropbear dropbearkey' LDFLAGS='-static -no-pie' -j4
```

## Three traps, all hit on the way

1. **`STATIC=1` is not enough.** Dropbear's Makefile drops it, and the build
   comes out `DYN` with an `INTERP` segment — dynamically linked against a
   glibc the panel does not have, and position-independent, which a 2.6.31
   kernel cannot load without an interpreter anyway. Pass
   `LDFLAGS='-static -no-pie'` **on the make command line**. Verify with
   `readelf -l | grep -c INTERP`; it must be `0`.

2. **Do not override `CFLAGS` on the make line.** It wipes the include paths
   the Makefile builds up, and the bundled libtommath fails with
   `fatal error: dbmalloc.h: No such file or directory`. Pass flags through
   `./configure` instead, or not at all.

3. **Password auth cannot be built statically.** `crypt()` is unavailable, and
   the build stops with
   `error: DROPBEAR_SVR_PASSWORD_AUTH requires 'crypt()'`. This is not a
   problem to work around — it is the right configuration. The panel's
   `/etc/passwd` is **empty** and there is no `/etc/shadow`, so there is
   nothing to authenticate a password against. Public-key only, as
   `localoptions.h` above.

## Still required before this would work

- **An account.** `/etc/passwd` is empty. Add e.g.
  `root:x:0:0:root:/:/bin/sh`.
- **`/root/.ssh/authorized_keys`**, shipped in the image, mode 600, with
  `/root/.ssh` mode 700.
- **A pre-generated host key** at `/etc/dropbear/dropbear_rsa_host_key`.
  The init script would generate one, but rootfs writability at boot is not
  proven: `rc.conf` sets `READONLY_FS=""` and the remount-rw line in
  `filesystems` is commented out. Shipping it removes the dependency and keeps
  the host identity stable across reflashes.
- **`DROPBEAR_ARGS`** in `rc.conf`, currently unset. At minimum `-s` to refuse
  password auth at runtime as well as at compile time.

## Unverified

The shipped `/dev` holds only `console`, `initctl`, `mtab`, `null` and `tty`.
Ptys come from `devpts`, mounted at runtime by `mdev`/`udev` and listed in
`/etc/fstab`, but that has not been confirmed. Without a pty, authentication
would succeed and an interactive shell would fail. `scp` and
`ssh <host> <command>` need no pty and would work regardless.

Binaries are in the session scratchpad under `/build/db2`, not committed here.

---

## Image built 2026-09-05, verified, not yet flashed

`app2.hdr`, size 125,389,888, checksum `0xa12a`. Preflight says WOULD PASS.

### What changed from stock

    usr/sbin/dropbear                    added, 1,187,028
    usr/sbin/dropbearkey                 added, 1,023,928
    etc/dropbear/dropbear_rsa_host_key   added, mode 600
    etc/dropbear/dropbear_ed25519_host_key   added, mode 600
    etc/passwd                           created: root:x:0:0:root:/root:/bin/sh
    etc/shadow                           created: root:!:...   ('!' = no password login)
    etc/group                            created
    root/.ssh/authorized_keys            added, mode 600, dir 700
    etc/rc.d/rc.conf                     DROPBEAR_ARGS="-p 22"
    etc/hosts                            OTA redirection block (previous build)
    opt/webserver/Barracuda              lockout + heap patch (previous build)

### Verification

- Round trip: **0 content differences**, metadata identical across 3,493 entries.
- `dropbear` sha256 is byte-identical after the JFFS2 round trip:
  `62d3bfe6906d91be...2460b837`.
- Permissions survived: `/root` and `/root/.ssh` 700, `authorized_keys` and both
  host keys 600.
- Device nodes intact (`console 5,1`, `null 1,3`, `tty 5,0`), 159 symlinks.

### Size

The image grew 1.29 MB, from 124,103,176 to 125,389,888. That matters because
the flasher enforces a limit, so it was decoded from the instruction rather
than assumed:

```
80007e08  mov r1, #1              -> 1
80007e0c  orr r1, r1, #180, #12   -> 188743680
80007e10  cmp r0, r1              -> limit = 188,743,681 = 180.00 MiB
```

At 125 MB the image uses 66% of that. Roughly 60 MB of headroom remains.

### Security posture of this build

Password authentication is impossible three times over: it is compiled out
(`DROPBEAR_SVR_PASSWORD_AUTH 0`), refused at runtime (`-s -g -w`), and the only
account has `!` in its password field. Public key only.

The key is dedicated to this panel rather than reused, so it cannot widen the
blast radius of a key that already unlocks anything else.


---

## Tested under emulation before flashing, and it caught a real bug

`qemu-user-static` plus a `chroot` of the panel's root filesystem runs the real
ARM binary against the real `/etc/passwd`, host keys and `authorized_keys`.

### The bug it caught

The first build set `DROPBEAR_ARGS="-s -g -w -p 22"`, which looked like careful
hardening. Dropbear refused to start:

```
Invalid option -s
```

**Compiling password authentication out removes the flags that disable it.**
`-s`, `-g` and `-w` do not exist in a build with `DROPBEAR_SVR_PASSWORD_AUTH 0`.
Flashing that image would have produced a panel with no SSH at all, and the only
way to find out would have been to flash it.

Corrected to `DROPBEAR_ARGS="-p 22"`. Password auth is already impossible: it is
compiled out, and the sole account carries `!` in its password field.

### What the test proves

```
Dropbear v2022.83                            <- ARM binary executes
LISTEN 0 1000 0.0.0.0:2222                   <- accepts connections
Pubkey auth succeeded for 'root' with ssh-ed25519 key SHA256:ORKzpmMC...
uid=0(root) gid=0(root)                      <- shell runs
Linux ... armv7l GNU/Linux
```

Host keys load. The `Failed loading ... dss_host_key` and `... ecdsa_host_key`
lines are harmless: only RSA and ed25519 are shipped, and dropbear tries all
four by default.

### scp does NOT work, and does not need to

```
sh: line 1: /usr/libexec/sftp-server: No such file or directory
```

Modern OpenSSH `scp` speaks SFTP, and the panel has no `sftp-server`. Rather
than ship another binary, use redirection, which needs nothing that is not
already there:

```bash
# upload
ssh -i ~/.ssh/tuxedo_ed25519 root@<panel> 'cat > /mnt/sd/app2.hdr' < app2.hdr
# download
ssh -i ~/.ssh/tuxedo_ed25519 root@<panel> 'cat /mnt/sd/app2.hdr' > app2.hdr
```

Both **verified byte-for-byte** through the emulated panel with a 200,000-byte
random payload: uploaded, hashed on disk, downloaded, hashed again, all three
matching.

### Reproducing the test

`test_ssh.sh` and `test_xfer.sh` in the session scratchpad. The shape is:

```bash
cp -a root_patched sshtest
cp /usr/bin/qemu-arm-static sshtest/usr/bin/
mount -t proc proc sshtest/proc; mount -t devpts devpts sshtest/dev/pts
mknod sshtest/dev/ptmx c 5 2; mknod sshtest/dev/urandom c 1 9
chroot sshtest /usr/bin/qemu-arm-static /usr/sbin/dropbear -F -E -p 2222
ssh -i <key> -p 2222 root@127.0.0.1 'id'
```

Note the `/dev` nodes. The shipped image has only `console`, `initctl`, `mtab`,
`null` and `tty`; the chroot needs `ptmx` and `urandom` created by hand.

### The pty assumption, now RESOLVED

This was the last unverified thing in the build, so it was checked in the
kernel image rather than left as a caveat. `vmlinux.bin` reports itself as
`Linux version 2.6.31-207-g7286c01`, and it contains:

```
devpts: get root dentry failed
devpts: called with bogus options
/dev/ptmx
Couldn't register /dev/ptmx driver
Couldn't allocate Unix98 ptm driver
Couldn't allocate Unix98 pts driver
```

Those are the failure strings from the kernel's own registration paths, which
only exist when the feature is compiled in. **Unix98 ptys and `devpts` are both
built into this kernel, and `/dev/ptmx` is registered by the kernel itself.**

Together with the `devpts /dev/pts devpts gid=5,mode=620` line already in
`/etc/fstab` and the `devpts` mount in the `mdev`/`udev` init scripts, ptys
will be available at boot. Interactive shells should work, not merely
`cat`-based transfer.

That is a static check, not an observation of the running panel, so it stays
`[CONFIRMED statically]` until someone actually opens a shell.

---

## The first SSH flash did not work, and why

Port 22 was refused after flashing. The panel was otherwise healthy: 80, 443
and 6280 all listening.

**Cause, and it is the same mistake as the `-s` flag.** I put dropbear in
`rc.conf`'s `all_services` and treated "registered in the service list" as
meaning it starts. It is not the list the boot uses. `/etc/rc.d/rcS` line 14:

```sh
services=$cfg_services
```

and

```sh
cfg_services="mount-proc-sys  udev hostname  depmod modules filesystems"
```

Six entries. No dropbear, no `network`, no `settime`, no `inetd`. **`all_services`
is a reference list that nothing iterates.** That also explains why the vendor
removed the `boa`, `inetd`, `dropbear` and `sshd` binaries but kept the scripts:
none of them were ever going to run.

### The actual boot sequence

```
/etc/rc.d/rcS
  1. loop over cfg_services            (six entries, as above)
  2. source ifcfgeth.conf
  3. /etc/rc.d/init.d/network start    <- interfaces come up here
  4. /etc/rc.d/rc.local $mode          <- runs if present and executable
  5. /etc/rc.d/init.d/startup          <- launches /supervis and /tuxedo
```

`startup` is not a service either; `rcS` calls it directly at the end.

### The fix

`rc.local` is the right hook and the vendor's own comment says so: *"This
script will be executed after all the other init scripts. You can put your own
initialization stuff in here."* It runs **after** networking and **before** the
application, which is exactly the window wanted, and appending to it changes no
vendor logic.

The added block is fail-open throughout: every branch ends `|| true`, so a
missing binary, a missing key or a refused bind costs remote access and cannot
stop the panel booting.

### Tested through the real boot path this time

Rather than starting dropbear by hand, `rc.local` is now executed the way `rcS`
executes it — through the panel's own `/bin/sh`, which is ARM `bash`, under
`qemu-user` in a chroot of the patched rootfs:

```
chroot $T /usr/bin/qemu-arm-static /bin/bash -c \
    '. /etc/rc.d/rc.conf; /etc/rc.d/rc.local start'
```

Result:

```
LISTEN 0 1000 0.0.0.0:2222   users:(("dropbear",pid=228,fd=3))
uid=0(root) gid=0(root)
BOOT_PATH_WORKS
```

`rc.local` starts it, it binds, the key authenticates, a command runs. The one
error in the log, `chown: 'user.user': invalid user`, is from the vendor's own
pre-existing block and is harmless — there is no `user` account.

### Image

`app2.hdr`, size 125,397,712, checksum `0x1bfb`. Round trip clean, metadata
identical across 3,493 entries, dropbear byte-identical after the round trip.

### The lesson, which is now three for three on this firmware

Twice in one build I read a mechanism partly and generalised: `-s` looked like
a flag because it is documented as one, and `all_services` looked like the
service list because of its name. Both times the fix was to run the thing
rather than reason about it. **Anything that has to work at boot on this panel
should be executed through `qemu-user` in a chroot first.** It costs two
minutes and it has now caught two failures that would each have cost a flash.

---

## Second SSH flash also failed: `/dev/urandom` does not exist

The `rc.local` fix was correct and necessary, but not sufficient. After
flashing it, port 22 was still refused while the panel was otherwise healthy.

### Cause

**Dropbear opens `/dev/urandom` at startup and exits if it cannot.** The
shipped image's `/dev` contains exactly five entries:

```
console  initctl  mtab  null  tty
```

No `urandom`. No `ptmx`. At boot, `/etc/rc.d/init.d/udev` mounts a **fresh
tmpfs over `/dev`**, creates only `console` and `null` by hand, and then relies
on `udevd` and `udevtrigger` to populate everything else. Whether that produces
`/dev/urandom` on this 2.6.31 system with this udev version was never
established — and it evidently does not, or does not before `rc.local` runs.

### Why the emulation test did not catch it

Because the test created the nodes by hand:

```bash
mknod $T/dev/ptmx c 5 2
mknod $T/dev/urandom c 1 9
```

Those two lines existed to make the chroot work and had the side effect of
hiding the exact dependency that was about to fail. **A test environment
prepared to make the subject work cannot tell you whether the subject works.**

Third partial-read failure in this build; second time the test concealed it.

### Fix

`rc.local` now creates what dropbear needs rather than assuming udev did:

```sh
[ -c /dev/urandom ] || mknod /dev/urandom c 1 9 2>/dev/null || true
[ -c /dev/random ]  || mknod /dev/random  c 1 8 2>/dev/null || true
[ -c /dev/ptmx ]    || mknod /dev/ptmx    c 5 2 2>/dev/null || true
mount -t devpts devpts /dev/pts 2>/dev/null || true
```

Each is conditional and each swallows failure, so if udev did create them the
lines are harmless.

It also **logs to `/opt/tuxedo/configuration/dropbear.log`** instead of
discarding output. That partition survives a reflash, so a future failure
leaves evidence that can be read once SSH works, rather than vanishing.

### Retested with a bare `/dev`

The new test starts from `/dev` exactly as the image ships it and pre-creates
nothing:

```
=== /dev before rc.local ===
console initctl mtab null tty

=== /dev after rc.local ===
console initctl mtab null ptmx pts random tty urandom

--- rc.local starting dropbear Sat Sep  5 22:06:22 UTC 2026 ---
crw-rw-rw- 1 root root 5, 2 /dev/ptmx
crw-rw-rw- 1 root root 1, 9 /dev/urandom
--- dropbear invocation returned 0 ---

listening: YES
uid=0(root) gid=0(root)
NO_PREBUILT_DEV_NEEDED
```

### Image

`app2.hdr`, size 125,397,712, checksum `0xeca8`. Round trip clean, metadata
identical across 3,493 entries.

### Note on the "nothing new to apply" reflash

A second flash of the same image booted straight through without programming
anything: the flasher tracks what it applied and skips unchanged content. A
failed attempt cannot be retried with the identical card; each attempt needs a
different image.

---

## Ending the reflash cycle

Reflashing by hand is the expensive part of this work: build a 125 MB image,
write a card, carry it to the panel, power-cycle, and find out afterwards
whether it worked. Three attempts so far, two of them wasted.

**SSH is what ends that**, and `ssh/tuxedo_remote.py` is the tool that uses it:

```bash
python tuxedo_remote.py info                       # mounts, partitions, free space
python tuxedo_remote.py get /etc/rc.d/rc.local ./rc.local
python tuxedo_remote.py put ./rc.local /etc/rc.d/rc.local --mode 755 --backup
python tuxedo_remote.py backup ./panel-backup/     # pull the files worth keeping
```

A change that previously meant a card and a walk becomes a verified file copy.

Three deliberate properties:

- **It refuses `scp`'s job the hard way.** The panel has no `sftp-server`, so
  modern `scp` fails. Everything goes through `ssh host 'cat > file'`.
- **Every write is verified before it replaces anything.** Content goes to a
  `.part` name, the byte count and hash are checked from the panel side, and
  only then is it renamed. A dropped connection cannot leave a truncated file.
  That is the same reasoning as the SD path, where a truncated component is the
  one failure the header checksum cannot catch.
- **It will not write `/tuxedo`, `/supervis` or `Barracuda`.** Those stay on the
  SD path, where a mistake is recoverable by reflashing. A bad write to the
  alarm application over SSH could remove the very access needed to fix it.

If `/` turns out to be mounted read-only, `put --remount` issues
`mount -o remount,rw /` first rather than assuming either way.

---

## Third revision: the log that would have told us nothing

An adversarial review of the `rc.local` block, run before flashing rather than
after, found three real defects. Two of them would have made a fourth failed
attempt as uninformative as the first three.

### 1. Dropbear logs to syslog, and no syslogd runs here [CONFIRMED]

`opts.usingsyslog` defaults to 1, and with `DEBUG_TRACE` off dropbear writes
**nothing** to stderr. `syslog` appears in `rc.conf`'s `all_services` but not in
`cfg_services`, so no syslogd is ever started on this panel.

The log would therefore have contained only the block's own `echo` lines, on
every boot, **identical whether dropbear started or died**. Every message that
would actually diagnose a failure — `Failure reading random device
/dev/urandom`, `No listening ports available`, host key load errors — goes to
syslog and vanishes. All of them are emitted *before* daemonising, so they are
reachable.

**Fix:** `DROPBEAR_ARGS="-p 22 -E"`. `-E` sends logging to stderr, which is
where the block already redirects.

### 2. The log target gated the daemon [CONFIRMED, was BLOCKS_SSH]

`/usr/sbin/dropbear $ARGS >> $DBLOG 2>&1 || true` makes the **log redirect** a
precondition for running dropbear. When a redirection cannot be opened, the
shell never executes the command, and `|| true` erases the evidence. If
`/opt/tuxedo/configuration` were unwritable — full, remounted read-only after
ECC errors, or failing to mount — SSH would silently not start.

The block's own comment claimed "fail-open throughout". This was the one line
where the fail-open ran backwards: the failure of the logging prevented the
thing being logged.

**Fix:** resolve the target once, with fallbacks, before anything uses it:

```sh
DBLOG=/opt/tuxedo/configuration/dropbear.log
: >> $DBLOG 2>/dev/null || DBLOG=/tmp/dropbear.log
: >> $DBLOG 2>/dev/null || DBLOG=/dev/null
```

### 3. `$?` after `|| true` always reads 0 [CONFIRMED]

The one line meant to report whether dropbear started would have said
`returned 0` even when it exited immediately. Capture the status before the
`||` consumes it. Dropping `|| true` there is safe: there is no `set -e`
anywhere under `/etc/rc.d`, and `rcS` ignores `rc.local`'s exit status.

### Also fixed

With `-E` the daemon holds the log fd open for its lifetime, so the first write
now truncates (`>` not `>>`) and the log holds exactly the most recent boot.
And the block is guarded on `$1 = start`, because `inittab` runs
`rcS stop` at runlevel 0 and the block was also executing at shutdown, after
`umount -a -r`.

### What the review confirmed was already fine

No CRLF anywhere on the boot path, which is the classic failure for a repo
living on a Windows host. No `set -e` or `set -u` under `/etc/rc.d`, so no line
can abort `rc.local`. No construct in the block can hang, which matters because
`rc.local` runs *before* the alarm application starts and a hang would mean the
panel never comes up. Account and key permissions pass dropbear's strict
checks. The binary is static, so glibc 2.5 is irrelevant.

---

## A self-inflicted detour worth recording

Partway through, one of the chroot test harnesses overwrote the **build
distro's own system binaries** with the panel's ARM ones. `ls`, `df`, `head`,
`dpkg` and `apt` all became ARM binaries; in-place repair was impossible
because the package manager itself was among the casualties.

Nothing outside the build environment was affected: the panel, the SD card and
this repository were untouched.

Recovery, in order:

1. **Salvage first.** `cat` still worked, so the built artifacts were copied out
   through `/mnt/c` using only shell redirection. The rescued `dropbear`
   hashes to `62d3bfe6906d91be…2460b837`, identical to the verified build, so
   no recompilation was needed.
2. Unregister and reinstall the distro.
3. Reinstall the toolchain. Two traps here: WSL resolved the Debian mirrors to
   IPv6 only with no IPv6 route, so `apt` failed while DNS looked healthy; and
   `qemu-user-static` does not register its binfmt handler without
   `binfmt-support` or systemd, neither of which runs in WSL, so chrooted ARM
   binaries report `cannot execute binary file` until it is registered by hand.
4. Re-extract from the stock image and rebuild.

**The lesson for the harnesses:** a test that copies a foreign root filesystem
around should never be able to reach the host's own `/`. The chroot scripts now
in the scratchpad build under `/work/<name>` with an explicitly set variable,
but the real protection would be to run them in a container or a throwaway
distro rather than the one holding the toolchain.

---

## v4 flashed, port 22 still refused

Web server, 80, 443 and 6280 all up. So `rcS` reached `startup`, which means
`rc.local` ran. Dropbear is therefore either absent or exited.

Those are indistinguishable from outside, and the log v4 writes to
`/opt/tuxedo/configuration` cannot be read without the SSH it is trying to
start.

## v5/v6: diagnostics on the SD card

The card can be pulled and read. v5 writes the same log to
`/mnt/sd/tuxedo-boot.log`, retrying for ten seconds in case the card is not
mounted when `rc.local` runs.

It records, before starting dropbear:

    ls -l /usr/sbin/dropbear /usr/sbin/dropbearkey
    ls -l /etc/dropbear/
    ls -l /root/.ssh/authorized_keys
    cat /etc/passwd
    DROPBEAR_ARGS
    grep -E ' / |mtdblock|/mnt/sd' /proc/mounts

and after:

    dropbear's own stderr (via -E)
    its exit status
    netstat -ltn | grep ':22 '

The block is tagged `IMAGE TAG v5` so the log identifies which image produced
it. If the tag is absent from the card, the image did not apply.

v6 also records `md5sum /opt/webserver/Barracuda`, which answers a larger
question in the same pass: **whether any patched image has ever been applied.**

| md5 | meaning |
|---|---|
| `324209e1fdfe2d61925a1bb4a7115452` | stock Barracuda; no image of ours has ever applied |
| `197b7e41daeedd849d6353bd0fb26059` | patched; the lockout fix is live |

That matters because the lockout patch was never confirmed either. If the log
shows the stock hash, every flash so far has been a no-op and the problem is
the flasher skipping the image, not the `rc.local` block.

Image: 125,397,712 bytes, checksum `0x78e8`.

### Procedure

1. Flash.
2. Power down, pull the card, read `tuxedo-boot.log`.

That answers, in one pass: whether the image applied, whether the binary is
present and executable, whether the keys and account are right, and what
dropbear said before exiting.

### Where "nothing new to apply" came from

Searched `ProgCV` for it: no such string. The flasher has no
"already up to date" message. What was seen on the panel was its normal boot,
i.e. the programmer either did not run or ran without displaying anything.

`ProgCV` is loaded by `seconboot`, not by Linux, so a flash that does nothing
looks identical to a normal boot from outside. The only strings it has in this
area are the type-mismatch ones:

    Hardware Version is New ,But Critical file app1.hdr is old type
    Hardware Version is Old ,But Critical file app1.hdr is new type

and `0x800004d8` turns out to be the platform-tag matcher (TEST, 6280,
6280PLUS, INNOVA, INNOVAPLUS, TUXEDO, TUXEDOPLUS, LINUXINNOVA, MSGW,
TUXEDOPLUSR2, TUXEDOPLUSVA, TUXEDOPLUSMSR2, TUXEDOPLUSMSVA), not a version
comparison. Our header carries `TUXEDOPLUSVA` unchanged, so it matches.

No skip-if-same-version logic has been found. That does not prove none exists,
which is why v6 records the Barracuda hash rather than continuing to reason
about it.

---

## Version tracking

`/etc/tuxedo-build` is written into every image:

```
BUILD=v6
BUILT=2026-09-05T23:22:34Z
BASE=TUXW_V5.3.21.0_VA
BARRACUDA_MD5=197b7e41daeedd849d6353bd0fb26059
DROPBEAR_MD5=642b6a1040e90c175bdb783b41493042
CHANGES=lockout-patch,heap-fix,ota-hosts-block,ssh
```

`rc.local` cats it into the boot log, so the log identifies its own image.
Stock has no such file, so its absence is also an answer.

Image: 125,397,712 bytes, checksum `0x02f5`.

## Reading the version over HTTP: not possible without patching Barracuda

`installVirtualDir` (`0x14598`) binds three **disk-backed** directories:

| Root | URL prefix |
|---|---|
| `/tmp/` | `VideoFiles` |
| `/mnt/sd` | `Videos` |
| `/opt/tuxedo/configuration/` | `Config` |

`DiskIo_constructor` at `0x1480c`, `0x14870`, `0x148d4`, each followed by
`DiskIo_setRootDir` and `HttpResRdr_constructor`, then
`HttpServer_insertDir` (`0x6e8ac`).

`/opt/tuxedo/configuration/` being bound to `Config` would have been ideal: the
boot log is written there, so it could be fetched without SSH or pulling the
card.

**They do not serve.** Tested live with a valid session, on 443, 80 and 6280:
every known-present file under `/Config/` returns 404
(`webuseraccountsenc.json`, `Tuxedo.json`, `registereddevMAClist.json`,
`CRCdata.json`, `ipupdate.txt`). `/VideoFiles/` and `/Videos/` likewise. A
name that does *not* exist returns 302 to itself with a trailing slash, which
is the only response that differs.

So the directories are installed but something downstream refuses to serve
them, and the web application is a size-locked ZIP embedded mid-ELF, so a new
page cannot be added either. Serving the version over HTTP would mean patching
`Barracuda`.

The boot log on the SD card remains the delivery path.
