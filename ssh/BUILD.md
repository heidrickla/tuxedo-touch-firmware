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

`app2.hdr`, size 125,389,888, checksum `0x473b`. Preflight says WOULD PASS.

### What changed from stock

    usr/sbin/dropbear                    added, 1,187,028
    usr/sbin/dropbearkey                 added, 1,023,928
    etc/dropbear/dropbear_rsa_host_key   added, mode 600
    etc/dropbear/dropbear_ed25519_host_key   added, mode 600
    etc/passwd                           created: root:x:0:0:root:/root:/bin/sh
    etc/shadow                           created: root:!:...   ('!' = no password login)
    etc/group                            created
    root/.ssh/authorized_keys            added, mode 600, dir 700
    etc/rc.d/rc.conf                     DROPBEAR_ARGS="-s -g -w -p 22"
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
