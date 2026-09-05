# Upload handler

An optional way to put firmware on the panel's SD card over the network,
instead of carrying the card to a PC.

**Not installed. Not tested against a panel.** This is a worked design, not a
deployed one.

## Why this shape

The web server has no upload capability at all — no multipart parser, no
`Content-Disposition`, nothing. Adding one means hand-assembling a parser and a
URI handler into `Barracuda` and adding a page to a ZIP embedded mid-ELF that
cannot change size.

`inetd` avoids all of that. The vendor shipped the init script and removed the
binary, and the userland already has full `bash`, `dd` and `cat`. So the whole
change is one small binary and two text files.

## Files

| File | Goes to | Notes |
|---|---|---|
| `tuxedo-upload.sh` | `/usr/sbin/tuxedo-upload.sh`, mode 755 | the handler |
| `inetd.conf.example` | one line appended to `/etc/inetd.conf` | |
| *(not supplied)* | `/usr/sbin/inetd` | static **armel** binary, see below |

The `inetd` binary must match the panel's ABI: **ARM EABI, soft-float
(`armel`), statically linked**. `armhf` will not run. Full detail in
`TUXEDO-NTP-PROPOSAL.md`, which needs a binary under the same constraints.

## Use

    curl -H "X-Upload-Key: <secret>" -T app2.hdr http://<panel>:8081/app2.hdr

## What it deliberately will not do

It writes to the **SD card only**, never to flash. It cannot reprogram the
panel on its own — the panel still has to be rebooted with the card present.
That separation is the point, and it should stay.

## Before installing it, read this

This puts a writable network service on an alarm panel. `TUXEDO-AUDIT-BUGS.md`
section (b) lists nine findings on the interface that already exists; this is a
tenth surface, added on purpose.

- **No TLS.** The secret and the firmware cross the network in clear.
- **The secret is plain text** in a file on the panel, compared literally.
  There is no hashing tool in this userland. It is a speed bump, not a control.
- **No rate limit** beyond `inetd`'s `nowait.2` concurrency cap.
- Bind it to the LAN. Do not expose it.

It also does not bootstrap itself: installing it needs one SD flash. It trades
one manual flash now for easier ones later.

## Design detail worth keeping

The handler writes to `.<name>.part` and renames only after the byte count
matches `Content-Length`. A connection that dies mid-transfer must not leave a
truncated file where the flasher will find it. A truncated component is the one
failure mode the header checksum does not catch, because a file whose length
happens to agree with its header would be flashed as-is.

---

## Superseded by SSH, if you take that route

`/etc/rc.d/init.d/dropbear` is already present and complete. It guards on
`/usr/sbin/dropbear`, generates its own host key on first start, and is already
registered in `rc.conf`'s service list — the same pattern as `boa` and `inetd`:
script shipped, binary removed.

SSH is better than this upload handler on every axis. It is encrypted rather
than clear, key-authenticated rather than a plain-text shared secret, and `scp`
replaces the whole handler while also giving a shell for diagnosis. If SSH goes
in, **delete this directory**; keeping both is two attack surfaces for one
capability.

The strongest argument is what it would have changed today. The one task this
project could not finish was confirming the login-lockout patch, because the
failure counter lives in `webuseraccountsenc.json` on `mtdblock17` and there is
no way to read it remotely. With a shell that is `cat`, and the test becomes
safe instead of a gamble on unreadable state.

### Three things SSH needs that the upload handler did not

1. **There are no accounts.** `/etc/passwd` is **empty** and there is no
   `/etc/shadow`. Dropbear has nothing to authenticate against. An account has
   to be added to the image, e.g. `root:x:0:0:root:/:/bin/sh`.

2. **Use public-key auth only.** Ship `/root/.ssh/authorized_keys` in the image
   and disable password auth in `DROPBEAR_ARGS` (`-s`, plus `-g` to refuse
   root password login). That removes the plain-text-secret problem this
   handler has rather than repeating it.

3. **Pre-generate the host key; do not rely on the runtime write.** The init
   script writes to `/etc/dropbear` on first boot, but rootfs writability is
   not proven: `rc.conf` sets `READONLY_FS=""` and the remount-rw line in
   `filesystems` is commented out with the note that the kernel already does
   it. Shipping the key in the image removes the dependency and makes the host
   identity deterministic across reflashes.

### One risk to check before trusting an interactive shell

The shipped `/dev` contains only `console`, `initctl`, `mtab`, `null` and
`tty`. Ptys come from `devpts`, mounted at runtime by the `mdev`/`udev` scripts
and listed in `/etc/fstab`. That should be enough, but it has not been
verified, and without a pty `dropbear` will authenticate and then fail to give
a shell. `scp` and `ssh <host> <command>` do not need a pty, so those would
work even if interactive sessions did not.
