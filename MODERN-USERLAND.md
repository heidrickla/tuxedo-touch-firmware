# Can the panel run modern libraries?

Answering it with measurements on the hardware rather than argument.

**Yes for anything we add. No for the vendor's own binaries.** Those are two
different questions and they have different answers.

## Measured on the panel, 2026-09-06

The same probe source (`probe/probe.c`), three toolchains, run on the panel over
SSH:

| Call | glibc 2.41 static (trixie) | glibc 2.5 dynamic (panel's own) | **musl 1.2.5 static** |
|---|---|---|---|
| `clock_gettime(MONOTONIC)` | ok | ok | ok |
| `clock_gettime(REALTIME)` | ok | ok | ok |
| `gettimeofday` | ok | ok | ok |
| `socket` / `bind` / `listen` | ok | ok | ok |
| `select` | **ENOSYS** | ok | **ok** |
| `fcntl` | ok | ok | ok |

Then the real thing, not a toy. dropbear 2022.83 built against musl 1.2.5,
static, 413,288 bytes, no `INTERP` segment, run on the panel on a temporary
port:

    listening        0.0.0.0:2223
    authentication   public key, uid=0(root)
    command exec     ok, uname -m = armv6l
    interactive pty  ok, tty = /dev/ttyp0

Removed afterwards; the panel is back to its six listeners.

musl 1.2.5 was released in 2024. It runs correctly on a 2017 build of Linux
2.6.31 on an ARM1136. The kernel is not the obstacle people assume it is.

## Why musl works where glibc 2.41 does not

Both use 64-bit `time_t` on 32-bit ARM. The difference is the fallback. musl
issues the time64 syscall, sees `ENOSYS`, and retries the legacy one. Debian
trixie's armel glibc declares a minimum kernel new enough that the legacy path
is compiled out, so `select` has nothing to fall back to. Everything else in
glibc has a fallback, which is why only `select` failed.

## What this changes

The v8 recipe, a bullseye chroot linking against a sysroot of the panel's own
libraries, works but is fragile: symbol-version archaeology, a hand-written
`libc.so` linker script, `--disable-largefile`, an `__isoc99_sscanf` shim, and
four `ac_cv_func_*` overrides. All of that exists to bridge glibc 2.31 headers
to a glibc 2.5 library.

musl static needs none of it:

    ./configure --target=arm-linux-gnueabi CC=arm-linux-gnueabi-gcc \
        --prefix=/build/musl/out --disable-shared
    make && make install
    musl-gcc -Os -static -o prog prog.c

**Prefer musl static for anything new.** It costs size (dropbear 413 KB against
233 KB) and 57 MB is free, so size is not a constraint. It buys a current libc,
no dependency on the panel's `/lib`, and a build that does not need the panel's
filesystem present to link.

## What cannot be modernised

| Thing | Why not |
|---|---|
| `/tuxedo`, 14.6 MB | Closed source, links glibc 2.5, and is the panel application. Nothing replaces it |
| `/opt/webserver/Barracuda`, 5.7 MB | Closed source, links glibc 2.5, serves the whole web UI from a ZIP embedded mid-ELF |
| `/lib/*.so`, glibc 2.5 | Cannot be upgraded while the two binaries above need it. A newer glibc could sit alongside under another prefix, but nothing would gain by it |
| The kernel | mtd13-15 are three 3 MB slots and the flasher does program them, but the drivers (`mxc_ts`, `mc13892`, `fb0`, i2c, led, audio) are vendor out-of-tree code for 2.6.31 with no upstream. Replacing it means porting them blind, with a bricked keypad as the failure mode |

So "rebuild it with modern libraries" cannot mean replacing the userland. It
can mean: every tool **we** add is built with a current libc, statically, and
does not touch the vendor's. That is already true of ntpclient and can be true
of dropbear from v10.

## Next

Rebuild dropbear and ntpclient against musl for v10 and drop the glibc 2.5
sysroot from the build path. Keep `ssh/BUILD.md` as the record of why the
sysroot route existed, since it is what proved the diagnosis.
