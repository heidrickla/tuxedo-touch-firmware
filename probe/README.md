# libc/kernel probe

Minimal replication of the bug that cost five flashes. One source file, built
two ways, run on the panel.

    A. trixie glibc 2.41, static      the recipe used for v1-v7 dropbear
    B. bullseye headers against the
       panel's glibc 2.5, dynamic     the recipe used from v8

## Result, on the panel, 2026-09-06

| Call | A, glibc 2.41 static | B, glibc 2.5 dynamic |
|---|---|---|
| `clock_gettime(CLOCK_MONOTONIC)` | ok | ok |
| `clock_gettime(CLOCK_REALTIME)` | ok | ok |
| `gettimeofday` | ok | ok |
| `socket` / `bind` / `listen` | ok | ok |
| **`select`** | **FAIL errno=38 ENOSYS** | ok |
| `fcntl` | ok | ok |

Both binaries exited 0; the failures are per-call.

## musl

A third build, musl 1.2.5 static, passes every call including `select`. musl
issues the time64 syscall, sees `ENOSYS` and retries the legacy one; trixie's
glibc has that fallback compiled out. See `../MODERN-USERLAND.md`.

## What this corrects

The first write-up said modern glibc issues "time64 syscalls the 2.6.31 kernel
does not have", listing `clock_gettime64`, `gettimeofday64` and `fcntl_time64`
alongside `select64`. Measured, that is too broad. glibc's fallbacks work for
`clock_gettime`, `gettimeofday` and `fcntl`. **`select` is the only one that
fails**, and it fails with `ENOSYS`, not with a wrong result.

That is exactly enough to kill dropbear. `svr-main.c` treats a negative `select`
with `errno != EINTR` as fatal and calls `dropbear_exit("Listening socket
error")`, which is what the panel logged. `ENOSYS` is 38, not 4.

Inferred, not measured: Debian trixie's armel port is 64-bit `time_t` and
declares a minimum kernel new enough that glibc is built without the legacy
`pselect6` fallback, so `__select64` issues `pselect6_time64` (ARM 413, Linux
5.1+) with nothing to fall back to. The measurement stands on its own either
way.

## Build and run

Build A on a trixie host:

    arm-linux-gnueabi-gcc -Os -static -no-pie -o probe_trixie probe.c

Build B inside the bullseye root, against the sysroot of the panel's libraries
described in `../ssh/BUILD.md`:

    arm-linux-gnueabi-gcc -Os -fno-stack-protector -U_FORTIFY_SOURCE -fno-PIE \
      -o probe_glibc25 probe.c \
      -no-pie -L/work/sysroot/lib -Wl,-rpath-link,/work/sysroot/lib -lrt

Ship and run. `/tmp` is tmpfs, so nothing persists:

    cat probe_x | ssh root@203.0.113.5 'cat > /tmp/probe_x && chmod 755 /tmp/probe_x'
    ssh root@203.0.113.5 /tmp/probe_x
    ssh root@203.0.113.5 rm -f /tmp/probe_x

Run this before trusting any new toolchain against the panel. It is far cheaper
than a flash.
