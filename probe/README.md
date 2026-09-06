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

## A static syscall gate looks attractive and does not work

The panel's `sys_call_table` is in the shipped vmlinux at file offset `0x7bee4`
(vaddr `0xc0083ee4`). It holds 368 entries: 0-363 are real, 364-367 are
`sys_ni_syscall`. Verified directly. So the kernel's ceiling is **363**, and the
ARM time64 syscalls start at 403.

That invites an obvious CI check: disassemble a staged binary, walk back from
each `svc #0` to the last write to `r7` (immediate move, or a PC-relative
literal load for numbers too large to encode), and fail anything above 363.

It was built and it does not work. Measured against binaries whose behaviour on
the panel is known:

| Binary | Works on the panel | High syscalls found |
|---|---|---|
| glibc 2.41 static | **no** | 384, 397, 398, 403, 422 |
| musl 1.2.5 static | **yes** | 403 |
| dropbear on musl | **yes** | 369, 387, 397, 403 |
| glibc 2.5 dynamic | yes | none; no `svc` sites at all |

musl issues syscall 403 too. The difference is not which syscalls a binary
contains, it is whether it **retries the legacy one on `ENOSYS`**, and that is
not cheaply decidable from the instruction stream. A gate on the syscall number
fails every working musl binary.

Two smaller traps in the same attempt: the ARM private syscall base is
`0x0F0000` (`cacheflush` = `0xf0002`, `set_tls` = `0xf0005`), not the OABI
`0x9F0000`, so those show up as syscalls 983042 and 983045 unless excluded. And
a dynamically linked binary has no `svc` sites of its own, so the check has
nothing to inspect and passes it vacuously; such a binary is safe by
construction anyway, because its syscalls happen inside the panel's own libc.

**Run the probe on the hardware instead.** It takes seconds, it answers the
question the gate was trying to approximate, and it cannot be fooled by a
fallback path.
