# tools

Small things built because the panel did not have them. Each exists because an
hour was lost working around its absence first.

## `peek.c`

Read words out of a running process on the panel.

    musl-gcc -Os -static -o peek peek.c        # on the build VM
    ssh root@panel 'cat > /tmp/peek && chmod 755 /tmp/peek' < peek
    ssh root@panel '/tmp/peek <pid> <hexaddr> [words]'

`/proc/<pid>/mem` refuses a plain read on 2.6.31 and the panel ships no
debugger, which looked like a dead end and is not: `ptrace` is in the kernel and
this is thirty lines. Attach, wait for the stop, `PTRACE_PEEKDATA`, detach.
Read-only, and it always detaches.

Used to settle the console-mode question by reading `GetOperationMode`'s byte
out of the live `/tuxedo`.

## `../tuxelf.py`

Symbol lookup, caller and callee lists, data cross-references and disassembly
for the panel binaries, parsing ELF natively so it needs only python3.

## `../probe/probe.c`

Runs a handful of syscalls on the panel and reports which fail. Answers "will a
binary from this toolchain work here" in seconds instead of a 124 MB flash.

## `busybox`

Not in this directory; built per `../NEUTERED-TOOLS.md`. Supplies `awk`,
`strings`, `ping`, `vi`, `syslogd` and `klogd`, all of which were worked around
by hand for hours before being built in two minutes.
