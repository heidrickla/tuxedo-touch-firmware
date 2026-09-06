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

## `panelstated.c`

Serves the panel's ECP link state over HTTP, so a client can learn it on a
transport independent of its own push stream.

    musl-gcc -Os -static -o panelstated panelstated.c
    panelstated [listen_port] [panel_host]      # defaults 8088, 127.0.0.1

    GET / -> {"talking":true,"code":1,"status":"Ready To Arm","age_s":32,
              "stream":"up","frames":2,"raw":"0:21:1:fe:þ1Ready To Arm:2"}

**Why it exists.** Field 2 of a push frame is `-1` whenever `PanelIsTalking()`
is false, and that is the only place the link state appears.
`GetSecurityStatus` reads the same ECP-fed cache and keeps answering the last
thing in it, so a client whose stream has died cannot tell "panel healthy,
stream dropped" from "panel still blind" and has to fail closed.

It holds the stream itself and reports what it sees. It patches nothing; it is
another reader of the same stream. The raw frame is served verbatim, escaped for
JSON, so a consumer can run one decoder rather than trusting the fields picked
out here.

Built and verified against the live panel from the build VM under qemu. **Not
installed on the panel**, and not a dependency of anything: the Home Assistant
integration is a public HACS repo and cannot require a daemon that exists in one
house.

Two escaping notes, both of which cost a rebuild: `''` and `'\'` written
through a Python-to-shell-to-C chain collapse into a literal CR and an
unterminated character constant. The source now uses `0x0d` and `0x5c`
directly, which cannot be mangled by any layer above it.

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
