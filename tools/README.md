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

Two escaping notes, both of which cost a rebuild: `'
'` and `'\'` written
through a Python-to-shell-to-C chain collapse into a literal CR and an
unterminated character constant. The source now uses `0x0d` and `0x5c`
directly, which cannot be mangled by any layer above it.

## `../tuxelf.py`

Symbol lookup, caller and callee lists, data cross-references and disassembly
for the panel binaries, parsing ELF natively so it needs only python3.

`callers()` and `calls()` count **tail calls** -- a `b` into another function,
not just `bl`. This is not a refinement, it is the difference between the tool
working and not. Both binaries reach a great deal of code by tail call: Qt moc
dispatch branches into slots from a jump table, and Barracuda's interface
vtables are 4-byte thunks that `b` to the real body.

Measured over every function symbol, functions with no `bl` caller that DO have
a tail-call caller:

| binary | symbols | rescued by counting tail calls |
|---|---:|---:|
| `tuxedo` | 10585 | 1567 |
| `Barracuda` | 2016 | 177 |

So a BL-only scan called 1744 reachable functions uncallable. It reported every
digit key on the touchscreen keypad as dead, and it put a false "dead code"
claim into three documents (see TUXEDO-LOCKOUT-PATCH.md). Treat any "no callers"
conclusion predating this fix as unverified.

Pass `tails=False` to either method for the old behaviour.

## `../probe/probe.c`

Runs a handful of syscalls on the panel and reports which fail. Answers "will a
binary from this toolchain work here" in seconds instead of a 124 MB flash.

## `busybox`

Not in this directory; built per `../NEUTERED-TOOLS.md`. Supplies `awk`,
`strings`, `ping`, `vi`, `syslogd` and `klogd`, all of which were worked around
by hand for hours before being built in two minutes.
