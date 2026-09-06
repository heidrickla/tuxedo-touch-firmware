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

## Know which binary you are reading

**The live panel runs v12 and has ALL EIGHT patches applied.** Any `Barracuda`
or `tuxedo` sitting in a scratch directory is a historical snapshot from some
earlier build — it is not what the panel is running, and it should never be
reasoned about as though it were.

**Every conclusion about "what the stock firmware does" is only as good as the
copy it was read from, and the copies are easy to confuse.** This has already
produced one wrong published claim: the threat model said three failed logins
permanently disable every web account on this panel, because the reference copy
used for the analysis already had P1 applied and looked like the shipped state.

Known `Barracuda` md5s:

| md5 | what it is |
|---|---|
| `324209e1fdfe2d61925a1bb4a7115452` | **genuine stock**; no image of ours has ever applied |
| `197b7e41daeedd849d6353bd0fb26059` | v9/v10 era — carries **P1, P2, P6**; NOT stock |
| `d14a3358b10007dc6bbde63fa0959bb9` | v11 — adds P8 |
| `c8971027bb9f77801d01713b4ae50b2f` | **v12 — what the panel runs now**; adds P11, P12 |

`/tuxedo`: `6f8055f5cadba9d0b1582297606427a8` is pre-P10;
**`98370c310e709ba565abfce8ea0a3e17` carries P10 and is what the panel runs.**

When in doubt, ask the panel rather than a file:
`./verify-panel.sh` checks all eight sites against the running unit.

**Check before you conclude**, in one command:

```bash
python apply-patches.py --check --root <tree-with-the-binary> --table patches.tsv
```

It reports each site as already patched, STOCK, or unrecognised, so "is this the
stock behaviour?" stops being a guess. Do this before writing anything of the
form *"stock firmware does X"* — especially in the regions P1, P2 and P6 touch,
where the commonly-used reference copy is already patched.

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
