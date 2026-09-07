# Running Barracuda under emulation

`docs/TRAPS.md` section 6 requires anything boot-critical to be executed under
`qemu-user` before it is flashed. `ssh/BUILD.md` documents that recipe for
`dropbear`. Barracuda needs three things dropbear does not, and each one fails
in a way that looks like something else.

This rig was built to answer two questions about the P13 push-stream patch that
`docs/PUSH-STREAM-AUTH.md` had recorded as unanswerable before a flash. It answered
both, and it did so without spending any of the panel's 24-relaunch watchdog
budget.

## Use

On the build VM, as root, with a rootfs tree extracted from an image:

```bash
sudo bash run.sh   /work/emu/v12 v12     # start, probe, stop
sudo bash serve.sh /work/emu/p13 p13     # start and LEAVE RUNNING for an
                                         # external client to drive
```

`run.sh` prints one line per probe and asserts the process answering is the one
it started. `serve.sh` leaves the server up so a real client can log in against
it — the whole authenticated path can then be exercised from a workstation:

```bash
python test-stream-auth.py --host <vm> --creds <file> --compare before.json
```

### `renewal-test.sh` — the one test that needs a server you can break

`tuxweb`'s session-renewal path fires only on an upstream `401`, and on the live
panel there is no way to produce one on demand: logging in from another host does
not void an existing session, and the only alternative is restarting Barracuda on
a running alarm panel. Here a restart is free, and P13's gate runs in
`EhDir_service` before any IPC, so the emulated server rejects a stale cookie
exactly as the panel does.

```bash
# once, on the build VM
cargo build --release && cp target/release/tuxweb /tmp/tuxweb-host   # host x86, NOT ARM
cp emu/probe.py /tmp/probe.py
cp emu/serve.sh /work/emu-serve.sh
printf '%s' "$PANEL_PASSWORD" > /tmp/pw && chmod 600 /tmp/pw

sudo bash /work/renewal-test.sh
```

It starts the P13 tree, proves a client is served, restarts Barracuda under it,
and asserts the shim reconnects with its spaced backoff and logs in again.
Result recorded in `docs/WEBSERVER-REPLACEMENT.md`. Two things it does **not** prove:
a session the panel expired by itself, and frames after renewal — there is no
`/tuxedo` here, so the stream carries no alarm state either way.

## The panel configuration is required

Barracuda starts without it but its init fails and it serves nothing — the
rootfs image ships an empty `/opt/tuxedo/configuration` because that path is
`mtdblock17` on the panel.

The canonical copy lives on the build VM at **`/work/panel-config`** and is
meant to stay there. `run.sh` and `serve.sh` seed a tree from it automatically.
Refresh it from the panel with:

```bash
./fetch-config.sh                 # panel -> /work/panel-config on the VM
```

`tls/` is excluded (the panel's private key is reissued from the owner CA, not
copied around) along with the two large logs.

**Do not delete `/work/panel-config` or the emulation trees.** They are
persistent infrastructure. See `../TRAPS.md` §5.

## The three traps

### 1. It binds all four ports and then answers nothing

Not a crash, and not a config problem. `qemu-arm-static -strace` ends at:

```
mq_timedsend(7,0x40800974,404,1,(nil))        <- no return: blocked
```

Barracuda sends 404-byte messages to `/Q_ServCmdRcver` for `/tuxedo` to read.
Under emulation there is no `/tuxedo`, the queue reaches `cur=32`, and the main
thread blocks in `mq_timedsend` forever. The socket dispatcher never reaches
`accept()`, so connections complete the TCP handshake — `connect()` succeeds —
and then sit in the backlog. Every client sees a silent hang.

`mqdrain.py` fixes it: it opens the queues and receives in a loop, discarding.
It never replies, so no alarm-state frames are produced. That is fine for
testing authentication, which happens in `EhDir_service` before any IPC.

The queues must be mounted at **`/dev/mq`**, which is where the panel's own
startup script puts them — not the conventional `/dev/mqueue`.

### 2. A stale process silently answers for the tree you think you are testing

This one produced three confident, wrong results in a row.

A diagnostic run started as `qemu-arm-static -strace /opt/webserver/Barracuda`
survived `pkill -f "qemu-arm-static /opt/webserver/Barracuda"`, because that
pattern does not match a command line with `-strace` in the middle. It kept all
four ports. Every later run failed to bind and exited, and the **stale unpatched
binary answered every probe** — so a patched build appeared to change nothing.

`run.sh` therefore asserts, after startup, that whoever holds `:80` is rooted at
the tree under test:

```sh
PID=$(ss -lntp | grep ":80 " | grep -oE 'pid=[0-9]+' | cut -d= -f2)
[ "$(readlink /proc/$PID/root)" = "$T" ] || exit 1
```

It also refuses to start if any of the four ports is already held. A negative
result from an emulation harness is worth nothing without that check.

### 3. Copying a tree that has `/proc` mounted under it

`cp -a /work/emu/v12 /work/emu/p13` with `/proc` mounted inside the source walks
into it and copies `/proc/1/task/1/pagemap`, which is reported as 43 GB. It
filled the VM's disk. Copy from a pristine tree that has nothing mounted under
it, and unmount before copying:

```sh
for m in $(mount | grep -o "/work/emu[^ ]*" | sort -r); do umount -l "$m"; done
```

## What this rig cannot tell you

`ssh/BUILD.md:871` states the limit and it applies here: `qemu-user` forwards
syscalls to the **build host's** kernel, so nothing specific to 2.6.31 is
modelled. For P13 the relevant exposure is socket behaviour — `EhDir_service`
reconfigures the socket with `FIONBIO` and fresh `SO_SNDTIMEO`/`SO_RCVTIMEO`
before the response is written, and under emulation that path runs against a
modern kernel. The 401 is generated at application level, which is what was in
doubt, but "it answered 401 here" is not "it will answer 401 on 2.6.31".

There is also no `/tuxedo`, so the push stream carries no alarm state. The
control's response on the push path is the multipart preamble, not a live feed.
