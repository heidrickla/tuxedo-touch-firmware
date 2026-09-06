# Traps

Things that produced a confident wrong answer or burned an hour. Read this
before starting, not after.

## 0. Read the docs first

Grep this repo for the topic before writing anything. Every trap below was
already written down somewhere when I hit it. Hand-rolling an emulation rig
cost hours while `ssh/BUILD.md` held the recipe and `WEBSERVER-REPLACEMENT.md`
held the queue facts.

## 1. Measurement

- **Prove the thing you measured is the thing you meant.** A stale
  `qemu-arm-static -strace /opt/webserver/Barracuda` survived
  `pkill -f "qemu-arm-static /opt/webserver/Barracuda"` (the `-strace` breaks
  the pattern), held all four ports, and answered three runs of probes. A
  patched build looked inert. Assert `readlink /proc/$PID/root`; refuse to
  start if the port is already held.
- **A check that can pass for the wrong reason is not a check.**
  `len(body) > 0` is true of a 401 error body, so it reported a gated panel as
  "delivers frames with no credential".
- **Never call something vendor behaviour from a binary you patched.** md5 it
  against genuine stock (`324209e1…`) first. I documented our own P1 stub as a
  vendor discovery.
- **Heartbeats mimic causation.** `0:18:` frames 32.98 s apart after a button
  press are the 33 s heartbeat. If the instrument cannot see the effect, a
  clean result is not evidence.
- **One clean run is not a result.** Say what rests on a single observation.
- **A doc's open-items list is a claim, not a fact.** `THREAT-MODEL.md` carried
  "bound the 300 s lockout by source address" as open; the tracker was already a
  splay tree keyed on address (`LoginTracker_splayTreeCmpAddr`). I re-raised it
  three times before reading the code. Verify a TODO before repeating it —
  especially one written here.

## 2. Addressing and ARM

- Barracuda: **file = VA − 0x8000** (PT_LOAD3). Second load segment is −0x10000.
  Do not generalise. `patches.tsv` holds FILE offsets.
- **Compute offsets in python, not in your head.** 0x72420 = 468000, not
  468512; an off-by-512 `dd` made a verification meaningless.
- `b` into another function **is a call** (tail call). BL-only scans reported
  1,744 reachable functions as uncallable.
- ARM immediates are 8-bit rotated: **1125 and 1126 are not encodable**, so a
  `cmp #imm` scan cannot see them. Check the literal pool.
- ELF sections with `sh_addr == 0` are not loaded. Mapping offsets inside
  `.symtab`/`.strtab`/`.comment` yields phantom VAs and fake data references.

## 3. Windows / bash / python plumbing

- Python on Windows: `"/tmp/x"` silently becomes `C:\tmp\x`; `"/c/tmp/x"`
  raises FileNotFoundError. **Use `C:/...`.**
- **Heredoc + non-raw python string eats `\r\n`** — `\r\n` inside `'''…'''`
  becomes a real newline and breaks the file. Use `r'''…'''` for anything
  containing backslashes. Cost this twice in one session.
- Foreground `sleep` is blocked. Use an `until` loop or `run_in_background`.

## 4. SSH to the panel

- **Set PATH first**: `PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH`. A
  non-interactive shell lacks `awk`, `cmp`, `which`, and a `set -e` script
  aborts silently mid-install.
- **No `tar`, `gzip`, `cpio`, `find`, `sftp-server`.** `scp` fails. Transfer
  with `ssh host 'cat > /path' < file`; for a tree, emit a length-prefixed
  stream (`===F <size> <path>` then raw bytes) — binary-safe.
- **Backgrounded jobs die with the session.** Use `setsid` (this swallowed a
  `reboot` once).
- Writing a running executable gives **ETXTBSY**. Copy, patch, rename.
- **busybox dispatches on `argv[0]`** — a renamed copy exits "applet not found".
- **`/proc/<pid>/comm` does not exist** on 2.6.31. Use field 2 of
  `/proc/<pid>/stat`.

## 5. The build VM and emulation

- **DO NOT DELETE ANYTHING ON THE DEV VM.** It is persistent infrastructure,
  not scratch. The extracted trees, `/work/panel-config`, the emulation chroots
  and the stock images are expensive to rebuild and are meant to persist. I
  removed them three times in one day — as "cleanup", as disk recovery, and as
  "credential hygiene" — and each time Lewis had to watch the dev machine get
  reconstituted. Leave it alone. If disk is genuinely short, say so and ask.
- Do not remove the copied panel configuration either. It lives at
  `/work/panel-config` on purpose, so emulation does not need a re-pull. It
  contains real credentials and that is accepted — it is a dev VM.
- **Never `cp -a` a tree with `/proc` mounted under it.** It copies
  `/proc/1/task/1/pagemap`, reported as 43 GB, and fills the disk. Unmount
  first, or copy from a pristine tree.
- **Barracuda binds all four ports then answers nothing** = blocked in
  `mq_timedsend` with no `/tuxedo` draining `/Q_ServCmdRcver`. Run
  `emu/mqdrain.py`. Queues mount at **`/dev/mq`**, not `/dev/mqueue`.
- **qemu-user forwards syscalls to the HOST kernel.** Nothing 2.6.31-specific
  is modelled. Emulation passed dropbear five times on a bug that only appears
  on the panel.
- Build on the VM (`claude@203.0.113.40`, `~/.ssh/fwbuild_ed25519`), **not WSL**.

## 6. Panel safety

- **Never submit a wrong password.** On stock, three failures permanently
  disable every web account and the count survives a reflash. Exclude the path
  by construction, not by remembering.
- **Leave the panel disarmed.**
- `supervis` allows **24 relaunches then a hardware reset**, and the counter is
  never zeroed. Check the budget before flashing a request-path change.
- **A flash wipes anything added over SSH.** `/opt/tuxedo/configuration`
  (mtdblock17) survives.
- **Prove request-path patches under `emu/` before flashing.** That is what
  turned P13 from "cannot be known before it runs" into a boring flash.
