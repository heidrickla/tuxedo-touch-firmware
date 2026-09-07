# Traps

Things that produced a confident wrong answer or burned an hour. Read this
before starting, not after.

## 0. Read the docs first

Grep this repo for the topic before writing anything. Every trap below was
already written down somewhere when I hit it. Hand-rolling an emulation rig
cost hours while `ssh/BUILD.md` held the recipe and `WEBSERVER-REPLACEMENT.md`
held the queue facts.

**When you find something stale, FIX it. Do not annotate it as stale.** Saying
"this is superseded" and moving on leaves the next reader hunting for the actual
state, which is the whole failure this file exists to stop. Rewrite the entry to
say what is true now, with the evidence. Two of today's worst time sinks were
exactly this: a threat-model TODO that had been done all along and got raised
three times, and `§4.0 rule 5` of the migration plan, which I called superseded
and left sitting there saying the opposite of the truth.

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
- **Bound a disassembly walk at the function's real exit, never at a fixed
  distance.** Handlers here sit 0x20–0x40 bytes apart, so a fixed window is
  *guaranteed* to run into the next one and attribute its constants to the
  wrong case. This produced a published table of nine frame formatters of which
  **seven were wrong** — those handlers emit nothing, they `pthread_create`.
  Follow to the exit branch and count only what is actually reached.
- **When a capture disagrees with the disassembly, the capture is right and the
  disassembly is incomplete.** The corpus held `0:18:` and `0:504:` frames whose
  handlers never call `bprintf`; that is what revealed the frame path is partly
  asynchronous. Reconcile the two rather than trusting the static read.
- **`capstone.disasm()` STOPS at the first undecodable word — it does not skip
  it.** A linear pass over `/tuxedo`'s `.text` decoded **442 instructions, 0.03%
  of the section**, halting in the first literal pool, and cheerfully reported
  "0 matches". That produced a published claim that a constant appeared nowhere
  in the binary when it sits at `0x1472e8`. **Never conclude absence from a
  linear scan.** Disassemble per function (`addr`/`end`), and even then check
  the walk reached the end rather than dying in an inline pool.
- **Run the recipe before you write it down.** I documented a corrected scanning
  method — locate a struct base from an `add rB,sp,#N` / `add rT,rB,#0xe` idiom
  — committed it as the way forward, then ran it: 0 results against 194 misses,
  strictly worse than what it replaced, because the one sender known to be
  correct builds at `sp` with no such idiom. A method that has not been executed
  is a guess with formatting.
- **A sweep generates candidates; only reading the code confirms one.** Every
  correct result in this project came from verifying an individual site. Every
  wrong one came from trusting a pattern match across many.
- **"No case for X" is not "X does not exist."** A receiver's dispatch table
  says what it handles, never what the sender emits. msgType **20 is real** —
  `/tuxedo` sends it with the keypad display — and Barracuda simply has no case,
  so it is dropped. Stating the absence as though the message did not exist
  loses the entire console-mode finding. Name the side you measured.
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
- **`mnemonic.startswith("bl")` also matches `blo`, `bls`, `blt`, `ble`.** Four
  conditional branches read as calls; whole subtrees go unexplored and the
  result still looks tidy. Test `m in ("bl", "blx")`.
- **Not every case in a switch has a comparison.** After `cmp #127` and
  `cmp #125`, gcc knows 126 is the only value left and emits the handler with
  no test at all; a contiguous run like 300-303 shares one block behind a
  range check. Four successive attempts to read `CReceiverThread::run` by
  matching instruction patterns each looked complete and each was short --
  40, 55, 56, then 78 codes. Carry the constraint (an interval plus an
  exclusion set, narrowed on both edges of every conditional branch) and the
  question "which pattern" stops existing. `dispatch_tree.py` does this.

## 3. Windows / bash / python plumbing

- Python on Windows: `"/tmp/x"` silently becomes `C:\tmp\x`; `"/c/tmp/x"`
  raises FileNotFoundError. **Use `C:/...`.**
- **Heredoc + non-raw python string eats `\r\n`.** Inside `'''…'''` it becomes a
  REAL newline in the file you write. **Rule, no exceptions: if a heredoc emits
  code or data containing a backslash, the python string is `r'''…'''`.**
  Broken four times in one day, including once writing Rust where it compiled
  cleanly and surfaced only as a wrong test result. Writing this entry did not
  stop me repeating it. Two things do: prefer the Edit tool over a heredoc for
  files with escapes, and when a heredoc is unavoidable, check the result with
  `sed -n '/marker/,/end/p' file | cat -A` before trusting it.
- Foreground `sleep` is blocked. Use an `until` loop or `run_in_background`.
- **Windows `curl` is schannel, not OpenSSL.** `--cacert <private-ca>` fails with
  `schannel: the revocation status is unknown` because a private CA publishes no
  CRL or OCSP. Add `--ssl-revoke-best-effort`. Not a server fault; do not go
  debugging the listener.
- Line endings are per file. Check with python (`data.count(b"\r\n")`), not
  `grep -c $'\r'` - if the shell does not expand `$'\r'` the pattern is empty and
  matches every line, which reads as "the whole file is CRLF".

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
- **Never kill by command-line pattern over ssh.** `pkill -f X`, or a `/proc`
  scan matching `cmdline`, matches the shell running the command, because its
  own command line contains `X`. It kills the session, the real target survives,
  and the next test runs against a stale process. Match `readlink
  /proc/<pid>/exe` against the binary path instead, and skip `$$`.
- No `awk` and no `wget` even with PATH set. `netstat`, `grep`, `tr`, `readlink`,
  `sed` are there.

## 5. The build VM and emulation

- **Archive, do not delete. The test is cost to recreate.** Keeping the VM tidy
  is fine; destroying work is not. If regenerating something would mean a real
  rebuild, a long download, or a fan-out, keep it — move it to `/work/archive/`
  so it is out of the current build but still referenceable. Only genuinely
  redundant, cheaply regenerated things may go.
- **If space is short, grow the disk. Do not reclaim by deleting.**
- Live paths that stay put: `/work/stock`, `/work/extracted`, `/work/v12` (the
  rollback image), `/work/v13`, `/work/emu`, `/work/panel-config`,
  `/work/sysroot`. Expensive artifacts elsewhere: `/build/rt`, `/build/bb`,
  `/build/musl-1.2.5`.
- Do not remove the copied panel configuration. It lives at `/work/panel-config`
  on purpose so emulation needs no re-pull. It contains real credentials and
  that is accepted — it is a dev VM.
- I removed dev-VM state three times in one day — as "cleanup", as recovery from
  a disk I filled myself, and as unrequested "credential hygiene" — and each
  time it had to be rebuilt in front of Lewis. Two of the three were not
  recovery at all.
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
- **Leave the panel disarmed.** Arming and disarming are authorised and fast —
  just do it, do not ask. Scripted so the API call is never re-derived again:
  `python D:/temp/tux-arm.py [stay|away|night]` and
  `python D:/temp/tux-disarm.py`. They read the code from `D:/temp/tuxpw.txt`
  (4 bytes — it is the panel code, and the same value is the web password), and
  the disarm tool exits non-zero unless it confirms a disarmed state.
- **Panel sessions are bound to the client's source IP.** A cookie obtained on
  one host gets `401` on the push path and the login page on `/authenticated/*`
  from another, byte-identical and at the same moment. Log in from the host that
  will use the session; do not hand a cookie between machines.
- **The panel's reply to an arm/disarm means "command sent", not "code
  accepted"** — `{"Status":"Sucess", ... "Command sent sucessfully"}`, vendor
  spelling. Confirm the outcome from the stream or the status, never from that.
- **REST `GetSecurityStatus` lags badly.** During a measured exit delay it
  reported `34  Secs Remaining` six polls running across 30 s while the push
  stream counted down correctly. Use the stream for state.
- `supervis` allows **24 relaunches then a hardware reset**, and the counter is
  never zeroed. Check the budget before flashing a request-path change.
- **A flash wipes anything added over SSH.** `/opt/tuxedo/configuration`
  (mtdblock17) survives.
- **Prove request-path patches under `emu/` before flashing.** That is what
  turned P13 from "cannot be known before it runs" into a boring flash.
