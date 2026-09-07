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
- **A CHECK MUST DISTINGUISH "RAN AND PASSED" FROM "DID NOT RUN".** Deciding a
  verdict by searching a command's output for a failure word conflates them,
  because the absence of that word is produced by success and by absence alike.
  `check_hdr_checksum` was
  `python3 ci/test_hdr.py | grep -q FAIL && fail || pass`, so a missing script,
  an `ImportError`, a syntax error or no `python3` at all each printed
  **`ok  header checksum`**, and the suite then printed `all checks passed`.
  Confirmed by moving the script aside and watching it go green. That was the
  check between a wrong header checksum and an image reaching the panel.
  **Judge the exit status**, and keep the text search only as a second gate.
- **A multi-file `grep -q` hides a missing file.** `grep -q PAT a.md b.md`
  matches in `a.md`, returns 0, and reports a full pass having searched half of
  what it names. It does not fail and it does not even skip. This went stale for
  real when the documents moved into `docs/`. **Confirm each input exists before
  searching it**, and say which one was missing.
- **Prove the check can go red.** After fixing either of the above, move the
  input away and confirm the suite fails; a fix that leaves it green did not
  work. Then run the whole suite either side and **diff the ok/skip/fail
  counts** — a check that has quietly stopped checking looks exactly like a
  check that passed.
- **Revert the feature and watch the test go red, or you have not tested it.**
  I wrote `test_the_entry_loads_and_streams_from_the_relay` for the HA push
  source and it passes with the feature REVERTED — the fake panel serves the
  relay URL too, same host and port, so the assertion cannot tell the two
  apart. Two more in the same batch could not fail either: a Cookie check
  neutralised by its own `or` clause, and a form test that only asserted a form
  appeared. Found by the ha-management session on review, 2026-09-07, which
  ran each new test against reverted code before keeping it. **The failing run
  is the evidence, not the passing one** — and note this entry sits directly
  below a rule I had already written and still did not apply to my own tests.
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
- **Searching for "is this string referenced" needs the address of the string's
  START, not of your needle.** A literal pool holds the address of
  `/opt/tuxedo/configuration/webuseraccountsenc.json`; grepping for
  `webuseraccounts` matches 25 bytes into it, and the address of *that* appears
  nowhere. Back up to the byte after the preceding NUL. This returned "not
  referenced" for a file Barracuda demonstrably reads.
- **Every sweep needs a positive control you already know the answer to.** The
  above was caught only because Barracuda was run through the same code and also
  came back "not referenced", which is impossible. Without the control it would
  have been published as a finding about `/tuxedo`.
- **Build the control INTO the tool, not into the session.** `reply-layouts.py`
  asserts `registerclient`'s five hand-read fields under `--check` and failed
  4 of 5 on its first run — one of those failures was in the check itself,
  which kept only the last row per offset and so reported a field the tool had
  actually recovered. A control that lives only in your head is not run again
  after the change that breaks it.
- **Do not re-derive a count by grepping your own tool's prose.** The reply map
  prints `msgType 21 or 22` for a builder that stores either, and a
  `msgType (\d+)` regex over that output took only the first number — so a
  summary said 25 types when the map held 26, and msgType 22 would have been
  published as not existing. The map was right; the count of it was not. Have
  the tool emit the number, or parse the structure rather than the sentence.
- **A search that never ran must not report "not found".** The cross-reference
  for "who filled this buffer" printed `no writer of +0x004 found in the
  searched set` for a shape whose candidate selection matched no branch, so
  the candidate set was empty and nothing was ever examined. That reads as a
  searched-and-empty result and it was not one; the writer existed and set
  msgType 21. Distinguish "searched, empty" from "did not search".
- **When a rewrite finds MORE, diff what it finds LESS.** Going from 45 to 92
  resolved layouts looked like unambiguous progress; the diff showed 17 fields
  the old tool had and the new one did not, of which four were real regressions
  in the rewrite and two were old false positives. Neither group is visible
  from the totals. Compare like for like and adjudicate every difference by
  reading the code — assuming the new one is right because it is newer is how
  the false positives would have been preserved and the regressions shipped.
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
- **There are four store-multiple modes, not two.** `stmib`/`stmda` write at a
  different offset from `stm`/`stmdb`, and handling only the latter pair drops
  the instruction *silently* — `wdelaytimerstart`'s entire header,
  `stmib sp,{r3,ip}`, which is where its session and its msgType (24) live.
  The map still printed, one instruction short, and the type read as never
  written. Same for the `ldm` family.
- **`v2o` must skip sections with `sh_addr == 0`, exactly as `o2v` does.** The
  integer 801 — a message type from a literal pool — mapped into `.comment` and
  came back as the string `"U) 4.1.2"`, part of the GCC version banner, which
  was then published as a field's value. `o2v` was fixed for this trap years
  ago and `v2o` was not, so the same file was caught by it twice. **A word from
  a literal pool is a pointer only if it maps to a LOADED section**; otherwise
  it is a number.
- **`ldr pc, [pc, rN, lsl #2]` is a switch, not a return.** gcc puts the table
  immediately after the instruction, so reading it as a return cuts every case
  off *and* leaves the table's own words in the instruction stream.
  `refreshUploadZoneList` reached 178 of its 768 instructions and two of its
  `osal_MqSend` sites vanished from a map that still read as complete. The
  bound is the preceding `cmp rN, #k`; targets follow at `addr+8`.
- **An epilogue in the middle of a function is not on the path after it.**
  `pop {r4,r5,pc}`, and `pop {r4,r5,lr}` before a tail-call `b`, restore the
  caller's registers; letting them clobber state for the code that follows
  wiped buffer pointers held in callee-saved registers and turned five
  resolved functions into "unresolvable".
- **Do not fall through an unconditional `b`.** The next address is reachable
  only by branch, so carrying registers across it attributes one path's values
  to another. This reported two message buffers as `osal_Free()` and
  `CTimer2::start()` — values that are obviously not buffers, which is the only
  reason it was caught. Walk the CFG; a linear pass also interprets literal
  pools as code.
- **`cmp rD, #0` does not write `rD`.** Nor do `cmn`, `tst`, `teq`, `push`.
  Treating operand 0 as a destination destroys the tested value one
  instruction before the predicated store that consumes it, so
  `cmp r0,#0` / `strbeq r0,[sp,#0xb8]` lost the field's source.
- **A store with a register index is not a store at offset 0.**
  `str r6,[r0,r7]` has `mem.disp == 0`; ignoring `mem.index` published a
  phantom `+0x000` field. Refuse the operand instead of guessing.
- **Matching by register NAME is not matching the object.** A backward walk
  that finds `mov r1, r3` and then collects every store through "r3" in the
  function pulls in stores from disjoint branches and from after the buffer was
  freed. Two published fields were exactly that. Resolve what the register
  *points at* — same symbolic root, offsets subtracted — not what it is called.
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
- **Do not use heredocs on this machine. Write files with the Write/Edit tools,
  then run them.** This is Lewis's instruction and it is not conditional.
  **Enforced in the tool layer since 2026-09-07** — `block-guard.py` denies a
  heredoc that authors content, in every tree. If one ever succeeds again, the
  hook has regressed; check it rather than concluding the rule relaxed.
  It had been a hard block since 2026-08-02 and *did not fire here*: the check
  sat behind `hook_scope`, whose Windows allowlist is `D:\WorkRepo` only, so
  the identical `python - <<'PY'` denied there and ran silently in
  `D:\Projects`. A session used heredocs about a dozen times in one
  sitting believing the rule was enforced. **A control that is correct but
  unreachable is indistinguishable, from inside, from no control** — when a
  rule keeps being broken, check whether its guard actually covers where you
  are working.
  Note also that in auto mode the harness *instructs* heredoc use ("make file
  changes with sed, heredocs, or short scripts"). That instruction is wrong
  for this machine; Lewis's rule wins.
  Backslashes get eaten somewhere between the shell and the interpreter, so
  `\r\n` becomes a real newline in whatever you write. It has cost a day across
  at least seven occurrences: a silently-wrong Rust test that compiled cleanly,
  three failed `assert` guards on replacement text, and — twice — the mangling
  of *this bullet* while editing it. A narrower version of this rule ("use
  `r'''…'''`") was written here and then broken again the same session, which is
  why it now says: don't.
- Foreground `sleep` is blocked. Use an `until` loop or `run_in_background`.
- **Windows `curl` is schannel, not OpenSSL.** `--cacert <private-ca>` fails with
  `schannel: the revocation status is unknown` because a private CA publishes no
  CRL or OCSP. Add `--ssl-revoke-best-effort`. Not a server fault; do not go
  debugging the listener.
- Line endings are per file. Check with python (`data.count(b"\r\n")`), not
  `grep -c $'\r'` - if the shell does not expand `$'\r'` the pattern is empty and
  matches every line, which reads as "the whole file is CRLF".
- **`LIVE-RESULTS.md` is not valid UTF-8 and has bitten twice, from opposite
  directions.** It carries raw latin-1 bytes from the push stream, one of them a
  NUL. Both consequences are silent:
  - **`git filter-repo --replace-text` SKIPS ANY BLOB CONTAINING A NUL.** In the
    2026-09-07 publication scrub every other file was rewritten and this one was
    not, leaving it as the only file still carrying the real panel address while
    every check read green. Use the **Python API with a `blob_callback`**, which
    has no binary check. Add a `commit_callback` too - `--replace-text` does not
    touch commit messages, and three of them named the address and the
    workstation.
  - **`git grep` reports it as `Binary file ... matches`**, so a sweep for
    citations across the repo silently misses whatever it holds. Read it with an
    explicit decode-and-replace.
  Same underlying fact, diagnosed separately a day apart, by two people who had
  each already been told the other half. **When a file is not valid UTF-8,
  assume every text tool has an opinion about it and find out which.**
- **Verify a scrub in BOTH directions**: zero hits for what must go, and
  still-non-zero for what must stay - vendor addresses, placeholder MACs, the
  shipped `/etc/hosts`. Only the second half catches a pattern broad enough to
  have eaten the evidence this repo exists to hold.
- **After `filter-repo`, the remote-tracking refs lie.** It rewrites
  `refs/remotes/*` as well, so `gitea/main` pointed at the rewritten head while
  the server still held the original, and
  `git rev-list --left-right --count gitea/main...HEAD` read as "in sync, one to
  push" when nothing had been pushed at all. Ask `git ls-remote`, then
  `git fetch` to make the tracking refs honest.

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
- **...but `exe` is wrong the moment you REPLACE the file.** A running process
  whose image has been renamed or overwritten reports
  `/opt/webserver/Barracuda (deleted)`, so a `*/Barracuda` pattern stops
  matching and the scan finds nothing. That turned a stage-5 test into a
  confident "supervis did not accept it" while the untouched vendor process was
  still serving. When the test swaps a binary, match on **`comm`** — field 2 of
  `/proc/<pid>/stat`, the text inside the parentheses.
- **Waiting for a port to open proves nothing if the old process still holds
  it.** The predecessor keeps all four listeners until it dies, so the wait
  returns instantly. Wait for a **different pid**.
- No `awk` and no `wget` even with PATH set. `netstat`, `grep`, `tr`, `readlink`,
  `sed` are there.
- **`/bin/busybox` is already on the panel since v13** (1328384 bytes, the one
  built per `NEUTERED-TOOLS.md`), and it has `awk`, `strings`, `seedrng` and the
  rest. Check for it before pushing another copy. It is not on `PATH` as
  individual applets — call `/bin/busybox <applet>`.
- **Cross-compile panel binaries with `/opt/musl-armel/bin/musl-gcc`, not
  `arm-linux-gnueabi-gcc`.** The gnueabi static output is stamped
  `for GNU/Linux 3.2.0` and the panel is 2.6.31; musl stamps no minimum. `file`
  will tell you which you built.

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
- **Linting the working tree is not linting the repo.** A gate run in
  `/work/ha-tuxedo` failed with 70 ruff errors, every one of them from an
  untracked `.claude/hooks/keep-working.py` — gitignored, not a tracked file,
  invisible to real CI. The failure was entirely an artifact of checking a
  DIRECTORY instead of a REPOSITORY, and the same confusion hides the reverse:
  a tracked file CI would fail on, buried in untracked noise. Check what is
  actually committed:
  `git ls-files | tar -cf - -T - | (cd /work/verify && tar -xf -)`.
  `tar` needs **`--force-local`** on these paths or it reads `C:/...` as a
  remote host. Found by the ha-management session, 2026-09-07.
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
  **A block at `0xc684` looks like it confirms this and DOES NOT — do not cite
  it.** It reads a counter, `add r3,r3,#1`, `cmp r3,#0x18`, stores it back and
  branches when it exceeds, which is exactly the shape expected. But `0xc680`
  is an unconditional `b #0xc4f0`, and a full-coverage scan of `.text` (3323 of
  3334 words decoded, 99.7%) finds **zero branches targeting `0xc680-0xc6b0`**.
  Nothing reaches it. An earlier edit of this entry cited it as the mechanism,
  "seen directly rather than quoted"; that was wrong, and the shape of the block
  is what made it convincing. **Code that says what you expect is not evidence
  until something reaches it.** The 24-limit itself stands on its original
  source, not on this block.
- **DO NOT read the relaunch budget out of the running `supervis`.** The counter
  is at `0x16be0` in `.bss` and the process is non-PIE with that page mapped
  `rw`, so it is at a real fixed address and looks readable. Reading it on
  2.6.31 needs `ptrace` — and `supervis` holds `/dev/watchdog` on fd 4 and kicks
  it at 1 Hz. **Attaching stops the process, the kicks stop, and the watchdog
  resets the panel in hardware.** Track the budget by hand in the runbook. The
  address being reachable is not the same as it being safe to reach.
- **A flash wipes anything added over SSH.** `/opt/tuxedo/configuration`
  (mtdblock17) survives.
- **Prove request-path patches under `emu/` before flashing.** That is what
  turned P13 from "cannot be known before it runs" into a boring flash.
- **Anything that must work at boot gets executed under `qemu-user` in a chroot
  of the extracted rootfs, with `/dev` left exactly as the image ships it.**
  Preparing the test environment to make the subject work conceals the
  dependency that fails. `WEBSERVER-REPLACEMENT.md`, `emu/README.md` and
  `ssh/BUILD.md` all lean on this rule.
- **Mark a statement `[CONFIRMED]` only after tracing every branch into and out
  of the thing**, not merely reading the instructions at the site. Both flash
  failures in this repo came from reading a mechanism partly and then describing
  it in the register the resolved parts had earned.
