# Traps

Things that produced a confident wrong answer or burned an hour. Read this
before starting, not after.

## 0. Read the docs first

Grep this repo for the topic before writing anything. Every trap below was
already written down somewhere when I hit it. Hand-rolling an emulation rig
cost hours while `ssh/BUILD.md` held the recipe and `WEBSERVER-REPLACEMENT.md`
held the queue facts.

**READING THIS FILE IS NOT CHECKING THE REPO, AND THAT DISTINCTION COST A
PANEL RESET.** 2026-09-08: I read §6, found the 24-relaunch decode, felt covered,
and never grepped further. **`docs/PUSH-STREAM-AUTH.md` R1/R4 held the actual
procedure** — the log path, the counter readout, the ceiling, the note that
a SIGTERM restart spends a unit — and because I never read it I spent the budget unaware
it was cumulative across the whole uptime and **tripped the hardware reset.**
Same day, twice more: I re-derived §6's decode from the binary, and re-derived
the event enum that `probe/supervis_events.py` regenerates on demand.

**This file carries MECHANISMS. Procedures for the live panel are in
`docs/PUSH-STREAM-AUTH.md`.** Before deriving anything about panel behaviour,
grep `docs/` for the noun — `SupervisionLog`, `RESTART`, `budget`. Three
re-derivations in one day, each worse than the record it duplicated, is not bad
luck; it is what stopping at one file looks like.

**When you find something stale, FIX it. Do not annotate it as stale.** Saying
"this is superseded" and moving on leaves the next reader hunting for the actual
state, which is the whole failure this file exists to stop. Rewrite the entry to
say what is true now, with the evidence. Two of today's worst time sinks were
exactly this: a threat-model TODO that had been done all along and got raised
three times, and `§4.0 rule 5` of the migration plan, which I called superseded
and left sitting there saying the opposite of the truth.

## 1. Measurement

- **A byte-for-byte replay of the captures only covers values the captures
  hold.** tuxweb reproduced both push-stream fixtures exactly and still printed
  the reply's `+0x08` unsigned, because no fixture has the panel off the air:
  the vendor's `%d` puts `-1` on the wire, tuxweb put `4294967295`, and the
  consumer's `== -1` test could never match. Same blind spot for msgType 22
  (never captured, silently dropped) and for a replay cache keyed on a field
  misread as the partition. When a field can take a value the corpus lacks,
  read the producer (the decompiler answers `sltSendChangedPartitionStatus` in
  one call) and add the value to the fake panel — and run the harness against
  the OLD binary once, so the new oracle is seen to fail on it
  (`WEBSERVER-REPLACEMENT.md` §8d.2).
- **Prove the thing you measured is the thing you meant.** A stale
  `qemu-arm-static -strace /opt/webserver/Barracuda` survived
  `pkill -f "qemu-arm-static /opt/webserver/Barracuda"` (the `-strace` breaks
  the pattern), held all four ports, and answered three runs of probes. A
  patched build looked inert. Assert `readlink /proc/$PID/root`; refuse to
  start if the port is already held.
- **A check that can pass for the wrong reason is not a check.**
  `len(body) > 0` is true of a 401 error body, so it reported a gated panel as
  "delivers frames with no credential".
- **HTTP 200 IS NOT EVIDENCE THE HANDLER RAN.** `/handlerequest.html` gates on
  a CSRF token *before* its dispatch — `getCSRFToken1` at `0x3a3c0`, `beq 3e858`
  at `0x3a3c8` when it returns NULL — and the bail-out answers **200** like a
  success. `leakprobe.py --mode console` never carries a token, so every request
  it has ever sent to that endpoint returned 200, left RSS flat, and **executed
  nothing past `0x3a3c4`**. Confirmed by trace for `cmd` 0, 1, 140 and 141: four
  values, identical last block. A flat RSS over clean 200s is precisely what a
  gate produces, so "no leak here" and "this code never ran" are the same
  reading at the HTTP layer. **Trace one request, or assert a side effect, before
  believing any endpoint measurement.** `TuxedoProbe.login()` does the genuine
  challenge/HMAC UI login, so being properly logged in does not imply a
  dispatchable session. **The panel does the same thing, measured** with
  `leakfix/dispatchcheck.py`: the bail precedes the switch, so it cannot answer
  differently per command — and `Type` 0, 1, 141, 60000 and 65535 all return one
  identical **empty** body on the panel as well as the bench. That is the
  trace-free way to ask "did this endpoint dispatch at all", and it works where
  qemu cannot go. The empty body was the tell all along: "400 requests, all
  200" was 400 empty responses, and nobody looked at the length.
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
- **`objdump -d` disassembles only executable sections, so a grep of the dump
  cannot prove a reference does not exist.** On Barracuda it emits `.init`,
  `.plt`, `.text`, `.fini` and nothing else — the 0x4cba04-byte `.rodata`, plus
  `.data` and `.got`, are **absent from the dump entirely**. "grep found no
  reference to 0xNNNN in bd.txt" excludes only *code* references; a pointer table
  in `.rodata` or a GOT slot is invisible. To prove absence, byte-search the file
  for the little-endian word and map hits to sections, **restricting to LOADED
  ranges** — hits inside `.symtab` are `st_value` fields, not data. 0x3a2a0 was
  settled this way; the code-only grep could not have settled it.
- **In `add rN, pc, rN`, `pc` is THAT instruction's address + 8** — not the
  previous instruction's. The GOT base for libjson from `add sl, pc, sl` at
  0x2100c is 0x21014 + literal = 0x35478, exactly `_GLOBAL_OFFSET_TABLE_`.
  Taking `pc` from the neighbouring instruction gives 0x35474, one slot low, and
  every subsequent GOT lookup then resolves to the **previous** symbol, with no
  error raised. Cross-check a computed GOT base against
  `readelf -Ws | grep GLOBAL_OFFSET_TABLE`.
- **The 0x693DC–0x6975C code cave is a REAL NAMED VENDOR FUNCTION,
  `HttpServer_getStatusCode` (size exactly 0x380 = 896 B), and it is dead.** In
  stock nothing `bl`s its entry, and a byte search of the whole file for the LE
  word `0x000693dc` finds **one** hit, in `.symtab` — its own symbol-table entry
  — with **zero hits in any loaded section**. The `b 69628`…`b 69688` branches a
  naive grep turns up are the function's own internal switch arms, not external
  callers. Do not read "a symbol exists there" as "the code is live", and do not
  settle it with a disassembly grep: `ci/wordref.py` maps every raw hit to
  a section and discounts the symbol table. Our stubs have overwritten 437 of
  those 896 bytes and the panel is healthy.
  In a patched image, leftover stock bytes in the unused part of the cave still
  **disassemble as instructions**, so a call-site census over the region reports
  sites that nothing can reach. Two of the "16 `json_parse_unformatted` call
  sites" in this build are exactly that.
- **Symbol names go STALE where our own patches replaced a function body.**
  `0x6c8c0` still disassembles as `HttpServer_destructor`, but in v13 the body is
  the **push-stream auth gate we installed** — it calls
  `HttpDir_authenticateAndAuthorize`, compares against `simpleDebugger+0x20` and
  calls `AuthenticatedUser_get1`. The symbol table was not rewritten, so objdump
  prints the dead function's name over our code. Reasoning about "which functions
  the patch changed" by symbol name mislabels the biggest hunks — diff the bytes
  (`cmp -l`) and word-align.
- **A COMPILER-GENERATED BINARY-SEARCH CHAIN ROUTES VALUES BY RANGE, SO
  ENUMERATING `cmp`/`beq` PAIRS SILENTLY MISSES THEM.** `gettuxedoIPCCommFunc`
  was documented for a release as dispatching "42 message types" with **no case
  for 20**, and three docs concluded console mode "cannot work through Barracuda
  by any means". Type 20 *is* dispatched — by the range arm:

      d6b0  cmp r8, #21
      d6b4  beq da80        <- 21
      d6b8  bcc db8c        <- everything BELOW 21, including 20

  `bcc` is unsigned less-than, and nothing in the chain ever compares against 20,
  so an equality-based enumeration cannot see it however carefully it is run.
  Disproved by injecting msgType 20 and finding its text in the guest heap, with
  msgType 23 as a control leaving none. **Any claim of the form "value N is not
  in the dispatch table", derived by listing equality comparisons, is unsafe** —
  walk the chain for the specific value, or drive it and observe.
  Same family as the `bl`-only scan that made `pthread_detach` look uncalled and
  `grep -A1 '^Tcp:'` landing on the UDP header: **a scan that answers by
  enumeration is only as complete as the shapes it enumerates.**
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
  disable every web account and the count survives a reflash. This panel runs
  v14, where P1 makes that 5 attempts and a 300 s self-clearing lock, so it is
  recoverable here — still exclude the path by construction, not by
  remembering, because the repo also targets stock panels.
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
  never zeroed *while the panel is up* — a **boot** clears it, because it lives
  in `.bss` and `supervis` restarts with the system. Both halves matter: the
  budget is **cumulative across an entire uptime**, so a panel up for two days
  may have almost none left, and it is **full again after a reset**.
  **OBSERVED FIRING 2026-09-08**, not merely decoded — it reset the panel
  during leak work, over an uptime whose counter already stood at 19. The log
  extract and the per-boot trap are in `PUSH-STREAM-AUTH.md` R4.
  **Read the budget without touching the process** — `supervis` prints it into
  a file on mtd17 that survives a reflash:

      grep -oE "BARRACUDA_RESTART-[0-9]+" /opt/tuxedo/configuration/SupervisionLog.txt | tail -1

  Read it **before** the first restart of a session, not after the last.
  **There is no free restart.** `kill -9` posts no message at all and *still*
  spends a unit (measured: `RESTART-1`, no `RECV_*` line), so the charge is for
  the relaunch, not the signal. A SIGTERM restart can spend **two**, because
  `sigHandler` often faults during its own cleanup and both signals count.
  **DECODED, not folklore, and the mechanism is not what it sounds like:**

      0xc528  cmp   r3, #0x1d              in main; 30 cases, default 0xc8fc
      0xc52c  ldrls pc, [pc, r3, lsl #2]   dispatch, table based at 0xc534
              cases 6,7,8   -> 0xc684      the counter block
              cases 3,4,5,9 -> 0xc910      straight to the disarm, see below

      0xc684  counter at 0x16be0, add #1, cmp #0x18, str back
      0xc69c  bgt 0xc90c                   on exceeding 24
      0xc90c  bl log_SupervisionText
      0xc910  ldr r0, [0x16c14]            <- four switch cases enter HERE
      0xc918  bl DisArmSWTimer  on that handle
      0xc91c  b  0xc4f0                    and carry on

  **The counter is not the only route to a reset**, and the split is by app:

  | main case | enum value | event | path |
  |---|---|---|---|
  | 3, 4, 5 | 4, 5, 6 | `TUXEDO_RECV_SIGABRT`, `_SIGSEGV`, `_MSGQ_OVERFLOW` | **direct disarm, no budget** |
  | 9 | 10 | `POWER_MANAGEMENT_EVENTS` | **direct disarm, no budget** |
  | 6, 7, 8 | 7, 8, 9 | `BARRACUDA_RECV_SIGABRT`, `_SIGSEGV`, `_MSGQ_OVERFLOW` | counter, then reset past 24 |

  **`/tuxedo` failures reset the panel immediately; Barracuda failures spend the
  relaunch budget first.** That is coherent rather than arbitrary — there is
  nothing to relaunch when the core app is gone — and it decides where a
  replacement web server sits. **A stage-6 cutover binary is a Barracuda
  replacement, so its crashes and queue events land on the COUNTER path**, which
  is the budgeted one. The `MSGQ_OVERFLOW` in the no-budget set is `/tuxedo`'s,
  not the web server's.

  Regenerate with `probe/supervis_events.py <rootfs>/supervis` rather than
  trusting this table; it resolves the labels from control flow every run.

  `0x16c14` is the **watchdog kick timer** — the only functions holding it are
  `wdg_init`, `wdg_deinit`, `main` and `SupervisTimeout`, and the binary carries
  `WDG KICK ioctl failed`, `/dev/watchdog` and `Opening watchdog driver`. So
  past 24 relaunches `supervis` **stops kicking the watchdog and the hardware
  resets the panel.** There is no explicit reboot call; the reset is the
  deliberate cessation of the kick. The counter is never zeroed because the
  store at `0xc694` happens after the compare and no path clears it.

  **The consequence is not "supervis gives up on an app".** It is the panel
  resetting itself, possibly with somebody standing in front of it during a
  booked window. Budget accordingly — a phase1 + phase2 + revert cycle spends
  three of the 24.

  **Two scans of this block concluded "unreachable" and both were wrong the
  same way: they modelled only `B`/`BL`.** ARM dispatches a switch with
  `ldr pc, [pc, rN, lsl #2]` and a table of absolute addresses, which leaves no
  `B` or `BL` anywhere — so a branch scan is *structurally* blind to it and
  returns a clean, confident, wrong answer. One of those scans even found the
  three table words and then dismissed them in a comment as "far more likely an
  unrelated constant". **The resolving method is not a better disassembler: ask
  whether the ADDRESS appears as a word anywhere**, and `refs(0xc684)` returns
  exactly those three slots. Same blindness as `ldr pc,[pc,rN,lsl #2]` read as a
  return, which section 2 already records — third time in one day.

  **AND THE CORRECTED SCAN WAS ALSO WRONG, WHICH IS THE SHARPER LESSON.** The
  first scan covered 29% of `.text` because `capstone.disasm()` stops at the
  first undecodable word; that was a real defect and fixing it gave 99.7%. The
  fixed scan then produced a conclusion that was wrong for an entirely unrelated
  reason — and it *looked more trustworthy precisely because a scanner had just
  been repaired to obtain it*. **Removing one blindness does not certify the
  result against a second.** This one reached the file: an entry saying the
  block was "NOT evidence" stood over a decoded safety mechanism until it was
  caught.
- **A killed Barracuda is relaunched on supervis's 10-MINUTE TICK, not "soon".**
  Every `BARRACUDA_RESTART-N` in `SupervisionLog.txt` lands on the same
  timestamp as an `E_SUPVTRD_FTPCLI_RESTART` line (`03:43:34`, `07:53:43`…):
  the dead-Barracuda check runs on the FTPCLI 600 s timer. That is the whole
  explanation for "the respawn took 90 s once and SEVEN MINUTES another time" —
  it is the phase of the tick, and the worst case is ten minutes with no web
  server. tuxweb has no `sigHandler`, so nothing shortens it. On 2026-09-12 a
  `kill -9` at real 06:48 UTC relaunched at 06:53:43 and looked, from HA, like a
  six-minute outage; `stage8-panel.sh` now starts the new binary itself after
  the kill instead of waiting for the tick.
- **The panel's clock is ONE HOUR AHEAD of real UTC for two thirds of the year,
  and it is `/tuxedo`, not the OS.** Measured 2026-09-12: panel − real UTC =
  **+3578 s** (59 m 38 s); `devices.md` had it 5 h 0 m 23 s BEHIND on vendor
  firmware, before the `TZ` export. Both readings carry the same ~22 s residual
  (the VISTA's own clock). Mechanism, decompiled: `dal_setCurrentTime` builds a
  `struct tm` from the VISTA's LOCAL time and sets **`tm_isdst = 0`** before
  `mktime()` — "this is standard time" — so under
  `TZ=CST6CDT,M3.2.0/2,M11.1.0/2` a CDT time is converted as CST, +6 h instead
  of +5. Correct all winter, an hour ahead from the second Sunday of March to
  the first Sunday of November (238 of 365 days). It is re-asserted on every
  VISTA time poll, so NTP at boot cannot hold it (`TUXEDO-NTP-PROPOSAL.md`).
  **Fix: `P16-dst-isdst`** (`patches.tsv`, v15): `tm_isdst = -1`, let `mktime`
  apply the rule. Prediction to check the reading against, from the
  `ha-management` session: an UNPATCHED panel silently becomes correct on
  2026-11-01 and breaks by exactly one hour on 2027-03-14. **Never trust a
  panel-side timestamp against an external one without measuring the offset
  that day** — a January spot-check finds the clock right and writes it down.
  Quote UTC from HA or the VM for anything cross-referenced. (The OS side is
  fine: TZ is inherited by `/tuxedo`, `supervis` and tuxweb, and this libc's
  `date -d` applies the rule correctly; `/etc/adjtime` says `LOCAL`, so the RTC
  holds local time and reads 5 h low until NTP at boot — harmless.)
- **`E_SUPVTRD_FTPCLI_RESTART` every 10 minutes forever is EXPECTED. Do not
  chase it.** `supervis` supervises `/ftpclient`, and that binary **has never
  shipped** — absent from the extracted v12 and v13 rootfs and from every image
  in `/work`. So `relaunchFtpCli` fires on its 600 s timer, the launch fails, and
  it logs. Continuously, through all 18 logged boots.
  **It costs nothing that matters, checked rather than assumed:**
  `relaunchFtpCli` (0xc194) contains **no compare and no reference to the counter
  at 0x16be0** — it calls `launchFtpCli`, formats, and logs. So it does **not**
  spend the 24-relaunch budget; only Barracuda's three events do. And the log
  growth is ~7.6 kB/day against 57 MB free on mtd17, which is about 20 years.
  `/vidrec` is missing too but does **not** loop — it is launched once at boot
  with no retry timer. So "missing binary" alone does not predict the behaviour;
  the retry timer does.
- **`find`, `diff`, `xargs`, `awk`, `tar` AND `gzip` ARE NOT IN THE PANEL'S PATH,
  AND A MISSING COMMAND LOOKS LIKE A NEGATIVE RESULT.** `sh` prints its error to
  stderr and the pipeline yields nothing, so `find /var/www -type f` returns empty
  and reads as "the directory is empty". That conclusion was drawn once: `/var/www`
  holds an LTIB test page and a test CGI, with no server installed to serve them.
  A `diff` of two config files would likewise print nothing and read as "no
  differences".
  **All six exist as busybox applets: call them `busybox find`, `busybox diff`,
  `busybox awk`.** Only the PATH symlinks are missing. An earlier version of this
  entry claimed the panel had no such tools at all, which was wrong — `command -v`
  answering "not found" says nothing about what `busybox --list` holds, and that
  list includes awk, find, diff, xargs, tar, gzip and `httpd`.
  In PATH directly: `sed`, `grep`, `tr`, `cut`, `sort`, `md5sum`, `dd`, `od`,
  `hexdump`, `ls`, `readlink`.
  **Verify the tool ran before believing what its silence means**, and check
  `busybox --list` before concluding a tool is unavailable.
- **`pkill -f <pattern>` MATCHES YOUR OWN SSH COMMAND LINE AND KILLS THE SESSION.**
  `pkill -9 -f "qemu-arm-static.*Barracuda"` and `pkill -9 -f mqdrain.py` both
  killed the shell running them, mid-script, twice in one session; the second time
  after the first was written down here, because the rule named one pattern rather
  than `-f` itself. Use `pkill -x <exact-name>`, or make the pattern unable to
  match itself: `pkill -f "mqdrain[.]py"`.
- **`/proc/PID/mem` CANNOT BE READ ON THE PANEL — the kernel refuses, with a
  misleading error.** Every cross-process read returns **`ESRCH`**, which `dd`
  prints as `No such process` even though the pid is in `/proc` and serving
  traffic. Pre-2.6.39 `mem_read` requires the target to be ptrace-attached **and
  stopped** by the reader. Measured on the unit against a live Barracuda, at
  offset 0 and at a mapped address: not an addressing bug, and offset-checking
  will not fix it. Any instrument that reads guest memory is **bench-only**; on
  the panel the alternative is ptrace, which stops the process and makes
  `supervis` spend relaunch budget. A shell rewrite does not help — the obstacle
  is the read, not the language — and the panel has **no interpreter at all**, no
  `python`, `python2`, `python3` or `perl`, only `dd`, `od` and `hexdump`.
  Related, and why reading the image did not catch it: **the panel's
  Barracuda maps `/vidrec/lib/libjson.so.7` (md5 `610d5009`), not
  `/usr/lib/libjson.so.7.6.1` (md5 `6aa09429`)**, because
  `/etc/rc.d/init.d/startup` puts `/vidrec/lib` on `LD_LIBRARY_PATH`. Check
  `/proc/PID/maps` for which copy is loaded before trusting any library offset.
  (For the registry offsets in `ALLOCATOR-REWORK.md` the two agree exactly, but
  that is a fact about those addresses, not a general licence.)
- **DO NOT read the relaunch budget out of the running `supervis`.** The counter
  is at `0x16be0` in `.bss` and the process is non-PIE with that page mapped
  `rw`, so it is at a real fixed address and looks readable. Reading it on
  2.6.31 needs `ptrace` — and `supervis` holds `/dev/watchdog` and kicks it at
  1 Hz. **Attaching stops the process, the kicks stop, and the watchdog resets
  the panel in hardware.** Track the budget by hand in the runbook. The address
  being reachable is not the same as it being safe to reach.
  **This is the same failure as the 24-limit above, not a separate risk:**
  in both cases the panel resets because the kick stopped. Anything that halts
  `supervis` — `ptrace`, `SIGSTOP`, a debugger — is in that class.
- **A flash wipes anything added over SSH.** `/opt/tuxedo/configuration`
  (mtdblock17) survives.
- **START THE EMULATOR WITH `emu/serve.sh`, NEVER A BARE `chroot`.** Barracuda
  blocks on its POSIX message queues waiting for `/tuxedo`, which does not exist
  under emulation, so `serve.sh` also starts **`mqdrain.py`** to drain them.
  Without the drainer the server binds **all four listeners** and then answers
  **nothing** — `curl` hangs until timeout on plain HTTP as well as TLS.
  **`listeners=4/4` is not evidence the server serves**, and this failure
  imitates a broken patch: several A/B runs read as "the patched binary hangs"
  when the control hung identically. Whenever a run times out, **run the control
  through the same path before believing anything about the patch.**
  `serve-traced.sh` does NOT start the drainer; if you use it directly, start
  `mqdrain.py` yourself afterwards.
  Do not clean up with `pkill -f "qemu-arm-static.*Barracuda"` — the pattern
  matches the **ssh command line running it**, so it kills its own session and the
  connection dies mid-script. Use `pkill -x qemu-arm-static`.
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

## 7. libjson

Full working in `ALLOCATOR-REWORK.md`. The ones that will bite a patch author:

- **`json_free` is NOT a `free()` wrapper, and it corrupts the heap on a
  pointer libjson did not issue.** libjson is built with `JSON_MEMORY_MANAGE`, so
  it keeps a global `std::map` of every pointer its C API hands out. `json_free`
  looks the pointer up, computes *was it registered* into a register, passes that
  to a **non-fatal** assert, and then **never branches on it** — an unregistered
  pointer makes it rebalance-for-erase and `operator delete` the **map's own
  header node** before it ever reaches the real `free()`. So "wrong allocator"
  here is not a mismatched-free but corruption, *before* any message you might
  see. NULL is safe (early-out).
  For debugging: a crash from a `json_free` stub tells you **nothing** about
  whether that site leaks or who owns the pointer. LEAK 29 spent a measurement
  cycle on that inference.
- **A BAD POINTER TO `json_delete` HANGS, AND TAKES THE WHOLE SERVER WITH IT.**
  It is not a crash and there is nothing in any log. Because `json_delete` skips
  the registry erase when the pointer is not registered (below) and then calls
  `deleteJSONNode` anyway, a non-node makes it walk a child list forever. The
  worker is then stuck **holding the dispatcher mutex**, which is held across the
  handler and dropped only around blocking `send()` — so every other request
  blocks behind it. Measured: one API request against such a build timed out, and
  immediately afterwards plain HTTP on `:80` returned nothing either, with the
  process still alive and its log clean.
  **The registry counter tells you which happened**, cheaply: if the node count
  is **unchanged** the delete ran (created +1, deleted −1); if it went **up by
  one** the delete never erased anything, so the pointer was never registered.
  `leakfix/jsoncount.py`, one request either side.
  Do not diagnose "is this register still the object" statically —
  `leakfix/liveness.py` reconstructs executed blocks from a qemu trace and
  reported a register untouched across a path where the counter proves it was not
  the registered pointer.
- **`json_delete` does NOT share `json_free`'s erase flaw, and the asymmetry is
  diagnostic.** It performs the same registry lookup but **branches on the
  result** — `cmp r1, r0` / `beq 25b48` at libjson 0x25b30 skips the erase when
  `find()` returned `end()` — before calling `deleteJSONNode` regardless. So a bad
  pointer handed to `json_delete` leaves the registry intact and only mis-frees
  one object. When a delete stub misbehaves, a **hang or a wrong result means the
  object was still live**, not that the registry was corrupted; only `json_free`
  can corrupt it. LEAK 30's second attempt was read this way.
- **glibc's two free-time messages mean different things.** `free(): invalid
  pointer` is the chunk-alignment / arena-bounds check — the address is not a heap
  chunk. `double free or corruption` is the double-free check. Reading the first
  as the second sends you looking for a phantom earlier owner.
- **libjson exports bulk frees that Barracuda cannot reach, and they must stay
  unreached.** `json_free_all` (0x20de0) and `json_delete_all` (0x2458c) free
  *everything registered process-wide*. They are absent from Barracuda's
  relocation table, and wiring one up to "free by scope" would corrupt the heap,
  because HTTP requests run concurrently on a 20-thread pool whose serialising
  mutex is **dropped around every blocking `send()`** — so another request is
  live, mid-handler, with registered allocations, whenever you might call it.
  Two copies of the library exist with different md5s (`usr/lib` and
  `vidrec/lib`, and `/vidrec/lib` is on `LD_LIBRARY_PATH`), so offset work must
  name which one is mapped.
