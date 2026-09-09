# Reworking the allocator so memory frees itself — assessed, and the answer is no

**Question, 2026-09-08:** rather than keep adding per-site free stubs, can the
allocator be reworked so leaked memory is freed by *scope* instead of by
*ownership*? Every failure in this work has come from guessing which code owns a
pointer; scope-based freeing removes the question.

**Answer: the idea is sound, the machinery already exists in the vendor's own
library, and it still must not be used here.** One measured fact kills it. What the
investigation produced instead is a better diagnostic and a corrected model of a
crash we had already suffered.

---

## 1. The idea is not just viable, it is already built — by libjson

`libjson.so.7.6.1` is compiled with **`JSON_MEMORY_MANAGE`**. It keeps a global
registry of every pointer its C interface hands out, and it **exports bulk frees**:

    json_free_all      libjson VA 0x20de0   (544 B, void signature)
    json_delete_all    libjson VA 0x2458c   (544 B, void signature)
    auto_expand::purge        0x156e8       frees every registered string
    auto_expand_node::purge   0x1569c       deletes every registered node

Two registries, both `std::map`, singletons at `0x35cd4` (strings) and `0x35c9c`
(nodes). Every string-returning API call registers unconditionally through one
choke point, **`toCString` @0x27d78** — malloc, then an insert with no branch that
could skip it. So `json_as_string`, `json_write`, `json_write_formatted`,
`json_name` and `json_strip_white_space` results are all tracked.

All four verified present in `usr/lib/libjson.so.7.6.1` at exactly those addresses
(`nm -D --defined-only`).

**Barracuda never imports either bulk free** — verified against the relocation
table, not assumed: 24 `R_ARM_JUMP_SLOT` libjson imports, and `json_free_all` /
`json_delete_all` are in none of them. The machinery is present in the library and
genuinely unreachable from the web server. That is exactly the shape the question
hoped for.

⚠ Nothing in this repo recorded this before. It is worth knowing independently of
the decision below.

## 2. The measured fact that kills it: 20 concurrent request threads

    panel /proc/PID/task/*/stat, field 2:
        20  ThreadPool          the HTTP worker pool
         2  Barracuda           main + SoDisp dispatcher
         1  VideoRecCommThr     video IPC
         1  TuxedoAppCommTh     /tuxedo IPC

matching the wchan census exactly: 20 in `futex_wait_queue_me`, 2 on message
queues, 1 in `sys_rt_sigtimedwait`, 1 in `poll_schedule_timeout`.

⚠ **`/proc/PID/comm` does not exist on this kernel** (2.6.31; `comm` arrived in
2.6.33), so the thread names must be read from field 2 of
`/proc/PID/task/TID/stat`. A `comm`-based check returns empty and looks like "the
threads are unnamed".

This is a genuine 20-thread `HttpCmdThreadPool`, not the classic single-threaded
SoDisp build: pool size comes from `HttpServerConfig_setNoOfHttpCommands(cfg, 20)`
at 0x1081c, and the workers run the same `HttpServer_serviceRequest` the dispatcher
would. Handlers are reachable from **21** threads — the 20 workers plus the
dispatcher, which serves the request itself whenever every worker is busy.

Measured independently on the bench: **25 sequential requests were served on 20
different threads** (qemu assigns one CPU per guest thread; the trace prefix
`Trace N` is that CPU).

🔑 **And the requests genuinely interleave.** A single dispatcher mutex is held
across a request, which *looks* like it rescues a global arena. It does not: the
mutex is **dropped around every blocking `send()`** on both the plain and the TLS
path. Read out of the binary, plain path `SoDispCon_execute`:

    68a78  cmp     r8, #0            ; no lock object?
    68a7c  beq     68ae4             ;   -> skip, already unlocked
    68a80  bl      pthread_self
    68a84  ldr     sl, [r8]          ; sl = owner tid word
    68a8c  cmp     sl, r0            ; am I the owner?
    68a94  bne     68ae4             ;   -> not mine, skip
    68a98  str     r5, [r4], #4      ; owner = 0, and r4 = &mutex  (r8+4)
    68aa0  bl      pthread_mutex_unlock      <-- LOCK RELEASED
    68ac0  bl      send                      <-- BLOCKS HERE, unlocked
    68acc  bl      pthread_mutex_lock        <-- reacquired
    68adc  str     sl, [r8]          ; owner restored

So the object is an owner-tid word at `[r8]` with the real `pthread_mutex_t` at
`r8+4`, and the release is guarded by "am I the current owner" so a reentrant
caller cannot double-unlock. The TLS path (`SoDispCon_internalWrite`, after
`SharkSslCon_encrypt`/`getEncData`) is the same shape — `pthread_self` 0x4a454,
`pthread_mutex_unlock` 0x4a474, `send` 0x4a494, `pthread_mutex_lock` 0x4a4a0 — and
that is the path the panel actually uses, since it serves HTTPS on 6280.

So while worker A is parked in `send()` mid-handler with its allocations live,
worker B acquires the mutex and enters the handler for another request. It fires on
any response larger than the 8192-byte response buffer, which is essentially every
API response.

**Therefore a scope-based bulk free at a request boundary would release memory that
another in-flight request still holds.** `json_free_all()` is process-wide; the
registries are unlocked; the scope we want is per-request and the tool is
per-process. Those cannot be reconciled without rebuilding libjson.

## 3. Why a bump arena is not even implementable here

`json_as_string` / `json_write` / `json_new` **do not allocate in Barracuda.** They
allocate *inside* libjson, through libjson's own PLT — `toCString` @0x27dbc,
`private_RemoveWhiteSpace` @0x1cda0/0x1d138, the `internalJSONNode` constructors,
`jsonChildren::inc`. Barracuda only ever sees the returned pointer. There is
nothing in Barracuda to redirect to a bump allocator.

The only real form of the idea is replacing libjson — and that has the worst blast
radius on this unit:

* `libjson.so.7` is in `DT_NEEDED` of **`/tuxedo`**, `vidrec/vidApp` and
  `audioapp`, not only Barracuda. `/tuxedo` owns the alarm bus.
* There are **two different copies**: `usr/lib/libjson.so.7.6.1` (md5 `6aa09429`)
  and `vidrec/lib/libjson.so.7` (md5 `610d5009`), and
  `/etc/rc.d/init.d/startup` puts `/vidrec/lib` on `LD_LIBRARY_PATH` — so you can
  patch the copy a given process does not load. Both are byte-identical in
  `json_free`, but any offset-level work must be redone against whichever is mapped.

## 4. This explains the LEAK 29 crash, which we had already suffered

**`json_free` is not a `free()` wrapper.** Disassembled at libjson 0x21000:

    21008  subs r7, r0, #0 / beq        ; NULL is safe, early out
    21030  ldr  r4, [sl, r9]            ; r4 = the string registry map
    21048  ldr  pc, [sl, r3]            ; map::find(&ptr) -> r0
    21058  mov  r6, r0                  ; r6 = the find result
    21050  add  r4, r4, #4              ; r4 = end()
    2105c  subs r4, r4, r0              ; r4 = (found != end())  -- a BOOLEAN
    21060  movne r4, #1
    2107c  bl   JSONDebug::_JSON_ASSERT(r4, msg)   ; NON-FATAL, returns
    21094  bl   _Rb_tree_rebalance_for_erase(r6, ...)  ; uses r6, IGNORES r4
    21098  bl   operator delete(r6)
    2109c  ldr  r3, [r4, #20] / sub #1 / str        ; size--
    210ac  bl   free(r7)                            ; the real free, LAST

The membership test is computed into `r4`, handed to a **non-fatal** assert, and
then **never branched on**. So for a pointer libjson never issued, `find` returns
`end()` — the map's own header node — and the code proceeds to
rebalance-for-erase it and `operator delete` **the registry's header**, decrement
the size word, and only then `free()` the foreign pointer.

That is three destructive operations, and the glibc abort is the *last* of them:

    *** glibc detected *** free(): invalid pointer: 0x40bddcd8 ***

which is why the address in the message was the foreign pointer and named nothing
registry-related — by then the registry was already destroyed. LEAK 29's failure
was not mistiming and not the wrong allocator: the slot simply did not hold a
registered libjson pointer.

✅ Passing NULL is safe (early-out at 0x21008), so a stub that fires on an
already-cleared slot costs nothing.

✅ **No shipped stub has armed this landmine** — checked, not assumed.
`mkapifix.py` routes libjson-produced strings to `JSON_FREE_PLT` 0xBCA0 and uses
`FREE_PLT` 0xC150 only for genuinely `malloc`'d buffers (Base64 output, HMAC and
base64 buffers). The 24 live fixes are contract-correct.

## 5. What a correct scope-based design would have to look like

Not an allocator at all. Wrap the libjson **producer** PLT entries in Barracuda,
retain each returned pointer, and release it through `json_free` at the request
boundary. Every pointer held is then a genuine registered libjson pointer, so
`json_free` is the contract-correct call and the registry stays consistent. That
removes the arena-pointer-meets-real-free class entirely.

The boundary exists and is clean:

    HttpServer_serviceRequest 0x6f2cc  …  HttpServer_releaseResources 0x6f404
    4-instruction prologue, single return at 0x6f34c, exactly 3 callers

Space is not the constraint either: the largest dead cave is **3316 bytes at
0x11dd8–0x12acc** (3.7x the cave the current stubs use), 33 236 bytes of dead code
in total, and GOT redirection works — no RELRO, no `BIND_NOW`, lazy binding.

⚠ **But it converts heap corruption into use-after-free, which is not an
improvement in kind:**

* the untrack side must cover *every* release path, and libxml2, libcurl and
  libcrypto each reach libc `free` through their own PLT, invisible to us. The
  vendor already frees an API response string with plain `free` at 0x2903c.
* it needs a per-thread registry keyed on `pthread_self()` under a mutex, because
  of the 20 concurrent workers.
* a naive reset at that boundary would wrongly free **HttpSessions** (malloc
  0x71980), **AuthenticatedUser session attributes** (0x65914/0x65a58),
  **push-stream PushConNodes** (0x7b0c8/0x79fa0) and the retained **HttpAllocator
  request buffer** (0x6a57x) — all allocated during a request and all required to
  outlive it.

## 6. Decision, and the asymmetry that drives it

**Keep the per-site stubs.** Their failure mode is characterised, the blast radius
is one function per stub, and a revert is one table row. 24 are shipped and
measured; two endpoints are now leak-free in production.

Getting a global allocator change wrong does not cost a web-server restart — it
costs a **reboot**. `supervis` carries `SYSTEM RESTART DUE TO MAX
RECOVERY/RELAUNCH limit exeeded` and `BarracudaMemoryusageExceeded`, and the
relaunch budget is cumulative per boot. A corruption that crashes Barracuda on
every API request reaches the ceiling in minutes. That asymmetry, not the
engineering elegance, is what decides it.

## 7. ✅ What the investigation DID hand us: a zero-risk exact leak counter

`json_free` decrements the registry tree's size word at `[r4,#20]` (0x210a4, seen in
the listing above); `json_free_all` zeroes it at 0x20e3c. The map itself is reached
by a GOT-relative load (`ldr r4, [sl, r9]` at 0x21030), so its address is
recoverable from the process without running any code. **Reading that word before
and after N requests gives an exact count of outstanding libjson strings** — no
patching, no freeing, nothing on the request path. `heapwalk.py` and `chunkdiff.py`
already read guest memory through `/proc/pid/mem`, so the instrument is a few
lines.

That replaces content-guessing with a number, and it settles a question two null
results left open: **every leaked string also leaks its registry node** — a
`map<void*,void*>` node is 24 B of payload in a 32-byte chunk. So a leaked libjson
string leaks *twice*, and part of the residual histogram we have been chasing is
registry overhead rather than payload. Testable directly.

---

### Standing corrections this produced

* The balance-sheet row `malloc 63.50 / free 63.40 balanced` is **not** a
  process-wide malloc meter. The 5.2 unfreed `json_as_string` results per request
  are themselves malloc'd *inside libjson*, and a process-wide meter would have
  shown them. It meters Barracuda's own ~105 malloc PLT sites only, so it is not
  evidence that no malloc bytes leak.
* `/tmp/bd.txt` is the **v13** build, which predates the shipped json_free fixes.
  Call-site counts taken from it are the correct pre-fix baseline, but not the
  current image.

### Provenance

The four load-bearing claims were re-derived from primary sources rather than taken
from the investigation's report, because the adversarial verify pass never returned:

| Claim | How checked |
|---|---|
| mutex dropped around `send()`, both paths | `objdump -d` of 0x68a60–0x68ae4 and 0x4a3dc–0x4a4b0 |
| Barracuda cannot reach the bulk frees | `objdump -R`: 24 libjson JUMP_SLOTs, neither bulk free present |
| libjson exports the bulk frees | `nm -D --defined-only` on `libjson.so.7.6.1` |
| `json_free` erases without branching on membership | `objdump -d` of 0x21000–0x210c8 |

The 20-thread census was measured on the panel itself
(`/proc/PID/task/*/stat` field 2), corroborated by the wchan census.

⚠ One thing here is NOT verified and is not needed for the decision: nobody has
observed two handler entries interleaving in a trace under parallel load. The
mutex-drop listing makes it structurally possible, which is enough to rule the arena
out — but do not cite an observed interleave, because there isn't one.
`scratchpad/concurrency.sh` is the test if it is ever wanted.
