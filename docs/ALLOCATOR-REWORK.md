# Reworking the allocator so memory frees itself: assessed, rejected

**Question, 2026-09-08:** rather than keep adding per-site free stubs, can the
allocator be reworked so leaked memory is freed by *scope* instead of by
*ownership*? Every failure in this work has come from guessing which code owns a
pointer; scope-based freeing removes the question.

**Answer: the idea is sound, the machinery already exists in the vendor's own
library, and it still must not be used here** — the 20 concurrent request threads of
§2 give it the wrong scope. The investigation produced a better diagnostic and a
corrected model of an earlier crash.

---

## 1. libjson already implements it

`libjson.so.7.6.1` is compiled with **`JSON_MEMORY_MANAGE`**. It keeps a global
registry of every pointer its C interface hands out, and it **exports bulk frees**:

    json_free_all      libjson VA 0x20de0   (544 B)
    json_delete_all    libjson VA 0x2458c   (544 B)
    auto_expand::purge        0x156e8       frees every registered string
    auto_expand_node::purge   0x1569c       deletes every registered node

Both **read no argument register** (r0 is redefined at 0x20df0 / 0x2459c before
any read), which fits `void json_free_all(void)` and equally a one-argument variant
whose parameter is dead; no header or debug info in the tree settles the prototype.
On AAPCS it is moot — calling with zero arguments is safe either way — but do not
write "void signature" as proven.

Two registries, both `std::map`, singletons at `0x35cd4` (strings) and `0x35c9c`
(nodes), reached from GOT slots 0x358a4 and 0x35978 (`R_ARM_GLOB_DAT` →
`jsonSingletonSTRING_HANDLER::getValue()::single` and `…NODE_HANDLER…`). GOT base is
0x35478, matching `_GLOBAL_OFFSET_TABLE_` in the symbol table.

Every string-returning API call registers unconditionally through one choke point,
**`toCString` @0x27d78** — malloc, then an insert with no branch that could skip it.
So `json_as_string`, `json_write`, `json_write_formatted`, `json_name` and
`json_strip_white_space` results are all tracked. Nodes register on a *separate*
path — `operator new` plus an `internalJSONNode`/`JSONNode` constructor — so no
single allocation helper spans both.

Each registry is a function-local static, so its first use runs the usual
`__cxa_guard_acquire` / `__aeabi_atexit` pair (0x20e04 / 0x20ec8 in `json_free_all`)
to construct it and register its destructor. Hence `purge` has four call sites, not
two: the two bulk frees plus the atexit destructors `__tcf_8` (0x20244) and `__tcf_9`
(0x203b4). Everything registered is purged at process exit, harmlessly, which is why
the leak never shows up as a shutdown complaint.

All four are present in `usr/lib/libjson.so.7.6.1` at those addresses
(`nm -D --defined-only`).

**Barracuda never imports either bulk free** — verified against the relocation
table: 24 `R_ARM_JUMP_SLOT` libjson imports, with `json_free_all` /
`json_delete_all` in none of them. So the machinery is present but unreachable from
the web server. Nothing in this repo recorded it before.

## 2. The blocker: 20 concurrent request threads

    panel /proc/PID/task/*/stat, field 2:
        20  ThreadPool          the HTTP worker pool
         2  Barracuda           main + SoDisp dispatcher
         1  VideoRecCommThr     video IPC
         1  TuxedoAppCommTh     /tuxedo IPC

matching the wchan census exactly: 20 in `futex_wait_queue_me`, 2 on message
queues, 1 in `sys_rt_sigtimedwait`, 1 in `poll_schedule_timeout`.

**`/proc/PID/comm` does not exist on this kernel** (2.6.31; `comm` arrived in
2.6.33), so thread names must be read from field 2 of `/proc/PID/task/TID/stat`. A
`comm`-based check returns empty, which looks like unnamed threads.

This is a genuine 20-thread `HttpCmdThreadPool`, not the classic single-threaded
SoDisp build: pool size comes from `HttpServerConfig_setNoOfHttpCommands(cfg, 20)`
at 0x1081c, and the workers run the same `HttpServer_serviceRequest` the dispatcher
would. Handlers are reachable from **21** threads — the 20 workers plus the
dispatcher, which serves the request itself when every worker is busy.

Measured independently on the bench: **25 sequential requests were served on 20
different threads** (qemu assigns one CPU per guest thread; the trace prefix
`Trace N` is that CPU).

**The requests interleave.** A single dispatcher mutex is held across a request,
which looks like it rescues a global arena. It does not: the mutex is **dropped
around every blocking `send()`** on both the plain and the TLS path. Read out of the
binary, plain path `SoDispCon_execute`:

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
that is the path the panel uses, since it serves HTTPS on 6280.

So while worker A is parked in `send()` mid-handler with its allocations live,
worker B acquires the mutex and enters the handler for another request. It fires on
any response larger than the 8192-byte response buffer, i.e. nearly every API
response.

**So a scope-based bulk free at a request boundary would release memory another
in-flight request still holds.** `json_free_all()` is process-wide and the registries
are unlocked; the scope wanted is per-request. The two cannot be reconciled without
rebuilding libjson.

**Demonstrated accidentally.** A later fix attempt handed `json_delete` a pointer
that was not a JSONNode; it hung inside `deleteJSONNode` instead of crashing. One API
request stopped the **entire server** answering — plain HTTP on `:80` returned nothing
afterwards, with the process still alive and its log clean. A single worker stuck
while holding the dispatcher mutex blocks every other request, which is the failure a
global free-by-scope would produce.

## 3. A bump arena cannot be scoped where it needs to be

`json_as_string` / `json_write` / `json_new` **do not allocate in Barracuda.** They
allocate *inside* libjson, through libjson's own PLT — `toCString` @0x27dbc,
`private_RemoveWhiteSpace` @0x1cda0/0x1d138, the `internalJSONNode` constructors,
`jsonChildren::inc`. Barracuda only ever sees the returned pointer. So there is
nothing *in Barracuda* to redirect to a bump allocator.

**The allocator is nonetheless replaceable — just not at a useful scope.** Every
allocator reference in both binaries is a lazily-bound `R_ARM_JUMP_SLOT`
(libjson: malloc 0x35570, realloc 0x3562c, free 0x3566c, `_Znwj` 0x35624, `_ZdlPv`
0x356d8; Barracuda: 0x55a420 / 0x55a540 / 0x55a5ac), libjson has **no `DT_FLAGS`
entry at all** — no `DF_SYMBOLIC`, no `DF_BIND_NOW` — and Barracuda is a non-PIE
`EXEC` with a normal interpreter. So one `LD_PRELOAD` definition would interpose for
both. **But interposition is process-wide**: it replaces malloc/free for Barracuda's
own allocations, libstdc++, libxml2, libcurl and libssl too, and cannot tell "this
allocation belongs to request N" from "this one must outlive it". The scope is wrong,
not impossible — put that way because "impossible" invites someone to disprove it and
then build the dangerous thing.

The only form that reaches libjson scope is replacing libjson, which has the worst
blast radius on this unit:

* `libjson.so.7` is in `DT_NEEDED` of **`/tuxedo`**, `vidrec/vidApp` and
  `audioapp`, not only Barracuda. `/tuxedo` owns the alarm bus.
* There are **two different copies**: `usr/lib/libjson.so.7.6.1` (md5 `6aa09429`)
  and `vidrec/lib/libjson.so.7` (md5 `610d5009`), and `/etc/rc.d/init.d/startup`
  puts `/vidrec/lib` on `LD_LIBRARY_PATH` — so you can patch the copy a given
  process does not load.
  **The panel's Barracuda maps the `/vidrec` copy, not the `usr/lib` one** —
  read out of `/proc/PID/maps` on the unit, so anyone reasoning from
  `usr/lib/libjson.so.7.6.1` is reading a library the web server does not load.
  **For this work it makes no difference, and that was checked:** the two have
  identical section tables (names, addresses, sizes), a byte-identical `json_free`,
  and the same addresses for both registries, both init guards and both bulk frees.
  They differ by 499 bytes of non-loaded content. So one address set serves both —
  but re-check that before trusting it for a *different* offset.

## 4. This explains the LEAK 29 crash

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
`end()` — the map's own header node — and the code rebalance-for-erases it,
`operator delete`s **the registry's header**, decrements the size word, and only then
`free()`s the foreign pointer.

Three destructive operations, and the glibc abort is the *last* of them:

    *** glibc detected *** free(): invalid pointer: 0x40bddcd8 ***

so the address in the message was the foreign pointer and named nothing
registry-related — by then the registry was already destroyed. LEAK 29's failure
was not mistiming and not the wrong allocator: the slot simply did not hold a
registered libjson pointer.

Passing NULL is safe (early-out at 0x21008), so a stub that fires on an
already-cleared slot costs nothing.

**`json_delete` does NOT share the flaw.** At 0x25adc it runs the same lookup but
**branches on it** — `cmp r1, r0` / `beq 25b48` at 0x25b30 skips the erase when
`find()` returned `end()` — then calls `deleteJSONNode` on the pointer regardless. So
only `json_free` can corrupt the registry. When a *delete* stub misbehaves, the
registry is intact and the fault is the object's lifetime; when a *free* stub
misbehaves, the registry may already be destroyed and nothing downstream can be
trusted.

**No shipped stub has armed this landmine** — checked.
`mkapifix.py` routes libjson-produced strings to `JSON_FREE_PLT` 0xBCA0 and uses
`FREE_PLT` 0xC150 only for genuinely `malloc`'d buffers (Base64 output, HMAC and
base64 buffers). The 24 live fixes are contract-correct.

## 5. What a correct scope-based design would require

Not an allocator at all. Wrap the libjson **producer** PLT entries in Barracuda,
retain each returned pointer, and release it through `json_free` at the request
boundary. Every pointer held is then a registered libjson pointer, so `json_free` is
the contract-correct call and the registry stays consistent, which removes the
arena-pointer-meets-real-free class entirely.

The boundary is clean:

    HttpServer_serviceRequest 0x6f2cc  …  HttpServer_releaseResources 0x6f404
    4-instruction prologue, single return at 0x6f34c, exactly 3 callers

Space is not the constraint: the largest dead cave is **3316 bytes at
0x11dd8–0x12acc** (3.7x the cave the current stubs use), 33 236 bytes of dead code
in total, and GOT redirection works — no RELRO, no `BIND_NOW`, lazy binding.

**But it converts heap corruption into use-after-free, which is no improvement:**

* the untrack side must cover *every* release path, and libxml2, libcurl and
  libcrypto each reach libc `free` through their own PLT, invisible to us. The
  vendor already frees an API response string with plain `free` at 0x2903c.
* it needs a per-thread registry keyed on `pthread_self()` under a mutex, because
  of the 20 concurrent workers.
* a naive reset at that boundary would wrongly free **HttpSessions** (malloc
  0x71980), **AuthenticatedUser session attributes** (0x65914/0x65a58),
  **push-stream PushConNodes** (0x7b0c8/0x79fa0) and the retained **HttpAllocator
  request buffer** (0x6a574) — all allocated during a request and all required to
  outlive it.
* **the boundary nests.** `HttpResponse_incOrForward` (0x6e5c4) carries a
  forward/redirect depth counter tested against 9 (`cmp r3, #9` at 0x6e5e4 and
  0x6e608, `baFatalEf` at 0x6e694 on overflow), so `serviceRequest` re-enters up to
  ten deep. The arena would have to be a **stack** of scopes; a reset on the inner
  return would free the outer request's allocations.

### How much it would recover, and where the 733 B goes

The `/GetSceneList` histogram reconciles with the measured slope, refuting a claim
raised during this investigation that 453 B/request were unattributed. That figure
came from summing only the three chunks `chunkdiff` could name by content
(120 + 96 + 64 = 280) while ignoring the per-class counts. Summing the whole
histogram over its 300 requests:

    chunk   count    B/req
       32    1243    132.6
      120     302    120.8
       40     895    119.3
       64     556    118.6
       96     298     95.4
       16     843     45.0
       24     379     30.3
    ----------------------
              total   662.0   accounted  (90.3% of the 733 B/req slope)
                       71.0   unattributed

So the bookkeeping is sound to within 10% and the arena's payoff can be costed. The
96 B Base64 chunk is plain `malloc` and outside a libjson arena; most of the rest is
libjson-issued, putting recovery around 70–85%.

The largest class is the registry overhead this investigation predicted. A
`_Rb_tree_node<pair<void* const, void*>>` is 16 B of base plus an 8 B pair = 24 B,
which glibc serves from a **32 B** chunk — and 32 B is the biggest single class at
4.14 chunks/request. That is the shape of "every leaked string also leaks its
registry node", and it lines up with the older direct count of ~5.2 unfreed
`json_as_string` results per request, measured before some of the shipped frees
landed.

**Predicted ≈4.1 outstanding libjson strings per request, then measured.**
300 × `/GetSceneList` on the bench, build `0066ad95`, via `leakfix/jsoncount.py`:

    strings   69 ->  1007    =  938 / 300 =  3.1267 per request
    trees      4 ->   304    =  300 / 300 =  1.0000 per request
                                          ------------------
    registry nodes total                     4.1267 per request
    32 B chunks in the histogram             4.1433 per request   (0.40% apart)

**The prediction was wrong literally** — strings alone are 3.13, not 4.14 — and right
once **both** registries are counted: the strings map holds `pair<void*, void*>` and
the nodes map `pair<void*, JSONNode*>`, both 8-byte pairs, so both produce 24 B tree
nodes in 32 B chunks feeding the same class. Summed, they land on the observed 4.1433
to within 0.4%.

So the largest class in the biggest remaining leak is **132 B/request of pure
libjson bookkeeping**, and no per-site stub can target it directly: a registry node
is only released by a real `json_free`/`json_delete` on the pointer it tracks. Each
correct free recovers its node for nothing.

**The counter also found a leak the histogram could not name: exactly 1.0000
JSONNode tree per request.** 300 requests, 300 trees, an integer match — one tree
built per request and never `json_delete`d, a distinct defect from the string leaks.

It then located that tree (`json_new` at 0x1ef04, top of `WnmpDir_serviceField`) and
refuted two candidate fixes, each with a different signature: a fix at
`WnmpDir_service` 0x2a084 moved the count by *nothing* (that code never runs), and
one at 0x2955c *wedged* the request (that code runs, but the tree is still live). An
exact integer instrument distinguishes "wrong path" from "right path, wrong
lifetime"; the page-quantised RSS slope before it could do neither. Both attempts are
recorded and disabled in `leakfix/mkapifix.py`; the leak stands, unfixed.

Do not quote this bench instance's byte slope. `leakprobe` reported 2957 B/request
against the panel's measured 733, an unexplained 4× disagreement; the counter deltas
are exact integers and agree with the panel-derived histogram, so they are the
trustworthy half of this run.

README correction: the 64 B class runs at **1.85 chunks/request**, not the "one of
each per request" recorded for the three named chunks. There is a second 64 B
allocation beyond the named `{"Status":"Sucess"…}` one.

## 6. Decision

**Keep the per-site stubs.** Their failure mode is characterised, the blast radius
is one function per stub, and a revert is one table row. 24 are shipped and
measured; two endpoints are now leak-free in production.

Getting a global allocator change wrong does not cost a web-server restart — it
costs a **reboot**. `supervis` carries `SYSTEM RESTART DUE TO MAX
RECOVERY/RELAUNCH limit exeeded` and `BarracudaMemoryusageExceeded`, and the
relaunch budget is cumulative per boot. A corruption that crashes Barracuda on
every API request reaches the ceiling in minutes.

## 7. What the investigation produced: an exact leak counter (bench only)

`json_free` decrements the registry tree's size word at `[r4,#20]` (0x210a4, seen in
the listing above); `json_free_all` zeroes it at 0x20e3c. **Reading that word before
and after N requests gives an exact count of outstanding libjson strings** — no
patching, no freeing, nothing on the request path. `heapwalk.py` and `chunkdiff.py`
already read guest memory through `/proc/pid/mem`, so the instrument is a few lines.

**The addresses, so this never has to be re-derived** — library-relative, add the
`libjson.so.7.6.1` load base from `/proc/PID/maps`:

    strings outstanding   base + 0x35ce8      (registry 0x35cd4 + 20)
    nodes   outstanding   base + 0x35cb0      (registry 0x35c9c + 20)
    init guards           base + 0x35a90 (strings), 0x35a94 (nodes)

Offset 20 is `_M_node_count`, confirmed twice over: the code computes `end()` as
`map+4` before calling `_Rb_tree_rebalance_for_erase`, and **both singletons have
`st_size` exactly 24** — the only layout that fits (4 pad + 16 `_Rb_tree_node_base`
header + 4 count). Read the guard word first: zero means the singleton is not
constructed yet and the count is trivially 0.

Implemented as [`leakfix/jsoncount.py`](../leakfix/jsoncount.py), working — the
numbers in §3 are its output.

**It cannot be run on the panel, and the reason is the kernel.** On 2.6.31
`/proc/PID/mem` refuses every cross-process read with **`ESRCH`** — measured against
the live Barracuda, at offset 0 as well as at a mapped address, so it is not an
addressing mistake. `mem_read` before 2.6.39 requires the target to be
ptrace-attached *and stopped* by the reader, and stopping Barracuda makes `supervis`
relaunch it, spending budget. The panel also has **no interpreter at all** — no
`python`, `python2`, `python3` or `perl`, only `dd`, `od` and `hexdump` — so a shell
port buys nothing: the obstacle is the read, not the language.

So the instrument is zero-risk **and bench-only**. The bench runs the same build as
the panel (`0066ad95`) and its counter output reconciles with the panel-derived
histogram to 0.4%, so bench counts are good evidence about panel behaviour — but they
are not a panel measurement and must not be reported as one.

It replaces content-guessing with a number, and settles a question two null results
left open: **every leaked string also leaks its registry node** — a
`map<void*,void*>` node is 24 B of payload in a 32-byte chunk, so a leaked libjson
string leaks *twice*. §3 has the numeric test.

---

### Standing corrections this produced

* The balance-sheet row `malloc 63.50 / free 63.40 balanced` is **not** a
  process-wide malloc meter. The 5.2 unfreed `json_as_string` results per request
  are themselves malloc'd *inside libjson*, and a process-wide meter would have
  shown them. It meters Barracuda's own ~105 malloc PLT sites only, so it is no
  evidence that malloc bytes do not leak.
* `/tmp/bd.txt` is the **v13** build, which predates the shipped json_free fixes.
  Call-site counts taken from it are the correct pre-fix baseline, not the current
  image.

### Provenance

These claims were re-derived from primary sources rather than taken from the
investigation's report, because the adversarial verify pass never returned:

| Claim | How checked |
|---|---|
| mutex dropped around `send()`, both paths | `objdump -d` of 0x68a60–0x68ae4 and 0x4a3dc–0x4a4b0 |
| Barracuda cannot reach the bulk frees | `objdump -R`: 24 libjson JUMP_SLOTs, neither bulk free present |
| libjson exports the bulk frees | `nm -D --defined-only` on `libjson.so.7.6.1` |
| `json_free` erases without branching on membership | `objdump -d` of 0x21000–0x210c8 |
| registry addresses and the count at offset 20 | `objdump -R` on the two GOT slots; `readelf -Ws` for addresses and `st_size` 24 |
| the boundary nests | `objdump -d` of `HttpResponse_incOrForward` 0x6e5c4 |
| singleton lazy-init registers an atexit dtor | `objdump -d` of `json_free_all`: guard 0x20e04, `__aeabi_atexit` 0x20ec8 |
| the panel maps the `/vidrec` copy | `grep libjson /proc/PID/maps` on the unit; md5 `610d5009` |
| the two copies agree on every address used | `readelf -Ws`, `objdump -h`, and a byte diff of `json_free` |
| `/proc/PID/mem` is unreadable on the panel | `dd` on the unit → `ESRCH` at offset 0 and at a mapped address |
| the counter's numbers | `leakfix/jsoncount.py`, 300 × `/GetSceneList`, bench `0066ad95` |

The 20-thread census was measured on the panel itself
(`/proc/PID/task/*/stat` field 2), corroborated by the wchan census.

One claim is NOT verified, and is not needed for the decision: nobody has observed
two handler entries interleaving in a trace under parallel load. The mutex-drop
listing makes it structurally possible, which is enough to rule the arena out — but
do not cite an observed interleave, because there isn't one.
`scratchpad/concurrency.sh` is the test if it is ever wanted.
