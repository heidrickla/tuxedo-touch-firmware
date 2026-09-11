# P15 leak fix: tooling and derivation

The vendor webserver leaked **1488 bytes per API request**, **7537 per
`/tuxedoapi.html` request**, **10880 per IPC status message**, **727 per
`/scene_configuration.html` view** and **704 per `/groups.html` view**. All of
those now measure zero. `patches.tsv` carries the **228** resulting rows; this
directory is how they were derived and verified, because without it those rows
are unexplained hex.

Still leaking, measured and recorded rather than assumed closed: `/GetSceneList`
at ~491 B/request after LEAK 20 — see the two `json_write` strings below.

Every site is a vendor defect present in unmodified `324209e1`. None was
introduced by our patches — `attribute.py` proves it.

## The IPC path, added 2026-09-08 (LEAKS 13-18)

HTTP-only testing could never have found this one. The bench measured 0 B per
request on both HTTP paths while the panel kept growing at ~1160 kB/h, and that
gap was the whole clue: the driver had to be something only the panel does.
`emu/pushdriver.py` injects msgType 21/22 straight into `/Q_ServCmdTrsmtr` and
reproduces it with no panel involved.

    gettuxedoIPCCommFunc -> pushSecurityStatus -> pushEventsToClientsDevAdded
                         -> registeredClients -> scene_getRootNodeOfObjects

| # | defect |
| --- | --- |
| 13 | `scene_getRootNodeOfObjects` frees neither the `operator new[]` file buffer nor the `json_strip_white_space` copy of it |
| 14 | `registeredClients` leaks 4 `json_as_string` results **per registry entry** |
| 15 | `registeredClients` abandons the entire parsed registry tree — no `json_delete` anywhere in the function |
| 16 | the per-entry object is allocated *before* the test that decides whether to use it, so every skipped entry leaks one |
| 17 | `pushEventsToClientsDevAdded` frees the client array but never its event payload |
| 18 | `scene_getRootNodeOfObjects` calls `getErrorNode` and the caller overwrites the result on the very next instruction |

Three different release functions are in play and using the wrong one corrupts
the heap rather than leaking: `operator new[]` takes `delete[]`,
`json_write` / `json_as_string` / `json_strip_white_space` take **`json_free`**,
and `curl_easy_escape` would take `curl_free` — which **this image does not
import**, so that one is left alone.

**Ownership was verified in `libjson.so.7.6.1`, not assumed.** `json_new_a`
reaches `JSONNode::JSONNode(std::string const&, std::string const&)` and
`json_parse_unformatted` reaches
`JSONWorker::parse_unformatted(std::string const&)`. Both take `std::string`,
so both copy, so the sources are safe to free once consumed.

### Two of these are correct but inert, and that is on purpose

`registereddevMAClist.json` is an array of six entries with **exactly four
fields each** (`DeviceMAC`, `DeviceType`, `PrivateKey`, `PublicKey`), and both
functions keep an entry only when `json_size(entry) > 4`. Four is not greater
than four, so every entry is skipped and the outbound webhook loop never runs.
LEAK 14 therefore never executes, and the three further leaks inside that loop
(`json_as_string` 0x13314, `json_write` 0x13350, `curl_easy_escape` 0x13360)
are **deliberately left unpatched** — shipping stubs no test can exercise is
how the first attempt at this fix went wrong. Use `regshape.py` to re-check the
file's shape before assuming that still holds.

### Measured, on the exact binary the panel runs

    a84c220a  (live before)                              10880 B/message
    + 13a  delete[] the file buffer                        9656   -11%
    + 13b  json_free the strip copy, plus 14 and 15        1413   -87%
    + 16, 17                                                264   -97.6%
    + 18                                                      0   -100%

208 in-use chunks before and after 100 messages, and the guest heap region did
not extend by a byte. A further 400 messages under `ipcverify.sh` changed
nothing, and the HTTP API path still measures 0.0 B/request.

**Meter the GUEST heap, never qemu's RSS.** The qemu process grows ~34.9 kB
per message against the guest's 10.9 kB; the difference is qemu's own
per-guest-thread cost, which the panel does not pay. An early figure of
"38.5 kB per message" was that confound.

**`--without-ipc` rebuilds `a84c220a` byte-for-byte.** That is the control:
run it after any edit here, and if the md5 moves you changed something you did
not mean to.

## LEAK 19: every `json_strip_white_space` result in the image (43 sites)

The image makes **44** `json_strip_white_space` calls and **all 44** are
immediately followed by `bl json_parse_unformatted`, adjacent, no exceptions.
The parse's return value overwrites `r0`, so the only pointer to the stripped
copy is destroyed by the call that consumes it.

**This was found by measurement, and only because the UI pages got driven for
the first time.** Every path anyone had thought to test read zero:

| page | before | after |
| --- | --- | --- |
| `/scene_configuration.html` | 727.9, then 726.7 B/req | see below |
| `/devicelist.html` | 180.2, then 179.1 B/req | |
| `/camerasetup.html` | 0.0 | |
| `/tuxedoapi.html` | 0.0 (negative control, same session) | |

`heapwalk.py` pinned it to one 648-byte chunk per request and `chunkdiff.py`
dumped the contents — the voice-command vocabulary.
`voicecommandglobal.json` is exactly 640 bytes; 640 + 8 = 648. The chain is
`scene_configuration::service` → `requestHandler` (a jump-table dispatcher) →
`getRootNodeOfObjects` (0x34340), a near-clone of `scene_getRootNodeOfObjects`
that returns the raw `new[]` buffer instead of a tree. The caller frees the
buffer; nothing frees the strip copy.

**One shared 36-byte stub covers all 43 sites** (0x34964 is excluded — it is
already redirected to the IPC stub, which additionally frees that site's
`operator new[]` buffer). This needs **no per-site liveness analysis**, which
is unusual enough to justify:

- the two calls are adjacent at *every* site, so `r0` on entry is always the
  strip result — there is no site where it is something else;
- `json_parse_unformatted` takes `std::string const&`, so the tree holds copies
  and retains no pointer into the input;
- the original code already lets the parse's return value destroy the pointer,
  so nothing downstream can be using it.

The builder guards **both** words at each site — the `bl
json_parse_unformatted` and the preceding `bl json_strip_white_space` — so
anything that is not actually this pattern refuses rather than being silently
rewritten.

There are **58** `json_parse_unformatted` calls but only 44 follow a strip.
Redirect only the 43; the rest take a different argument.

## Page sweep: every measurable page reads 0.0 after LEAK 19

    0.0 B/request   tuxedoapi, home, console, consolekeypad, devicelist,
                    groups, multipartition, bookmarksView, camerasetup,
                    camaddedit, camsingleview, videoplayback, videoscreen,
                    scene_configuration, mobileview, eventhandler
    302 by design   index, occupancy, pList  -- their 0.0 means nothing
    unmeasurable    zwavedevicelist

**`/zwavedevicelist.html` wedges the webserver under a couple of hundred
requests, on the patched and unpatched builds alike** — so it is a vendor
defect, not a regression. At 20 requests it is harmless; at 200 the server stops
answering *any* page while the process stays alive, sleeping, with all four
listeners bound. A restart clears it. Same family as the ~60-parameter API
crash in `docs/TUXEDO-AUDIT-BUGS.md`.

It first looked like the documented "wedges under sustained load", because in
the sweep it sat at position 17 and everything after it failed too. Running it
**first** on a freshly started server wedges it immediately. When a failure
shows up late in a sequence, re-run it first before concluding it is cumulative
— and A/B it against the previous build before concluding it is yours.

## LEAK 20: `getEScenes`, the `/GetSceneList` handler — 780 → 491 B/request

**Attribution took a jump table, which is why a `bl` search never found it.**
`/GetSceneList` is dispatched by ID: `Test1Module_constructor` (0x15740)
registers a 74-entry table at 0x8ab14 of `{name1_ptr, name2_ptr, id}` with the
decoder at 0x15778, which does `ldrh` the id, `bic #0xf000` to strip the flag
nibble, `sub #8`, then `ldr pc, [pc, r1, lsl #2]` into a jump table at 0x15798.
For `GetSceneList` (id 0x10018039) that is index 49 → 0x1585c → **0x159a0**,
which is a **tail-branch thunk**: `mov r1, r3 ; b getEScenes`.

`getEScenes` (0x16520, 252 bytes) is **straight-line — no conditional branches**
— and leaks four things, the same four as `getPartitionStatus`:

| where | what | patched |
| --- | --- | --- |
| 1656c | `json_write(r6)` STRING 1, destroyed by `strlen`'s return | no, see below |
| 1657c | tree B (`r7`), never deleted | **yes** |
| 165a4 | `json_write(r6)` STRING 2, destroyed by `encrypt`'s return | no |
| 165c8 | the `Base64Encode` buffer at `[fp-48]` | **yes** |

The epilogue is the safe place: at 0x165f8 both `r7` and `[fp-48]` are still
live, `r7` is callee-saved so `json_delete` preserves it, and nothing can branch
past it. **Measured 778/790 → 491.5 B/request**, two runs each, with the plain
API endpoint reading 0.0 in the same session.

### LEAKS 21 and 22 were both built, measured, and NOT shipped

Freeing STRING 1 (wrapping `bl strlen` at 0x16570) and freeing STRING 2
(wrapping `bl encrypt` at 0x165b8) each changed **nothing**: 491.5 B/request with
STRING 1 freed, with STRING 2 freed, and with neither — identical, two runs each.
Both stubs are sound; the STRING 2 build served 302 with all four listeners up
afterwards. They simply release nothing that was accumulating. Both are kept in
`mkapifix.py` with their `*_SITES` tuples emptied, so the next attempt knows what
was tried and what it produced.

**The two null results together are the useful finding: the residual is not
the strings.** The chunk histogram after LEAK 20 shows, per request, roughly

    5 x 40 B    3 x 32 B    2.7 x 16 B    1 x 64 B    1 x 56 B

— a dozen small chunks, which is the shape of a **JSON tree**, not of two large
serialised strings. Freeing strings was the wrong target, and measuring said so
twice before anything shipped.

### What the residual actually is — named by dumping the chunks

`chunkdiff.py` on the growing sizes gives it directly:

| size | contents |
| --- | --- |
| 64 B, 56 B | copies of the Base64 response string, `Rn/ljjpt3Bda8joyGqr1kdvMmt7qSWoc6eNtpVaojJw=` |
| 40 B | `{"Status":"No scenes found"}` and **`Children is null inc`** — a libjson error string |

So it is libjson error nodes plus extra copies of the encoded response, not a tree
of ours. `Children is null inc` is libjson complaining about a node with no
children, which fits: the scene database is all placeholder slots.

**AND THE BENCH IS FAITHFUL HERE — checked, not assumed.**
`hatcscenedb.json` is **byte-identical on the bench and the panel** (3182 bytes,
every entry `"id":0, "name":"", "isUsed":0`), so "No scenes found" is what the
panel returns too and this residual is real rather than an artefact of an empty
test fixture. Worth stating because the obvious worry — that the bench takes an
empty-database branch the panel does not — is exactly the mistake that cost a day
on the IPC path. Re-check the two files before trusting any future measurement
here.

Note the scene names visible in the web UI (`Bed time`, `Evening time`, ...)
come from `voicecommandglobal.json`'s `SCENES` list, **not** from
`hatcscenedb.json`. Seeing them does not mean scenes are configured.

## `/GetSceneList` STILL LEAKS 733 B/request — re-measured 2026-09-08 on `0066ad95`

The "491.5 B/request" figure below is **stale and was measured with a
page-quantised instrument**. On the current build, with the chunk histogram:

    slope 733 B/request over 300 requests, all 200
    32 B +1243   40 B +895   16 B +843   64 B +556
    24 B  +379  120 B +302   96 B +298

`chunkdiff` names the three biggest by contents, and they are the API response
chain rather than the scene tree:

    120 B   {"Result" : "H+wsszVIJ5tJnSFfrHo4KvKnmG8yASStfm8W+807n...=="}
     96 B   H+wsszVIJ5tJnSFfrHo4KvKnmG8yASStfm8W+807n...==
     64 B   {"Status":"Sucess","Result":{"Response":"No scenes found...

So the response is serialised, Base64'd, wrapped and
formatted, and **every stage is abandoned**. The 120 B chunk is the
`json_write_formatted` result `getEScenes` hands back through its out-param at
0x165f0 — the one allocation whose fate is decided by the CALLER, which is why the
handler-side analysis below could not account for it.

**The histogram reconciles with the slope — 662 of 733 B/request, 90.3%** — so
this leak is accounted for, not merely observed. Per-class rates, which matter
because the named chunks are not all one-per-request:

    32 B 132.6   120 B 120.8   40 B 119.3   64 B 118.6
    96 B  95.4    16 B  45.0   24 B  30.3    -> 662.0 B/req, 71 B unattributed

120 B and 96 B do run at ~1.0/request, but **64 B runs at 1.85/request** — there
is a second 64 B allocation beyond the named `{"Status":"Sucess"…}` one.
**The 32 B class is the largest, at 4.14 chunks/request, and it is libjson
REGISTRY OVERHEAD, not payload — MEASURED, not inferred.** libjson keeps a `std::map`
of every pointer its C API issues; a node is 16 B of `_Rb_tree_node_base` plus an
8 B pair = 24 B, which glibc serves from a 32 B chunk. Counting the two registries
directly with [jsoncount.py](jsoncount.py) over 300 × `/GetSceneList`:

    strings   69 -> 1007   =  3.1267 /request
    trees      4 ->  304   =  1.0000 /request
                             -------
    registry nodes            4.1267 /request   vs 4.1433 observed  (0.40% apart)

So **132 B/request of this leak is pure bookkeeping**, and no per-site stub reaches
it directly — a registry node is freed only by a real `json_free`/`json_delete` on
the pointer it tracks, so every correct free reclaims its node for nothing.

**EXACTLY ONE JSONNode TREE LEAKS PER REQUEST — 300 requests, 300 trees.** An
integer match, so this is a single tree built per request and never `json_delete`d.
It is a distinct defect from the string leaks and it has an exact rate.

The tree is identified: `json_new` at **0x1ef04**, at the very top of
`WnmpDir_serviceField` before any endpoint dispatch, with `json_push_back` at
0x1f014 erasing its child (hence net +1, not +2). Of the ~350 `json_new` and ~330
`json_write` sites in that generated dispatcher, tracing the whole function shows
**only two libjson calls run per request, and no `json_delete`, `json_free` or
`json_write` at all**.

**Two candidate fix sites are now REFUTED, each by a different signature** — see
LEAK 30 in [mkapifix.py](mkapifix.py), where both are kept disabled:

| Site | Result | What it means |
|---|---|---|
| `WnmpDir_service` 0x2a084 | A/B moved the counter by **nothing**, server healthy | the code never runs on this path |
| `WnmpDir_serviceField` 0x2955c | the request **wedges**; process survives, no abort | the code runs, but the object is still live |

A null result and a hang are different evidence, and neither is a crash: nothing here
was a mismatched free. 0x2955c genuinely does jump past the vendor's own
`json_delete` pair at 0x29860 — **and stock has the identical branch, so the leak is
the vendor's, not ours** — but r7 is not dead there. The tree is the request-scoped
root the whole dispatcher shares, so its real release point is likely in the
**caller**, after the response is written. Read the caller's frame; do not add a
third delete inside `serviceField`.

Background and the full derivation: [../docs/ALLOCATOR-REWORK.md](../docs/ALLOCATOR-REWORK.md)
§3 and §7. The counter is **bench-only** — the panel's 2.6.31 kernel refuses
`/proc/PID/mem` with `ESRCH` unless the target is ptrace-stopped.

**This is the API surface, so today's `cmd=140`/`cmd=141` fixes do not touch
it** — different auth, different path. It is the largest single leak known in the
image.

### AND IT IS CONFIRMED ON THE PANEL, scaling properly

    N=300   panel VmRSS 5628 -> 5852 kB   +224 kB   = 764 B/request
    N=900   panel VmRSS 5852 -> 6552 kB   +700 kB   = 796 B/request

Tripling the load tripled the growth, so unlike the `cmd=141` residual this is a
real per-request rate, and it agrees with the bench's 733 B/request.

**Do not read `leakprobe`'s own `rss:` line for a panel run.** It reported
`24044 -> 24044 kB, slope 0.0` while the panel grew 224 kB. `leakprobe` measures a
LOCAL pid — the emulator on the build VM — so against a remote host it is measuring
the wrong process entirely and will report a clean zero for any leak. Read the
panel's own `VmRSS`.

**What it costs:** ~780 B/request. If the scene page polls this the way
`/console.html` polls `commandID=5002` (every 5 s, 720/hour), that is roughly
**560 kB/hour with a scene page left open** — against ~70 MB free, so days rather
than weeks. That is the number that decides whether a structural fix is worth its
risk.

Honest note: taking this measurement leaked about 0.9 MB into the live panel
(1200 requests), which will not come back until Barracuda restarts. Harmless at
70 MB free, but it is the cost of measuring this endpoint on the unit.

### LEAK 29 attempted the obvious fix and it CRASHES — do not repeat it

The owner of that 120 B chunk looked settled. `WnmpDir_serviceField` calls the
module through a vtable and drops the out slot:

    2908c  str r1(=0), [fp,#-868]        the out slot, initialised
    290b0  ldr pc, [r4, #12]             module->get(..., out=&slot, ...)
    290e0  WnmpModule_printFieldControl(..., &slot, ...)
    290fc  ldr r4, [r7, #4]              <- slot dropped here

and the vendor's **own sibling path** shows the intended shape, print-then-free:

    29018  ldr pc, [ip, #16]   -> r0 = a string
    29034  HttpResponse_printf(r9, r4)
    2903c  bl free             <- FREED

Traced on `/GetSceneList`: 0x290b4, 0x290e0 and 0x290fc each run once per request
and the freeing sibling at 0x29014 runs **zero** times. Every one of those facts is
true. Freeing the slot at 0x290fc still produces, on the first request:

    *** glibc detected *** /opt/webserver/Barracuda: free(): invalid pointer:
        0x40bddcd8 ***

which also means **the 120 B chunk is not leaked at this site** and the
733 B/request is elsewhere in the chain.

**An ownership argument assembled from a sibling path is a hypothesis, not a
contract.** Four independent true observations pointed one way and the conclusion
was still wrong.

**And this is exactly why it was bench-only.** `WnmpDir_serviceField` serves
EVERY API endpoint, so on the panel this would have corrupted the heap on the
first API request and cost two relaunch units per crash. The panel never saw it —
it stayed on `0066ad95` throughout, with zero glibc errors in its log.

**Both allocators were tried and both crash.** `json_free` first, then plain
`free` to match the vendor's sibling — same result. So the slot at `[fp-868]` is
simply not a pointer this code may release, and the site is dead as a candidate.

**`WnmpModule_printFieldControl` (0x1e48c) does not free it either** — 600 lines,
**zero** `free`/`json_free`/`json_delete` calls, checked. So neither the dispatcher
nor its callee releases the slot, yet releasing it is invalid.

**The mechanism is now known, and it was NOT a double free** — see
[../docs/ALLOCATOR-REWORK.md](../docs/ALLOCATOR-REWORK.md) §4, which disassembles
both allocators. One reason per attempt:

* **`json_free` is not a `free()` wrapper.** It looks the pointer up in libjson's
  registry, computes "was it registered" into a register, hands that to a
  **non-fatal** assert, and then **never branches on it** — so an unregistered
  pointer makes it rebalance-for-erase and `operator delete` the registry map's own
  header node before it ever reaches `free()`. Handing it a non-libjson pointer
  corrupts the heap regardless of who owns the pointer, so that attempt could never
  have worked and tells us nothing about ownership.
* **plain `free` reported `invalid pointer`**, which in glibc is the
  chunk-alignment / arena-bounds check — *not* the double-free check, which reports
  `double free or corruption`. So the slot does not hold a malloc'd heap pointer.

Between the two possibilities this section left open, that confirms the second:
**the slot does not hold the string by the time 0x290fc runs.** Nobody frees it
early; it was never the string's home.

**Where the next attempt should start, given all of the above:** stop reasoning
about who *should* free it and read what the slot actually contains at 0x290fc.
The crash address `0x40bddcd8` is far outside the heap `heapwalk` walks
(0x56b000-0x5f5000), so the value there is probably not the response string at all
— which would mean the whole `[fp-868]` premise is wrong rather than the free
being mistimed. `leakfix/findsession.py` shows the technique: search guest memory
for a value you already know, instead of computing where it ought to be.

**And it revises the note below.** "Freeing STRING 1 and STRING 2 changed
nothing" was measured with the RSS slope, which cannot resolve anything under
~14 B/request; the contents above show 64-byte `json_write` output accumulating at
one per request. Re-measure those two with the chunk histogram before trusting the
null result — the instrument, not the fix, may have been the problem.

**Where to look next — two candidates already eliminated.**

- `Base64Encode` (0x1cf20) is **balanced**: `malloc ; fmemopen ; BIO_new(b64) ;
  BIO_new_fp ; BIO_push ; BIO_write ; BIO_ctrl ; BIO_free_all ; fclose`. The two
  BIOs are chained, so one `BIO_free_all` releases both — the textbook OpenSSL
  idiom. Its single `malloc` is the output buffer, which LEAK 20 frees.
- `encrypt` (0x1cdf8) is **balanced**: `EVP_CIPHER_CTX_new` / `EVP_CIPHER_CTX_free`.

**One theory tried and refuted, recorded so it is not tried again:** that
`json_push_back` COPIES the node `json_new_a` returns, leaving the original
unowned. If that were true, every `json_new_a` + `json_push_back` pair in the
image would leak a node — and the API path, which uses that pair, measures
**0.0 B/request**. So `push_back` takes ownership and the node dies with its
tree. The API path reading zero is the evidence.

That leaves the allocation unattributed. The next step is a trace rather than
more static reading: `serve-traced.sh` over `getEScenes` and its callees with a
wide `-dfilter`, comparing executed blocks against the frees, which is how the
`getPartitionStatus` leaks were found. Before spending that effort, weigh that
this endpoint is polled only while someone has the scene page open and the panel
measures flat at idle — the libjson error nodes in particular are inside the
library and may not be reachable from our side at all.

**The RSS slope is page-quantised and cannot resolve small wins.** 144 kB over
300 requests moves in 4 kB steps, so anything under ~14 B/request is invisible to
it. Use `sceneleak.sh` for increments that size — and note that a slope repeating
to the decimal across builds is a sign it is quantisation, not stability.

**A stub at 0x165b8 must not push.** `encrypt` takes a fifth argument on the
stack (`str r5,[sp]` at 0x165ac), so moving sp hands it the wrong value. The
disabled LEAK 22 stub shows the alternative: stash in r4/r8/r9, which are each
consumed into an argument register before the call and never read again, and
return with `bx r9` because `json_free` destroys lr.

## `commandID=5002` does NOT leak — settled by construction

The console display poll runs 720 times an hour, far heavier than anything else
here, so it was the obvious suspect. It cannot leak:

    getConsoleMessage:  ldr r0, [pc]   -> the static buffer 0x55b7e4
                        bx lr
    the 5002 arm:       bl getConsoleMessage ; HttpResponse_printf ; exit

Three instructions and no allocation. The ~1965 B/poll seen while the page was
open was page-load working set, which is consistent with RSS plateauing the
moment the page closed.

`/handlerequest_mobile.html` rejects every `commandID` with
`Session_Expired` for a session obtained the normal way — the page's own
`hiddenKey` is `-1` and `hidSession` a placeholder, so something else populates
them. Driving that surface would need a bench-only session bypass; it was not
needed here because the static reading is decisive.

## Still open: the rest of `/GetSceneList`

Remaining after LEAK 20: ~491 B/request, which is STRING 1 and STRING 2 above.
The "no driver" problem is solved for the API side:

    leakprobe.py --mode api --endpoint /GetSceneList --plain operation=get

answers **HTTP 200** and leaks — 778.2 then 790.5 B/request on `13f33352`, with
the plain API endpoint reading 0.0 in the same session as a control. Of the
names tried, only `/GetSceneList` answers; `getScenes`, `getEScenes`,
`allscenes`, `GetSceneDetails`, `getSceneList`, `SceneList`,
`GetDiscoveredTuxedos` and `getDiscoverCameras` all 404.

Per-request chunk profile (≈787 B), the shape of an abandoned JSON tree:
`120x1 96x1 112x1 64x1.6 32x4.1 40x3 16x2.6 24x1.5 72x0.35`.

**Not yet attributed to a function**, and "same shape as the six below" is not
evidence — that inference is what the `getErrorNode` mistake cost once already.

The dispatch table is decoded. It sits in `.rodata`, spans at least
`0x8ac00..0x8ae40`, and holds **12-byte entries**:

    +0  name1_ptr      +4  name2_ptr      +8  id
    GetSceneList at 0x8ada8:  {0x89f40, 0x89f50, 0x10018039}

The id's low byte increments by one per entry (…0x36, 0x37, 0x38, **0x39** for
GetSceneList…), so it indexes a command; the upper bytes (0x1001, 0x1024,
0x2e10, 0x3110) are flags or a group. That low byte is **not** `commands.tsv`'s
first column — 0x39 is 57, and row 57 there is `getDiscoverCameras`. Reconcile
the two numbering schemes before trusting either.

Next: find the code scanning this table (likely a `strcmp` loop over
name1/name2 against the request operation), follow the id to the handler, patch,
and re-measure with `sceneleak.sh`.

## Still open: six latent sites on the scene and camera paths

`scene_getRootNodeOfObjects` has **eleven** callers. LEAK 13 is internal to it
and so fixes its own temporaries for all eleven, but each caller also receives
the parsed tree and owns it. Only four free it:

| caller | frees the tree? |
| --- | --- |
| `registeredClients` | no → **fixed here (LEAK 15)** |
| `discoveredTuxedos` | no |
| `checkIfSceneExists` | no |
| `deleteExistngScene` | no |
| `checkSceneNameExists` | no |
| `editSceneDetails` | no |
| `getCameraRecording` | no |
| `getMAXSceneID`, `addnewscene`, `disableScene`, `enableScene` | yes, one `json_delete` each |

**These are NOT what made the panel grow.** They run on user-initiated scene
and camera operations, not on a clock — and the panel measures flat after the
IPC fix, which is the evidence that none of them is periodic. They are latent:
each leaks a parsed tree per operation.

**Deliberately not patched, and the reasons are per-function:**

- **They cannot be driven on this bench — but NOT for the reason recorded here
  originally.** The endpoints are identified and wired up now; the blocker moved
  to a CSRF gate. `handlerequest_html076EF7::service` dispatches on
  `U32_atoi(getParameter("Type"))`, and two arms reach these functions:

      cmd 140  ->  editSceneDetails(getParameter("scenedata"))
      cmd 141  ->  deleteExistngScene(atoi(getParameter("sceneid")))

  `leakprobe.py` now takes `--extra` so console mode can carry those operands,
  and `sceneopleak.sh` drives them.

  **BUT EVERY CONSOLE-MODE REQUEST ANSWERS 200 AND DISPATCHES NOTHING.** The
  handler gates on a CSRF token *before* the switch:

      3a3c0  bl   getCSRFToken1([sp,#120])   <- keyed on the SESSION's own field
      3a3c4  subs r6, r0, #0                    [r7,#8], NOT on ?sessionid=
      3a3c8  beq  3e858                       <- no token: bail out, r5 = -1

  Traced with `-dfilter 0x3a2a0..0x3a730`, the last block executed is **`0x3a3c4`
  for `cmd` 0, 1, 140 and 141 alike** — four values, one stop, so this is the
  gate and not a per-command quirk. `handlerequest_mobile_html076EF` calls
  `getCSRFToken1` too, so it is not a way around.

  **AND THE PANEL DOES THE SAME — measured, not inferred.** The panel cannot
  be traced, so a trace-free instrument was needed:
  **`leakfix/dispatchcheck.py`**. The bail is taken *before* the switch, so it
  cannot give a command-dependent answer — if the handler dispatches, a real
  command and an out-of-range one must differ somewhere. Both hosts:

      Type=0  1  141  60000  65535   ->  200, 0 bytes, one identical sha1

  `Type=60000` and `65535` are far outside the switch bound and would have to
  reach the default arm if the dispatch were running at all. **The response body
  is EMPTY**, which is the tell that was there all along: "400 requests, all
  200" was 400 empty bodies.

  The `hiddenKey=-1` on `/console.html` is *consistent* with this but is not
  the evidence — it is rendered by a different code path from the handler's
  `r5 = -1`. The command-independence above is the measurement; cite that.

  `TuxedoProbe.login()` performs the real challenge/HMAC UI login, so being
  logged in is not sufficient on the bench. Registration goes through
  `addSessionItem` (0x2e868), called from `authPage_service`, `MyPage_service`,
  `LogOutPage_service` and `checkvalidSessions` — reached by tail-branch thunks,
  which is why a `bl` scan for `addCSRFTokenToSessionID` finds nothing and reads
  as dead code.

  ### How far the registration chase got — start here, do not redo it

  **The registrar is `authPage_service`, bound to `authenticated/index.html`.**
  `installVirtualDir` calls `HttpPage_constructor(page, 0x1418c, "index.html")`
  into the dir named `authenticated` (0x546648).

  **It needs a `url` QUERY PARAMETER, and without one it skips registration
  entirely.** Traced:

      141f0  bl   HttpRequest_getParameter(req, "url")
      141f4  subs r6, r0, #0
      141f8  beq  143c0        <- absent: jumps PAST the addSessionItem region
      141fc  bl   validatePageName

  With no `url`, the executed blocks go `0x1418c … 0x141f4 -> 0x143c0`, skipping
  everything. **With `?url=home.html` the path instead runs
  `0x1438c -> 0x14394 -> 0x14398 -> 0x143a8`** — the `bne` at 0x14390 not taken,
  `clientEnter` called, and the block containing `bl addSessionItem` at 0x143a4
  executed. So the call happens.

  **Record layout**, from `addSessionItem1` (0x2b444):
  `[0..3]` session id, `[4]` flag, `[5..]` a token string from
  `random_string(32)` + `getKeyFromPassword`.

  **RETRACTED: "it registers at index 0, which the reader never searches."**
  That was committed here and it is WRONG. `mov r8, r6` at 0x1431c is *inside*
  the basic block starting at 0x14314, and 0x14314 IS in the trace — so it does
  execute, and `r8` ends up as **the last free/reclaimed slot index**, not 0.
  The mistake was reading a trace of block ENTRIES as if a listed address were
  the only instruction that ran; every instruction from the block start to its
  terminating branch runs. `r8 = 0` at 0x142d8 is only the initial value.

  **What the loop actually does** (0x142f8..0x14340), for the next attempt:

      142f8  getSessionID(r6)              -> r4 = slot r6's stored id
      14308  HttpServer_getSession(...)    -> is that session still alive?
      14310  bne 14334                     alive -> compare with ours
      14314  cmn r4, #1 ; mov r8, r6       empty slot: REMEMBER it as reusable
      14324  removeSessionItem / clientExit   stale: reclaim it
      14334  cmp fp, r4 ; moveq sl, #1     ours already present
      143a4  addSessionItem(r8, fp, 1)     write into the remembered slot

  and `fp` is a real value, not `-1`: the `mvneq fp, #-1` arm at 0x142e4 needs
  `[sp,#4] == 0`, which cannot hold here because the path reached 0x142d0 past
  the `beq` at 0x142cc.

  ❔ **So the write looks correct and the lookup still fails. The live suspect is
  now the FRAMEWORK session, not the vendor one.** Both sides key on
  `HttpRequest_getSession(req, ...)->[r7,#8]`, and 0x142b0 calls it with the
  **create** flag. If a scripted client does not carry whatever identifies that
  framework session, every request mints a *new* one — so the id registered
  during the GET is not the id looked up during the `/handlerequest.html` call,
  and both halves are individually correct.

  **Eliminated, so nobody spends the afternoon on them again.** Each was tested
  by command-independence, on the bench unless noted:

  | candidate | result |
  | --- | --- |
  | no `url` parameter on the registering GET | **this one was real** — without it the registration region is skipped entirely |
  | login target (`?url=` = tuxedoapi/home/console/index/absent) | all five bail |
  | GETting the landing pages after login | bails; `hiddenKey` stays `-1` |
  | repeating the registering GET up to 6 times | bails every time |
  | a real `http.cookiejar` keeping `_zFL` across the flow | bails |
  | HTTPS instead of HTTP (needs `OP_LEGACY_SERVER_CONNECT`) | bails |
  | client-list saturation from many logins | refuted: a freshly restarted server with ONE login bails |
  | the table being empty (tested on the panel with a real browser session live) | bails |

  The first cookie attempt had a bug worth not repeating: the jar was built
  with `re.findall(r"([^,;\s]+)=([^,;\s]+)")` over `Set-Cookie`, which swallows
  attributes and produced a cookie literally named `path`. The table row above is
  the corrected `http.cookiejar` run.

  **And a browser DOES work** — Lewis created a group through the web UI on
  2026-09-08 while the scripted session was bailing, so this is a difference
  between the two clients and not a dead endpoint.

  ## RETRACTED ROOT CAUSE — and the real one, which the repo already had

  **THE ENDPOINT DISPATCHES. One login is all it ever needed:**

      hiddenKey  = c0386cff1a1aadaa88d49dcfaeb586a   31 hex, not -1
      hidSession == int(cookie[0:8], 16)             PASS
      Type 0 / 141 / 65535 -> bodies of 38 and 43 B  DISPATCHES

  **The cause was my own driver, not a vendor bug.**
  `docs/TUXEDO-AUDIT-BUGS.md` §2.4 says `No_Of_Users` = **10 concurrent
  sessions**, reaped only when the `HttpSession` dies (`Session_Timer` = 10 min),
  and warns in as many words: *"do not re-login per poll … a client that re-logs
  every 30 s will exhaust the table."* §2.6 lists the symptom outright:
  **`hiddenKey == "-1"` → session has no slot, re-login.** Every test above
  logged in afresh — dozens of times — so from the eleventh onward there was no
  slot, and `-1` was the table saying so.

  **So the analysis below is WRONG where it concludes "index 10 is outside the
  search".** `getCSRFToken1` scans `i = 1..getNoOfUsers()`, and `getNoOfUsers()`
  returns `No_Of_Users` from `/root/Settings/WebConfig.conf` — **10 on this unit,
  verified** — not the 5 web accounts I assumed. Index 10 is *inside* the range.
  The record being at 10 was the last free slot, exactly as designed.

  **The mechanism notes that follow are still accurate and worth keeping** —
  the record layout, the `url` parameter requirement, the highest-free-slot
  choice. Only the conclusion drawn from them was wrong, and it was wrong because
  I supplied `getNoOfUsers()` from a guess instead of reading it.

  ### What the reading below was, and where it went wrong

  Found by searching guest memory for a value the server itself had rendered,
  rather than by address arithmetic — `/eventhandler.html` carries
  `<input id="hidSession" value="...">`, so the session id is knowable exactly,
  and `findsession.py` looks for that u32 instead of computing where the table
  ought to be. Two constraints then fix the mapping (the pointer must land in a
  writable region **and** the found record must sit on a 40-byte boundary from
  it), so a wrong delta cannot quietly satisfy it.

      the record IS there:  index 10   id=0x21cb39c0  flag=1
                            token='7c17e051...'   (truncated: real key material)
      slots 1..9:           0xFFFFFFFF, i.e. FREE

  `addSessionItem` writes correctly, and `getCSRFToken1` scans
  **`i = 1 .. getNoOfUsers()`** from `r4 = 40`. **I read `getNoOfUsers()` as the
  5 web accounts in `UserNamesFile.txt` and concluded index 10 was out of range.
  That was a guess and it was wrong** — it returns `No_Of_Users` from
  `/root/Settings/WebConfig.conf`, which is **10** here, so index 10 is the last
  valid slot rather than one past the end.

  **The writer picks the LAST free slot** — `mov r8, r6` at 0x1431c runs on
  every empty slot the scan passes, so `r8` ends as the highest free index. With
  ten slots and one session that is index 10, which is correct behaviour and not
  a bug. It only *looked* like one because the table was already full of my own
  abandoned sessions.

  **Not explained: the browser DOES dispatch, and that is now verified from an
  artifact rather than from a report.** Lewis created a group in the web UI on
  2026-09-08 at 13:00; the panel holds

      /opt/tuxedo/configuration/hagroupdb.json   78 B, mtime Sep 8 13:00
      [{"u8GrpId":1,"enmGrpType":0,"grpName":"Test","voiceCommand":"","NodeID":[]}]

  `group_configuration.js` writes that through `sendCommand(6293, …)`, and
  `httpRequest.js` builds it as
  `/handlerequest.html?cmd=…&sessionid=<hidSession>&tokenkey=<hiddenKey>&sid=<rand>`
  — the same gated endpoint that answers a scripted client 200-with-no-body. So
  the gate passes for a browser and not for the probe, and **the index model
  above is incomplete rather than wrong**: it explains why the scripted session
  fails, not why the browser succeeds.

  **Candidates NOT yet eliminated**, for whoever picks this up:
  - **Slot ordering over time.** The writer takes the highest free slot, so the
    index falls as sessions accumulate. Lewis logged in among a day of scripted
    logins; his may have landed at ≤ getNoOfUsers() where mine did not.
  - **A different auth route for LAN clients.** `getLocalLoginStatus` /
    "Authentication for web server local access" means local access may not run
    `FormAuthenticator` at all, so a browser session can be created by a path the
    probe's challenge/HMAC login never takes.
  - **The four-session ceiling below.** Past four sessions `hidSession` is 0, so
    a probe that has logged in repeatedly is not in the same state as a browser
    that logged in once.

  The peer found arm/disarm going to `/AdvancedSecurity/*` on the API surface,
  so a second route exists for *some* commands — but not for this one: the group
  write is `cmd=6293` on `handlerequest`, and it landed.

  **What this hands the next attempt:** the scripted request shape is now
  known exactly — `sessionid` is the NUMERIC `hidSession` from
  `/eventhandler.html`, not the cookie's hex, and `tokenkey` is a required
  parameter that is `-1` precisely because of the bug above.

  ### REPRODUCIBLE: session issuance stops after FOUR sessions

  Twenty rounds of login + registering GET + three `handlerequest` calls, each a
  separate login, reading `hidSession` back from `/eventhandler.html`:

      round 1  hidSession=1777928950
      round 2  hidSession=1797863368
      round 3  hidSession=1200513841
      round 4  hidSession=-1593037569
      round 5  hidSession=0        <- and 0 for every round after
      ... 20 rounds, server still answering

  **Four sessions, then the panel stops issuing ids.** Nothing recovers it inside
  the run. That is worth knowing before blaming a driver: past the fourth
  concurrent session every scripted client gets `hidSession=0`, and any test that
  logs in repeatedly is measuring an exhausted server from round 5 on. It also
  explains why no amount of re-registering moved the index — after the fourth,
  registration has nothing to register.

  **SEEN ONCE, NOT REPRODUCED: a segfault.** The first `fillslots` run left this
  in `/tmp/barra.scenes.log`:

      Barracuda g_mqSuperVisionIn sending mq 7
      Barracuda g_mqSuperVisionIn sending mq 8
      qemu: uncaught target signal 11 (Segmentation fault) - core dumped

  messages 7 and 8 being `BARRACUDA_RECV_SIGABRT` and `_SIGSEGV`. **It has not
  recurred**: 30 logins twice, each `handlerequest` variant on its own, and 20
  full rounds all survived. So it is **one observation, not a result** — recorded
  because a remote crash matters if it is real, and because on the panel each
  crash posts BOTH messages, i.e. **two relaunch units of twenty-four**. Do not
  chase it on the panel; it belongs on the bench.

  Reading the table on the PANEL to settle it directly does not work either:
  `/proc/<pid>/mem` on 2.6.31 needs a ptrace attach, and attaching to Barracuda
  is not worth a relaunch unit.

  **The consequence reaches past the scene work: any `/handlerequest.html`
  number taken through console mode measured the bail-out.** Clean 200s with a
  flat RSS is exactly what a gate that dispatches nothing produces, and at the
  HTTP layer it is indistinguishable from "this endpoint does not leak". Settle
  the token before trusting a console-mode measurement.
- **`deleteExistngScene` has a node-aliasing hazard.** It does
  `json_push_back(newArray, json_at(tree, i))`, so the two trees may share
  nodes; freeing both could double-free and freeing one could leave the other
  dangling. `json_push_back` reaches `internalJSONNode::push_back(JSONNode*)`
  and whether that copies or takes ownership is **unsettled** — resolve it
  empirically before touching this one. It also leaks its `json_new` array on
  the early-return path when the tree is NULL.
- **`checkSceneNameExists` leaks twice**: the tree, and a `json_as_string`
  result per loop iteration (0x34d74, consumed by `strcmp` and dropped). It has
  two separate return points, so it needs two stubs or a converged exit.

**The easy one, if you want a starting point:** `checkIfSceneExists` (0x34bec)
is unambiguously safe. Nothing derived from the tree escapes — the loop uses
`json_as_int`, which returns a value — and both exits converge on `mov r0, r5`
at **0x34c50**, where a NULL-guarded `json_delete(r6)` fits. r6 is NULL exactly
on the branch that skips the loop, so the guard covers it.

**It leaks on EVERY call, not only when the scene exists** — worth stating
because it changes what a driver has to arrange. The tree is parsed before the
id is ever compared:

    34c00  bl   scene_getRootNodeOfObjects  -> r6 = parsed tree
    34c04  subs r6, r0, #0 ; beq 34c50      -> NULL only if the parse failed
    34c24  loop: json_at / json_get / json_as_int, r5 = 1 on a match
    34c50  mov  r0, r5                      <- returns an INT; the tree is dropped

So a database of placeholder scenes still leaks a tree per call, and
`deleteExistngScene` calls it at `0x34c68` **before** its own early return at
`0x34c70` — meaning cmd 141 leaks even though the delete itself does nothing and
writes nothing. That makes it the safest possible driver for this fix, once a
request can get past the CSRF gate above.

The stub is five words and needs no stack: `json_delete` clobbers `lr`, but the
function returns through `pop {r4,r5,r6,r7,r8,pc}` off the frame it pushed at
0x34bf0, so `lr` is dead. r5 and r6 are callee-saved and survive the call.

    mov r0, r6 ; cmp r0, #0 ; blne json_delete ; mov r0, r5 ; pop {r4,r5,r6,r7,r8,pc}

**WRITTEN, MEASURED, AND WITHHELD — it frees nothing on this unit.** LEAK 23 in
`mkapifix.py` is exactly that stub, and the endpoint is drivable now, so it was
measured properly rather than reasoned about:

    json_delete calls per 10 requests, traced at the PLT (0xba18):
        62ee361c unpatched   29
        + LEAK 23            29        <- identical: the blne is NEVER taken

    chunk deltas over 300 requests, before -> after the fix:
        40 B  +374 -> +366     32 B  +361 -> +361     16 B  +75 -> +76

The stub definitely executes — `0x69580` and `0x6958c` each run exactly once per
request — so this is not the "stub never written" failure that wasted a day on the
IPC path. **`r6` is simply always 0.**

**Because `checkIfSceneExists` parses the WRONG-looking file, and reading the
string settles it.** The pointer at `0x90e94` is `0x8b080` =
`/opt/tuxedo/configuration/hascenedb.json` — the **Z-Wave** scene database, which
is **0 bytes** on the panel and the bench. Not `hatcscenedb.json`, the 3182-byte
TC scene file the rest of the scene code reads. An empty file parses to NULL, so
`scene_getRootNodeOfObjects` allocates nothing and there is nothing to free.

**So the ~107 B/request on `cmd=141` is real but comes from elsewhere — and
`chunkdiff.py` has now NAMED IT BY CONTENTS**, the way it named the IPC registry
buffers. `leakfix/sceneopdump.sh`, 200 requests, the 40-byte size:

    +010  00 79 5c 00 bc c8 5c 00 ...  "10":"home.
    +020  68 74 6d 6c 22 7d 00 00      html"}
    ...
    +010  00 00 00 00 00 22 39 22 ...  "9":"mobile
    +020  76 69 65 77 2e 68 74 6d      view.htm
    ...                          l"}

**It is a page-ID → page-name JSON map** — `{"9":"mobileview.html","10":"home.html",…}`
— parsed per request and abandoned. That is the document `validatePageName`
(0x13afc) works on, which `authPage_service` calls at 0x141fc and which the
request path evidently reaches too. The 0x29 word at +4 is a libjson node header,
and the `inc` fragments are the tail of libjson's own `Children is null inc`
error string, the same one that turned up in the `/GetSceneList` residual.

**LOCATED: `validatePageName` (0x13afc), and it leaks TWICE per call.** The map
is a string literal at guest VA `0x86168` — the 29-entry
`[{"1":"zwavedevicelist.html"},…,{"29":"treeview.html"}]` array — and `0x13b70`,
the only reference to it in the image, is `validatePageName`'s literal pool.

    13b08  r0 = the page-map literal
    13b0c  bl json_strip_white_space   -> ALREADY FIXED: 0x13B10 is the first
    13b10  bl json_parse_unformatted      entry in STRIP_PARSE_SITES (LEAK 19)
    13b14  subs r6, r0, #0 ; beq 13b64 -> r6 = the parsed tree
    13b1c  json_size, then the loop:
    13b2c    json_at / json_at
    13b38    json_as_string           -> LEAK 2: consumed by strcmp at 0x13b40
    13b40    strcmp                      and dropped, ONCE PER ITERATION
    13b64  mov r0, #0                 (no-match path, falls through)
    13b68  add sp, #4 ; pop {r4,r5,r6,r7,pc}   <- LEAK 1: r6 never json_delete'd

**Two leaks, and the second scales with the map.** The tree is one allocation per
call; the `json_as_string` results are one per iteration, up to 29 before a match
— which is why the 40- and 32-byte rows grow at ~1.2 per request rather than
exactly 1.

**The exit is a single convergence at 0x13b68** — 0x13b64 falls through to it —
so one stub covers both paths. `lr` is expendable (the function returns through
`pop {…,pc}`), and `r4` is restored by that same pop, so it is free to hold the
return value across a `bl`:

    mov r4, r0 ; mov r0, r6 ; cmp r0,#0 ; blne json_delete ;
    mov r0, r4 ; add sp,sp,#4 ; pop {r4,r5,r6,r7,pc}

## LEAK 24 SHIPPED IN THE BUILDER: 107 -> 39 B/request, replicated

`VALIDPAGE_SITES` is live in `mkapifix.py` (7-word stub at 0x69594, one site at
0x13b68). Same 300-request load on `cmd=141`, before and after:

    size    62ee361c    + LEAK 24
    40 B      +374        +294 / +295     <- the tree, gone
    32 B      +361        +349 / +349     <- barely moves: the per-iteration
    24 B      +128         +32 /  +32        json_as_string, still unfixed
    16 B       +75         +20 /  +17
    total   ~107 B/req    39 B/req  (both runs)

**Two runs, identical to the byte.** And it does not break the handler: 1200
requests across the runs all answered 200 with 43-byte bodies, and a fresh login
still passes the §2.6 smoke test (31-hex `hiddenKey`, `DISPATCHES`) — which
matters because `authPage_service` is one of the two callers, so the login path
exercises this stub every time.

### LEAK 25 (the loop's `json_as_string`) — BUILT, MEASURED, WITHHELD

I predicted the 32-byte row was the per-iteration `json_as_string` at 0x13b38 and
built the stub. It changes nothing:

    per-request bytes:  + LEAK 24  39 B     + LEAK 24 and 25  39 B
    32-byte row:        +349        ->      +337

The stub runs — 0x695b0, 0x695b8, 0x695c8 each execute exactly once per request —
so this is not the never-reached failure.

**"Once per request" is the whole point, and the arithmetic had already said
so.** I predicted up to 29 frees per request, one per map entry. The loop body
runs **once**. And +349 over 300 requests is **1.16 per request**, not 10 or 29 —
the growth rate refuted the per-iteration theory before any stub was written.
**When a per-iteration theory predicts N per request and the measurement says ~1,
it is already refuted; check the rate against the theory before building.**

### The residual's FAMILY is named: unfreed `json_as_string`

The 32-byte chunks hold **pointers, not text** — a `0x21` glibc size field then
pointer pairs — so `chunkdiff` cannot name this one from its contents the way it
named the page map. A per-PLT allocation/free balance sheet does it instead
(`leakfix/balance.sh`, 10 requests of `cmd=141` on `5cdbb3f3`):

    json_as_string   7.20/req      json_free    2.00/req   -> ~5.2 UNFREED
    json_new+new_a   4.50/req      json_delete  2.90/req   -> ~1.6 unfreed
    malloc          63.50/req      free        63.40/req   -> balanced
    new[]            1.00/req      delete[]     1.00/req   -> balanced

**`malloc`/`free` and `new[]`/`delete[]` balance to within 0.1 per request**, which
is the useful negative: the residual is not raw allocation, it is libjson
ownership. `json_as_string` returns caller-owned memory needing `json_free`, and
five of every seven results are dropped.

The balance sheet is the reusable part: it names the *family* without needing
the site, and it did in one run what two speculative stubs did not.

**`readUserNamePasswordFromJSON` looked like the answer and is NOT.** It holds
exactly 7 `json_as_string` calls against a measured 7.20/request — a fit so exact
it was tempting. Traced: it runs **once per ten requests**. That is the login, not
the request path. Arithmetic that good is still not evidence.

## LEAK 26 SHIPPED AND DEPLOYED: the tokenkey compare, 39 -> ~11 B/request

Found by tracing all six `json_as_string` sites inside the handler: **five run
zero times per request and `0x3a430` runs exactly ten times for ten requests.**

    3a42c  bl json_get(r6, ...)     the CSRF token node
    3a430  bl json_as_string        -> r0, CALLER-OWNED, needs json_free
    3a438  mov r4, r0
    3a44c  bl strcmp(r4, tokenkey)  <- consumed and DROPPED
    3a454  bne 3e86c                mismatch: tree freed there, string not
    3a45c  bl json_delete(r6)       match: the TREE is freed, the STRING never is

**The tree is freed on both paths and the string on neither.** Fixed with the same
stub shape the 0x13B40 attempt used — the situation is identical, and at 0x3a44c
r0 already holds the string and r1 the parameter.

    size    62ee361c   +LEAK 24   +LEAK 26
    40 B      +374       +294       gone
    32 B      +361       +349       +55 / +50
    24 B      +128        +32       +10 / +19
    16 B       +75        +20       +38 / +28
    total   ~107 B/req   39 B/req   ~11 B/req   (two runs)

**This modifies an AUTHENTICATION comparison, so the rejection was tested, not
assumed:**

    correct tokenkey -> 200, 43 bytes   (dispatches)
    wrong   tokenkey -> 200,  0 bytes   (rejected)

The stub stashes the compare result on the stack precisely so freeing the string
cannot disturb it. **Live on the panel as `07987132`**, 263 verify checks passing,
`patches.tsv` regenerated to 266 sites and re-verified from genuine stock.

The restart cost **two** budget units this time (2 → 4): `RECV_SIGABRT` and
`RECV_SIGSEGV` one second apart, which is `sigHandler` faulting during its own
cleanup — the documented two-for-one, seen live rather than inferred.

## `cmd=141` IS NOW LEAK-FREE PER REQUEST — and the residual was the instrument

The "~11 B/request" above is **not a per-request leak**. Same binary, fresh server
each time, only the request count changed:

    size    N=300   N=900        a per-request leak TRIPLES; this does not
    32 B     +55     +55
    16 B     +38     +37
    24 B     +10     +17
    40 B       0      +5

**Growth is flat against request count, so it scales with LOGINS, not requests** —
each measurement phase logs in once, and a login allocates. `balance.sh` says the
same thing from the other side: `json_as_string` totals 72 calls over 10 requests
and 71 over 100, i.e. essentially all of it is one-off session setup.

So LEAK 24 + LEAK 26 took `cmd=141` from **~107 B/request to zero**, and the
earlier "39" and "11 B/request" figures were partly a per-run constant divided by
N. **Divide-by-N reports a constant as a rate.** Vary N before believing one.

### CONFIRMED ON THE PANEL, not just the bench

Every per-request figure above is from the emulated bench. Driven against the real
unit on `0066ad95`, reading `VmRSS` either side and using the same
does-it-scale-with-N discriminator:

    N=300 requests   VmRSS 5584 -> 5600 kB    +16 kB
    N=900 requests   VmRSS 5616 -> 5628 kB    +12 kB
    pre-fix rate would have put N=900 at about +94 kB

**Tripling the load produced less growth**, so there is no per-request component —
that is page quantisation, not a leak. 1200 requests, all answering 200 with 43-byte
bodies. `cmd=141` is leak-free in production.

RSS can only see about 14 B/request or more at this sample size, so this confirms
the absence of the ~107 B/request that was there before; it could not have detected
a few bytes per request. The chunk histogram on the bench is the sensitive
instrument, and it agrees.

Idle RSS is also flat: 5600 kB right after the LEAK 24 deploy, 5576 kB some
19 000 s later.

**A zero-delta table is NOT proof of a fix, and it fooled me once here.** Two
runs reported no growing sizes at all — because `scenedrive` had correctly aborted
on an exhausted session table and `sceneopmeasure` swallowed the message, so
nothing was driven. An empty delta table looks exactly like a perfect fix.
`sceneopmeasure.sh` now fails loudly when the driver produced no `body sizes`
line. **Ten session slots, reaped only when the HttpSession dies: restart the
server between measurement campaigns.**

## `cmd=140` (editSceneDetails) ALSO LEAK-FREE — LEAKS 27 and 28, deployed

`editSceneDetails` frees **nothing**: six allocations, one exit. Measured at
~124 B/request, and it scaled properly (16 B `+873 → +2621`, 40 B `+300 → +898`
from 300 to 900 requests), so it was a real rate.

| | 16 B | 32 B | 40 B | 24 B | per request |
|---|---|---|---|---|---|
| before | +873 | +353 | +300 | +68 | ~124 B |
| + LEAK 27 | +574 | +350 | +299 | +72 | ~114 B |
| + LEAK 28 | **+31** | **+50** | **gone** | **+12** | **~0** |
| same, N=900 | +37 | +52 | gone | +13 | flat → per-login |

**LEAK 27** frees the `Base64Decode` buffer at the single exit — safe because it is
a plain `malloc`'d string never pushed into a tree, and `Base64Decode` (0x33d98)
is branch-free and always writes its out-param, so `[sp+4]` is never uninitialised
stack.

**LEAK 28** frees tree B and tree C on the **parse-failed** early exit. That is the
path malformed input takes, so it was remotely reachable: a client POSTing
unparseable `scenedata` leaked two trees per request.

**The trees still leak on the FULL path and that is deliberate.** On the match
branch `json_push_back(r7, r6)` pushes tree A *into* tree C, and the loop pushes
tree B's nodes into tree C, so r5/r6/r7 share nodes and freeing any two
double-frees. The early exits do not alias but converge on the same exit, which is
why LEAK 28 hooks the `beq` at 0x34E00 instead. **That site is conditional** —
the redirect keeps cond EQ, because a plain `b` would free on every call and skip
the rest of the function.

Live on the panel as **`0066ad95`**, 273 verify checks passing, `patches.tsv` at
284 sites re-verified from genuine stock. Scene databases byte-identical after
2400 edit attempts.

### The rest of the dispatch surface is CLEAN — swept, not assumed

`leakfix/cmdsweep.sh` drives each remaining arm of the chain at 0x3a6c8 and
reports its chunk growth, so the next target is chosen by size rather than by
which function looked suspicious. 200 requests each, fresh server per command:

    cmd=129  38 B bodies    32 +55   16 +40   24 +10
    cmd=134  44 B bodies    32 +55   16 +40   24 +10
    cmd=136  46 B bodies    32 +55   16 +38   24 +10
    cmd=137  81 B bodies    32 +55   16 +40   24 +10
    cmd=139  38 B bodies    32 +55   16 +40   24 +10
    cmd=145  38 B bodies    32 +55   16 +40   24 +10
    cmd=146  38 B bodies    32 +55   16 +40   24 +10

**Every arm shows the identical figure, and it is the per-login constant** — the
same +55/+40/+10 that a fixed `cmd=141` shows. Different body sizes prove the
handlers really ran and differ from one another, so this is not seven copies of
one bail-out. **None of them leaks per request.**

So on this surface `cmd=140` and `cmd=141` were the leaky pair, and both are now
closed. The sweep's own numbers are not per-request rates — each measured phase
logs in once. Anything that ever looks interesting here must be re-measured at two
request counts before it is believed.

**`patches.tsv` STILL DESCRIBES 62ee361c AND MUST NOT BE REGENERATED UNTIL THIS
IS DEPLOYED.** The table's whole value is that it says what the panel runs;
regenerating it now would make it describe a build that exists nowhere, which is
the stale-header failure its own header records twice. When LEAK 24 goes to the
panel: deploy, then regenerate the P15 rows, then re-verify stock -> new md5 from
a clean tree, then update the chain and the `LIVE_DRIFT` line together.

**Re-enable LEAK 23 the moment `hascenedb.json` is non-empty** — i.e. once real
Z-Wave scenes exist. Then the tree is real, the leak is real, and the stub frees
it. Disabling it restores the previous build byte-for-byte (`ad0a4c30`, 228
words), so `patches.tsv` does not drift while it sits idle.

## The defect

libjson's `json_as_string()` and `json_write()` return **caller-owned** memory
that must be released with `json_free`. The image makes **391** and **521** such
calls against **28** `json_free`. The vendor's own correct site at `0x470e8`
shows the intended pattern. Six `json_as_string` ran per API request and none
was freed.

`json_free`, not `free`. They are different functions and using the wrong one
corrupts the heap.

On top of that, several buffers are abandoned at birth: the request parameter
tree is lost when `r7` — the only pointer to it — is overwritten at `0x29088`,
and two `json_write` results are destroyed by the return value of the very call
that consumes them.

## Tools

| tool | what it answers |
| --- | --- |
| `mkapifix.py` | builds the patched binary and emits the `patches.tsv` rows. Every site carries its rationale: why it leaks, why the fix is safe, which registers are live. Start here. |
| `leakprobe.py` | drives authenticated requests and fits RSS against request count. Reports the HTTP status distribution, because 200 requests that all 302 exercise nothing and read as "no leak". |
| `heapwalk.py` | histograms in-use glibc chunk sizes. Sample before and after N requests; a size growing by ~N is allocated once per request and never freed. |
| `chunkdiff.py` | dumps the *contents* of chunks that appeared between two snapshots. This is what named the leaks when execution tracing could not. |
| `scanmem.py` | counts a byte pattern in a live process. Send a marker in the request, count retained copies. |
| `findcave.py` | finds genuinely dead functions usable as code caves. |
| `attribute.py` | classifies each leak site vendor vs ours, and checks caves do not collide with existing patches. |
| `panelleak.py` | measures the live panel, tracking `[heap]` separately from total RSS. |
| `barra-sampler.sh` | long-run sampler for the panel. |
| `serve-traced.sh` | starts the emulator with qemu execution tracing restricted to an address range. |
| `ipcmeasure.sh` | drives IPC messages and reports the three quantities that get conflated: qemu's RSS, the guest heap region, and the in-use chunk sum. Aborts if anything is draining the inbound queue. |
| `ipcverify.sh` | proves a patched binary still *works*: listeners, HTTP, the P13 gate, 400 messages, heap integrity, and the guest log. A wrong free corrupts the heap silently, so leak numbers alone are not evidence. |
| `regshape.py` | structural view of `registereddevMAClist.json` — counts and key names only, never a value, because the file holds per-device private keys. |

## Traps these tools exist to avoid

**Chunk in-use is the NEXT chunk's PREV_INUSE bit.** Bit 0 of a chunk's own size
field describes the *previous* chunk. Reading it as "this chunk is live" gives a
plausible histogram right up until frees become common — which is exactly when
it matters. It reported "no growth at all" once the big leaks were fixed, while
~16 chunks per request were still leaking.

**A cave hunt must scan `b` as well as `bl`.** CSP page handlers are reached by a
tail branch from their registration thunk, and `get` reaches
`getPartitionStatus` the same way. A `bl`-only scan offered
`handlerequest_html076EF::service` — 18 KB of live page handler — as free space.
A cave qualifies only if nothing branches to it *and* every image word equal to
its address lies in the symbol-table tail. The second test alone rejected
`AsynchResp_dispSendEv`, whose address sits in an indirect-call slot.

**Warm up before measuring.** The startup working-set ramp is steep enough to
dominate a short run: a payload that truly leaks 2321 B/request read 4342 with
`--warmup 10` and 17326 with `--warmup 0`. Use `--warmup 200` and check that
consecutive runs agree.

**`-dfilter` reads `start-size` as start MINUS size.** Use `start..end`.

**Distinguish time-driven from work-driven growth.** The panel first read
~79 B/request. Running the same interval with *no* requests grew the heap
*more*. That figure was time-driven ramp divided by however many requests
happened to be sent — it would change with the send rate and mean nothing.

**Shell scripts written on Windows arrive on the panel as CRLF and fail
silently.** `INTERVAL=300\r` breaks `sleep`; `LOG=...tsv\r` names a different
file. Pipe through `tr -d '\r'`. Python on the build VM tolerates CRLF; the
panel's `/bin/sh` does not.

**Never match a process by a substring that your own command line contains.**
`case "$c" in *barra-sampler*)` over ssh matched the ssh command itself and
killed the session. Match a cmdline prefix, or identify by who holds the port.

## Verification performed

Under emulation, against the exact binary later deployed: API and
`/tuxedoapi.html` both 0 B/request, 2000 and 500 sustained requests with RSS
unchanged, responses checked by content rather than status, and a negative
control confirming the harness still reads ~1488 on an unpatched binary.

On the panel: `verify-panel.sh` passes all 134 rows, the P13 push stream denies
anonymous access with 401 on all four listeners and delivers frames when
authenticated, and a paired control (400 requests versus the same interval idle)
shows requests contribute no growth.

## LEAK 31 — the REST arm/disarm handlers leak, all three. MEASURED, rate NOT established

Found 2026-09-09 within twenty minutes of installing a decompiler, in a function
already read twice by hand that same day for a different question. Measured on the
live panel the same day, with Lewis's authorisation to arm and disarm.

**The leak is real. The rate is not, and the mechanism is narrower than first written**
(see the registry-node correction below). Two paired runs on the panel, 12 arm/disarm
cycles each (24 handler calls), `leakfix/armrss.sh` and `leakfix/armrss2.sh`:

| run | busy | idle control | attributable | per call |
|---|---|---|---|---|
| 1 | 392 kB / 633 s | 0 kB / 203 s (**not duration-matched**) | ~380 kB | ~16 kB |
| 2 | 84 kB / 635 s | 4 kB / 636 s | 80 kB | **3.3 kB** |

Barracuda held pid 2830 across both, so neither is void from a restart, and the panel
was confirmed DISARMED at the end of each. The runs disagree by 4.7x for identical
work, so only run 2 is quotable: run 1's control was a third of its test's duration,
and run 1 began at 5500 kB while the heap was still ramping after a restart, which is
this panel's documented post-restart behaviour. Run 2 began at 5904 kB, settled, and
its control was matched by construction. **Take single-digit kB per call as an order
of magnitude, not 16 kB and not 3.3 kB as a figure.**

Two further reasons not to quote a rate from this. `VmRSS` is page-quantised at 4 kB,
so 24 calls resolve to at best 20 pages of signal. And the busy phase is not only the
24 calls: arming changes state, so Home Assistant polls and the push stream fires,
and none of that happens during an idle control. 3.3 kB/call is therefore an upper
bound on the handler's own cost, and it already exceeds what the static count can
explain (below), which points at allocator arena behaviour rather than at bytes
leaked.

**The exact measurement was not available.** `jsoncount.py` reads libjson's registries
and would give tree and string counts directly, but 2.6.31 refuses `/proc/PID/mem`
with ESRCH, so it cannot run on the panel; and the bench cannot run the arm path at
all, because `setarmwithcode` `mq_send`s to the alarm bus and waits for a `/tuxedo`
reply that does not exist under emulation. See "How to get an exact number" below --
five family members never touch the bus and are hammerable on the bench.

`setarmwithcode` @`0x1afc8` (0x17c bytes), `setdisarmwithcode` @`0x1ae50` (0x178) and
`setPartitionArmed` @`0x1c958` (0x180) share one shape. Counted from the
disassembly, not from the decompiler:

| call | setarm | setdisarm | setPartitionArmed |
|---|---|---|---|
| `json_new` | 3 | 3 | 3 |
| `json_new_a` | 3 | 3 | 3 |
| `json_push_back` | 4 | 4 | 4 |
| `json_write` | 3 | 3 | 2, plus 1 `json_write_formatted` |
| `Base64Encode` | 1 | 1 | 1 |
| `json_free` / `json_delete` / `free` | **0** | **0** | **0** |

Six nodes created and four absorbed by `push_back`, so **two roots leak per call**,
plus **two serialised strings**, plus almost certainly the `Base64Encode` buffer —
the malloc'd-buffer pattern LEAK 20 already fixed in `getEScenes`.

**Correction, 2026-09-09: two strings, not three.** The count above says `json_write`
x3 and that is right, but the third one is the RETURN VALUE, not a leak. Every one of
these functions ends

    bl json_write ; mov sp,r7 ; sub sp,fp,#28 ; ldm sp,{r4,r5,r6,r7,fp,sp,pc}

with nothing touching r0 between the call and the return, so the caller receives that
string and owns it. Ghidra types the functions `void` — that is Ghidra guessing, and
believing it would have double-freed the response body on the first fix. The census
counts *calls* and cannot see where a result goes, which is exactly the caveat this
file already recorded, now with a concrete instance.

Ownership propagates two frames: `set` @`0x15a00` contains no `json_free`,
`json_delete` or `free` of any kind and returns the string straight up to
`WnmpDir_serviceField`.

**Correction to the correction: the string is NOT leaked, and this file said it was.**
`WnmpDir_serviceField` does dispose of it, at `0x29018`:

    29018: ldr pc, [ip, #16]      call the module's set method -> r0 = the string
    29020: mov r4, r0             save it
    29028: bl HttpResponse_setContentType
    29034: bl HttpResponse_printf sent to the client
    2903c: bl free                <- disposed of here

So the claim that "a fix belongs one or two frames higher" was written before this
site was read, and it was wrong about the string being leaked at all.

**What IS leaked here is the registry node, and the fix is one instruction.** That
`free` should be `json_free`. libjson is built with `JSON_MEMORY_MANAGE`, and
`json_write` returns the result of `toCString` @`0x27d78` in the library, which
mallocs, memcpys, and then **inserts the pointer into the string registry** (an
indirect map insert, then `str r0,[r2,#20]` into the node). `json_free` @`0x21000`
erases that entry — it calls `_Rb_tree_rebalance_for_erase`, `operator delete` for
the node, and `free` for the block. Plain `free` releases the block and strands the
node, so the registry gains exactly one entry per REST write request, holding a
pointer that is now dangling.

**Measured, and it is NOT one node per request.** An earlier version of this section
said the stranding explains the 1.0000-outstanding-per-request signature. That was
reasoning, not measurement, and measuring refuted it. `leakfix/regtest.c` exercises
libjson directly under emulation — no webserver, no credentials — with a
leak-on-purpose control that must rise by exactly n:

| arm, n = 100 | registry count | per call |
|---|---|---|
| control: `json_write`, never freed | 0 -> 100 | **+1.0000** (validates the reader) |
| `free()`, identical sizes | 100 -> 101 | +0.01 |
| `json_free()`, identical sizes | 101 -> 100 | -0.01 |
| `free()`, varying sizes | 100 -> 118 | **+0.18** |
| `json_free()`, varying sizes | 118 -> 111 | -0.07 |

The registry is keyed by the pointer. Free a string, allocate the same size again,
and glibc hands back the same address — so the insert overwrites the existing key and
the map does not grow. Stranded entries accumulate with the number of DISTINCT
addresses the allocator ever uses for these strings, not with the request count: 0.18
per call when the reply size varies over 400 bytes, 0.01 when it does not.

So the 1.0000 per request measured earlier is NOT this. That figure is leaked trees,
which do grow per request; this is a separate and much smaller effect, and the fix
below is worth far less than the first draft of this section claimed.

It is still worth doing, and not only for bytes: every stranded entry is a dangling
pointer left in a global registry. Nothing dereferences them today because Barracuda
never calls libjson's bulk frees (`docs/ALLOCATOR-REWORK.md`), so it is latent rather
than active — but it costs one instruction to remove.

Two cautions the experiment also settled. The reader must be validated before any arm
is believed: the first run of `regtest.c` took `&json_write` for libjson's
implementation, got the **PLT stub in the test executable**, computed a negative
library base and reported 0 for every arm including the deliberate leak. Only the
control caught it. And the panel's glibc has no `__isoc99_sscanf`, so parse
`/proc/self/maps` with `strtoul` or the build links on the host and fails against the
sysroot.

The substitution is safe in the other direction too: `json_free` erases without
branching on membership, so for a pointer that was never registered it is an erase
that matches nothing followed by the same `free`. It is a strict superset of `free`
here, which matters because not every module method need return a registered string.

    site   VA 0x2903c   (file offset 0x2103c, VA - 0x8000)
    from   bl free
    to     bl json_free

**Built and A/B'd on the bench; the A/B was UNINFORMATIVE, not a refutation.**
`patches.tsv` has no entry at `0x2103c`; the nearest is `P15-leakfix-site-29088`,
which fixes a leaked *tree* on the `get` path and does not touch this. The
one-instruction change was built (2 bytes differ, `ebff8c43` -> `ebff8b17`), installed
on the bench and measured against the same five arms: **zero effect, to four
decimals.** That is not evidence the fix is wrong. An execution trace afterwards
showed `0x29000..0x29060` never runs for `/system_http_api` requests, so the A/B
exercised a path that does not include the site. It still needs an arm that reaches
the WNMP field service. See the retraction below.

This is the security-operation path. Home Assistant arms and disarms through it, so
it runs on every alarm state change, not only when someone opens a web page.

**Why every earlier sweep missed it.** The hunt followed measured growth on endpoints
that can be hammered: `/GetSceneList`, `cmd=140`, `cmd=141`. Arming cannot be
hammered, so it never produced a slope, and a function no instrument pointed at was
never read for frees. `setarmwithcode` was read twice the same day for the
`sessionId = 0` question and the missing frees were not what either reading sought.

**Before fixing:** these are `json_write` results, so `json_free` and never `free` —
`json_free` is not a `free()` wrapper, and the wrong one corrupts libjson's registry
rather than mismatching an allocator (`docs/ALLOCATOR-REWORK.md` §4). And free only
the first two: the third `json_write` is the reply body the caller is about to send,
so freeing it in the handler is a use-after-free on every REST write, not a leak fix.

### LEAK 31 is a FAMILY of 16, not three functions

(The census found 19; three of them turned out to be dead code. The table below is
the census output as it stood, with the correction recorded under it.)

`leakfix/alloccensus.py` counts allocating calls against freeing calls for every
function in the image, cross-references `patches.tsv` so shipped fixes are marked,
and ranks what is left. Of 127 functions where allocations exceed frees, **19 have
the LEAK 31 signature exactly: a `json_write` and not one free.**

| net | address | function |
|---|---|---|
| 11 | `0x18ffc` | `setAddIPURL` |
| 10 | `0x18c68` | `setUpdateIPURL` |
| 10 | `0x189d4` | `setViewIPURL` |
| 7 | `0x19be4` | `setAddDevMAC` |
| 6 | `0x12c54` | `uploadDevicesToOtherTuxedos` |
| 5 | `0x1b470` | **`setDoorLock`** |
| 5 | `0x1bbec` | `setMode` |
| 5 | `0x1c7fc` | `setOccupancyMode` |
| 5 | `0x1b868` | `setThermostatEnergyMode` |
| 5 | `0x1ba28` | `setThermostatSetPoint` |
| 4 | `0x1724c` | `getDeviceStatusFromFile` |
| 4 | `0x15f7c` | `setClientUnregister` |
| 4 | `0x1aa10` | `setEScenes` |
| 4 | `0x1c958` | `setPartitionArmed` |
| 4 | `0x1afc8` | `setarmwithcode` |
| 4 | `0x1ae50` | `setdisarmwithcode` |
| 3 | `0x13064` | `BLightStatusToOtherTuxedos` |
| 3 | `0x12f18` | `DLightStatusToOtherTuxedos` |
| 3 | `0x1c340` | `setLights` |

That is the REST write API more or less entire: arming, disarming, door locks,
lights, thermostat set-point and mode, occupancy, scenes, device registration. Every
state-changing call the Home Assistant integration can make is on this list.

### All nineteen now read. The family is 16, not 19

Read 2026-09-09 with `Decomp.java` over the whole list. Three results changed it.

**1. The last `json_write` is returned, in 18 of 19.** Detailed above for the arm
handlers; it holds for every member with one variant. `getDeviceStatusFromFile`
@`0x1724c` stores it through an out-pointer (`str r0,[r9]`) and returns 0, which is
the same transfer by a different route. So every member leaks one fewer string than
the census counts, and no member's trailing `json_write` may be freed in place.

**2. Three members are dead code and must come off the list.**
`BLightStatusToOtherTuxedos` @`0x13064`, `DLightStatusToOtherTuxedos` @`0x12f18` and
`uploadDevicesToOtherTuxedos` @`0x12c54` have **zero** `bl` callers and **zero** data
references in any loaded section. That evidence is only worth stating because the
method was validated first: run the same two checks against `setarmwithcode`, which
24 live arm cycles prove runs, and they find its caller at `0x15d60` (inside `set`)
— so "no references" here means dead, not "the search was blind".

**3. Those three dead functions contain a use-after-free**, and it is worth recording
because if anything ever calls them it is worse than a leak:

    curl_easy_init -> curl_easy_setopt(handle, URL) -> curl_easy_cleanup(handle)
                   -> curl_easy_escape(handle, ...)   <- handle already destroyed

All three do this. They also never call `curl_easy_perform`, so they build a URL in a
256-byte stack buffer, set it as an option, destroy the handle, then `strcat` more
onto a buffer nobody sends — with `strcat` of escaped JSON into `char[256]` and no
bound. They allocate, leak per loop iteration, and accomplish nothing. Dead, so not
exploitable; do not "fix" them, delete them if anything ever touches this area.

`setDoorLock` was read first, being a lock. It has the family shape and one extra
`json_write`: two root trees, three `json_write` calls of which the third is
returned, and the `Base64Encode` buffer. Its first root pointer is overwritten by a
later assignment before the function returns, so that tree is unreachable, not merely
unfreed.

### The family is still NOT measured. What follows measures the API error path

> **RETRACTED within the hour, by an execution trace.** This section first said "3
> strings and 1 tree per call, identical across three handlers" and attributed it to
> the LEAK 31 family. The numbers below are real and reproduce exactly, but they are
> **not the family**: `/System/Tuxedo/ZwaveSync/{ViewIPURL,AddIPURL,UpdateIPURL}` are
> **not implemented** on this firmware. They return a generic envelope, and
> `setAddIPURL` never executes when they are called. Kept in full because the numbers
> are sound and because the way it went wrong is the point.

The arm path cannot be counted on the bench (alarm bus) or on the panel (ESRCH), and
**five family members never touch the alarm bus**: `setAddIPURL`, `setUpdateIPURL`,
`setViewIPURL`, `setAddDevMAC`, `setClientUnregister`. Those look hammerable under
emulation with `jsoncount.py`, which counts libjson's registries exactly instead of
inferring from 4 kB pages. `leakfix/famcount2.sh`, 200 requests per arm, each arm
warmed with 200 first:

| arm | endpoint | strings/call | trees/call |
|---|---|---|---|
| control A | `/GetSceneList` | +2.19 | **+1.0000** |
| control B | `/GetSecurityStatus` | +0.19 | **+0.0000** |
| unimplemented | `ViewIPURL` | +3.19 | +1.0000 |
| unimplemented | `AddIPURL` | +3.19 | +1.0000 |
| unimplemented | `UpdateIPURL` | +3.19 | +1.0000 |

The +0.19 is constant in every arm including the one that leaks nothing, so it is
background, not per-call. Subtracting it, and stating only what is actually
established: **an unimplemented `/system_http_api` command costs 3 strings and 1 tree
per call**, `/GetSceneList` costs 2 and 1, and `/GetSecurityStatus` costs nothing at
all. Control A reproduces its documented 1.0000 trees per request exactly, which is
the instrument check; `famcount.sh` run 1 and run 2 agreed to four decimals at
completely different registry occupancies (812 -> 1250 and 3086 -> 3524).

**Two things this does establish.**

*"1.0000 trees per request" is per-PATH, not per-request.* Control B is a request, and
it leaks zero trees and zero strings. Some API endpoints leak nothing at all, so
LEAK 30's rate cannot be multiplied by a request count to get a panel-wide figure.

*Rejecting an unknown command costs more than serving a real one.* The error envelope
leaks 3 strings and 1 tree; `/GetSceneList`, which does real work, leaks 2 and 1. An
unauthenticated-but-routable caller cannot reach this, but anything that probes the
documented-and-unimplemented endpoint list walks straight into the most expensive path
measured here.

**How the attribution went wrong, in one line each.**

*The response shape was taken as proof of execution.* `ViewIPURL` returns
`{"Result":"<base64>"}`, which is the shape `setViewIPURL` builds, so it looked
decisive. It is not: a deliberately bogus command,
`/System/Tuxedo/ZwaveSync/NoSuchCommandXYZ`, returns a **byte-identical** body. That
one control, which takes seconds, would have caught this before any of it was written
down.

*The execution trace settles it.* `serve-traced.sh` with `-dfilter 0x18ffc..0x19390`
over 200 successful `AddIPURL` calls logs **zero** blocks: `setAddIPURL` never runs.
The same for `0x29000..0x29060`, so the `set` dispatch at `0x29018` and the `free` at
`0x2903c` are not on this path either.

*And the trace needed its own control.* An empty log is also what a broken harness
produces. `-dfilter 0x6b678..0x6b780` (`HttpResponse_printf`, on every response) over
50 requests logs 9594 bytes, so the harness emits and the zeros mean what they say.
Without that check the correct reading of an empty log is "no information".

*`docs/TRAPS.md` and the REST-API note already said this.* ~6 endpoints are
implemented; a vendor endpoint list is not evidence of implementation. The endpoint
was picked off a help string in the binary, which is a vendor list by another name.

**What it would take to measure the family.** The handlers are real and are called —
`setAddIPURL` from `set` @`0x15e20`, `setUpdateIPURL` @`0x15e44` — and `set` is the
WNMP module's `+16` method, invoked at exactly one place, `0x29018` in
`WnmpDir_serviceField`. Four traced facts narrow where that is reachable from, each
with the `HttpResponse_printf` positive control re-run under the identical request
(5972 bytes, so the zeros below are absence of execution, not absence of tracing):

| filter | over | traced |
|---|---|---|
| `0x18ffc..0x19390` (`setAddIPURL`) | 200 calls | **0** |
| `0x29000..0x29060` (`set` arm + the `free`) | 30 calls | **0** |
| `0x1eedc..0x1f120` (`serviceField` prologue) | 30 calls | **0** |
| `0x6b678..0x6b780` (`HttpResponse_printf`) | 30 calls | 5972 B |

So **`WnmpDir_serviceField` does not run at all** for `/system_http_api/API_REV01/…`.
That is the surprise, because the WNMP directory's own HTTP name IS `system_http_api`
— `WnmpDir_constructor` @`0x1edec` calls `HttpDir_constructor(dir, "system_http_api",
1)` and then `HttpDir_overloadService(dir, 0x29978)`. The `/API_REV01` surface is
served inside `WnmpDir_service` @`0x29978` itself, which calls `serviceField` at three
sites (`0x29ecc`, `0x2a788`, `0x2a810`) that this URL shape does not reach.

`operation=set` is not the missing key either, though it looked like it: `0x1f0f0`
compares the request's `operation` field against `"set"` (literals `0x8d46c` and
`0x549eac`), and the vendor's own URL template at `0x85cd4` reads
`…/ZwaveSync/AddNewDeviceRemote?devicenode=&operation=set`. Sending it changes
nothing — rows 1 and 2 above were measured with `operation=set`.

**ANSWERED — and the family is now measured. See the next section.** The rule is a
three-name blacklist, not a whitelist: `WnmpDir_service` sends a path to
`serviceField` *unless* it starts with one of three prefixes.

This also retracts a claim made earlier in this section's own history: that the reply
string is freed at `0x2903c` on the path these requests take. It is not — that site is
on the field-service path, which they never enter. Where an `/API_REV01` reply string
is released is not established.

### The WNMP URL that reaches serviceField

`WnmpDir_service` tests the path with three `strncmp`s and **branches AWAY** on a
match, so the route to `serviceField` is the fall-through:

| test | at | prefix | on match |
|---|---|---|---|
| 1 | `0x29a98` | `API_REV01/System` (16) | `b 0x29ed4` — away |
| 2 | `0x29ab0` | `API_REV01/Administration` (24) | `b 0x29ed4` — away |
| 3 | `0x29ac8` | `API_REV01/AutomationTest` (24) | `b 0x29ed4` — away |
| — | `0x29adc` | anything else | `WnmpDir_resolveLocation` -> `serviceField` @`0x29ecc` |

    ANY /system_http_api/API_REV01/<path> reaches serviceField
    UNLESS <path> starts with System, Administration or AutomationTest.

Confirmed by trace, one filter on `0x1eedc..0x1f120`:

| endpoint | serviceField |
|---|---|
| `/API_REV01/Registration/Unregister` | 30195 B |
| `/API_REV01/GetSceneList` | 33231 B |
| `/API_REV01/Administration/AddIPURL` | **0 B** |

That last row is why the earlier attempt failed: `AddIPURL`, `UpdateIPURL` and
`ViewIPURL` are all children of field id `0x7` = **Administration**, one of the three
blacklisted prefixes. They were the worst three endpoints in the family to have
picked.

**The path segments are a field table**, not free text. `WnmpDir_resolveLocation`
@`0x1e248` walks the path one `/`-separated segment at a time and matches each against
12-byte records at `0x8ab10` (the `r1` that `Test1Module_constructor` hands to
`WnmpModule_constructor`, landing at module+4). `leakfix/fieldtab.py` dumps all 75:
each record is `{u16 id, u16 parent, char *name}`, so the tree is recoverable exactly
— e.g. `ArmWithCode` is id `0x22` under parent `0x3` = `AdvancedSecurity`, giving
`/API_REV01/AdvancedSecurity/ArmWithCode`.

### MEASURED: the arm handlers leak 3 trees and 8-12 strings per call

Two family members reach `serviceField` and need no Z-Wave device, so they are the
ones that can actually be driven on the bench. Both were confirmed to EXECUTE by
trace before any number was believed — `setPartitionArmed` @`0x1c958` logged 18585 B
and `setarmwithcode` @`0x1afc8` logged 18810 B over 10 calls each:

| arm, 200 requests | strings/call | trees/call |
|---|---|---|
| control A `/GetSceneList` | +2.19 | +1.0000 |
| control B `/GetSecurityStatus` | +0.19 | +0.0000 |
| `/SetSecurityArm` -> `setPartitionArmed` | **+8.19** | **+3.0000** |
| `/AdvancedSecurity/ArmWithCode` -> `setarmwithcode` | **+12.15** | **+3.0000** |

Subtracting the +0.19 background that every arm carries: **`setPartitionArmed` leaks 8
strings and 3 trees per call; `setarmwithcode` leaks about 12 strings and 3 trees.**
Control A reproduces its documented 1.0000 trees exactly, which is the instrument
check.

**This refutes the static prediction in both directions.** The count above says "six
nodes created, four absorbed by `push_back`, so two roots leak". The measurement says
**three** trees, and eight to twelve strings rather than two or three. Counting
`json_new` against `json_push_back` in the handler body under-reads the real cost by
several times, because it cannot see what the shared dispatcher allocates on the way
in and out, and cannot see allocations inside the callees.

**Required parameters, since every one of these rejects an incomplete request** (found
by decrypting the reply with `leakfix/showresult.py` rather than by guessing):

    /API_REV01/SetSecurityArm                 operation=set&arming=STAY&pID=1
    /API_REV01/AdvancedSecurity/ArmWithCode   operation=set&arming=STAY&pID=1&ucode=<code>
    /API_REV01/Registration/Unregister        operation=set&token=<t>&DeviceMAC=<registered MAC>

**Two bench requirements, both of which cost a run here.** `emu/serve-traced.sh` does
NOT start `mqdrain.py`, and the arm handlers `mq_send`; without a drain the queue
backs up and the server wedges into TLS handshake timeouts. Start the drain alongside
it — `Q=$(ls $TREE/dev/mq | sed 's|^|/|'); setsid python3 /tmp/mqdrain.py $Q &`. And
the bench `zwavedevdb.json` is `{"BLights":[],"Dlocks":[],…}` — completely empty — so
`SetDoorLock`, `SetLight` and the thermostat handlers all bail at device validation
and cannot be measured until that database is populated.

Method notes worth keeping. Arms are serial by necessity -- one process, one global
registry, so driving two endpoints at once attributes each one's allocations to the
other. The mutating handlers run last because `AddIPURL`/`UpdateIPURL` would write the
registered-device list that `getRegisteredDevNodes` walks; they are safe on the bench
only because `emu/serve.sh` re-seeds the config from `/work/panel-config` every start
-- and, as it turns out, because they never ran.

### readCRCJSONFile @`0x32280` — 45 strings per IPC message type 154

The largest single candidate is not in the family, and the route this file gave for
it was wrong. **It is NOT reached from `getRegisteredDevNodes` by way of
`validateCRCFileOnFileRead`.** `validateCRCFileOnFileRead` @`0x334c4` does not call it
at all — that function calls only `calculate_CRC`, `apl_isConfigurationFileExist`,
`system()` x4 and `sprintf`. `readCRCJSONFile` has exactly two callers:

  - `barracuda`, once at startup
  - `gettuxedoIPCCommFunc` @`0xd5d0`, at `0xd810`

The second is the one that matters, and it is a recurring leak rather than a startup
one. `gettuxedoIPCCommFunc` is a 12,336-byte message pump: `osal_MqRecv` at `0xd610`,
then a binary-search dispatch on the message type in r8, every arm ending in a branch
back to the receive tail at `0x105c4`. The `readCRCJSONFile` arm is selected by

    d788: cmp r8, #154 ; beq d7f8      -> memset 180 B ; readCRCJSONFile ; memcpy

so **it runs once per IPC message of type 154**, leaking 45 strings each time. Note
the dispatch is range-partitioned (`bhi`/`beq`), not a flat equality chain, which is
the structure that hid reply type 20 from an earlier enumeration — follow the `bhi`
branches or the arm is invisible.

The function is otherwise clean, which is worth saying because it narrows the fix to
one line-shape: the file buffer is `operator_delete__`d, the parsed tree IS
`json_delete`d, and `param_1` is a caller-supplied 180-byte struct (45 ints, matching
the `0xb4` memcpy), so nothing is returned. The only leak is the 45 `json_as_string`
results, each fed straight to `atoi` and then dropped:

    json_get(node, name) ; json_as_string() -> pcVar ; atoi(pcVar) ; store int
    ^ pcVar never freed, 45 times

Each is short numeric text, so the byte cost is small; the count is what is large.
**Still unknown: the rate of type-154 messages**, which is a property of `/tuxedo`,
not of Barracuda, and needs measuring rather than reading. Until then this is 45
strings times an unknown frequency, and calling it "the biggest number in the image"
was ranking a static count as though it were a rate.

**What this says about the method.** Thirty leak sites were found by hammering an
endpoint and watching RSS. That cannot see a handler which is not hammerable, and
the entire write API is not hammerable: you cannot arm a panel a thousand times to
raise a slope. The census took minutes and found nineteen candidates the growth
method could never have surfaced. Neither approach replaces the other -- growth
proves a leak is real and gives its rate, the census says where to look -- but the
gap between them was a whole API surface.
