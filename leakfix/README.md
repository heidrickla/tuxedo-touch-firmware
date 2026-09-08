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

🔑 **Meter the GUEST heap, never qemu's RSS.** The qemu process grows ~34.9 kB
per message against the guest's 10.9 kB; the difference is qemu's own
per-guest-thread cost, which the panel does not pay. An early figure of
"38.5 kB per message" was that confound.

⚠ **`--without-ipc` rebuilds `a84c220a` byte-for-byte.** That is the control:
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

⚠ There are **58** `json_parse_unformatted` calls but only 44 follow a strip.
Redirect only the 43; the rest take a different argument.

## Page sweep: every measurable page reads 0.0 after LEAK 19

    0.0 B/request   tuxedoapi, home, console, consolekeypad, devicelist,
                    groups, multipartition, bookmarksView, camerasetup,
                    camaddedit, camsingleview, videoplayback, videoscreen,
                    scene_configuration, mobileview, eventhandler
    302 by design   index, occupancy, pList  -- their 0.0 means nothing
    unmeasurable    zwavedevicelist

🚨 **`/zwavedevicelist.html` wedges the webserver under a couple of hundred
requests, on the patched and unpatched builds alike** — so it is a vendor
defect, not a regression. At 20 requests it is harmless; at 200 the server stops
answering *any* page while the process stays alive, sleeping, with all four
listeners bound. A restart clears it. Same family as the ~60-parameter API
crash in `docs/TUXEDO-AUDIT-BUGS.md`.

⚠ It first looked like the documented "wedges under sustained load", because in
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

🔑 **The two null results together are the useful finding: the residual is not
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

🔑 **AND THE BENCH IS FAITHFUL HERE — checked, not assumed.**
`hatcscenedb.json` is **byte-identical on the bench and the panel** (3182 bytes,
every entry `"id":0, "name":"", "isUsed":0`), so "No scenes found" is what the
panel returns too and this residual is real rather than an artefact of an empty
test fixture. Worth stating because the obvious worry — that the bench takes an
empty-database branch the panel does not — is exactly the mistake that cost a day
on the IPC path. Re-check the two files before trusting any future measurement
here.

⚠ Note the scene names visible in the web UI (`Bed time`, `Evening time`, ...)
come from `voicecommandglobal.json`'s `SCENES` list, **not** from
`hatcscenedb.json`. Seeing them does not mean scenes are configured.

**Where to look next — two candidates already eliminated.**

- `Base64Encode` (0x1cf20) is **balanced**: `malloc ; fmemopen ; BIO_new(b64) ;
  BIO_new_fp ; BIO_push ; BIO_write ; BIO_ctrl ; BIO_free_all ; fclose`. The two
  BIOs are chained, so one `BIO_free_all` releases both — the textbook OpenSSL
  idiom. Its single `malloc` is the output buffer, which LEAK 20 frees.
- `encrypt` (0x1cdf8) is **balanced**: `EVP_CIPHER_CTX_new` / `EVP_CIPHER_CTX_free`.

⚠ **One theory tried and refuted, recorded so it is not tried again:** that
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

⚠ **The RSS slope is page-quantised and cannot resolve small wins.** 144 kB over
300 requests moves in 4 kB steps, so anything under ~14 B/request is invisible to
it. Use `sceneleak.sh` for increments that size — and note that a slope repeating
to the decimal across builds is a sign it is quantisation, not stability.

⚠ **A stub at 0x165b8 must not push.** `encrypt` takes a fifth argument on the
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

⚠ `/handlerequest_mobile.html` rejects every `commandID` with
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

⚠ **Not yet attributed to a function**, and "same shape as the six below" is not
evidence — that inference is what the `getErrorNode` mistake cost once already.

The dispatch table is decoded. It sits in `.rodata`, spans at least
`0x8ac00..0x8ae40`, and holds **12-byte entries**:

    +0  name1_ptr      +4  name2_ptr      +8  id
    GetSceneList at 0x8ada8:  {0x89f40, 0x89f50, 0x10018039}

The id's low byte increments by one per entry (…0x36, 0x37, 0x38, **0x39** for
GetSceneList…), so it indexes a command; the upper bytes (0x1001, 0x1024,
0x2e10, 0x3110) are flags or a group. ⚠ That low byte is **not** `commands.tsv`'s
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

- **They cannot be driven on this bench.** No scene endpoint is wired into
  `leakprobe.py`, so a fix could not be verified — which is exactly how the
  first IPC attempt went wrong. Build a driver first, then patch.
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
