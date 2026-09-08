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

- **They cannot be driven on this bench — but NOT for the reason recorded here
  originally.** The endpoints are identified and wired up now; the blocker moved
  to a CSRF gate. `handlerequest_html076EF7::service` dispatches on
  `U32_atoi(getParameter("Type"))`, and two arms reach these functions:

      cmd 140  ->  editSceneDetails(getParameter("scenedata"))
      cmd 141  ->  deleteExistngScene(atoi(getParameter("sceneid")))

  `leakprobe.py` now takes `--extra` so console mode can carry those operands,
  and `sceneopleak.sh` drives them.

  🚨 **BUT EVERY CONSOLE-MODE REQUEST ANSWERS 200 AND DISPATCHES NOTHING.** The
  handler gates on a CSRF token *before* the switch:

      3a3c0  bl   getCSRFToken1([sp,#120])   <- keyed on the SESSION's own field
      3a3c4  subs r6, r0, #0                    [r7,#8], NOT on ?sessionid=
      3a3c8  beq  3e858                       <- no token: bail out, r5 = -1

  Traced with `-dfilter 0x3a2a0..0x3a730`, the last block executed is **`0x3a3c4`
  for `cmd` 0, 1, 140 and 141 alike** — four values, one stop, so this is the
  gate and not a per-command quirk. `handlerequest_mobile_html076EF` calls
  `getCSRFToken1` too, so it is not a way around.

  ✅ **AND THE PANEL DOES THE SAME — measured, not inferred.** The panel cannot
  be traced, so a trace-free instrument was needed:
  **`leakfix/dispatchcheck.py`**. The bail is taken *before* the switch, so it
  cannot give a command-dependent answer — if the handler dispatches, a real
  command and an out-of-range one must differ somewhere. Both hosts:

      Type=0  1  141  60000  65535   ->  200, 0 bytes, one identical sha1

  `Type=60000` and `65535` are far outside the switch bound and would have to
  reach the default arm if the dispatch were running at all. **The response body
  is EMPTY**, which is the tell that was there all along: "400 requests, all
  200" was 400 empty bodies.

  ⚠ The `hiddenKey=-1` on `/console.html` is *consistent* with this but is not
  the evidence — it is rendered by a different code path from the handler's
  `r5 = -1`. The command-independence above is the measurement; cite that.

  `TuxedoProbe.login()` performs the real challenge/HMAC UI login, so being
  logged in is not sufficient on the bench. Registration goes through
  `addSessionItem` (0x2e868), called from `authPage_service`, `MyPage_service`,
  `LogOutPage_service` and `checkvalidSessions` — reached by tail-branch thunks,
  which is why a `bl` scan for `addCSRFTokenToSessionID` finds nothing and reads
  as dead code.

  ### How far the registration chase got — start here, do not redo it

  ✅ **The registrar is `authPage_service`, bound to `authenticated/index.html`.**
  `installVirtualDir` calls `HttpPage_constructor(page, 0x1418c, "index.html")`
  into the dir named `authenticated` (0x546648).

  ✅ **It needs a `url` QUERY PARAMETER, and without one it skips registration
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

  ✅ **Record layout**, from `addSessionItem1` (0x2b444):
  `[0..3]` session id, `[4]` flag, `[5..]` a token string from
  `random_string(32)` + `getKeyFromPassword`.

  🚨 **RETRACTED: "it registers at index 0, which the reader never searches."**
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

  ⚠ The first cookie attempt had a bug worth not repeating: the jar was built
  with `re.findall(r"([^,;\s]+)=([^,;\s]+)")` over `Set-Cookie`, which swallows
  attributes and produced a cookie literally named `path`. The table row above is
  the corrected `http.cookiejar` run.

  🔑 **And a browser DOES work** — Lewis created a group through the web UI on
  2026-09-08 while the scripted session was bailing, so this is a difference
  between the two clients and not a dead endpoint.

  ## 🚨 RETRACTED ROOT CAUSE — and the real one, which the repo already had

  ✅ **THE ENDPOINT DISPATCHES. One login is all it ever needed:**

      hiddenKey  = c0386cff1a1aadaa88d49dcfaeb586a   31 hex, not -1
      hidSession == int(cookie[0:8], 16)             PASS
      Type 0 / 141 / 65535 -> bodies of 38 and 43 B  DISPATCHES

  🚨 **The cause was my own driver, not a vendor bug.**
  `docs/TUXEDO-AUDIT-BUGS.md` §2.4 says `No_Of_Users` = **10 concurrent
  sessions**, reaped only when the `HttpSession` dies (`Session_Timer` = 10 min),
  and warns in as many words: *"do not re-login per poll … a client that re-logs
  every 30 s will exhaust the table."* §2.6 lists the symptom outright:
  **`hiddenKey == "-1"` → session has no slot, re-login.** Every test above
  logged in afresh — dozens of times — so from the eleventh onward there was no
  slot, and `-1` was the table saying so.

  ⚠ **So the analysis below is WRONG where it concludes "index 10 is outside the
  search".** `getCSRFToken1` scans `i = 1..getNoOfUsers()`, and `getNoOfUsers()`
  returns `No_Of_Users` from `/root/Settings/WebConfig.conf` — **10 on this unit,
  verified** — not the 5 web accounts I assumed. Index 10 is *inside* the range.
  The record being at 10 was the last free slot, exactly as designed.

  🔑 **The mechanism notes that follow are still accurate and worth keeping** —
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
                            token='7c17e0518d3c7a1c41894ce458...'
      slots 1..9:           0xFFFFFFFF, i.e. FREE

  `addSessionItem` writes correctly, and `getCSRFToken1` scans
  **`i = 1 .. getNoOfUsers()`** from `r4 = 40`. ⚠ **I read `getNoOfUsers()` as the
  5 web accounts in `UserNamesFile.txt` and concluded index 10 was out of range.
  That was a guess and it was wrong** — it returns `No_Of_Users` from
  `/root/Settings/WebConfig.conf`, which is **10** here, so index 10 is the last
  valid slot rather than one past the end.

  🔑 **The writer picks the LAST free slot** — `mov r8, r6` at 0x1431c runs on
  every empty slot the scan passes, so `r8` ends as the highest free index. With
  ten slots and one session that is index 10, which is correct behaviour and not
  a bug. It only *looked* like one because the table was already full of my own
  abandoned sessions.

  🚨 **Not explained: the browser DOES dispatch, and that is now verified from an
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

  ⚠ The peer found arm/disarm going to `/AdvancedSecurity/*` on the API surface,
  so a second route exists for *some* commands — but not for this one: the group
  write is `cmd=6293` on `handlerequest`, and it landed.

  ✅ **What this hands the next attempt:** the scripted request shape is now
  known exactly — `sessionid` is the NUMERIC `hidSession` from
  `/eventhandler.html`, not the cookie's hex, and `tokenkey` is a required
  parameter that is `-1` precisely because of the bug above.

  ### ✅ REPRODUCIBLE: session issuance stops after FOUR sessions

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

  ⚠ **SEEN ONCE, NOT REPRODUCED: a segfault.** The first `fillslots` run left this
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

  ⚠ Reading the table on the PANEL to settle it directly does not work either:
  `/proc/<pid>/mem` on 2.6.31 needs a ptrace attach, and attaching to Barracuda
  is not worth a relaunch unit.

  🔑 **The consequence reaches past the scene work: any `/handlerequest.html`
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

🔑 **It leaks on EVERY call, not only when the scene exists** — worth stating
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

🚨 **WRITTEN, MEASURED, AND WITHHELD — it frees nothing on this unit.** LEAK 23 in
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

🔑 **Because `checkIfSceneExists` parses the WRONG-looking file, and reading the
string settles it.** The pointer at `0x90e94` is `0x8b080` =
`/opt/tuxedo/configuration/hascenedb.json` — the **Z-Wave** scene database, which
is **0 bytes** on the panel and the bench. Not `hatcscenedb.json`, the 3182-byte
TC scene file the rest of the scene code reads. An empty file parses to NULL, so
`scene_getRootNodeOfObjects` allocates nothing and there is nothing to free.

✅ **So the ~107 B/request on `cmd=141` is real but comes from elsewhere — and
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

✅ **LOCATED: `validatePageName` (0x13afc), and it leaks TWICE per call.** The map
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

✅ **The exit is a single convergence at 0x13b68** — 0x13b64 falls through to it —
so one stub covers both paths. `lr` is expendable (the function returns through
`pop {…,pc}`), and `r4` is restored by that same pop, so it is free to hold the
return value across a `bl`:

    mov r4, r0 ; mov r0, r6 ; cmp r0,#0 ; blne json_delete ;
    mov r0, r4 ; add sp,sp,#4 ; pop {r4,r5,r6,r7,pc}

## ✅ LEAK 24 SHIPPED IN THE BUILDER: 107 -> 39 B/request, replicated

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

### ⚠ LEAK 25 (the loop's `json_as_string`) — BUILT, MEASURED, WITHHELD

I predicted the 32-byte row was the per-iteration `json_as_string` at 0x13b38 and
built the stub. It changes nothing:

    per-request bytes:  + LEAK 24  39 B     + LEAK 24 and 25  39 B
    32-byte row:        +349        ->      +337

The stub runs — 0x695b0, 0x695b8, 0x695c8 each execute exactly once per request —
so this is not the never-reached failure.

🔑 **"Once per request" is the whole point, and the arithmetic had already said
so.** I predicted up to 29 frees per request, one per map entry. The loop body
runs **once**. And +349 over 300 requests is **1.16 per request**, not 10 or 29 —
the growth rate refuted the per-iteration theory before any stub was written.
**When a per-iteration theory predicts N per request and the measurement says ~1,
it is already refuted; check the rate against the theory before building.**

❔ **So the remaining 39 B/request is still unidentified.** The 32-byte chunks hold
**pointers, not text** — a `0x21` header then pointer pairs, the shape of an
internal node — so they belong to some other structure abandoned once per request.
`chunkdiff` named the first one from its text; this one will need the allocation
traced instead, because its contents are addresses.

🚨 **`patches.tsv` STILL DESCRIBES 62ee361c AND MUST NOT BE REGENERATED UNTIL THIS
IS DEPLOYED.** The table's whole value is that it says what the panel runs;
regenerating it now would make it describe a build that exists nowhere, which is
the stale-header failure its own header records twice. When LEAK 24 goes to the
panel: deploy, then regenerate the P15 rows, then re-verify stock -> new md5 from
a clean tree, then update the chain and the `LIVE_DRIFT` line together.

✅ **Re-enable LEAK 23 the moment `hascenedb.json` is non-empty** — i.e. once real
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
