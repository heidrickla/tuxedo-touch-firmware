# Push-stream authentication for the Tuxedo Touch — patch design (proposed P13)

Target: `/opt/webserver/Barracuda`, v12, md5 `c8971027bb9f77801d01713b4ae50b2f` (bench copy re-hashed this session: match).
All offsets below are **FILE** offsets. For Barracuda, file = VA − 0x8000 (PT_LOAD3: off 0x0, vaddr 0x8000, filesz 0x54a084). The second load segment uses −0x10000; do not generalise the rule.

---

## 1. VERDICT

**Superseded 2026-09-06. The patch is now verified end to end under emulation and every gate but D is closed.** The original verdict, and the reasoning that produced it, is kept below because the reasoning was right — what changed is the evidence, not the argument.

**Original verdict: No. Do not flash this today.**

The design below is sound, and I re-derived every structural fact in it myself against the v12 binary rather than inheriting it. But three things are true at once, and the third is the one that decides:

1. Two of the three designs on the table are refuted, not merely worse. `newClientCon` returning non-zero cannot produce an HTTP status and silently zeroes the client counter that gates every pushed byte; attaching the existing `FormAuthenticator` to the EhDir answers with HTTP 200 and a login page. Both fail as *silent* failures on a live alarm feed. Design B below is the only survivor.
2. ~~Design B's decisive precondition has never been observed.~~ **Closed 2026-09-06 — this is now measured, not inferred.** See §3. It no longer argues against flashing.
3. ~~**The hazard model in the brief is backwards for this patch.**~~ **Still true as written, but no longer unmeasured — see the emulation result below.** The analysis stands: The brief treats startup crashes as the primary hazard. `sigHandler` is installed in `barracuda()` at 0x10974–0x10a1c, *after* `bl installVirtualDir` at 0x1092c — so a startup fault is never reported to supervis and cannot reach the 24-relaunch watchdog disarm. But this patch does not run at startup. It runs **in the request path**, which is after `SoDisp_run`, i.e. fully inside the reported path: SIGSEGV → msg 8 → supervis 0xc684 → `cmp #0x18` → `DisArmSWTimer(g_wdgtmr)` → hardware reset. And the push endpoint is hit continuously by Home Assistant's reconnect loop and by every open browser page. A fault in the cave is therefore not "a broken web page" — it is a self-driving crash loop that reaches the reset ceiling in roughly two minutes and repeats. `barracudarestartcnt` (supervis 0x16be0) is never reset to zero anywhere in supervis, so the budget is 24 *minus whatever this boot has already spent*.

### What changed: the patch was executed, not just reasoned about

`emu/` runs the real ARM binary under `qemu-user` in a chroot of the v12 rootfs, with the panel's own configuration partition restored into it. Both builds were driven through the identical rig, and the runner asserts that the process answering `:80` is the one it started — see `emu/README.md` for why that assertion is load-bearing.

Anonymous, no credential:

| path | v12 control | P13 |
|---|---|---|
| `/` | 200, 133 B | 200, 133 B — unchanged |
| `/SimpleDebugger.interface/G.` :80 | 200, 526 B | **401 Unauthorized**, 241 B |
| `/SimpleDebugger.interface/G.` :6280 | 200, 526 B | **401 Unauthorized**, 241 B |
| `/home.html` | 302, 215 B | 302, 215 B — unchanged |
| process afterwards | alive | alive |

Then the full suite against the running P13 instance, logging in with the panel's real credentials against the panel's real account store, all four listeners:

```
anonymous     :80 denied   :6280 denied   :443 denied   :9443 denied      (all 401)
authenticated :80 OK       :6280 OK       :443 OK       :9443 OK
panel web UI  200
vs the live-panel baseline: anon:80, anon:443, anon:6280, anon:9443  OPEN -> denied   FIXED
                            authed x4, webui                          unchanged
```

The server stayed up through all of it with **zero** `SIGSEGV` in its log. So the deny direction answers `401` rather than "something else", the allow direction still delivers frames, non-push paths are untouched, and the cave does not fault in the request path — the three things the hazard analysis above said would cost a self-driving crash loop if wrong.

Two honest limits: `qemu-user` forwards syscalls to the build host kernel, so 2.6.31 socket semantics are not modelled (`ssh/BUILD.md:871`), and with no `/tuxedo` the stream carries no alarm state, so the authenticated result is "frames flow", not "9 frames of live state".

### The original gate list

What would have to be true before the answer becomes yes:

| Gate | What must be observed | Cost | Who |
|---|---|---|---|
| ~~**A**~~ | **PASSED 2026-09-06.** See §3. Both halves measured on the live panel, read-only. | done | done |
| ~~**B**~~ | **PASSED.** `verify-panel.sh:42` now derives the length from the row (`n=$(( ${#patched} / 2 ))`); the hardcoded `count=4` is gone, and the 124-byte P1c row already exercises the long-site path. | done | done |
| ~~**C**~~ | **PASSED 2026-09-06**, and stronger than a stored copy: v12 is *reproducible*. Genuine stock (`324209e1`) is on the build VM at `/work/extracted/root_stock/`, the vendor `app2.hdr` it came from is sha256-pinned in `/work/stock/MANIFEST.sha256`, and applying all 11 `patches.tsv` rows to stock was **executed** and produced the three v12 md5s exactly. Golden v12 also sits at `/work/v12/root/` and `/work/v12/root_verify/`. | done | done |
| ~~**D**~~ | **MET 2026-09-06.** Lewis at the panel; he stopped the Home Assistant Tuxedo integration before the flash and restarted it after, and it came back normally; v12 rollback image staged both locally (`build/v12final/app2.hdr`) and on the build VM. **v13 flashed and verified** — 13/13 sites, anonymous 401 on all four listeners, authenticated still streaming, conformance 20/20, Barracuda never restarted. | done | done |

Gate A was the one that decided whether the patch *works*; it passed on 2026-09-06 and the allow direction is no longer an inference. Gates B and C — survivability of a mistake — also passed. **D is the only gate still open, and it is scheduling, not evidence.**

Nothing was modified. Gate A used authenticated read-only HTTP requests and no SSH connection; no wrong password was submitted at any point.

---

## 2. THE PATCH

### 2.1 Where the hook goes, and why not where the brief looked

`EhDir_service` already calls `HttpDir_authenticateAndAuthorize` on itself, once per request, **before a single response byte is written** and before the `G.`/`I.`/`C.`/`B.` path dispatch at 0x7a450. Verified:

```
0x07a414  ldr   r0, [sp, #0x10]      ; this HttpDir*
0x07a418  mov   r1, sb               ; HttpCommand*   (sb = r2 = arg3, set at 0x7a384)
0x07a41c  mov   r2, r7               ; relative path
0x07a420  bl    #0x6b544             ; HttpDir_authenticateAndAuthorize   <-- HOOK HERE
0x07a424  cmp   r0, #0
0x07a428  beq   #0x7b260             ; 0 => "already handled", return 0 from EhDir_service
```

That call currently allows everything, because the dir's `+0x14`/`+0x18` are NULL. Note which field matters: in `HttpDir_authenticateAndAuthorize`, the `+0x14` (realm) branch at 0x6b5ac calls `AuthenticatedUser_get1` and then does `mov r0,#1` **unconditionally** — the realm cannot deny. Only `+0x18` (authenticator) can. The brief's "write both fields" framing is half inert.

Why this site and not `SimpleDebugger_newClientCon`:

- `EventHandler_PushConRequest` has **exactly one caller**, `EhDir_service` (verified). Gating 0x7a420 gates the entire push surface — the XHR stream `G.`, the iframe transport `I.`, and the client→server command channel `C.` — with one patch.
- At 0x7a420 nothing has been committed, so a real HTTP status is still possible. By the time `newClientCon` is consulted, the 200, the multipart headers and the `['setCid',N]` part are already through `InitJsPcon_flush`.
- The `newClientCon` route additionally has a counter bug that turns the patch into a remote DoS on the alarm feed: `SimpleDebugger_vprintf` at 0x1e0ac gates *all* pushed data on `[sd+0x138]`, `EventHandler_cleanupTerminatedCon` decrements it for every terminated connection with no "was it accepted" flag, and a denied connection never incremented it. One anonymous GET would silently mute an authenticated consumer's stream.

`EhDir_service` is shared: `EhDir_constructor` has exactly two callers, `initAndInstallServlet` (dir `0x55b59c`, from its literal pool at 0x1de24) and `initAndInstallBookmarksServlet` (dir `0x55b458`, pool 0x1d168). The dir-pointer compare is therefore **mandatory**, not optional.

### 2.2 The cave

Three candidates were scanned. My own scan, over allocated sections only, for: B/BL all condition codes, BLX(imm), PC-relative LDR literals, ADR (`add/sub rd,pc,#imm`), 4-byte-aligned pointer words including the Thumb `|1` form, `.rel.dyn`, `.rel.plt`, `.dynsym`, `.ARM.exidx`:

| Candidate | VA range | Size | Hits |
|---|---|---|---|
| `LoginTracker_getFirstNode`+`getNextNode` | 0x64e9c–0x64ed4 | 56 B | **0** |
| `HttpServer_destructor` | 0x6c8c0–0x6c978 | **184 B** | **0** |
| `decrypt/encryptAESforTuxdbAPI` | 0x1ee20–0x1eedc | 188 B | 1 (`.rodata` 0x455158 → 0x1ee50, inside the embedded ZIP; noise, but non-zero) |

**Use `HttpServer_destructor`, VA 0x6c8c0, file 0x648c0.** It is the only candidate that is both large enough and returns a clean zero at every scope. The 56-byte cave is clean but too small once the mandatory dir compare is included; the AES pair is large enough but does not return zero. `HttpServer_destructor` also sits in inert territory, whereas the 56-byte cave is bracketed by the login tracker that P1/P2/P6 already rework.

Boundaries are hard on both ends: `0x6c8bc` is `pop {r4,r5,pc}` (no fall-through in), and `0x6c978` starts the next function's `push`. No exidx entry, no relocation, no dynsym. `callers()` is empty and no pointer to 0x6c8c0 exists in any allocated section — it is a destructor for an object this embedded server never destroys.

A caution learned here: `patches.tsv`'s six 4-byte Barracuda offsets are **not** the full inventory of modified bytes. P2's patched word at file 0xbaf0 branches to VA 0x15074, the head of `resetLoginFailureCount`, where ~124 bytes are a hand-written lockout stub with orphaned stock tail behind it. Check the bytes, not the table, before claiming a region is free.

### 2.3 The cave body — 92 bytes at file 0x648c0 (VA 0x6c8c0)

Round-tripped through capstone; the listing below is capstone's own output of the bytes to be written.

```
VA        word      instruction              annotation
0x06c8c0  e92d4070  push  {r4,r5,r6,lr}      16-byte frame; keeps sp 8-aligned. Same
                                             prologue the function we replace used.
0x06c8c4  e1a04000  mov   r4, r0             r4 = HttpDir* (this dir) - r0 dies at the bl
0x06c8c8  e1a05001  mov   r5, r1             r5 = HttpCommand*
0x06c8cc  ebfffb1c  bl    #0x6b544           the REAL HttpDir_authenticateAndAuthorize,
                                             called with r0/r1/r2 untouched. Stock
                                             semantics for every dir are preserved first.
0x06c8d0  e3500000  cmp   r0, #0
0x06c8d4  08bd8070  popeq {r4,r5,r6,pc}      stock already denied and handled -> return 0
                                             unchanged. We never second-guess a deny.
0x06c8d8  e59f3034  ldr   r3, [pc,#0x34]     -> 0x6c914 = 0x0055b59c
0x06c8dc  e1540003  cmp   r4, r3
0x06c8e0  18bd8070  popne {r4,r5,r6,pc}      not the SimpleDebugger EhDir (i.e. it is
                                             BookmarksHandler, dir 0x55b458) -> return
                                             stock's r0 = 1. Bookmarks behaviour
                                             is bit-for-bit unchanged.
0x06c8e4  e2850008  add   r0, r5, #8         HttpRequest = HttpCommand+8. This is the
                                             identical expression stock uses at 0x6b570.
0x06c8e8  ebffe477  bl    #0x65acc           AuthenticatedUser_get1(req)
                                             = HttpSession_getAttribute(
                                                 HttpRequest_getSession(req,0),
                                                 "AuthenticatedUser")
0x06c8ec  e3500000  cmp   r0, #0
0x06c8f0  13a00001  movne r0, #1             normalise the attribute pointer to a boolean
0x06c8f4  18bd8070  popne {r4,r5,r6,pc}      session carries AuthenticatedUser -> ALLOW
0x06c8f8  e1d53bb6  ldrh  r3, [r5,#0xb6]     response-committed flag. r5 is guaranteed
                                             non-NULL: stock dereferenced [r1,#0xb8] at
                                             0x6b544 three instructions ago.
0x06c8fc  e2850060  add   r0, r5, #0x60      HttpResponse = HttpCommand+0x60. Confirmed
                                             by EhDir_service's own `add sl,sb,#0x60`
                                             at 0x7a474.
0x06c900  e59f1010  ldr   r1, [pc,#0x10]     -> 0x6c918 = 401. 0x191 spans bits 0..8 so
                                             it CANNOT be an ARM immediate; the vendor
                                             hits the same wall with 411 at 0x7a56c.
0x06c904  e3530000  cmp   r3, #0
0x06c908  0bfffc61  bleq  #0x6ba94           HttpResponse_sendError1(resp,401), and only
                                             if the response is not already committed.
                                             sendError1 is already used twice in this
                                             very function (411 @0x7a56c, 404 @0x7a894),
                                             on this same socket, after the same
                                             FIONBIO / SO_SNDTIMEO reconfiguration.
0x06c90c  e3a00000  mov   r0, #0             DENY: 0 = "request already handled"
0x06c910  e8bd8070  pop   {r4,r5,r6,pc}
0x06c914  0055b59c  .word                    SimpleDebugger EhDir (in .bss)
0x06c918  00000191  .word 401
```

Ends at 0x6c91c. 92 of 184 cave bytes used; 0x6c91c–0x6c978 is left as stale `HttpServer_destructor` remnant, unreachable (nothing branches into it and no path falls through `pop {..,pc}`).

Register discipline: `r4/r5/r6` are callee-saved and are restored by every exit; `lr` is on the stack across both inner `bl`s and the conditional `bleq`; `sendError1` is `mov r2,#0; b sendError2`, an ordinary AAPCS callee. `r0` on every exit path is exactly what `EhDir_service`'s `cmp r0,#0 / beq 0x7b260` expects.

### 2.4 patches.tsv rows

Format is `name<TAB>binary<TAB>file_offset<TAB>stock<TAB>patched<TAB>description`. `apply-patches.py` takes the length from `len(stock)`, so a 92-byte row needs no tooling change there.

```
P13-pushauth-hook	/opt/webserver/Barracuda	0x72420	47c4ffeb	26c9ffeb	push stream: EhDir_service auth call redirected into the P13 stub
P13-pushauth-cave	/opt/webserver/Barracuda	0x648c0	30402de90050a0e104d04de2020000ead8ffffeb0400a0e11c7efeeb0500a0e16be9ffeb004050e2f8ffff1a020000ead0ffffeb0400a0e1147efeeb080085e263e9ffeb004050e2f8ffff1a030000eaa82095e54830a0e3912320e0	70402de90040a0e10150a0e11cfbffeb000050e37080bd0834309fe5030054e17080bd18080085e277e4ffeb000050e30100a0137080bd18b63bd5e1600085e210109fe5000053e361fcff0b0000a0e37080bde89cb5550091010000	P13 stub in dead HttpServer_destructor: SimpleDebugger.interface now needs a logged-in session, else HTTP 401
```

**`verify-panel.sh` must be fixed first** or it will fail this row. It hardcodes `count=4`:

```sh
-        live=$($SSH "dd if=$binary bs=1 skip=$dec count=4 2>/dev/null | od -An -tx1 | tr -d ' \n'" 2>/dev/null)
+        n=$(( ${#patched} / 2 ))
+        live=$($SSH "dd if=$binary bs=1 skip=$dec count=$n 2>/dev/null | od -An -tx1 | tr -d ' \n'" 2>/dev/null)
```

### 2.5 Deliberate scope limit

`/BookmarksHandler.interface/G.` is a second unauthenticated push interface on the same shared `EhDir_service`. The dir compare at 0x6c8dc deliberately leaves it open. It does not carry alarm state, nobody has characterised what consumes it, and widening the blast radius for no alarm-state benefit is the wrong trade on the first flash. There are 92 spare cave bytes; closing it later is a second compare, once someone has watched what talks to it.

---

## 3. WHY AN UNAUTHENTICATED CLIENT CANNOT PASS

This is the failure mode that would look like success — a patch that ships, verifies, and still serves partition status to anyone on the LAN. The argument has to be airtight in the *deny* direction and merely strong in the allow direction, because a false allow is a silent security hole and a false deny is a loud broken feature.

**The predicate is not new.** `AuthenticatedUser_get1(HttpCommand+8)` is precisely what `HttpDir_authenticateAndAuthorize` itself evaluates at 0x6b570–0x6b57c to gate `/authenticated/`, and it is what twenty of the panel's own page handlers use (`home_html076EF::service`, `armcontrol_html076EF::service`, `consolekeypad_html076EF::service`, …). We are not inventing a test; we are applying the panel's own test to a directory the vendor forgot.

**The only writer of the attribute is a real password check.** `HttpSession_setAttribute` has **exactly one caller** in the entire binary: `FormAuthenticator_authenticate`. That call is downstream of `AuthUserList_createOrCheck` returning 0, which is itself downstream of a credential comparison (20-byte digest memcmp at 0x65f4c / strcmp at 0x65f78, `cmp r0,#0; beq <fail>` at 0x65f88). There is no other path by which the string `"AuthenticatedUser"` (0x5465e4) becomes a session attribute. That literal appears in exactly three literal pools: `get1`, `get2`, and `AuthenticatedUser_constructor`.

**The anonymous-user trap does not exist in this build.** `AuthenticatedUser_getAnonymous` (0x65850) has zero callers and zero references from any allocated section. Nothing can obtain the anonymous singleton, therefore nothing can install it in a session, therefore a bare non-NULL test is a real gate and `getType == 3` hardening is unnecessary. (`AuthenticatedUser_getType` at 0x64e50 is also dead, and is a *pointer-identity* comparison against the literals `"BAU"`/`"DAU"`/`"FAU"` with no NULL guard — it would have been the wrong thing to lean on.)

**A client with no session reaches NULL without crashing.** `AuthenticatedUser_get1` → `HttpRequest_getSession(req, create=0)` → `HttpSession_getAttribute`, which opens `cmp r0,#0 / moveq r4,r0 / … / mov r0,r4` (0x7121c–0x7125c) and returns NULL for a NULL session. This exact call already executes on every anonymous request to `/authenticated/*`, which the panel demonstrably answers rather than faults on.

**The client cannot forge the early-outs.** `HttpDir_authenticateAndAuthorize`'s two short-circuits are `cmd+0xb8` (written only by `HttpRootDir_service` at 0x6e250/0x6e264, a ++/-- around the user-404 re-dispatch) and `cmd+0xb6` (response-committed; never written as a halfword anywhere in `.text`). Neither is reachable from request content. Note the stub is *stricter* than stock here: if either flag is set, stock allows unconditionally and the stub still applies the session test. That is fail-closed, and the only realistic way to reach it is a 404 re-dispatch into `SimpleDebugger.interface`, which no configured 404 page does.

**Every transport is covered.** The gate is upstream of the path dispatch at 0x7a450, so `G.` (XHR stream), `I.` (iframe stream), `C.` (POST command channel) and the WebSocket upgrade are all behind it. `EventHandler_PushConRequest` has one caller. All four listeners (80, 443, 6280, 9443) feed one `HttpServer` and one dir object inserted once at 0x1ddc0.

**The allow direction — MEASURED 2026-09-06, Gate A.** This was the last inference in the design. It is now an observation.

*The predicate is shared, not analogous.* `AuthenticatedUser_get1` @0x65acc — the function the cave calls — is called in **stock** by `FormAuthenticator_authenticate` and by `home_html076EF::service`, among 22 callers. So exercising `/authenticated/*` and `/home.html` over HTTP reads the return value of the exact function the patch branches on. There is one `"AuthenticatedUser"` literal in the binary (0x5465e4, file 0x53e5e4); it is loaded from three pools only — `AuthenticatedUser_constructor` (the writer) and `_get1`/`_get2` (the readers). One attribute, one name, no second path.

*It discriminates on the session value, not on the presence of a cookie.* Three requests to `/authenticated/index.html`, differing only in the `Cookie` header:

| request | result |
|---|---|
| valid session | `302` → `https://203.0.113.5/home.html` |
| **forged cookie** — same name, same length, wrong value | `200`, 6311 B login page |
| no cookie at all | `200`, 6311 B login page |

Forged and absent are byte-identical, so the deny is a real session lookup. `/home.html` confirms it from the other side: `200` 13130 B of application with the session, `302` with none.

*Both consumers will carry the cookie.* Read at 0x71ae0 said `Path=/`; the wire agrees — `Set-Cookie: z9ZAqJtI_...=...; path=/; HttpOnly; secure`. `path=/` covers `/SimpleDebugger.interface/G.` and the push XHR is same-origin, so a logged-in browser sends it. Home Assistant never depended on scoping: `push.py` sets `headers={"Cookie": cookie}` explicitly.

*The `secure` attribute does not break port 80, though it looked like it would.* A `Secure` cookie is not sent over plaintext, which would have denied the panel's own UI on :80 after the patch. Measured: the panel **omits `secure` when the login itself happens over HTTP** (`z9ZAqJtI_...; path=/; HttpOnly;` — no `secure`), so a plaintext session holds its cookie and still reaches the :80 stream. Allow holds on every listener. (The unrelated `_zFL` redirect cookie keeps `secure` unconditionally even over HTTP, so it is dropped by browsers on :80. It carries a return URL, not a session, and nothing in this patch reads it.)

*What Gate A did not cover.* Only that `sendError1` produces a clean `401` on this endpoint after `EhDir_service`'s socket reconfiguration — §6 row 2, unchanged, and still only answerable after a flash.

**What a denied client sees.** `HTTP/1.1 401`, no body of consequence, connection closed before any multipart byte. `ha-tuxedo-touch` handles that at `push.py:487` — `if resp.status in (401, 302): raise PushSessionExpired` → `invalidate_session()` → one immediate re-login, then backoff. That is the designed recovery, and it is the reason 401 was chosen over a silent close. The browser's `$GeckoPushCon_onreadystatechange` (`eh.js:454`) detects `status != 200` and calls `$doException` → `close()` → `EhStatus.prototype.onError`, which is **empty** (`eventHandler.js:770`) with no reconnect and `ErrorType.showError` a no-op. So for the browser a wrong patch is a *silent permanent loss of live status for that page load*. That is exactly why T5 below must be judged by watching status actually update, never by the absence of an error.

---

## 4. TEST PLAN

Run in order. Each step names the observation that proves it. Never submit a wrong password anywhere: P1 gives five attempts and a 300 s self-clearing lock, and there is no reason to spend that budget.

**T0 — Gate A. DONE 2026-09-06, PASSED.** Read-only, unpatched panel, no SSH, no wrong password.
Superseded the devtools procedure: the `Set-Cookie` attributes were read off the wire (`path=/`, and `secure` absent over HTTP), which settles what a browser will send without needing to watch it send it, and the predicate was exercised directly with valid / forged / absent sessions. Full result in §3.
*The stop condition did not trigger.* The allow direction holds for a browser on :443 and :80 and for Home Assistant.

**T0b — emulation, free, no panel. DONE 2026-09-06, PASSED.**
`sudo bash emu/run.sh <tree> <label>` on the build VM for the control and the patched build, then `emu/serve.sh` plus `test-stream-auth.py --host <vm> --creds <file>` for the authenticated direction. See `emu/README.md`.
*Proves:* deny answers `401` and not a 200-with-login-page; allow still delivers frames; `/` and `/home.html` are byte-identical to the control; the process survives. This is T5 and T6 run somewhere a crash costs nothing.
*Does not prove:* anything kernel-specific — `qemu-user` uses the build host's kernel.

**T1 — offline, free.** `python apply-patches.py --check --root <staged>`; then independently read the four bytes at file 0x72420 and the 92 bytes at 0x648c0 back out of the *built* binary and compare against the row.
*Proves:* the offsets are file offsets and the applier wrote what the table says.

**T2 — offline, free.** Assert the cave write is exactly 92 bytes and that file 0x648c0+92 .. 0x648c0+184 is untouched, and that 0x64978 (VA 0x6c978) still disassembles as the next function's `push`.
*Proves:* no overrun into live code.

**T3 — offline, free.** Disassemble the 92 written bytes at 0x6c8c0 and check the three call targets resolve to 0x6b544, 0x65acc, 0x6ba94, and the two literal loads to 0x6c914 / 0x6c918.
*Proves:* no arithmetic error in the branch or pool offsets — the single most likely way this crashes.

**T4 — flash. Preconditions: Gates B/C/D done, HA integration disabled, someone at the panel, rollback terminal already open.**
Immediately after the restart, from the rollback terminal:
`ssh ... 'PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH; ps | grep -c [B]arracuda; tail -5 /opt/tuxedo/configuration/SupervisionLog.txt'`
*Proves:* the process exists. `ps` is the load-bearing half — `SupervisionLog.txt` can be silent for up to 600 s for an unreported death, so an empty log is not reassurance.
Also record the restart counter now: `grep -c BARRACUDA_RESTART /opt/tuxedo/configuration/SupervisionLog.txt` since the last `SYSTEM START`. The ceiling is 24 minus that.

**T5 — the crash canary. One request, from the console, before anything else reconnects.**
```
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" -m 4 http://203.0.113.5/SimpleDebugger.interface/G.
ssh ... 'ps | grep -c [B]arracuda'
```
*Proves:* the deny path executes without faulting. This is the single highest-risk instant of the whole operation — the first time the new code runs. Do it once and check the process before doing it twice.

**T6 — deny, all four listeners.** Repeat T5 on `:6280`, and on TLS via (modern curl cannot negotiate with this panel — exit 35):
```
printf 'GET /SimpleDebugger.interface/G. HTTP/1.0\r\nHost: 203.0.113.5\r\n\r\n' \
  | openssl s_client -connect 203.0.113.5:443 -tls1 -cipher 'ALL:@SECLEVEL=0' -quiet -ign_eof 2>/dev/null | head -20
```
and the same on `:9443`. Then the sibling transports a `G.`-only patch would have missed:
```
curl -s -m 3 "http://203.0.113.5/SimpleDebugger.interface/I.?oid=1"
curl -s -m 3 "http://203.0.113.5/SimpleDebugger.interface/C.?cmd=S"
```
*Proves:* `401` on all four listeners and all three transports. **Judge on the status line here** — unlike the FormAuthenticator design, this one does produce a real status. A body containing `statusMessageText` or a partition string like `0:21:1:fe:...Ready To Arm:2` is a FAIL.

**T7 — bookmarks unchanged.** `curl -s -m 3 http://203.0.113.5/BookmarksHandler.interface/G. | head -c 200`
*Proves:* still 200 with `['setCid',N]` — i.e. the dir compare at 0x6c8dc works and we did not accidentally gate the other EhDir.

**T8 — authenticated stream still works. Lewis only; I must not handle credentials.**
In a browser already logged in:
```js
fetch('/SimpleDebugger.interface/G.',{credentials:'same-origin'}).then(r=>console.log(r.status))
```
*Proves:* `200`. A `401` here means the patch is wrong and must be rolled back immediately, regardless of how well T6 went. T6 passing while T8 fails is the bad outcome.

**T9 — the panel's own web UI.** Log in, land on home, watch the top status bar populate and the partition status change.
*Proves:* live status updates. There is exactly one stream in the whole UI (`eventHandler.js:750`, guarded by `if(eh==null)`), and its `onError` is empty — so this must be judged by seeing status *move*, never by the absence of an error.

**T10 — arm/disarm, and read this carefully because it fails in a dangerous direction.** Arm/disarm does not travel on the stream: `HomehttpRequest.js` sends `GET /handlerequest.html?cmd=…`. The stream carries only the answer. **A broken stream means the panel still arms and disarms while the web UI shows the user nothing** — no exit-delay countdown, no user-code accept/reject.
Press Disarm in the web UI, then confirm the outcome **on the physical touchscreen**, not in the browser. Two independent confirmations. The browser alone cannot tell you the truth here.

**T11 — Home Assistant.** Re-enable the integration. Check diagnostics for `connected`, `frames`, `reconnect_wait`.
*Proves:* `connected: true` with `frames` climbing. On a correct patch a stale cookie now produces one `PushSessionExpired` and an immediate re-login. FAIL looks like `reconnect_wait` climbing toward 300 with `frames` static.

**T12 — soak, 20 minutes.** Re-read `SupervisionLog.txt` (two 600 s poll cycles) and re-read the restart counter.
*Proves:* no relaunches, and HA's frame count still climbing. This is the pass.

---

## 5. ROLLBACK

Written to be followed under pressure. Have R0 done and an R1 terminal open **before** flashing.

**R0 — before touching anything.** Get a golden `Barracuda` off the panel and out of the scratchpad (which is session-temporary) and out of mtd16 (which the partition you are modifying, and which a reflash wipes). All three built v12 images carry the exact running binary; extract from `build/v12final/app2.hdr` and verify `c8971027bb9f77801d01713b4ae50b2f`. Keep it outside the repo — `ci/checks.sh` rejects `*.bin`.
Note: `RECOVERY-BACKUP.md` says mtd16 was deliberately not captured because it is "reproducible from the firmware image" — that is true of *stock*, not of the patched build. Separately, `MANIFEST.txt` claims stock Barracuda (`324209e1…`) is not on this bench, but `build-image.sh:113` builds every image with `--template /work/stock/app2.hdr` on the build VM, so a stock template plausibly does exist there. Nobody has checked. Do not rely on either claim; just take the golden copy.

**R1 — normal case, SSH up.** Barracuda cannot be written in place while running (ETXTBSY). Copy, then rename over it — `rename(2)` swaps the directory entry while the running process keeps its inode. This is the pattern `deploy.py` already uses.
```
scp -i ~/.ssh/tuxedo_ed25519 Barracuda.v12.golden root@203.0.113.5:/tmp/B.good
ssh ... 'PATH=/bin:/sbin:/usr/bin:/usr/sbin:$PATH; md5sum /tmp/B.good'      # must be c8971027...
ssh ... 'cp /tmp/B.good /opt/webserver/Barracuda.new && chmod 755 /opt/webserver/Barracuda.new \
         && mv /opt/webserver/Barracuda.new /opt/webserver/Barracuda && md5sum /opt/webserver/Barracuda'
ssh ... 'killall Barracuda'
```
`killall` sends **SIGTERM**, not SIGKILL (busybox v1.36.1: "Send a signal (default: TERM)"). Barracuda registers `sigHandler` for SIGTERM at 0x10a10, so this takes supervis's *reported* path: message 7 → `ArmSWTimer(g_barracudaTmr, 5)` → relaunch in about 5 seconds. Confirmed live in `SupervisionLog.txt`: `RECV_SIGABRT 09:36:28` → `RESTART-1 09:36:33`.
Do **not** use `kill -9`. That runs no handler, so supervis only notices on its 600 s `SupervisTimeout` poll and the panel has no web server for up to ten minutes.
Each rollback cycle spends one unit of the cumulative 24-relaunch budget. Read it back: `grep BARRACUDA_RESTART /opt/tuxedo/configuration/SupervisionLog.txt | tail -1`.

**R2 — crash loop, SSH window ~2.5 min per cycle.** dropbear (rc.local) starts before supervis and is independent of Barracuda, so SSH is up early in every boot. Loop:
```
while ! ssh -o ConnectTimeout=3 -i ~/.ssh/tuxedo_ed25519 root@203.0.113.5 'true'; do sleep 2; done
# then immediately run the R1 cp/mv block
```
Get the `mv` in during that window and the loop stops at the next relaunch. Budget: 24 relaunches at 5 s plus sub-second crashes = roughly 2.0–2.5 minutes from the first crash to the watchdog disarm, *minus* whatever the counter already held. Boot to Barracuda launch is 26–32 s across four measured boots.

**R3 — last resort.** `./push-image.sh build/v12final/app2.hdr --reboot`. This reflashes mtd16 and wipes everything added over SSH, including dropbear keys and `authorized_keys` — verify the image you push carries rc.local v11 / IMAGE TAG v6 or you lose SSH. `/opt/tuxedo/configuration` is mtd17 and survives, so `SupervisionLog.txt` is preserved.

**R4 — post-mortem, always.**
```
grep -c "reached max relaunches" /opt/tuxedo/configuration/SupervisionLog.txt
grep "E_SUPVTRD_BARRACUDA" /opt/tuxedo/configuration/SupervisionLog.txt | tail -20
```
That partition survives reflash, and the restart counter is printed in the line (`E_SUPVTRD_BARRACUDA_RESTART-N`). Across 16 logged `SYSTEM START`s this unit has **never** hit the ceiling, so the reset half of the model is READ, not MEASURED.

---

## 6. WHAT REMAINS UNVERIFIED, AND THE CHEAPEST EXPERIMENT FOR EACH

| # | Unverified | Confidence today | Cheapest experiment |
|---|---|---|---|
| ~~1~~ | ~~That a logged-in browser's push request actually carries the session cookie.~~ | **MEASURED 2026-09-06** | Done, and by a stronger method than the one planned — see §3. `path=/` confirmed on the wire, `secure` confirmed absent over HTTP, and the shared predicate `AuthenticatedUser_get1` exercised with valid / forged / absent sessions. |
| ~~2~~ | ~~That the panel answers `401` on this endpoint rather than something else.~~ | **MEASURED 2026-09-06 under emulation** | Answered without a flash, which the row said was impossible: the real ARM binary under `qemu-user` returns `HTTP/1.1 401 Unauthorized`, 241 B, on `:80` and `:6280`, against a control that returns `200`, 526 B. **Caveat, and it is not small:** `qemu-user` forwards syscalls to the build host kernel, so the `FIONBIO` + fresh `SO_SNDTIMEO`/`SO_RCVTIMEO` reconfiguration this row worries about ran against a modern kernel, not 2.6.31. The status line is generated at application level, which is the part that was in doubt. T6 still worth running. |
| ~~3~~ | ~~That no cave instruction faults in the request path.~~ | **MEASURED 2026-09-06 under emulation** | The patched binary served anonymous denials and authenticated streams on all four listeners, plus a full `test-stream-auth.py` run, and stayed alive with **zero** `SIGSEGV` in its log. Every instruction in the cave was executed: both early-outs, the dir compare, `AuthenticatedUser_get1`, the `ldrh`, and `sendError1`. T5 remains worth running because emulation does not model 2.6.31. |
| 4 | Whether the on-panel touchscreen consumes the stream. Netstat showed no loopback client, but that is one instant, and a second sample this session showed a `203.0.113.248` client on :80 the first sample did not contain. | INFERRED | Already effectively settled by a better method: the Qt binary `tuxedo` (md5 98370c31…) contains no occurrence of `SimpleDebugger` or `.interface` in its strings. That is a property of the binary, not of a moment. Re-run `strings` if you want it on the record. |
| ~~5~~ | ~~What `203.0.113.248` is.~~ | **IDENTIFIED 2026-09-06** | Reverse DNS: `zabbix.example.com` — the monitoring server. Short `:80` connections are availability polls, not stream consumption, which matches the observed shape. It is **not** an unauthenticated stream consumer, so the patch does not break it: the cave compares `r4` against the SimpleDebugger EhDir (`0x55b59c`) and returns stock's verdict unchanged for every other dir. Worth a glance at the Zabbix item's configured URL before flashing if it was ever pointed at something under `/SimpleDebugger.interface/`. |
| 6 | Whether the mobile UI opens the stream through the same `eventhandler` frame. Only `eventHandler.js` and the dead `eventHandler_org.js` construct an `EventHandler` in 776 extracted files, so it almost certainly does. | INFERRED | Load a mobile page in a desktop browser at a narrow width and repeat T9. |
| 7 | The hardware watchdog timeout after `DisArmSWTimer`. The kick is a 1 Hz `ioctl(0x7403)` on a 2.6.31 driver with no sysfs or dmesg exposure. | unknown | Not measurable without letting it fire on a live alarm panel. Do not. It only bounds the tail of "bad flash → first hard reset"; everything before it is measured. |
| ~~8~~ | ~~Whether the build VM's stock template is genuinely `324209e1`, i.e. whether v12 could be rebuilt from `patches.tsv` at all.~~ | **VERIFIED 2026-09-06** | Answered yes, by execution rather than inspection. `/work/extracted/root_stock/` holds all three genuine stock binaries (`324209e1` / `6f8055f5` / `04386af2`); `apply-patches.py --apply` against a copy of that tree reported `11 sites: 0 already patched, 11 applied, 0 needing attention` and produced `c8971027` / `98370c31` / `6caac69e` — the v12 md5s, byte-exact. R0 is therefore a convenience, not the only copy. |

---

## 7. CORRECTIONS TO THE BRIEF, FOR THE RECORD

Four of the brief's stated premises are wrong. All were checked against this exact binary.

- **`EhDir_constructor`'s 4th argument is not `newClientCon`.** It is an optional 28-byte config struct, dereferenced at 0x7a23c–0x7a270 and defaulted to a zeroed stack struct when NULL. `newClientCon` is registered separately by `EhConListener_constructor` at 0x1ddd8.
- **`initAndInstallServlet` is not the only place to attach auth, and is the wrong place.** `EhDir_service` already calls `HttpDir_authenticateAndAuthorize` on itself at 0x7a420, per request, before any header is written. No new code is needed in the service path, and hooking there avoids writing struct fields at startup.
- **tuxelf's `refs()` is systematically wrong and its output was used to rank cave risk.** `.symtab`, `.strtab`, `.comment`, `.shstrtab` and `.ARM.attributes` all have `sh_addr == 0`, so `o2v()` maps their file offsets into low VA space and every function symbol gets at least one phantom data reference. `LoginTracker_getFirstNode`'s single "data ref" is file 0x5589b0 — its own `st_value` inside `.symtab` — reported as VA 0xd0b4 "in createServer". Any "this dead function has a data reference" result from that helper must be re-checked against the section table. Same class of bug as the caller-count bug that produced three refuted findings. Worth fixing in `D:/Projects/tuxedo-touch-firmware/tuxelf.py`.
- **The stream is unauthenticated on four listeners, not two.** 80, 443, 6280 and 9443 all serve it. One patch covers all four (one dir, one `HttpServer`), but the test plan must exercise all four.

And one correction to the reviews themselves: the hazard inversion in §1.3. `sigHandler` being installed after `installVirtualDir` means startup faults are *unreported* — but this patch does not run at startup, and request-path faults are fully on the reported, counted, watchdog-disarming path. The brief's "startup-crash risk is the primary hazard" framing does not apply to this patch; "request-path crash driven by the consumers' own reconnect loops" does.