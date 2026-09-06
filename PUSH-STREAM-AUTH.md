# Authenticating the push stream

**Status: PROPOSED. Nothing has been written to the panel.** An adversarial
review is in flight; this is my own single-pass analysis and this project's
consistent lesson is that those get refuted. Do not apply it until §6 is closed.

## The problem, measured

`GET /SimpleDebugger.interface/G.` serves live alarm state to anything on the
LAN with no credential. Baseline from `test-stream-auth.py` on v12:

```
anonymous port 80    EXPOSED  17 frames, 8 carrying alarm state
anonymous port 6280  EXPOSED   9 frames, 4 carrying alarm state
authenticated  :80   OK        9 frames
panel web UI         OK        HTTP 200
```

## Why it is open, exactly

Not an oversight in routing — **the check already runs and passes.**
`EhDir_service` is one of the three callers of
`HttpDir_authenticateAndAuthorize` @`0x6b544`, which reads:

```
0x6b56c  ldr r3, [r5, #0x18]     ; r5 = the dir; +0x18 = the authenticator
0x6b574  cmp r3, #0
0x6b578  beq 0x6b5ac             ; NULL -> fall through to the allow path
0x6b57c  bl  AuthenticatedUser_get1(request+8)
0x6b580  cmp r0, #0
0x6b58c  bne 0x6b5c8             ; already authenticated -> allow
0x6b590  ldr r3, [r5, #0x18]     ; else call the authenticator's vtable[0]
0x6b59c  ldr pc, [r3]            ; -> challenge / deny
```

And the `+0x18 == NULL` path:

```
0x6b5ac  ldr r3, [r5, #0x14]     ; the authorizer
0x6b5b4  cmp r3, #0
0x6b5b8  beq 0x6b5c8             ; -> return 1 (allow)
0x6b5bc  bl  AuthenticatedUser_get1
0x6b5c0  mov r0, #1              ; -> return 1 (allow) REGARDLESS
```

So **`dir+0x18` is the gate, and it is the only gate.** `+0x14` returns allow on
both of its branches, so setting it alone would do nothing. `initAndInstallServlet`
never sets either, because it inserts the EhDir into the plain root dir
(`ldr r0, [r6, #0x78]`) with `EhDir_constructor`'s 4th argument NULL.

The vendor's own "authenticated" dir @`0x55b388` differs only in that
`installVirtualDir` does `str r6, [r5, #0x18]` with r6 = `0x55b23c`, the
`FormAuthenticator`.

## The proposed patch

**Write the vendor's existing FormAuthenticator into the EhDir.** No new auth
logic, no per-connection check — the same pointer the authenticated dir uses, so
the semantics are identical to a dir the vendor already ships as protected.
`AuthenticatedUser_get1` does the deciding either way.

One instruction changes, plus a 16-byte stub in verified-dead code.

| | |
|---|---|
| EhDir object | `0x55b59c` |
| FormAuthenticator | `0x55b23c` |
| Cave | `LoginTracker_getFirstNode` @`0x64e9c`, 32 B, 0 callers, 0 data-refs, adjacent to `getNextNode` for 56 B total |

Cave contents (16 bytes at VA `0x64e9c`, file `0x5ce9c`):

```
0x64e9c  ldr r3, [pc, #4]        ; = 0x55b23c, the FormAuthenticator
0x64ea0  str r3, [r1, #0x18]     ; r1 already holds the EhDir at the call site
0x64ea4  b   HttpDir_insertDir   ; tail-call; r0 and r1 are already correct
0x64ea8  .word 0x55b23c
```

Call-site change in `initAndInstallServlet`, VA `0x1ddc0` / file `0x15dc0`:

```
before:  bl HttpDir_insertDir
after:   bl 0x64e9c              ; the stub, which stores then tail-calls
```

At that point `r0` = the root dir and `r1` = the EhDir, which is exactly what
both the stub and `HttpDir_insertDir` need, so nothing has to be shuffled.

**One patch covers all four ports.** `HttpServer_constructor` has one caller and
`initAndInstallServlet` is handed the same server every other dir insertion uses,
so 80, 443, 6280 and 9443 are four listeners over one directory tree with one
EhDir.

## Why this should not pass an unauthenticated or anonymous client

The check is the vendor's, not ours. After the patch the stream takes the exact
path a request to `/authenticated/` takes today: `AuthenticatedUser_get1` on the
request, and on NULL, the FormAuthenticator's challenge. If that admitted
anonymous clients, the vendor's own authenticated area would already be open.

**This is an argument, not a measurement.** It must be tested, because "looks
fixed but still serves anonymous clients" is the worst outcome here — §6.

## Test plan

`python test-stream-auth.py --host 203.0.113.5 --creds <file> --compare baseline.json`

| must show | meaning |
|---|---|
| `anon:80` OPEN -> denied | FIXED |
| `anon:6280` OPEN -> denied | FIXED, and confirms the one-dir model |
| `authed:80` OK unchanged | no regression for the known consumer |
| `webui` OK unchanged | the panel's own UI still works |

Then, by hand: the touchscreen still arms and disarms, and the panel's own web
keypad still loads. `anon:6280` staying OPEN while `anon:80` closes would mean
the one-server model is wrong and the patch should be reverted and re-analysed.

## Rollback

```bash
ssh -i ~/.ssh/tuxedo_ed25519 root@203.0.113.5 \
  'cp /opt/webserver/Barracuda.v12 /opt/webserver/Barracuda && sync'
# then kill Barracuda; supervis relaunches it within ~5 s
```

Backups, all md5 `c8971027bb9f77801d01713b4ae50b2f`: on-panel
`/opt/webserver/Barracuda.v12`, and off-panel in the scratch `panel-v12/`
directory. **The off-panel copy is the real safety net** — a flash wipes anything
added over SSH, which is how the previous `.orig` backups were lost.

`supervis` is the sole `/dev/watchdog` kicker and disarms the keepalive after 24
relaunches, so a Barracuda that crashes on startup resets the unit rather than
just breaking a web page. That is the primary hazard, and it is why the stub
must be verified byte by byte before it is written.

## 6. Unverified, and blocking

**CLOSED — 1. The cave is dead.** Re-derived independently, and the re-derivation
found two things the first pass missed, which is the reason for doing it:

- One branch lands inside the range: `0x64ea8 -> 0x64eb4`, internal control flow
  within `getFirstNode`. Irrelevant once the whole function is overwritten, but
  it means the function is not straight-line and a partial overwrite would be
  unsafe. Overwrite from `0x64e9c`.
- A whole-file scan found 4-byte values equal to `0x64e9c` and `0x64ebc` at file
  offsets `0x5589b0` and `0x55da00`, which the first scan reported as zero data
  references. **They are ELF symbol-table entries, not code references.** The
  16-byte records read `value=0x64e9c size=0x20` and `value=0x64ebc size=0x18` —
  the functions' own addresses and sizes, matching exactly. Both offsets are
  outside `.text` (`0x4438`-`0x7cd20`) and `.symtab` is not loaded at runtime.

No BL, no B from outside, no function-pointer install. **56 contiguous bytes at
file `0x5ce9c` are safe to overwrite.** One cosmetic consequence: the symbol
table will still name that address `LoginTracker_getFirstNode`, so disassembly
of a patched binary shows the stub under a misleading name. Worth a comment in
`patches.tsv`.

**CLOSED — 4. The stub assembles to the bytes claimed.** Encoded and
disassembled back:

```
0x64e9c  04 30 9f e5   ldr r3, [pc, #4]
0x64ea0  18 30 81 e5   str r3, [r1, #0x18]
0x64ea4  35 13 00 ea   b   #0x69b80   -> HttpDir_insertDir
0x64ea8  3c b2 55 00   .word 0x0055b23c
```

The literal load resolves to `0x64ea8`, which is where the literal sits. The
call-site word at VA `0x1ddc0` / file `0x15dc0` goes `6e 2f 01 eb` ->
`35 1c 01 eb`, i.e. `bl HttpDir_insertDir` -> `bl 0x64e9c`. The file-offset
convention (`file = VA - 0x8000`) was checked against `v2o` at both addresses
rather than assumed, because getting that wrong has already cost one bad
verifier entry today.

**STILL OPEN — 2. A non-NULL `+0x18` on an EhDir is safe.** `EhDir_service`
calls the auth function, but whether a *streaming* handler tolerates a challenge
response mid-path is not established. **This is the one that matters** and it
is what the review in flight should settle.

**STILL OPEN — 3. The panel's own web UI sends a cookie on this stream.**
Browsers do so automatically, but which page opens it and how has not been read
out of the embedded web app.

Until 2 and 3 are closed this stays a proposal.
