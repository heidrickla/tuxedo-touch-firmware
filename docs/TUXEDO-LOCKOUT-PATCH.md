# Honeywell Tuxedo Touch WIFI — Web Login Lockout
## Patch Specification: 3-strikes-permanent → 5-strikes / 5-minute self-clearing

**Target firmware:** TUXW_V5.3.21.0
**Binary:** `/opt/webserver/Barracuda`, sha256 `b9bf50d8d1cfe198bb6a0e33888092f4d29016a09a3db67df99401e49060186b`, 5,680,361 bytes
**Local copy:** `C:\Users\dev\AppData\Local\Temp\claude\D--PersonalProjects-iot-protocol-tools\000ba43d-52f5-43a6-902d-6c0edfdf3ceb\scratchpad\fw\carved\app2_root\opt\webserver\Barracuda`
**Address convention:** `.text` addr `0x0000c438` / off `0x00004438`; `.rodata` addr `0x00084d30` / off `0x0007cd30` → **VA − 0x8000 = file offset**, confirmed on two independent sections. [CONFIRMED]
**Status:** APPLIED AND SHIPPED. The analysis below was read-only — the stock `Barracuda` sha256 was re-verified unchanged after all of it — but the patch it recommends is now `patches.tsv` rows P1/P1a/P1b/P1c, in shipped images since v11 and current in v14, flashed to the live panel 2026-09-09 (`RELEASES.md`). §6's "not packaged, not flashed" is superseded.

---

## 1. THE ANSWER UP FRONT

**"Five attempts, then a five-minute lock that clears itself" is achievable, but it splits into two very different jobs.**

| Half | Difficulty | Verdict |
|---|---|---|
| Stop the permanent, all-accounts disable | **4 bytes, one instruction** | Provably single-entry. Reviewer: apply today. |
| 5 attempts / 300 s self-clearing lock | **136 bytes: 3 word patches + a 124-byte hand-written ARM routine in a dead-code cave** | Sound, but a separate and genuinely riskier project. |

Three corrections to the brief's premises, all settled by instruction-level reading:

- **The brief's hypothesis is wrong.** Barracuda's stock `LoginTracker` does **not** implement a timed ban, and the constructor has no ban-time argument. `LoginTracker_constructor` @0x64ed4 is `(this, nodeCount, LoginTrackerIntf*, AllocatorIntf*)` — arg2 is stored verbatim at `o+0x18` (0x64ef4) and dereferenced only as a 4-slot vtable. The "ban-time shape" at 0x653a8 is an illusion: `node+0x2c` is a **write-only** timestamp with no load site anywhere, and `node+0x34` (the apparent "limit") is hardcoded to 0 at 0x65188 and read once into a dead field. There is no constant to tune. [CONFIRMED]
- **There is therefore no "neutralise the overlay and let the stock timer take over" path.** Honeywell's policy hook `LoginTrackerIntf_Validate_func` @0x13af0 is 12 bytes that tail-call `LoginTracker_find`, so `LoginTracker_validate` **structurally cannot return 0**. The stock tracker is a fully inert, decorative rate-limiter. The timer must be written. [CONFIRMED]
- **The audit's headline is literally true; its stated reason is wrong.** A reset does exist and does run on successful login — but it never writes `"status"`, and it is unreachable once accounts are disabled. Both things are true at once. Detail in §2.

**Recommendation — SUPERSEDED 2026-09-09.** Both tiers shipped, in the order advised: P1 alone first, then the timed lock once the §4/§5 deployment discipline was in place. v14 carries `P1-lockout`, `P1a`/`P1b`/`P1c-lockout-stub` and `P2-validate-hook`, giving the live panel 5 attempts then a 300 s self-clearing lock. Tier 3 (P7/P8/P9) remains unapplied. Read §3 below as the record of what was decided, not as an open proposal.

---

## 2. WHAT THE LOCKOUT ACTUALLY DOES TODAY

### 2.1 RECOVERY FIRST — if this has already happened to you

Nothing in Barracuda ever writes `"status" = 1`. If three failures have already fired, **patching the binary will not un-brick the login.** Repair the config first, verify, *then* patch.

**Route A — touchscreen (preferred, no shell needed).** Panel → User Setup → "Enable All". This runs `saveuserDetailsInstruct` in the panel binary, which writes `status=1`, `accountLocked=0`, `accLockedCount=0` at 0x3275e8-0x3275fc. [LIKELY — the panel binary `/tuxedo` was string-matched and the write sites located, but not fully disassembled.]

**Route B — root shell.** `/etc/inetd.conf` carries `telnet stream tcp nowait root /usr/sbin/telnetd`, and `inetd` (plus `dropbear`, `sshd`) is in `rc.conf`'s `all_services`. [CONFIRMED from the carved rootfs.] With a shell: write a plaintext `/opt/tuxedo/configuration/webuseraccounts.json` with `status:1` on every record and **delete both** `webuseraccountsenc.json` and `webuseraccountsenc_sec.json`; `migrateAccSetupFile` @0x3269cc re-encrypts and rebuilds the CRC at next boot. [LIKELY]

**Do not hand-edit the encrypted files.** Both readers (`updateLoginFailureCount` @0x153a0, `readUserNamePasswordFromJSON` @0x14c38) call `validateCRCFileOnFileRead` @0x334c4 and, on mismatch, self-heal by copying the `_sec` twin over the primary rather than rejecting. A hand-edit is likely to be silently reverted. [LIKELY — the 364-byte body of `validateCRCFileOnFileRead` was not read.]

**Before you touch anything:** touchscreen SD backup ("Backup Conf" → `cp -rf /opt/tuxedo/configuration /mnt/sd/`). Note there is **no SD restore path** in the panel binary — the backup is for manual reconstruction, not one-click recovery. [CONFIRMED]

### 2.2 What fires, and when

The "3" is in two places in `updateLoginFailureCount` @0x1537c, and **neither is the one people look for**:

- **The real gate** is `cmp r6, #1` @0x00015588 (file `0x0000d588`, on-disk `01 00 56 e3`), followed by `ble #0x15634` @0x15590. `r6` is the **old** `accLockedCount` of the matched user (set at 0x1552c from `atoi`, incremented at 0x15538). `old > 1` ⇒ fires on the **3rd** failure, and on every failure thereafter. [CONFIRMED]
- `cmp r0, #3` @0x000155cc sets the **cosmetic** `accountLocked` flag only. It gates nothing in the auth path. [CONFIRMED]
- The several `cmp Rn, #5` (0x15580, 0x15624, 0x14e78, 0x138f0, 0x38810) are the **WEBUSERS array bound**, not a threshold. Do not mistake them for one. [CONFIRMED]

### 2.3 The blast radius is every account — correction to one analyst

One analyst read the `status=0` write as per-record and conditional. **That is wrong**, and their own flagged unknown resolves against them. `bne #0x155fc` @0x155d8 skips *only* the `accountLocked` write and lands **on** the status block; the loop tail `cmp r5,#5` sits at 0x15624, *below* it. A full `.text` branch decode finds **exactly one** branch into `[0x155fc, 0x15624)` — from 0x155d8. So the block at 0x155fc-0x15620 (`json_pop_back` / `json_delete` / `mov r1,#0` @0x1560c / `json_new_i` / `json_push_back` on `"status"`) executes for **every one of the five WEBUSERS records, unconditionally**. [CONFIRMED, verified twice independently]

**Three bad passwords against one valid username disable all five web accounts.** Guesses against a *non-existent* username do nothing — `r6` stays 0 and the gate is skipped. [CONFIRMED]

The disabled state is written to `/opt/tuxedo/configuration/webuseraccountsenc.json` **and** its `_sec` twin, AES-encrypted, CRC store updated, panel notified via `sendRegisterCommand(0x9a)` (0x15638-0x156dc). Barracuda never touches the plaintext `webuseraccounts.json` — no literal reference to that path exists in the binary. [CONFIRMED]

### 2.4 THE DEADLOCK — SETTLED. It is genuinely permanent.

Two independent gates, either of which alone is fatal:

- **Gate 1** — `readUserNamePasswordFromJSON` @0x14bf8: `cmp r0,#1` @0x14ddc on `atoi(json_get(rec,"status"))`, `bne #0x14e78` @0x14dec. A `status=0` record is never even considered; the 0x53-byte output record stays all-zero. [CONFIRMED]
- **Gate 2** — `MyUserDB_getPwd` @0x14ef8: `cmp r3,#0` @0x14f7c / `beq #0x14fd8` @0x14f8c on the status byte, jumping to a failure path that `strcpy`s `"Failed"` into `AuthInfo+0x32` and then immediately zeroes it (0x14fec/0x14ff4) — an **empty password**, which can never match. [CONFIRMED]

`MyUserDB_getPwd` is the sole password source; `readUserNamePasswordFromJSON` has exactly one caller. There is no path around them. So authentication can never succeed, and every attempt falls to 0x6614c → `LoginTracker_loginFailed` → `updateLoginFailureCount`, which re-stamps `status=0` — **undoing any external repair on the very next attempt.** [CONFIRMED]

**The audit's letter vs. its substance.** A reset *does* exist and *does* run on successful login: `resetLoginFailureCount1` @0x136d4, called from `authPage_service` at 0x14290 and 0x14434 — but only after `AuthenticatedUser_get1` yields a non-NULL authenticated user, i.e. only after a **successful** login. So it cannot run once accounts are disabled. And even if it ran it would not help: it writes only `accLockedCount`, `accLockedTime`, `accountLocked` — its literal pool contains **no reference to `"status"`**. Same for its dead twin `resetLoginFailureCount` @0x15074. **No function anywhere in Barracuda writes `status=1`.** [CONFIRMED]

**Correction to an earlier claim:** the enumeration of `"status"` references was stated as complete and was not. `WnmpDir_serviceField` also references the string (0x25d14 / 0x2611c / 0x26138) — read-only (`json_get`/`json_as_string`/`strlen`), different subsystem. And `checkTotalUserAccount` was called dead; it is not — `_Z21checkTotalUserAccountPiS_S_` @0x2c3f8 is called from `callCheckTotalUserAccount` @0x314a8, also read-only on `status`. Neither changes the conclusion: `updateLoginFailureCount` remains the only **writer**. [CONFIRMED]

### 2.5 This is a designed-for state, not an accident

`Invalid_html076EF::service` @0x38604 counts named users (0x387d0) and users with `status==1` **and** `accountLocked==0` (0x387e8/0x38804), and selects message code 3 when users exist but none is usable (0x3882c-0x38848). The firmware has a dedicated "all accounts locked" screen. [CONFIRMED]

### 2.6 Bonus: a live 56-byte heap overflow

`LoginTracker_constructor` computes `n × 0x38` @0x64ee0 then **subtracts one node** @0x64ef0 (`sub ip,ip,#0x38`) before passing the size to malloc @0x64efc — but the bound check @0x6528c is `cmp ip,r3 / bhs` against `o[0x20] = n`, so slot index `n−1` is handed out and `LoginTrackerNode_constructor` writes 56 bytes at `buf[(n−1)×56 .. n×56−1]`. At the shipped n=3: a 112-byte buffer receiving a write at offsets 112..167. `AllocatorIntf_defaultMalloc` @0x62000 is `ldr r0,[r1]; b malloc` — it never enlarges the request. Reachable from unauthenticated network input by three distinct source IPs. [CONFIRMED]

Today it is **rare**, not routine: `clearCache` fires on nearly every failure and returns nodes to the free list, so the bump-allocate path is reached only by three distinct IPs failing with no intervening `clearCache`. **P4/P5 below delete exactly those resets** — which is why P6 is a hard prerequisite for Tier 2, not an optional extra. [CONFIRMED]

---

## 3. THE PATCH

### 3.0 MANDATORY APPLICATION METHOD

**Do not edit the live file in place with successive writes.** Copy the binary off the device (or use the carved copy), apply all bytes offline, verify the resulting sha256, and install the finished file with a single atomic `cp`/`mv`.

If you nevertheless edit in place, the ordering is not optional:

- **P3 (cave) before P2 (hook).** Reverse order means the validate callback branches into the *original* `resetLoginFailureCount`, which begins `mov ip,sp` / `push {r4-r11,lr}`, dereferences its arguments as JSON/file pointers, and opens and rewrites files — on **every unauthenticated HTTP request**. Rollback is the mirror: **P2 first**, cave second or never.
- **P6 before P7**, always. P7 without P6 simply enlarges the overflow.
- **P8 and P9 together, or P9 alone.** P8 alone silently disables the `accountLocked` flag entirely (the untouched inner `cmp r0,#3` can never match once the outer gate moves to `#3`).

**Precondition:** repair any existing `status:0` per §2.1 and verify the web login works *before* patching. Otherwise the patch will appear to have failed.

---

### TIER 1 — kill the permanent lockout (4 bytes, mandatory, standalone)

**P1 — `updateLoginFailureCount`: skip the mass `status=0` write**

| | |
|---|---|
| file offset | `0x0000d5fc` |
| vaddr | `0x000155fc` |
| before | `30 11 9f e5` → `ldr r1, [pc, #0x130]` (loads `"status"`) |
| after | `08 00 00 ea` → `b #0x15624` |

Branches straight to the loop tail `cmp r5,#5` @0x15624. `add r5,r5,#1` has already happened at 0x155b4. Both predecessors — the fall-through from the `accountLocked` write, and `bne #0x155fc` @0x155d8 — land on the new branch and skip cleanly. Single-entry basic block, verified by full `.text` branch decode. [CONFIRMED]

**Why not `mov r1,#1` @0x1560c** (the obvious alternative): writing 1 would *re-enable* an account the owner deliberately disabled from the touchscreen. P1 leaves `"status"` untouched by the failure path entirely, preserving admin intent. Same 4 bytes, strictly better semantics.
**Why not 9 NOPs** over 0x155fc-0x15620: identical effect, 36 bytes of edit surface instead of 4.

With P1 applied, both deadlock gates can never trip from a failed login. **The permanent lockout is gone.** The `accLockedCount` bookkeeping, the file rewrite, the CRC update and `sendRegisterCommand` all continue unchanged.

---

### TIER 2 — the 5-attempt / 300-second self-clearing lock (P2–P6, all five required)

Built in the **in-memory** tracker, not the JSON. It writes no flash, needs no CRC or AES handling, cannot desynchronise the `_sec` twin, and cannot brick the panel — worst case, a reboot clears it.

**The JSON route is a dead end and was rejected on evidence:** after a lock expired, a successful login runs `resetLoginFailureCount1`, which zeroes `accLockedTime` but never writes `"status"` — so the permanent lock re-forms on the next cycle. `accLockedTime` is write-only dead data (written 0x15550-0x1557c, never `json_get`'d or `atoi`'d anywhere). [CONFIRMED]

**P2 — redirect the always-permit stub into the cave**

| | |
|---|---|
| file offset | `0x0000baf0` |
| vaddr | `0x00013af0` |
| before | `09 00 91 e8` → `ldm r1, {r0, r3}` |
| after | `5f 05 00 ea` → `b #0x15074` |

The following 8 bytes (`08 10 83 e2 64 45 01 ea`) become unreachable; leave them — harmless, and it makes rollback a single word. Symtab size for this function is exactly 12; the only reference to 0x13af0 in the image is the vtable initialiser at file `0xc9dc` (`r4 = 0x0055d848`, slot 0). [CONFIRMED]

**Calling convention, verified at the call site.** `LoginTracker_validate` sets `r1 = AuthInfo` (0x65380) and `r2 = node` (0x65384), then `ldr r3,[r6,#0x18]; mov r0,r3; mov lr,pc; ldr pc,[r3]` (0x65390-0x6539c). So the hook is entered with **r0 = intf, r1 = AuthInfo, r2 = node**, `lr` = 0x653a0. **Non-zero return = allow.** [CONFIRMED]

**P3 — the routine, at file `0x0000d074` / VA `0x00015074` (124 bytes)**

```
15074  10 40 2d e9   push   {r4, lr}
15078  00 40 52 e2   subs   r4, r2, #0        ; r4 = node
1507c  01 00 a0 03   moveq  r0, #1            ; no node -> allow
15080  10 80 bd 08   popeq  {r4, pc}
15084  28 30 94 e5   ldr    r3, [r4, #0x28]   ; lockStart (0 = not locked)
15088  00 00 53 e3   cmp    r3, #0
1508c  0b 00 00 0a   beq    #0x150c0
15090  00 00 a0 e3   mov    r0, #0
15094  4e dc ff eb   bl     #0xc1d4           ; time(NULL)
15098  28 30 94 e5   ldr    r3, [r4, #0x28]
1509c  03 00 40 e0   sub    r0, r0, r3        ; elapsed (unsigned)
150a0  4b 0f 50 e3   cmp    r0, #0x12c        ; 300
150a4  00 00 a0 33   movlo  r0, #0            ; still locked -> DENY
150a8  10 80 bd 38   poplo  {r4, pc}
150ac  00 30 a0 e3   mov    r3, #0
150b0  28 30 84 e5   str    r3, [r4, #0x28]   ; expired: clear lock
150b4  30 30 84 e5   str    r3, [r4, #0x30]   ; and clear counter
150b8  01 00 a0 e3   mov    r0, #1            ; allow
150bc  10 80 bd e8   pop    {r4, pc}
150c0  30 30 94 e5   ldr    r3, [r4, #0x30]   ; failure count
150c4  05 00 53 e3   cmp    r3, #5
150c8  01 00 a0 33   movlo  r0, #1            ; 0..4 -> allow
150cc  10 80 bd 38   poplo  {r4, pc}
150d0  00 00 a0 e3   mov    r0, #0
150d4  3e dc ff eb   bl     #0xc1d4
150d8  00 00 50 e3   cmp    r0, #0
150dc  01 00 a0 03   moveq  r0, #1            ; clock at epoch 0 -> don't arm
150e0  10 80 bd 08   popeq  {r4, pc}
150e4  28 00 84 e5   str    r0, [r4, #0x28]   ; arm lock at 'now'
150e8  00 00 a0 e3   mov    r0, #0            ; DENY this attempt
150ec  10 80 bd e8   pop    {r4, pc}
```

Flat bytes for file offset `0x0000d074`:

```
10 40 2d e9 00 40 52 e2 01 00 a0 03 10 80 bd 08 28 30 94 e5 00 00 53 e3
0b 00 00 0a 00 00 a0 e3 4e dc ff eb 28 30 94 e5 03 00 40 e0 4b 0f 50 e3
00 00 a0 33 10 80 bd 38 00 30 a0 e3 28 30 84 e5 30 30 84 e5 01 00 a0 e3
10 80 bd e8 30 30 94 e5 05 00 53 e3 01 00 a0 33 10 80 bd 38 00 00 a0 e3
3e dc ff eb 00 00 50 e3 01 00 a0 03 10 80 bd 08 28 00 84 e5 00 00 a0 e3
10 80 bd e8
```

Round-tripped through capstone at base 0x15074: exactly 31 instructions, 124/124 bytes, no residue. Both `bl`s resolve to 0xc1d4 = **`time`**, confirmed by walking `.rel.plt` against `.plt` (header 20, stride 12). [CONFIRMED, verified independently by the reviewer]

**Cave safety.** `resetLoginFailureCount` @0x15074, size 776, has **zero branch callers**, and the only 4-byte occurrences of `0x00015074` in the whole file — `0x54cdf0` and `0x55a700` — are both inside `.symtab`. No vtable, GOT entry, or data pointer targets it. [CONFIRMED]

**Field choice — `node+0x28`, not `+0x34`.** `+0x28` is zeroed at 0x6518c and touched nowhere else in the closed consumer set. `+0x34` is read at 0x653c4 and its value lands in `AuthInfo+0x2c`, so parking a Unix timestamp there would make that field a large negative number. Nothing appears to read it, but `+0x28` costs nothing and removes the question. (Note `str r3,[r6,#0x28]` @0x13a60 is *AuthInfo*+0x28 — a different object.) `LoginTrackerNode_reset` zeroes only `+0x30`, not `+0x28`, so a freed node can carry a stale lock stamp — harmless, because `LoginTrackerNode_constructor` re-zeroes `+0x28` on reuse. [CONFIRMED]

**Counting.** A node is created only in `LoginTracker_loginFailed`, so attempt 1 sees no node and is allowed. Counter reaching 5 at validate time means five password attempts have been consumed. **Attempts 1–5 allowed; attempt 6 denied and arms the lock.** The deny path at 0x653a8 keeps incrementing `+0x30` while locked; harmless, since expiry zeroes it.

**Clock safety.** `sub` + unsigned `cmp` means a backward clock jump (the panel falls back to `date 0101000013` at boot when `/opt/tuxedo/configuration/datetime` is absent) underflows to a huge elapsed value and **unlocks early**. Deliberate fail-open — it can never lock the owner out longer than intended. The `time()==0` guard at 0x150d8 is a second deliberate fail-open: no rate limiting during that one second. Both named as fail-open by design.

**P4 / P5 — remove the two cache wipes on the failure path**

| | offset | vaddr | before | after |
|---|---|---|---|---|
| P4 | `0x0000ba68` | `0x00013a68` | `71 45 01 eb` `bl #0x65034` | `00 00 a0 e1` `mov r0, r0` |
| P5 | `0x0000ba7c` | `0x00013a7c` | `6c 45 01 eb` `bl #0x65034` | `00 00 a0 e1` `mov r0, r0` |

`LoginTracker_clearCache` @0x65034 walks the active list calling `LoginTrackerNode_reset`, which zeroes `+0x30` (0x64ff0) and `SplayTree_remove`s the node (0x64fd4) — after which validate's lookup misses and returns 1. P4 fires when the JSON count exceeds 2 (`cmp r0,#2` @0x13a54); **P5 fires on any unknown username** (`ldrb r3,[r6,#0x32]` @0x13a6c), which is an attacker-controlled reset — P5 also closes that bypass. The preceding `ldr r0,[r6]` becomes a dead load in both cases; no return value is consumed. [CONFIRMED]

**Leave `bl #0x65034` @0x13ab0 (file `0x0000bab0`) alone** — that one is on the *successful* login path and is precisely the self-clear you want.

`cmp r0,#2` @0x13a54 is deliberately **not** touched; with P4 applied it guards only `str r3,[r6,#0x28]`, and leaving it minimises blast radius.

**P6 — fix the heap overflow (PREREQUISITE for Tier 2, not optional)**

| | |
|---|---|
| file offset | `0x0005cef0` |
| vaddr | `0x00064ef0` |
| before | `38 c0 4c e2` → `sub ip, ip, #0x38` |
| after | `00 00 a0 e1` → `mov r0, r0` |

`ip` is dead after 0x64efc; `r0` is dead at 0x64ef0 (saved to r4 @0x64ee4, reloaded `#0` @0x64f00) and the NOP sets no flags. Allocates 56 more bytes at startup and removes a heap write past the end. Strictly safety-increasing. **Mandatory with P4/P5**, which delete the resets that make the overflow rare today. [CONFIRMED]

---

### TIER 3 — optional

**P7 — raise tracked peer IPs from 3 to 16.** File `0x0000c78c` / VA `0x0001478c`: `03 10 a0 e3` (`mov r1,#3`) → `10 10 a0 e3` (`mov r1,#16`). With three slots, a fourth distinct failing source evicts the oldest node via 0x652bc and reconstruction re-zeroes `+0x28`/`+0x30`, **silently clearing a live lock**. Costs 896 bytes at startup instead of 168. **Only with P6.** Allocation failure routes to `baFatalEf` @0x60d8c, which aborts the web server at startup — verify the panel comes back up. [CONFIRMED]

**P8 / P9 — keep the cosmetic `accountLocked` flag consistent (apply together or not at all):**
- `0x0000d588` / `0x00015588`: `01 00 56 e3` (`cmp r6,#1`) → `03 00 56 e3` (`cmp r6,#3`). r6 is **pre-increment** and the branch is `ble`, so 5 attempts needs **#3**, not #5.
- `0x0000d5cc` / `0x000155cc`: `03 00 50 e3` (`cmp r0,#3`) → `05 00 50 e3` (`cmp r0,#5`).

Neither affects whether login succeeds — `readUserNamePasswordFromJSON` checks only `u8UserId > 0` (0x14dbc/0x14dc4) and `status == 1` (0x14ddc/0x14dec), never `accountLocked`. They only keep `Invalid_html076EF::service`'s indication honest. [CONFIRMED]

---

### 3.1 Encodability

Every new immediate is a legal 8-bit value with an even rotate, verified by capstone round-trip at final address:

- **`#300` (0x12c) IS encodable** — imm8 `0x4b`, rot field 15, giving `e3500f4b`. **Correction:** two analysts asserted it was not and proposed a two-instruction workaround. They were wrong; the single `cmp` is used. [CONFIRMED, independently re-verified]
- `#5`, `#3`, `#16`, `#1`, `#0` — all trivially encodable.
- Branch words recomputed independently: `0x13af0→0x15074` = `ea00055f`; `0x155fc→0x15624` = `ea000008`; `bl` to 0xc1d4 = `ebffdc4e` / `ebffdc3e`. All well inside ±32 MB.

### 3.2 Resulting behaviour

Five password attempts per source IP. The sixth is denied **before any credential check** — validate is consulted at 0x65df0 and a zero return short-circuits to `LoginResp_service` at 0x65dfc — for 300 s from when the lock arms. Expiry clears the counter and the lock by itself. A successful login from any IP clears every node (stock `LoginTrackerIntf_Login_func` @0x13ab0). Restarting the web server or rebooting clears everything.

**No account is ever disabled, no file is written while locked, and `"status"` is never modified by a failed login.** The deny path does not reach `LoginTracker_loginFailed` (@0x6615c, on the far side of 0x66144), so a locked attempt writes no flash. [CONFIRMED]

**Established sessions are unaffected.** A session carrying a valid authenticated user returns at 0x65c4c/0x65c64/0x65cb0 and never reaches 0x65df0. Only unauthenticated requests are gated — which matters behind NAT, where attacker and owner share a source address. [CONFIRMED]

### 3.3 ROLLBACK — exact bytes

| file offset | len | restore to |
|---|---|---|
| `0x0000d5fc` | 4 | `30 11 9f e5` |
| `0x0000baf0` | 4 | `09 00 91 e8` |
| `0x0000ba68` | 4 | `71 45 01 eb` |
| `0x0000ba7c` | 4 | `6c 45 01 eb` |
| `0x0005cef0` | 4 | `38 c0 4c e2` |
| `0x0000c78c` | 4 | `03 10 a0 e3` |
| `0x0000d588` | 4 | `01 00 56 e3` |
| `0x0000d5cc` | 4 | `03 00 50 e3` |

Cave, `0x0000d074`, 124 bytes:

```
0d c0 a0 e1 f0 df 2d e9 04 b0 4c e2 14 d0 4d e2 c4 42 9f e5 c4 12 9f e5
30 00 0b e5 10 20 94 e5 bc 02 9f e5 09 79 00 eb 10 30 94 e5 03 00 50 e1
01 00 00 0a 10 00 84 e5 e7 76 00 eb a0 02 9f e5 a0 12 9f e5 75 dc ff eb
00 90 50 e2 a0 00 00 0a 00 10 a0 e3 02 20 a0 e3 2a da ff eb 00 40 50 e2
8a 00 00 1a 09 00 a0 e1 4c db ff eb 00 50 50 e2 86 00 00 0a 0e 30 85 e2
07 80 c3 e3
```

Restoring **P2 alone** reverts all Tier-2 behaviour regardless of cave contents — that is the emergency single-word undo. Keep a byte-exact copy of the original 5,680,361-byte binary and verify sha256 `b9bf50d8…60186b` before and after.

**Real-world rollback is one `cp`.** `app2.hdr` identifies the payload as `app2.jffs2` — a read-write filesystem — and `/etc/fstab` mounts only `/dev/mtdblock17` at `/opt/tuxedo/configuration`, so `/opt/webserver` is on the writable app2 rootfs. Restoring the original over a root telnet session is a single command. **Two caveats:** `/opt/webserver` holds only `Barracuda` with no on-device spare (put the backup on the device *before* patching), and Barracuda is not launched from any rc script — the line in `/etc/rc.d/init.d/startup:88` is commented out, so it is spawned by the tuxedo app and there is **no init respawn**. [CONFIRMED from the carved rootfs]

---

## 4. THE REVIEWER'S OBJECTIONS

### Verdict

> **Tier 1 (P1 alone): SAFE_TO_TRY.**
> **Tier 2 + 3 as written (P2–P9): NEEDS_CHANGES.**

Not `DO_NOT_APPLY`. The reviewer independently re-derived essentially all of the reverse engineering — all nine byte offsets read out of the file, the 124-byte cave round-tripped through capstone, every branch word recomputed, `0xc1d4` re-resolved as `time` — and found **no defect in the patch logic**. Their words: *"I could not find a way for this patch set to weaken authentication. That axis is clean, and I checked it hard."* The catastrophic failure mode (validate always succeeds) is structurally impossible here: the only new outcome the hook can introduce is 0, which is a denial.

`NEEDS_CHANGES` is about **deployment discipline**, which on a live alarm panel is where the risk actually lives. Five defects, all folded into §3 above:

**D1 — No application order was specified, and the wrong order bricks the web UI.** This was the most dangerous omission in the draft. P2 before P3 means every unauthenticated HTTP request branches into the original `resetLoginFailureCount`, which pushes a frame, dereferences its arguments as JSON/file pointers, and rewrites files. → Now §3.0, with the offline-build-and-atomic-install method as the preferred answer.

**D2 — P6 was misclassified as optional, and the draft's own reasoning under-argued its case.** The draft said the overflow "is live today"; that overstates in one direction and understates in another. Today `clearCache` fires on nearly every failure and returns nodes to the free list, so the bump path is rarely reached. **P4/P5 delete exactly those resets** — after Tier 2, the third distinct failing peer overflows 56 bytes on the heap routinely, from unauthenticated network input. → P6 promoted to Tier 2, mandatory.

**D3 — P1 does not un-brick a panel that is already locked out, and the draft never said so.** This is the first thing that will happen operationally, and the owner would reasonably conclude the patch broke it. → Now the lead of §2.1 and a precondition in §3.0.

**D4 — P8 without P9 silently disables the `accountLocked` flag entirely.** The draft's arithmetic was right (r6 is pre-increment) but the coupling was unstated. → Now presented as an inseparable pair.

**D5 — "Threading unverified" was a shrug, and it is not unverified.** `DT_NEEDED` includes `libpthread.so.0`; `pthread_create`, `pthread_mutex_lock/unlock/init/destroy`, `pthread_self`, `pthread_detach` are all imported. The process **is** threaded. Whether the HTTP dispatcher is single-threaded remains open. The cave adds a **new** unsynchronised read-modify-write pair (clearing `+0x28` and `+0x30` on expiry) on a structure the loginFailed path also mutates. The reviewer traced the failure modes: every race outcome is a lost update on two integers — lock arms late, unlocks early, counter under-counts. **No pointer is written, so no corruption and no auth bypass.** Acceptable, but stated honestly rather than deferred.

### Smaller corrections the reviewer made

- `checkTotalUserAccount` is **not** callerless (called from `callCheckTotalUserAccount` @0x314a8). Read-only on `status`; P1 unaffected, but the claim as written was false.
- The "only writer of `status`" enumeration omitted `WnmpDir_serviceField` (0x25d14 / 0x2611c / 0x26138) — read-only. Conclusion survives; the enumeration should not have been asserted as absolute.
- **Recovery is materially better than the draft implied** — root telnet is in `inetd.conf` and app2 is a read-write JFFS2. That changes the risk calculus considerably. Now in §2.1 and §3.3.
- `node+0x28` survives on the free list (`LoginTrackerNode_reset` zeroes only `+0x30`); harmless because the constructor re-zeroes it on reuse.
- `strb r3,[r4,#0x431]` @0x14fd0 is real, and `r4` **is** the AuthInfo pointer — the caller passes `sp+0x10` in a `sub sp,sp,#0x134` frame, so this writes ~0x30d bytes past that frame. Pre-existing, unrelated to this patch, correctly out of scope — but it deserves its own investigation rather than a footnote.
- **The lock is trivially evictable.** With 3 slots and P4/P5 applied, a 4th distinct failing source evicts the oldest node and clears a live lock. P7 raises that to 17. Anyone rotating source addresses defeats this entirely. Not a regression — stock has no working lock at all — but §3.2 should not be read as more absolute than the mechanism supports.
- **No payload checksum found.** The `app2.hdr` container is `"appl000"` + u32 length (`0x0765aa08` = 124,103,176, exact) + `"app2.jffs2"` + `"TUXEDO_V5.3.21.0"`. The reviewer brute-forced sum8, sum16 LE+BE, sum32, xor32, adler32, crc32, CRC16-CCITT/XMODEM/IBM/MODBUS over a small payload against every header word — **no match**. The Barracuda ELF itself carries no build-id or hash section. [LIKELY — absence of evidence, not proof of absence.]

### The reviewer's bottom line, verbatim in substance

> If Lewis wants the minimum-risk change that solves the problem he actually described — the panel disabling all his accounts forever — **P1 alone is four bytes, provably single-entry, and I would apply it today.** The 5-minute timed lock is a separate, larger, genuinely riskier project, and it should be evaluated on its own merits rather than bundled.

Do the five fixes (all now incorporated) and **Tier 1 + Tier 2 + P6 become SAFE_TO_TRY.** P7 optional and only with P6; P8/P9 cosmetic and can wait.

---

## 5. HOW TO TEST IT SAFELY

### 5.1 The one rule that matters

**app1 and app2 writes are recoverable. Bootloader writes are not.** Nothing in this patch set touches U-Boot, the environment, or any partition other than the app2 rootfs. Keep it that way. If any step ever proposes writing outside app1/app2, stop — a bad bootloader write is an unrecoverable brick with no software route back.

### 5.2 Order of operations

1. **Prove recovery works before you need it.** Confirm root telnet (or dropbear/sshd) is reachable. Copy the pristine `Barracuda` to a second location **on the device** — `/opt/tuxedo/configuration/Barracuda.orig` or an SD card. `/opt/webserver` holds only the one file; there is no on-device spare. Practise the restore `cp` and a service restart *with the unmodified binary* so you know the sequence works.
2. **Touchscreen SD backup** of `/opt/tuxedo/configuration` ("Backup Conf"). Remember: no restore path in the panel binary — this is for manual reconstruction.
3. **Record current state.** Read the `status`, `accLockedCount`, `accountLocked` values for all five records before anything. Repair any existing `status:0` per §2.1 and verify web login works. Patching a locked panel will look like the patch failed.
4. **Establish the fallback.** Barracuda is spawned by the tuxedo app, not by init, and **there is no respawn**. Whether the tuxedo app blocks or degrades if its child fails to exec is **not determined**. Assume the worst: if Barracuda fails to start, you may have only the touchscreen and the shell, so verify the shell is up *first*.

### 5.3 U-Boot netboot — what it does and does not buy you

U-Boot can `tftpboot` a kernel and `bootm` it **without writing flash**, which is the right tool for validating a kernel or a recovery initramfs. It is a genuine safety net for *boot-level* experimentation.

It does **not** validate this patch. The change is in a userspace ELF on the app2 JFFS2, and netbooting a kernel does not exercise `Barracuda`'s login path. Netboot's real value here is as **insurance**: a netbooted kernel with a busybox initramfs can mount `/dev/mtdblock*` and restore the original `Barracuda` even if the normal boot path is unusable. Set that up and prove it works **before** patching, not after — and read the U-Boot environment without writing it (`printenv`, never `saveenv`).

### 5.4 Staging

- **Stage A — P1 only.** Four bytes, single-entry, no new code. Install, restart, log in normally, then deliberately fail 4-5 times and confirm the accounts are **not** disabled (`status` stays 1 in the config). Run it for several days. This alone solves the stated problem.
- **Stage B — offline verify Tier 2.** Apply P3 → P2 → P4 → P5 → P6 to a copy. Re-disassemble at 0x13af0, 0x15074, 0x13a68, 0x13a7c, 0x64ef0 and confirm the decode matches §3 exactly. Confirm the 124 bytes at 0x0000d074 round-trip to 31 instructions. Diff the file against the original: **exactly 140 bytes should differ** (5 words + 124-byte cave, minus overlap = 20 + 124 = 144 bytes across 6 regions; count them and confirm nothing else moved). Record the new sha256.
- **Stage C — install Tier 2 atomically**, single `cp`. Restart the web server (or reboot). First check: does the panel come back and does the web UI serve at all? An allocation failure routes to `baFatalEf` @0x60d8c and aborts the server at startup.
- **Stage D — behavioural test, from a single source IP.** Five bad passwords → all should be rejected normally. Sixth → should be denied *without* a password check (fast, and no config file write — watch the mtime of `webuseraccountsenc.json`). Wait 300 s → sixth-equivalent attempt should be allowed again. Then log in correctly and confirm the counter is cleared.
- **Stage E — the eviction case.** Fail from a second and third distinct IP while the first is locked. With P6 applied there should be no crash. Without P7, a fourth IP will evict and clear the lock — verify that is the behaviour you see, and decide whether P7 is worth it.
- **P7, P8, P9 last**, separately, each with its own restart-and-verify.

### 5.5 What to watch for

- Web server fails to start → restore immediately; suspect P6/P7 allocation.
- Any segfault or unexplained restart under load → suspect the D5 race or a residual heap issue; restore.
- Config file mtime changing on a *locked* attempt → the deny path is reaching `loginFailed`, contrary to analysis; restore and re-examine.
- Touchscreen behaving oddly around User Setup → the panel binary shares these records and was never disassembled.

---

## 6. OPEN QUESTIONS

**Blocking — settle before flashing anything:**

1. **Is this carved binary what the device actually runs, and is app2 signed or hash-checked at boot or at flash time?** Nothing in the ELF or the `"appl000"` container header answers this. The reviewer's exhaustive checksum search over the header found no match, which is suggestive but not proof. This single question decides whether any of this is installable. [UNKNOWN]
2. **Does the tuxedo app survive a failed Barracuda exec?** Barracuda is spawned by the panel app, not init, and there is no respawn (`/etc/rc.d/init.d/startup:88` is commented out). If a failed exec takes the panel down, the recovery window is much narrower than assumed. [UNKNOWN]

**Affects behaviour, not safety:**

3. **SoDisp thread model.** The process is threaded (`libpthread`, `pthread_create` imported). Whether HTTP dispatch is single-threaded is unverified. All identified race outcomes are lost updates on two integers — no pointer writes, no corruption, no auth bypass — but the counter can under-count. [UNKNOWN]
4. **`validateCRCFileOnFileRead` @0x334c4** — 364 bytes, not read. Both call sites *read* as self-healing (`system("cp <_sec> <primary>")` on mismatch), which is why hand-editing the encrypted JSON is discouraged. Matters only for the manual recovery route. [LIKELY, not CONFIRMED]
5. **`setLoginForLocal` @0x2bf50 / `getLocalLoginStatus` @0x2ab70** and globals `localLoginStatus` @0x55b97c / `loginEnabled` @0x55c4bc — not analysed. If these provide a console login that bypasses `MyUserDB_getPwd`, that is both a third recovery route and a second place policy would need to stay consistent. [UNKNOWN]
6. **The panel binary `/tuxedo`** (14.6 MB) carries the same `WEBUSERS` / `status` / `passWord` / `accLockedCount` strings and is the presumed touchscreen recovery route. **String-matched only, never disassembled.** Confirm "Enable All" actually works before relying on it. [LIKELY]
7. **`strb r3,[r4,#0x431]` @0x14fd0** writes ~0x30d bytes past the caller's stack frame. Pre-existing, unrelated to this patch, real. Deserves its own investigation. [CONFIRMED as an out-of-bounds write; consequences UNKNOWN]

**Structural, not exhaustive:**

8. ~~**`node+0x28` is proven unread structurally, not exhaustively.**~~ **REFUTED
   2026-09-05, then that refutation was itself WITHDRAWN 2026-09-06.**

   The "refutation" read `resetLoginFailureCount` @`0x15074` out of a PATCHED
   Barracuda and described what it found as vendor behaviour. That function is
   **our own P1 lockout stub**, which this project wrote. Reading our patch and
   calling it a discovery about stock is not a refutation of anything.

   The original claim was about STOCK, where `0x15074` is an entirely different
   function — `validateCRCFileOnFileRead` / `fopen` / `writeCRCJSONFile`, the
   on-disk JSON path. Whether stock reads `node+0x28` is therefore **still
   open**, exactly as item 8 first said. [ORIGINAL CLAIM STANDS, unverified]

   The one part worth keeping: the tail-call-through-thunk observation is real
   and the tooling fix it prompted was correct. It just does not license the
   conclusion that was drawn from it.

## What P1 actually implements (OUR code, not the vendor's)

**Corrected 2026-09-06.** This section previously read as a discovery about the
vendor. It is not: `resetLoginFailureCount` @`0x15074` in a patched build is the
~124-byte stub P1 installs, and the two `bl` sites at `0x13a68` and `0x13a7c`
are NOP'd by the same patch. Stock's function at that address is the on-disk
JSON path and looks nothing like this.

So what follows describes **the behaviour we built**, which is worth documenting
precisely — it is what the panel does now — but it says nothing about what
Honeywell shipped.

`barracuda` calls `installVirtualDir` @`0x14598`, which builds the LoginTracker
interface vtable at `0x14758`-`0x1477c`:

| slot | thunk | real body |
|---|---|---|
| `[r4+0]` Validate | `0x13af0` | `resetLoginFailureCount` @`0x15074` |
| `[r4+4]` Login | `0x13aa4` | |
| `[r4+8]` LoginFailed | `0x13a24` | `updateLoginFailureCount` @`0x1537c` |
| `[r4+0xc]` TerminateNode | `0x133d8` | |

So `resetLoginFailureCount` runs on every validate. Decoded:

```c
if (node == 0)             return 1;    // allow
t = node[0x28];                         // lockout timestamp
if (t != 0) {
    if (time(0) - t < 300) return 0;    // DENY, still locked
    node[0x28] = 0;                     // expire the lockout
    node[0x30] = 0;                     // and clear the failure counter
    return 1;
}
if (node[0x30] < 5)        return 1;    // under threshold
node[0x28] = time(0);      return 0;    // start the 5-minute lockout
```

Threshold **5** failures, lockout **300 s**, and it clears both the timestamp
and the counter on expiry. This is a self-healing in-memory lockout, not a
permanent one.

**Do not read this as "lockout is harmless."** It is one of two mechanisms and
they are independent:

- **In-memory** (above): LoginTracker node in a splay tree. 5 strikes, 5
  minutes, self-clearing, lost on restart.
- **On-disk**: `updateLoginFailureCount` @`0x1537c` reached from the
  `LoginFailed` vtable slot. It decrypts the WEBUSERS JSON
  (`decryptAESforTuxdb` → `json_parse_unformatted`), edits it, and writes it
  back encrypted (`encryptAESforTuxdb`, `validateCRCFileOnFileWrite`). That is
  the path behind the persistent `status=0` account disable, and nothing here
  shows it expiring.

The threshold and expiry above are **read from the binary, not observed on
hardware.** Provoking a real lockout to confirm them was deliberately not
done.
9. **`.ARM.exidx`:** a single entry starting 0x000133c0, next at 0x0002a994, inline compact word `0x80a8b0b0`, whose opcodes decode to `pop {r4,lr}` + finish — which happens to match the cave's frame exactly. Both 0x13af0 and 0x15074 sit inside it. Harmless for a routine that never unwinds, but it is an inherited descriptor, not a correct one. [CONFIRMED coverage; correctness incidental]
10. **Nothing here has been executed.** Every instruction is encoding-verified and every branch target is verified, by two independent passes. No patched binary has been run.

---

**Working scripts** (read-only; target sha256 re-verified unchanged): `C:\Users\dev\AppData\Local\Temp\claude\D--PersonalProjects-iot-protocol-tools\000ba43d-52f5-43a6-902d-6c0edfdf3ceb\scratchpad\pd\` — `bd.py` (VA→file-offset disassembler), `scan.py` (branch/xref/exidx), `chk.py` (byte verification), `plt.py` / `plt2.py` (PLT resolution), `rv.py` (literal-pool → string), `st3.py` (string xref by function), `xr.py` (caller/data-word xref), `ex.py` (exidx coverage), `vc.py` (cave round-trip), `hdr.py` / `ck.py` (container header checksum search).

---

# ADDENDUM — closing the reviewer's three gaps

The reviewer accepted Tier 1 as SAFE_TO_TRY and marked Tier 2 NEEDS_CHANGES for
three reasons. One of them is now answered from the parallel verification run.

## Gap 3, ANSWERED: what if the panel is ALREADY locked out?

**Recovery does not require the patch, a flash write, or rebuilding accounts.**

The web server never writes the `status` flag back — that part of the audit was
proven exhaustively. But the **touchscreen application does**, and it is a
shipped, user-reachable path:

1. At the panel, open **Settings → user account setup**.
2. Each account shows an **Enabled / Disabled** button reflecting the stored flag.
3. Press **Enable All** (or the per-user Enable buttons).
4. **Apply.**

On Apply the app writes `status=1`, `accountLocked=0` and `accLockedCount=0` for
every row not explicitly marked Disabled, re-encrypts the accounts file, and
notifies the web server. Usernames and passwords reload from the same file and
never need retyping.

So the corrected statement of the original finding is:

> Three failed web logins disable every web account **until someone clears it at
> the panel's touchscreen.** Not permanent, not a rebuild — a panel visit.

**Historical — this was the case for not rushing the patch.** On stock firmware the
failure mode is recoverable at the touchscreen without a flash write, which lowered
the urgency at the time. Superseded: the patch shipped in v14, flashed 2026-09-09.
Enable All remains the recovery path for a panel still on stock.

## Gap 1, PROPOSED ORDER

The reviewer asked for a mandatory application order. The safe one follows from
its own verdict:

| Step | What | Risk |
|---|---|---|
| 1 | **P1 alone** — the single 4-byte word at file `0x0000D5FC` | accepted SAFE_TO_TRY |
| 2 | Verify: fail a login 3 times, confirm accounts still work | none |
| 3 | Only then consider Tier 2 | NEEDS_CHANGES — do not apply as written |

**P1 is standalone and is the whole fix for the dangerous behaviour.** It stops
the mass disable. Tier 2 only adds the nicety of a self-clearing 5-attempt lock,
and it is 124 bytes of new code rather than one word.

If the goal is "stop three typos from locking me out", **P1 alone achieves it**
and Tier 2 is optional.

## Gap 2, NOT ADDRESSED

The reviewer says P6's dependency relationship is stated backwards. I have not
re-derived that and am not going to assert a correction I have not checked.
**Tier 2 stays NEEDS_CHANGES until someone resolves it against the binary.**

## Standing caveat

Nothing here has been written to the device. Tier 1 modifies the **root
filesystem**, which is the recoverable partition class — a bad write is fixed by
re-flashing from SD, unlike the bootloader. Test it over the U-Boot netboot path
before committing it to flash if that path is available.

---

## 6. BUILD RECORD — Tier 1 + Tier 2 built and verified 2026-09-05

Both tiers are now applied to a binary and every patched site has been
disassembled back and checked against the specification above.

| Artifact | sha256 (first 16) | Size | Contents |
|---|---|---|---|
| stock `Barracuda` | `b9bf50d8d1cfe198` | 5,680,361 | unmodified |
| `Barracuda.patched` | `af722b6d5debe46a` | 5,680,361 | Tier 1 only (P1) |
| `Barracuda.tier2` | `af9d34d2b694ef79` | 5,680,361 | Tier 1 + Tier 2 (P1–P6) |

131 bytes differ from stock, across the six documented sites. Size is
unchanged, so no section, segment or symbol offset moves.

### Verification performed on `Barracuda.tier2`

- **P3 round-trips.** The 124-byte cave disassembles to exactly 31 ARM
  instructions with no residue, matching the listing in §3 instruction for
  instruction.
- **Both `bl` targets resolve to `time`.** `0xc1d4` is `.plt` entry 218;
  walking `.rel.plt` into `.dynsym` gives the symbol name `time`. Confirmed
  from the ELF section headers rather than by assumption.
- **P2 lands on the cave.** `0x00013af0` decodes to `b #0x15074`.
- **P1 still lands correctly.** `0x000155fc` decodes to `b #0x15624`, and
  `0x15624` is `cmp r5, #5` as the specification requires.
- **Cave safety re-verified independently.** A full branch decode of `.text`
  (`va 0xc438`, size `0x788e8`) finds **zero** `bl` instructions targeting
  `0x00015074`, and the only word-sized occurrences of that address in the
  whole file are inside `.symtab`. Nothing calls the function whose body was
  replaced. The same scan finds zero `bl` callers of the P2 stub at
  `0x00013af0`, consistent with it being reached only through the vtable.
- **P4, P5, P6** each decode to `mov r0, r0` at the specified addresses, with
  the surrounding instructions unchanged.

### What was deliberately NOT applied

**Tier 3 (P7, P8, P9) is left out.** The reviewer classed it optional, and each
item buys little for this panel's stated goal:

- **P7** (tracked peer IPs 3 → 16) closes a real gap: with three slots, a
  fourth distinct failing source evicts the oldest node and silently clears a
  live lock. But it raises a startup allocation from 168 to 896 bytes, and an
  allocation failure routes to `baFatalEf`, which aborts the web server at
  boot. On a wall-mounted alarm panel that trade is not worth making for a
  threat model that is "stop locking me out permanently", not "resist a
  determined attacker". Revisit only if the lock proves easy to clear in use.
- **P8/P9** only keep the cosmetic `accountLocked` indication honest. Neither
  affects whether a login succeeds.

### Resulting behaviour

Attempts 1–5 are allowed. Attempt 6 is denied and arms a lock stamped with the
current time in `node+0x28`. Any attempt inside 300 seconds is denied. The
first attempt after 300 seconds clears both the stamp and the counter and is
allowed. A successful login still clears the cache through the untouched call
at `0x13ab0`. Nothing is written to flash, so a reboot also clears the lock.

### Still not done

`Barracuda.tier2` has **not** been packaged into a filesystem image and has
**not** been flashed. It is a patched ELF on disk and nothing more.
